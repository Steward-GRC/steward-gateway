// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package diagnostics gathers the build and version facts behind the
// diagnostics query: every Steward service's version and commit, read from the
// headers on its standard gRPC health check, and the third-party versions
// (Kratos, Polis, Postgres, Valkey, RabbitMQ, OPA, Kubernetes).
//
// Probes run in parallel, each under its own timeout inside one overall
// budget. The assembled block is cached, failed entries for a shorter time, and
// concurrent reads share one refresh. A probe that fails, times out or answers
// something unparseable makes its entry unavailable; it never fails the read.
// Only names, versions, commits and states leave this package: never an
// address, a DSN, an error text or a response body.
package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Bugs5382/go-buildinfo"
	"github.com/Bugs5382/go-buildinfo/grpcbuildinfo"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
)

// Prefix is the Steward build-info header prefix.
const Prefix = "steward"

// The two statuses an entry can have.
const (
	StatusOK          = "OK"
	StatusUnavailable = "UNAVAILABLE"
)

// Unavailable and Unknown are the version strings for an entry that couldn't
// be read, and for a service that answered without build-info headers.
const (
	Unavailable = "unavailable"
	Unknown     = "unknown"
)

// Component is one versioned component.
type Component struct {
	Name    string
	Version string
	Commit  string
	Status  string
}

// Snapshot is the assembled block.
type Snapshot struct {
	Gateway    Component
	Release    string
	Appliance  string
	Services   []Component
	ThirdParty []Component
}

// VersionFunc reads one third-party version.
type VersionFunc func(ctx context.Context) (string, error)

// Config is what the service probes.
type Config struct {
	// Services are the backend connections by service name.
	Services map[string]grpc.ClientConnInterface
	// HTTPServices are probe-only components with an HTTP health endpoint
	// (name to URL); their Steward-Version and Steward-Commit headers are read.
	HTTPServices map[string]string
	// ThirdParty are the direct third-party probes by component name.
	ThirdParty map[string]VersionFunc
	// Release is the pinned release version; empty when unknown.
	Release string
	// ApplianceFile is the file the appliance writes its version to; empty or
	// absent off the appliance.
	ApplianceFile string
	HTTPClient    *http.Client
	// ProbeTimeout, Budget, TTL and UnavailableTTL default to 1 s, 2 s, 60 s
	// and 10 s.
	ProbeTimeout, Budget, TTL, UnavailableTTL time.Duration
	Now                                       func() time.Time
}

// Service serves cached snapshots.
type Service struct {
	cfg     Config
	sf      singleflight.Group
	mu      sync.Mutex
	snap    Snapshot
	expires time.Time
}

// New returns a Service over cfg.
func New(cfg Config) *Service {
	if cfg.ProbeTimeout == 0 {
		cfg.ProbeTimeout = time.Second
	}
	if cfg.Budget == 0 {
		cfg.Budget = 2 * time.Second
	}
	if cfg.TTL == 0 {
		cfg.TTL = time.Minute
	}
	if cfg.UnavailableTTL == 0 {
		cfg.UnavailableTTL = 10 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{cfg: cfg}
}

// Snapshot returns the cached block, refreshing it when it has expired.
func (s *Service) Snapshot(ctx context.Context) Snapshot {
	s.mu.Lock()
	if s.cfg.Now().Before(s.expires) {
		snap := s.snap
		s.mu.Unlock()
		return snap
	}
	s.mu.Unlock()
	v, _, _ := s.sf.Do("snapshot", func() (any, error) {
		snap, failed := s.collect(context.WithoutCancel(ctx))
		ttl := s.cfg.TTL
		if failed {
			ttl = s.cfg.UnavailableTTL
		}
		s.mu.Lock()
		s.snap, s.expires = snap, s.cfg.Now().Add(ttl)
		s.mu.Unlock()
		return snap, nil
	})
	return v.(Snapshot)
}

type serviceResult struct {
	comp Component
	deps map[string]string
}

func (s *Service) collect(ctx context.Context) (Snapshot, bool) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Budget)
	defer cancel()

	bi := buildinfo.Get()
	snap := Snapshot{
		Gateway:   Component{Name: "gateway", Version: clean(bi.Version), Commit: clean(bi.Commit), Status: StatusOK},
		Release:   optional(s.cfg.Release),
		Appliance: s.appliance(),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var services []serviceResult
	add := func(r serviceResult) { mu.Lock(); services = append(services, r); mu.Unlock() }
	for name, conn := range s.cfg.Services {
		wg.Go(func() { add(s.grpcService(ctx, name, conn)) })
	}
	for name, url := range s.cfg.HTTPServices {
		wg.Go(func() { add(s.httpService(ctx, name, url)) })
	}
	third := map[string]Component{}
	for name, fn := range s.cfg.ThirdParty {
		wg.Go(func() {
			c := s.thirdParty(ctx, name, fn)
			mu.Lock()
			third[name] = c
			mu.Unlock()
		})
	}
	wg.Wait()

	failed := false
	for _, r := range services {
		snap.Services = append(snap.Services, r.comp)
		failed = failed || r.comp.Status == StatusUnavailable
	}
	sort.Slice(snap.Services, func(i, j int) bool { return snap.Services[i].Name < snap.Services[j].Name })
	for _, dep := range []string{"postgres", "rabbitmq", "opa"} {
		for _, c := range reported(dep, services) {
			third[c.Name] = c
		}
	}
	for _, c := range third {
		snap.ThirdParty = append(snap.ThirdParty, c)
		failed = failed || c.Status == StatusUnavailable
	}
	sort.Slice(snap.ThirdParty, func(i, j int) bool { return snap.ThirdParty[i].Name < snap.ThirdParty[j].Name })
	return snap, failed
}

func (s *Service) grpcService(ctx context.Context, name string, conn grpc.ClientConnInterface) serviceResult {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ProbeTimeout)
	defer cancel()
	res, err := grpcbuildinfo.Read(ctx, conn, Prefix)
	if err != nil {
		return serviceResult{comp: unavailable(name)}
	}
	deps := map[string]string{}
	for dep, d := range res.Dependencies {
		if v := clean(d.Version); v != Unknown {
			deps[dep] = v
		}
	}
	return serviceResult{comp: Component{Name: name, Version: clean(res.Version), Commit: clean(res.Commit), Status: StatusOK}, deps: deps}
}

func (s *Service) httpService(ctx context.Context, name, url string) serviceResult {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return serviceResult{comp: unavailable(name)}
	}
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return serviceResult{comp: unavailable(name)}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
	return serviceResult{comp: Component{Name: name, Version: clean(resp.Header.Get("Steward-Version")),
		Commit: clean(resp.Header.Get("Steward-Commit")), Status: StatusOK}}
}

func (s *Service) thirdParty(ctx context.Context, name string, fn VersionFunc) Component {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ProbeTimeout)
	defer cancel()
	ch := make(chan string, 1)
	go func() {
		v, err := fn(ctx)
		if err != nil {
			v = ""
		}
		ch <- v
	}()
	select {
	case v := <-ch:
		if v = clean(v); v != Unknown {
			return Component{Name: name, Version: v, Status: StatusOK}
		}
	case <-ctx.Done():
	}
	return unavailable(name)
}

// reported turns the services' dep headers into third-party entries: one
// entry when every service agrees, else one per service.
func reported(dep string, services []serviceResult) []Component {
	byVersion := map[string][]string{}
	for _, r := range services {
		if v, ok := r.deps[dep]; ok {
			byVersion[v] = append(byVersion[v], r.comp.Name)
		}
	}
	if len(byVersion) == 1 {
		for v := range byVersion {
			return []Component{{Name: dep, Version: v, Status: StatusOK}}
		}
	}
	var out []Component
	for v, names := range byVersion {
		for _, n := range names {
			out = append(out, Component{Name: dep + " (" + n + ")", Version: v, Status: StatusOK})
		}
	}
	return out
}

func (s *Service) appliance() string {
	if s.cfg.ApplianceFile == "" {
		return ""
	}
	b, err := os.ReadFile(s.cfg.ApplianceFile)
	if err != nil {
		return ""
	}
	return optional(string(b))
}

// optional is v cleaned, or empty when v is unset or not a version.
func optional(v string) string {
	if v = clean(v); v == Unknown {
		return ""
	}
	return v
}

func unavailable(name string) Component {
	return Component{Name: name, Version: Unavailable, Status: StatusUnavailable}
}

var versionShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// clean keeps a value only when it looks like a version or a commit, so an
// address, a URL or a key=value pair from a probe never leaves the gateway.
func clean(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || !versionShape.MatchString(v) {
		return Unknown
	}
	return v
}

// KratosVersion reads Kratos's admin /version.
func KratosVersion(c *http.Client, adminURL string) VersionFunc {
	return jsonVersion(c, strings.TrimRight(adminURL, "/")+"/version", "version")
}

// PolisVersion reads the version Polis reports on its health endpoint.
func PolisVersion(c *http.Client, healthURL string) VersionFunc {
	return jsonVersion(c, healthURL, "version")
}

// KubernetesVersion reads the API server's discovery /version (gitVersion)
// with the pod's service-account token. It returns nil outside a cluster.
func KubernetesVersion(apiURL, tokenFile string, c *http.Client) VersionFunc {
	if apiURL == "" {
		return nil
	}
	return func(ctx context.Context) (string, error) {
		tok, err := os.ReadFile(tokenFile) // #nosec G304 -- the pod's service-account token path
		if err != nil {
			return "", err
		}
		return getJSON(ctx, c, strings.TrimRight(apiURL, "/")+"/version", "gitVersion", strings.TrimSpace(string(tok)))
	}
}

func jsonVersion(c *http.Client, url, field string) VersionFunc {
	return func(ctx context.Context) (string, error) { return getJSON(ctx, c, url, field, "") }
}

func getJSON(ctx context.Context, c *http.Client, url, field, bearer string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return "", err
	}
	v, _ := body[field].(string)
	return v, nil
}

// ValkeyVersion reads valkey_version, else redis_version, from INFO server.
func ValkeyVersion(info func(ctx context.Context) (string, error)) VersionFunc {
	return func(ctx context.Context) (string, error) {
		out, err := info(ctx)
		if err != nil {
			return "", err
		}
		fields := map[string]string{}
		for _, line := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
				fields[k] = v
			}
		}
		if v := fields["valkey_version"]; v != "" {
			return v, nil
		}
		return fields["redis_version"], nil
	}
}
