// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

type headerHealth struct {
	*health.Server
	md metadata.MD
}

func (h *headerHealth) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	if h.md != nil {
		_ = grpc.SetHeader(ctx, h.md)
	}
	return h.Server.Check(ctx, req)
}

func serve(t *testing.T, md metadata.MD) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	healthpb.RegisterHealthServer(srv, &headerHealth{Server: health.NewServer(), md: md})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func deadConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := lis.Addr().String()
	require.NoError(t, lis.Close())
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func find(cs []Component, name string) (Component, bool) {
	for _, c := range cs {
		if c.Name == name {
			return c, true
		}
	}
	return Component{}, false
}

func TestServicesReportTheirBuildAndDependencies(t *testing.T) {
	core := serve(t, metadata.Pairs("steward-version", "v0.1.0", "steward-commit", "abc1234", "steward-dep-postgres", "17.2", "steward-dep-opa", "v1.4.0"))
	identity := serve(t, metadata.Pairs("steward-version", "v0.1.0", "steward-commit", "def5678", "steward-dep-postgres", "17.2"))
	s := New(Config{Services: map[string]grpc.ClientConnInterface{"core": core, "identity": identity}})

	snap := s.Snapshot(context.Background())
	c, ok := find(snap.Services, "core")
	require.True(t, ok)
	assert.Equal(t, Component{Name: "core", Version: "v0.1.0", Commit: "abc1234", Status: StatusOK}, c)
	pg, ok := find(snap.ThirdParty, "postgres")
	require.True(t, ok, "one value when every service agrees")
	assert.Equal(t, "17.2", pg.Version)
	opa, ok := find(snap.ThirdParty, "opa")
	require.True(t, ok)
	assert.Equal(t, "v1.4.0", opa.Version)
	assert.Equal(t, "gateway", snap.Gateway.Name)
}

func TestDisagreeingDependencyVersionsAreListedPerService(t *testing.T) {
	a := serve(t, metadata.Pairs("steward-dep-postgres", "17.2"))
	b := serve(t, metadata.Pairs("steward-dep-postgres", "16.4"))
	snap := New(Config{Services: map[string]grpc.ClientConnInterface{"core": a, "workflow": b}}).Snapshot(context.Background())
	_, ok := find(snap.ThirdParty, "postgres (core)")
	assert.True(t, ok)
	_, ok = find(snap.ThirdParty, "postgres (workflow)")
	assert.True(t, ok)
}

func TestServiceWithoutHeadersIsUnknown(t *testing.T) {
	snap := New(Config{Services: map[string]grpc.ClientConnInterface{"audit": serve(t, nil)}}).Snapshot(context.Background())
	c, _ := find(snap.Services, "audit")
	assert.Equal(t, Component{Name: "audit", Version: Unknown, Commit: Unknown, Status: StatusOK}, c)
}

func TestDownServiceIsUnavailableAndTheReadSucceeds(t *testing.T) {
	snap := New(Config{Services: map[string]grpc.ClientConnInterface{"delivery": deadConn(t)}, ProbeTimeout: 100 * time.Millisecond}).Snapshot(context.Background())
	c, _ := find(snap.Services, "delivery")
	assert.Equal(t, StatusUnavailable, c.Status)
	assert.Equal(t, Unavailable, c.Version)
}

func TestEachThirdPartyDownOrSlowIsUnavailableWithinTheBudget(t *testing.T) {
	slow := func(ctx context.Context) (string, error) { <-ctx.Done(); return "", ctx.Err() }
	failing := func(context.Context) (string, error) {
		return "", errors.New("dial tcp 192.0.2.44:4434: connection refused postgres://app:hunter2@db.example.org")
	}
	ok := func(context.Context) (string, error) { return "v1.3.0", nil }
	for name, cfg := range map[string]map[string]VersionFunc{
		"one slow":  {"kratos": slow, "valkey": ok},
		"one fails": {"kratos": failing, "valkey": ok},
		"all down":  {"kratos": slow, "valkey": failing, "polis": slow, "kubernetes": failing},
	} {
		t.Run(name, func(t *testing.T) {
			s := New(Config{ThirdParty: cfg, ProbeTimeout: 100 * time.Millisecond, Budget: 300 * time.Millisecond})
			start := time.Now()
			snap := s.Snapshot(context.Background())
			assert.Less(t, time.Since(start), 400*time.Millisecond)
			for n := range cfg {
				c, found := find(snap.ThirdParty, n)
				require.True(t, found, n)
				if n == "valkey" && name != "all down" {
					assert.Equal(t, StatusOK, c.Status)
					continue
				}
				assert.Equal(t, StatusUnavailable, c.Status, n)
			}
			b, _ := json.Marshal(snap)
			for _, canary := range []string{"192.0.2.44", "hunter2", "db.example.org", "connection refused", "postgres://"} {
				assert.NotContains(t, string(b), canary)
			}
		})
	}
}

func TestProbeAnswersThatAreNotVersionsNeverLeave(t *testing.T) {
	leaky := func(context.Context) (string, error) { return "https://kratos-admin.example.org:4434/ token=abc", nil }
	snap := New(Config{ThirdParty: map[string]VersionFunc{"kratos": leaky}}).Snapshot(context.Background())
	b, _ := json.Marshal(snap)
	assert.NotContains(t, string(b), "kratos-admin")
	assert.NotContains(t, string(b), "token=abc")
}

func TestSnapshotsAreCachedAndFailuresExpireSooner(t *testing.T) {
	var calls atomic.Int32
	now := time.Unix(0, 0)
	fail := true
	probe := func(context.Context) (string, error) {
		calls.Add(1)
		if fail {
			return "", errors.New("down")
		}
		return "v1.0.0", nil
	}
	s := New(Config{ThirdParty: map[string]VersionFunc{"kratos": probe}, Now: func() time.Time { return now }})
	s.Snapshot(context.Background())
	s.Snapshot(context.Background())
	assert.Equal(t, int32(1), calls.Load())

	now = now.Add(11 * time.Second)
	fail = false
	s.Snapshot(context.Background())
	assert.Equal(t, int32(2), calls.Load(), "an unavailable entry is retried after 10 seconds")

	now = now.Add(30 * time.Second)
	s.Snapshot(context.Background())
	assert.Equal(t, int32(2), calls.Load(), "a good block is kept for 60 seconds")
}

func TestApplianceAndRelease(t *testing.T) {
	f := filepath.Join(t.TempDir(), "version")
	require.NoError(t, os.WriteFile(f, []byte("v0.1.0\n"), 0o600))
	snap := New(Config{ApplianceFile: f, Release: "v0.1.0"}).Snapshot(context.Background())
	assert.Equal(t, "v0.1.0", snap.Appliance)
	assert.Equal(t, "v0.1.0", snap.Release)

	snap = New(Config{ApplianceFile: filepath.Join(t.TempDir(), "absent")}).Snapshot(context.Background())
	assert.Empty(t, snap.Appliance, "absent off the appliance")
	assert.Empty(t, snap.Release)
}

func TestValkeyVersion(t *testing.T) {
	v, err := ValkeyVersion(func(context.Context) (string, error) {
		return "# Server\r\nredis_version:7.2.4\r\nvalkey_version:8.0.1\r\n", nil
	})(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "8.0.1", v)
	v, _ = ValkeyVersion(func(context.Context) (string, error) { return "redis_version:7.2.4\r\n", nil })(context.Background())
	assert.Equal(t, "7.2.4", v)
}
