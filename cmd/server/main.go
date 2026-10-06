// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Command server runs the gateway: the browser-facing GraphQL edge over every
// Steward service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	gootel "github.com/Bugs5382/go-otel"
	redis "github.com/Bugs5382/go-redis"
	"google.golang.org/grpc"

	"github.com/Steward-GRC/steward-gateway/internal/assets"
	"github.com/Steward-GRC/steward-gateway/internal/backend"
	"github.com/Steward-GRC/steward-gateway/internal/collabws"
	"github.com/Steward-GRC/steward-gateway/internal/config"
	"github.com/Steward-GRC/steward-gateway/internal/diagnostics"
	"github.com/Steward-GRC/steward-gateway/internal/documents"
	"github.com/Steward-GRC/steward-gateway/internal/readiness"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"github.com/Steward-GRC/steward-gateway/internal/server"
	"github.com/Steward-GRC/steward-gateway/internal/workloadauth"
)

const serviceName = "steward-gateway"

func main() {
	if err := run(); err != nil {
		log.NewLogger(serviceName).Fatal(err, "gateway: start-up failed")
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := log.NewLogger(serviceName)

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	otelShutdown, err := gootel.Init(ctx, serviceName, cfg.OTLPEndpoint)
	if err != nil {
		return fmt.Errorf("otel: %w", err)
	}
	defer func() { _ = otelShutdown(context.Background()) }()
	if !cfg.WorkloadAuth {
		go workloadauth.WarnDisabled(ctx, logger, workloadauth.DisabledWarnInterval)
	}

	valkey, err := redis.Connect(ctx, redis.WithAddr(cfg.ValkeyAddr), redis.WithPassword(cfg.ValkeyPassword))
	if err != nil {
		return fmt.Errorf("valkey: %w", err)
	}
	defer func() { _ = valkey.Close() }()

	dialOpts, err := backend.DialOptions(cfg.TokenFile)
	if err != nil {
		return fmt.Errorf("workload token: %w", err)
	}
	conns, err := backend.Dial(cfg.Backends, dialOpts)
	if err != nil {
		return err
	}
	defer func() { _ = conns.Close() }()
	clients, err := backend.NewClients(conns)
	if err != nil {
		return err
	}

	httpc := &http.Client{Timeout: 2 * time.Second}
	diag := diagnostics.New(diagnosticsConfig(cfg, conns, valkey, httpc))
	root := (&resolvers.Resolver{AllowHardDelete: cfg.AllowTemplateDelete, Diagnostics: diag}).FromClients(clients)

	probes, err := readiness.New(readiness.Deps{
		Valkey:      valkey,
		KratosReady: cfg.KratosAdminURL + "/health/ready",
		PolisHealth: polisHealth(cfg.PolisURL),
		Backends:    conns,
		Logger:      logger,
	})
	if err != nil {
		return err
	}

	// The sign-in layer: every protected route goes through session, which
	// resolves the cookie and the CSRF token to the signed-in user. Until it is
	// wired every protected route is refused.
	session := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		})
	}
	hasSession := func(*http.Request) bool { return false }

	gql := server.NewGraphQL(resolvers.NewExecutableSchema(resolvers.Config{Resolvers: root}), server.GraphQLOptions{
		Logger:         logger,
		AllowedOrigins: cfg.AllowedOrigins,
	})
	assetsH := assets.New(clients.Asset, logger)

	mux := http.NewServeMux()
	mux.Handle("POST /query", session(gql))
	mux.Handle("GET /query", server.WithRequest(gql))
	mux.Handle("POST /documents/extract", session(http.HandlerFunc(documents.ExtractHandler)))
	mux.Handle("POST /documents/validate-url", session(http.HandlerFunc(documents.ValidateURLHandler)))
	mux.Handle("POST /api/assets", session(http.HandlerFunc(assetsH.Upload)))
	mux.Handle("GET /api/assets/{id}", session(http.HandlerFunc(assetsH.Serve)))
	mux.Handle(collabws.RoutePattern, collabws.New(collabws.Config{
		Upstream:        cfg.CollabUpstream,
		AllowedOrigins:  cfg.AllowedOrigins,
		MaxMessageBytes: cfg.CollabMaxMessageBytes,
		IdleTimeout:     cfg.CollabIdleTimeout,
	}, hasSession, logger))
	mux.Handle("GET /livez", probes.Livez())
	mux.Handle("GET /readyz", probes.Readyz())

	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: server.Wrap(mux, logger), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Info("gateway: listening", log.F("addr", cfg.HTTPAddr))
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// kubeClient trusts the cluster CA the pod's service account carries.
func kubeClient() *http.Client {
	pool := x509.NewCertPool()
	if pem, err := os.ReadFile(serviceAccountDir + "/ca.crt"); err == nil {
		pool.AppendCertsFromPEM(pem)
	}
	return &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
}

func polisHealth(polisURL string) string {
	if polisURL == "" {
		return ""
	}
	return polisURL + "/api/health"
}

func diagnosticsConfig(cfg config.Config, conns backend.Conns, valkey *redis.Client, httpc *http.Client) diagnostics.Config {
	services := map[string]grpc.ClientConnInterface{}
	for n, c := range conns {
		services[n] = c
	}
	third := map[string]diagnostics.VersionFunc{
		"kratos": diagnostics.KratosVersion(httpc, cfg.KratosAdminURL),
		"valkey": diagnostics.ValkeyVersion(func(ctx context.Context) (string, error) {
			return valkey.Redis().Info(ctx, "server").Result()
		}),
	}
	if h := polisHealth(cfg.PolisURL); h != "" {
		third["polis"] = diagnostics.PolisVersion(httpc, h)
	}
	if k := diagnostics.KubernetesVersion(cfg.KubernetesAPI, serviceAccountDir+"/token", kubeClient()); k != nil {
		third["kubernetes"] = k
	}
	return diagnostics.Config{
		Services:      services,
		HTTPServices:  cfg.HTTPProbes,
		ThirdParty:    third,
		Release:       cfg.Release,
		ApplianceFile: cfg.ApplianceVersionFile,
		HTTPClient:    httpc,
	}
}
