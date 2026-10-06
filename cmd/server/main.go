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

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	log "github.com/Bugs5382/go-log"
	gootel "github.com/Bugs5382/go-otel"
	"github.com/Bugs5382/go-rabbitmq"
	redis "github.com/Bugs5382/go-redis"
	"github.com/Bugs5382/go-redis/ratelimit"
	"google.golang.org/grpc"

	"github.com/Steward-GRC/steward-gateway/internal/aijobs"
	"github.com/Steward-GRC/steward-gateway/internal/assets"
	"github.com/Steward-GRC/steward-gateway/internal/audit"
	"github.com/Steward-GRC/steward-gateway/internal/backend"
	"github.com/Steward-GRC/steward-gateway/internal/bff"
	"github.com/Steward-GRC/steward-gateway/internal/collabws"
	"github.com/Steward-GRC/steward-gateway/internal/config"
	"github.com/Steward-GRC/steward-gateway/internal/diagnostics"
	"github.com/Steward-GRC/steward-gateway/internal/documents"
	"github.com/Steward-GRC/steward-gateway/internal/live"
	"github.com/Steward-GRC/steward-gateway/internal/maintenance"
	"github.com/Steward-GRC/steward-gateway/internal/notifyunsub"
	"github.com/Steward-GRC/steward-gateway/internal/passwordreset"
	"github.com/Steward-GRC/steward-gateway/internal/readiness"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"github.com/Steward-GRC/steward-gateway/internal/server"
	"github.com/Steward-GRC/steward-gateway/internal/setup"
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

	store := bff.NewStore(valkey, cfg.SessionTTL)

	var rabbit *rabbitmq.Conn
	var emitter resolvers.AuditEmitter
	bus, broker := live.NewBus(), aijobs.NewBroker()
	if cfg.RabbitMQURL != "" {
		rabbit, err = rabbitmq.Connect(ctx, cfg.RabbitMQURL, rabbitmq.WithLogger(rabbitLogger{logger}))
		if err != nil {
			return fmt.Errorf("rabbitmq: %w", err)
		}
		defer func() { _ = rabbit.Close() }()
		pub := rabbit.NewPublisher(audit.Exchange,
			rabbitmq.WithExchangeDeclare(rabbitmq.ExchangeConfig{Name: audit.Exchange, Kind: "topic", Durable: true}),
			rabbitmq.WithDefaultContentType(audit.ContentType))
		emitter = audit.New(publisher{pub})
		go func() {
			if err := live.RunConsumer(ctx, rabbit, bus, logger); err != nil && ctx.Err() == nil {
				logger.Error(err, "gateway: live updates consumer stopped")
			}
		}()
		go func() {
			if err := aijobs.Consume(ctx, rabbit, broker); err != nil && ctx.Err() == nil {
				logger.Error(err, "gateway: AI job results consumer stopped")
			}
		}()
	} else {
		logger.Warn("gateway: RABBITMQ_URL is empty; live updates, AI job results and act-as audit events are off")
	}

	httpc := &http.Client{Timeout: 2 * time.Second}
	diag := diagnostics.New(diagnosticsConfig(cfg, conns, valkey, httpc))
	root := (&resolvers.Resolver{
		AllowHardDelete:    cfg.AllowTemplateDelete,
		Diagnostics:        diag,
		SessionStore:       store,
		AuditEmitter:       emitter,
		Log:                logger,
		Bus:                bus,
		AIJobBroker:        broker,
		AIJobContentReader: aijobs.NewContentReader(valkey.Redis()),
		ReportLimiter:      ratelimit.New(valkey, ratelimit.WithPrefix("gateway:")),
	}).FromClients(clients)

	var rabbitCheck func(context.Context) error
	if rabbit != nil {
		rabbitCheck = func(context.Context) error {
			if !rabbit.Healthy() {
				return errors.New("rabbitmq connection is down")
			}
			return nil
		}
	}
	probes, err := readiness.New(readiness.Deps{
		Valkey:      valkey,
		KratosReady: cfg.KratosAdminURL + "/health/ready",
		PolisHealth: polisHealth(cfg.PolisURL),
		RabbitMQ:    rabbitCheck,
		Backends:    conns,
		Logger:      logger,
	})
	if err != nil {
		return err
	}

	auth := &bff.Handler{
		Store:             store,
		TTL:               cfg.SessionTTL,
		Secure:            !cfg.Auth.CookieInsecure,
		Auth:              bff.NewKratosClient(cfg.KratosPublicURL, cfg.KratosAdminURL).WithLogger(logger),
		Identity:          clients.IdentityRead,
		Pending:           store,
		PasskeyLogin:      passkeyStore(cfg.Auth.PasskeyLogin, store),
		SSOState:          store,
		SSOTestLink:       store,
		SSORedirectBase:   cfg.Auth.SSORedirectBase,
		TestLinkTTL:       cfg.Auth.SSOTestLinkTTL,
		IdPTestRecorder:   bff.RecordIdPTestWith(clients.IdentitySSOAdmin),
		BreakGlassPublish: bff.RecordBreakGlassWith(clients.IdentitySSOAdmin, logger),
		MFA: bff.MFAConfig{
			Mode: cfg.Auth.MFAMode, EdgeHeader: cfg.Auth.MFAEdgeHeader,
			EdgePublicValue: cfg.Auth.MFAEdgePublicValue, RequireStrong: cfg.Auth.MFARequireStrong,
		},
		Log: logger,
	}
	if cfg.Auth.PolisPublicURL != "" {
		auth.Polis = bff.NewPolisClient(cfg.Auth.PolisPublicURL, cfg.Auth.PolisIssuerURL, cfg.Auth.PolisProduct)
	}
	session := func(next http.Handler) http.Handler { return auth.Authenticate(auth.ActAs(next)) }

	gate := maintenance.NewGate(clients.Settings, cfg.Auth.MaintenanceCacheTTL)
	gql := server.NewGraphQL(resolvers.NewExecutableSchema(resolvers.Config{Resolvers: root}), server.GraphQLOptions{
		Logger:         logger,
		AllowedOrigins: cfg.AllowedOrigins,
		WebsocketInit:  websocketInit(auth),
		OperationMiddleware: []graphql.OperationMiddleware{
			gate.Middleware(),
			resolvers.ImpersonationDenylistMiddleware(),
		},
	})
	assetsH := assets.New(clients.Asset, logger)

	mux := http.NewServeMux()
	mux.Handle("POST /query", bff.PublicOps(session(gql), gql))
	mux.Handle("GET /query", server.WithRequest(gql))
	mux.Handle("POST /documents/extract", session(http.HandlerFunc(documents.ExtractHandler)))
	mux.Handle("POST /documents/validate-url", session(http.HandlerFunc(documents.ValidateURLHandler)))
	mux.Handle("POST /api/assets", session(http.HandlerFunc(assetsH.Upload)))
	mux.Handle("GET /api/assets/{id}", auth.AuthenticateSafeRead(auth.ActAs(http.HandlerFunc(assetsH.Serve))))
	mux.Handle(collabws.RoutePattern, collabws.New(collabws.Config{
		Upstream:        cfg.CollabUpstream,
		AllowedOrigins:  cfg.AllowedOrigins,
		MaxMessageBytes: cfg.CollabMaxMessageBytes,
		IdleTimeout:     cfg.CollabIdleTimeout,
	}, auth.HasSession, logger))
	auth.Register(mux)
	passwordreset.New(clients.IdentityRead,
		passwordreset.WithLogger(logger),
		passwordreset.WithDefaultLoginMethod(cfg.Auth.DefaultLoginMethod),
		passwordreset.WithPasskeyLogin(cfg.Auth.PasskeyLogin),
		passwordreset.WithReportProblemURL(cfg.Auth.ReportProblemURL),
	).Register(mux)
	setup.New(clients.IdentityRead, cfg.Auth.SetupToken).WithLogger(logger).WithSSOAdmin(clients.IdentitySSOAdmin).Register(mux)
	gate.Register(mux)
	if cfg.Auth.NotifySecret != "" {
		verifier, err := notifyunsub.NewVerifier(cfg.Auth.NotifySecret)
		if err != nil {
			return fmt.Errorf("notify links: %w", err)
		}
		notifyunsub.New(verifier, clients.NotifPref, cfg.Auth.NotifyPreferencesURL).Register(mux)
		notifyunsub.NewVerifyEmail(verifier, clients.IdentityRead).WithLogger(logger).Register(mux)
	}
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

// websocketInit authenticates a subscription from its upgrade request's
// session cookie and the CSRF token in the connection_init payload.
func websocketInit(auth *bff.Handler) transport.WebsocketInitFunc {
	return func(ctx context.Context, payload transport.InitPayload) (context.Context, *transport.InitPayload, error) {
		r, ok := server.RequestFromContext(ctx)
		if !ok {
			return ctx, nil, bff.ErrWebsocketUnauthorized
		}
		csrf, _ := payload["csrfToken"].(string)
		ctx, err := auth.WebsocketInit(ctx, r, csrf)
		return ctx, nil, err
	}
}

func passkeyStore(enabled bool, s *bff.Store) bff.PasskeyLoginStore {
	if !enabled {
		return nil
	}
	return s
}

// publisher narrows a go-rabbitmq publisher to the Publish the emitter uses.
type publisher struct{ p *rabbitmq.Publisher }

func (p publisher) Publish(ctx context.Context, routingKey string, body []byte) error {
	return p.p.Publish(ctx, routingKey, body)
}

type rabbitLogger struct{ l log.Logger }

func (r rabbitLogger) Debugf(f string, a ...any) { r.l.Debug(fmt.Sprintf(f, a...)) }
func (r rabbitLogger) Infof(f string, a ...any)  { r.l.Info(fmt.Sprintf(f, a...)) }
func (r rabbitLogger) Warnf(f string, a ...any)  { r.l.Warn(fmt.Sprintf(f, a...)) }
func (r rabbitLogger) Errorf(f string, a ...any) { r.l.Error(nil, fmt.Sprintf(f, a...)) }

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
