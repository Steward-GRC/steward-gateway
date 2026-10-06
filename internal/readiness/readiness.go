// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package readiness builds the gateway's /livez and /readyz on go-buildinfo.
// Valkey (the sessions) and Kratos (every sign-in and session check) are
// required: without them nobody can be served. RabbitMQ (live updates), Polis
// (SSO) and the backend services are optional, so one backend outage never
// takes the whole edge out; they report degraded.
package readiness

import (
	"context"
	"net/http"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	"github.com/Bugs5382/go-buildinfo/httpbuildinfo"
	log "github.com/Bugs5382/go-log"
	redis "github.com/Bugs5382/go-redis"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// Prefix is the build-info header prefix every Steward component uses.
const Prefix = "steward"

// Deps are the dependencies readiness checks.
type Deps struct {
	Valkey *redis.Client
	// KratosReady is Kratos's readiness URL (its admin /health/ready).
	KratosReady string
	// PolisHealth is Polis's health URL; empty when SSO is off.
	PolisHealth string
	// RabbitMQ reports the live-update connection; nil when there is none.
	RabbitMQ func(context.Context) error
	// Backends are the service connections, by name, checked with the
	// standard gRPC health check.
	Backends map[string]*grpc.ClientConn
	Logger   log.Logger
	// TTL and Timeout default to 5 and 2 seconds.
	TTL, Timeout time.Duration
}

// New returns the probe handler and the checker behind it.
func New(d Deps) (*httpbuildinfo.Handler, error) {
	if d.TTL == 0 {
		d.TTL = 5 * time.Second
	}
	if d.Timeout == 0 {
		d.Timeout = 2 * time.Second
	}
	opts := []health.Option{health.WithTTL(d.TTL), health.WithTimeout(d.Timeout)}
	if d.Logger != nil {
		opts = append(opts, health.WithLogger(d.Logger))
	}
	c := health.New(opts...)
	httpc := &http.Client{Timeout: d.Timeout}
	deps := []health.Dependency{
		{Name: "valkey", Required: true, Check: func(ctx context.Context) error { return d.Valkey.Redis().Ping(ctx).Err() }},
		{Name: "kratos", Required: true, Check: health.CheckHTTP(httpc, d.KratosReady)},
	}
	if d.PolisHealth != "" {
		deps = append(deps, health.Dependency{Name: "polis", Check: health.CheckHTTP(httpc, d.PolisHealth)})
	}
	if d.RabbitMQ != nil {
		deps = append(deps, health.Dependency{Name: "rabbitmq", Check: d.RabbitMQ})
	}
	for name, conn := range d.Backends {
		hc := healthpb.NewHealthClient(conn)
		deps = append(deps, health.Dependency{Name: name, Check: func(ctx context.Context) error {
			_, err := hc.Check(ctx, &healthpb.HealthCheckRequest{})
			return err
		}})
	}
	if err := c.Register(deps...); err != nil {
		return nil, err
	}
	return httpbuildinfo.New(httpbuildinfo.WithPrefix(Prefix), httpbuildinfo.WithChecker(c))
}
