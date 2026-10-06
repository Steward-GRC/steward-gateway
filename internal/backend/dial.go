// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"fmt"
	"time"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	gootel "github.com/Bugs5382/go-otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Steward-GRC/steward-gateway/internal/workloadauth"
)

// serviceConfig spreads calls over every backend replica behind a headless
// Service, so a rolling restart never sends every call to one pod.
const serviceConfig = `{"loadBalancingConfig":[{"round_robin":{}}]}`

// DialOptions are the options for every backend connection. Each call carries
// the gateway's projected service-account token, read from tokenFile on every
// call, and go-grpc-actor puts the request's Actor on it. An empty tokenFile
// is WORKLOAD_AUTH=disabled and sends no token. A token file that can't be
// read now fails, so a missing mount stops the boot instead of every call.
func DialOptions(tokenFile string) ([]grpc.DialOption, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(gootel.GRPCClientStatsHandler()),
		grpc.WithChainUnaryInterceptor(grpcactor.UnaryClientInterceptor()),
		grpc.WithChainStreamInterceptor(grpcactor.StreamClientInterceptor()),
		grpc.WithDefaultServiceConfig(serviceConfig),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: 250 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 3 * time.Second},
			MinConnectTimeout: 3 * time.Second,
		}),
	}
	if tokenFile == "" {
		return opts, nil
	}
	token, _, err := workloadauth.DialOptionFromEnv(func(k string) string {
		if k == workloadauth.EnvTokenFile {
			return tokenFile
		}
		return ""
	})
	if err != nil {
		return nil, err
	}
	return append(opts, token), nil
}

// Dial opens one lazy connection per address. addrs maps each name in Names
// to its host:port; a connection only fails when it is used, so one backend
// that is down never stops the gateway from serving the rest.
func Dial(addrs map[string]string, opts []grpc.DialOption) (Conns, error) {
	conns := Conns{}
	for _, n := range Names() {
		addr := addrs[n]
		if addr == "" {
			_ = conns.Close()
			return nil, fmt.Errorf("backend: no address for %s", n)
		}
		conn, err := grpc.NewClient("dns:///"+addr, opts...)
		if err != nil {
			_ = conns.Close()
			return nil, fmt.Errorf("backend: dial %s: %w", n, err)
		}
		conns[n] = conn
	}
	return conns, nil
}
