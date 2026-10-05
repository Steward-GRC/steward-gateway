// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// recordingHealth is a health server that records the incoming metadata.
type recordingHealth struct {
	*health.Server
	md chan metadata.MD
}

func (h *recordingHealth) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	h.md <- md
	return h.Server.Check(ctx, req)
}

func serve(t *testing.T) (string, *recordingHealth) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	h := &recordingHealth{Server: health.NewServer(), md: make(chan metadata.MD, 4)}
	healthpb.RegisterHealthServer(srv, h)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), h
}

func addrsFor(addr string) map[string]string {
	m := map[string]string{}
	for _, n := range Names() {
		m[n] = addr
	}
	return m
}

func TestEveryCallCarriesTheTokenReadAgainAndTheActor(t *testing.T) {
	addr, h := serve(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("first-token\n"), 0o600))

	opts, err := DialOptions(tokenFile)
	require.NoError(t, err)
	conns, err := Dial(addrsFor(addr), opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conns.Close() })

	ctx := grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: "u-bob", Impersonator: "u-admin"})
	hc := healthpb.NewHealthClient(conns[Core])
	_, err = hc.Check(ctx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	md := <-h.md
	assert.Equal(t, []string{"Bearer first-token"}, md.Get("authorization"))
	assert.NotEmpty(t, md.Get(grpcactor.MetadataKey), "the actor travels")

	require.NoError(t, os.WriteFile(tokenFile, []byte("rotated-token"), 0o600))
	_, err = hc.Check(ctx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	md = <-h.md
	assert.Equal(t, []string{"Bearer rotated-token"}, md.Get("authorization"), "the token is read again on every call")
}

func TestMissingTokenFileFailsClosed(t *testing.T) {
	_, err := DialOptions(filepath.Join(t.TempDir(), "absent"))
	require.Error(t, err)
}

func TestDisabledSendsNoToken(t *testing.T) {
	addr, h := serve(t)
	opts, err := DialOptions("")
	require.NoError(t, err)
	conns, err := Dial(addrsFor(addr), opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conns.Close() })
	_, err = healthpb.NewHealthClient(conns[Identity]).Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Empty(t, (<-h.md).Get("authorization"))
}

func TestDialNeedsEveryAddress(t *testing.T) {
	_, err := Dial(map[string]string{Core: "127.0.0.1:1"}, nil)
	require.Error(t, err)
}

func TestNewClientsNeedsEveryConnection(t *testing.T) {
	_, err := NewClients(Conns{})
	require.Error(t, err)
}
