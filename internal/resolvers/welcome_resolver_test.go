// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

type fakeWelcomeClient struct {
	obligationsv1.WelcomeServiceClient
	lastReq *obligationsv1.ResendWelcomeRequest
	resp    *obligationsv1.ResendWelcomeResponse
	err     error
}

func (f *fakeWelcomeClient) ResendWelcome(_ context.Context, in *obligationsv1.ResendWelcomeRequest, _ ...grpc.CallOption) (*obligationsv1.ResendWelcomeResponse, error) {
	f.lastReq = in
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &obligationsv1.ResendWelcomeResponse{Sent: true}, nil
}

func TestResendWelcomeEmailResolverHappyPath(t *testing.T) {
	wc := &fakeWelcomeClient{}
	ok, err := resolvers.ResendWelcomeEmailResolver(
		ctxWithRoles(t, "u-admin", []string{"site-admin"}), wc, "u-1")
	if err != nil {
		t.Fatalf("ResendWelcomeEmailResolver: %v", err)
	}
	if !ok {
		t.Error("expected sent=true")
	}
	if wc.lastReq == nil || wc.lastReq.UserId != "u-1" {
		t.Errorf("ResendWelcome not called correctly: %+v", wc.lastReq)
	}
}

func TestResendWelcomeEmailResolverPropagatesSentFalse(t *testing.T) {
	wc := &fakeWelcomeClient{resp: &obligationsv1.ResendWelcomeResponse{Sent: false}}
	ok, err := resolvers.ResendWelcomeEmailResolver(
		ctxWithRoles(t, "u-admin", []string{"site-admin"}), wc, "u-1")
	if err != nil {
		t.Fatalf("ResendWelcomeEmailResolver: %v", err)
	}
	if ok {
		t.Error("expected sent=false to propagate")
	}
}

func TestResendWelcomeEmailResolverUnavailableClient(t *testing.T) {
	if _, err := resolvers.ResendWelcomeEmailResolver(
		ctxWithRoles(t, "u-admin", []string{"site-admin"}), nil, "u-1"); err == nil {
		t.Fatal("expected error when compliance-notify client is nil")
	}
}

func TestResendWelcomeEmailResolverServiceError(t *testing.T) {
	wc := &fakeWelcomeClient{err: errors.New("smtp down")}
	if _, err := resolvers.ResendWelcomeEmailResolver(
		ctxWithRoles(t, "u-admin", []string{"site-admin"}), wc, "u-1"); err == nil {
		t.Fatal("expected error to propagate from the service")
	}
}
