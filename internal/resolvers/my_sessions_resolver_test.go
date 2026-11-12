// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"

	"testing"

	log "github.com/Bugs5382/go-log"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/bff"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeReadWithMySessions answers identity's ListMySessions and RevokeMySession
// and records the requests, for the self-service session list (steward-gateway#72).
type fakeReadWithMySessions struct {
	fakeReadClient

	listResp *identityv1.ListMySessionsResponse
	listErr  error
	lastList *identityv1.ListMySessionsRequest

	revokeResp *identityv1.RevokeMySessionResponse
	revokeErr  error
	lastRevoke *identityv1.RevokeMySessionRequest
}

func (f *fakeReadWithMySessions) ListMySessions(_ context.Context, in *identityv1.ListMySessionsRequest, _ ...grpc.CallOption) (*identityv1.ListMySessionsResponse, error) {
	f.lastList = in
	return f.listResp, f.listErr
}

func (f *fakeReadWithMySessions) RevokeMySession(_ context.Context, in *identityv1.RevokeMySessionRequest, _ ...grpc.CallOption) (*identityv1.RevokeMySessionResponse, error) {
	f.lastRevoke = in
	return f.revokeResp, f.revokeErr
}

func TestListMySessionsNilClient(t *testing.T) {
	_, err := resolvers.ListMySessionsResolver(context.Background(), log.Nop(), nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestListMySessionsSendsCurrentSessionAndMarksIt(t *testing.T) {
	read := &fakeReadWithMySessions{listResp: &identityv1.ListMySessionsResponse{Sessions: []*identityv1.Session{
		{SessionId: "k-1", UserId: "u-me", Active: true, Current: true, UserAgent: "UA", ClientIp: "203.0.113.7"},
		{SessionId: "k-2", UserId: "u-me", Active: true},
	}}}
	ctx := bff.WithKratosSessionID(ctxWithRoles(t, "u-me", []string{"author"}), "k-1")
	got, err := resolvers.ListMySessionsResolver(ctx, log.Nop(), read)
	if err != nil {
		t.Fatalf("ListMySessionsResolver: %v", err)
	}
	if read.lastList.GetCurrentSessionId() != "k-1" {
		t.Errorf("current session id forwarded = %q, want k-1", read.lastList.GetCurrentSessionId())
	}
	if len(got) != 2 || !got[0].Current || got[1].Current {
		t.Fatalf("current flags wrong: %+v", got)
	}
	if got[0].ClientIP == nil || *got[0].ClientIP != "203.0.113.7" {
		t.Errorf("clientIp not mapped")
	}
}

func TestListMySessionsRelaysIdentityError(t *testing.T) {
	read := &fakeReadWithMySessions{listErr: status.Error(codes.Unavailable, "sign-in service down")}
	_, err := resolvers.ListMySessionsResolver(ctxWithUser(t, "u-me"), log.Nop(), read)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable relayed, got %v", err)
	}
}

func TestRevokeMySessionNilClient(t *testing.T) {
	_, err := resolvers.RevokeMySessionResolver(context.Background(), log.Nop(), nil, "k-2")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestRevokeMySessionForwardsBothIDs(t *testing.T) {
	read := &fakeReadWithMySessions{revokeResp: &identityv1.RevokeMySessionResponse{Revoked: 1}}
	ctx := bff.WithKratosSessionID(ctxWithUser(t, "u-me"), "k-1")
	n, err := resolvers.RevokeMySessionResolver(ctx, log.Nop(), read, "k-2")
	if err != nil {
		t.Fatalf("RevokeMySessionResolver: %v", err)
	}
	if n != 1 {
		t.Errorf("revoked = %d, want 1", n)
	}
	if read.lastRevoke.GetSessionId() != "k-2" || read.lastRevoke.GetCurrentSessionId() != "k-1" {
		t.Errorf("request = %v", read.lastRevoke)
	}
}

func TestRevokeMySessionRelaysCurrentSessionRefusal(t *testing.T) {
	read := &fakeReadWithMySessions{revokeErr: status.Error(codes.FailedPrecondition, "current session")}
	ctx := bff.WithKratosSessionID(ctxWithUser(t, "u-me"), "k-1")
	_, err := resolvers.RevokeMySessionResolver(ctx, log.Nop(), read, "k-1")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition relayed, got %v", err)
	}
}
