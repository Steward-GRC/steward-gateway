// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeAdminWithSessions struct {
	fakeAdminClient

	listResp    *identityv1.ListUserSessionsResponse
	listErr     error
	lastListReq *identityv1.ListUserSessionsRequest

	revokeUserResp    *identityv1.RevokeUserSessionsResponse
	revokeUserErr     error
	lastRevokeUserReq *identityv1.RevokeUserSessionsRequest
}

func (f *fakeAdminWithSessions) ListUserSessions(_ context.Context, in *identityv1.ListUserSessionsRequest, _ ...grpc.CallOption) (*identityv1.ListUserSessionsResponse, error) {
	f.lastListReq = in
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResp, nil
}

func (f *fakeAdminWithSessions) RevokeUserSessions(_ context.Context, in *identityv1.RevokeUserSessionsRequest, _ ...grpc.CallOption) (*identityv1.RevokeUserSessionsResponse, error) {
	f.lastRevokeUserReq = in
	if f.revokeUserErr != nil {
		return nil, f.revokeUserErr
	}
	return f.revokeUserResp, nil
}

type fakeReadWithRevokeMy struct {
	fakeReadClient

	revokeMyResp *identityv1.RevokeMySessionsResponse
	revokeMyErr  error
}

func (f *fakeReadWithRevokeMy) RevokeMySessions(_ context.Context, _ *identityv1.RevokeMySessionsRequest, _ ...grpc.CallOption) (*identityv1.RevokeMySessionsResponse, error) {
	if f.revokeMyErr != nil {
		return nil, f.revokeMyErr
	}
	return f.revokeMyResp, nil
}

func TestListUserSessionsRequiresSiteAdmin(t *testing.T) {
	admin := &fakeAdminWithSessions{}
	_, err := resolvers.ListUserSessionsResolver(context.Background(), admin, "u-1")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated without claims, got %v", status.Code(err))
	}
}

func TestListUserSessionsNonAdminDenied(t *testing.T) {
	admin := &fakeAdminWithSessions{}
	_, err := resolvers.ListUserSessionsResolver(ctxWithRoles(t, "u-1", []string{"author"}), admin, "u-1")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for non-admin, got %v", status.Code(err))
	}
}

func TestListUserSessionsNilAdminClient(t *testing.T) {
	_, err := resolvers.ListUserSessionsResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), nil, "u-1")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable for nil client, got %v", status.Code(err))
	}
}

func TestListUserSessionsHappyPath(t *testing.T) {
	admin := &fakeAdminWithSessions{
		listResp: &identityv1.ListUserSessionsResponse{
			Sessions: []*identityv1.Session{
				{
					SessionId:       "sid-1",
					UserId:          "u-1",
					IssuedAt:        "2026-06-25T09:00:00Z",
					AuthenticatedAt: "2026-06-25T09:30:00Z",
					ExpiresAt:       "2026-06-25T17:00:00Z",
					Active:          true,
					UserAgent:       "Mozilla/5.0",
					ClientIp:        "203.0.113.7",
				},
				{
					SessionId: "sid-2",
					UserId:    "u-1",
					IssuedAt:  "2026-06-25T08:00:00Z",
					ExpiresAt: "2026-06-25T16:00:00Z",
					UserAgent: "curl/8.0",
				},
			},
		},
	}
	out, err := resolvers.ListUserSessionsResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), admin, "u-1")
	if err != nil {
		t.Fatalf("ListUserSessionsResolver: %v", err)
	}
	if admin.lastListReq == nil || admin.lastListReq.UserId != "u-1" {
		t.Errorf("ListUserSessions not called with correct userId: %+v", admin.lastListReq)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(out))
	}
	if out[0].SessionID != "sid-1" || out[0].AuthenticatedAt != "2026-06-25T09:30:00Z" || !out[0].Active {
		t.Errorf("session 1 not mapped: %+v", out[0])
	}
	if out[0].ClientIP == nil || *out[0].ClientIP != "203.0.113.7" {
		t.Errorf("session 1 clientIp not mapped: %+v", out[0].ClientIP)
	}
	if out[1].Active || out[1].UserAgent != "curl/8.0" {
		t.Errorf("session 2 not mapped: %+v", out[1])
	}
	if out[1].ClientIP != nil {
		t.Errorf("session 2 expected nil clientIp (none recorded), got %v", *out[1].ClientIP)
	}
}

func TestRevokeUserSessionsRequiresSiteAdmin(t *testing.T) {
	admin := &fakeAdminWithSessions{}
	_, err := resolvers.RevokeUserSessionsResolver(context.Background(), admin, "u-1", nil)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", status.Code(err))
	}
}

func TestRevokeUserSessionsNilAdminClient(t *testing.T) {
	_, err := resolvers.RevokeUserSessionsResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), nil, "u-1", nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestRevokeUserSessionsHappyPath(t *testing.T) {
	admin := &fakeAdminWithSessions{
		revokeUserResp: &identityv1.RevokeUserSessionsResponse{Revoked: 3},
	}
	reason := "security-rotation"
	count, err := resolvers.RevokeUserSessionsResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), admin, "u-1", &reason)
	if err != nil {
		t.Fatalf("RevokeUserSessionsResolver: %v", err)
	}
	if admin.lastRevokeUserReq == nil {
		t.Fatal("RevokeUserSessions not called")
	}
	if admin.lastRevokeUserReq.UserId != "u-1" {
		t.Errorf("UserId: got %q", admin.lastRevokeUserReq.UserId)
	}
	if admin.lastRevokeUserReq.Reason != "security-rotation" {
		t.Errorf("Reason: got %q", admin.lastRevokeUserReq.Reason)
	}
	if count != 3 {
		t.Errorf("expected 3 revoked, got %d", count)
	}
}

func TestRevokeUserSessionsNilReasonOmitted(t *testing.T) {
	admin := &fakeAdminWithSessions{
		revokeUserResp: &identityv1.RevokeUserSessionsResponse{Revoked: 0},
	}
	_, err := resolvers.RevokeUserSessionsResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), admin, "u-1", nil)
	if err != nil {
		t.Fatalf("RevokeUserSessionsResolver: %v", err)
	}
	if admin.lastRevokeUserReq == nil {
		t.Fatal("RevokeUserSessions not called")
	}
	if admin.lastRevokeUserReq.Reason != "" {
		t.Errorf("nil reason should produce empty Reason, got %q", admin.lastRevokeUserReq.Reason)
	}
}

func TestRevokeMySessionsNilClient(t *testing.T) {
	_, err := resolvers.RevokeMySessionsResolver(context.Background(), nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestRevokeMySessionsHappyPath(t *testing.T) {
	read := &fakeReadWithRevokeMy{
		revokeMyResp: &identityv1.RevokeMySessionsResponse{Revoked: 2},
	}
	count, err := resolvers.RevokeMySessionsResolver(ctxWithUser(t, "u-me"), read)
	if err != nil {
		t.Fatalf("RevokeMySessionsResolver: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 revoked, got %d", count)
	}
}

func TestRevokeMySessionsNoAdminGate(t *testing.T) {
	// revokeMySessions must work for any authenticated user (no site-admin required).
	read := &fakeReadWithRevokeMy{
		revokeMyResp: &identityv1.RevokeMySessionsResponse{Revoked: 1},
	}
	// ctxWithRoles with a non-admin role — should still succeed.
	count, err := resolvers.RevokeMySessionsResolver(ctxWithRoles(t, "u-regular", []string{"author"}), read)
	if err != nil {
		t.Fatalf("RevokeMySessionsResolver should not require admin role: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1, got %d", count)
	}
}
