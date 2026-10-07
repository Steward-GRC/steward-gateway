// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func groupManagerCtx(t *testing.T) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: "u-manager", RolesValue: []string{"reader"}})
}

func managerRead() *managedGroupsRead {
	return &managedGroupsRead{users: map[string]*identityv1.User{
		"u-manager": {Id: "u-manager", ManagedGroupIds: []string{"g-sec", "g-audit"}},
		"u-reader":  {Id: "u-reader"},
	}}
}

func TestQueryAuditLogSendsAGroupManagersManagedGroups(t *testing.T) {
	client := &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{}}
	read := managerRead()
	group := "g-sec"

	if _, err := resolvers.QueryAuditLogResolver(groupManagerCtx(t), client, read, nil, nil, nil,
		nil, &group, nil, nil, nil, nil); err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	got := client.lastQueryReq.GetRequester()
	if got.GetUserId() != "u-manager" || len(got.GetManagedGroups()) != 2 ||
		got.GetManagedGroups()[0] != "g-sec" || got.GetManagedGroups()[1] != "g-audit" {
		t.Fatalf("requester=%+v, want the caller and its managed groups", got)
	}
	if len(read.userReqs) != 1 || read.userReqs[0] != "u-manager" {
		t.Fatalf("identity reads=%v, want only the caller", read.userReqs)
	}
}

func TestVerifyAuditChainSendsAGroupManagersManagedGroups(t *testing.T) {
	client := &fakeAuditClient{verifyResp: &auditv1.VerifyAuditChainResponse{Valid: true}}

	if _, err := resolvers.VerifyAuditChainResolver(groupManagerCtx(t), client, managerRead(), "1", "10"); err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if got := client.lastVerifyReq.GetRequester().GetManagedGroups(); len(got) != 2 {
		t.Fatalf("managed groups=%v, want both", got)
	}
}

func TestAuditReadsSkipTheManagedGroupLookupForAuditRead(t *testing.T) {
	client := &fakeAuditClient{
		queryResp:  &auditv1.QueryAuditLogResponse{},
		verifyResp: &auditv1.VerifyAuditChainResponse{Valid: true},
	}
	read := managerRead()
	ctx := ctxWithRoles(t, "u-compliance", []string{"compliance-admin"})

	if _, err := resolvers.QueryAuditLogResolver(ctx, client, read, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	if _, err := resolvers.VerifyAuditChainResolver(ctx, client, read, "1", "10"); err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if len(read.userReqs) != 0 {
		t.Fatalf("identity reads=%v, want none for an audit.read holder", read.userReqs)
	}
}

func TestAuditReadsRefuseACallerWhoManagesNoGroup(t *testing.T) {
	client := &fakeAuditClient{}
	ctx := ctxWithRoles(t, "u-reader", []string{"reader"})

	_, err := resolvers.QueryAuditLogResolver(ctx, client, managerRead(), nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("query: want PermissionDenied, got %v", err)
	}
	_, err = resolvers.VerifyAuditChainResolver(ctx, client, managerRead(), "1", "10")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("verify: want PermissionDenied, got %v", err)
	}
	if client.lastQueryReq != nil || client.lastVerifyReq != nil {
		t.Fatal("audit was called for a caller with neither audit.read nor a managed group")
	}
}

type failingUserRead struct {
	identityv1.IdentityReadServiceClient
}

func (failingUserRead) GetUser(context.Context, *identityv1.GetUserRequest, ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	return nil, status.Error(codes.Unavailable, "identity down")
}

func TestAuditReadsReturnAnIdentityFailure(t *testing.T) {
	client := &fakeAuditClient{}

	_, err := resolvers.QueryAuditLogResolver(groupManagerCtx(t), client, failingUserRead{}, nil, nil, nil,
		nil, nil, nil, nil, nil, nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	if client.lastQueryReq != nil {
		t.Fatal("audit was called without the managed groups")
	}
}

func TestAuditSegmentRefusesAGroupManager(t *testing.T) {
	client := &fakeAuditClient{}
	_, err := resolvers.ExportAuditSegmentResolver(groupManagerCtx(t), client, "1", "10")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}
