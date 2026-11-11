// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// actionsAuditClient adds ListAuditActions to the shared audit fake.
type actionsAuditClient struct {
	*fakeAuditClient
	resp  *auditv1.ListAuditActionsResponse
	err   error
	calls int
	last  *auditv1.ListAuditActionsRequest
}

func (f *actionsAuditClient) ListAuditActions(_ context.Context, in *auditv1.ListAuditActionsRequest, _ ...grpc.CallOption) (*auditv1.ListAuditActionsResponse, error) {
	f.calls++
	f.last = in
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func actionsClient(actions ...string) *actionsAuditClient {
	return &actionsAuditClient{
		fakeAuditClient: &fakeAuditClient{},
		resp:            &auditv1.ListAuditActionsResponse{Actions: actions},
	}
}

func TestQueryAuditActionsReturnsTheCodesForAnAuditReader(t *testing.T) {
	client := actionsClient("policy.draft_saved", "policy.published")
	read := managerRead()

	got, err := resolvers.QueryAuditActionsResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), log.Nop(), client, read)
	if err != nil {
		t.Fatalf("QueryAuditActions: %v", err)
	}
	if len(got) != 2 || got[0] != "policy.draft_saved" || got[1] != "policy.published" {
		t.Fatalf("actions=%v, want both codes in order", got)
	}
	if client.last.GetRequester().GetUserId() != "auditor-1" {
		t.Fatalf("requester=%v, want the signed-in caller", client.last.GetRequester())
	}
	if len(read.userReqs) != 0 {
		t.Fatalf("identity reads=%v, want none for an audit.read holder", read.userReqs)
	}
}

func TestQueryAuditActionsIsOpenToAGroupManager(t *testing.T) {
	client := actionsClient("policy.published")

	got, err := resolvers.QueryAuditActionsResolver(groupManagerCtx(t), log.Nop(), client, managerRead())
	if err != nil {
		t.Fatalf("QueryAuditActions: %v", err)
	}
	if len(got) != 1 || got[0] != "policy.published" {
		t.Fatalf("actions=%v, want the code", got)
	}
	if m := client.last.GetRequester().GetManagedGroups(); len(m) != 2 {
		t.Fatalf("managed groups=%v, want the caller's groups sent as for auditLog", m)
	}
}

func TestQueryAuditActionsRefusesACallerWhoManagesNoGroup(t *testing.T) {
	client := actionsClient("policy.published")

	_, err := resolvers.QueryAuditActionsResolver(ctxWithRoles(t, "u-reader", []string{"reader"}), log.Nop(), client, managerRead())
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.calls != 0 {
		t.Fatal("audit was called for a caller with neither audit.read nor a managed group")
	}
}

func TestQueryAuditActionsFailsClosedWithoutIdentity(t *testing.T) {
	client := actionsClient("policy.published")

	_, err := resolvers.QueryAuditActionsResolver(ctxWithRoles(t, "u-reader", []string{"reader"}), log.Nop(), client, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.calls != 0 {
		t.Fatal("audit was called without a scope check")
	}
}

func TestQueryAuditActionsReturnsAnIdentityFailure(t *testing.T) {
	client := actionsClient("policy.published")

	_, err := resolvers.QueryAuditActionsResolver(groupManagerCtx(t), log.Nop(), client, failingUserRead{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	if client.calls != 0 {
		t.Fatal("audit was called after the scope check failed")
	}
}

func TestQueryAuditActionsRefusesAnUnauthenticatedCaller(t *testing.T) {
	client := actionsClient("policy.published")

	if _, err := resolvers.QueryAuditActionsResolver(context.Background(), log.Nop(), client, managerRead()); err == nil {
		t.Fatal("want an error for a request with no signed-in caller")
	}
	if client.calls != 0 {
		t.Fatal("audit was called with no caller")
	}
}

func TestQueryAuditActionsReturnsTheAuditError(t *testing.T) {
	client := actionsClient()
	client.err = status.Error(codes.Unavailable, "audit down")

	got, err := resolvers.QueryAuditActionsResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), log.Nop(), client, nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	if got != nil {
		t.Fatalf("actions=%v, want none on error", got)
	}
}

func TestQueryAuditActionsReturnsAnEmptyListNotNull(t *testing.T) {
	client := actionsClient()

	got, err := resolvers.QueryAuditActionsResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), log.Nop(), client, nil)
	if err != nil {
		t.Fatalf("QueryAuditActions: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("actions=%#v, want a non-nil empty list (the field is non-null)", got)
	}
}
