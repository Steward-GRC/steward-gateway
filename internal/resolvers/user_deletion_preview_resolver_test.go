// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type deletionPreviewAdmin struct {
	*fakeAdminClient
	req  *identityv1.PreviewUserDeletionRequest
	resp *identityv1.PreviewUserDeletionResponse
	err  error
}

func (f *deletionPreviewAdmin) PreviewUserDeletion(_ context.Context, in *identityv1.PreviewUserDeletionRequest, _ ...grpc.CallOption) (*identityv1.PreviewUserDeletionResponse, error) {
	f.req = in
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func newDeletionPreviewAdmin(resp *identityv1.PreviewUserDeletionResponse) *deletionPreviewAdmin {
	return &deletionPreviewAdmin{fakeAdminClient: &fakeAdminClient{}, resp: resp}
}

func TestPreviewUserDeletion_RequiresSiteAdmin(t *testing.T) {
	for _, roles := range [][]string{nil, {"author"}, {"approver"}, {"template-admin"}, {"compliance-admin"}} {
		admin := newDeletionPreviewAdmin(&identityv1.PreviewUserDeletionResponse{})
		_, err := resolvers.PreviewUserDeletionResolver(ctxWithRoles(t, "u-1", roles), admin, "u-target")
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("roles %v: want PermissionDenied, got %v", roles, err)
		}
		if admin.req != nil {
			t.Fatalf("roles %v: identity must not be called when unauthorized", roles)
		}
	}
}

func TestPreviewUserDeletion_RequiresAuthentication(t *testing.T) {
	admin := newDeletionPreviewAdmin(&identityv1.PreviewUserDeletionResponse{})
	_, err := resolvers.PreviewUserDeletionResolver(context.Background(), admin, "u-target")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
	if admin.req != nil {
		t.Fatal("identity must not be called without a caller")
	}
}

func TestPreviewUserDeletion_IdentityUnavailable(t *testing.T) {
	_, err := resolvers.PreviewUserDeletionResolver(ctxWithRoles(t, "admin-1", []string{"site-admin"}), nil, "u-target")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
}

func TestPreviewUserDeletion_MapsProjection(t *testing.T) {
	admin := newDeletionPreviewAdmin(&identityv1.PreviewUserDeletionResponse{Preview: &identityv1.UserDeletionPreview{
		UserId: "u-target",
		Counts: &identityv1.UserDeletionCounts{
			PendingApprovals: 1, OwnedPolicies: 2, RaciGrants: 3, Roles: 4, Permissions: 5,
			GroupMemberships: 6, IdpGroups: 7, PolicyOverrides: 8, BreakGlassGrants: 9, ManagedGroups: 10,
		},
		Items: []*identityv1.UserDeletionPreviewItem{
			{Kind: identityv1.DeletionItemKind_DELETION_ITEM_KIND_PENDING_APPROVAL, RefId: "task-1", Label: "IT-001 — Access Control", Detail: "stage 2, due 2026-10-13", BlocksDelete: true},
			{Kind: identityv1.DeletionItemKind_DELETION_ITEM_KIND_OWNED_POLICY, RefId: "pol-1", Label: "IT-002 — Backups", Detail: "owner"},
			{Kind: identityv1.DeletionItemKind_DELETION_ITEM_KIND_RACI_GRANT, RefId: "cat-1", Label: "IT", Detail: "author grant"},
			{Kind: identityv1.DeletionItemKind_DELETION_ITEM_KIND_ACCESS_ROW, RefId: "approver", Label: "approver", Detail: "role"},
			{Kind: identityv1.DeletionItemKind_DELETION_ITEM_KIND_CREDENTIAL, RefId: "u-target", Label: "local password", Detail: "revoked"},
		},
		Warnings: []*identityv1.UserDeletionWarning{
			{Code: "DELETE_BLOCKED_PENDING_APPROVALS", Message: "clear the pending approval first"},
			{Code: "LAST_LOCAL_CREDENTIAL", Message: "this is the only local login"},
		},
		BlocksDelete:         true,
		LocallyAuthenticable: true,
	}})
	out, err := resolvers.PreviewUserDeletionResolver(ctxWithRoles(t, "admin-1", []string{"site-admin"}), admin, "u-target")
	if err != nil {
		t.Fatalf("PreviewUserDeletionResolver: %v", err)
	}
	if admin.req.GetUserId() != "u-target" {
		t.Fatalf("user id not forwarded: %+v", admin.req)
	}
	if out.UserID != "u-target" || !out.BlocksDelete || !out.LocallyAuthenticable {
		t.Fatalf("preview scalars not mapped: %+v", out)
	}
	want := resolvers.UserDeletionCounts{
		PendingApprovals: 1, OwnedPolicies: 2, RaciGrants: 3, Roles: 4, Permissions: 5,
		GroupMemberships: 6, IdpGroups: 7, PolicyOverrides: 8, BreakGlassGrants: 9, ManagedGroups: 10,
	}
	if out.Counts == nil || *out.Counts != want {
		t.Fatalf("counts: got %+v want %+v", out.Counts, want)
	}
	kinds := []resolvers.DeletionItemKind{
		resolvers.DeletionItemKindPendingApproval,
		resolvers.DeletionItemKindOwnedPolicy,
		resolvers.DeletionItemKindRaciGrant,
		resolvers.DeletionItemKindAccessRow,
		resolvers.DeletionItemKindCredential,
	}
	if len(out.Items) != len(kinds) {
		t.Fatalf("want %d items, got %d", len(kinds), len(out.Items))
	}
	for i, k := range kinds {
		if out.Items[i].Kind != k {
			t.Errorf("item %d kind: got %s want %s", i, out.Items[i].Kind, k)
		}
	}
	first := out.Items[0]
	if first.RefID != "task-1" || first.Label != "IT-001 — Access Control" || first.Detail != "stage 2, due 2026-10-13" || !first.BlocksDelete {
		t.Fatalf("blocking item not mapped: %+v", first)
	}
	if out.Items[1].BlocksDelete {
		t.Fatal("a non-blocking item must not be marked blocksDelete")
	}
	if len(out.Warnings) != 2 || out.Warnings[1].Code != "LAST_LOCAL_CREDENTIAL" || out.Warnings[1].Message != "this is the only local login" {
		t.Fatalf("warnings not mapped: %+v", out.Warnings)
	}
}

func TestPreviewUserDeletion_EmptyPreviewKeepsNonNullShape(t *testing.T) {
	admin := newDeletionPreviewAdmin(&identityv1.PreviewUserDeletionResponse{Preview: &identityv1.UserDeletionPreview{UserId: "u-target"}})
	out, err := resolvers.PreviewUserDeletionResolver(ctxWithRoles(t, "admin-1", []string{"site-admin"}), admin, "u-target")
	if err != nil {
		t.Fatalf("PreviewUserDeletionResolver: %v", err)
	}
	if out.Counts == nil || out.Items == nil || out.Warnings == nil {
		t.Fatalf("non-null fields must be populated: %+v", out)
	}
}

func TestPreviewUserDeletion_RelaysIdentityError(t *testing.T) {
	admin := newDeletionPreviewAdmin(nil)
	admin.err = status.Error(codes.FailedPrecondition, "delete checks unavailable")
	_, err := resolvers.PreviewUserDeletionResolver(ctxWithRoles(t, "admin-1", []string{"site-admin"}), admin, "u-target")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("identity error must relay verbatim, got %v", err)
	}
}

func TestPreviewUserDeletionGraphQL(t *testing.T) {
	admin := newDeletionPreviewAdmin(&identityv1.PreviewUserDeletionResponse{Preview: &identityv1.UserDeletionPreview{
		UserId:       "u-target",
		Counts:       &identityv1.UserDeletionCounts{PendingApprovals: 1},
		Items:        []*identityv1.UserDeletionPreviewItem{{Kind: identityv1.DeletionItemKind_DELETION_ITEM_KIND_PENDING_APPROVAL, RefId: "task-1", BlocksDelete: true}},
		Warnings:     []*identityv1.UserDeletionWarning{{Code: "DELETE_BLOCKED_PENDING_APPROVALS"}},
		BlocksDelete: true,
	}})
	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{
		Resolvers: &resolvers.Resolver{IdentityAdminClient: admin},
	}))
	srv.AddTransport(transport.POST{})
	body, err := json.Marshal(map[string]any{
		"query": `{ previewUserDeletion(userId: "u-target") {
			userId blocksDelete locallyAuthenticable
			counts { pendingApprovals ownedPolicies raciGrants roles permissions groupMemberships idpGroups policyOverrides breakGlassGrants managedGroups }
			items { kind refId label detail blocksDelete }
			warnings { code message }
		} }`,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest("POST", "/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithRoles(t, "admin-1", []string{"site-admin"}))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	var out struct {
		Data struct {
			PreviewUserDeletion struct {
				UserID       string `json:"userId"`
				BlocksDelete bool   `json:"blocksDelete"`
				Counts       struct {
					PendingApprovals int `json:"pendingApprovals"`
				} `json:"counts"`
				Items []struct {
					Kind         string `json:"kind"`
					BlocksDelete bool   `json:"blocksDelete"`
				} `json:"items"`
				Warnings []struct {
					Code string `json:"code"`
				} `json:"warnings"`
			} `json:"previewUserDeletion"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, rec.Body.String())
	}
	if len(out.Errors) > 0 {
		t.Fatalf("graphql errors: %+v", out.Errors)
	}
	p := out.Data.PreviewUserDeletion
	if p.UserID != "u-target" || !p.BlocksDelete || p.Counts.PendingApprovals != 1 ||
		len(p.Items) != 1 || p.Items[0].Kind != "PENDING_APPROVAL" || !p.Items[0].BlocksDelete ||
		len(p.Warnings) != 1 || p.Warnings[0].Code != "DELETE_BLOCKED_PENDING_APPROVALS" {
		t.Fatalf("unexpected preview: %s", rec.Body.String())
	}
}
