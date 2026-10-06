// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestListPoliciesByOwner_RequiresSiteAdmin(t *testing.T) {
	client := &fakePolicyClient{}
	ctx := ctxWithRoles(t, "u-1", []string{"policy-author"})
	if _, err := resolvers.ListPoliciesByOwner(ctx, client, "victim", nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.lastListByOwner != nil {
		t.Fatal("must not call core when unauthorized")
	}
}

func TestListPoliciesByOwner_MapsRows(t *testing.T) {
	client := &fakePolicyClient{byOwnerResp: &corev1.ListPoliciesByOwnerResponse{
		Policies: []*corev1.Policy{
			{Id: "p1", OwnerUserId: "victim"},
			{Id: "p2", OwnerUserId: "victim"},
		},
	}}
	ctx := ctxWithRoles(t, "admin-1", []string{"site-admin"})
	out, err := resolvers.ListPoliciesByOwner(ctx, client, "victim", new(true))
	if err != nil {
		t.Fatalf("ListPoliciesByOwner: %v", err)
	}
	if len(out) != 2 || out[0].ID != "p1" || out[1].ID != "p2" {
		t.Fatalf("rows not mapped: %+v", out)
	}
	if client.lastListByOwner.GetOwnerUserId() != "victim" || !client.lastListByOwner.GetIncludeRetired() {
		t.Fatalf("request not forwarded: %+v", client.lastListByOwner)
	}
}

func TestReassignUserPolicies_PassesActorAndMaps(t *testing.T) {
	client := &fakePolicyClient{reassignResp: &corev1.ReassignUserPoliciesResponse{
		ReassignedPolicyIds:    []string{"p1", "p2"},
		ReassignedOwnerCount:   2,
		ReassignedAuthorGrants: 3,
	}}
	ctx := ctxWithRoles(t, "admin-9", []string{"site-admin"})
	out, err := resolvers.ReassignUserPolicies(ctx, client, "victim", "heir")
	if err != nil {
		t.Fatalf("ReassignUserPolicies: %v", err)
	}
	if out.ReassignedOwnerCount != 2 || out.ReassignedAuthorGrants != 3 || len(out.ReassignedPolicyIds) != 2 {
		t.Fatalf("result not mapped: %+v", out)
	}
	if client.lastReassign.GetFromUserId() != "victim" || client.lastReassign.GetToUserId() != "heir" {
		t.Fatalf("from/to not forwarded: %+v", client.lastReassign)
	}
	if client.lastReassign.GetActorUserId() != "admin-9" {
		t.Fatalf("actor not bound from claims; got %q", client.lastReassign.GetActorUserId())
	}
}

func TestReassignUserPolicies_RequiresSiteAdmin(t *testing.T) {
	client := &fakePolicyClient{}
	ctx := ctxWithRoles(t, "u-1", []string{"policy-author"})
	if _, err := resolvers.ReassignUserPolicies(ctx, client, "victim", "heir"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.lastReassign != nil {
		t.Fatal("must not call core when unauthorized")
	}
}

// TestDeleteUser_BlocksWhenPoliciesRemain is the core safety guarantee of
// a user who still owns policies cannot be deleted (the orphaned
// set must be re-assigned first), and identity is never called.
func TestDeleteUser_BlocksWhenPoliciesRemain(t *testing.T) {
	policyClient := &fakePolicyClient{byOwnerResp: &corev1.ListPoliciesByOwnerResponse{
		Policies: []*corev1.Policy{{Id: "p1", OwnerUserId: "victim"}},
	}}
	admin := &fakeAdminClient{}
	ctx := ctxWithRoles(t, "admin-1", []string{"site-admin"})
	_, err := resolvers.DeleteUserResolver(ctx, policyClient, admin, "victim")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
	if admin.lastDeleteUser != nil {
		t.Fatal("must NOT delete a user who still owns policies")
	}
	if !policyClient.lastListByOwner.GetIncludeRetired() {
		t.Fatal("guard must include retired policies so none are missed")
	}
}

func TestDeleteUser_ProceedsWhenNoPolicies(t *testing.T) {
	policyClient := &fakePolicyClient{byOwnerResp: &corev1.ListPoliciesByOwnerResponse{}}
	admin := &fakeAdminClient{deleteUserResp: &identityv1.DeleteUserResponse{
		User: &identityv1.User{Id: "victim"}, RevokedSessions: 4,
	}}
	ctx := ctxWithRoles(t, "admin-1", []string{"site-admin"})
	out, err := resolvers.DeleteUserResolver(ctx, policyClient, admin, "victim")
	if err != nil {
		t.Fatalf("DeleteUserResolver: %v", err)
	}
	if out.UserID != "victim" || out.RevokedSessions != 4 {
		t.Fatalf("result not mapped: %+v", out)
	}
	if admin.lastDeleteUser.GetUserId() != "victim" {
		t.Fatalf("delete not forwarded: %+v", admin.lastDeleteUser)
	}
}

func TestDeleteUser_RequiresSiteAdmin(t *testing.T) {
	policyClient := &fakePolicyClient{}
	admin := &fakeAdminClient{}
	ctx := ctxWithRoles(t, "u-1", []string{"policy-author"})
	if _, err := resolvers.DeleteUserResolver(ctx, policyClient, admin, "victim"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if policyClient.lastListByOwner != nil || admin.lastDeleteUser != nil {
		t.Fatal("must not call backends when unauthorized")
	}
}
