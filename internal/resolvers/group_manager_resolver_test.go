// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestGrantRevokeGroupManagerResolver covers the admin-only group-manager grant
// mutations.
func TestGrantRevokeGroupManagerResolver(t *testing.T) {
	admin := &fakeAdminClient{
		grantMgrResp:  &identityv1.GrantGroupManagerResponse{User: &identityv1.User{Id: "u1", ManagedGroupIds: []string{"g1"}}},
		revokeMgrResp: &identityv1.RevokeGroupManagerResponse{User: &identityv1.User{Id: "u1"}},
	}
	siteAdminCtx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin", RolesValue: []string{"site-admin"}})

	u, err := resolvers.GrantGroupManagerResolver(siteAdminCtx, admin, "u1", "g1")
	if err != nil {
		t.Fatalf("GrantGroupManager: %v", err)
	}
	if len(u.ManagedGroupIds) != 1 || u.ManagedGroupIds[0] != "g1" {
		t.Fatalf("managedGroupIds=%v", u.ManagedGroupIds)
	}
	if admin.lastGrantMgrReq.GetGroupId() != "g1" || admin.lastGrantMgrReq.GetUserId() != "u1" {
		t.Fatalf("grant req=%v", admin.lastGrantMgrReq)
	}
	if _, err := resolvers.RevokeGroupManagerResolver(siteAdminCtx, admin, "u1", "g1"); err != nil {
		t.Fatalf("RevokeGroupManager: %v", err)
	}

	// A non-site-admin cannot grant.
	plainCtx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u1", RolesValue: []string{"reader"}})
	if _, err := resolvers.GrantGroupManagerResolver(plainCtx, admin, "u2", "g1"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin grant must be denied, got %v", err)
	}
}

// TestMembershipResolverGroupManagerScope covers the scoped membership authz on
// the add/remove resolvers: a group-manager may add/remove MANUAL
// members of a group they manage, is refused on IdP-synced rows, and is denied
// on groups they do not manage; a site-admin is unrestricted.
func TestMembershipResolverGroupManagerScope(t *testing.T) {
	// The fake read client returns one user for every GetUser; it doubles as the
	// caller (managed_group_ids) and the membership target (memberships).
	read := &fakeReadClient{getUserResp: &identityv1.GetUserResponse{User: &identityv1.User{
		Id:              "mgr",
		ManagedGroupIds: []string{"g-mine"},
		Memberships: []*identityv1.Membership{
			{GroupId: "g-mine", Source: "idp-sync"},
		},
	}}}
	admin := &fakeAdminClient{
		addGroupResp:    &identityv1.AddUserToGroupResponse{},
		removeGroupResp: &identityv1.RemoveUserFromGroupResponse{},
	}
	mgrCtx := ctxWithStubClaims(t, principal.Static{UserIDValue: "mgr", RolesValue: []string{"reader"}})

	// Manager can add to a group they manage.
	if _, err := resolvers.AddUserToGroupResolver(mgrCtx, admin, read, "target", "g-mine"); err != nil {
		t.Fatalf("manager add to managed group: %v", err)
	}
	// Manager denied on a group they do not manage.
	if _, err := resolvers.AddUserToGroupResolver(mgrCtx, admin, read, "target", "g-other"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("manager add to unmanaged group must be denied, got %v", err)
	}
	// Manager removal of an IdP-synced membership is refused up front.
	if _, err := resolvers.RemoveUserFromGroupResolver(mgrCtx, admin, read, "target", "g-mine"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("manager remove of sync-owned row must be denied, got %v", err)
	}

	// A site-admin is unrestricted: even the sync-owned row removes fine.
	adminCtx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin", RolesValue: []string{"site-admin"}})
	if _, err := resolvers.RemoveUserFromGroupResolver(adminCtx, admin, read, "target", "g-mine"); err != nil {
		t.Fatalf("site-admin remove of sync-owned row: %v", err)
	}
}

// TestManagedGroupMembersResolver covers the manager-scoped member listing
// : a group-manager of the group may list its members; a caller
// who neither is site-admin nor manages the group is denied.
func TestManagedGroupMembersResolver(t *testing.T) {
	read := &fakeReadClient{
		getUserResp:      &identityv1.GetUserResponse{User: &identityv1.User{Id: "mgr", ManagedGroupIds: []string{"g-mine"}}},
		usersInGroupResp: &identityv1.ListUsersInGroupResponse{Users: []*identityv1.User{{Id: "m1"}, {Id: "m2"}}},
	}
	mgrCtx := ctxWithStubClaims(t, principal.Static{UserIDValue: "mgr", RolesValue: []string{"reader"}})

	members, err := resolvers.ManagedGroupMembersResolver(mgrCtx, read, "g-mine")
	if err != nil {
		t.Fatalf("ManagedGroupMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("want 2 members, got %d", len(members))
	}
	if read.lastUsersInGroupReq.GetGroupId() != "g-mine" {
		t.Fatalf("groupId=%q", read.lastUsersInGroupReq.GetGroupId())
	}

	// A caller who does not manage the group is denied.
	if _, err := resolvers.ManagedGroupMembersResolver(mgrCtx, read, "g-other"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-manager list must be denied, got %v", err)
	}
}
