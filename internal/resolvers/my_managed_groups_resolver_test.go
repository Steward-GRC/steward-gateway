// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type managedGroupsRead struct {
	identityv1.IdentityReadServiceClient
	users     map[string]*identityv1.User
	groups    map[string]*identityv1.Group
	userReqs  []string
	groupReqs []string
}

func (f *managedGroupsRead) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	f.userReqs = append(f.userReqs, in.GetUserId())
	u, ok := f.users[in.GetUserId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no user")
	}
	return &identityv1.GetUserResponse{User: u}, nil
}

func (f *managedGroupsRead) GetGroup(_ context.Context, in *identityv1.GetGroupRequest, _ ...grpc.CallOption) (*identityv1.GetGroupResponse, error) {
	f.groupReqs = append(f.groupReqs, in.GetGroupId())
	g, ok := f.groups[in.GetGroupId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no group")
	}
	return &identityv1.GetGroupResponse{Group: g}, nil
}

func TestMyManagedGroupsResolverReturnsTheCallersOwnGroupsByName(t *testing.T) {
	read := &managedGroupsRead{
		users: map[string]*identityv1.User{
			"u-manager": {Id: "u-manager", ManagedGroupIds: []string{"g-sec", "g-gone", "g-audit"}},
		},
		groups: map[string]*identityv1.Group{
			"g-sec":   {Id: "g-sec", Name: "Security"},
			"g-audit": {Id: "g-audit", Name: "Audit", ParentId: "g-root"},
			"g-other": {Id: "g-other", Name: "Not managed"},
		},
	}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-manager", RolesValue: []string{"reader"}})

	groups, err := resolvers.MyManagedGroupsResolver(ctx, read)
	if err != nil {
		t.Fatalf("MyManagedGroups: %v", err)
	}
	if len(groups) != 2 || groups[0].ID != "g-audit" || groups[0].Name != "Audit" || *groups[0].ParentID != "g-root" ||
		groups[1].ID != "g-sec" || groups[1].ParentID != nil {
		t.Fatalf("groups=%+v", groups)
	}
	if len(read.userReqs) != 1 || read.userReqs[0] != "u-manager" {
		t.Fatalf("user reads=%v, want only the caller", read.userReqs)
	}
	for _, id := range read.groupReqs {
		if id == "g-other" {
			t.Fatalf("read a group the caller does not manage: %v", read.groupReqs)
		}
	}
}

func TestMyManagedGroupsResolverIsEmptyForANonManager(t *testing.T) {
	read := &managedGroupsRead{users: map[string]*identityv1.User{"u-admin": {Id: "u-admin"}}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-admin", RolesValue: []string{"site-admin"}})

	groups, err := resolvers.MyManagedGroupsResolver(ctx, read)
	if err != nil {
		t.Fatalf("MyManagedGroups: %v", err)
	}
	if groups == nil || len(groups) != 0 || len(read.groupReqs) != 0 {
		t.Fatalf("groups=%+v group reads=%v, want an empty list and no group reads", groups, read.groupReqs)
	}
}

func TestMyManagedGroupsResolverRefusals(t *testing.T) {
	if _, err := resolvers.MyManagedGroupsResolver(context.Background(), &managedGroupsRead{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("signed out: want Unauthenticated, got %v", err)
	}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u1", RolesValue: []string{"reader"}})
	if _, err := resolvers.MyManagedGroupsResolver(ctx, nil); status.Code(err) != codes.Unavailable {
		t.Fatalf("unwired: want Unavailable, got %v", err)
	}
	failing := &managedGroupsRead{users: map[string]*identityv1.User{"u1": {Id: "u1", ManagedGroupIds: []string{"g1"}}}}
	if _, err := resolvers.MyManagedGroupsResolver(ctx, &erroringGroupRead{managedGroupsRead: failing}); status.Code(err) != codes.Internal {
		t.Fatalf("identity failure: want Internal, got %v", err)
	}
}

type erroringGroupRead struct {
	*managedGroupsRead
}

func (f *erroringGroupRead) GetGroup(context.Context, *identityv1.GetGroupRequest, ...grpc.CallOption) (*identityv1.GetGroupResponse, error) {
	return nil, status.Error(codes.Internal, "boom")
}
