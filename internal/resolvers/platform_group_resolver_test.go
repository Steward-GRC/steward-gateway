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

type platformGroupAdmin struct {
	identityv1.IdentityAdminServiceClient
	last *identityv1.CreateGroupRequest
}

func (f *platformGroupAdmin) CreateGroup(_ context.Context, in *identityv1.CreateGroupRequest, _ ...grpc.CallOption) (*identityv1.CreateGroupResponse, error) {
	f.last = in
	return &identityv1.CreateGroupResponse{Group: &identityv1.Group{Id: "g-new", Name: in.GetName(), ParentId: in.GetParentId()}}, nil
}

type platformGroupRead struct {
	identityv1.IdentityReadServiceClient
	pages map[string]*identityv1.ListGroupsResponse
	reqs  []*identityv1.ListGroupsRequest
}

func (f *platformGroupRead) ListGroups(_ context.Context, in *identityv1.ListGroupsRequest, _ ...grpc.CallOption) (*identityv1.ListGroupsResponse, error) {
	f.reqs = append(f.reqs, in)
	return f.pages[in.GetPageToken()], nil
}

func TestPlatformGroupsResolverListsEveryPage(t *testing.T) {
	read := &platformGroupRead{pages: map[string]*identityv1.ListGroupsResponse{
		"":   {Groups: []*identityv1.Group{{Id: "g1", Name: "Privacy Officers"}}, NextPageToken: "p2"},
		"p2": {Groups: []*identityv1.Group{{Id: "g2", Name: "Reviewers", ParentId: "g1"}}},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin", RolesValue: []string{"site-admin"}})

	parent := "g0"
	groups, err := resolvers.PlatformGroupsResolver(ctx, read, &parent)
	if err != nil {
		t.Fatalf("PlatformGroups: %v", err)
	}
	if len(groups) != 2 || groups[0].ID != "g1" || groups[0].ParentID != nil || *groups[1].ParentID != "g1" {
		t.Fatalf("groups=%+v", groups)
	}
	if len(read.reqs) != 2 || read.reqs[0].GetParentId() != "g0" || read.reqs[1].GetPageToken() != "p2" {
		t.Fatalf("requests=%v", read.reqs)
	}
}

func TestCreatePlatformGroupResolver(t *testing.T) {
	admin := &platformGroupAdmin{}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin", RolesValue: []string{"site-admin"}})

	g, err := resolvers.CreatePlatformGroupResolver(ctx, admin, "  Privacy Officers ", nil)
	if err != nil {
		t.Fatalf("CreatePlatformGroup: %v", err)
	}
	if g.ID != "g-new" || g.Name != "Privacy Officers" || g.ParentID != nil {
		t.Fatalf("group=%+v", g)
	}
	if admin.last.GetName() != "Privacy Officers" || admin.last.GetParentId() != "" {
		t.Fatalf("request=%v", admin.last)
	}

	admin.last = nil
	if _, err := resolvers.CreatePlatformGroupResolver(ctx, admin, "   ", nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("blank name must be InvalidArgument, got %v", err)
	}
	if admin.last != nil {
		t.Fatal("a blank name must not reach identity")
	}
}

func TestPlatformGroupResolversAreSiteAdminOnly(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u1", RolesValue: []string{"reader"}})
	if _, err := resolvers.PlatformGroupsResolver(ctx, &platformGroupRead{}, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("list: want PermissionDenied, got %v", err)
	}
	if _, err := resolvers.CreatePlatformGroupResolver(ctx, &platformGroupAdmin{}, "x", nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("create: want PermissionDenied, got %v", err)
	}

	admin := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin", RolesValue: []string{"site-admin"}})
	if _, err := resolvers.PlatformGroupsResolver(admin, nil, nil); status.Code(err) != codes.Unavailable {
		t.Fatalf("unwired list: want Unavailable, got %v", err)
	}
	if _, err := resolvers.CreatePlatformGroupResolver(admin, nil, "x", nil); status.Code(err) != codes.Unavailable {
		t.Fatalf("unwired create: want Unavailable, got %v", err)
	}
}
