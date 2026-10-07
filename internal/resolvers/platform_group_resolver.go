// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"strings"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// platformGroupPageSize is identity's ListGroups ceiling.
const platformGroupPageSize = 200

func platformGroupToGraphQL(g *identityv1.Group) *PlatformGroup {
	out := &PlatformGroup{ID: g.GetId(), Name: g.GetName()}
	if p := g.GetParentId(); p != "" {
		out.ParentID = &p
	}
	return out
}

// PlatformGroupsResolver lists the identity platform groups directly under
// parentID (the roots when nil), following every page. Site-admin only.
func PlatformGroupsResolver(ctx context.Context, read identityv1.IdentityReadServiceClient, parentID *string) ([]*PlatformGroup, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	if read == nil {
		return nil, status.Error(codes.Unavailable, "identity unavailable")
	}
	req := &identityv1.ListGroupsRequest{Limit: platformGroupPageSize}
	if parentID != nil {
		req.ParentId = *parentID
	}
	out := []*PlatformGroup{}
	for {
		resp, err := read.ListGroups(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, g := range resp.GetGroups() {
			out = append(out, platformGroupToGraphQL(g))
		}
		if resp.GetNextPageToken() == "" {
			return out, nil
		}
		req.PageToken = resp.GetNextPageToken()
	}
}

// CreatePlatformGroupResolver creates an identity platform group under
// parentID (a root group when nil). Site-admin only.
func CreatePlatformGroupResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, name string, parentID *string) (*PlatformGroup, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "a platform group needs a name")
	}
	req := &identityv1.CreateGroupRequest{Name: name}
	if parentID != nil {
		req.ParentId = *parentID
	}
	resp, err := admin.CreateGroup(ctx, req)
	if err != nil {
		return nil, err
	}
	return platformGroupToGraphQL(resp.GetGroup()), nil
}
