// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// searchPlatformGroups is the group half of the access picker's typeahead
// (steward-gateway#81): groups are found in the identity directory by name, so a
// rule names a group that exists; people are found with searchUsers.

type groupSearchRead struct {
	identityv1.IdentityReadServiceClient
	reqs []*identityv1.SearchGroupsRequest
	resp *identityv1.SearchGroupsResponse
}

func (f *groupSearchRead) SearchGroups(_ context.Context, in *identityv1.SearchGroupsRequest, _ ...grpc.CallOption) (*identityv1.SearchGroupsResponse, error) {
	f.reqs = append(f.reqs, in)
	return f.resp, nil
}

func newGroupSearchRead() *groupSearchRead {
	return &groupSearchRead{resp: &identityv1.SearchGroupsResponse{Groups: []*identityv1.Group{
		{Id: "g1", Name: "Facilities Team"},
		{Id: "g2", Name: "Facilities Leads", ParentId: "g1"},
	}}}
}

func TestSearchPlatformGroups_MapsTheDirectoryHits(t *testing.T) {
	read := newGroupSearchRead()
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "a", RolesValue: []string{"site-admin"}})
	got, err := resolvers.SearchPlatformGroupsResolver(ctx, read, "  facil ", nil)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, "g1", got[0].ID)
	require.Equal(t, "Facilities Team", got[0].Name)
	require.Nil(t, got[0].ParentID)
	require.Equal(t, "g1", *got[1].ParentID)
	require.Len(t, read.reqs, 1)
	require.Equal(t, "facil", read.reqs[0].GetQuery(), "the query is trimmed")
	require.EqualValues(t, 20, read.reqs[0].GetLimit(), "default limit")
}

func TestSearchPlatformGroups_LimitIsCapped(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "a", RolesValue: []string{"site-admin"}})
	for _, tc := range []struct {
		in   *int
		want int32
	}{{nil, 20}, {ptrInt(0), 20}, {ptrInt(-3), 20}, {ptrInt(7), 7}, {ptrInt(50), 50}, {ptrInt(5000), 50}} {
		read := newGroupSearchRead()
		_, err := resolvers.SearchPlatformGroupsResolver(ctx, read, "fac", tc.in)
		require.NoError(t, err)
		require.Equal(t, tc.want, read.reqs[0].GetLimit())
	}
}

func ptrInt(i int) *int { return &i }

func TestSearchPlatformGroups_NeedsTwoCharacters(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "a", RolesValue: []string{"site-admin"}})
	for _, q := range []string{"", " ", "f", " f "} {
		read := newGroupSearchRead()
		_, err := resolvers.SearchPlatformGroupsResolver(ctx, read, q, nil)
		require.Equal(t, codes.InvalidArgument, status.Code(err), "query %q", q)
		require.Empty(t, read.reqs, "identity must not be asked")
	}
}

// Whoever edits access may search: a site admin, a template admin. A reader and
// a plain author may not, and the directory is not asked for them.
func TestSearchPlatformGroups_WhoMay(t *testing.T) {
	cases := []struct {
		name      string
		claims    principal.Static
		wantAllow bool
	}{
		{"site admin", principal.Static{UserIDValue: "u", RolesValue: []string{"site-admin"}}, true},
		{"template admin", principal.Static{UserIDValue: "u", RolesValue: []string{"template-admin"}}, true},
		{"reader", principal.Static{UserIDValue: "u", RolesValue: []string{"reader"}}, false},
		{"author", principal.Static{UserIDValue: "u", RolesValue: []string{"author"}}, false},
		{"compliance admin", principal.Static{UserIDValue: "u", RolesValue: []string{"compliance-admin"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			read := newGroupSearchRead()
			_, err := resolvers.SearchPlatformGroupsResolver(ctxWithStubClaims(t, tc.claims), read, "fac", nil)
			if tc.wantAllow {
				require.NoError(t, err)
				return
			}
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			require.Empty(t, read.reqs)
		})
	}
}

func TestSearchPlatformGroups_UnavailableAndSignedOut(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "a", RolesValue: []string{"site-admin"}})
	_, err := resolvers.SearchPlatformGroupsResolver(ctx, nil, "fac", nil)
	require.Equal(t, codes.Unavailable, status.Code(err))
	_, err = resolvers.SearchPlatformGroupsResolver(context.Background(), newGroupSearchRead(), "fac", nil)
	require.Error(t, err)
}
