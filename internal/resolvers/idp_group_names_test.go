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

// idpGroupNames lists the directory (identity provider) group names a category
// group rule can match, for the rule picker (steward-gateway#57, item 3).

type idpNamesRead struct {
	identityv1.IdentityReadServiceClient
	reqs []*identityv1.ListIdpGroupNamesRequest
	resp *identityv1.ListIdpGroupNamesResponse
	err  error
}

func (f *idpNamesRead) ListIdpGroupNames(_ context.Context, in *identityv1.ListIdpGroupNamesRequest, _ ...grpc.CallOption) (*identityv1.ListIdpGroupNamesResponse, error) {
	f.reqs = append(f.reqs, in)
	return f.resp, f.err
}

func newIdpNamesRead() *idpNamesRead {
	return &idpNamesRead{resp: &identityv1.ListIdpGroupNamesResponse{Names: []string{"Facilities", "Finance"}}}
}

func TestIdpGroupNames_MapsNamesAndTruncated(t *testing.T) {
	read := newIdpNamesRead()
	read.resp.Truncated = true
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "a", RolesValue: []string{"site-admin"}})
	got, err := resolvers.IdpGroupNamesResolver(ctx, read, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"Facilities", "Finance"}, got.Names)
	require.True(t, got.Truncated)
}

func TestIdpGroupNames_NoNamesIsAnEmptyListNotNull(t *testing.T) {
	read := &idpNamesRead{resp: &identityv1.ListIdpGroupNamesResponse{}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "a", RolesValue: []string{"site-admin"}})
	got, err := resolvers.IdpGroupNamesResolver(ctx, read, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, got.Names)
	require.Empty(t, got.Names)
	require.False(t, got.Truncated)
}

func TestIdpGroupNames_PrefixIsTrimmedAndPassedThrough(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "a", RolesValue: []string{"site-admin"}})
	for _, tc := range []struct {
		in   *string
		want string
	}{{nil, ""}, {ptrStr(""), ""}, {ptrStr("  "), ""}, {ptrStr(" Fin "), "Fin"}, {ptrStr("fin"), "fin"}} {
		read := newIdpNamesRead()
		_, err := resolvers.IdpGroupNamesResolver(ctx, read, tc.in, nil)
		require.NoError(t, err)
		require.Len(t, read.reqs, 1)
		require.Equal(t, tc.want, read.reqs[0].GetPrefix())
	}
}

// An unset or non-positive limit goes as 0 so identity applies its own default;
// a larger one is capped at identity's maximum of 200.
func TestIdpGroupNames_LimitPassThrough(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "a", RolesValue: []string{"site-admin"}})
	for _, tc := range []struct {
		in   *int
		want int32
	}{{nil, 0}, {ptrInt(0), 0}, {ptrInt(-3), 0}, {ptrInt(7), 7}, {ptrInt(200), 200}, {ptrInt(5000), 200}} {
		read := newIdpNamesRead()
		_, err := resolvers.IdpGroupNamesResolver(ctx, read, nil, tc.in)
		require.NoError(t, err)
		require.Equal(t, tc.want, read.reqs[0].GetLimit())
	}
}

// Whoever edits category access may list: group.manage or template.manage. A
// reader, a plain author and compliance may not, and identity is not asked.
func TestIdpGroupNames_WhoMay(t *testing.T) {
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
			read := newIdpNamesRead()
			_, err := resolvers.IdpGroupNamesResolver(ctxWithStubClaims(t, tc.claims), read, nil, nil)
			if tc.wantAllow {
				require.NoError(t, err)
				return
			}
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			require.Empty(t, read.reqs)
		})
	}
}

func TestIdpGroupNames_UnavailableErrorAndSignedOut(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "a", RolesValue: []string{"site-admin"}})
	_, err := resolvers.IdpGroupNamesResolver(ctx, nil, nil, nil)
	require.Equal(t, codes.Unavailable, status.Code(err))

	read := newIdpNamesRead()
	read.err = status.Error(codes.PermissionDenied, "not allowed")
	_, err = resolvers.IdpGroupNamesResolver(ctx, read, nil, nil)
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = resolvers.IdpGroupNamesResolver(context.Background(), newIdpNamesRead(), nil, nil)
	require.Error(t, err)
}
