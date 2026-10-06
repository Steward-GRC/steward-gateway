// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package principal

import (
	"context"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticSlicesAreNeverNil(t *testing.T) {
	var s Static
	assert.NotNil(t, s.Roles())
	assert.NotNil(t, s.Groups())
	assert.NotNil(t, s.IdpGroups())
	assert.NotNil(t, s.ScopedRoles())
	assert.NotNil(t, s.PolicyOverrides())
}

func TestHelpersAreNilSafe(t *testing.T) {
	assert.False(t, HasRole(nil, "site-admin"))
	assert.False(t, HasScopedRole(nil, "author", "Finance"))
	assert.False(t, IsInGroup(nil, "g1"))
}

func TestHasScopedRole(t *testing.T) {
	c := Static{RolesValue: []string{"admin"}, ScopedRolesValue: []ScopedRole{{Role: "author", Category: "Finance"}}}
	assert.True(t, HasScopedRole(c, "author", "Finance"))
	assert.False(t, HasScopedRole(c, "author", "People"))
	assert.True(t, HasScopedRole(c, "admin", ""))
}

func TestWithClaimsPutsTheActorOnTheContext(t *testing.T) {
	ctx := WithClaims(context.Background(), Static{UserIDValue: "u-alice", SessionIDValue: "s1"})
	a, ok := grpcactor.FromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, grpcactor.Actor{Subject: "u-alice", Session: "s1"}, a)
}

func TestActAsCarriesTheRealAdmin(t *testing.T) {
	ctx := WithImpersonator(context.Background(), Static{UserIDValue: "u-admin", SessionIDValue: "s9"})
	ctx = WithClaims(ctx, Static{UserIDValue: "u-bob"})
	a, ok := grpcactor.FromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, grpcactor.Actor{Subject: "u-bob", Impersonator: "u-admin", Session: "s9"}, a)
	admin, ok := ImpersonatorFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "u-admin", admin.UserID())
	eff, _ := FromContext(ctx)
	assert.Equal(t, "u-bob", eff.UserID())
}

func TestNoUserNoActor(t *testing.T) {
	ctx := WithClaims(context.Background(), Static{})
	_, ok := grpcactor.FromContext(ctx)
	assert.False(t, ok)
}
