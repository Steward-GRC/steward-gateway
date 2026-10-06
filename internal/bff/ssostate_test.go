// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/Bugs5382/go-redis"
	"github.com/stretchr/testify/require"
)

// newTestStoreClock is newTestStore plus the miniredis handle, so a test can
// fast-forward past a TTL.
func newTestStoreClock(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := goredis.Connect(context.Background(), goredis.WithAddr(mr.Addr()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return NewStore(c, time.Hour), mr
}

func TestSSOStateStore_SingleUse(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, st.PutSSOState(ctx, "s1", SSOState{Connection: "example-sso", Mode: "login"}, time.Minute))
	got, ok, err := st.TakeSSOState(ctx, "s1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "example-sso", got.Connection)
	_, ok, _ = st.TakeSSOState(ctx, "s1")
	require.False(t, ok, "state must be single-use")
}

// The full record round-trips.
func TestSSOStateStore_RoundTripAllFields(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	want := SSOState{
		Connection:   "example-saml",
		ConnectionID: "conn-123",
		Mode:         "test",
		ReturnPath:   "/admin/organizations",
		Tenant:       "example.org",
		AdminUserID:  "admin-1",
	}
	require.NoError(t, st.PutSSOState(ctx, "s2", want, time.Minute))
	got, ok, err := st.TakeSSOState(ctx, "s2")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, want, got)
}

func TestSSOStateStore_TakeMiss(t *testing.T) {
	st := newTestStore(t)
	_, ok, err := st.TakeSSOState(context.Background(), "nope")
	require.NoError(t, err)
	require.False(t, ok)
}

// TTL expiry: a state that outlives its ttl must miss on Take, same as if it
// had never been stored — the callback window is bounded server-side, not
// just by the client returning promptly.
func TestSSOStateStore_TTLExpiry(t *testing.T) {
	st, mr := newTestStoreClock(t)
	ctx := context.Background()
	require.NoError(t, st.PutSSOState(ctx, "s3", SSOState{Connection: "example-sso", Mode: "login"}, time.Minute))

	mr.FastForward(2 * time.Minute)

	_, ok, err := st.TakeSSOState(ctx, "s3")
	require.NoError(t, err)
	require.False(t, ok, "state must expire after its ttl")
}

func TestGenerateState_UniqueAndURLSafe(t *testing.T) {
	a, err := GenerateState()
	require.NoError(t, err)
	b, err := GenerateState()
	require.NoError(t, err)
	require.NotEmpty(t, a)
	require.NotEqual(t, a, b)
	require.False(t, strings.ContainsAny(a, "+/="), "state must be base64url (no +, /, or = padding)")
}
