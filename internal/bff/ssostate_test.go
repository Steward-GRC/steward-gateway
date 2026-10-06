// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newMiniRedis(t *testing.T) redis.UniversalClient {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// newMiniRedisClock is like newMiniRedis but also returns the miniredis
// server handle so tests can fast-forward its clock to exercise TTL expiry.
func newMiniRedisClock(t *testing.T) (redis.UniversalClient, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()}), mr
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

// gateway#saml-jit-sso task 12: the full record round-trips, not just the
// field the single-use test happens to check.
func TestSSOStateStore_RoundTripAllFields(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	want := SSOState{
		Connection:   "acme-saml",
		ConnectionID: "conn-123",
		Nonce:        "nonce-xyz",
		ReturnTo:     "/dashboard",
		Mode:         "test",
	}
	require.NoError(t, st.Put(ctx, "s2", want, time.Minute))
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
