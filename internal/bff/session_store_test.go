// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"testing"
	"time"

	redis "github.com/Bugs5382/go-redis"
	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := redis.Connect(context.Background(), redis.WithAddr(mr.Addr()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return NewStore(c, time.Hour)
}

func TestStore_CreateGetDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	want := Session{AccessToken: "at", RefreshToken: "rt", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(5 * time.Minute)}
	require.NoError(t, s.Create(ctx, "sid1", want))

	got, ok, err := s.Get(ctx, "sid1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "at", got.AccessToken)
	require.Equal(t, "csrf", got.CSRFToken)
	require.Equal(t, "u1", got.UserID)

	require.NoError(t, s.Delete(ctx, "sid1"))
	_, ok, err = s.Get(ctx, "sid1")
	require.NoError(t, err)
	require.False(t, ok, "expected a miss after delete")
}

func TestStore_RefreshLockIsSingleFlight(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tok, ok, err := s.AcquireRefreshLock(ctx, "sid1", time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
	_, ok, err = s.AcquireRefreshLock(ctx, "sid1", time.Minute)
	require.NoError(t, err)
	require.False(t, ok, "a second refresher must not get the lock")

	require.NoError(t, s.ReleaseRefreshLock(ctx, "sid1", "not-the-owner"))
	_, ok, _ = s.AcquireRefreshLock(ctx, "sid1", time.Minute)
	require.False(t, ok, "a non-owner release must leave the lock in place")

	require.NoError(t, s.ReleaseRefreshLock(ctx, "sid1", tok))
	_, ok, err = s.AcquireRefreshLock(ctx, "sid1", time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
}
