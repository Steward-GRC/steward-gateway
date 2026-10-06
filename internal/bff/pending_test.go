// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"testing"
	"time"
)

func TestPendingStore_CreateGetSaveDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	want := PendingAuth{
		AccessToken: "at", UserID: "u1",
		Factors:        []string{"totp", "email"},
		TokenExpiresAt: time.Now().Add(5 * time.Minute),
		ExpiresAt:      time.Now().Add(pendingTTL),
	}
	if err := s.CreatePending(ctx, "p1", want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetPending(ctx, "p1")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.AccessToken != "at" || got.UserID != "u1" || len(got.Factors) != 2 || got.Attempts != 0 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	got.Attempts = 3
	got.WebauthnSessionID = "wa1"
	if err := s.SavePending(ctx, "p1", got); err != nil {
		t.Fatal(err)
	}
	got2, ok, _ := s.GetPending(ctx, "p1")
	if !ok || got2.Attempts != 3 || got2.WebauthnSessionID != "wa1" {
		t.Fatalf("save not persisted: ok=%v %+v", ok, got2)
	}

	if err := s.DeletePending(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetPending(ctx, "p1"); ok {
		t.Fatal("expected miss after delete")
	}
}

func TestPendingStore_ConsumeIsSingleUse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.CreatePending(ctx, "p2", PendingAuth{UserID: "u1", ExpiresAt: time.Now().Add(pendingTTL)})

	got, ok, err := s.ConsumePending(ctx, "p2")
	if err != nil || !ok || got.UserID != "u1" {
		t.Fatalf("first consume: ok=%v err=%v %+v", ok, err, got)
	}
	if _, ok, _ := s.ConsumePending(ctx, "p2"); ok {
		t.Fatal("second consume must miss (single-use)")
	}
	if _, ok, _ := s.GetPending(ctx, "p2"); ok {
		t.Fatal("consume must delete the record")
	}
}

func TestPendingStore_SaveDoesNotResurrectExpired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.SavePending(ctx, "ghost", PendingAuth{UserID: "u1"}); err != nil {
		t.Fatalf("save on missing key must be a no-op, got err=%v", err)
	}
	if _, ok, _ := s.GetPending(ctx, "ghost"); ok {
		t.Fatal("save must not create a pending record that Create never made")
	}
}
