// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/Steward-GRC/steward-gateway/internal/aijobs"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

func newTestContentReader(t *testing.T) (*aijobs.ContentReader, redis.UniversalClient) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return aijobs.NewContentReader(rdb), rdb
}

// TestAIJobResultContentResolver_Draft verifies an authenticated caller can
// fetch a DRAFT job's content by resultRef and gets back the operation tag
// plus the raw sections JSON — the exact shape the ai operator wrote.
func TestAIJobResultContentResolver_Draft(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})

	raw := `{"operation":"DRAFT","result":{"sections":[{"sectionKey":"purpose","content":"Body."}]}}`
	if err := rdb.Set(context.Background(), "ai:job-result:aijob-abc:DRAFT", raw, 0).Err(); err != nil {
		t.Fatal(err)
	}

	got, err := resolvers.AIJobResultContentResolver(ctx, reader, "ai:job-result:aijob-abc:DRAFT")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Operation != "DRAFT" {
		t.Fatalf("expected operation DRAFT, got %q", got.Operation)
	}
	if got.ResultJSON != `{"sections":[{"sectionKey":"purpose","content":"Body."}]}` {
		t.Fatalf("unexpected resultJson: %s", got.ResultJSON)
	}
}

// TestAIJobResultContentResolver_Review mirrors the Draft test for a REVIEW
// job's findings payload.
func TestAIJobResultContentResolver_Review(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})

	raw := `{"operation":"REVIEW","result":{"findings":[{"sectionKey":"purpose","severity":"BLOCKER","finding":"Missing scope.","suggestion":"Add one."}]}}`
	if err := rdb.Set(context.Background(), "ai:job-result:pol-1:ver-1:REVIEW", raw, 0).Err(); err != nil {
		t.Fatal(err)
	}

	got, err := resolvers.AIJobResultContentResolver(ctx, reader, "ai:job-result:pol-1:ver-1:REVIEW")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Operation != "REVIEW" {
		t.Fatalf("expected operation REVIEW, got %q", got.Operation)
	}
	if got.ResultJSON != `{"findings":[{"sectionKey":"purpose","severity":"BLOCKER","finding":"Missing scope.","suggestion":"Add one."}]}` {
		t.Fatalf("unexpected resultJson: %s", got.ResultJSON)
	}
}

func TestAIJobResultContentResolver_Unauthenticated(t *testing.T) {
	reader, _ := newTestContentReader(t)
	_, err := resolvers.AIJobResultContentResolver(context.Background(), reader, "ai:job-result:aijob-abc:DRAFT")
	if err == nil {
		t.Fatal("expected an error for an unauthenticated caller")
	}
}

func TestAIJobResultContentResolver_NotFound(t *testing.T) {
	reader, _ := newTestContentReader(t)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
	_, err := resolvers.AIJobResultContentResolver(ctx, reader, "ai:job-result:missing:DRAFT")
	if err == nil {
		t.Fatal("expected an error for a missing resultRef")
	}
}
