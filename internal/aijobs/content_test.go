// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package aijobs

import (
	"context"
	"errors"
	"testing"

	redis "github.com/Bugs5382/go-redis"
	"github.com/alicebob/miniredis/v2"
)

func newTestContentReader(t *testing.T) (*ContentReader, redis.UniversalClient) {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := redis.Connect(context.Background(), redis.WithAddr(mr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return NewContentReader(c.Redis()), c.Redis()
}

// TestContentReader_Fetch_Draft mirrors the exact envelope shape the ai
// operator writes for a DRAFT job (its result envelope
// wrapping generation.DraftResponse).
func TestContentReader_Fetch_Draft(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	ctx := context.Background()

	raw := `{"operation":"DRAFT","result":{"sections":[{"sectionKey":"purpose","content":"Body one."},{"sectionKey":"scope","content":"Body two."}]}}`
	if err := rdb.Set(ctx, "ai:job-result:aijob-abc:DRAFT", raw, 0).Err(); err != nil {
		t.Fatal(err)
	}

	got, err := reader.Fetch(ctx, "ai:job-result:aijob-abc:DRAFT")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Operation != "DRAFT" {
		t.Fatalf("expected operation DRAFT, got %q", got.Operation)
	}
	if got.ResultJSON != `{"sections":[{"sectionKey":"purpose","content":"Body one."},{"sectionKey":"scope","content":"Body two."}]}` {
		t.Fatalf("unexpected resultJson: %s", got.ResultJSON)
	}
}

// TestContentReader_Fetch_Review mirrors the REVIEW job envelope shape
// (generation.ReviewResponse).
func TestContentReader_Fetch_Review(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	ctx := context.Background()

	raw := `{"operation":"REVIEW","result":{"findings":[{"sectionKey":"purpose","severity":"BLOCKER","finding":"Missing scope.","suggestion":"Add a scope statement."}]}}`
	if err := rdb.Set(ctx, "ai:job-result:pol-1:ver-1:REVIEW", raw, 0).Err(); err != nil {
		t.Fatal(err)
	}

	got, err := reader.Fetch(ctx, "ai:job-result:pol-1:ver-1:REVIEW")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Operation != "REVIEW" {
		t.Fatalf("expected operation REVIEW, got %q", got.Operation)
	}
	if got.ResultJSON != `{"findings":[{"sectionKey":"purpose","severity":"BLOCKER","finding":"Missing scope.","suggestion":"Add a scope statement."}]}` {
		t.Fatalf("unexpected resultJson: %s", got.ResultJSON)
	}
}

func TestContentReader_Fetch_NotFound(t *testing.T) {
	reader, _ := newTestContentReader(t)
	_, err := reader.Fetch(context.Background(), "ai:job-result:missing:DRAFT")
	if !errors.Is(err, ErrResultNotFound) {
		t.Fatalf("expected ErrResultNotFound, got %v", err)
	}
}
