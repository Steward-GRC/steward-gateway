// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	log "github.com/Bugs5382/go-log"
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

	raw := `{"operation":"DRAFT","owner_user_id":"user-1","result":{"sections":[{"sectionKey":"purpose","content":"Body."}]}}`
	if err := rdb.Set(context.Background(), "ai:job-result:aijob-abc:DRAFT", raw, 0).Err(); err != nil {
		t.Fatal(err)
	}

	got, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, "ai:job-result:aijob-abc:DRAFT")
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

	raw := `{"operation":"REVIEW","owner_user_id":"user-1","result":{"findings":[{"sectionKey":"purpose","severity":"BLOCKER","finding":"Missing scope.","suggestion":"Add one."}]}}`
	if err := rdb.Set(context.Background(), "ai:job-result:pol-1:ver-1:REVIEW", raw, 0).Err(); err != nil {
		t.Fatal(err)
	}

	got, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, "ai:job-result:pol-1:ver-1:REVIEW")
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
	_, err := resolvers.AIJobResultContentResolver(context.Background(), log.Nop(), reader, "ai:job-result:aijob-abc:DRAFT")
	if err == nil {
		t.Fatal("expected an error for an unauthenticated caller")
	}
}

func TestAIJobResultContentResolver_NotFound(t *testing.T) {
	reader, _ := newTestContentReader(t)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
	_, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, "ai:job-result:missing:DRAFT")
	if err == nil {
		t.Fatal("expected an error for a missing resultRef")
	}
}

// putResult stores a raw envelope under ref.
func putResult(t *testing.T, rdb redis.UniversalClient, ref, raw string) {
	t.Helper()
	if err := rdb.Set(context.Background(), ref, raw, 0).Err(); err != nil {
		t.Fatal(err)
	}
}

// requireNotFound fails unless err is the standard not-found refusal.
func requireNotFound(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got content")
	}
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("expected codes.NotFound, got %v (%v)", got, err)
	}
}

const ownedEnvelope = `{"operation":"REWRITE","owner_user_id":"user-1","result":{"sections":[]}}`

func TestAIJobResultContentResolver_OwnerReadsOwnResult(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	putResult(t, rdb, "ai:job-result:job-1:REWRITE", ownedEnvelope)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})

	got, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, "ai:job-result:job-1:REWRITE")
	if err != nil {
		t.Fatalf("owner refused: %v", err)
	}
	if got.Operation != "REWRITE" || got.ResultJSON != `{"sections":[]}` {
		t.Fatalf("unexpected content: %+v", got)
	}
}

func TestAIJobResultContentResolver_OtherUserRefused(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	putResult(t, rdb, "ai:job-result:job-1:REWRITE", ownedEnvelope)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-2"})

	got, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, "ai:job-result:job-1:REWRITE")
	requireNotFound(t, err)
	if got != nil {
		t.Fatalf("content leaked with the refusal: %+v", got)
	}
}

// The refusal for a result that belongs to someone else and for one that does
// not exist must be the same, so a ref reveals nothing about another job.
func TestAIJobResultContentResolver_OtherUserAndMissingLookAlike(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	putResult(t, rdb, "ai:job-result:job-1:REWRITE", ownedEnvelope)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-2"})

	_, other := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, "ai:job-result:job-1:REWRITE")
	_, missing := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, "ai:job-result:nope:REWRITE")
	requireNotFound(t, other)
	requireNotFound(t, missing)
	if other.Error() != missing.Error() {
		t.Fatalf("refusals differ: %q vs %q", other, missing)
	}
}

func TestAIJobResultContentResolver_EmptyOwnerRefused(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	putResult(t, rdb, "ai:job-result:job-1:REWRITE", `{"operation":"REWRITE","owner_user_id":"","result":{}}`)

	// Not even an empty-id caller matches an empty owner.
	for _, uid := range []string{"user-1", ""} {
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: uid})
		_, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, "ai:job-result:job-1:REWRITE")
		requireNotFound(t, err)
	}
}

func TestAIJobResultContentResolver_EmptyCallerRefused(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	putResult(t, rdb, "ai:job-result:job-1:REWRITE", ownedEnvelope)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: ""})

	_, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, "ai:job-result:job-1:REWRITE")
	requireNotFound(t, err)
}

// An envelope written before owners were recorded is owned by nobody.
func TestAIJobResultContentResolver_EnvelopeWithoutOwnerRefused(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	putResult(t, rdb, "ai:job-result:job-1:REWRITE", `{"operation":"REWRITE","result":{"sections":[]}}`)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})

	_, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, "ai:job-result:job-1:REWRITE")
	requireNotFound(t, err)
}

// While an admin acts as someone, the principal on the context is that user,
// so the comparison is against the user being acted as.
func TestAIJobResultContentResolver_ImpersonationComparesTheActedAsUser(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	putResult(t, rdb, "ai:job-result:job-1:REWRITE", ownedEnvelope)
	ctx := principal.WithImpersonator(context.Background(), principal.Static{UserIDValue: "admin-1"})

	asOwner := principal.WithClaims(ctx, principal.Static{UserIDValue: "user-1"})
	if _, err := resolvers.AIJobResultContentResolver(asOwner, log.Nop(), reader, "ai:job-result:job-1:REWRITE"); err != nil {
		t.Fatalf("admin acting as the owner refused: %v", err)
	}
	asOther := principal.WithClaims(ctx, principal.Static{UserIDValue: "user-2"})
	_, err := resolvers.AIJobResultContentResolver(asOther, log.Nop(), reader, "ai:job-result:job-1:REWRITE")
	requireNotFound(t, err)
}

// The ref is an opaque key: whatever it looks like, only the stored owner decides.
func TestAIJobResultContentResolver_RefIsNotParsed(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	// A ref that embeds another user's id and a different operation.
	ref := "anything:user-2:whatever/REVIEW"
	putResult(t, rdb, ref, ownedEnvelope)

	owner := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
	got, err := resolvers.AIJobResultContentResolver(owner, log.Nop(), reader, ref)
	if err != nil {
		t.Fatalf("owner refused for an odd ref: %v", err)
	}
	if got.Operation != "REWRITE" {
		t.Fatalf("operation must come from the envelope, got %q", got.Operation)
	}
	other := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-2"})
	_, err = resolvers.AIJobResultContentResolver(other, log.Nop(), reader, ref)
	requireNotFound(t, err)
}
