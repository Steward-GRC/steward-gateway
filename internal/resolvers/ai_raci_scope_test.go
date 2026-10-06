// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// The AI category gate honours the category rules: a user with a direct
// author grant on a category may draft in it, a user with none is denied.

// aiRaciCat is the target category id.
const aiRaciCat = "cat-records"

// aiRaciEnv builds a category client for aiRaciCat with the given owners and
// rules.
func aiRaciEnv(owners []string, rules []*corev1.CategoryRule) *raciCategoryClient {
	gc := newRaciReadClient(
		map[string]*corev1.Category{aiRaciCat: {Id: aiRaciCat, Name: "Records", ParentId: "", Owners: owners}},
		map[string][]*corev1.CategoryRule{aiRaciCat: rules},
	)
	return gc
}

// TestSubmitDraftGeneration_RACIAuthorAllowed is Bob's case: a direct
// category_rules author=allow rule (plus everyone-read) authorizes a draft with
// groupId=category through its rules alone.
func TestSubmitDraftGeneration_RACIAuthorAllowed(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "aijob-Bob"}}
	gc := aiRaciEnv(nil, []*corev1.CategoryRule{
		allowEveryoneRule(),
		authorRule("Bob", corev1.GrantEffect_GRANT_EFFECT_ALLOW),
	})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "Bob", RolesValue: []string{"reader"}})

	gid := aiRaciCat
	res, err := resolvers.SubmitDraftGenerationResolver(
		ctx, client, gc, nil,
		resolvers.SubmitDraftGenerationInput{CategoryID: &gid, Brief: "Draft the IT Access Management policy."},
	)
	if err != nil {
		t.Fatalf("expected RACI author to authorize draft, got %v", err)
	}
	if res.JobID != "aijob-Bob" {
		t.Fatalf("jobId: got %q", res.JobID)
	}
	if client.lastSubmitReq == nil || client.lastSubmitReq.CategoryId != aiRaciCat {
		t.Fatalf("AI SubmitAIJob not invoked with the category scope: %+v", client.lastSubmitReq)
	}
}

// TestSubmitDraftGeneration_RACINoGrantDenied proves a caller with no RACI
// author grant on the category is still denied, and
// the AI service is never dialed.
func TestSubmitDraftGeneration_RACINoGrantDenied(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "nope"}}
	// everyone can READ, but no author rule for this caller → draft (author) denied.
	gc := aiRaciEnv(nil, []*corev1.CategoryRule{allowEveryoneRule()})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "stranger", RolesValue: []string{"reader"}})

	gid := aiRaciCat
	_, err := resolvers.SubmitDraftGenerationResolver(
		ctx, client, gc, nil,
		resolvers.SubmitDraftGenerationInput{CategoryID: &gid, Brief: "b"},
	)
	if err == nil {
		t.Fatal("expected permission denied for a caller with no RACI author grant")
	}
	if client.lastSubmitReq != nil {
		t.Fatal("AI service must not be dialed when the RACI scope check fails")
	}
}

// TestSubmitDraftGeneration_RACIDeniedAuthorDenied proves a deny-author rule
// removes a caller's ability to draft even if an everyone rule would otherwise
// read — deny-aware, order-resolved, exactly like the co-authoring gate.
func TestSubmitDraftGeneration_RACIDeniedAuthorDenied(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "nope"}}
	gc := aiRaciEnv(nil, []*corev1.CategoryRule{
		authorRule("denied-u", corev1.GrantEffect_GRANT_EFFECT_DENY),
		allowEveryoneRule(),
	})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "denied-u", RolesValue: []string{"reader"}})

	gid := aiRaciCat
	_, err := resolvers.SubmitDraftGenerationResolver(
		ctx, client, gc, nil,
		resolvers.SubmitDraftGenerationInput{CategoryID: &gid, Brief: "b"},
	)
	if err == nil {
		t.Fatal("expected permission denied for a RACI-denied author")
	}
	if client.lastSubmitReq != nil {
		t.Fatal("AI service must not be dialed for a denied author")
	}
}

// TestSubmitDraftGeneration_SiteAdminAlwaysAllowed proves the site-admin bypass
// survives: a site-admin drafts in any category with no RACI rules and no
// any directory group.
func TestSubmitDraftGeneration_SiteAdminAlwaysAllowed(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "aijob-admin"}}
	gc := aiRaciEnv(nil, []*corev1.CategoryRule{})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-u", RolesValue: []string{"site-admin"}})

	gid := aiRaciCat
	res, err := resolvers.SubmitDraftGenerationResolver(
		ctx, client, gc, nil,
		resolvers.SubmitDraftGenerationInput{CategoryID: &gid, Brief: "b"},
	)
	if err != nil {
		t.Fatalf("expected site-admin bypass to authorize draft, got %v", err)
	}
	if res.JobID != "aijob-admin" || client.lastSubmitReq == nil {
		t.Fatalf("AI SubmitAIJob not invoked for site-admin: %+v", client.lastSubmitReq)
	}
}

// TestSubmitDraftGeneration_EmptyGidNoOp proves the empty-gid no-op survives: a
// non-admin with no groups and no RACI grant may still submit a draft when no
// category scope hint is supplied (the AI handler applies its own defence).
func TestSubmitDraftGeneration_EmptyGidNoOp(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "aijob-noscope"}}
	gc := aiRaciEnv(nil, []*corev1.CategoryRule{})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-noscope", RolesValue: []string{"reader"}})

	res, err := resolvers.SubmitDraftGenerationResolver(
		ctx, client, gc, nil,
		resolvers.SubmitDraftGenerationInput{Brief: "b"}, // no GroupID
	)
	if err != nil {
		t.Fatalf("empty gid must be a no-op, got %v", err)
	}
	if res.JobID != "aijob-noscope" {
		t.Fatalf("jobId: got %q", res.JobID)
	}
	if client.lastSubmitReq == nil || client.lastSubmitReq.CategoryId != "" {
		t.Fatalf("expected empty group scope forwarded: %+v", client.lastSubmitReq)
	}
}

// TestSubmitDraftGeneration_RACIReadNotEnoughForAuthor proves the read/author
// distinction: a caller with only RACI READ on the category (everyone-read, no
// author grant) is denied a DRAFT, which requires author.
func TestSubmitDraftGeneration_RACIReadNotEnoughForAuthor(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "nope"}}
	gc := aiRaciEnv(nil, []*corev1.CategoryRule{allowEveryoneRule()})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-only", RolesValue: []string{"reader"}})

	gid := aiRaciCat
	_, err := resolvers.SubmitDraftGenerationResolver(
		ctx, client, gc, nil,
		resolvers.SubmitDraftGenerationInput{CategoryID: &gid, Brief: "b"},
	)
	if err == nil {
		t.Fatal("read-only RACI access must NOT authorize a draft (author required)")
	}
	if client.lastSubmitReq != nil {
		t.Fatal("AI service must not be dialed when author scope check fails")
	}
}

// TestSearchAndAnswer_RACIReadAllowed proves a READ-type operation is authorized
// by RACI READ: an everyone-read rule lets a caller run
// a scoped search.
func TestSearchAndAnswer_RACIReadAllowed(t *testing.T) {
	client := &fakeAIClient{searchResp: &aiv1.SearchAndAnswerResponse{Answer: "the policy says X"}}
	gc := aiRaciEnv(nil, []*corev1.CategoryRule{allowEveryoneRule()})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "Bob", RolesValue: []string{"reader"}})

	gid := aiRaciCat
	out, err := resolvers.SearchAndAnswerResolver(ctx, client, gc, "is X allowed?", &gid)
	if err != nil {
		t.Fatalf("expected RACI read to authorize search, got %v", err)
	}
	if out.Answer != "the policy says X" {
		t.Fatalf("unexpected answer: %+v", out)
	}
	if client.lastSearchReq == nil || client.lastSearchReq.CategoryId != aiRaciCat {
		t.Fatalf("AI SearchAndAnswer not invoked with the category scope: %+v", client.lastSearchReq)
	}
}

// TestSearchAndAnswer_RACINoReadDenied proves a caller with no RACI read on the
// category (no rules) is denied a scoped search, and the AI
// service is never dialed.
func TestSearchAndAnswer_RACINoReadDenied(t *testing.T) {
	client := &fakeAIClient{searchResp: &aiv1.SearchAndAnswerResponse{}}
	gc := aiRaciEnv(nil, []*corev1.CategoryRule{})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "stranger", RolesValue: []string{"reader"}})

	gid := aiRaciCat
	_, err := resolvers.SearchAndAnswerResolver(ctx, client, gc, "q", &gid)
	if err == nil {
		t.Fatal("expected permission denied for a caller with no RACI read grant")
	}
	if client.lastSearchReq != nil {
		t.Fatal("AI service must not be dialed when the RACI read scope check fails")
	}
}
