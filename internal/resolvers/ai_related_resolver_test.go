// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

func TestRelatedPolicySuggestions_mapsAndScopesFromClaims(t *testing.T) {
	client := &fakeAIClient{relatedResp: &aiv1.GetRelatedPoliciesResponse{
		Related: []*aiv1.RelatedPolicy{
			{PolicyId: "p2", PolicyTitle: "Secure Coding", CategoryId: "g-eng", VersionNo: 4, Distance: 0.12},
			{PolicyId: "p3", PolicyTitle: "Change Management", CategoryId: "g-ops", VersionNo: 2, Distance: 0.31},
		},
	}}
	first := 5

	out, err := resolvers.RelatedPolicySuggestionsResolver(ctxWithUser(t, "u-42"), client, aiReadableCategory("g-eng"), "p1", &first)
	if err != nil {
		t.Fatalf("RelatedPolicySuggestions: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 suggestions, got %d", len(out))
	}
	if out[0].PolicyID != "p2" || out[0].PolicyTitle != "Secure Coding" || out[0].CategoryID != "g-eng" ||
		out[0].VersionNo != 4 || !approxEqual(out[0].Distance, 0.12) {
		t.Fatalf("first suggestion not mapped: %+v", out[0])
	}

	// policyId, first, and the caller's read scope must be threaded from claims
	// and the category rules, never trusted from client input.
	req := client.lastRelatedReq
	if req.GetPolicyId() != "p1" {
		t.Fatalf("policyId: got %q want p1", req.GetPolicyId())
	}
	if req.GetTopN() != 5 {
		t.Fatalf("topN: got %d want 5", req.GetTopN())
	}
	if client.lastActor != "u-42" {
		t.Fatalf("actor: got %q want u-42", client.lastActor)
	}
	scope := req.GetScope()
	if len(scope.GetCategoryIds()) != 1 || scope.GetCategoryIds()[0] != "g-eng" {
		t.Fatalf("read scope not derived from the category rules: %+v", scope)
	}
	if scope.GetIncludeSensitive() || scope.GetAllCategories() {
		t.Fatalf("a reader without grants gets no sensitive or all-category scope: %+v", scope)
	}
}

func TestRelatedPolicySuggestions_nilFirstLeavesTopNZero(t *testing.T) {
	client := &fakeAIClient{relatedResp: &aiv1.GetRelatedPoliciesResponse{}}

	if _, err := resolvers.RelatedPolicySuggestionsResolver(ctxWithUser(t, "u-1"), client, nil, "p1", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.lastRelatedReq.GetTopN() != 0 {
		t.Fatalf("expected topN=0 (server default) when first is nil, got %d", client.lastRelatedReq.GetTopN())
	}
}

// TestRelatedPolicySuggestions_failsOpenOnRPCError verifies the supplementary
// surface degrades to an empty list rather than failing the whole response.
func TestRelatedPolicySuggestions_failsOpenOnRPCError(t *testing.T) {
	client := &fakeAIClient{relatedErr: errors.New("ai svc unavailable")}

	out, err := resolvers.RelatedPolicySuggestionsResolver(ctxWithUser(t, "u-1"), client, nil, "p1", nil)
	if err != nil {
		t.Fatalf("expected fail-open (nil error), got %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty list on RPC error, got %d", len(out))
	}
}

func TestRelatedPolicySuggestions_requiresAuth(t *testing.T) {
	client := &fakeAIClient{}
	if _, err := resolvers.RelatedPolicySuggestionsResolver(context.Background(), client, nil, "p1", nil); err == nil {
		t.Fatal("expected an unauthenticated error with no claims in context")
	}
}

func TestRelatedPolicySuggestions_requiresPolicyID(t *testing.T) {
	client := &fakeAIClient{}
	if _, err := resolvers.RelatedPolicySuggestionsResolver(ctxWithUser(t, "u-1"), client, nil, "", nil); err == nil {
		t.Fatal("expected an error for an empty policyId")
	}
}

// approxEqual compares float64 values within a small tolerance, since a proto
// float32 distance widens to float64 with a tiny representation error.
func approxEqual(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-6
}
