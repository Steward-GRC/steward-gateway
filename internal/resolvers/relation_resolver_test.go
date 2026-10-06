// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

type fakeRelationClient struct {
	corev1.RelationServiceClient
	list    []*corev1.RelatedPolicy
	lastSet *corev1.SetRelatedPoliciesRequest
}

func (f *fakeRelationClient) ListRelatedPolicies(_ context.Context, _ *corev1.ListRelatedPoliciesRequest, _ ...grpc.CallOption) (*corev1.ListRelatedPoliciesResponse, error) {
	return &corev1.ListRelatedPoliciesResponse{Related: f.list}, nil
}

func (f *fakeRelationClient) SetRelatedPolicies(_ context.Context, in *corev1.SetRelatedPoliciesRequest, _ ...grpc.CallOption) (*corev1.SetRelatedPoliciesResponse, error) {
	f.lastSet = in
	out := make([]*corev1.RelatedPolicy, len(in.RelatedPolicyIds))
	for i, id := range in.RelatedPolicyIds {
		out[i] = &corev1.RelatedPolicy{PolicyId: id, Number: "POL-IT-1", Title: "T"}
	}
	return &corev1.SetRelatedPoliciesResponse{Related: out}, nil
}

// TestRelatedPoliciesResolver_FiltersUnreadableAndDrafts: the display resolver
// runs each linked policy through the read model with the caller's subject, so a
// read-only viewer sees a published related link but NOT a never-published draft
// linked as related — a related link must never disclose a draft's existence
// (the reported leak). Authoritative Number/Title come from the loaded policy.
func TestRelatedPoliciesResolver_FiltersUnreadableAndDrafts(t *testing.T) {
	gc, ic, pc := core22Fixtures()
	rc := &fakeRelationClient{list: []*corev1.RelatedPolicy{
		{PolicyId: "B-open", Number: "stale", Title: "stale"},
		{PolicyId: "D-draft", Number: "POL-OPEN-D", Title: "Secret draft"},
	}}
	// u-contractor reads cat-open (Everyone) but is not an overseer of either.
	ctx := ctxWithRoles(t, "u-contractor", nil)

	out, err := resolvers.RelatedPoliciesResolver(ctx, rc, pc, gc, nil, ic, "A-open")
	if err != nil {
		t.Fatalf("RelatedPoliciesResolver: %v", err)
	}
	if len(out) != 1 || out[0].PolicyID != "B-open" || out[0].Number != "POL-OPEN-B" {
		t.Fatalf("expected only the published link [B-open] with authoritative number, got: %+v", out)
	}
}

func TestSetRelatedPoliciesResolver_ForwardsAndGates(t *testing.T) {
	c := &fakeRelationClient{}
	// Unauthenticated is denied and never calls core. nil policy/group/identity
	// clients disable the read-superset check (offline/mock mode), so this
	// exercises the authentication gate alone.
	if _, err := resolvers.SetRelatedPoliciesResolver(context.Background(), log.Nop(), c, nil, nil, nil, "a", []string{"b"}); err == nil {
		t.Fatal("expected error with no authenticated user")
	}
	if c.lastSet != nil {
		t.Fatal("must not call core without authenticated user")
	}
	// Authenticated forwards the ids (superset check disabled: nil engines).
	ctx := ctxWithRoles(t, "user-1", []string{"author"})
	out, err := resolvers.SetRelatedPoliciesResolver(ctx, log.Nop(), c, nil, nil, nil, "a", []string{"b", "c"})
	if err != nil {
		t.Fatalf("SetRelatedPoliciesResolver: %v", err)
	}
	if c.lastSet == nil || c.lastSet.PolicyId != "a" || len(c.lastSet.RelatedPolicyIds) != 2 {
		t.Fatalf("unexpected forwarded request: %+v", c.lastSet)
	}
	if len(out) != 2 {
		t.Fatalf("unexpected result len: %d", len(out))
	}
}
