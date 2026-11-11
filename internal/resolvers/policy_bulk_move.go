// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// PreviewMovePolicies is the dry run of MovePolicies: what moving the documents
// to the category would do, in the order asked. Nothing changes. Site admin only.
func PreviewMovePolicies(ctx context.Context, client corev1.PolicyServiceClient, policyIDs []string, homeCategoryID string) (*MovePoliciesPreview, error) {
	actor, err := requireSiteAdmin(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.PreviewMovePolicies(ctx, &corev1.PreviewMovePoliciesRequest{
		PolicyIds: policyIDs, HomeCategoryId: homeCategoryID, ActorUserId: actor,
	})
	if err != nil {
		return nil, err
	}
	return &MovePoliciesPreview{Items: movePolicyItems(resp.GetItems())}, nil
}

// MovePolicies moves several documents to one category, all or nothing. A
// document core refuses refuses the whole batch with core's coded MOVE_REFUSED,
// which the error presenter relays as it is. Site admin only.
func MovePolicies(ctx context.Context, client corev1.PolicyServiceClient, policyIDs []string, homeCategoryID string) (*MovePoliciesResult, error) {
	actor, err := requireSiteAdmin(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.MovePolicies(ctx, &corev1.MovePoliciesRequest{
		PolicyIds: policyIDs, HomeCategoryId: homeCategoryID, ActorUserId: actor,
	})
	if err != nil {
		return nil, err
	}
	return &MovePoliciesResult{Moved: movePolicyItems(resp.GetMoved())}, nil
}

// movePolicyItems maps core's items. An empty new number or refusal is null, and
// the refusal is core's sentence unchanged.
func movePolicyItems(in []*corev1.MovePoliciesItem) []*MovePolicyItem {
	out := make([]*MovePolicyItem, 0, len(in))
	for _, it := range in {
		out = append(out, &MovePolicyItem{
			PolicyID:  it.GetPolicyId(),
			Title:     it.GetTitle(),
			Number:    it.GetNumber(),
			NewNumber: nullIfEmpty(it.GetNewNumber()),
			Refusal:   nullIfEmpty(it.GetRefusal()),
		})
	}
	return out
}

// nullIfEmpty is nil for an empty string, so GraphQL answers null, not "".
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
