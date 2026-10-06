// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// relatedPolicySuggestionFromProto maps an aiv1.RelatedPolicy onto the GraphQL
// RelatedPolicySuggestion model.
func relatedPolicySuggestionFromProto(r *aiv1.RelatedPolicy) *RelatedPolicySuggestion {
	if r == nil {
		return nil
	}
	return &RelatedPolicySuggestion{
		PolicyID:    r.GetPolicyId(),
		PolicyTitle: r.GetPolicyTitle(),
		CategoryID:  r.GetCategoryId(),
		VersionNo:   int(r.GetVersionNo()),
		Distance:    float64(r.GetDistance()),
	}
}

// RelatedPolicySuggestionsResolver returns AI-suggested related policies for a policy, from
// access-filtered centroid similarity in the AI service.
func RelatedPolicySuggestionsResolver(ctx context.Context, client aiv1.AiServiceClient, categoryClient corev1.CategoryServiceClient, policyID string, first *int) ([]*RelatedPolicySuggestion, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	if policyID == "" {
		return nil, fmt.Errorf("policyId is required")
	}
	scope, err := aiReadScope(ctx, categoryClient)
	if err != nil {
		return nil, err
	}

	var topN int32
	if first != nil && *first > 0 {
		topN = toInt32(*first)
	}

	resp, err := client.GetRelatedPolicies(ctx, &aiv1.GetRelatedPoliciesRequest{
		PolicyId: policyID,
		TopN:     topN,
		Scope:    scope,
	})
	if err != nil {
		return []*RelatedPolicySuggestion{}, nil
	}

	out := make([]*RelatedPolicySuggestion, 0, len(resp.GetRelated()))
	for _, r := range resp.GetRelated() {
		if s := relatedPolicySuggestionFromProto(r); s != nil {
			out = append(out, s)
		}
	}
	return out, nil
}
