// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	log "github.com/Bugs5382/go-log"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

func relatedPolicyFromProto(r *corev1.RelatedPolicy) *RelatedPolicy {
	return &RelatedPolicy{
		PolicyID: r.GetPolicyId(),
		Number:   r.GetNumber(),
		Title:    r.GetTitle(),
	}
}

// SetRelatedPoliciesResolver replaces a policy's entire related-policy set.
func SetRelatedPoliciesResolver(ctx context.Context, logger log.Logger, client corev1.RelationServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, identity identityv1.IdentityReadServiceClient, policyID string, relatedPolicyIDs []string) ([]*RelatedPolicy, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return nil, err
	}
	if err := enforceReadSuperset(ctx, logger, policyClient, categoryClient, identity, policyID, relatedPolicyIDs); err != nil {
		return nil, err
	}
	resp, err := client.SetRelatedPolicies(ctx, &corev1.SetRelatedPoliciesRequest{
		PolicyId:         policyID,
		RelatedPolicyIds: relatedPolicyIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("set related policies: %w", err)
	}
	out := make([]*RelatedPolicy, 0, len(resp.GetRelated()))
	for _, r := range resp.GetRelated() {
		out = append(out, relatedPolicyFromProto(r))
	}
	return out, nil
}
