// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	log "github.com/Bugs5382/go-log"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func relatedPolicyFromProto(r *corev1.RelatedPolicy) *RelatedPolicy {
	return &RelatedPolicy{
		PolicyID: r.GetPolicyId(),
		Number:   r.GetNumber(),
		Title:    r.GetTitle(),
	}
}

// RelatedPoliciesResolver lists a policy's structured related-policy links, resolved to
// number+title.
func RelatedPoliciesResolver(ctx context.Context, client corev1.RelationServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, identity identityv1.IdentityReadServiceClient, policyID string) ([]*RelatedPolicy, error) {
	resp, err := client.ListRelatedPolicies(ctx, &corev1.ListRelatedPoliciesRequest{PolicyId: policyID})
	if err != nil {
		return nil, fmt.Errorf("list related policies: %w", err)
	}
	related := resp.GetRelated()
	if len(related) == 0 {
		return []*RelatedPolicy{}, nil
	}

	loaded := make([]*Policy, 0, len(related))
	for _, r := range related {
		p, err := loadPolicyByID(ctx, policyClient, r.GetPolicyId())
		if err != nil {
			if status.Code(err) == codes.NotFound {
				continue
			}
			return nil, err
		}
		loaded = append(loaded, p)
	}

	visible, err := resolvePolicyReadModel(ctx, loaded, policyClient, categoryClient, adminClient, identity)
	if err != nil {
		return nil, err
	}
	out := make([]*RelatedPolicy, 0, len(visible))
	for _, p := range visible {
		out = append(out, &RelatedPolicy{PolicyID: p.ID, Number: p.Number, Title: p.Title})
	}
	return out, nil
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
