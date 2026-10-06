// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// BreakGlassRevealResolver backs breakGlassReveal: a site admin who would see
// a policy obfuscated asks for a time-boxed, audited reveal. The reason is
// required here before any backend call; identity gates on site admin, audits
// and sets the expiry. Grants are keyed by policy number.
func BreakGlassRevealResolver(
	ctx context.Context,
	adminClient identityv1.IdentityAdminServiceClient,
	policyClient corev1.PolicyServiceClient,
	policyID, reason string,
) (*BreakGlassResult, error) {
	if reason == "" {
		return nil, status.Error(codes.InvalidArgument, "break-glass requires a non-empty reason")
	}
	if adminClient == nil {
		return nil, status.Error(codes.Unavailable, "identity admin service unavailable")
	}
	if policyClient == nil {
		return nil, status.Error(codes.Unavailable, "policy service unavailable")
	}
	resp, err := policyClient.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: policyID})
	if err != nil {
		return nil, err
	}
	p := resp.GetPolicy()
	if p.GetNumber() == "" {
		return nil, status.Error(codes.NotFound, "policy not found")
	}
	revealed, err := adminClient.BreakGlassReveal(ctx, &identityv1.BreakGlassRevealRequest{
		PolicyNumber: p.GetNumber(),
		Reason:       reason,
	})
	if err != nil {
		return nil, err
	}
	return &BreakGlassResult{GrantedUntil: revealed.GetGrantedUntil()}, nil
}

// activeBreakGlassFor returns the policy numbers the caller holds an unexpired
// break-glass grant for. Only site admins are ever obfuscated, so everyone
// else skips the lookup. Any failure is no grants: the content stays
// obfuscated.
func activeBreakGlassFor(ctx context.Context, adminClient identityv1.IdentityAdminServiceClient, isSiteAdmin bool) map[string]bool {
	if !isSiteAdmin || adminClient == nil {
		return nil
	}
	resp, err := adminClient.ActiveBreakGlass(ctx, &identityv1.ActiveBreakGlassRequest{})
	if err != nil || len(resp.GetPolicyNumbers()) == 0 {
		return nil
	}
	out := make(map[string]bool, len(resp.GetPolicyNumbers()))
	for _, n := range resp.GetPolicyNumbers() {
		out[n] = true
	}
	return out
}
