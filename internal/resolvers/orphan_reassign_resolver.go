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

// ListPoliciesByOwner returns the policies a user owns/authors — the "orphaned set" surfaced to a
// site-admin before/after deleting the user so ownership can be re-assigned.
func ListPoliciesByOwner(ctx context.Context, client corev1.PolicyServiceClient, userID string, includeRetired *bool) ([]*Policy, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.ListPoliciesByOwner(ctx, &corev1.ListPoliciesByOwnerRequest{
		OwnerUserId:    userID,
		IncludeRetired: includeRetired != nil && *includeRetired,
	})
	if err != nil {
		return nil, err
	}
	out := make([]*Policy, 0, len(resp.GetPolicies()))
	for _, p := range resp.GetPolicies() {
		out = append(out, policyFromProto(p))
	}
	return out, nil
}

// ReassignUserPolicies bulk-transfers a user's owned policies and category RACI author grants to
// another user in one auditable admin op.
func ReassignUserPolicies(ctx context.Context, client corev1.PolicyServiceClient, fromUserID, toUserID string) (*ReassignUserPoliciesResult, error) {
	actor, err := requireSiteAdmin(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.ReassignUserPolicies(ctx, &corev1.ReassignUserPoliciesRequest{
		FromUserId:  fromUserID,
		ToUserId:    toUserID,
		ActorUserId: actor,
	})
	if err != nil {
		return nil, err
	}
	return &ReassignUserPoliciesResult{
		ReassignedPolicyIds:    resp.GetReassignedPolicyIds(),
		ReassignedOwnerCount:   int(resp.GetReassignedOwnerCount()),
		ReassignedAuthorGrants: int(resp.GetReassignedAuthorGrants()),
	}, nil
}

// DeleteUserResolver soft-deletes a user.
func DeleteUserResolver(ctx context.Context, policyClient corev1.PolicyServiceClient, admin identityv1.IdentityAdminServiceClient, userID string) (*DeleteUserResult, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	owned, err := policyClient.ListPoliciesByOwner(ctx, &corev1.ListPoliciesByOwnerRequest{
		OwnerUserId:    userID,
		IncludeRetired: true,
	})
	if err != nil {
		return nil, err
	}
	if n := len(owned.GetPolicies()); n > 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"user still owns %d policy(ies); re-assign them to another user before deleting", n)
	}
	resp, err := admin.DeleteUser(ctx, &identityv1.DeleteUserRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	return &DeleteUserResult{
		UserID:          userID,
		RevokedSessions: int(resp.GetRevokedSessions()),
	}, nil
}
