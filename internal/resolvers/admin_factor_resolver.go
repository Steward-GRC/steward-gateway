// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-authz"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UserFactorsResolver lists the target user's enrolled second factors for the admin Security tab.
func UserFactorsResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID string) ([]*MfaFactor, error) {
	if err := authorizeOp(ctx, authz.UserManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := admin.AdminListUserFactors(ctx, &identityv1.AdminListUserFactorsRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	out := make([]*MfaFactor, 0, len(resp.GetFactors()))
	for _, f := range resp.GetFactors() {
		out = append(out, &MfaFactor{
			ID:         f.GetId(),
			Kind:       f.GetKind(),
			EnrolledAt: optStr(f.GetEnrolledAt()),
			Label:      optStr(f.GetLabel()),
		})
	}
	return out, nil
}

// RemoveUserMfaFactorResolver resets (removes) one of the target user's factors so they can
// re-enroll.
func RemoveUserMfaFactorResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, methodID string) (bool, error) {
	if err := authorizeOp(ctx, authz.UserManage); err != nil {
		return false, err
	}
	if admin == nil {
		return false, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	if _, err := admin.AdminRemoveUserFactor(ctx, &identityv1.AdminRemoveUserFactorRequest{UserId: userID, MethodId: methodID}); err != nil {
		return false, err
	}
	return true, nil
}

// RenameUserMfaFactorResolver sets the user-facing label on one of the target user's factors.
func RenameUserMfaFactorResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, methodID, label string) (bool, error) {
	if err := authorizeOp(ctx, authz.UserManage); err != nil {
		return false, err
	}
	if admin == nil {
		return false, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	if _, err := admin.AdminRenameUserFactor(ctx, &identityv1.AdminRenameUserFactorRequest{UserId: userID, MethodId: methodID, Label: label}); err != nil {
		return false, err
	}
	return true, nil
}
