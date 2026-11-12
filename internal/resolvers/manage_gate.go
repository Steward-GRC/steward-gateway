// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// authorizeMove gates moving documents to another category and returns the
// caller's user id. The old gate (the site-admin role) still allows; the new
// one is added beside it, so no existing right is removed: the caller may move
// a document when the category rules allow Manage in the document's own
// category and Author in the target category (Manage implies Author, and an
// author may already create a document there). Owners and root hold both.
// Whether Manage should replace the site-admin gate rather than join it is an
// open question for the owner. Manage does not gate the rules or the governance.
func authorizeMove(ctx context.Context, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyIDs []string, targetCategoryID string) (string, error) {
	if uid, err := requireSiteAdmin(ctx); err == nil {
		return uid, nil
	}
	uid, subj, err := evalSubjectFromCtx(ctx)
	if err != nil {
		return "", err
	}
	denied := status.Error(codes.PermissionDenied, "insufficient role for this operation")
	if categoryClient == nil || policyClient == nil || len(policyIDs) == 0 || targetCategoryID == "" {
		return "", denied
	}
	person := personFromSubject(subj)
	target, err := loadCategoryAccess(ctx, categoryClient, targetCategoryID)
	if err != nil {
		return "", status.Errorf(codes.Internal, "load category access: %v", err)
	}
	if !target.decide(person).Author.Allowed {
		return "", denied
	}
	for _, id := range policyIDs {
		resp, err := policyClient.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: id})
		if err != nil {
			return "", err
		}
		home := resp.GetPolicy().GetHomeCategoryId()
		if home == "" {
			return "", denied
		}
		source, err := loadCategoryAccess(ctx, categoryClient, home)
		if err != nil {
			return "", status.Errorf(codes.Internal, "load category access: %v", err)
		}
		if !source.decide(person).Manage.Allowed {
			return "", denied
		}
	}
	return uid, nil
}
