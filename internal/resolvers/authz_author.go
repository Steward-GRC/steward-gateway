// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-gateway/internal/authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// Who may co-edit and submit a policy's drafts, top wins:
//  1. root, always;
//  2. the policy's primary author (its owner), always;
//  3. whoever the category access rules (the ordered engine) allow Author:
//     an owner of the category or any ancestor (undeniable), or an author
//     row, or Manage (which implies Author).
//
// A site admin who is not root follows the rules like everyone else; their
// fallback is break-glass for reading. Discarding a draft and deleting a
// never-published policy sit at the same tier; only reassigning ownership
// (setPolicyOwner, movePolicy) is site-admin only.

type effectiveAuthorCtx struct {
	uid         string
	subj        authz.Subject
	ownerUserID string
	draftID     string
	access      *categoryAccess
}

// loadEffectiveAuthorCtx resolves the caller and loads the policy's owner and category access
// (the chain with owners and rules) for an authorization decision.
func loadEffectiveAuthorCtx(ctx context.Context, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID string) (effectiveAuthorCtx, error) {
	uid, subj, err := evalSubjectFromCtx(ctx)
	if err != nil {
		return effectiveAuthorCtx{}, err
	}
	resp, err := policyClient.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: policyID})
	if err != nil {
		return effectiveAuthorCtx{}, err
	}
	p := resp.GetPolicy()
	var access *categoryAccess
	if categoryClient != nil && p.GetHomeCategoryId() != "" {
		c, cerr := loadCategoryAccess(ctx, categoryClient, p.GetHomeCategoryId())
		if cerr != nil {
			return effectiveAuthorCtx{}, status.Errorf(codes.Internal, "load category access: %v", cerr)
		}
		access = c
	}
	return effectiveAuthorCtx{uid: uid, subj: subj, ownerUserID: p.GetOwnerUserId(), draftID: p.GetCurrentDraftVersionId(), access: access}, nil
}

// isRoot reports whether the caller holds the root seat, the only exempt one.
func (e effectiveAuthorCtx) isRoot() bool { return e.subj.Root }

func (e effectiveAuthorCtx) isPrimaryAuthor() bool {
	return e.ownerUserID != "" && e.uid == e.ownerUserID
}

// authorAllowed is the category-rule Author decision: a row, an owner, Manage
// or root.
func (e effectiveAuthorCtx) authorAllowed() bool {
	if e.access == nil {
		return false
	}
	return e.access.decide(personFromSubject(e.subj)).Author.Allowed
}

// readAllowed is the category-rule Read decision (Author, Approve and Manage
// confer Read over a Read deny).
func (e effectiveAuthorCtx) readAllowed() bool {
	if e.access == nil {
		return false
	}
	return e.access.decide(personFromSubject(e.subj)).Read.Allowed
}

// authorizeEffectiveAuthor gates a draft edit or submit per the model above
// and returns the caller's user id.
func authorizeEffectiveAuthor(ctx context.Context, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID string) (string, error) {
	e, err := authorizeEffectiveAuthorCtx(ctx, policyClient, categoryClient, policyID)
	if err != nil {
		return "", err
	}
	return e.uid, nil
}

// authorizeEffectiveAuthorCtx is authorizeEffectiveAuthor for callers that also need what the gate
// already read off the policy, such as its working draft id.
func authorizeEffectiveAuthorCtx(ctx context.Context, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID string) (effectiveAuthorCtx, error) {
	e, err := loadEffectiveAuthorCtx(ctx, policyClient, categoryClient, policyID)
	if err != nil {
		return effectiveAuthorCtx{}, err
	}
	if e.isRoot() || e.isPrimaryAuthor() || e.authorAllowed() {
		return e, nil
	}
	return effectiveAuthorCtx{}, status.Error(codes.PermissionDenied, "not an author for this policy's category")
}

// categoryAccessFor loads the access for a category for a caller-only check
// (nil when no category is named or no client is wired).
func categoryAccessFor(ctx context.Context, categoryClient corev1.CategoryServiceClient, categoryID string) (*categoryAccess, error) {
	if categoryClient == nil || categoryID == "" {
		return nil, nil
	}
	return loadCategoryAccess(ctx, categoryClient, categoryID)
}

// authorizeCategoryAuthor gates creating a policy in homeCategoryID: root, or
// an owner of the category or an ancestor, or an author the category rules
// allow. Returns the caller's user id.
func authorizeCategoryAuthor(ctx context.Context, categoryClient corev1.CategoryServiceClient, homeCategoryID string) (string, error) {
	uid, subj, err := evalSubjectFromCtx(ctx)
	if err != nil {
		return "", err
	}
	e := effectiveAuthorCtx{uid: uid, subj: subj}
	if e.isRoot() {
		return uid, nil
	}
	if categoryClient == nil || homeCategoryID == "" {
		return "", status.Error(codes.PermissionDenied, "not an author for the target category")
	}
	access, cerr := loadCategoryAccess(ctx, categoryClient, homeCategoryID)
	if cerr != nil {
		return "", status.Errorf(codes.Internal, "load category access: %v", cerr)
	}
	e.access = access
	if e.authorAllowed() {
		return uid, nil
	}
	return "", status.Error(codes.PermissionDenied, "not an author for the target category")
}

// canAuthorCategory is authorizeCategoryAuthor as a boolean, for template
// visibility. A template with no category is visible to root only.
func canAuthorCategory(ctx context.Context, categoryClient corev1.CategoryServiceClient, uid string, subj authz.Subject, categoryID string) bool {
	e := effectiveAuthorCtx{uid: uid, subj: subj}
	if e.isRoot() {
		return true
	}
	if access, err := categoryAccessFor(ctx, categoryClient, categoryID); err == nil {
		e.access = access
	}
	return e.authorAllowed()
}

// canReadCategory is the read counterpart of canAuthorCategory, for the AI
// category-scope gate on read-type operations.
func canReadCategory(ctx context.Context, categoryClient corev1.CategoryServiceClient, uid string, subj authz.Subject, categoryID string) bool {
	e := effectiveAuthorCtx{uid: uid, subj: subj}
	if e.isRoot() {
		return true
	}
	if access, err := categoryAccessFor(ctx, categoryClient, categoryID); err == nil {
		e.access = access
	}
	return e.readAllowed()
}
