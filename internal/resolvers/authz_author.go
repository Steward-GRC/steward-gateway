// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"slices"

	authz "github.com/Steward-GRC/steward-authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// Who may co-edit and submit a policy's drafts, top wins:
//  1. a site admin (or root), always;
//  2. the policy's primary author (its owner), always;
//  3. an owner of the policy's category or any ancestor (undeniable);
//  4. an author whose category rules allow author and don't deny it.
//
// (3) and (4) are steward-authz's Resolve(...).Author on the category chain.
// Discarding a draft and deleting a never-published policy sit at the same
// tier; only reassigning ownership (setPolicyOwner, movePolicy) is site-admin
// only.

type effectiveAuthorCtx struct {
	uid         string
	subj        authz.Subject
	ownerUserID string
	draftID     string
	chain       []authz.CategoryRuleset
}

// loadEffectiveAuthorCtx resolves the caller and loads the policy's owner and category ruleset
// chain (leaf→root, with owners) for an authorization decision.
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
	var chain []authz.CategoryRuleset
	if categoryClient != nil && p.GetHomeCategoryId() != "" {
		c, cerr := buildCategoryChain(ctx, categoryClient, p.GetHomeCategoryId())
		if cerr != nil {
			return effectiveAuthorCtx{}, status.Errorf(codes.Internal, "load category ruleset chain: %v", cerr)
		}
		chain = c
	}
	return effectiveAuthorCtx{uid: uid, subj: subj, ownerUserID: p.GetOwnerUserId(), draftID: p.GetCurrentDraftVersionId(), chain: chain}, nil
}

func (e effectiveAuthorCtx) isSiteAdmin() bool { return e.subj.SiteAdmin() || e.subj.Root }

func (e effectiveAuthorCtx) isPrimaryAuthor() bool {
	return e.ownerUserID != "" && e.uid == e.ownerUserID
}

// meritAuthorAllowed is the category-rule author decision, with site admin
// left out (it is composed on top).
func (e effectiveAuthorCtx) meritAuthorAllowed(ctx context.Context) bool {
	if len(e.chain) == 0 {
		return false
	}
	return authz.Resolve(ctx, meritSubject(e.subj), e.chain).Author.Allowed
}

// meritReadAllowed is the category-rule read decision, with site admin left
// out. Resolve folds author and approve into read, and owners read.
func (e effectiveAuthorCtx) meritReadAllowed(ctx context.Context) bool {
	if len(e.chain) == 0 {
		return false
	}
	return authz.Resolve(ctx, meritSubject(e.subj), e.chain).Read.Allowed
}

// ownsCategory reports whether the caller owns the policy's category or any ancestor
// (owners-as-managers), independent of any author grant.
func (e effectiveAuthorCtx) ownsCategory() bool {
	for _, c := range e.chain {
		if slices.Contains(c.Owners, e.uid) {
			return true
		}
	}
	return false
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
	if e.isSiteAdmin() || e.isPrimaryAuthor() || e.meritAuthorAllowed(ctx) {
		return e, nil
	}
	return effectiveAuthorCtx{}, status.Error(codes.PermissionDenied, "not an author for this policy's category")
}

// authorizeCategoryAuthor gates creating a policy in homeCategoryID: a site
// admin, an owner of the category or an ancestor, or an author the category
// rules allow. Returns the caller's user id.
func authorizeCategoryAuthor(ctx context.Context, categoryClient corev1.CategoryServiceClient, homeCategoryID string) (string, error) {
	uid, subj, err := evalSubjectFromCtx(ctx)
	if err != nil {
		return "", err
	}
	e := effectiveAuthorCtx{uid: uid, subj: subj}
	if e.isSiteAdmin() {
		return uid, nil
	}
	if categoryClient == nil || homeCategoryID == "" {
		return "", status.Error(codes.PermissionDenied, "not an author for the target category")
	}
	chain, cerr := buildCategoryChain(ctx, categoryClient, homeCategoryID)
	if cerr != nil {
		return "", status.Errorf(codes.Internal, "load category ruleset chain: %v", cerr)
	}
	e.chain = chain
	if e.ownsCategory() || e.meritAuthorAllowed(ctx) {
		return uid, nil
	}
	return "", status.Error(codes.PermissionDenied, "not an author for the target category")
}

// canAuthorCategory is authorizeCategoryAuthor as a boolean, for template
// visibility. A template with no category is visible to site admins only.
func canAuthorCategory(ctx context.Context, categoryClient corev1.CategoryServiceClient, uid string, subj authz.Subject, categoryID string) bool {
	e := effectiveAuthorCtx{uid: uid, subj: subj}
	if e.isSiteAdmin() {
		return true
	}
	if categoryClient == nil || categoryID == "" {
		return false
	}
	if c, cerr := buildCategoryChain(ctx, categoryClient, categoryID); cerr == nil {
		e.chain = c
	}
	return e.ownsCategory() || e.meritAuthorAllowed(ctx)
}

// canReadCategory is the read counterpart of canAuthorCategory, for the AI
// category-scope gate on read-type operations.
func canReadCategory(ctx context.Context, categoryClient corev1.CategoryServiceClient, uid string, subj authz.Subject, categoryID string) bool {
	e := effectiveAuthorCtx{uid: uid, subj: subj}
	if e.isSiteAdmin() {
		return true
	}
	if categoryClient == nil || categoryID == "" {
		return false
	}
	if c, cerr := buildCategoryChain(ctx, categoryClient, categoryID); cerr == nil {
		e.chain = c
	}
	return e.meritReadAllowed(ctx)
}
