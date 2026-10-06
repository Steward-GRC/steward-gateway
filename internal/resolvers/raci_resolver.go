// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	log "github.com/Bugs5382/go-log"

	"context"
	"fmt"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetCategoryRulesetResolver fetches the stored ruleset for a category.
func GetCategoryRulesetResolver(ctx context.Context, gc corev1.CategoryServiceClient, categoryID string) (*CategoryRuleset, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		if err2 := authorizeOp(ctx, authz.TemplateManage); err2 != nil {
			return nil, err
		}
	}
	if gc == nil {
		return nil, status.Error(codes.Unavailable, "category service unavailable")
	}
	resp, err := gc.GetCategoryRuleset(ctx, &corev1.GetCategoryRulesetRequest{CategoryId: categoryID})
	if err != nil {
		return nil, err
	}
	rules := make([]*RaciRule, 0, len(resp.GetRules()))
	for _, pr := range resp.GetRules() {
		r := ruleFromProto(pr)
		rules = append(rules, raciRuleToGQL(r))
	}
	return &CategoryRuleset{CategoryID: categoryID, Rules: rules}, nil
}

// SetCategoryRulesetResolver persists a new ruleset for a category.
func SetCategoryRulesetResolver(ctx context.Context, gc corev1.CategoryServiceClient, categoryID string, inputs []*RaciRuleInput) (*CategoryRuleset, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}
	if gc == nil {
		return nil, status.Error(codes.Unavailable, "category service unavailable")
	}
	proto := make([]*corev1.CategoryRule, 0, len(inputs))
	for _, in := range inputs {
		r := RuleGQLInputToAuthz(in)
		proto = append(proto, authzRuleToProto(r))
	}
	resp, err := gc.SetCategoryRuleset(ctx, &corev1.SetCategoryRulesetRequest{CategoryId: categoryID, Rules: proto})
	if err != nil {
		return nil, err
	}
	rules := make([]*RaciRule, 0, len(resp.GetRules()))
	for _, pr := range resp.GetRules() {
		r := ruleFromProto(pr)
		rules = append(rules, raciRuleToGQL(r))
	}
	return &CategoryRuleset{CategoryID: categoryID, Rules: rules}, nil
}

// SimulateCategoryResolver evaluates a (possibly draft) ruleset for a given user against the full
// category chain.
func SimulateCategoryResolver(ctx context.Context, r *Resolver, categoryID string, userID string, draftRules []*RaciRuleInput) (*RaciDecision, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		if err2 := authorizeOp(ctx, authz.TemplateManage); err2 != nil {
			return nil, err
		}
	}

	chain, err := buildCategoryChain(ctx, r.CategoryClient, categoryID)
	if err != nil {
		return nil, err
	}

	if draftRules != nil && len(chain) > 0 {
		mapped := make([]authz.Rule, 0, len(draftRules))
		for _, in := range draftRules {
			mapped = append(mapped, RuleGQLInputToAuthz(in))
		}
		chain[0].Rules = mapped
	}

	if userID == "" {
		return AuthzResultToDecision(authz.Resolve(ctx, authz.Subject{}, chain)), nil
	}

	subj, err := subjectForUser(ctx, r.IdentityClient, userID)
	if err != nil {
		return nil, err
	}

	res := authz.Resolve(ctx, meritSubject(subj), chain)
	return AuthzResultToDecision(res), nil
}

// ViewerIsApproverResolver returns true when the authenticated caller holds RACI Approve in at
// least one category (via chart rules or owner-inheritance).
func ViewerIsApproverResolver(ctx context.Context, logger log.Logger, gc corev1.CategoryServiceClient) (bool, error) {
	claims, err := signedIn(ctx)
	if err != nil {
		return false, err
	}
	if gc == nil {
		return false, status.Error(codes.Unavailable, "category service unavailable")
	}

	merit := authz.Subject{UserID: claims.UserID(), Groups: claims.IdpGroups()}

	chainCache := make(map[string][]authz.CategoryRuleset)
	var lastErr error
	errCount := 0

	queue := []string{""}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]

		resp, err := gc.ListCategoryChildren(ctx, &corev1.ListCategoryChildrenRequest{ParentId: parent})
		if err != nil {
			lastErr = err
			errCount++
			continue
		}

		for _, g := range resp.GetCategories() {
			id := g.GetId()
			queue = append(queue, id)

			if _, seen := chainCache[id]; seen {
				continue
			}
			chain, err := buildCategoryChain(ctx, gc, id)
			if err != nil {
				logger.Warn("viewer approver check skipped a category", log.F("category_id", id), log.F("error", err.Error()))
				lastErr = err
				errCount++
				continue
			}
			chainCache[id] = chain

			res := authz.Resolve(ctx, merit, chain)
			if res.Approve.Allowed {
				return true, nil
			}
		}
	}

	if errCount > 0 && len(chainCache) == 0 {
		return false, lastErr
	}
	return false, nil
}

// CategoryApproversResolver returns the RACI-derived approve-eligible user pool for a category.
func CategoryApproversResolver(ctx context.Context, r *Resolver, categoryID string) ([]*User, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}

	chain, err := buildCategoryChain(ctx, r.CategoryClient, categoryID)
	if err != nil {
		return nil, err
	}

	allResp, err := r.IdentityClient.ListAllUsers(ctx, &identityv1.ListAllUsersRequest{})
	if err != nil {
		return nil, fmt.Errorf("list all users for categoryApprovers: %w", err)
	}

	seen := make(map[string]struct{})
	var out []*User

	for _, u := range allResp.GetUsers() {
		uid := u.GetId()
		if _, dup := seen[uid]; dup {
			continue
		}
		seen[uid] = struct{}{}

		subj, err := subjectForUser(ctx, r.IdentityClient, uid)
		if err != nil {
			r.logger().Warn("approver pool skipped a user", log.F("user_id", uid), log.F("error", err.Error()))
			continue
		}

		res := authz.Resolve(ctx, subj, chain)
		if res.Approve.Allowed {
			out = append(out, userToGraphQL(u))
		}
	}

	return out, nil
}
