// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	log "github.com/Bugs5382/go-log"

	"context"
	"fmt"

	"github.com/Bugs5382/go-authz/ordered"
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
	return &CategoryRuleset{CategoryID: categoryID, Rules: rulesProtoToGQL(resp.GetRules())}, nil
}

// SetCategoryRulesetResolver persists a new ruleset for a category. Editing the
// rules is global-admin only: Manage does not gate it.
func SetCategoryRulesetResolver(ctx context.Context, gc corev1.CategoryServiceClient, categoryID string, inputs []*RaciRuleInput) (*CategoryRuleset, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}
	if gc == nil {
		return nil, status.Error(codes.Unavailable, "category service unavailable")
	}
	proto := make([]*corev1.CategoryRule, 0, len(inputs))
	for _, in := range inputs {
		proto = append(proto, ruleInputToProto(in))
	}
	resp, err := gc.SetCategoryRuleset(ctx, &corev1.SetCategoryRulesetRequest{CategoryId: categoryID, Rules: proto})
	if err != nil {
		return nil, err
	}
	return &CategoryRuleset{CategoryID: categoryID, Rules: rulesProtoToGQL(resp.GetRules())}, nil
}

// SimulateCategoryResolver evaluates a (possibly draft) ruleset for a given user against the full
// category chain with the ordered engine. A deny configured for root is reported in
// configuredBlock and not applied.
func SimulateCategoryResolver(ctx context.Context, r *Resolver, categoryID string, userID string, draftRules []*RaciRuleInput) (*RaciDecision, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		if err2 := authorizeOp(ctx, authz.TemplateManage); err2 != nil {
			return nil, err
		}
	}

	access, err := loadCategoryAccess(ctx, r.CategoryClient, categoryID)
	if err != nil {
		return nil, err
	}

	if draftRules != nil {
		draft := make([]*corev1.CategoryRule, 0, len(draftRules))
		for _, in := range draftRules {
			draft = append(draft, ruleInputToProto(in))
		}
		access = access.withLeafRules(draft)
	}

	if userID == "" {
		return decisionsToGQL(access.decide(ordered.Person{})), nil
	}

	person, err := personForUser(ctx, r.IdentityClient, userID)
	if err != nil {
		return nil, err
	}
	return decisionsToGQL(access.decide(person)), nil
}

// ViewerIsApproverResolver returns true when the authenticated caller holds Approve in at
// least one category (via the rules, as an owner, or as root).
func ViewerIsApproverResolver(ctx context.Context, logger log.Logger, gc corev1.CategoryServiceClient) (bool, error) {
	subj, err := subjectFromCtx(ctx)
	if err != nil {
		return false, err
	}
	if gc == nil {
		return false, status.Error(codes.Unavailable, "category service unavailable")
	}

	person := personFromSubject(subj)
	seen := map[string]struct{}{}
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

			if _, ok := seen[id]; ok {
				continue
			}
			access, err := loadCategoryAccess(ctx, gc, id)
			if err != nil {
				logger.Warn("viewer approver check skipped a category", log.F("category_id", id), log.F("error", err.Error()))
				lastErr = err
				errCount++
				continue
			}
			seen[id] = struct{}{}

			if access.decide(person).Approve.Allowed {
				return true, nil
			}
		}
	}

	if errCount > 0 && len(seen) == 0 {
		return false, lastErr
	}
	return false, nil
}

// CategoryApproversResolver returns the approver pool for a category: its owners (inherited)
// and everyone whose Approve evaluates allowed, owners first.
func CategoryApproversResolver(ctx context.Context, r *Resolver, categoryID string) ([]*User, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}

	access, err := loadCategoryAccess(ctx, r.CategoryClient, categoryID)
	if err != nil {
		return nil, err
	}

	allResp, err := r.IdentityClient.ListAllUsers(ctx, &identityv1.ListAllUsersRequest{})
	if err != nil {
		return nil, fmt.Errorf("list all users for categoryApprovers: %w", err)
	}

	seen := make(map[string]struct{})
	byID := make(map[string]*identityv1.User)
	var people []ordered.Person

	for _, u := range allResp.GetUsers() {
		uid := u.GetId()
		if _, dup := seen[uid]; dup {
			continue
		}
		seen[uid] = struct{}{}

		person, err := personForUser(ctx, r.IdentityClient, uid)
		if err != nil {
			r.logger().Warn("approver pool skipped a user", log.F("user_id", uid), log.F("error", err.Error()))
			continue
		}
		byID[uid] = u
		people = append(people, person)
	}

	pool := access.pool(people, actApprove)
	out := make([]*User, 0, len(pool))
	for _, e := range pool {
		out = append(out, userToGraphQL(byID[e.Person]))
	}
	return out, nil
}
