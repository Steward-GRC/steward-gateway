// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	log "github.com/Bugs5382/go-log"

	"context"
	"fmt"

	"github.com/Bugs5382/go-authz/ordered"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	authz "github.com/Steward-GRC/steward-gateway/internal/authz"

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

// CategoryApproversResolver returns the RACI-derived approve-eligible user pool for a category.
func CategoryApproversResolver(ctx context.Context, r *Resolver, categoryID string) ([]*User, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}

	access, err := loadCategoryAccess(ctx, r.CategoryClient, categoryID)
	if err != nil {
		return nil, err
	}

	directory, err := loadApproverDirectory(ctx, r)
	if err != nil {
		return nil, err
	}
	return directory.pool(access), nil
}

// approverDirectory is every account with the person the ordered engine decides for, read once so
// several categories' pools can be asked without listing the accounts again.
type approverDirectory struct {
	people []ordered.Person
	byID   map[string]*identityv1.User
}

// loadApproverDirectory lists the accounts and builds a person for each. An account that cannot be
// read is skipped with a warning, so one bad record does not empty the pool.
func loadApproverDirectory(ctx context.Context, r *Resolver) (*approverDirectory, error) {
	allResp, err := r.IdentityClient.ListAllUsers(ctx, &identityv1.ListAllUsersRequest{})
	if err != nil {
		return nil, fmt.Errorf("list all users for the approver pool: %w", err)
	}

	d := &approverDirectory{byID: map[string]*identityv1.User{}}
	for _, u := range allResp.GetUsers() {
		uid := u.GetId()
		if _, dup := d.byID[uid]; dup {
			continue
		}

		person, err := personForUser(ctx, r.IdentityClient, uid)
		if err != nil {
			r.logger().Warn("approver pool skipped a user", log.F("user_id", uid), log.F("error", err.Error()))
			continue
		}
		d.byID[uid] = u
		d.people = append(d.people, person)
	}
	return d, nil
}

// pool is the accounts the category's rules and owners allow to approve, owners first. Root is in
// it only when the rows allow it: Approve is not part of the root exemption.
func (d *approverDirectory) pool(access *categoryAccess) []*User {
	entries := access.pool(d.people, actApprove)
	out := make([]*User, 0, len(entries))
	for _, e := range entries {
		out = append(out, userToGraphQL(d.byID[e.Person]))
	}
	return out
}

// WorkflowApproverCandidatesResolver answers who the workflow editor may offer as an approver: the
// union of the approve pools of the categories that use the workflow as their default workflow. A
// workflow no category uses has no chart to say who may approve, so it answers attached=false with
// no users rather than a global list. Gated like the workflow editor itself.
func WorkflowApproverCandidatesResolver(ctx context.Context, r *Resolver, workflowID string) (*WorkflowApproverCandidates, error) {
	logger := r.logger()
	logger.Debug("workflow approver candidates: start", log.F("workflow_id", workflowID))
	if err := authorizeOp(ctx, authz.WorkflowManage); err != nil {
		return nil, err
	}
	if r.WorkflowClient == nil {
		return nil, status.Error(codes.Unavailable, "workflow service unavailable")
	}
	if r.CategoryClient == nil {
		return nil, status.Error(codes.Unavailable, "category service unavailable")
	}
	// An unknown workflow is an error, not an empty answer.
	if _, err := r.WorkflowClient.GetWorkflowDef(ctx, &workflowv1.GetWorkflowDefRequest{Id: workflowID}); err != nil {
		return nil, err
	}

	attached, err := categoriesUsingWorkflow(ctx, r.CategoryClient, workflowID)
	if err != nil {
		return nil, err
	}
	out := &WorkflowApproverCandidates{
		WorkflowID:  workflowID,
		Attached:    len(attached) > 0,
		CategoryIds: attached,
		Users:       []*User{},
	}
	if len(attached) == 0 {
		logger.Debug("workflow approver candidates: not attached to any category", log.F("workflow_id", workflowID))
		return out, nil
	}

	directory, err := loadApproverDirectory(ctx, r)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, categoryID := range attached {
		access, err := loadCategoryAccess(ctx, r.CategoryClient, categoryID)
		if err != nil {
			return nil, err
		}
		for _, u := range directory.pool(access) {
			if _, dup := seen[u.UserID]; dup {
				continue
			}
			seen[u.UserID] = struct{}{}
			out.Users = append(out.Users, u)
		}
	}
	logger.Debug("workflow approver candidates: done",
		log.F("workflow_id", workflowID), log.F("categories", len(attached)), log.F("candidates", len(out.Users)))
	return out, nil
}

// categoriesUsingWorkflow lists the ids of the categories whose default workflow is workflowID,
// walking the whole category forest. Categories are at most three levels deep, so the walk is
// shallow.
func categoriesUsingWorkflow(ctx context.Context, gc corev1.CategoryServiceClient, workflowID string) ([]string, error) {
	out := []string{}
	var walk func(parentID string) error
	walk = func(parentID string) error {
		resp, err := gc.ListCategoryChildren(ctx, &corev1.ListCategoryChildrenRequest{ParentId: parentID})
		if err != nil {
			return fmt.Errorf("list categories under %q: %w", parentID, err)
		}
		for _, c := range resp.GetCategories() {
			if c.GetDefaultWorkflowId() == workflowID {
				out = append(out, c.GetId())
			}
			if err := walk(c.GetId()); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(""); err != nil {
		return nil, err
	}
	return out, nil
}
