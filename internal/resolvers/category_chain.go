// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	authz "github.com/Steward-GRC/steward-authz"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// maxCategoryDepth bounds every ancestor walk, so a cycle in stored data can't
// loop forever. Core caps the tree at three levels.
const maxCategoryDepth = 20

// categoryLineage returns the category ids from leafID up to the root.
func categoryLineage(ctx context.Context, categoryClient corev1.CategoryServiceClient, leafID string) ([]string, error) {
	ids, _, err := categoryLineageNamed(ctx, categoryClient, leafID)
	return ids, err
}

// categoryLineageNamed returns the category ids and names from leafID up to
// the root. Scoped grants and rule chains are keyed by category name.
func categoryLineageNamed(ctx context.Context, categoryClient corev1.CategoryServiceClient, leafID string) (ids, names []string, err error) {
	for id := leafID; id != "" && len(ids) < maxCategoryDepth; {
		resp, err := categoryClient.GetCategory(ctx, &corev1.GetCategoryRequest{Id: id})
		if err != nil {
			return nil, nil, fmt.Errorf("get category %s: %w", id, err)
		}
		ids = append(ids, id)
		names = append(names, resp.GetCategory().GetName())
		id = resp.GetCategory().GetParentId()
	}
	return ids, names, nil
}

// buildCategoryChain loads the steward-authz chain for categoryID: the
// category first, then each ancestor, each with its owners and ordered rules.
func buildCategoryChain(ctx context.Context, categoryClient corev1.CategoryServiceClient, categoryID string) ([]authz.CategoryRuleset, error) {
	var chain []authz.CategoryRuleset
	for id := categoryID; id != "" && len(chain) < maxCategoryDepth; {
		resp, err := categoryClient.GetCategory(ctx, &corev1.GetCategoryRequest{Id: id})
		if err != nil {
			return nil, fmt.Errorf("get category %s: %w", id, err)
		}
		c := resp.GetCategory()
		rs, err := categoryClient.GetCategoryRuleset(ctx, &corev1.GetCategoryRulesetRequest{CategoryId: id})
		if err != nil {
			return nil, fmt.Errorf("get category ruleset %s: %w", id, err)
		}
		rules := make([]authz.Rule, 0, len(rs.GetRules()))
		for _, r := range rs.GetRules() {
			rules = append(rules, ruleFromProto(r))
		}
		chain = append(chain, authz.CategoryRuleset{Name: c.GetName(), Owners: c.GetOwners(), Rules: rules})
		id = c.GetParentId()
	}
	return chain, nil
}

func ruleFromProto(r *corev1.CategoryRule) authz.Rule {
	return authz.Rule{
		Subject: authz.RuleSubject{Kind: subjectKindFromProto(r.GetSubjectKind()), Name: r.GetSubjectRef()},
		Grants: map[authz.Action]authz.Grant{
			authz.ActionRead:        grantFromProto(r.GetRead()),
			authz.ActionAcknowledge: grantFromProto(r.GetAck()),
			authz.ActionApprove:     grantFromProto(r.GetApprove()),
			authz.ActionAuthor:      grantFromProto(r.GetAuthor()),
		},
	}
}

func grantFromProto(e corev1.GrantEffect) authz.Grant {
	switch e {
	case corev1.GrantEffect_GRANT_EFFECT_ALLOW:
		return authz.GrantAllow
	case corev1.GrantEffect_GRANT_EFFECT_DENY:
		return authz.GrantDeny
	default:
		return authz.GrantBlank
	}
}

func subjectKindFromProto(k corev1.RuleSubjectKind) authz.SubjectKind {
	switch k {
	case corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP:
		return authz.SubjectGroup
	case corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER:
		return authz.SubjectUser
	default:
		return authz.SubjectEveryone
	}
}
