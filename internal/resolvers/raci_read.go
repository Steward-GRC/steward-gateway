// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-gateway/internal/authz"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// subjIsSiteAdmin reports whether the subject holds the site-admin role.
func subjIsSiteAdmin(subj authz.Subject) bool { return authz.IsSiteAdmin(subj) }

// subjOverrideFor returns the subject's per-policy override for the policy
// number: GrantAllow, GrantDeny or GrantBlank.
func subjOverrideFor(subj authz.Subject, number string) authz.Grant {
	for _, o := range subj.Overrides {
		if o.ResourceID == number {
			return o.Grant
		}
	}
	return authz.GrantBlank
}

// obfuscateOrDeny is the read effect for an excluded subject: a site admin (or
// root) sees that the policy exists with its content obfuscated, everyone else
// is denied.
func obfuscateOrDeny(subj authz.Subject) authz.Effect {
	if authz.IsSiteAdmin(subj) || subj.Root {
		return authz.EffectObfuscate
	}
	return authz.EffectDeny
}

// sensitivityGate applies the permission catalog (internal/authz)'s sensitive-document rule: only the
// individual read-sensitive grant or the policy's own author (its owner) reads
// a sensitive policy.
func sensitivityGate(subj authz.Subject, p *Policy) authz.Effect {
	if p.Sensitivity != SensitivitySensitive {
		return authz.EffectAllow
	}
	res := &authz.Resource{ID: p.Number, Sensitive: true, Authors: []string{p.OwnerUserID}}
	if authz.Authorize(subj, authz.PolicyRead, res).Allowed() {
		return authz.EffectAllow
	}
	return authz.EffectDeny
}

// meritRACIReadEffect decides read for one policy, in order: the root override,
// override allow, override deny, break glass, the category rules (meritRead,
// from the ordered engine), then the sensitive gate. Root is a global approver and global manager, so it
// always reads: no category rule, sensitivity or per-policy deny applies, and
// its content is never obfuscated.
func meritRACIReadEffect(subj authz.Subject, p *Policy, meritRead bool) authz.Effect {
	if subj.Root {
		return authz.EffectAllow
	}
	switch subjOverrideFor(subj, p.Number) {
	case authz.GrantAllow:
		return authz.EffectAllow
	case authz.GrantDeny:
		return obfuscateOrDeny(subj)
	}
	if subj.BreakGlass[p.Number] {
		return authz.EffectAllow
	}
	if !meritRead {
		return obfuscateOrDeny(subj)
	}
	return sensitivityGate(subj, p)
}

// raciReadResult is one policy's category-rule resolution, computed once and
// shared by the read decision and viewerCan.
type raciReadResult struct {
	effect authz.Effect
	action categoryDecisions
}

// computeRACIResult evaluates the policy's category chain for the caller with
// the ordered engine. The caller is decided as they are: Everyone covers a
// site admin, and only root (role:root) is exempt. The bool is false only when
// no category client is wired; a lookup error is returned, never treated as
// "no access", so a co-author is not silently locked out of their own draft.
func computeRACIResult(ctx context.Context, subj authz.Subject, p *Policy, categoryClient corev1.CategoryServiceClient) (raciReadResult, bool, error) {
	if categoryClient == nil {
		return raciReadResult{}, false, nil
	}
	access, err := loadCategoryAccess(ctx, categoryClient, p.HomeCategoryID)
	if err != nil {
		return raciReadResult{}, false, err
	}
	action := access.decide(personFromSubject(subj))
	return raciReadResult{
		effect: meritRACIReadEffect(subj, p, action.Read.Allowed),
		action: action,
	}, true, nil
}
