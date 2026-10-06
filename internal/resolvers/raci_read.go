// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-authz"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// subjIsSiteAdmin reports whether the subject holds the site-admin role.
func subjIsSiteAdmin(subj authz.Subject) bool { return subj.SiteAdmin() }

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
	if subj.SiteAdmin() || subj.Root {
		return authz.EffectObfuscate
	}
	return authz.EffectDeny
}

// sensitivityGate applies steward-authz's sensitive-document rule: only the
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

// meritRACIReadEffect decides read for one policy, in order: override allow,
// override deny, break glass, the category rules (meritRead), then the
// sensitive gate.
func meritRACIReadEffect(subj authz.Subject, p *Policy, meritRead bool) authz.Effect {
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
	action authz.Result
	// ackUngated is the acknowledge decision without the read gate, used when
	// an override allow settles read outside the rules.
	ackUngated bool
}

// meritSubject is the caller with roles and root dropped, so the category
// rules decide on merit; site admin is composed on top by each caller.
func meritSubject(subj authz.Subject) authz.Subject {
	return authz.Subject{UserID: subj.UserID, Groups: subj.Groups}
}

// computeRACIResult evaluates the policy's category chain for the caller. The
// bool is false only when no category client is wired; a chain-build error is
// returned, never treated as "no access", so a co-author is not silently
// locked out of their own draft.
func computeRACIResult(ctx context.Context, subj authz.Subject, p *Policy, categoryClient corev1.CategoryServiceClient) (raciReadResult, bool, error) {
	if categoryClient == nil {
		return raciReadResult{}, false, nil
	}
	chain, err := buildCategoryChain(ctx, categoryClient, p.HomeCategoryID)
	if err != nil {
		return raciReadResult{}, false, err
	}
	ev := authz.Compile(chain)
	merit := meritSubject(subj)
	action := ev.Resolve(ctx, merit)
	return raciReadResult{
		effect:     meritRACIReadEffect(subj, p, action.Read.Allowed),
		action:     action,
		ackUngated: ev.Acknowledgement(ctx, merit).Allowed,
	}, true, nil
}
