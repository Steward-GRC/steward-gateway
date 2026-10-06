// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"slices"

	authz "github.com/Steward-GRC/steward-authz"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// userToGraphQL projects an identity User onto the GraphQL User. Email and
// name come only from the identity record, never from session claims, so the
// web always shows the canonical value.
func userToGraphQL(u *identityv1.User) *User {
	if u == nil {
		return nil
	}
	scopes := &RoleScopes{Author: []string{}, Approver: []string{}}
	for _, sr := range u.GetScopedRoles() {
		switch sr.GetRole() {
		case string(authz.RoleAuthor):
			scopes.Author = append(scopes.Author, sr.GetCategory())
		case string(authz.RoleApprover):
			scopes.Approver = append(scopes.Approver, sr.GetCategory())
		}
	}
	overrides := make([]*PolicyOverride, 0, len(u.GetPolicyOverrides()))
	for _, po := range u.GetPolicyOverrides() {
		eff := overrideEffectToGraphQL(po.GetEffect())
		if eff == nil {
			continue
		}
		overrides = append(overrides, &PolicyOverride{PolicyNumber: po.GetPolicyNumber(), Effect: *eff})
	}
	return &User{
		UserID:           u.GetId(),
		Name:             u.GetName(),
		FirstName:        u.GetFirstName(),
		LastName:         u.GetLastName(),
		Email:            u.GetEmail(),
		Enabled:          u.GetEnabled(),
		Roles:            append([]string{}, u.GetRoles()...),
		Scopes:           scopes,
		GroupIds:         append([]string{}, u.GetGroups()...),
		IdpGroups:        append([]string{}, u.GetIdpGroups()...),
		PolicyOverrides:  overrides,
		IsRoot:           u.GetIsRoot(),
		Permissions:      userPermissions(u),
		LocalAccount:     u.GetLocalAccount(),
		Username:         u.GetUsername(),
		NeedsOnboarding:  u.GetNeedsOnboarding(),
		ManagedGroupIds:  append([]string{}, u.GetManagedGroupIds()...),
		Memberships:      membershipsToGraphQL(u.GetMemberships()),
		Locale:           u.GetLocale(),
		DeletedAt:        nilIfEmpty(u.GetDeletedAt()),
		MergedIntoUserID: nilIfEmpty(u.GetMergedIntoUserId()),
	}
}

// userPermissions lists the catalog permissions the user's roles hold, plus
// the individual read-sensitive grant, sorted.
func userPermissions(u *identityv1.User) []string {
	roles := make([]authz.Role, 0, len(u.GetRoles()))
	for _, r := range u.GetRoles() {
		roles = append(roles, authz.Role(r))
	}
	perms := authz.RolePermissions(roles...)
	out := make([]string, 0, len(perms)+1)
	for _, p := range perms {
		out = append(out, string(p))
	}
	if u.GetReadSensitiveGrant() && !slices.Contains(out, string(authz.PolicyReadSensitive)) {
		out = append(out, string(authz.PolicyReadSensitive))
	}
	slices.Sort(out)
	return out
}

func membershipsToGraphQL(ms []*identityv1.Membership) []*GroupMembership {
	out := make([]*GroupMembership, 0, len(ms))
	for _, m := range ms {
		out = append(out, &GroupMembership{GroupID: m.GetGroupId(), Source: m.GetSource()})
	}
	return out
}

func overrideEffectToGraphQL(e identityv1.OverrideEffect) *OverrideEffect {
	switch e {
	case identityv1.OverrideEffect_OVERRIDE_EFFECT_ALLOW:
		v := OverrideEffectAllow
		return &v
	case identityv1.OverrideEffect_OVERRIDE_EFFECT_DENY:
		v := OverrideEffectDeny
		return &v
	default:
		return nil
	}
}
