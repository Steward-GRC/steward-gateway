// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	collabv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/collab/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// The collab token gate is collab's own edit check (steward-collab internal/access):
// root, the policy owner, Author or Manage allowed by the category rules (owners
// and the root seat come out of the engine), or the catalog's scoped policy.author
// grant in the policy's category or an ancestor. A non-root site admin edits
// through a rule alone (steward-gateway#202).
func TestIssueCollabToken_GateMatchesCollab(t *testing.T) {
	reader := func() principal.Static {
		return principal.Static{UserIDValue: "u", RolesValue: []string{"reader"}}
	}
	groupRule := &corev1.CategoryRule{
		SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP, SubjectRef: "editors",
		Author: corev1.GrantEffect_GRANT_EFFECT_ALLOW,
	}
	cases := []struct {
		name      string
		claims    principal.Static
		owners    []string
		primary   string
		rules     []*corev1.CategoryRule
		wantAllow bool
	}{
		{name: "root", claims: principal.Static{UserIDValue: "u", IsRootValue: true}, wantAllow: true},
		{name: "policy owner", claims: reader(), primary: "u", wantAllow: true},
		{name: "category owner", claims: reader(), owners: []string{"u"}, wantAllow: true},
		{name: "author row", claims: reader(), rules: []*corev1.CategoryRule{authorOnlyRule("u")}, wantAllow: true},
		{name: "manage row alone", claims: reader(), rules: []*corev1.CategoryRule{manageRule("u", allowCell)}, wantAllow: true},
		{name: "author row for an idp group", claims: principal.Static{UserIDValue: "u", IdpGroupsValue: []string{"editors"}},
			rules: []*corev1.CategoryRule{groupRule}, wantAllow: true},
		{name: "scoped policy.author in the category",
			claims: principal.Static{UserIDValue: "u", ScopedRolesValue: []principal.ScopedRole{{Role: "author", Category: "CAT"}}}, wantAllow: true},
		{name: "scoped policy.author even under an author deny row (as collab)",
			claims: principal.Static{UserIDValue: "u", ScopedRolesValue: []principal.ScopedRole{{Role: "author", Category: "CAT"}}},
			rules:  []*corev1.CategoryRule{ruleFor("u", func(r *corev1.CategoryRule) { r.Author = denyCell })}, wantAllow: true},
		{name: "scoped policy.author in another category",
			claims: principal.Static{UserIDValue: "u", ScopedRolesValue: []principal.ScopedRole{{Role: "author", Category: "OTHER"}}}},
		{name: "scoped reader role", claims: principal.Static{UserIDValue: "u", ScopedRolesValue: []principal.ScopedRole{{Role: "reader", Category: "CAT"}}}},
		{name: "reader", claims: reader()},
		{name: "reader with a per-document allow override (read only)",
			claims: principal.Static{UserIDValue: "u", RolesValue: []string{"reader"}, ReadSensitiveValue: true,
				PolicyOverridesValue: []principal.Override{{PolicyNumber: "POL-CAT-1", Effect: "allow"}}}},
		{name: "reader with an author row for someone else", claims: reader(), rules: []*corev1.CategoryRule{authorOnlyRule("x")}},
		{name: "manage denied", claims: reader(), rules: []*corev1.CategoryRule{manageRule("u", denyCell)}},
		{name: "non-root site admin without a rule", claims: principal.Static{UserIDValue: "u", RolesValue: []string{"site-admin"}}},
		{name: "non-root site admin with an author row", claims: principal.Static{UserIDValue: "u", RolesValue: []string{"site-admin"}},
			rules: []*corev1.CategoryRule{authorOnlyRule("u")}, wantAllow: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			primary := tc.primary
			if primary == "" {
				primary = "someone"
			}
			pc, gc := coAuthMatrixEnv(primary, tc.owners, tc.rules)
			client := &fakeCollabClient{resp: &collabv1.IssueTokenResponse{Token: "jwt"}}
			_, err := resolvers.IssueCollabToken(ctxWithStubClaims(t, tc.claims), client, pc, gc, collabTokenInput())
			if tc.wantAllow {
				require.NoError(t, err)
				require.NotNil(t, client.lastReq, "collab must be reached")
				return
			}
			require.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
			require.Nil(t, client.lastReq, "collab must not be reached")
		})
	}
}

// A grant scoped to an ancestor category covers the policy below it.
func TestIssueCollabToken_ScopedGrantOnAnAncestor(t *testing.T) {
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol": {Id: "pol", HomeCategoryId: "g-child", Number: "POL-CH-1", Title: "P", OwnerUserId: "someone"},
	}}
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-top":   {Id: "g-top", Name: "TOP"},
			"g-child": {Id: "g-child", Name: "CHILD", ParentId: "g-top"},
		},
		map[string][]*corev1.CategoryRule{"g-top": nil, "g-child": nil},
	)
	claims := principal.Static{UserIDValue: "u", ScopedRolesValue: []principal.ScopedRole{{Role: "author", Category: "TOP"}}}
	client := &fakeCollabClient{resp: &collabv1.IssueTokenResponse{Token: "jwt"}}
	_, err := resolvers.IssueCollabToken(ctxWithStubClaims(t, claims), client, pc, gc, collabTokenInput())
	require.NoError(t, err)
}
