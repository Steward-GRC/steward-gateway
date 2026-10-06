// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// authorRule returns a USER-kind RACI rule granting/denying the author tag to a
// specific user id in a category.
func authorRule(userID string, effect corev1.GrantEffect) *corev1.CategoryRule {
	return &corev1.CategoryRule{
		SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
		SubjectRef:  userID,
		Author:      effect,
	}
}

// coAuthMatrixEnv builds a policy "pol" in category "g-cat" owned by
// primaryOwner, with the given category rules, and a group whose Owners are the
// given owners. Returns the policy + group clients.
func coAuthMatrixEnv(primaryOwner string, owners []string, rules []*corev1.CategoryRule) (*fakePolicyClient, *raciCategoryClient) {
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol": {Id: "pol", HomeCategoryId: "g-cat", Number: "POL-CAT-1", Title: "P", OwnerUserId: primaryOwner},
	}}
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT", ParentId: "", Owners: owners}},
		map[string][]*corev1.CategoryRule{"g-cat": rules},
	)
	return pc, gc
}

// TestCoAuthoring_EditMatrix exercises the effective-author EDIT gate (via
// SaveDraft) across the personas: site-admin, category owner, primary author,
// non-denied author, denied author, non-author.
func TestCoAuthoring_EditMatrix(t *testing.T) {
	cases := []struct {
		name      string
		claims    principal.Static
		owners    []string
		primary   string
		rules     []*corev1.CategoryRule
		wantAllow bool
	}{
		{
			name:      "site-admin edits (deny never applies)",
			claims:    principal.Static{UserIDValue: "admin-u", RolesValue: []string{"site-admin"}},
			rules:     []*corev1.CategoryRule{authorRule("admin-u", corev1.GrantEffect_GRANT_EFFECT_DENY)},
			wantAllow: true,
		},
		{
			name:      "category owner edits (undeniable)",
			claims:    principal.Static{UserIDValue: "owner-u", RolesValue: []string{"reader"}},
			owners:    []string{"owner-u"},
			rules:     []*corev1.CategoryRule{authorRule("owner-u", corev1.GrantEffect_GRANT_EFFECT_DENY)},
			wantAllow: true,
		},
		{
			name:      "primary author edits",
			claims:    principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}},
			primary:   "creator-u",
			wantAllow: true,
		},
		{
			name:      "non-denied category author co-edits",
			claims:    principal.Static{UserIDValue: "coauthor-u", RolesValue: []string{"reader"}},
			rules:     []*corev1.CategoryRule{authorRule("coauthor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)},
			wantAllow: true,
		},
		{
			name:      "denied author cannot edit",
			claims:    principal.Static{UserIDValue: "denied-u", RolesValue: []string{"reader"}},
			rules:     []*corev1.CategoryRule{authorRule("denied-u", corev1.GrantEffect_GRANT_EFFECT_DENY)},
			wantAllow: false,
		},
		{
			name:      "non-author cannot edit",
			claims:    principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}},
			rules:     []*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)},
			wantAllow: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			primary := tc.primary
			if primary == "" {
				primary = "creator-other"
			}
			pc, gc := coAuthMatrixEnv(primary, tc.owners, tc.rules)
			ctx := ctxWithStubClaims(t, tc.claims)
			_, err := resolvers.SaveDraft(ctx, pc, gc, "pol", `{"root":{}}`, "")
			if tc.wantAllow {
				if err != nil {
					t.Fatalf("expected edit allowed, got %v", err)
				}
				if pc.lastSave == nil {
					t.Fatal("expected core SaveDraft to be called")
				}
			} else {
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("expected PermissionDenied, got %v", err)
				}
				if pc.lastSave != nil {
					t.Fatal("core SaveDraft must NOT be called when denied")
				}
			}
		})
	}
}

// TestSetPolicySensitivity_EditGate confirms setPolicySensitivity is gated by
// the policy's EDIT access (the same effective-author gate as SaveDraft) — NOT
// the site-admin gate: any user who can edit the policy can flip its
// classification (both directions), while a non-editor is denied and core is
// never called.
func TestSetPolicySensitivity_EditGate(t *testing.T) {
	// An editor (non-denied category author, not a site-admin) may flip it.
	t.Run("editor flips both directions", func(t *testing.T) {
		claims := principal.Static{UserIDValue: "coauthor-u", RolesValue: []string{"reader"}}
		rules := []*corev1.CategoryRule{authorRule("coauthor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)}
		pc, gc := coAuthMatrixEnv("creator-other", nil, rules)
		ctx := ctxWithStubClaims(t, claims)

		// standard -> sensitive
		got, err := resolvers.SetPolicySensitivity(ctx, pc, gc, "pol", resolvers.SensitivitySensitive)
		if err != nil {
			t.Fatalf("expected flip allowed, got %v", err)
		}
		if got.Sensitivity != resolvers.SensitivitySensitive {
			t.Fatalf("sensitivity: got %q want SENSITIVE", got.Sensitivity)
		}
		if pc.lastSetSens == nil {
			t.Fatal("expected core SetPolicySensitivity to be called")
		}
		if pc.lastSetSens.GetActorUserId() != "coauthor-u" {
			t.Fatalf("actor: got %q want coauthor-u", pc.lastSetSens.GetActorUserId())
		}

		// sensitive -> standard (reverse direction)
		got, err = resolvers.SetPolicySensitivity(ctx, pc, gc, "pol", resolvers.SensitivityStandard)
		if err != nil {
			t.Fatalf("expected reverse flip allowed, got %v", err)
		}
		if got.Sensitivity != resolvers.SensitivityStandard {
			t.Fatalf("reverse sensitivity: got %q want STANDARD", got.Sensitivity)
		}
	})

	// A non-editor (non-author, not owner, not admin) is denied; core untouched.
	t.Run("non-editor denied", func(t *testing.T) {
		claims := principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}}
		rules := []*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)}
		pc, gc := coAuthMatrixEnv("creator-other", nil, rules)
		ctx := ctxWithStubClaims(t, claims)

		_, err := resolvers.SetPolicySensitivity(ctx, pc, gc, "pol", resolvers.SensitivitySensitive)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied, got %v", err)
		}
		if pc.lastSetSens != nil {
			t.Fatal("core SetPolicySensitivity must NOT be called when denied")
		}
	})
}

// TestCoAuthoring_DiscardDraftMatrix exercises the effective-author gate (via
// DiscardDraft): site-admin, category owner, primary author, and — per the
// product decision reversing the original owner-only-discard rule — a
// regular (non-owner) category author too. Same matrix/tier as
// TestCoAuthoring_EditMatrix (SaveDraft), asserted directly against DiscardDraft
// to guard against a future regression re-introducing a tighter gate here.
func TestCoAuthoring_DiscardDraftMatrix(t *testing.T) {
	cases := []struct {
		name      string
		claims    principal.Static
		owners    []string
		primary   string
		rules     []*corev1.CategoryRule
		wantAllow bool
	}{
		{
			name:      "site-admin may discard",
			claims:    principal.Static{UserIDValue: "admin-u", RolesValue: []string{"site-admin"}},
			wantAllow: true,
		},
		{
			name:      "category owner may discard",
			claims:    principal.Static{UserIDValue: "owner-u", RolesValue: []string{"reader"}},
			owners:    []string{"owner-u"},
			wantAllow: true,
		},
		{
			name:      "primary author may discard",
			claims:    principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}},
			primary:   "creator-u",
			wantAllow: true,
		},
		{
			name:      "regular co-author may discard (RACI author tier)",
			claims:    principal.Static{UserIDValue: "coauthor-u", RolesValue: []string{"reader"}},
			rules:     []*corev1.CategoryRule{authorRule("coauthor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)},
			wantAllow: true,
		},
		{
			name:      "non-author may NOT discard",
			claims:    principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}},
			rules:     []*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)},
			wantAllow: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			primary := tc.primary
			if primary == "" {
				primary = "creator-other"
			}
			pc, gc := coAuthMatrixEnv(primary, tc.owners, tc.rules)
			ctx := ctxWithStubClaims(t, tc.claims)
			_, err := resolvers.DiscardDraft(ctx, pc, gc, "pol")
			if tc.wantAllow {
				if err != nil {
					t.Fatalf("expected discard allowed, got %v", err)
				}
				if pc.lastDiscard == nil {
					t.Fatal("expected core DiscardDraft to be called")
				}
			} else {
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("expected PermissionDenied, got %v", err)
				}
				if pc.lastDiscard != nil {
					t.Fatal("core DiscardDraft must NOT be called when denied")
				}
			}
		})
	}
}

// TestCreatePolicy_CategoryAuthorGate exercises the security gate closed by
// creating a policy is an authoring action gated on Author capability
// for the TARGET category (homeCategoryID). A read-only user must be denied and core
// must never be called; a category author, a category owner, and a site-admin are
// allowed; and the gate is PER-CATEGORY (an author in category X may not create in
// category Y).
func TestCreatePolicy_CategoryAuthorGate(t *testing.T) {
	// A read-only subject (RACI read via allow-everyone, NO author grant) must be
	// denied — this is the exact hole: previously CreatePolicy did no authz at all.
	t.Run("read-only user denied, core untouched", func(t *testing.T) {
		gc := newRaciReadClient(
			map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT"}},
			map[string][]*corev1.CategoryRule{"g-cat": {allowEveryoneRule()}},
		)
		pc := &fakePolicyClient{}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u", RolesValue: []string{"reader"}})

		_, err := resolvers.CreatePolicy(ctx, pc, gc, "g-cat", "T", resolvers.SensitivityStandard, nil, nil)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied for read-only user, got %v", err)
		}
		if pc.lastCreate != nil {
			t.Fatal("core CreatePolicy must NOT be called for a non-author")
		}
	})

	// A non-denied category author may create; core is called with the caller bound
	// as owner_user_id.
	t.Run("category author allowed, owner bound to caller", func(t *testing.T) {
		gc := newRaciReadClient(
			map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT"}},
			map[string][]*corev1.CategoryRule{
				"g-cat": {authorRule("author-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)},
			},
		)
		pc := &fakePolicyClient{}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-u", RolesValue: []string{"reader"}})

		got, err := resolvers.CreatePolicy(ctx, pc, gc, "g-cat", "T", resolvers.SensitivityStandard, nil, nil)
		if err != nil {
			t.Fatalf("expected create allowed for category author, got %v", err)
		}
		if pc.lastCreate == nil {
			t.Fatal("expected core CreatePolicy to be called for an author")
		}
		if pc.lastCreate.GetOwnerUserId() != "author-u" {
			t.Fatalf("owner_user_id: got %q want author-u", pc.lastCreate.GetOwnerUserId())
		}
		if got == nil || got.HomeCategoryID != "g-cat" {
			t.Fatalf("returned policy: got %+v want HomeCategoryID=g-cat", got)
		}
	})

	// A site-admin may always create, even with no author rule in the category.
	t.Run("site-admin allowed", func(t *testing.T) {
		gc := newRaciReadClient(
			map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT"}},
			map[string][]*corev1.CategoryRule{"g-cat": {}},
		)
		pc := &fakePolicyClient{}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-u", RolesValue: []string{"site-admin"}})

		_, err := resolvers.CreatePolicy(ctx, pc, gc, "g-cat", "T", resolvers.SensitivityStandard, nil, nil)
		if err != nil {
			t.Fatalf("expected create allowed for site-admin, got %v", err)
		}
		if pc.lastCreate == nil {
			t.Fatal("expected core CreatePolicy to be called for a site-admin")
		}
	})

	// Per-category enforcement: an author in category X may NOT create in category Y.
	t.Run("author in category X denied in category Y", func(t *testing.T) {
		gc := newRaciReadClient(
			map[string]*corev1.Category{
				"g-x": {Id: "g-x", Name: "X"},
				"g-y": {Id: "g-y", Name: "Y"},
			},
			map[string][]*corev1.CategoryRule{
				"g-x": {authorRule("author-x", corev1.GrantEffect_GRANT_EFFECT_ALLOW)},
				"g-y": {},
			},
		)
		pc := &fakePolicyClient{}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-x", RolesValue: []string{"reader"}})

		_, err := resolvers.CreatePolicy(ctx, pc, gc, "g-y", "T", resolvers.SensitivityStandard, nil, nil)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied creating in a category the user does not author, got %v", err)
		}
		if pc.lastCreate != nil {
			t.Fatal("core CreatePolicy must NOT be called for a cross-category non-author")
		}
	})
}
