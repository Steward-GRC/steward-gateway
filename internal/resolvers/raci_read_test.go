// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newRaciReadClient creates a raciCategoryClient for the merit-RACI read tests.
// We reuse raciCategoryClient defined in raci_map_test.go (same test package).
func newRaciReadClient(groups map[string]*corev1.Category, rulesets map[string][]*corev1.CategoryRule) *raciCategoryClient {
	return &raciCategoryClient{groups: groups, rulesets: rulesets}
}

// allowEveryoneRule returns a CategoryRule that allows everyone to read.
func allowEveryoneRule() *corev1.CategoryRule {
	return &corev1.CategoryRule{
		SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE,
		Read:        corev1.GrantEffect_GRANT_EFFECT_ALLOW,
	}
}

// denyGroupRule returns a CategoryRule that denies a named group from reading.
func denyGroupRule(groupName string) *corev1.CategoryRule {
	return &corev1.CategoryRule{
		SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP,
		SubjectRef:  groupName,
		Read:        corev1.GrantEffect_GRANT_EFFECT_DENY,
	}
}

// TestMeritRACIRead_OwnerReads verifies that a group owner always reads
// the policy (owner auto-read from RACI chain, regardless of explicit rules).
func TestMeritRACIRead_OwnerReads(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: "", Owners: []string{"owner-u"}},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {}, // no rules — but owner auto-reads
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "owner-u",
	})
	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil || !p.ViewerCan.Read {
		t.Fatalf("owner must always read via RACI; got %+v", p.ViewerCan)
	}
	if p.ViewerCan.ContentObfuscated {
		t.Fatalf("owner read must not be obfuscated; got %+v", p.ViewerCan)
	}
}

// TestMeritRACIRead_EveryoneAllowReads verifies that a user in the
// "everyone allow" ruleset can read the policy.
func TestMeritRACIRead_EveryoneAllowReads(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {allowEveryoneRule()},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "plain-user",
		RolesValue:  []string{"reader"},
	})
	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil || !p.ViewerCan.Read || p.ViewerCan.ContentObfuscated {
		t.Fatalf("everyone-allow must produce visible read; got %+v", p.ViewerCan)
	}
}

// TestMeritRACIRead_GroupDenyHidesNonAdmin verifies that a non-site-admin
// user whose group is denied read is hidden (Deny → filtered from list/NotFound).
func TestMeritRACIRead_GroupDenyHidesNonAdmin(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {
				denyGroupRule("Contractors"), // deny this group first
				allowEveryoneRule(),          // then allow everyone else
			},
		},
	)
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
		},
		listResult: []string{"pol-it"},
	}
	// User is in the Contractors AD group (matched by GroupNames in EvalSubject via AdGroups).
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:    "contractor-u",
		RolesValue:     []string{"reader"},
		IdpGroupsValue: []string{"Contractors"},
	})

	// GetPolicy → NotFound (existence hidden).
	if _, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol-it"); status.Code(err) != codes.NotFound {
		t.Fatalf("RACI-denied non-admin must get NotFound; got %v", err)
	}

	// ListPolicies → filtered out.
	out, err := resolvers.ListPolicies(ctx, pc, gc, nil, nil, "g-it", new(true), nil)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	for _, p := range out {
		if p.ID == "pol-it" {
			t.Fatal("RACI-denied non-admin must be filtered from the list")
		}
	}
}

// TestMeritRACIRead_GroupDenyObfuscatesSiteAdmin verifies that a site-admin
// whose group is RACI-denied on merit still sees the policy but gets obfuscated
// content (obfuscateOrDeny: site-admin → Obfuscate).
func TestMeritRACIRead_GroupDenyObfuscatesSiteAdmin(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {
				denyGroupRule("Contractors"),
				allowEveryoneRule(),
			},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	// Site-admin who is also in the denied Contractors AD group.
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:    "sa-contractor",
		RolesValue:     []string{"site-admin"},
		IdpGroupsValue: []string{"Contractors"},
	})
	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil || !p.ViewerCan.Read {
		t.Fatalf("RACI-denied site-admin must still see the policy (read=true); got %+v", p.ViewerCan)
	}
	if !p.ViewerCan.ContentObfuscated {
		t.Fatalf("RACI-denied site-admin must get contentObfuscated=true; got %+v", p.ViewerCan)
	}
	if !p.ViewerCan.CanBreakGlass {
		t.Fatalf("obfuscated site-admin must get canBreakGlass=true; got %+v", p.ViewerCan)
	}
}

// TestMeritRACIRead_OverrideAllowBeatsMeritDeny verifies that a per-policy
// "allow" override grants read even when RACI merit says deny.
func TestMeritRACIRead_OverrideAllowBeatsMeritDeny(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {denyGroupRule("Contractors")}, // no everyone rule → Contractors denied
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	// User has an "allow" override for this policy number despite RACI deny.
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:    "contractor-u",
		RolesValue:     []string{"reader"},
		IdpGroupsValue: []string{"Contractors"},
		PolicyOverridesValue: []principal.Override{
			{PolicyNumber: "POL-IT-1", Effect: "allow"},
		},
	})
	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil || !p.ViewerCan.Read || p.ViewerCan.ContentObfuscated {
		t.Fatalf("override allow must beat merit deny and grant visible read; got %+v", p.ViewerCan)
	}
}

// TestMeritRACIRead_OverrideDenyHidesNonAdmin verifies that a per-policy "deny"
// override hides a non-admin user even when RACI merit grants read.
func TestMeritRACIRead_OverrideDenyHidesNonAdmin(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {allowEveryoneRule()}, // everyone allowed on merit
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "reader-u",
		RolesValue:  []string{"reader"},
		PolicyOverridesValue: []principal.Override{
			{PolicyNumber: "POL-IT-1", Effect: "deny"},
		},
	})
	if _, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol-it"); status.Code(err) != codes.NotFound {
		t.Fatalf("override deny on non-admin must yield NotFound; got %v", err)
	}
}

// TestMeritRACIRead_OverrideDenyObfuscatesSiteAdmin verifies that a per-policy
// "deny" override on a site-admin produces obfuscation (not NotFound).
func TestMeritRACIRead_OverrideDenyObfuscatesSiteAdmin(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {allowEveryoneRule()},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "sa",
		RolesValue:  []string{"site-admin"},
		PolicyOverridesValue: []principal.Override{
			{PolicyNumber: "POL-IT-1", Effect: "deny"},
		},
	})
	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if !p.ViewerCan.ContentObfuscated {
		t.Fatalf("override deny on site-admin must obfuscate; got %+v", p.ViewerCan)
	}
}

// TestGetPolicy_ViewerCan_Ack verifies PolicyViewerCan.ack mirrors the
// compliance-notify obligation semantics: override-deny → false; override-allow
// → UNGATED ack match; otherwise the read-gated Resolve.Ack result.
func TestGetPolicy_ViewerCan_Ack(t *testing.T) {
	everyoneReadAck := &corev1.CategoryRule{
		SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE,
		Read:        corev1.GrantEffect_GRANT_EFFECT_ALLOW,
		Ack:         corev1.GrantEffect_GRANT_EFFECT_ALLOW,
	}
	everyoneAckOnly := &corev1.CategoryRule{
		SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE,
		Ack:         corev1.GrantEffect_GRANT_EFFECT_ALLOW,
		// No read grant — only reachable via a per-policy override-allow.
	}
	itAckDeny := &corev1.CategoryRule{
		SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP,
		SubjectRef:  "IT",
		Ack:         corev1.GrantEffect_GRANT_EFFECT_DENY,
	}

	cases := []struct {
		name    string
		rules   []*corev1.CategoryRule
		claims  principal.Static
		wantAck bool
	}{
		{
			name:    "everyone_ack_rule",
			rules:   []*corev1.CategoryRule{everyoneReadAck},
			claims:  principal.Static{UserIDValue: "plain-u"},
			wantAck: true,
		},
		{
			name:  "group_ack_deny_via_adgroups",
			rules: []*corev1.CategoryRule{itAckDeny, everyoneReadAck},
			claims: principal.Static{
				UserIDValue:    "it-u",
				IdpGroupsValue: []string{"IT"},
			},
			wantAck: false,
		},
		{
			name:  "override_allow_ungated_ack",
			rules: []*corev1.CategoryRule{everyoneAckOnly}, // no read rule at all
			claims: principal.Static{
				UserIDValue: "override-u",
				PolicyOverridesValue: []principal.Override{
					{PolicyNumber: "POL-IT-1", Effect: "allow"},
				},
			},
			wantAck: true,
		},
		{
			// Site-admin so the policy stays observable (obfuscated, not NotFound).
			name:  "override_deny",
			rules: []*corev1.CategoryRule{everyoneReadAck},
			claims: principal.Static{
				UserIDValue: "sa-u",
				RolesValue:  []string{"site-admin"},
				PolicyOverridesValue: []principal.Override{
					{PolicyNumber: "POL-IT-1", Effect: "deny"},
				},
			},
			wantAck: false,
		},
		{
			name:    "no_ack_rule",
			rules:   []*corev1.CategoryRule{allowEveryoneRule()}, // read only, no ack
			claims:  principal.Static{UserIDValue: "plain-u"},
			wantAck: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gc := newRaciReadClient(
				map[string]*corev1.Category{
					"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
				},
				map[string][]*corev1.CategoryRule{"g-it": tc.rules},
			)
			pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
				"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
			}}
			ctx := ctxWithStubClaims(t, tc.claims)
			p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol-it")
			if err != nil {
				t.Fatalf("GetPolicy: %v", err)
			}
			if p.ViewerCan == nil {
				t.Fatal("viewerCan must be populated")
			}
			if p.ViewerCan.Ack != tc.wantAck {
				t.Errorf("ack = %v, want %v (%+v)", p.ViewerCan.Ack, tc.wantAck, p.ViewerCan)
			}
		})
	}
}

// simpleBreakGlassAdmin is a minimal IdentityAdminServiceClient stub that grants
// break-glass for any policy number and returns it as active. Used only in
// non-integration tests to avoid depending on the integration-only rbacBreakGlassAdmin.
type simpleBreakGlassAdmin struct {
	identityv1.IdentityAdminServiceClient
	active []string // policy numbers with active break-glass
}

func (f *simpleBreakGlassAdmin) BreakGlassReveal(_ context.Context, in *identityv1.BreakGlassRevealRequest, _ ...grpc.CallOption) (*identityv1.BreakGlassRevealResponse, error) {
	f.active = append(f.active, in.GetPolicyNumber())
	return &identityv1.BreakGlassRevealResponse{GrantedUntil: "2099-01-01T00:00:00Z"}, nil
}

func (f *simpleBreakGlassAdmin) ActiveBreakGlass(_ context.Context, _ *identityv1.ActiveBreakGlassRequest, _ ...grpc.CallOption) (*identityv1.ActiveBreakGlassResponse, error) {
	return &identityv1.ActiveBreakGlassResponse{PolicyNumbers: f.active}, nil
}

// TestMeritRACIRead_BreakGlassFlipsObfuscate verifies that an active break-glass
// grant turns obfuscation into full read for an otherwise-denied site-admin.
// (Break-glass is only consulted in the default branch, not for override deny.)
func TestMeritRACIRead_BreakGlassFlipsObfuscate(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {denyGroupRule("Admins"), allowEveryoneRule()},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	admin := &simpleBreakGlassAdmin{}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:    "sa",
		RolesValue:     []string{"site-admin"},
		IdpGroupsValue: []string{"Admins"},
	})

	// Before break-glass → obfuscated (denied by group RACI rule, obfuscated for site-admin).
	p1, err := resolvers.GetPolicy(ctx, pc, gc, admin, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy (no break-glass): %v", err)
	}
	if !p1.ViewerCan.ContentObfuscated {
		t.Fatalf("before break-glass: RACI-denied site-admin must be obfuscated; got %+v", p1.ViewerCan)
	}

	// Grant break-glass for this policy number.
	admin.active = append(admin.active, "POL-IT-1")

	// After break-glass → real content.
	p2, err := resolvers.GetPolicy(ctx, pc, gc, admin, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy (with break-glass): %v", err)
	}
	if p2.ViewerCan.ContentObfuscated {
		t.Fatalf("active break-glass must flip obfuscation to clear; got %+v", p2.ViewerCan)
	}
}

// TestMeritRACIRead_GroupDenyMatchesADGroups verifies that group-kind RACI rules
// match against AD group names (from Claims.AdGroups / IdpGroupsValue), NOT platform
// group IDs (from Claims.Groups / GroupsValue). This is the production-faithful path:
// Keycloak-federated AD group names arrive via x-fwd-adgroups, not x-fwd-groups.
func TestMeritRACIRead_GroupDenyMatchesADGroups(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {
				denyGroupRule("Contractors"), // deny by AD group name
				allowEveryoneRule(),
			},
		},
	)
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
		},
		listResult: []string{"pol-it"},
	}

	// Platform GroupsValue does NOT contain "Contractors" (they are opaque IDs);
	// IdpGroupsValue DOES contain the AD group name — this must trigger the deny.
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:    "contractor-u",
		RolesValue:     []string{"reader"},
		GroupsValue:    []string{"grp-uuid-9999"}, // platform ID — must NOT match rule
		IdpGroupsValue: []string{"Contractors"},   // AD name — MUST match rule
	})

	// GetPolicy must return NotFound (hidden by group deny).
	if _, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol-it"); status.Code(err) != codes.NotFound {
		t.Fatalf("RACI group-deny must match AD group names (IdpGroupsValue), not platform IDs; got %v", err)
	}

	// ListPolicies must filter the policy out.
	out, err := resolvers.ListPolicies(ctx, pc, gc, nil, nil, "g-it", new(true), nil)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	for _, p := range out {
		if p.ID == "pol-it" {
			t.Fatal("RACI group-deny (AD name) must filter policy from list when only IdpGroupsValue matches")
		}
	}
}

// TestMeritRACIRead_SensitiveGateHidesWithoutClearance verifies that a sensitive
// policy is hidden from a reader who lacks PolicyReadSensitive clearance,
// even when RACI merit grants read (everyone allow rule).
func TestMeritRACIRead_SensitiveGateHidesWithoutClearance(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {allowEveryoneRule()}, // everyone allowed on merit
		},
	)
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol-sens": {
				Id:                        "pol-sens",
				HomeCategoryId:            "g-it",
				Number:                    "POL-IT-9",
				Title:                     "Sensitive",
				CurrentPublishedVersionId: "pol-sens-v1",
				Sensitivity:               corev1.Sensitivity_SENSITIVITY_SENSITIVE,
			},
		},
		listResult: []string{"pol-sens"},
	}

	// Plain reader (no read_sensitive) → denied by sensitivity gate.
	readerCtx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "reader-u",
		RolesValue:  []string{"reader"},
	})
	if _, err := resolvers.GetPolicy(readerCtx, pc, gc, nil, nil, "pol-sens"); status.Code(err) != codes.NotFound {
		t.Fatalf("sensitive without clearance must yield NotFound; got %v", err)
	}
	out, err := resolvers.ListPolicies(readerCtx, pc, gc, nil, nil, "g-it", new(true), nil)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("sensitive policy must be filtered from list without clearance; got %d", len(out))
	}

	// No role grants read-sensitive; only the individual grant does.
	clearedCtx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:        "ca",
		RolesValue:         []string{"compliance-admin"},
		ReadSensitiveValue: true,
	})
	visible, err := resolvers.ListPolicies(clearedCtx, pc, gc, nil, nil, "g-it", new(true), nil)
	if err != nil {
		t.Fatalf("ListPolicies (read-sensitive grant): %v", err)
	}
	if len(visible) != 1 || visible[0].ID != "pol-sens" {
		t.Fatalf("read_sensitive holder must see sensitive policy; got %v", visible)
	}
}
