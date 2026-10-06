// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// TestRaciGrantEnumMapping verifies all three GQL→authz and authz→GQL mappings.
func TestRaciGrantEnumMapping(t *testing.T) {
	cases := []struct {
		gql  resolvers.RaciGrant
		want authz.Grant
	}{
		{resolvers.RaciGrantBlank, authz.GrantBlank},
		{resolvers.RaciGrantAllow, authz.GrantAllow},
		{resolvers.RaciGrantDeny, authz.GrantDeny},
	}
	for _, tc := range cases {
		got := resolvers.RaciGrantFromGQL(tc.gql)
		if got != tc.want {
			t.Errorf("RaciGrantFromGQL(%v) = %v, want %v", tc.gql, got, tc.want)
		}
		back := resolvers.RaciGrantToGQL(tc.want)
		if back != tc.gql {
			t.Errorf("RaciGrantToGQL(%v) = %v, want %v", tc.want, back, tc.gql)
		}
	}
}

// TestRaciKindEnumMapping verifies all three GQL→authz and authz→GQL mappings.
func TestRaciKindEnumMapping(t *testing.T) {
	cases := []struct {
		gql  resolvers.RaciSubjectKind
		want authz.SubjectKind
	}{
		{resolvers.RaciSubjectKindEveryone, authz.SubjectEveryone},
		{resolvers.RaciSubjectKindGroup, authz.SubjectGroup},
		{resolvers.RaciSubjectKindUser, authz.SubjectUser},
	}
	for _, tc := range cases {
		got := resolvers.RaciKindFromGQL(tc.gql)
		if got != tc.want {
			t.Errorf("RaciKindFromGQL(%v) = %v, want %v", tc.gql, got, tc.want)
		}
		back := resolvers.RaciKindToGQL(tc.want)
		if back != tc.gql {
			t.Errorf("RaciKindToGQL(%v) = %v, want %v", tc.want, back, tc.gql)
		}
	}
}

// TestRuleGQLInputToAuthz verifies a full rule is mapped correctly.
func TestRuleGQLInputToAuthz(t *testing.T) {
	in := &resolvers.RaciRuleInput{
		SubjectKind: resolvers.RaciSubjectKindGroup,
		SubjectRef:  "IT-Staff",
		Read:        resolvers.RaciGrantAllow,
		Ack:         resolvers.RaciGrantBlank,
		Approve:     resolvers.RaciGrantDeny,
		Author:      resolvers.RaciGrantAllow,
	}
	r := resolvers.RuleGQLInputToAuthz(in)
	if r.Subject.Kind != authz.SubjectGroup {
		t.Errorf("Subject.Kind = %v, want group", r.Subject.Kind)
	}
	if r.Subject.Name != "IT-Staff" {
		t.Errorf("Subject.Name = %v, want IT-Staff", r.Subject.Name)
	}
	if r.Grants[authz.ActionRead] != authz.GrantAllow {
		t.Errorf("Read = %v, want allow", r.Grants[authz.ActionRead])
	}
	if r.Grants[authz.ActionAcknowledge] != authz.GrantBlank {
		t.Errorf("Ack = %v, want blank", r.Grants[authz.ActionAcknowledge])
	}
	if r.Grants[authz.ActionApprove] != authz.GrantDeny {
		t.Errorf("Approve = %v, want deny", r.Grants[authz.ActionApprove])
	}
	if r.Grants[authz.ActionAuthor] != authz.GrantAllow {
		t.Errorf("Author = %v, want allow", r.Grants[authz.ActionAuthor])
	}
}

// TestAuthzResultToDecision verifies all four fields are mapped.
func TestAuthzResultToDecision(t *testing.T) {
	res := authz.Result{
		Read:        authz.RuleDecision{Allowed: true, Reason: "r1"},
		Acknowledge: authz.RuleDecision{Allowed: false, Reason: "r2"},
		Approve:     authz.RuleDecision{Allowed: true, Reason: "r3"},
		Author:      authz.RuleDecision{Allowed: false, Reason: "r4"},
	}
	d := resolvers.AuthzResultToDecision(res)
	if d.Read != true || d.ReadReason != "r1" {
		t.Errorf("Read: got %v/%v, want true/r1", d.Read, d.ReadReason)
	}
	if d.Ack != false || d.AckReason != "r2" {
		t.Errorf("Ack: got %v/%v, want false/r2", d.Ack, d.AckReason)
	}
	if d.Approve != true || d.ApproveReason != "r3" {
		t.Errorf("Approve: got %v/%v, want true/r3", d.Approve, d.ApproveReason)
	}
	if d.Author != false || d.AuthorReason != "r4" {
		t.Errorf("Author: got %v/%v, want false/r4", d.Author, d.AuthorReason)
	}
}

// TestBuildCategoryChain verifies a 2-level tree: Health (leaf) → IT (root).
// Chain should be [Health, IT] with owners and rules mapped.
// This test exercises buildCategoryChain directly (gateway no longer
// owns a copy — the chain loader was extracted verbatim to platform/raciclient).
func TestBuildCategoryChain(t *testing.T) {
	gc := &raciCategoryClient{
		groups: map[string]*corev1.Category{
			"health-id": {
				Id:       "health-id",
				Name:     "Health",
				ParentId: "it-id",
				Owners:   []string{"owner-1"},
			},
			"it-id": {
				Id:     "it-id",
				Name:   "IT",
				Owners: []string{"owner-2"},
			},
		},
		rulesets: map[string][]*corev1.CategoryRule{
			"health-id": {
				{
					SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE,
					SubjectRef:  "",
					Read:        corev1.GrantEffect_GRANT_EFFECT_ALLOW,
					Ack:         corev1.GrantEffect_GRANT_EFFECT_ALLOW,
				},
			},
			"it-id": {
				{
					SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP,
					SubjectRef:  "Contractors",
					Read:        corev1.GrantEffect_GRANT_EFFECT_DENY,
				},
			},
		},
	}

	chain, err := resolvers.BuildCategoryChain(context.Background(), gc, "health-id")
	if err != nil {
		t.Fatalf("BuildCategoryChain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(chain))
	}

	// chain[0] = target (Health)
	if chain[0].Name != "Health" {
		t.Errorf("chain[0].Name = %v, want Health", chain[0].Name)
	}
	if len(chain[0].Owners) != 1 || chain[0].Owners[0] != "owner-1" {
		t.Errorf("chain[0].Owners = %v, want [owner-1]", chain[0].Owners)
	}
	if len(chain[0].Rules) != 1 {
		t.Fatalf("chain[0].Rules len = %d, want 1", len(chain[0].Rules))
	}
	if chain[0].Rules[0].Subject.Kind != authz.SubjectEveryone {
		t.Errorf("Health rule[0].Subject.Kind = %v, want everyone", chain[0].Rules[0].Subject.Kind)
	}
	if chain[0].Rules[0].Grants[authz.ActionRead] != authz.GrantAllow {
		t.Errorf("Health rule[0] read = %v, want allow", chain[0].Rules[0].Grants[authz.ActionRead])
	}

	// chain[1] = ancestor (IT)
	if chain[1].Name != "IT" {
		t.Errorf("chain[1].Name = %v, want IT", chain[1].Name)
	}
	if len(chain[1].Owners) != 1 || chain[1].Owners[0] != "owner-2" {
		t.Errorf("chain[1].Owners = %v, want [owner-2]", chain[1].Owners)
	}
	if len(chain[1].Rules) != 1 {
		t.Fatalf("chain[1].Rules len = %d, want 1", len(chain[1].Rules))
	}
	if chain[1].Rules[0].Subject.Kind != authz.SubjectGroup {
		t.Errorf("IT rule[0].Subject.Kind = %v, want group", chain[1].Rules[0].Subject.Kind)
	}
	if chain[1].Rules[0].Subject.Name != "Contractors" {
		t.Errorf("IT rule[0].Subject.Name = %v, want Contractors", chain[1].Rules[0].Subject.Name)
	}
	if chain[1].Rules[0].Grants[authz.ActionRead] != authz.GrantDeny {
		t.Errorf("IT rule[0] read = %v, want deny", chain[1].Rules[0].Grants[authz.ActionRead])
	}
}
