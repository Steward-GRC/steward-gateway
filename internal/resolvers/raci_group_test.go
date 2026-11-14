// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func groupRule(name string) *corev1.CategoryRule {
	return &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP, SubjectRef: name}
}

// A group simulation decides for a subject whose only membership is the group:
// the group's rows apply, a user's rows and ownership do not.
func TestSimulateCategory_GroupSubject(t *testing.T) {
	g := groupRule("Finance")
	g.Read = corev1.GrantEffect_GRANT_EFFECT_ALLOW
	g.Author = corev1.GrantEffect_GRANT_EFFECT_ALLOW
	u := userRule("erin")
	u.Approve = corev1.GrantEffect_GRANT_EFFECT_ALLOW
	r := manageEnv([]*corev1.CategoryRule{g, u}, []string{"erin"}, &identityv1.User{Id: "erin"})
	ctx := ctxWithRoles(t, "admin", []string{"site-admin"})

	d, err := resolvers.SimulateCategoryResolver(ctx, r, "c", "", "Finance", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Read || !d.Author || d.Approve || d.Manage {
		t.Fatalf("the group has Read and Author only: %+v", d)
	}
	if d.ReadVerdict.Code != resolvers.RaciVerdictCodeRuleAllow || d.ReadVerdict.Rule == nil ||
		d.ReadVerdict.Rule.SubjectKind != resolvers.RaciSubjectKindGroup || d.ReadVerdict.Rule.SubjectRef != "Finance" || d.ReadVerdict.Rule.RuleNumber != 1 {
		t.Fatalf("read verdict = %+v", d.ReadVerdict)
	}

	other, err := resolvers.SimulateCategoryResolver(ctx, r, "c", "", "Legal", nil)
	if err != nil {
		t.Fatal(err)
	}
	if other.Read || other.Author {
		t.Fatalf("a group no rule names has nothing: %+v", other)
	}
}

func TestSimulateCategory_GroupAlsoGetsEveryone(t *testing.T) {
	e := &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE, Read: corev1.GrantEffect_GRANT_EFFECT_ALLOW}
	r := manageEnv([]*corev1.CategoryRule{e}, nil)
	d, err := resolvers.SimulateCategoryResolver(ctxWithRoles(t, "admin", []string{"site-admin"}), r, "c", "", "Anything", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Read || d.ReadVerdict.Rule == nil || d.ReadVerdict.Rule.SubjectKind != resolvers.RaciSubjectKindEveryone {
		t.Fatalf("Everyone applies to a group: %+v", d)
	}
}

func TestSimulateCategory_GroupWithDraft(t *testing.T) {
	r := manageEnv(nil, nil)
	draft := []*resolvers.RaciRuleInput{{
		SubjectKind: resolvers.RaciSubjectKindGroup, SubjectRef: "Finance",
		Read: resolvers.RaciGrantAllow, Author: resolvers.RaciGrantBlank, Approve: resolvers.RaciGrantBlank,
		Manage: resolvers.RaciGrantBlank, Ack: resolvers.RaciGrantBlank,
	}}
	d, err := resolvers.SimulateCategoryResolver(ctxWithRoles(t, "admin", []string{"site-admin"}), r, "c", "", "Finance", draft)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Read {
		t.Fatalf("a draft group row must decide: %+v", d)
	}
}

func TestSimulateCategory_UserAndGroupTogetherAreRefused(t *testing.T) {
	r := manageEnv(nil, nil, &identityv1.User{Id: "u"})
	_, err := resolvers.SimulateCategoryResolver(ctxWithRoles(t, "admin", []string{"site-admin"}), r, "c", "u", "Finance", nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("userId with groupName = %v, want InvalidArgument", err)
	}
}

// The group simulation is gated like the person simulation: group managers and
// template admins may ask, anyone else is refused.
func TestSimulateCategory_GroupPermission(t *testing.T) {
	r := manageEnv(nil, nil)
	for _, tc := range []struct {
		role  string
		allow bool
	}{
		{"site-admin", true},
		{"template-admin", true},
		{"compliance-admin", false},
		{"author", false},
	} {
		_, err := resolvers.SimulateCategoryResolver(ctxWithRoles(t, "caller", []string{tc.role}), r, "c", "", "Finance", nil)
		switch {
		case tc.allow && err != nil:
			t.Fatalf("%s: %v, want allowed", tc.role, err)
		case !tc.allow && status.Code(err) != codes.PermissionDenied:
			t.Fatalf("%s: %v, want PermissionDenied", tc.role, err)
		}
	}
	if _, err := resolvers.SimulateCategoryResolver(ctxWithRoles(t, "caller", nil), r, "c", "", "Finance", nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no role: %v, want PermissionDenied", err)
	}
}
