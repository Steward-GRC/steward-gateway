// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// rootPolicyView loads one policy in category g-it with the given rules and
// sensitivity as the given caller.
func rootPolicyView(t *testing.T, rules []*corev1.CategoryRule, sens corev1.Sensitivity, who principal.Static) *resolvers.PolicyViewerCan {
	t.Helper()
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-it": {Id: "g-it", Name: "IT"}},
		map[string][]*corev1.CategoryRule{"g-it": rules},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1", Sensitivity: sens},
	}}
	p, err := resolvers.GetPolicy(ctxWithStubClaims(t, who), pc, gc, nil, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil {
		t.Fatalf("viewerCan is nil")
	}
	return p.ViewerCan
}

func requireRootAll(t *testing.T, vc *resolvers.PolicyViewerCan) {
	t.Helper()
	if !vc.Read || vc.ContentObfuscated || vc.CanBreakGlass || !vc.Edit || !vc.Submit || !vc.Manage {
		t.Fatalf("root must read, edit, submit and manage with no obfuscation or break-glass; got %+v", vc)
	}
}

var rootCaller = principal.Static{UserIDValue: "root-u", RolesValue: []string{"site-admin"}, IsRootValue: true}

func TestRootOverride_EmptyRuleset(t *testing.T) {
	requireRootAll(t, rootPolicyView(t, nil, corev1.Sensitivity_SENSITIVITY_UNSPECIFIED, rootCaller))
}

func TestRootOverride_Sensitive(t *testing.T) {
	requireRootAll(t, rootPolicyView(t, []*corev1.CategoryRule{allowEveryoneRule()}, corev1.Sensitivity_SENSITIVITY_SENSITIVE, rootCaller))
}

func TestRootOverride_CategoryDeny(t *testing.T) {
	deny := &corev1.CategoryRule{
		SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
		SubjectRef:  "root-u",
		Read:        corev1.GrantEffect_GRANT_EFFECT_DENY,
	}
	requireRootAll(t, rootPolicyView(t, []*corev1.CategoryRule{deny, allowEveryoneRule()}, corev1.Sensitivity_SENSITIVITY_UNSPECIFIED, rootCaller))
}

func TestRootOverride_PerPolicyDeny(t *testing.T) {
	who := rootCaller
	who.PolicyOverridesValue = []principal.Override{{PolicyNumber: "POL-IT-1", Effect: "deny"}}
	requireRootAll(t, rootPolicyView(t, []*corev1.CategoryRule{allowEveryoneRule()}, corev1.Sensitivity_SENSITIVITY_SENSITIVE, who))
}

func TestRootOverride_AckFollowsRule(t *testing.T) {
	everyoneAck := &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE, Ack: corev1.GrantEffect_GRANT_EFFECT_ALLOW}
	if vc := rootPolicyView(t, []*corev1.CategoryRule{everyoneAck}, corev1.Sensitivity_SENSITIVITY_UNSPECIFIED, rootCaller); !vc.Ack {
		t.Fatalf("root must ack when the category Ack rule covers them; got %+v", vc)
	}
	itAck := &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP, SubjectRef: "IT", Ack: corev1.GrantEffect_GRANT_EFFECT_ALLOW}
	if vc := rootPolicyView(t, []*corev1.CategoryRule{itAck}, corev1.Sensitivity_SENSITIVITY_UNSPECIFIED, rootCaller); vc.Ack {
		t.Fatalf("root outside the Ack group must not ack; got %+v", vc)
	}
	inIT := rootCaller
	inIT.IdpGroupsValue = []string{"IT"}
	if vc := rootPolicyView(t, []*corev1.CategoryRule{itAck}, corev1.Sensitivity_SENSITIVITY_UNSPECIFIED, inIT); !vc.Ack {
		t.Fatalf("root in the Ack group must ack; got %+v", vc)
	}
	if vc := rootPolicyView(t, nil, corev1.Sensitivity_SENSITIVITY_UNSPECIFIED, rootCaller); vc.Ack {
		t.Fatalf("root with no Ack rule must not ack; got %+v", vc)
	}
}

// A site admin who is not root keeps the old behaviour.
func TestRootOverride_NonRootSiteAdminUnchanged(t *testing.T) {
	sa := principal.Static{UserIDValue: "sa-u", RolesValue: []string{"site-admin"}}
	vc := rootPolicyView(t, nil, corev1.Sensitivity_SENSITIVITY_UNSPECIFIED, sa)
	if !vc.ContentObfuscated || !vc.CanBreakGlass || vc.Approve {
		t.Fatalf("non-root site admin with no rule stays obfuscated, break-glass, no approve; got %+v", vc)
	}
}
