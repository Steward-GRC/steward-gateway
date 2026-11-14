// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"testing"

	"github.com/Bugs5382/go-authz/ordered"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

func groupRow(name string) *corev1.CategoryRule {
	return &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP, SubjectRef: name}
}

// twoLevels is a child "Child" under "Top", the child's rows first.
func twoLevels(child, top []*corev1.CategoryRule, owners []string) *categoryAccess {
	return newCategoryAccess([]*corev1.EffectiveLevel{
		{CategoryId: "child", Name: "Child", Rules: child},
		{CategoryId: "top", Name: "Top", Rules: top, Owners: owners},
	})
}

func wantVerdict(t *testing.T, label string, got *RaciVerdictReason, code RaciVerdictCode) *RaciDecidingRule {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: verdict is nil", label)
	}
	if got.Code != code {
		t.Fatalf("%s: code = %v, want %v", label, got.Code, code)
	}
	return got.Rule
}

func TestVerdictRuleDenyNamesTheRule(t *testing.T) {
	filler := userRow("someone")
	filler.Read = allowEffect
	deny := groupRow("Finance")
	deny.Read = denyEffect
	got := decisionsToGQL(twoLevels([]*corev1.CategoryRule{filler, deny}, nil, nil).decide(ordered.Person{Groups: []string{"Finance"}}))

	r := wantVerdict(t, "read", got.ReadVerdict, RaciVerdictCodeRuleDeny)
	if r == nil || r.CategoryID != "child" || r.CategoryName != "Child" || r.Depth != 0 || r.RuleNumber != 2 ||
		r.SubjectKind != RaciSubjectKindGroup || r.SubjectRef != "Finance" || r.Action != RaciActionRead {
		t.Fatalf("rule = %+v", r)
	}
	if got.ReadCode != RaciReasonCodeEntry || got.ReadReason == "" {
		t.Fatalf("the coarse code and the text must stay: %v %q", got.ReadCode, got.ReadReason)
	}
}

func TestVerdictRuleAllowFromAParentHasDepth(t *testing.T) {
	filler := userRow("someone")
	filler.Author = allowEffect
	allow := everyoneRow()
	allow.Read = allowEffect
	got := decisionsToGQL(twoLevels(nil, []*corev1.CategoryRule{filler, allow}, nil).decide(ordered.Person{ID: "u"}))

	r := wantVerdict(t, "read", got.ReadVerdict, RaciVerdictCodeRuleAllow)
	if r == nil || r.CategoryID != "top" || r.CategoryName != "Top" || r.Depth != 1 || r.RuleNumber != 2 ||
		r.SubjectKind != RaciSubjectKindEveryone || r.SubjectRef != "" {
		t.Fatalf("rule = %+v", r)
	}
}

func TestVerdictDefaultDenyHasNoRule(t *testing.T) {
	got := decisionsToGQL(oneLevel(nil).decide(ordered.Person{ID: "u"}))
	for label, v := range map[string]*RaciVerdictReason{"read": got.ReadVerdict, "author": got.AuthorVerdict, "approve": got.ApproveVerdict, "manage": got.ManageVerdict} {
		if r := wantVerdict(t, label, v, RaciVerdictCodeDefaultDeny); r != nil {
			t.Fatalf("%s: default deny carries no rule: %+v", label, r)
		}
	}
}

func TestVerdictOwner(t *testing.T) {
	got := decisionsToGQL(twoLevels(nil, nil, []string{"u"}).decide(ordered.Person{ID: "u"}))
	for label, v := range map[string]*RaciVerdictReason{"read": got.ReadVerdict, "author": got.AuthorVerdict, "approve": got.ApproveVerdict, "manage": got.ManageVerdict} {
		if r := wantVerdict(t, label, v, RaciVerdictCodeOwner); r != nil {
			t.Fatalf("%s: an owner verdict carries no rule: %+v", label, r)
		}
	}
}

func TestVerdictSiteAdminSeat(t *testing.T) {
	deny := everyoneRow()
	deny.Read, deny.Author, deny.Manage = denyEffect, denyEffect, denyEffect
	got := decisionsToGQL(oneLevel(nil, deny).decide(ordered.Person{ID: "r", Roles: []string{rootRole}}))
	wantVerdict(t, "read", got.ReadVerdict, RaciVerdictCodeSiteAdminRead)
	wantVerdict(t, "author", got.AuthorVerdict, RaciVerdictCodeSiteAdminAuthor)
	wantVerdict(t, "manage", got.ManageVerdict, RaciVerdictCodeSiteAdminManage)
	wantVerdict(t, "approve", got.ApproveVerdict, RaciVerdictCodeDefaultDeny)
}

func TestVerdictImplications(t *testing.T) {
	cases := []struct {
		name     string
		set      func(r *corev1.CategoryRule)
		wantRead RaciVerdictCode
		wantAct  RaciAction
	}{
		{"author", func(r *corev1.CategoryRule) { r.Author = allowEffect }, RaciVerdictCodeAuthorImpliesRead, RaciActionAuthor},
		{"approve", func(r *corev1.CategoryRule) { r.Approve = allowEffect }, RaciVerdictCodeApproverImpliesRead, RaciActionApprove},
		{"manage", func(r *corev1.CategoryRule) { r.Manage = allowEffect }, RaciVerdictCodeManageImpliesRead, RaciActionManage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A Read deny in the same row would be first; the higher allow still gives Read.
			row := userRow("u")
			row.Read = denyEffect
			tc.set(row)
			got := decisionsToGQL(oneLevel(nil, row).decide(ordered.Person{ID: "u"}))
			if !got.Read {
				t.Fatalf("read must be given by the higher action: %+v", got)
			}
			r := wantVerdict(t, "read", got.ReadVerdict, tc.wantRead)
			if r == nil || r.Action != tc.wantAct || r.RuleNumber != 1 || r.SubjectKind != RaciSubjectKindUser || r.SubjectRef != "u" {
				t.Fatalf("rule = %+v", r)
			}
		})
	}
}

func TestVerdictManageImpliesAuthor(t *testing.T) {
	row := userRow("u")
	row.Author = denyEffect
	row.Manage = allowEffect
	got := decisionsToGQL(oneLevel(nil, row).decide(ordered.Person{ID: "u"}))
	r := wantVerdict(t, "author", got.AuthorVerdict, RaciVerdictCodeManageImpliesAuthor)
	if r == nil || r.Action != RaciActionManage {
		t.Fatalf("rule = %+v", r)
	}
}

func TestVerdictRequiresRead(t *testing.T) {
	row := userRow("u")
	row.Read = denyEffect
	row.Ack = allowEffect
	got := decisionsToGQL(oneLevel(nil, row).decide(ordered.Person{ID: "u"}))
	if got.Ack {
		t.Fatal("ack needs read")
	}
	if r := wantVerdict(t, "ack", got.AckVerdict, RaciVerdictCodeRequiresRead); r != nil {
		t.Fatalf("a failed requirement carries no rule: %+v", r)
	}
}

func TestVerdictEveryActionHasOne(t *testing.T) {
	got := decisionsToGQL(oneLevel(nil).decide(ordered.Person{}))
	for label, v := range map[string]*RaciVerdictReason{"read": got.ReadVerdict, "ack": got.AckVerdict, "approve": got.ApproveVerdict, "author": got.AuthorVerdict, "manage": got.ManageVerdict} {
		if v == nil {
			t.Fatalf("%s: a verdict is required on every action", label)
		}
	}
}
