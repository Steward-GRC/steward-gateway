// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// manageEnv is a category "c" with the given rows and owners, and users
// known to identity.
func manageEnv(rules []*corev1.CategoryRule, owners []string, users ...*identityv1.User) *resolvers.Resolver {
	um := map[string]*identityv1.User{}
	for _, u := range users {
		um[u.Id] = u
	}
	return &resolvers.Resolver{
		CategoryClient: &raciCategoryClient{
			groups:   map[string]*corev1.Category{"c": {Id: "c", Name: "Cat", Owners: owners}},
			rulesets: map[string][]*corev1.CategoryRule{"c": rules},
		},
		IdentityClient: &raciIdentityClient{users: um, idpGroups: map[string][]string{}},
	}
}

func userRule(id string) *corev1.CategoryRule {
	return &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER, SubjectRef: id}
}

func TestSimulateCategory_ManageColumn(t *testing.T) {
	m := userRule("mgr")
	m.Manage = corev1.GrantEffect_GRANT_EFFECT_ALLOW
	r := manageEnv([]*corev1.CategoryRule{m}, nil, &identityv1.User{Id: "mgr"}, &identityv1.User{Id: "other"})
	ctx := ctxWithRoles(t, "admin", []string{"site-admin"})

	d, err := resolvers.SimulateCategoryResolver(ctx, r, "c", "mgr", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Manage || !d.Read || !d.Author || d.Approve || d.Ack {
		t.Fatalf("Manage gives Read and Author, not Approve or Ack: %+v", d)
	}
	if d.ManageCode != resolvers.RaciReasonCodeEntry || d.ReadCode != resolvers.RaciReasonCodeEntry || d.ApproveCode != resolvers.RaciReasonCodeDefaultDeny {
		t.Fatalf("codes = manage %v read %v approve %v", d.ManageCode, d.ReadCode, d.ApproveCode)
	}
	if !strings.Contains(d.ManageReason, "user mgr") {
		t.Fatalf("manageReason = %q", d.ManageReason)
	}
	d, err = resolvers.SimulateCategoryResolver(ctx, r, "c", "other", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Manage || d.Read {
		t.Fatalf("a person with no row has nothing: %+v", d)
	}
}

func TestSimulateCategory_DraftCarriesManage(t *testing.T) {
	r := manageEnv(nil, nil, &identityv1.User{Id: "u"})
	draft := []*resolvers.RaciRuleInput{{
		SubjectKind: resolvers.RaciSubjectKindUser, SubjectRef: "u",
		Read: resolvers.RaciGrantBlank, Author: resolvers.RaciGrantBlank, Approve: resolvers.RaciGrantBlank,
		Manage: resolvers.RaciGrantAllow, Ack: resolvers.RaciGrantBlank,
	}}
	d, err := resolvers.SimulateCategoryResolver(ctxWithRoles(t, "admin", []string{"site-admin"}), r, "c", "u", "", draft)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Manage || !d.Read || !d.Author {
		t.Fatalf("a draft Manage allow must decide: %+v", d)
	}
}

// A deny configured for root is stored and shown as blocked, never applied; a
// site admin who is not root follows the same deny.
func TestSimulateCategory_RootDenyIsBlockedNotApplied(t *testing.T) {
	deny := userRule("root-u")
	deny.Read = corev1.GrantEffect_GRANT_EFFECT_DENY
	deny.Manage = corev1.GrantEffect_GRANT_EFFECT_DENY
	everyoneDeny := userRule("plain-admin")
	everyoneDeny.Read = corev1.GrantEffect_GRANT_EFFECT_DENY
	r := manageEnv([]*corev1.CategoryRule{deny, everyoneDeny}, nil,
		&identityv1.User{Id: "root-u", IsRoot: true, Roles: []string{"site-admin"}},
		&identityv1.User{Id: "plain-admin", Roles: []string{"site-admin"}},
	)
	ctx := ctxWithRoles(t, "admin", []string{"site-admin"})

	d, err := resolvers.SimulateCategoryResolver(ctx, r, "c", "root-u", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Read || !d.Manage || !d.Author {
		t.Fatalf("root stays allowed over its own deny: %+v", d)
	}
	if d.Approve {
		t.Fatalf("root's Approve follows the rows and nothing allows it: %+v", d)
	}
	if d.Ack {
		t.Fatalf("root's Ack follows the rule, and nothing allows it: %+v", d)
	}
	if d.ReadCode != resolvers.RaciReasonCodeRoot || !strings.HasPrefix(d.ReadReason, "blocked:") {
		t.Fatalf("read = %v %q, want ROOT and a blocked reason", d.ReadCode, d.ReadReason)
	}
	if len(d.ConfiguredBlock) != 2 || d.ConfiguredBlock[0].Action != resolvers.RaciActionRead || d.ConfiguredBlock[1].Action != resolvers.RaciActionManage ||
		d.ConfiguredBlock[0].SubjectRef != "root-u" || d.ConfiguredBlock[0].SubjectKind != resolvers.RaciSubjectKindUser || d.ConfiguredBlock[0].CategoryID != "c" {
		t.Fatalf("configuredBlock = %+v", d.ConfiguredBlock)
	}

	a, err := resolvers.SimulateCategoryResolver(ctx, r, "c", "plain-admin", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Read || len(a.ConfiguredBlock) != 0 {
		t.Fatalf("a non-root site admin follows the deny and has nothing blocked: %+v", a)
	}
}

func TestSimulateCategory_DefaultEveryoneRead(t *testing.T) {
	ev := &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE, Read: corev1.GrantEffect_GRANT_EFFECT_ALLOW}
	r := manageEnv([]*corev1.CategoryRule{ev}, nil, &identityv1.User{Id: "u", Roles: []string{"site-admin"}})
	d, err := resolvers.SimulateCategoryResolver(ctxWithRoles(t, "admin", []string{"site-admin"}), r, "c", "u", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Read || d.Author || d.Approve || d.Manage || d.Ack {
		t.Fatalf("a new category's Everyone: Read gives every person, a site admin too, Read only: %+v", d)
	}
}

// Manage is stored and read back through the core calls, all five cells.
func TestSetCategoryRuleset_PersistsManageRoundTrip(t *testing.T) {
	gc := &raciCategoryClient{groups: map[string]*corev1.Category{"c": {Id: "c"}}, rulesets: map[string][]*corev1.CategoryRule{}}
	in := []*resolvers.RaciRuleInput{{
		SubjectKind: resolvers.RaciSubjectKindGroup, SubjectRef: "IT",
		Read: resolvers.RaciGrantAllow, Author: resolvers.RaciGrantDeny, Approve: resolvers.RaciGrantBlank,
		Manage: resolvers.RaciGrantAllow, Ack: resolvers.RaciGrantDeny,
	}}
	ctx := ctxWithRoles(t, "admin", []string{"site-admin"})
	out, err := resolvers.SetCategoryRulesetResolver(ctx, gc, "c", in)
	if err != nil {
		t.Fatal(err)
	}
	sent := gc.rulesets["c"]
	if len(sent) != 1 || sent[0].GetManage() != corev1.GrantEffect_GRANT_EFFECT_ALLOW || sent[0].GetRead() != corev1.GrantEffect_GRANT_EFFECT_ALLOW ||
		sent[0].GetAuthor() != corev1.GrantEffect_GRANT_EFFECT_DENY || sent[0].GetAck() != corev1.GrantEffect_GRANT_EFFECT_DENY ||
		sent[0].GetApprove() != corev1.GrantEffect_GRANT_EFFECT_UNSPECIFIED {
		t.Fatalf("core received %v, want all five cells with Manage allowed", sent)
	}
	if out.Rules[0].Manage != resolvers.RaciGrantAllow {
		t.Fatalf("response manage = %v", out.Rules[0].Manage)
	}
	back, err := resolvers.GetCategoryRulesetResolver(ctx, gc, "c")
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Rules[0]; got.Manage != resolvers.RaciGrantAllow || got.Author != resolvers.RaciGrantDeny || got.Ack != resolvers.RaciGrantDeny || got.Approve != resolvers.RaciGrantBlank {
		t.Fatalf("read back %+v", got)
	}
}

// Manage does not let anyone edit the rules or the governance; that stays with
// the global admin.
func TestManageDoesNotGateRulesOrGovernance(t *testing.T) {
	gc := &raciCategoryClient{groups: map[string]*corev1.Category{"c": {Id: "c"}}, rulesets: map[string][]*corev1.CategoryRule{}}
	manager := ctxWithStubClaims(t, principal.Static{UserIDValue: "mgr", RolesValue: []string{"reader"}})
	if _, err := resolvers.SetCategoryRulesetResolver(manager, gc, "c", nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("setCategoryRuleset by a Manage holder = %v, want PermissionDenied", err)
	}
	if _, err := resolvers.SetCategoryGovernance(manager, gc, ownerIdentity("mgr"), "c", []string{"mgr"}, nil, nil, resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("setCategoryGovernance by a Manage holder = %v, want PermissionDenied", err)
	}
}

func TestSetCategoryGovernance_OwnersArePeopleOnly(t *testing.T) {
	ctx := ctxWithRoles(t, "admin", []string{"site-admin"})
	for _, tc := range []struct {
		name  string
		owner string
	}{
		{"a group", "group:Contractors"},
		{"everyone", "everyone:*"},
		{"an empty id", ""},
		{"an id identity does not know", "ghost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeCategoryClient{groups: map[string]*corev1.Category{"g": {Id: "g", Name: "G"}}}
			_, err := resolvers.SetCategoryGovernance(ctx, client, ownerIdentity("u1"), "g", []string{"u1", tc.owner}, nil, nil, resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("owner %q: err = %v, want InvalidArgument", tc.owner, err)
			}
			if client.lastGovernance != nil {
				t.Fatalf("owner %q reached core: %v", tc.owner, client.lastGovernance)
			}
		})
	}

	t.Run("people are stored as user ids", func(t *testing.T) {
		client := &fakeCategoryClient{groups: map[string]*corev1.Category{"g": {Id: "g", Name: "G"}}}
		_, err := resolvers.SetCategoryGovernance(ctx, client, ownerIdentity("u1", "u2"), "g", []string{"u1", "u2", "u1"}, nil, nil, resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := client.lastGovernance.GetOwners(); len(got) != 3 || got[0] != "u1" || got[1] != "u2" {
			t.Fatalf("owners sent = %v", got)
		}
	})

	t.Run("no owners needs no identity", func(t *testing.T) {
		client := &fakeCategoryClient{groups: map[string]*corev1.Category{"g": {Id: "g", Name: "G"}}}
		if _, err := resolvers.SetCategoryGovernance(ctx, client, nil, "g", []string{}, nil, nil, resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("identity down is not read as a person", func(t *testing.T) {
		client := &fakeCategoryClient{groups: map[string]*corev1.Category{"g": {Id: "g", Name: "G"}}}
		if _, err := resolvers.SetCategoryGovernance(ctx, client, nil, "g", []string{"u1"}, nil, nil, resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil); status.Code(err) != codes.Unavailable {
			t.Fatalf("err = %v, want Unavailable", err)
		}
	})
}

// The approver pool is the owners plus everyone whose Approve is allowed,
// owners first. Root is in it only through a row (here Everyone: Approve).
func TestCategoryApprovers_OwnersThenRows(t *testing.T) {
	appr := userRule("approver")
	appr.Approve = corev1.GrantEffect_GRANT_EFFECT_ALLOW
	denied := userRule("denied")
	denied.Approve = corev1.GrantEffect_GRANT_EFFECT_DENY
	everyone := &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE, Approve: corev1.GrantEffect_GRANT_EFFECT_ALLOW}
	r := manageEnv([]*corev1.CategoryRule{denied, appr, everyone}, []string{"owner"})
	ic := r.IdentityClient.(*raciIdentityClient)
	for _, id := range []string{"approver", "denied", "owner", "bystander", "the-root"} {
		ic.users[id] = &identityv1.User{Id: id}
	}
	ic.users["the-root"].IsRoot = true
	ic.allUsers = []*identityv1.User{ic.users["bystander"], ic.users["denied"], ic.users["approver"], ic.users["owner"], ic.users["the-root"]}

	got, err := resolvers.CategoryApproversResolver(ctxWithRoles(t, "admin", []string{"site-admin"}), r, "c")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, u := range got {
		ids = append(ids, u.UserID)
	}
	want := []string{"owner", "bystander", "approver", "the-root"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("pool = %v, want %v (the denied person is out; Everyone: Approve brings in the rest)", ids, want)
	}
}

// viewerCan carries manage, from a Manage row, an owner or root.
func TestGetPolicy_ViewerCanManage(t *testing.T) {
	m := userRule("mgr")
	m.Manage = corev1.GrantEffect_GRANT_EFFECT_ALLOW
	ev := allowEveryoneRule()
	groups := newRaciReadClient(
		map[string]*corev1.Category{"g": {Id: "g", Name: "G", Owners: []string{"own"}}},
		map[string][]*corev1.CategoryRule{"g": {m, ev}},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"p": {Id: "p", HomeCategoryId: "g", Number: "P-1", Title: "T", CurrentPublishedVersionId: "p-v1"},
	}}
	for _, tc := range []struct {
		name string
		c    principal.Static
		want bool
	}{
		{"a Manage row", principal.Static{UserIDValue: "mgr"}, true},
		{"an owner", principal.Static{UserIDValue: "own"}, true},
		{"root", principal.Static{UserIDValue: "r", RolesValue: []string{"site-admin"}, IsRootValue: true}, true},
		{"a plain reader", principal.Static{UserIDValue: "x"}, false},
		{"a non-root site admin", principal.Static{UserIDValue: "sa", RolesValue: []string{"site-admin"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := resolvers.GetPolicy(ctxWithStubClaims(t, tc.c), pc, groups, nil, nil, nil, "p")
			if err != nil {
				t.Fatal(err)
			}
			if p.ViewerCan.Manage != tc.want {
				t.Fatalf("viewerCan.manage = %v, want %v (%+v)", p.ViewerCan.Manage, tc.want, p.ViewerCan)
			}
		})
	}
}

// A site admin who is not root follows the rules at the write gates too: with
// no Author row for them they are refused, and with one they are let in.
func TestNonRootSiteAdminFollowsTheRulesAtTheWriteGates(t *testing.T) {
	admin := principal.Static{UserIDValue: "sa", RolesValue: []string{"site-admin"}}
	cases := []struct {
		name      string
		rules     []*corev1.CategoryRule
		wantAllow bool
	}{
		{"no row for them", []*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)}, false},
		{"an Author deny", []*corev1.CategoryRule{authorRule("sa", corev1.GrantEffect_GRANT_EFFECT_DENY)}, false},
		{"an Author row", []*corev1.CategoryRule{authorRule("sa", corev1.GrantEffect_GRANT_EFFECT_ALLOW)}, true},
		{"a Manage row", []*corev1.CategoryRule{func() *corev1.CategoryRule {
			r := userRule("sa")
			r.Manage = corev1.GrantEffect_GRANT_EFFECT_ALLOW
			return r
		}()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, gc := coAuthMatrixEnv("creator-other", nil, tc.rules)
			ctx := ctxWithStubClaims(t, admin)

			_, saveErr := resolvers.SaveDraft(ctx, pc, gc, "pol", `{"root":{}}`, "")
			_, createErr := resolvers.CreatePolicy(ctx, pc, gc, "g-cat", "T", resolvers.SensitivityStandard, nil, nil)
			for op, err := range map[string]error{"SaveDraft": saveErr, "CreatePolicy": createErr} {
				if tc.wantAllow && err != nil {
					t.Fatalf("%s: %v, want allowed", op, err)
				}
				if !tc.wantAllow && status.Code(err) != codes.PermissionDenied {
					t.Fatalf("%s: %v, want PermissionDenied", op, err)
				}
			}
		})
	}
}

// Root is not in any approver pool by being root: with no Approve row for it, it
// is out; an Approve row, or owning the category, brings it in.
func TestCategoryApprovers_RootOnlyThroughARowOrOwnership(t *testing.T) {
	appr := userRule("approver")
	appr.Approve = corev1.GrantEffect_GRANT_EFFECT_ALLOW
	rootRow := userRule("the-root")
	rootRow.Approve = corev1.GrantEffect_GRANT_EFFECT_ALLOW
	cases := []struct {
		name   string
		rules  []*corev1.CategoryRule
		owners []string
		want   string
	}{
		{"no row for root", []*corev1.CategoryRule{appr}, nil, "approver"},
		{"an approve row for root", []*corev1.CategoryRule{appr, rootRow}, nil, "approver,the-root"},
		{"root owns the category", []*corev1.CategoryRule{appr}, []string{"the-root"}, "the-root,approver"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := manageEnv(tc.rules, tc.owners)
			ic := r.IdentityClient.(*raciIdentityClient)
			ic.users["approver"] = &identityv1.User{Id: "approver"}
			ic.users["the-root"] = &identityv1.User{Id: "the-root", IsRoot: true, Roles: []string{"site-admin"}}
			ic.allUsers = []*identityv1.User{ic.users["approver"], ic.users["the-root"]}
			got, err := resolvers.CategoryApproversResolver(ctxWithRoles(t, "admin", []string{"site-admin"}), r, "c")
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, u := range got {
				ids = append(ids, u.UserID)
			}
			if strings.Join(ids, ",") != tc.want {
				t.Fatalf("pool = %v, want %s", ids, tc.want)
			}
		})
	}
}

// viewerIsApprover follows the rows for root as for anyone.
func TestViewerIsApprover_RootFollowsTheRows(t *testing.T) {
	root := principal.Static{UserIDValue: "the-root", RolesValue: []string{"site-admin"}, IsRootValue: true}
	for _, tc := range []struct {
		name   string
		rules  []*corev1.CategoryRule
		owners []string
		want   bool
	}{
		{"no approve cell", []*corev1.CategoryRule{userRule("someone")}, nil, false},
		{"an approve row", func() []*corev1.CategoryRule {
			r := userRule("the-root")
			r.Approve = corev1.GrantEffect_GRANT_EFFECT_ALLOW
			return []*corev1.CategoryRule{r}
		}(), nil, true},
		{"owner", nil, []string{"the-root"}, true},
		{"approve denied", func() []*corev1.CategoryRule {
			r := userRule("the-root")
			r.Approve = corev1.GrantEffect_GRANT_EFFECT_DENY
			return []*corev1.CategoryRule{r}
		}(), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := manageEnv(tc.rules, tc.owners)
			got, err := resolvers.ViewerIsApproverResolver(ctxWithStubClaims(t, root), log.Nop(),
				topLevelLister{r.CategoryClient.(*raciCategoryClient)})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("viewerIsApprover = %v, want %v", got, tc.want)
			}
		})
	}
}

// The simulator for root: a deny of read, author or manage is allowed with the
// ROOT code and a configuredBlock entry; a deny of approve or ack applies.
func TestSimulateCategory_RootApproveAndAckDenyApply(t *testing.T) {
	deny := userRule("root-u")
	deny.Read, deny.Author, deny.Manage = corev1.GrantEffect_GRANT_EFFECT_DENY, corev1.GrantEffect_GRANT_EFFECT_DENY, corev1.GrantEffect_GRANT_EFFECT_DENY
	deny.Approve, deny.Ack = corev1.GrantEffect_GRANT_EFFECT_DENY, corev1.GrantEffect_GRANT_EFFECT_DENY
	every := &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE,
		Read: corev1.GrantEffect_GRANT_EFFECT_ALLOW, Approve: corev1.GrantEffect_GRANT_EFFECT_ALLOW, Ack: corev1.GrantEffect_GRANT_EFFECT_ALLOW}
	r := manageEnv([]*corev1.CategoryRule{deny, every}, nil,
		&identityv1.User{Id: "root-u", IsRoot: true, Roles: []string{"site-admin"}})
	d, err := resolvers.SimulateCategoryResolver(ctxWithRoles(t, "admin", []string{"site-admin"}), r, "c", "root-u", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Read || !d.Author || !d.Manage {
		t.Fatalf("read, author and manage stay allowed: %+v", d)
	}
	if d.ReadCode != resolvers.RaciReasonCodeRoot || d.AuthorCode != resolvers.RaciReasonCodeRoot || d.ManageCode != resolvers.RaciReasonCodeRoot {
		t.Fatalf("codes = %v %v %v, want ROOT", d.ReadCode, d.AuthorCode, d.ManageCode)
	}
	if len(d.ConfiguredBlock) != 3 {
		t.Fatalf("configuredBlock = %+v, want read, author and manage only", d.ConfiguredBlock)
	}
	for _, b := range d.ConfiguredBlock {
		if b.Action == resolvers.RaciActionApprove || b.Action == resolvers.RaciActionAck {
			t.Fatalf("approve and ack denies apply and are not blocked: %+v", d.ConfiguredBlock)
		}
	}
	if d.Approve || d.Ack {
		t.Fatalf("a deny of approve or ack applies to root: %+v", d)
	}
}

// topLevelLister lists the one category "c" under the top level, so the
// approver walk has something to visit.
type topLevelLister struct{ *raciCategoryClient }

func (topLevelLister) ListCategoryChildren(_ context.Context, in *corev1.ListCategoryChildrenRequest, _ ...grpc.CallOption) (*corev1.ListCategoryChildrenResponse, error) {
	if in.GetParentId() != "" {
		return &corev1.ListCategoryChildrenResponse{}, nil
	}
	return &corev1.ListCategoryChildrenResponse{Categories: []*corev1.Category{{Id: "c", Name: "Cat"}}}, nil
}
