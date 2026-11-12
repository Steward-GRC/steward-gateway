// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Bugs5382/go-authz/ordered"
	authz "github.com/Steward-GRC/steward-authz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// The mapping layer: a rule row is a GraphQL RaciRule, a core CategoryRule and
// engine ordered.Entry cells, and must survive every hop with all five actions.

var allActions = []string{actRead, actAuthor, actApprove, actManage, actAck}

// inputWith sets one action's cell on an otherwise blank user row.
func inputWith(action string, g RaciGrant) *RaciRuleInput {
	in := &RaciRuleInput{
		SubjectKind: RaciSubjectKindUser, SubjectRef: "u1",
		Read: RaciGrantBlank, Author: RaciGrantBlank, Approve: RaciGrantBlank, Manage: RaciGrantBlank, Ack: RaciGrantBlank,
	}
	switch action {
	case actRead:
		in.Read = g
	case actAuthor:
		in.Author = g
	case actApprove:
		in.Approve = g
	case actManage:
		in.Manage = g
	case actAck:
		in.Ack = g
	}
	return in
}

func TestRuleMappingEveryActionRoundTrips(t *testing.T) {
	for _, action := range allActions {
		for _, tc := range []struct {
			g   RaciGrant
			eff ordered.Effect
		}{{RaciGrantAllow, ordered.Allow}, {RaciGrantDeny, ordered.Deny}} {
			t.Run(action+"/"+string(tc.g), func(t *testing.T) {
				in := inputWith(action, tc.g)
				proto := ruleInputToProto(in)

				entries := ruleEntries(proto)
				want := []ordered.Entry{{Subject: "user:u1", Action: action, Effect: tc.eff}}
				if !reflect.DeepEqual(entries, want) {
					t.Fatalf("entries = %+v, want %+v", entries, want)
				}
				// Back from entries to the stored row, then to GraphQL.
				if back := rulesFromEntries(entries); len(back) != 1 || !reflect.DeepEqual(back[0].String(), proto.String()) {
					t.Fatalf("rulesFromEntries = %v, want %v", back, proto)
				}
				gql := ruleProtoToGQL(proto)
				if gql.Read != in.Read || gql.Author != in.Author || gql.Approve != in.Approve || gql.Manage != in.Manage || gql.Ack != in.Ack {
					t.Fatalf("GraphQL round trip = %+v, want the input cells %+v", gql, in)
				}
			})
		}
	}
}

func TestRuleMappingBlankCellsHaveNoEntry(t *testing.T) {
	in := inputWith(actRead, RaciGrantBlank)
	if got := ruleEntries(ruleInputToProto(in)); len(got) != 0 {
		t.Fatalf("a blank row has entries %+v", got)
	}
}

func TestRuleMappingFullRowKeepsFiveCells(t *testing.T) {
	in := &RaciRuleInput{
		SubjectKind: RaciSubjectKindGroup, SubjectRef: "IT",
		Read: RaciGrantAllow, Author: RaciGrantDeny, Approve: RaciGrantAllow, Manage: RaciGrantDeny, Ack: RaciGrantAllow,
	}
	got := ruleEntries(ruleInputToProto(in))
	want := []ordered.Entry{
		{Subject: "group:IT", Action: actRead, Effect: ordered.Allow},
		{Subject: "group:IT", Action: actAuthor, Effect: ordered.Deny},
		{Subject: "group:IT", Action: actApprove, Effect: ordered.Allow},
		{Subject: "group:IT", Action: actManage, Effect: ordered.Deny},
		{Subject: "group:IT", Action: actAck, Effect: ordered.Allow},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries = %+v, want %+v", got, want)
	}
}

func TestRuleMappingSubjects(t *testing.T) {
	ev := ruleInputToProto(&RaciRuleInput{SubjectKind: RaciSubjectKindEveryone, SubjectRef: "ignored", Read: RaciGrantAllow})
	if ev.GetSubjectRef() != "" {
		t.Fatalf("Everyone keeps ref %q, want none", ev.GetSubjectRef())
	}
	if e := ruleEntries(ev); len(e) != 1 || e[0].Subject != ordered.Everyone {
		t.Fatalf("Everyone entries = %+v", e)
	}
	if got := ruleProtoToGQL(ev).SubjectKind; got != RaciSubjectKindEveryone {
		t.Fatalf("kind = %v", got)
	}
}

func TestRulesFromEntriesGroupsRowsByFirstAppearance(t *testing.T) {
	rows := rulesFromEntries([]ordered.Entry{
		{Subject: "group:b", Action: actRead, Effect: ordered.Deny},
		{Subject: ordered.Everyone, Action: actRead, Effect: ordered.Allow},
		{Subject: "group:b", Action: actManage, Effect: ordered.Allow},
	})
	if len(rows) != 2 || rows[0].GetSubjectRef() != "b" || rows[0].GetManage() != corev1.GrantEffect_GRANT_EFFECT_ALLOW ||
		rows[0].GetRead() != corev1.GrantEffect_GRANT_EFFECT_DENY || rows[1].GetSubjectKind() != corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE {
		t.Fatalf("rows = %v", rows)
	}
}

// The shared vectors, run through the gateway's mapping: every rule row goes to
// core's shape and back through newCategoryAccess before the engine sees it.

type vectorFile struct {
	Options struct {
		Superusers *ordered.Superusers `json:"superusers"`
	} `json:"options"`
	Cases []struct {
		Name     string          `json:"name"`
		RuleSet  ordered.RuleSet `json:"ruleSet"`
		Person   ordered.Person  `json:"person"`
		Category string          `json:"category"`
		Action   string          `json:"action"`
		Expect   struct {
			Allowed         bool           `json:"allowed"`
			Reason          string         `json:"reason"`
			DecidedBy       *ordered.Entry `json:"decidedBy"`
			GatedBy         string         `json:"gatedBy"`
			ConfiguredBlock *ordered.Entry `json:"configuredBlock"`
		} `json:"expect"`
	} `json:"cases"`
	Pools []struct {
		Name     string              `json:"name"`
		RuleSet  ordered.RuleSet     `json:"ruleSet"`
		People   []ordered.Person    `json:"people"`
		Category string              `json:"category"`
		Action   string              `json:"action"`
		Expect   []ordered.PoolEntry `json:"expect"`
	} `json:"pools"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/ordered.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var v vectorFile
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// representable reports whether every subject of the rule set is one a core
// rule can hold: a user, a group or Everyone.
func representable(rs ordered.RuleSet) bool {
	for _, c := range rs.Categories {
		for _, e := range c.Entries {
			if e.Subject != ordered.Everyone && !strings.HasPrefix(e.Subject, "user:") && !strings.HasPrefix(e.Subject, "group:") {
				return false
			}
		}
	}
	return true
}

// levelsFor is what core's GetEffectiveRuleset returns for the category: the
// chain nearest first, never revisiting a category, rows and owners as stored.
func levelsFor(rs ordered.RuleSet, category string) []*corev1.EffectiveLevel {
	var out []*corev1.EffectiveLevel
	seen := map[string]bool{}
	for at, ok := category, true; ok && !seen[at]; at, ok = rs.Parents[at] {
		seen[at] = true
		c := rs.Categories[at]
		owners := make([]string, 0, len(c.Owners))
		for _, o := range c.Owners {
			owners = append(owners, strings.TrimPrefix(o, "user:"))
		}
		out = append(out, &corev1.EffectiveLevel{CategoryId: at, Name: at, Owners: owners, Rules: rulesFromEntries(c.Entries)})
	}
	return out
}

func TestOrderedVectorsThroughTheMapping(t *testing.T) {
	v := loadVectors(t)
	if !reflect.DeepEqual(v.Options.Superusers, accessModel().Superusers) {
		t.Fatalf("the vectors' superuser seat %+v differs from the gateway's %+v", v.Options.Superusers, accessModel().Superusers)
	}
	ran, skipped := 0, 0
	for _, c := range v.Cases {
		if !representable(c.RuleSet) {
			skipped++
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			access := newCategoryAccess(levelsFor(c.RuleSet, c.Category))
			d := accessModel().Decide(access.rs, c.Person, access.leaf, c.Action)
			if d.Allowed != c.Expect.Allowed || d.Reason != c.Expect.Reason || d.GatedBy != c.Expect.GatedBy {
				t.Fatalf("decision = %+v, want allowed=%v reason=%q gatedBy=%q", d, c.Expect.Allowed, c.Expect.Reason, c.Expect.GatedBy)
			}
			if !reflect.DeepEqual(d.DecidedBy, c.Expect.DecidedBy) {
				t.Fatalf("decidedBy = %+v, want %+v", d.DecidedBy, c.Expect.DecidedBy)
			}
			if !reflect.DeepEqual(d.ConfiguredBlock, c.Expect.ConfiguredBlock) {
				t.Fatalf("configuredBlock = %+v, want %+v", d.ConfiguredBlock, c.Expect.ConfiguredBlock)
			}
		})
	}
	t.Logf("vector cases run through the mapping: %d of %d (%d use a subject core cannot hold)", ran, len(v.Cases), skipped)
	// The ten left out name a role or a capability matcher in a row, which core
	// cannot store (a row is a user, a group or Everyone); the engine's own
	// tests run them.
	if ran != 59 || skipped != 10 {
		t.Fatalf("ran %d and skipped %d vector cases, want 59 and 10", ran, skipped)
	}
}

func TestOrderedPoolVectorsThroughTheMapping(t *testing.T) {
	v := loadVectors(t)
	ran := 0
	defer func() { t.Logf("pool vectors run through the mapping: %d of %d", ran, len(v.Pools)) }()
	for _, p := range v.Pools {
		if !representable(p.RuleSet) {
			continue
		}
		ran++
		t.Run(p.Name, func(t *testing.T) {
			access := newCategoryAccess(levelsFor(p.RuleSet, p.Category))
			got := access.pool(p.People, p.Action)
			if !reflect.DeepEqual(got, p.Expect) {
				t.Fatalf("pool = %+v, want %+v", got, p.Expect)
			}
		})
	}
}

// Gateway-level behaviour, with rows built the way core stores them.

func userRow(id string) *corev1.CategoryRule {
	return &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER, SubjectRef: id}
}

func everyoneRow() *corev1.CategoryRule {
	return &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE}
}

const (
	allowEffect = corev1.GrantEffect_GRANT_EFFECT_ALLOW
	denyEffect  = corev1.GrantEffect_GRANT_EFFECT_DENY
)

func oneLevel(owners []string, rules ...*corev1.CategoryRule) *categoryAccess {
	return newCategoryAccess([]*corev1.EffectiveLevel{{CategoryId: "c", Name: "Cat", Owners: owners, Rules: rules}})
}

func TestStrictPerAction(t *testing.T) {
	deny := userRow("u")
	deny.Manage = denyEffect
	allow := everyoneRow()
	allow.Read, allow.Author = allowEffect, allowEffect
	d := oneLevel(nil, deny, allow).decide(ordered.Person{ID: "u"})
	if !d.Read.Allowed || !d.Author.Allowed {
		t.Fatalf("a red Manage row must not deny Read or Author: read=%+v author=%+v", d.Read, d.Author)
	}
	if d.Manage.Allowed {
		t.Fatalf("the red Manage row must deny Manage: %+v", d.Manage)
	}
}

func TestManageImpliesReadAndAuthorOnly(t *testing.T) {
	row := userRow("u")
	row.Manage = allowEffect
	deny := userRow("u")
	deny.Read, deny.Author, deny.Approve, deny.Ack = denyEffect, denyEffect, denyEffect, allowEffect
	d := oneLevel(nil, row, deny).decide(ordered.Person{ID: "u"})
	if !d.Manage.Allowed || !d.Read.Allowed || !d.Author.Allowed {
		t.Fatalf("Manage must give Read and Author over their denies: %+v", d)
	}
	if d.Approve.Allowed {
		t.Fatalf("Manage must not give Approve: %+v", d.Approve)
	}
}

func TestNonRootSiteAdminFollowsADeny(t *testing.T) {
	deny := everyoneRow()
	deny.Read = denyEffect
	access := oneLevel(nil, deny)
	subj := authz.Subject{UserID: "admin", Roles: []authz.Role{authz.RoleSiteAdmin}}
	if access.decide(personFromSubject(subj)).Read.Allowed {
		t.Fatal("a site admin who is not root must follow the Read deny")
	}
	root := subj
	root.Root = true
	d := access.decide(personFromSubject(root))
	if !d.Read.Allowed || d.Read.Reason != ordered.ReasonSuperuser {
		t.Fatalf("root must read over the deny: %+v", d.Read)
	}
	if d.Read.ConfiguredBlock == nil {
		t.Fatal("the deny that root ignores must be reported")
	}
}

func TestRootIsExemptExceptForAck(t *testing.T) {
	ackDeny := everyoneRow()
	ackDeny.Read, ackDeny.Ack = allowEffect, denyEffect
	d := oneLevel(nil, ackDeny).decide(personFromSubject(authz.Subject{UserID: "r", Root: true}))
	if !d.Read.Allowed || !d.Author.Allowed || !d.Approve.Allowed || !d.Manage.Allowed {
		t.Fatalf("root must hold Read, Author, Approve and Manage: %+v", d)
	}
	if d.Ack.Allowed {
		t.Fatal("root's Ack follows the rule: a deny must apply")
	}
	if d.AckUngated {
		t.Fatal("the ungated Ack is the rule alone: a deny still applies")
	}
}

func TestOwnersAreImmuneToADenyAndDoNotAck(t *testing.T) {
	deny := everyoneRow()
	deny.Read, deny.Author, deny.Approve, deny.Manage, deny.Ack = denyEffect, denyEffect, denyEffect, denyEffect, denyEffect
	d := oneLevel([]string{"o"}, deny).decide(ordered.Person{ID: "o"})
	if !d.Read.Allowed || !d.Author.Allowed || !d.Approve.Allowed || !d.Manage.Allowed {
		t.Fatalf("an owner holds Read, Author, Approve and Manage over a deny: %+v", d)
	}
	if d.Ack.Allowed {
		t.Fatal("an owner is not given Ack")
	}
}

func TestOwnersAreInheritedAndPeopleOnly(t *testing.T) {
	a := newCategoryAccess([]*corev1.EffectiveLevel{
		{CategoryId: "child", Name: "Child"},
		{CategoryId: "top", Name: "Top", Owners: []string{"o1", "o2"}},
	})
	if !a.decide(ordered.Person{ID: "o2"}).Manage.Allowed {
		t.Fatal("an owner of the top category owns the child")
	}
	if a.decide(ordered.Person{ID: "stranger", Groups: []string{"o1"}}).Manage.Allowed {
		t.Fatal("a group named like an owner is not an owner")
	}
}

func TestDefaultNewCategoryIsEveryoneRead(t *testing.T) {
	row := everyoneRow()
	row.Read = allowEffect
	d := oneLevel(nil, row).decide(ordered.Person{ID: "anyone"})
	if !d.Read.Allowed || d.Author.Allowed || d.Approve.Allowed || d.Manage.Allowed {
		t.Fatalf("Everyone: Read allows Read only: %+v", d)
	}
	if d.Ack.Allowed {
		t.Fatal("Everyone: Read is not an Ack row")
	}
}

func TestChildRowsComeBeforeParentRows(t *testing.T) {
	childDeny := userRow("u")
	childDeny.Read = denyEffect
	parentAllow := everyoneRow()
	parentAllow.Read = allowEffect
	a := newCategoryAccess([]*corev1.EffectiveLevel{
		{CategoryId: "child", Name: "Child", Rules: []*corev1.CategoryRule{childDeny}},
		{CategoryId: "top", Name: "Top", Rules: []*corev1.CategoryRule{parentAllow}},
	})
	if a.decide(ordered.Person{ID: "u"}).Read.Allowed {
		t.Fatal("the child's own row wins over the inherited one")
	}
	if !a.decide(ordered.Person{ID: "v"}).Read.Allowed {
		t.Fatal("the inherited row decides when no child row speaks")
	}
}

func TestSimulatorDraftReplacesOnlyTheLeaf(t *testing.T) {
	parentAllow := everyoneRow()
	parentAllow.Read = allowEffect
	a := newCategoryAccess([]*corev1.EffectiveLevel{
		{CategoryId: "child", Name: "Child"},
		{CategoryId: "top", Name: "Top", Rules: []*corev1.CategoryRule{parentAllow}},
	})
	deny := userRow("u")
	deny.Read = denyEffect
	if a.withLeafRules([]*corev1.CategoryRule{deny}).decide(ordered.Person{ID: "u"}).Read.Allowed {
		t.Fatal("the draft row must apply")
	}
	if !a.decide(ordered.Person{ID: "u"}).Read.Allowed {
		t.Fatal("the stored rules must be left alone")
	}
}

func TestDecisionsToGQLReportsRootAsBlocked(t *testing.T) {
	deny := everyoneRow()
	deny.Read, deny.Manage = denyEffect, denyEffect
	d := oneLevel(nil, deny).decide(personFromSubject(authz.Subject{UserID: "r", Root: true}))
	got := decisionsToGQL(d)
	if !got.Read || !got.Manage {
		t.Fatalf("root stays allowed: %+v", got)
	}
	if got.ReadCode != RaciReasonCodeRoot || got.ManageCode != RaciReasonCodeRoot {
		t.Fatalf("codes = %v %v, want ROOT", got.ReadCode, got.ManageCode)
	}
	if len(got.ConfiguredBlock) != 2 || got.ConfiguredBlock[0].Action != RaciActionRead || got.ConfiguredBlock[1].Action != RaciActionManage ||
		got.ConfiguredBlock[0].SubjectKind != RaciSubjectKindEveryone || got.ConfiguredBlock[0].CategoryID != "c" {
		t.Fatalf("configuredBlock = %+v", got.ConfiguredBlock)
	}
	if !strings.HasPrefix(got.ReadReason, "blocked:") {
		t.Fatalf("reason = %q, want a blocked reason", got.ReadReason)
	}
}

func TestDecisionsToGQLCodes(t *testing.T) {
	row := userRow("u")
	row.Read = denyEffect
	row.Ack = allowEffect
	got := decisionsToGQL(oneLevel(nil, row).decide(ordered.Person{ID: "u"}))
	if got.ReadCode != RaciReasonCodeEntry || got.AuthorCode != RaciReasonCodeDefaultDeny || got.AckCode != RaciReasonCodeRequires {
		t.Fatalf("codes = read %v author %v ack %v", got.ReadCode, got.AuthorCode, got.AckCode)
	}
	if got.ConfiguredBlock == nil || len(got.ConfiguredBlock) != 0 {
		t.Fatalf("configuredBlock = %#v, want an empty list", got.ConfiguredBlock)
	}
	owner := decisionsToGQL(oneLevel([]string{"u"}).decide(ordered.Person{ID: "u"}))
	if owner.ReadCode != RaciReasonCodeOwner || owner.ManageCode != RaciReasonCodeOwner {
		t.Fatalf("owner codes = %v %v", owner.ReadCode, owner.ManageCode)
	}
}

// effectiveOnly answers GetEffectiveRuleset from fixed levels.
type effectiveOnly struct {
	corev1.CategoryServiceClient
	levels []*corev1.EffectiveLevel
	err    error
	calls  int
}

func (f *effectiveOnly) GetEffectiveRuleset(context.Context, *corev1.GetEffectiveRulesetRequest, ...grpc.CallOption) (*corev1.GetEffectiveRulesetResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &corev1.GetEffectiveRulesetResponse{Levels: f.levels}, nil
}

func TestLoadCategoryAccessIsOneCall(t *testing.T) {
	row := everyoneRow()
	row.Read = allowEffect
	f := &effectiveOnly{levels: []*corev1.EffectiveLevel{{CategoryId: "a"}, {CategoryId: "b"}, {CategoryId: "c", Rules: []*corev1.CategoryRule{row}}}}
	a, err := loadCategoryAccess(t.Context(), f, "a")
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 {
		t.Fatalf("GetEffectiveRuleset calls = %d, want one for the whole chain", f.calls)
	}
	if !a.decide(ordered.Person{ID: "x"}).Read.Allowed {
		t.Fatal("the grandparent's row must apply")
	}
}

func TestLoadCategoryAccessErrors(t *testing.T) {
	if _, err := loadCategoryAccess(t.Context(), &effectiveOnly{err: status.Error(codes.NotFound, "x")}, "a"); err == nil {
		t.Fatal("a core error must be returned, not read as no access")
	}
	if _, err := loadCategoryAccess(t.Context(), &effectiveOnly{}, "a"); err == nil {
		t.Fatal("an empty chain must be an error")
	}
}

func TestViewerCanManageAndStrippedSiteAdmin(t *testing.T) {
	manage := userRow("m")
	manage.Manage = allowEffect
	everyone := everyoneRow()
	everyone.Read = allowEffect
	access := oneLevel(nil, manage, everyone)
	res := authz.Resource{ID: "P-1", Category: "c"}

	decide := func(subj authz.Subject) *PolicyViewerCan {
		d := access.decide(personFromSubject(subj))
		raci := raciReadResult{effect: meritRACIReadEffect(subj, &Policy{Number: "P-1"}, d.Read.Allowed), action: d}
		return viewerCanFor(subj, res, raci.effect, raci, false, DocumentTypePolicy)
	}

	m := decide(authz.Subject{UserID: "m"})
	if !m.Manage || !m.Read || !m.Edit || !m.Submit || m.Approve {
		t.Fatalf("a Manage holder reads, edits and manages but does not approve: %+v", m)
	}
	reader := decide(authz.Subject{UserID: "x"})
	if reader.Manage || reader.Edit || !reader.Read {
		t.Fatalf("a reader neither manages nor edits: %+v", reader)
	}
	// A site admin who is not root has no rule for Author: no edit.
	admin := decide(authz.Subject{UserID: "a", Roles: []authz.Role{authz.RoleSiteAdmin}})
	if admin.Edit || admin.Manage {
		t.Fatalf("a non-root site admin follows the rules: %+v", admin)
	}
	root := decide(authz.Subject{UserID: "r", Root: true})
	if !root.Manage || !root.Edit || !root.Approve || !root.Read {
		t.Fatalf("root holds everything: %+v", root)
	}
}
