// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	"github.com/Bugs5382/go-authz/ordered"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// The category access model is go-authz's ordered engine: per top-level
// category, ordered rows (user, group or Everyone) with a cell per action,
// decided per action from the top, the category's own rows first and then each
// parent's. Core stores the rows and the owners and evaluates nothing; this
// file turns what core returns into an ordered.RuleSet and asks the engine.

// The five actions of the model, as the engine spells them.
const (
	actRead    = "read"
	actAuthor  = "author"
	actApprove = "approve"
	actManage  = "manage"
	actAck     = "ack"
)

// rootRole is the engine role of the one root seat. It comes from identity's
// is_root flag, never from a user name or id.
const rootRole = "root"

// accessActions lists the actions in the order the schema and the decision
// report them.
var accessActions = []string{actRead, actAuthor, actApprove, actManage, actAck}

// accessModel is the engine configuration: the five default actions (Manage
// implies Read and Author, Approve and Author imply Read, Ack requires Read,
// owners hold Read, Author, Approve and Manage but not Ack) and the root seat,
// exempt for Read, Author and Manage only: Approve and Ack follow the rows.
func accessModel() ordered.Model {
	m := ordered.DefaultModel()
	m.Superusers = &ordered.Superusers{
		Subjects: []string{"role:" + rootRole},
		Actions:  []string{actRead, actAuthor, actManage},
	}
	return m
}

// ackUngatedModel is accessModel with Ack's Read requirement lifted. It answers
// the acknowledge rule alone, for a document a per-document override allows
// the reader to open outside the rules.
func ackUngatedModel() ordered.Model {
	m := accessModel()
	acts := ordered.DefaultActions()
	for i := range acts {
		if acts[i].ID == actAck {
			acts[i].Requires = nil
		}
	}
	m.Actions = acts
	return m
}

// categoryAccess is one category's rules and its ancestors', ready to decide.
type categoryAccess struct {
	rs    ordered.RuleSet
	leaf  string
	names map[string]string // category id -> name, for reasons
	// lineage is the category names, the leaf first, then each parent.
	lineage []string
}

// loadCategoryAccess reads the category's whole chain in one call.
func loadCategoryAccess(ctx context.Context, client corev1.CategoryServiceClient, categoryID string) (*categoryAccess, error) {
	if categoryID == "" {
		// A document with no home category has no rules: nothing is allowed
		// but what root, being exempt, holds.
		return &categoryAccess{rs: ordered.RuleSet{Categories: map[string]ordered.Category{}, Parents: map[string]string{}}, names: map[string]string{}}, nil
	}
	resp, err := client.GetEffectiveRuleset(ctx, &corev1.GetEffectiveRulesetRequest{CategoryId: categoryID})
	if err != nil {
		return nil, fmt.Errorf("get effective ruleset %s: %w", categoryID, err)
	}
	if len(resp.GetLevels()) == 0 {
		return nil, fmt.Errorf("get effective ruleset %s: no levels", categoryID)
	}
	return newCategoryAccess(resp.GetLevels()), nil
}

// newCategoryAccess builds the rule set from the chain, nearest first. Owners
// are people: core stores their user ids and the engine matches "user:<id>".
func newCategoryAccess(levels []*corev1.EffectiveLevel) *categoryAccess {
	a := &categoryAccess{
		rs:    ordered.RuleSet{Categories: map[string]ordered.Category{}, Parents: map[string]string{}},
		leaf:  levels[0].GetCategoryId(),
		names: map[string]string{},
	}
	for i, l := range levels {
		id := l.GetCategoryId()
		owners := make([]string, 0, len(l.GetOwners()))
		for _, o := range l.GetOwners() {
			owners = append(owners, "user:"+o)
		}
		a.rs.Categories[id] = ordered.Category{Entries: rulesEntries(l.GetRules()), Owners: owners}
		a.names[id] = l.GetName()
		a.lineage = append(a.lineage, l.GetName())
		if i+1 < len(levels) {
			a.rs.Parents[id] = levels[i+1].GetCategoryId()
		}
	}
	return a
}

// withLeafRules is a copy that decides with rules in place of the category's
// own, for the simulator's draft. Ancestors and owners stay as stored.
func (a *categoryAccess) withLeafRules(rules []*corev1.CategoryRule) *categoryAccess {
	cats := make(map[string]ordered.Category, len(a.rs.Categories))
	for id, c := range a.rs.Categories {
		cats[id] = c
	}
	leaf := cats[a.leaf]
	leaf.Entries = rulesEntries(rules)
	cats[a.leaf] = leaf
	return &categoryAccess{rs: ordered.RuleSet{Categories: cats, Parents: a.rs.Parents}, leaf: a.leaf, names: a.names, lineage: a.lineage}
}

// categoryDecisions is the answer for one person on one category, one decision
// per action.
type categoryDecisions struct {
	Read, Author, Approve, Manage, Ack ordered.Decision
	// AckUngated is the acknowledge rule without the Read requirement.
	AckUngated bool
	names      map[string]string
}

// decide answers every action for the person.
func (a *categoryAccess) decide(p ordered.Person) categoryDecisions {
	m := accessModel()
	return categoryDecisions{
		Read:       m.Decide(a.rs, p, a.leaf, actRead),
		Author:     m.Decide(a.rs, p, a.leaf, actAuthor),
		Approve:    m.Decide(a.rs, p, a.leaf, actApprove),
		Manage:     m.Decide(a.rs, p, a.leaf, actManage),
		Ack:        m.Decide(a.rs, p, a.leaf, actAck),
		AckUngated: ackUngatedModel().Decide(a.rs, p, a.leaf, actAck).Allowed,
		names:      a.names,
	}
}

// pool lists, owners first, the people for whom the action is allowed.
func (a *categoryAccess) pool(people []ordered.Person, action string) []ordered.PoolEntry {
	return accessModel().Pool(a.rs, people, a.leaf, action)
}

// decisionFor is the decision of one action by name.
func (d categoryDecisions) decisionFor(action string) ordered.Decision {
	switch action {
	case actRead:
		return d.Read
	case actAuthor:
		return d.Author
	case actApprove:
		return d.Approve
	case actManage:
		return d.Manage
	default:
		return d.Ack
	}
}
