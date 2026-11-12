// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"fmt"
	"strings"

	"github.com/Bugs5382/go-authz/ordered"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// This file is the mapping layer between the three shapes of a category rule:
// the GraphQL RaciRule/RaciRuleInput, core's CategoryRule and the engine's
// ordered.Entry. A rule is one row: a subject and a cell (blank, allow or
// deny) for each of the five actions. Blank cells have no entry.

// raciGrantToProto maps a GraphQL grant to core's.
func raciGrantToProto(g RaciGrant) corev1.GrantEffect {
	switch g {
	case RaciGrantAllow:
		return corev1.GrantEffect_GRANT_EFFECT_ALLOW
	case RaciGrantDeny:
		return corev1.GrantEffect_GRANT_EFFECT_DENY
	default:
		return corev1.GrantEffect_GRANT_EFFECT_UNSPECIFIED
	}
}

// raciGrantFromProto maps core's grant to the GraphQL one.
func raciGrantFromProto(e corev1.GrantEffect) RaciGrant {
	switch e {
	case corev1.GrantEffect_GRANT_EFFECT_ALLOW:
		return RaciGrantAllow
	case corev1.GrantEffect_GRANT_EFFECT_DENY:
		return RaciGrantDeny
	default:
		return RaciGrantBlank
	}
}

// grantEffect is a core grant as an engine effect; blank has none.
func grantEffect(e corev1.GrantEffect) (ordered.Effect, bool) {
	switch e {
	case corev1.GrantEffect_GRANT_EFFECT_ALLOW:
		return ordered.Allow, true
	case corev1.GrantEffect_GRANT_EFFECT_DENY:
		return ordered.Deny, true
	default:
		return "", false
	}
}

// raciKindToProto maps a GraphQL subject kind to core's.
func raciKindToProto(k RaciSubjectKind) corev1.RuleSubjectKind {
	switch k {
	case RaciSubjectKindGroup:
		return corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP
	case RaciSubjectKindUser:
		return corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER
	default:
		return corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE
	}
}

// raciKindFromProto maps core's subject kind to the GraphQL one.
func raciKindFromProto(k corev1.RuleSubjectKind) RaciSubjectKind {
	switch k {
	case corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP:
		return RaciSubjectKindGroup
	case corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER:
		return RaciSubjectKindUser
	default:
		return RaciSubjectKindEveryone
	}
}

// ruleInputToProto converts a GraphQL rule row to core's. Everyone carries no
// reference.
func ruleInputToProto(in *RaciRuleInput) *corev1.CategoryRule {
	r := &corev1.CategoryRule{
		SubjectKind: raciKindToProto(in.SubjectKind),
		SubjectRef:  in.SubjectRef,
		Read:        raciGrantToProto(in.Read),
		Author:      raciGrantToProto(in.Author),
		Approve:     raciGrantToProto(in.Approve),
		Manage:      raciGrantToProto(in.Manage),
		Ack:         raciGrantToProto(in.Ack),
	}
	if r.SubjectKind == corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE {
		r.SubjectRef = ""
	}
	return r
}

// ruleProtoToGQL converts a stored rule row to the GraphQL type.
func ruleProtoToGQL(r *corev1.CategoryRule) *RaciRule {
	return &RaciRule{
		SubjectKind: raciKindFromProto(r.GetSubjectKind()),
		SubjectRef:  r.GetSubjectRef(),
		Read:        raciGrantFromProto(r.GetRead()),
		Author:      raciGrantFromProto(r.GetAuthor()),
		Approve:     raciGrantFromProto(r.GetApprove()),
		Manage:      raciGrantFromProto(r.GetManage()),
		Ack:         raciGrantFromProto(r.GetAck()),
	}
}

// rulesProtoToGQL converts a list of stored rows.
func rulesProtoToGQL(rules []*corev1.CategoryRule) []*RaciRule {
	out := make([]*RaciRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, ruleProtoToGQL(r))
	}
	return out
}

// ruleSubject is the engine subject of a row: "user:<id>", "group:<name>" or
// the Everyone subject.
func ruleSubject(kind corev1.RuleSubjectKind, ref string) string {
	switch kind {
	case corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP:
		return "group:" + ref
	case corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER:
		return "user:" + ref
	default:
		return ordered.Everyone
	}
}

// ruleEntries is a row as engine cells: one entry per non-blank cell, in the
// order of the five actions.
func ruleEntries(r *corev1.CategoryRule) []ordered.Entry {
	subject := ruleSubject(r.GetSubjectKind(), r.GetSubjectRef())
	cells := []struct {
		action string
		grant  corev1.GrantEffect
	}{
		{actRead, r.GetRead()},
		{actAuthor, r.GetAuthor()},
		{actApprove, r.GetApprove()},
		{actManage, r.GetManage()},
		{actAck, r.GetAck()},
	}
	var out []ordered.Entry
	for _, c := range cells {
		if eff, ok := grantEffect(c.grant); ok {
			out = append(out, ordered.Entry{Subject: subject, Action: c.action, Effect: eff})
		}
	}
	return out
}

// rulesEntries flattens rows into the engine's entries, keeping row order.
func rulesEntries(rules []*corev1.CategoryRule) []ordered.Entry {
	var out []ordered.Entry
	for _, r := range rules {
		out = append(out, ruleEntries(r)...)
	}
	return out
}

// ruleFromSubject is the reverse of ruleSubject, for a row built from entries.
func ruleFromSubject(subject string) (corev1.RuleSubjectKind, string) {
	switch {
	case subject == ordered.Everyone:
		return corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE, ""
	case strings.HasPrefix(subject, "group:"):
		return corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP, strings.TrimPrefix(subject, "group:")
	default:
		return corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER, strings.TrimPrefix(subject, "user:")
	}
}

// rulesFromEntries groups entries back into rows by subject, in order of first
// appearance, the engine's own row definition.
func rulesFromEntries(entries []ordered.Entry) []*corev1.CategoryRule {
	var rows []*corev1.CategoryRule
	index := map[string]int{}
	for _, e := range entries {
		i, ok := index[e.Subject]
		if !ok {
			kind, ref := ruleFromSubject(e.Subject)
			i = len(rows)
			index[e.Subject] = i
			rows = append(rows, &corev1.CategoryRule{SubjectKind: kind, SubjectRef: ref})
		}
		g := corev1.GrantEffect_GRANT_EFFECT_DENY
		if e.Effect == ordered.Allow {
			g = corev1.GrantEffect_GRANT_EFFECT_ALLOW
		}
		switch e.Action {
		case actRead:
			rows[i].Read = g
		case actAuthor:
			rows[i].Author = g
		case actApprove:
			rows[i].Approve = g
		case actManage:
			rows[i].Manage = g
		case actAck:
			rows[i].Ack = g
		}
	}
	return rows
}

// raciReasonCode maps the engine's reason to the GraphQL code.
func raciReasonCode(reason string) RaciReasonCode {
	switch reason {
	case ordered.ReasonEntry:
		return RaciReasonCodeEntry
	case ordered.ReasonOwner:
		return RaciReasonCodeOwner
	case ordered.ReasonSuperuser:
		return RaciReasonCodeRoot
	case ordered.ReasonRequires:
		return RaciReasonCodeRequires
	default:
		return RaciReasonCodeDefaultDeny
	}
}

// raciActionOf maps an engine action id to the GraphQL enum.
func raciActionOf(action string) RaciAction {
	switch action {
	case actRead:
		return RaciActionRead
	case actAuthor:
		return RaciActionAuthor
	case actApprove:
		return RaciActionApprove
	case actManage:
		return RaciActionManage
	default:
		return RaciActionAck
	}
}

// entryLabel names the row that decided, for the human reason.
func entryLabel(e *ordered.Entry, names map[string]string) string {
	who := strings.TrimPrefix(strings.TrimPrefix(e.Subject, "user:"), "group:")
	switch {
	case e.Subject == ordered.Everyone:
		who = "Everyone"
	case strings.HasPrefix(e.Subject, "group:"):
		who = "group " + who
	default:
		who = "user " + who
	}
	if name := names[e.Category]; name != "" {
		return fmt.Sprintf("%s in %s", who, name)
	}
	return who
}

// reasonText is the human reason for one action's decision. The structured
// code travels beside it.
func reasonText(d ordered.Decision, names map[string]string) string {
	switch d.Reason {
	case ordered.ReasonEntry:
		verb := "denied"
		if d.Allowed {
			verb = "allowed"
		}
		return fmt.Sprintf("%s by %s", verb, entryLabel(d.DecidedBy, names))
	case ordered.ReasonOwner:
		return "allowed: owner of the category or a parent"
	case ordered.ReasonSuperuser:
		if d.ConfiguredBlock != nil {
			return fmt.Sprintf("blocked: a deny for %s is configured, but root is always allowed and ignores it", entryLabel(d.ConfiguredBlock, names))
		}
		return "allowed: root"
	case ordered.ReasonRequires:
		return fmt.Sprintf("denied: requires %s", d.GatedBy)
	default:
		return "denied: no rule decides"
	}
}

// decisionsToGQL maps the engine's answers to the GraphQL decision.
func decisionsToGQL(d categoryDecisions) *RaciDecision {
	out := &RaciDecision{
		Read: d.Read.Allowed, ReadReason: reasonText(d.Read, d.names), ReadCode: raciReasonCode(d.Read.Reason),
		Author: d.Author.Allowed, AuthorReason: reasonText(d.Author, d.names), AuthorCode: raciReasonCode(d.Author.Reason),
		Approve: d.Approve.Allowed, ApproveReason: reasonText(d.Approve, d.names), ApproveCode: raciReasonCode(d.Approve.Reason),
		Manage: d.Manage.Allowed, ManageReason: reasonText(d.Manage, d.names), ManageCode: raciReasonCode(d.Manage.Reason),
		Ack: d.Ack.Allowed, AckReason: reasonText(d.Ack, d.names), AckCode: raciReasonCode(d.Ack.Reason),
		ConfiguredBlock: []*RaciConfiguredBlock{},
	}
	for _, action := range accessActions {
		cb := d.decisionFor(action).ConfiguredBlock
		if cb == nil {
			continue
		}
		kind, ref := ruleFromSubject(cb.Subject)
		out.ConfiguredBlock = append(out.ConfiguredBlock, &RaciConfiguredBlock{
			Action:      raciActionOf(action),
			CategoryID:  cb.Category,
			SubjectKind: raciKindFromProto(kind),
			SubjectRef:  ref,
		})
	}
	return out
}
