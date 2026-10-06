// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// RaciGrantFromGQL maps a GraphQL RaciGrant enum to the steward-authz Grant.
func RaciGrantFromGQL(g RaciGrant) authz.Grant {
	switch g {
	case RaciGrantAllow:
		return authz.GrantAllow
	case RaciGrantDeny:
		return authz.GrantDeny
	default:
		return authz.GrantBlank
	}
}

// RaciGrantToGQL maps a steward-authz Grant to the GraphQL RaciGrant enum.
func RaciGrantToGQL(g authz.Grant) RaciGrant {
	switch g {
	case authz.GrantAllow:
		return RaciGrantAllow
	case authz.GrantDeny:
		return RaciGrantDeny
	default:
		return RaciGrantBlank
	}
}

// RaciKindFromGQL maps a GraphQL RaciSubjectKind to the steward-authz SubjectKind.
func RaciKindFromGQL(k RaciSubjectKind) authz.SubjectKind {
	switch k {
	case RaciSubjectKindGroup:
		return authz.SubjectGroup
	case RaciSubjectKindUser:
		return authz.SubjectUser
	default:
		return authz.SubjectEveryone
	}
}

// RaciKindToGQL maps a steward-authz SubjectKind to the GraphQL RaciSubjectKind.
func RaciKindToGQL(k authz.SubjectKind) RaciSubjectKind {
	switch k {
	case authz.SubjectGroup:
		return RaciSubjectKindGroup
	case authz.SubjectUser:
		return RaciSubjectKindUser
	default:
		return RaciSubjectKindEveryone
	}
}

// grantAuthzToProto maps an authz.Grant to a proto GrantEffect.
func grantAuthzToProto(g authz.Grant) corev1.GrantEffect {
	switch g {
	case authz.GrantAllow:
		return corev1.GrantEffect_GRANT_EFFECT_ALLOW
	case authz.GrantDeny:
		return corev1.GrantEffect_GRANT_EFFECT_DENY
	default:
		return corev1.GrantEffect_GRANT_EFFECT_UNSPECIFIED
	}
}

// kindAuthzToProto maps an authz.SubjectKind to a proto RuleSubjectKind.
func kindAuthzToProto(k authz.SubjectKind) corev1.RuleSubjectKind {
	switch k {
	case authz.SubjectGroup:
		return corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP
	case authz.SubjectUser:
		return corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER
	default:
		return corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE
	}
}

// RuleGQLInputToAuthz converts a GraphQL RaciRuleInput to an authz.Rule.
func RuleGQLInputToAuthz(in *RaciRuleInput) authz.Rule {
	return authz.Rule{
		Subject: authz.RuleSubject{
			Kind: RaciKindFromGQL(in.SubjectKind),
			Name: in.SubjectRef,
		},
		Grants: map[authz.Action]authz.Grant{
			authz.ActionRead:        RaciGrantFromGQL(in.Read),
			authz.ActionAcknowledge: RaciGrantFromGQL(in.Ack),
			authz.ActionApprove:     RaciGrantFromGQL(in.Approve),
			authz.ActionAuthor:      RaciGrantFromGQL(in.Author),
		},
	}
}

// authzRuleToProto converts an authz.Rule to a proto CategoryRule.
func authzRuleToProto(r authz.Rule) *corev1.CategoryRule {
	return &corev1.CategoryRule{
		SubjectKind: kindAuthzToProto(r.Subject.Kind),
		SubjectRef:  r.Subject.Name,
		Read:        grantAuthzToProto(r.Grants[authz.ActionRead]),
		Ack:         grantAuthzToProto(r.Grants[authz.ActionAcknowledge]),
		Approve:     grantAuthzToProto(r.Grants[authz.ActionApprove]),
		Author:      grantAuthzToProto(r.Grants[authz.ActionAuthor]),
	}
}

// AuthzResultToDecision maps an authz.Result to a GraphQL RaciDecision.
func AuthzResultToDecision(res authz.Result) *RaciDecision {
	return &RaciDecision{
		Read:          res.Read.Allowed,
		ReadReason:    res.Read.String(),
		Ack:           res.Acknowledge.Allowed,
		AckReason:     res.Acknowledge.String(),
		Approve:       res.Approve.Allowed,
		ApproveReason: res.Approve.String(),
		Author:        res.Author.Allowed,
		AuthorReason:  res.Author.String(),
	}
}

// raciRuleToGQL converts an authz.Rule to a GraphQL RaciRule (for response mapping).
func raciRuleToGQL(r authz.Rule) *RaciRule {
	return &RaciRule{
		SubjectKind: RaciKindToGQL(r.Subject.Kind),
		SubjectRef:  r.Subject.Name,
		Read:        RaciGrantToGQL(r.Grants[authz.ActionRead]),
		Ack:         RaciGrantToGQL(r.Grants[authz.ActionAcknowledge]),
		Approve:     RaciGrantToGQL(r.Grants[authz.ActionApprove]),
		Author:      RaciGrantToGQL(r.Grants[authz.ActionAuthor]),
	}
}
