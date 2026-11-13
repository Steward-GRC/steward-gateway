// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	authz "github.com/Steward-GRC/steward-gateway/internal/authz"
)

// Semantic versions (steward-gateway#66): core stamps policy and template versions with
// MAJOR.MINOR.FIX and the change type behind it. These helpers turn core's messages into the
// gateway's enum and string, and the author's pick into workflow's enum. An unset value stays
// null; nothing is invented here.

// semanticVersionString renders core's semantic version, "2.1.0". Core sends the text with it;
// the three numbers are the fallback when it does not. Nil when core sent no version.
func semanticVersionString(v *corev1.SemanticVersion) *string {
	if v == nil {
		return nil
	}
	s := v.GetText()
	if s == "" {
		s = fmt.Sprintf("%d.%d.%d", v.GetMajor(), v.GetMinor(), v.GetFix())
	}
	return &s
}

// changeTypeFromCore maps core's change type. Nil for UNSPECIFIED (and anything unknown), so the
// client sees null rather than a value core never decided.
func changeTypeFromCore(c corev1.ChangeType) *ChangeType {
	var out ChangeType
	switch c {
	case corev1.ChangeType_CHANGE_TYPE_MAJOR:
		out = ChangeTypeMajor
	case corev1.ChangeType_CHANGE_TYPE_MINOR:
		out = ChangeTypeMinor
	case corev1.ChangeType_CHANGE_TYPE_FIX:
		out = ChangeTypeFix
	default:
		return nil
	}
	return &out
}

// changeTypeToWorkflow maps the author's pick to workflow's enum (the values match core's, so the
// pick passes through unchanged). Nil or unknown is UNSPECIFIED: core's suggestion stands.
func changeTypeToWorkflow(c *ChangeType) workflowv1.ChangeType {
	if c == nil {
		return workflowv1.ChangeType_CHANGE_TYPE_UNSPECIFIED
	}
	switch *c {
	case ChangeTypeMajor:
		return workflowv1.ChangeType_CHANGE_TYPE_MAJOR
	case ChangeTypeMinor:
		return workflowv1.ChangeType_CHANGE_TYPE_MINOR
	case ChangeTypeFix:
		return workflowv1.ChangeType_CHANGE_TYPE_FIX
	default:
		return workflowv1.ChangeType_CHANGE_TYPE_UNSPECIFIED
	}
}

// changeTypeLabel names a pick for the log; "unset" when the author made none.
func changeTypeLabel(c *ChangeType) string {
	if c == nil {
		return "unset"
	}
	return c.String()
}

// reacknowledgeFor is PolicyVersion.reacknowledge once the facts are known: a policy (never a
// procedure) that asks for acknowledgement on change, published as a MAJOR change. pick is the
// author's choice at submit time; without it the version's own type stands, else core's
// suggestion. An unknown type is false (steward-gateway#231).
func reacknowledgeFor(documentType DocumentType, ob *corev1.ResolvePolicyObligationResponse, v *PolicyVersion, pick *ChangeType) bool {
	if documentType == DocumentTypeProcedure || !ob.GetRequiresAck() || !ob.GetOnChange() {
		return false
	}
	effective := pick
	if effective == nil {
		effective = v.ChangeType
	}
	if effective == nil {
		effective = v.SuggestedChangeType
	}
	return effective != nil && *effective == ChangeTypeMajor
}

// ReacknowledgeForVersionResolver is PolicyVersion.reacknowledge. The version was read under
// the policy's read decision; it is checked again here, as for appendices, because the flag is
// also asked for a version that arrived from a mutation. Core says whether the policy asks for
// acknowledgement and on change; the document type is read from the policy so a procedure is
// false whatever core answers.
func (r *Resolver) ReacknowledgeForVersionResolver(ctx context.Context, v *PolicyVersion, pick *ChangeType) (bool, error) {
	logger := r.logger()
	if _, err := signedIn(ctx); err != nil {
		return false, err
	}
	effect, _, err := versionReadDecisionChecked(ctx, r.PolicyClient, r.CategoryClient, r.IdentityAdminClient, v.PolicyID)
	if err != nil {
		logger.Error(err, "reacknowledge: could not read the policy", log.F("policy_version_id", v.ID), log.F("policy_id", v.PolicyID))
		return false, err
	}
	if effect == authz.EffectDeny {
		logger.Debug("reacknowledge refused by the policy read decision", log.F("policy_version_id", v.ID), log.F("policy_id", v.PolicyID))
		return false, status.Error(codes.NotFound, "policy version not found")
	}
	pol, err := r.PolicyClient.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: v.PolicyID})
	if err != nil {
		logger.Error(err, "reacknowledge: core get policy failed", log.F("policy_id", v.PolicyID), log.F("code", status.Code(err).String()))
		return false, err
	}
	docType := documentTypeFromProto(pol.GetPolicy().GetDocumentType())
	if docType == DocumentTypeProcedure {
		logger.Debug("reacknowledge: a procedure has no acknowledgements", log.F("policy_id", v.PolicyID))
		return false, nil
	}
	started := time.Now()
	ob, err := r.PolicyClient.ResolvePolicyObligation(ctx, &corev1.ResolvePolicyObligationRequest{PolicyId: v.PolicyID})
	if err != nil {
		logger.Error(err, "reacknowledge: core resolve obligation failed", log.F("policy_id", v.PolicyID),
			log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return false, err
	}
	out := reacknowledgeFor(docType, ob, v, pick)
	logger.Debug("reacknowledge worked out", log.F("policy_version_id", v.ID), log.F("policy_id", v.PolicyID),
		log.F("requires_ack", ob.GetRequiresAck()), log.F("on_change", ob.GetOnChange()),
		log.F("picked", pick != nil), log.F("result", out), log.F("duration_ms", time.Since(started).Milliseconds()))
	return out, nil
}
