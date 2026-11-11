// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authz "github.com/Steward-GRC/steward-authz"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// policyExportedAction is the audit action for a print or export of a sensitive policy
// (steward-gateway#78). steward-audit stores any non-empty action name, so no audit change is needed.
const policyExportedAction = "policy.exported"

// RecordPolicyExport backs the recordPolicyExport mutation: the browser print has no server call of
// its own, so the web reports it here. A caller who cannot read the policy gets NotFound; one who
// sees it obfuscated printed nothing real and records nothing. Only a sensitive policy is recorded;
// the result says whether an entry was written. The entry never carries content. A sensitive
// record that cannot be written is an error, not a quiet success.
func RecordPolicyExport(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, emitter AuditEmitter, policyID string, kind PolicyExportKind, includeHistory bool) (bool, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return false, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	effect, _ := versionReadDecision(ctx, client, categoryClient, adminClient, policyID)
	switch effect {
	case authz.EffectAllow:
	case authz.EffectObfuscate:
		return false, nil
	default:
		return false, status.Error(codes.NotFound, "policy not found")
	}
	resp, err := client.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: policyID})
	if err != nil {
		return false, err
	}
	p := resp.GetPolicy()
	if p.GetSensitivity() != corev1.Sensitivity_SENSITIVITY_SENSITIVE {
		return false, nil
	}
	label := "print"
	if kind == PolicyExportKindPDF {
		label = "pdf"
	}
	if err := emitPolicyExport(ctx, emitter, policyID, p.GetCurrentPublishedVersionId(), label, includeHistory); err != nil {
		return false, err
	}
	return true, nil
}

// recordPDFExport audits a PDF export of one version when its policy is sensitive. It runs before
// the render job starts, so a sensitive export that cannot be recorded does not happen.
func recordPDFExport(ctx context.Context, client corev1.PolicyServiceClient, emitter AuditEmitter, policyID, versionID string) error {
	resp, err := client.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: policyID})
	if err != nil {
		return err
	}
	if resp.GetPolicy().GetSensitivity() != corev1.Sensitivity_SENSITIVITY_SENSITIVE {
		return nil
	}
	return emitPolicyExport(ctx, emitter, policyID, versionID, "pdf", false)
}

// emitPolicyExport writes the audit entry. The actor is the real user: during act-as that is the
// admin, with the effective user named in acting_as, as the impersonation events do.
func emitPolicyExport(ctx context.Context, emitter AuditEmitter, policyID, versionID, kind string, includeHistory bool) error {
	if emitter == nil {
		return status.Error(codes.Unavailable, "audit unavailable")
	}
	claims, _ := principal.FromContext(ctx)
	actor := claims.UserID()
	attrs := map[string]string{
		"policy_id":       policyID,
		"version_id":      versionID,
		"kind":            kind,
		"include_history": strconv.FormatBool(includeHistory),
	}
	if admin, acting := principal.ImpersonatorFromContext(ctx); acting && admin.UserID() != actor {
		attrs["acting_as"] = actor
		actor = admin.UserID()
	}
	return emitter.Emit(ctx, &auditv1.AuditEvent{
		Tier:        auditv1.Tier_TIER_AUDIT,
		Action:      policyExportedAction,
		ActorUserId: actor,
		OccurredAt:  timestamppb.Now(),
		Subject:     "policy:" + policyID,
		Attributes:  attrs,
	})
}
