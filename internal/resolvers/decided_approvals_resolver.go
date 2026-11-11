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

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// decidedPolicy is what one policy contributes to the list: whether the caller
// may see it, and its title. It is resolved once per policy for the request.
type decidedPolicy struct {
	title   string
	visible bool
}

// DecidedApprovalsResolver lists the approvals the signed-in user has decided on
// runs still in review (steward-gateway#154). Workflow answers for the caller
// alone, so the caller's id is bound here and no other user's decision is asked
// for. Each entry then meets the policy's read decision, the one policyVersion
// applies (versionReadDecision): a policy the caller can no longer read is left
// out. An obfuscated reader keeps the entry, as the title is metadata the way
// WorkflowStatus treats it. A read only a break-glass grant allows is left out
// as well, since a list cannot record each read first. An entry core answers
// NotFound for is left out and logged; any other core error fails the query.
//
// Core is asked once per distinct version and once per distinct policy.
func DecidedApprovalsResolver(
	ctx context.Context,
	logger log.Logger,
	client workflowv1.WorkflowServiceClient,
	policies corev1.PolicyServiceClient,
	categories corev1.CategoryServiceClient,
	admin identityv1.IdentityAdminServiceClient,
) ([]*DecidedApproval, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		logger.Debug("decided approvals refused: no signed-in user")
		return nil, fmt.Errorf("unauthenticated")
	}
	start := time.Now()
	resp, err := client.ListDecidedApprovals(ctx, &workflowv1.ListDecidedApprovalsRequest{UserId: claims.UserID()})
	if err != nil {
		logger.Error(err, "decided approvals: workflow list failed",
			log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(start).Milliseconds()))
		return nil, fmt.Errorf("workflow list decided approvals: %w", err)
	}
	logger.Debug("decided approvals: workflow answered",
		log.F("entries", len(resp.GetApprovals())), log.F("duration_ms", time.Since(start).Milliseconds()))

	versionPolicy := map[string]string{} // version id -> policy id, "" when core has no such version
	byPolicy := map[string]*decidedPolicy{}
	out := make([]*DecidedApproval, 0, len(resp.GetApprovals()))
	for _, d := range resp.GetApprovals() {
		vid := d.GetPolicyVersionId()
		pid, seen := versionPolicy[vid]
		if !seen {
			vr, verr := policies.GetPolicyVersion(ctx, &corev1.GetPolicyVersionRequest{Id: vid})
			switch {
			case verr == nil:
				pid = vr.GetVersion().GetPolicyId()
			case status.Code(verr) == codes.NotFound:
				logger.Warn("decided approvals: core has no such version, entry dropped",
					log.F("policy_version_id", vid), log.F("run_id", d.GetRunId()))
			default:
				logger.Error(verr, "decided approvals: core version lookup failed",
					log.F("policy_version_id", vid), log.F("code", status.Code(verr).String()))
				return nil, fmt.Errorf("core get policy version: %w", verr)
			}
			versionPolicy[vid] = pid
		}
		if pid == "" {
			continue
		}
		pol, known := byPolicy[pid]
		if !known {
			var perr error
			pol, perr = decidedPolicyFor(ctx, logger, policies, categories, admin, pid)
			if perr != nil {
				return nil, perr
			}
			byPolicy[pid] = pol
		}
		if !pol.visible {
			log.Trace(logger, "decided approvals: entry dropped, policy not readable",
				log.F("policy_version_id", vid), log.F("run_id", d.GetRunId()))
			continue
		}
		decidedAt := ""
		if ts := d.GetDecidedAt(); ts != nil {
			decidedAt = ts.AsTime().UTC().Format(time.RFC3339)
		}
		out = append(out, &DecidedApproval{
			PolicyVersionID: vid,
			PolicyTitle:     pol.title,
			RunID:           d.GetRunId(),
			CurrentStageIdx: int(d.GetCurrentStageIdx()),
			StageCount:      int(d.GetStageCount()),
			Decision:        d.GetDecision(),
			DecidedAt:       decidedAt,
		})
	}
	logger.Debug("decided approvals listed",
		log.F("from_workflow", len(resp.GetApprovals())), log.F("returned", len(out)),
		log.F("policies", len(byPolicy)), log.F("duration_ms", time.Since(start).Milliseconds()))
	return out, nil
}

// decidedPolicyFor reads one policy's title and the caller's read decision on
// it. A policy core no longer holds is not visible; any other core error fails.
func decidedPolicyFor(ctx context.Context, logger log.Logger, policies corev1.PolicyServiceClient, categories corev1.CategoryServiceClient, admin identityv1.IdentityAdminServiceClient, policyID string) (*decidedPolicy, error) {
	pr, err := policies.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: policyID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			logger.Warn("decided approvals: core has no such policy, entries dropped", log.F("policy_id", policyID))
			return &decidedPolicy{}, nil
		}
		logger.Error(err, "decided approvals: core policy lookup failed",
			log.F("policy_id", policyID), log.F("code", status.Code(err).String()))
		return nil, fmt.Errorf("core get policy: %w", err)
	}
	effect, breakGlass := versionReadDecision(ctx, policies, categories, admin, policyID)
	visible := effect != authz.EffectDeny && !breakGlass
	logger.Debug("decided approvals: policy read decision",
		log.F("policy_id", policyID), log.F("effect", string(effect)), log.F("break_glass_only", breakGlass), log.F("visible", visible))
	return &decidedPolicy{title: pr.GetPolicy().GetTitle(), visible: visible}, nil
}
