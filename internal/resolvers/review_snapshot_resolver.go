// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"strings"
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

// unchangedSection is the change type core gives a section that did not move.
const unchangedSection = "unchanged"

// VersionChangesSinceReview returns what changed in each section of a version
// since the caller, an approver on its run, last reviewed it (#114). Core keeps
// the snapshot and lists every section; only the changed ones are returned. The
// read decision on the version comes first (a denied read is NotFound, an
// obfuscated one drops the word diffs), then the seat check. Core is asked only
// for a caller who passed both, because its first read takes the snapshot.
func VersionChangesSinceReview(ctx context.Context, logger log.Logger, snapshots corev1.ReviewSnapshotServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, workflow workflowv1.WorkflowServiceClient, versionID string) ([]*SectionDiff, error) {
	userID, effect, err := authorizeSnapshotAccess(ctx, logger, "versionChangesSinceReview", policyClient, categoryClient, adminClient, workflow, versionID)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	resp, err := snapshots.GetChangesSinceReview(ctx, &corev1.GetChangesSinceReviewRequest{PolicyVersionId: versionID, UserId: userID})
	if err != nil {
		logger.Error(err, "changes since review: core read failed",
			log.F("policy_version_id", versionID), log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	out := make([]*SectionDiff, 0, len(resp.GetDiffs()))
	for _, d := range resp.GetDiffs() {
		if d.GetChangeType() == unchangedSection {
			continue
		}
		out = append(out, sectionDiffFromProto(d))
	}
	logger.Debug("changes since review served",
		log.F("policy_version_id", versionID), log.F("sections", len(resp.GetDiffs())), log.F("changed", len(out)),
		log.F("effect", string(effect)), log.F("duration_ms", time.Since(started).Milliseconds()))
	return obfuscateSectionDiffs(out, effect), nil
}

// MarkVersionReviewed moves the caller's snapshot to the version as it is now
// (#114). It takes the same read decision and seat check as the diff, and moves
// the caller's snapshot only.
func MarkVersionReviewed(ctx context.Context, logger log.Logger, snapshots corev1.ReviewSnapshotServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, workflow workflowv1.WorkflowServiceClient, versionID string) (bool, error) {
	userID, _, err := authorizeSnapshotAccess(ctx, logger, "markVersionReviewed", policyClient, categoryClient, adminClient, workflow, versionID)
	if err != nil {
		return false, err
	}
	started := time.Now()
	if _, err := snapshots.MarkVersionReviewed(ctx, &corev1.MarkVersionReviewedRequest{PolicyVersionId: versionID, UserId: userID}); err != nil {
		logger.Error(err, "mark version reviewed: core write failed",
			log.F("policy_version_id", versionID), log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return false, err
	}
	logger.Info("version marked reviewed",
		log.F("policy_version_id", versionID), log.F("duration_ms", time.Since(started).Milliseconds()))
	return true, nil
}

// markReviewedAfterAct moves userID's snapshot of the version after userID acted
// on it: a decision, a comment sent back, or a thread act (#115). The act has
// already happened, so this never returns an error: a failed mark is a warning
// that names the ids and the status code only, never the comment or the error
// text. No snapshot client means no snapshots are kept, which is not a failure.
// The caller has to have established the seat; unlike MarkVersionReviewed this
// does not ask the read decision or the run again.
func markReviewedAfterAct(ctx context.Context, logger log.Logger, snapshots corev1.ReviewSnapshotServiceClient, op, versionID, userID string) {
	if snapshots == nil {
		log.Trace(logger, "mark after act skipped: no snapshot client", log.F("op", op), log.F("policy_version_id", versionID))
		return
	}
	started := time.Now()
	if _, err := snapshots.MarkVersionReviewed(ctx, &corev1.MarkVersionReviewedRequest{PolicyVersionId: versionID, UserId: userID}); err != nil {
		logger.Warn("mark after act failed: the act stands",
			log.F("op", op), log.F("policy_version_id", versionID), log.F("user_id", userID),
			log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return
	}
	logger.Debug("version marked reviewed after the act",
		log.F("op", op), log.F("policy_version_id", versionID), log.F("duration_ms", time.Since(started).Milliseconds()))
}

// authorizeSnapshotAccess is the gate in front of both fields. It returns the
// signed-in user, whose id is the only one core is ever given, and the read
// effect on the version's content. The order is fixed: the read decision, then
// the seat. Every failure serves nothing and leaves core untouched.
func authorizeSnapshotAccess(ctx context.Context, logger log.Logger, op string, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, workflow workflowv1.WorkflowServiceClient, versionID string) (string, authz.Effect, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		logger.Debug("review snapshot refused: no signed-in user", log.F("op", op), log.F("policy_version_id", versionID))
		return "", authz.EffectDeny, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	userID := claims.UserID()
	log.Trace(logger, "review snapshot access check", log.F("op", op), log.F("policy_version_id", versionID))

	_, effect, err := authorizeVersionReads(ctx, policyClient, categoryClient, adminClient, workflow, versionID)
	if err != nil {
		logger.Debug("review snapshot refused by the version read decision",
			log.F("op", op), log.F("policy_version_id", versionID), log.F("code", status.Code(err).String()))
		return "", authz.EffectDeny, err
	}
	seat, err := holdsSeatOnRun(ctx, workflow, versionID, userID)
	if err != nil {
		logger.Error(err, "review snapshot: could not read the version's run",
			log.F("op", op), log.F("policy_version_id", versionID), log.F("code", status.Code(err).String()))
		return "", authz.EffectDeny, err
	}
	if !seat {
		logger.Info("review snapshot refused: no seat on the version's run",
			log.F("op", op), log.F("policy_version_id", versionID), log.F("user_id", userID))
		return "", authz.EffectDeny, status.Error(codes.PermissionDenied, "You don't have permission to do that.")
	}
	log.Trace(logger, "review snapshot access granted",
		log.F("op", op), log.F("policy_version_id", versionID), log.F("effect", string(effect)))
	return userID, effect, nil
}

// holdsSeatOnRun reports whether userID is seated on the version's approval
// run, in any stage and in any state: an approver who has already decided keeps
// the view. Only individual seats count; a group seat is not expanded here. A
// version with no run seats nobody. Any other workflow error is returned, so
// nothing is served when the seat cannot be checked.
func holdsSeatOnRun(ctx context.Context, client workflowv1.WorkflowServiceClient, versionID, userID string) (bool, error) {
	seats, err := seatsOnRun(ctx, client, versionID)
	if err != nil {
		return false, err
	}
	return seats[userID], nil
}

// seatsOnRun lists everyone seated on the version's approval run, by user id,
// with the same rules as holdsSeatOnRun.
func seatsOnRun(ctx context.Context, client workflowv1.WorkflowServiceClient, versionID string) (map[string]bool, error) {
	if client == nil {
		return nil, status.Error(codes.Unavailable, "workflow is not available")
	}
	resp, err := client.GetStatus(ctx, &workflowv1.GetStatusRequest{PolicyVersionId: versionID})
	if err != nil {
		if st, ok := status.FromError(err); (ok && st.Code() == codes.NotFound) || strings.Contains(err.Error(), "no approval run") {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	seats := map[string]bool{}
	for _, stage := range resp.GetStageAssignees() {
		for _, a := range stage.GetAssignees() {
			if id := a.GetUserId(); id != "" {
				seats[id] = true
			}
		}
	}
	return seats, nil
}

// sectionDiffFromProto maps core's section diff to the GraphQL type.
func sectionDiffFromProto(d *corev1.SectionDiff) *SectionDiff {
	return &SectionDiff{
		SectionKey:    d.GetSectionKey(),
		SectionTitle:  d.GetSectionTitle(),
		ChangeType:    d.GetChangeType(),
		WordDiffHTML:  nilIfEmpty(d.GetWordDiffHtml()),
		IsBoilerplate: d.GetIsBoilerplate(),
	}
}
