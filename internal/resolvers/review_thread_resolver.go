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
)

// Inline review threads on a policy version (#79). Core stores the threads and
// enforces the rules that need no roles (blank text, a reviewer acting only on
// their own thread, only the starter deleting). The gateway decides the rest:
// which side the caller acts on, whether an approver an author names holds a
// seat, who sees which thread, and who is shown message bodies. The mock server
// (review-threads.ts) is the reference for each refusal.

// versionOfThread finds the policy version a thread belongs to. Replying to,
// resolving and deleting a thread name only the thread, but the side, the seat
// and the read decision all hang on its version, so the gateway reads the thread
// from core (which applies no actor check on a read) before deciding anything.
// An unknown thread is NotFound and a bad id InvalidArgument, relayed from core.
func (r *Resolver) versionOfThread(ctx context.Context, threadID string) (string, error) {
	resp, err := r.ReviewClient.GetReviewThread(ctx, &corev1.GetReviewThreadRequest{ThreadId: threadID})
	if err != nil {
		return "", err
	}
	return resp.GetThread().GetPolicyVersionId(), nil
}

// reviewAccess is what the gateway decided about one caller on one version.
type reviewAccess struct {
	userID string
	// side is the side the caller acts on, or unspecified when they take no part.
	side   corev1.ReviewSide
	effect authz.Effect
	// seats is everyone seated on the version's run.
	seats map[string]bool
}

func (a reviewAccess) takesPart() bool { return a.side != corev1.ReviewSide_REVIEW_SIDE_UNSPECIFIED }

var errReviewForbidden = status.Error(codes.PermissionDenied, "You don't have permission to do that.")

// authorizeReview decides the caller's access to the threads of a version. The
// order is fixed: the read decision (a denied read is NotFound), then the seats
// on the version's run, then the right to edit the policy. The author side is
// whoever may edit the policy and holds no seat; anyone with a seat, a site
// admin on the approvers included, is a reviewer; anyone else takes no part.
func (r *Resolver) authorizeReview(ctx context.Context, op, versionID string) (reviewAccess, error) {
	logger := r.logger()
	claims, err := signedIn(ctx)
	if err != nil {
		logger.Debug("review thread refused: no signed-in user", log.F("op", op))
		return reviewAccess{}, err
	}
	userID := claims.UserID()
	reads, effect, err := authorizeVersionReads(ctx, r.PolicyClient, r.CategoryClient, r.IdentityAdminClient, r.WorkflowClient, versionID)
	if err != nil {
		logger.Debug("review thread refused by the version read decision",
			log.F("op", op), log.F("policy_version_id", versionID), log.F("code", status.Code(err).String()))
		return reviewAccess{}, err
	}
	seats, err := seatsOnRun(ctx, r.WorkflowClient, versionID)
	if err != nil {
		logger.Error(err, "review thread: could not read the version's run",
			log.F("op", op), log.F("policy_version_id", versionID), log.F("code", status.Code(err).String()))
		return reviewAccess{}, err
	}
	editor := false
	if _, aerr := authorizeEffectiveAuthor(ctx, r.PolicyClient, r.CategoryClient, reads[0].version.PolicyID); aerr == nil {
		editor = true
	} else if status.Code(aerr) != codes.PermissionDenied {
		logger.Error(aerr, "review thread: could not decide the author right",
			log.F("op", op), log.F("policy_version_id", versionID), log.F("code", status.Code(aerr).String()))
		return reviewAccess{}, aerr
	}
	access := reviewAccess{userID: userID, effect: effect, seats: seats}
	switch {
	case seats[userID]:
		access.side = corev1.ReviewSide_REVIEW_SIDE_REVIEWER
	case editor:
		access.side = corev1.ReviewSide_REVIEW_SIDE_AUTHOR
	}
	log.Trace(logger, "review thread access decided",
		log.F("op", op), log.F("policy_version_id", versionID), log.F("side", access.side.String()), log.F("effect", string(effect)))
	return access, nil
}

// authorizeThread is authorizeReview for a request that names only a thread:
// it finds the thread's version first and refuses a caller who takes no part.
func (r *Resolver) authorizeThread(ctx context.Context, op, threadID string) (reviewAccess, string, error) {
	logger := r.logger()
	if _, err := signedIn(ctx); err != nil {
		logger.Debug("review thread refused: no signed-in user", log.F("op", op))
		return reviewAccess{}, "", err
	}
	if r.ReviewClient == nil {
		return reviewAccess{}, "", status.Error(codes.Unavailable, "review is not available")
	}
	versionID, err := r.versionOfThread(ctx, threadID)
	if err != nil {
		logger.Debug("review thread: version not found",
			log.F("op", op), log.F("thread_id", threadID), log.F("code", status.Code(err).String()))
		return reviewAccess{}, "", err
	}
	access, err := r.authorizeReview(ctx, op, versionID)
	if err != nil {
		return reviewAccess{}, "", err
	}
	if !access.takesPart() {
		logger.Info("review thread refused: the caller takes no part in the review",
			log.F("op", op), log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("user_id", access.userID))
		return reviewAccess{}, "", errReviewForbidden
	}
	return access, versionID, nil
}

// ReviewThreadsResolver lists the threads of a version the caller may see: the
// author side sees every thread, a seat holder only the threads with them, and
// a reader who takes no part sees none. An obfuscated reader gets no bodies.
func (r *Resolver) ReviewThreadsResolver(ctx context.Context, versionID string) ([]*ReviewThread, error) {
	logger := r.logger()
	access, err := r.authorizeReview(ctx, "reviewThreads", versionID)
	if err != nil {
		return nil, err
	}
	if !access.takesPart() {
		logger.Debug("review threads: caller takes no part, none listed",
			log.F("policy_version_id", versionID), log.F("user_id", access.userID))
		return []*ReviewThread{}, nil
	}
	if r.ReviewClient == nil {
		return nil, status.Error(codes.Unavailable, "review is not available")
	}
	filter := ""
	if access.side == corev1.ReviewSide_REVIEW_SIDE_REVIEWER {
		filter = access.userID
	}
	started := time.Now()
	resp, err := r.ReviewClient.ListReviewThreads(ctx, &corev1.ListReviewThreadsRequest{PolicyVersionId: versionID, ApproverUserId: filter})
	if err != nil {
		logger.Error(err, "review threads: core list failed",
			log.F("policy_version_id", versionID), log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	labels := newLabelResolver(r.IdentityClient, nil, nil, nil)
	out := make([]*ReviewThread, 0, len(resp.GetThreads()))
	for _, t := range resp.GetThreads() {
		out = append(out, reviewThreadFromProto(ctx, labels, t, access.effect))
	}
	logger.Debug("review threads listed",
		log.F("policy_version_id", versionID), log.F("side", access.side.String()), log.F("filtered", filter != ""),
		log.F("count", len(out)), log.F("effect", string(access.effect)), log.F("duration_ms", time.Since(started).Milliseconds()))
	return out, nil
}

// AddReviewThreadResolver starts a thread with its first message. A reviewer's
// thread is with the reviewer; an author names the one approver it is for, who
// must hold a seat on the version's run.
func (r *Resolver) AddReviewThreadResolver(ctx context.Context, versionID, quote string, occurrence int, body string, suggestedText, toUserID *string) (*ReviewThread, error) {
	logger := r.logger()
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	if r.ReviewClient == nil {
		return nil, status.Error(codes.Unavailable, "review is not available")
	}
	access, err := r.authorizeReview(ctx, "addReviewThread", versionID)
	if err != nil {
		return nil, err
	}
	if !access.takesPart() {
		logger.Info("add review thread refused: the caller takes no part in the review",
			log.F("policy_version_id", versionID), log.F("user_id", access.userID))
		return nil, errReviewForbidden
	}
	if strings.TrimSpace(quote) == "" {
		return nil, status.Error(codes.InvalidArgument, "Select some text to comment on.")
	}
	if occurrence < 1 {
		return nil, status.Error(codes.InvalidArgument, "occurrence counts from 1.")
	}
	if strings.TrimSpace(body) == "" {
		return nil, status.Error(codes.InvalidArgument, "A comment can't be empty.")
	}
	if proposed := strings.TrimSpace(derefOrEmpty(suggestedText)); proposed != "" && proposed != strings.TrimSpace(quote) {
		logger.Debug("add review thread refused: suggestions are not served yet", log.F("policy_version_id", versionID))
		return nil, status.Error(codes.Unimplemented, "Suggested text is not available yet.")
	}
	approver := access.userID
	if access.side == corev1.ReviewSide_REVIEW_SIDE_AUTHOR {
		approver = strings.TrimSpace(derefOrEmpty(toUserID))
		if approver == "" || !access.seats[approver] {
			logger.Debug("add review thread refused: the author named no approver with a seat",
				log.F("policy_version_id", versionID), log.F("named", approver != ""))
			return nil, status.Error(codes.InvalidArgument, "Choose the approver this is for.")
		}
	}
	started := time.Now()
	resp, err := r.ReviewClient.AddReviewThread(ctx, &corev1.AddReviewThreadRequest{
		ActorUserId: access.userID, ActorSide: access.side, PolicyVersionId: versionID,
		Quote: quote, Occurrence: toInt32(occurrence), Body: body, ApproverUserId: approver,
	})
	if err != nil {
		logger.Error(err, "add review thread: core write failed",
			log.F("policy_version_id", versionID), log.F("side", access.side.String()), log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	logger.Info("review thread added",
		log.F("thread_id", resp.GetThread().GetId()), log.F("policy_version_id", versionID), log.F("side", access.side.String()),
		log.F("approver", approver), log.F("duration_ms", time.Since(started).Milliseconds()))
	return reviewThreadFromProto(ctx, newLabelResolver(r.IdentityClient, nil, nil, nil), resp.GetThread(), access.effect), nil
}

// ReplyReviewThreadResolver adds a message to a thread. Core refuses a
// reviewer who is not the thread's approver.
func (r *Resolver) ReplyReviewThreadResolver(ctx context.Context, threadID, body string) (*ReviewThread, error) {
	logger := r.logger()
	access, versionID, err := r.authorizeThread(ctx, "replyReviewThread", threadID)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	resp, err := r.ReviewClient.ReplyReviewThread(ctx, &corev1.ReplyReviewThreadRequest{ActorUserId: access.userID, ActorSide: access.side, ThreadId: threadID, Body: body})
	if err != nil {
		logger.Error(err, "reply review thread: core write failed",
			log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("side", access.side.String()), log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	logger.Info("review thread replied",
		log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("side", access.side.String()), log.F("duration_ms", time.Since(started).Milliseconds()))
	return reviewThreadFromProto(ctx, newLabelResolver(r.IdentityClient, nil, nil, nil), resp.GetThread(), access.effect), nil
}

// SetReviewThreadResolvedResolver resolves a thread, or reopens it.
func (r *Resolver) SetReviewThreadResolvedResolver(ctx context.Context, threadID string, resolved bool) (*ReviewThread, error) {
	logger := r.logger()
	access, versionID, err := r.authorizeThread(ctx, "setReviewThreadResolved", threadID)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	resp, err := r.ReviewClient.SetReviewThreadResolved(ctx, &corev1.SetReviewThreadResolvedRequest{ActorUserId: access.userID, ActorSide: access.side, ThreadId: threadID, Resolved: resolved})
	if err != nil {
		logger.Error(err, "set review thread resolved: core write failed",
			log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("side", access.side.String()), log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	logger.Info("review thread state changed",
		log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("side", access.side.String()), log.F("resolved", resolved), log.F("duration_ms", time.Since(started).Milliseconds()))
	return reviewThreadFromProto(ctx, newLabelResolver(r.IdentityClient, nil, nil, nil), resp.GetThread(), access.effect), nil
}

// DeleteReviewThreadResolver deletes a thread. Core allows only the person who
// started it.
func (r *Resolver) DeleteReviewThreadResolver(ctx context.Context, threadID string) (bool, error) {
	logger := r.logger()
	access, versionID, err := r.authorizeThread(ctx, "deleteReviewThread", threadID)
	if err != nil {
		return false, err
	}
	started := time.Now()
	if _, err := r.ReviewClient.DeleteReviewThread(ctx, &corev1.DeleteReviewThreadRequest{ActorUserId: access.userID, ActorSide: access.side, ThreadId: threadID}); err != nil {
		logger.Error(err, "delete review thread: core write failed",
			log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("side", access.side.String()), log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return false, err
	}
	logger.Info("review thread deleted",
		log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("side", access.side.String()), log.F("duration_ms", time.Since(started).Milliseconds()))
	return true, nil
}

// reviewThreadFromProto maps a core thread to the GraphQL type: author names
// from identity (best effort; an unknown author has none), and no message body
// for a reader whose view of the policy is obfuscated.
func reviewThreadFromProto(ctx context.Context, labels *labelResolver, t *corev1.ReviewThread, effect authz.Effect) *ReviewThread {
	out := &ReviewThread{
		ID: t.GetId(), PolicyVersionID: t.GetPolicyVersionId(), Quote: t.GetQuote(), Occurrence: int(t.GetOccurrence()),
		Resolved: t.GetResolved(), CreatedAt: t.GetCreatedAt().AsTime(), ApproverUserID: t.GetApproverUserId(),
		Messages: make([]*ReviewMessage, 0, len(t.GetMessages())),
	}
	for _, m := range t.GetMessages() {
		body := m.GetBody()
		if effect == authz.EffectObfuscate {
			body = ""
		}
		out.Messages = append(out.Messages, &ReviewMessage{
			ID: m.GetId(), AuthorUserID: m.GetAuthorUserId(), AuthorName: nilIfEmpty(labels.userName(ctx, m.GetAuthorUserId())),
			Body: body, CreatedAt: m.GetCreatedAt().AsTime(),
		})
	}
	return out
}
