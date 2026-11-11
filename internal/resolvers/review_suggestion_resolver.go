// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// Suggested text on a review thread (#113). A thread may carry a suggestion:
// replacement text for its quote, answered by counters in turn and ended in one
// outcome. Core keeps the rounds and enforces the turn, the outcome rules, a
// blank counter and the NOT_AGREED reason. The gateway decides the caller's side
// exactly as for the thread calls (authorizeThread), keeps anyone who takes no
// part out, and hides the text from a reader whose view is obfuscated. The text
// is never logged: only ids, sides, outcomes and durations. The mock server
// (review-threads.ts) is the reference.

// CounterReviewSuggestionResolver answers an open suggestion with new text on
// the caller's turn. Core refuses a blank counter (InvalidArgument), a counter
// out of turn, on a thread with no suggestion or on one that has ended
// (FailedPrecondition), and a reviewer who is not the thread's approver
// (PermissionDenied).
func (r *Resolver) CounterReviewSuggestionResolver(ctx context.Context, threadID, text string) (*ReviewThread, error) {
	logger := r.logger()
	access, versionID, err := r.authorizeThread(ctx, "counterReviewSuggestion", threadID)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	resp, err := r.ReviewClient.CounterReviewSuggestion(ctx, &corev1.CounterReviewSuggestionRequest{
		ActorUserId: access.userID, ActorSide: access.side, ThreadId: threadID, Text: text,
	})
	if err != nil {
		logger.Error(err, "counter review suggestion: core write failed",
			log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("side", access.side.String()),
			log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	logger.Info("review suggestion countered",
		log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("side", access.side.String()),
		log.F("rounds", len(resp.GetThread().GetSuggestion().GetRounds())), log.F("duration_ms", time.Since(started).Milliseconds()))
	r.markReviewedByReviewer(ctx, "counterReviewSuggestion", versionID, access)
	return reviewThreadFromProto(ctx, newLabelResolver(r.IdentityClient, nil, nil, nil), resp.GetThread(), access.effect), nil
}

// CloseReviewSuggestionResolver ends an open suggestion with one outcome, which
// resolves the thread. Core decides whether the outcome is the caller's to
// choose now (FailedPrecondition) and requires a reason for NOT_AGREED
// (InvalidArgument).
func (r *Resolver) CloseReviewSuggestionResolver(ctx context.Context, threadID string, outcome SuggestionOutcome, reason *string) (*ReviewThread, error) {
	logger := r.logger()
	protoOutcome, ok := suggestionOutcomeToProto(outcome)
	if !ok {
		logger.Debug("close review suggestion refused: not a known outcome", log.F("thread_id", threadID))
		return nil, status.Error(codes.InvalidArgument, "Choose how the suggestion ends.")
	}
	access, versionID, err := r.authorizeThread(ctx, "closeReviewSuggestion", threadID)
	if err != nil {
		return nil, err
	}
	reasonText := derefOrEmpty(reason)
	started := time.Now()
	resp, err := r.ReviewClient.CloseReviewSuggestion(ctx, &corev1.CloseReviewSuggestionRequest{
		ActorUserId: access.userID, ActorSide: access.side, ThreadId: threadID, Outcome: protoOutcome, Reason: reasonText,
	})
	if err != nil {
		logger.Error(err, "close review suggestion: core write failed",
			log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("side", access.side.String()),
			log.F("outcome", string(outcome)), log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	logger.Info("review suggestion closed",
		log.F("thread_id", threadID), log.F("policy_version_id", versionID), log.F("side", access.side.String()),
		log.F("outcome", string(outcome)), log.F("has_reason", reasonText != ""), log.F("duration_ms", time.Since(started).Milliseconds()))
	r.markReviewedByReviewer(ctx, "closeReviewSuggestion", versionID, access)
	return reviewThreadFromProto(ctx, newLabelResolver(r.IdentityClient, nil, nil, nil), resp.GetThread(), access.effect), nil
}

var suggestionOutcomes = map[SuggestionOutcome]corev1.SuggestionOutcome{
	SuggestionOutcomeChanged:   corev1.SuggestionOutcome_SUGGESTION_OUTCOME_CHANGED,
	SuggestionOutcomeAgreed:    corev1.SuggestionOutcome_SUGGESTION_OUTCOME_AGREED,
	SuggestionOutcomeRemoved:   corev1.SuggestionOutcome_SUGGESTION_OUTCOME_REMOVED,
	SuggestionOutcomeWithdrawn: corev1.SuggestionOutcome_SUGGESTION_OUTCOME_WITHDRAWN,
	SuggestionOutcomeNotAgreed: corev1.SuggestionOutcome_SUGGESTION_OUTCOME_NOT_AGREED,
}

func suggestionOutcomeToProto(o SuggestionOutcome) (corev1.SuggestionOutcome, bool) {
	p, ok := suggestionOutcomes[o]
	return p, ok
}

// suggestionOutcomeFromProto is nil while the suggestion is open.
func suggestionOutcomeFromProto(p corev1.SuggestionOutcome) *SuggestionOutcome {
	for o, v := range suggestionOutcomes {
		if v == p {
			out := o
			return &out
		}
	}
	return nil
}

func suggestionSideFromProto(s corev1.ReviewSide) SuggestionSide {
	if s == corev1.ReviewSide_REVIEW_SIDE_AUTHOR {
		return SuggestionSideAuthor
	}
	return SuggestionSideReviewer
}

// reviewSuggestionFromProto maps a core suggestion. For an obfuscated reader the
// proposed text, each round's text and the closed text are blank, like a message
// body; who acted, when, the turn and the outcome stay.
func reviewSuggestionFromProto(s *corev1.ReviewSuggestion, effect authz.Effect) *ReviewSuggestion {
	if s == nil {
		return nil
	}
	hide := effect == authz.EffectObfuscate
	out := &ReviewSuggestion{
		Text: s.GetText(), Turn: suggestionSideFromProto(s.GetTurn()), Rounds: make([]*SuggestionRound, 0, len(s.GetRounds())),
		Outcome: suggestionOutcomeFromProto(s.GetOutcome()), Reason: nilIfEmpty(s.GetReason()), ClosedBy: nilIfEmpty(s.GetClosedBy()),
	}
	if s.GetOutcome() != corev1.SuggestionOutcome_SUGGESTION_OUTCOME_UNSPECIFIED {
		out.ClosedText = nilIfEmpty(s.GetClosedText())
	}
	for _, rd := range s.GetRounds() {
		text := rd.GetText()
		if hide {
			text = ""
		}
		out.Rounds = append(out.Rounds, &SuggestionRound{
			By: suggestionSideFromProto(rd.GetSide()), Text: text, UserID: rd.GetUserId(), CreatedAt: rd.GetCreatedAt().AsTime(),
		})
	}
	if hide {
		out.Text, out.ClosedText = "", nil
	}
	return out
}
