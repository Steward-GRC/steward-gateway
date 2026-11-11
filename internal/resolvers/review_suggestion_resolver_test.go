// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// Suggested text on a review thread (#113). A reviewer or the author proposes
// replacement text for the quote, the two sides counter in turn, and the thread
// ends in one outcome. Core keeps the rounds and enforces the turn and outcome
// rules; the gateway decides the caller's side, keeps outsiders out, passes the
// text through and hides it from an obfuscated reader. The fake core below
// applies core's own rules, so a refusal that must come from the gateway shows
// as a call core never received. These tests mirror steward-mock-server
// review-suggestions.test.ts.

// syncSuggestion fills the derived fields core serves: the current text and
// the side whose turn it is, from the latest round.
func syncSuggestion(s *corev1.ReviewSuggestion) {
	last := s.Rounds[len(s.Rounds)-1]
	s.Text = last.GetText()
	s.Turn = corev1.ReviewSide_REVIEW_SIDE_AUTHOR
	if last.GetSide() == corev1.ReviewSide_REVIEW_SIDE_AUTHOR {
		s.Turn = corev1.ReviewSide_REVIEW_SIDE_REVIEWER
	}
}

// openSuggestion is core's openFor: the actor may act on the thread, and it
// carries a suggestion that has not ended.
func (c *reviewCore) openSuggestion(op, id, actor string, side corev1.ReviewSide) (*corev1.ReviewThread, *corev1.ReviewSuggestion, error) {
	t, err := c.act(op, id, actor, side)
	if err != nil {
		return nil, nil, err
	}
	s := t.GetSuggestion()
	switch {
	case s == nil:
		return nil, nil, status.Error(codes.FailedPrecondition, "that thread has no suggestion")
	case s.GetOutcome() != corev1.SuggestionOutcome_SUGGESTION_OUTCOME_UNSPECIFIED:
		return nil, nil, status.Error(codes.FailedPrecondition, "that suggestion has ended")
	}
	return t, s, nil
}

func (c *reviewCore) CounterReviewSuggestion(_ context.Context, in *corev1.CounterReviewSuggestionRequest, _ ...grpc.CallOption) (*corev1.CounterReviewSuggestionResponse, error) {
	t, s, err := c.openSuggestion("counter", in.GetThreadId(), in.GetActorUserId(), in.GetActorSide())
	if err != nil {
		return nil, err
	}
	if s.GetTurn() != in.GetActorSide() {
		return nil, status.Error(codes.FailedPrecondition, "it is not your turn to answer")
	}
	text := strings.TrimSpace(in.GetText())
	if text == "" {
		return nil, status.Error(codes.InvalidArgument, "a counter can't be empty")
	}
	c.lastCounter = in
	s.Rounds = append(s.Rounds, &corev1.SuggestionRound{Seq: int32(len(s.Rounds) + 1), Side: in.GetActorSide(), UserId: in.GetActorUserId(), Text: text, CreatedAt: timestamppb.Now()})
	syncSuggestion(s)
	return &corev1.CounterReviewSuggestionResponse{Thread: t}, nil
}

func (c *reviewCore) CloseReviewSuggestion(_ context.Context, in *corev1.CloseReviewSuggestionRequest, _ ...grpc.CallOption) (*corev1.CloseReviewSuggestionResponse, error) {
	t, s, err := c.openSuggestion("close", in.GetThreadId(), in.GetActorUserId(), in.GetActorSide())
	if err != nil {
		return nil, err
	}
	side := in.GetActorSide()
	mine := s.GetTurn() == side
	var allowed bool
	switch in.GetOutcome() {
	case corev1.SuggestionOutcome_SUGGESTION_OUTCOME_AGREED:
		allowed = mine && side == corev1.ReviewSide_REVIEW_SIDE_REVIEWER
	case corev1.SuggestionOutcome_SUGGESTION_OUTCOME_CHANGED, corev1.SuggestionOutcome_SUGGESTION_OUTCOME_REMOVED:
		allowed = mine && side == corev1.ReviewSide_REVIEW_SIDE_AUTHOR
	case corev1.SuggestionOutcome_SUGGESTION_OUTCOME_NOT_AGREED:
		allowed = mine
	case corev1.SuggestionOutcome_SUGGESTION_OUTCOME_WITHDRAWN:
		allowed = !mine && s.GetRounds()[0].GetSide() == side
	default:
		return nil, status.Error(codes.InvalidArgument, "choose an outcome")
	}
	if !allowed {
		return nil, status.Error(codes.FailedPrecondition, "that outcome is not yours to choose now")
	}
	reason := strings.TrimSpace(in.GetReason())
	if in.GetOutcome() == corev1.SuggestionOutcome_SUGGESTION_OUTCOME_NOT_AGREED && reason == "" {
		return nil, status.Error(codes.InvalidArgument, "say why it is not agreed")
	}
	c.lastClose = in
	s.Outcome, s.Reason, s.ClosedBy, s.ClosedText, s.ClosedAt = in.GetOutcome(), reason, in.GetActorUserId(), s.GetText(), timestamppb.Now()
	t.Resolved = true
	return &corev1.CloseReviewSuggestionResponse{Thread: t}, nil
}

// propose starts a thread with suggested text as the user: a reviewer on their
// own thread, the author naming Charlie.
func (e *thrEnv) propose(t *testing.T, user, text string) *resolvers.ReviewThread {
	t.Helper()
	var to *string
	if user == thrAuthor {
		c := thrCharlie
		to = &c
	}
	got, err := e.r.AddReviewThreadResolver(thrCtx(t, user), thrVersion, "seven years", 1, "Shorter?", &text, to)
	if err != nil {
		t.Fatalf("addReviewThread with a suggestion as %s: %v", user, err)
	}
	return got
}

func (e *thrEnv) counter(user, threadID, text string, t *testing.T) (*resolvers.ReviewThread, error) {
	t.Helper()
	return e.r.CounterReviewSuggestionResolver(thrCtx(t, user), threadID, text)
}

func (e *thrEnv) closeAs(t *testing.T, user, threadID string, outcome resolvers.SuggestionOutcome, reason string) (*resolvers.ReviewThread, error) {
	t.Helper()
	var r *string
	if reason != "" {
		r = &reason
	}
	return e.r.CloseReviewSuggestionResolver(thrCtx(t, user), threadID, outcome, r)
}

func roundSides(s *resolvers.ReviewSuggestion) []resolvers.SuggestionSide {
	out := []resolvers.SuggestionSide{}
	for _, r := range s.Rounds {
		out = append(out, r.By)
	}
	return out
}

// starting a suggestion

func TestReviewSuggestions_AReviewerProposalOpensOnTheAuthorsTurn(t *testing.T) {
	e := newThrEnv(t)
	got := e.propose(t, thrCharlie, "six years")
	s := got.Suggestion
	if s == nil || s.Text != "six years" || s.Turn != resolvers.SuggestionSideAuthor || s.Outcome != nil {
		t.Fatalf("suggestion = %+v, want six years, the author's turn, open", s)
	}
	if sides := roundSides(s); len(sides) != 1 || sides[0] != resolvers.SuggestionSideReviewer || s.Rounds[0].UserID != thrCharlie || s.Rounds[0].Text != "six years" {
		t.Fatalf("rounds = %+v, want the reviewer's proposal by Charlie", s.Rounds)
	}
	if e.core.lastAdd.GetSuggestedText() != "six years" {
		t.Fatalf("core got suggested text %q, want it passed through", e.core.lastAdd.GetSuggestedText())
	}
}

func TestReviewSuggestions_AnAuthorProposalOpensOnTheReviewersTurn(t *testing.T) {
	e := newThrEnv(t)
	got := e.propose(t, thrAuthor, "five years")
	if got.Suggestion == nil || got.Suggestion.Turn != resolvers.SuggestionSideReviewer {
		t.Fatalf("suggestion = %+v, want the reviewer's turn", got.Suggestion)
	}
	if sides := roundSides(got.Suggestion); len(sides) != 1 || sides[0] != resolvers.SuggestionSideAuthor {
		t.Fatalf("rounds = %v, want the author's proposal", sides)
	}
	if e.core.lastAdd.GetActorSide() != corev1.ReviewSide_REVIEW_SIDE_AUTHOR {
		t.Fatalf("core got side %s, want author", e.core.lastAdd.GetActorSide())
	}
}

func TestReviewSuggestions_NoTextOrTheSameTextIsAPlainComment(t *testing.T) {
	e := newThrEnv(t)
	if got := e.add(t, thrCharlie); got.Suggestion != nil {
		t.Fatalf("no suggested text: suggestion = %+v, want none", got.Suggestion)
	}
	for _, same := range []string{"seven years", "  seven years  ", "", "   "} {
		if got := e.propose(t, thrCharlie, same); got.Suggestion != nil {
			t.Fatalf("suggested text %q: suggestion = %+v, want a plain comment", same, got.Suggestion)
		}
	}
}

func TestReviewSuggestions_ComeBackOnTheVersionsThreadList(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	got := e.list(t, thrAuthor)
	if len(got) != 1 || got[0].ID != made.ID || got[0].Suggestion == nil || got[0].Suggestion.Text != "six years" {
		t.Fatalf("list = %+v, want the thread with its suggestion", got)
	}
	if got[0].Suggestion.Rounds[0].CreatedAt.IsZero() {
		t.Fatalf("round has no time: %+v", got[0].Suggestion.Rounds[0])
	}
}

// countering

func TestReviewSuggestions_TheSideOnTurnCountersAndTheTurnFlips(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	got, err := e.counter(thrAuthor, made.ID, "five years", t)
	if err != nil {
		t.Fatalf("counterReviewSuggestion: %v", err)
	}
	s := got.Suggestion
	if s.Text != "five years" || s.Turn != resolvers.SuggestionSideReviewer {
		t.Fatalf("suggestion = %+v, want five years on the reviewer's turn", s)
	}
	if sides := roundSides(s); len(sides) != 2 || sides[0] != resolvers.SuggestionSideReviewer || sides[1] != resolvers.SuggestionSideAuthor || s.Rounds[0].Text != "six years" || s.Rounds[1].Text != "five years" {
		t.Fatalf("rounds = %+v, want reviewer six years then author five years", s.Rounds)
	}
	if e.core.lastCounter.GetActorSide() != corev1.ReviewSide_REVIEW_SIDE_AUTHOR || e.core.lastCounter.GetActorUserId() != thrAuthor {
		t.Fatalf("core got %v, want the author as Bob", e.core.lastCounter)
	}
	back, err := e.counter(thrCharlie, made.ID, "six years and a day", t)
	if err != nil || back.Suggestion.Turn != resolvers.SuggestionSideAuthor || len(back.Suggestion.Rounds) != 3 {
		t.Fatalf("reviewer counter = %+v, %v; want the turn back with the author and 3 rounds", back, err)
	}
}

func TestReviewSuggestions_ACounterOutOfTurnEmptyOrOnAPlainCommentIsRefused(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	_, err := e.counter(thrCharlie, made.ID, "four years", t)
	wantCode(t, "a counter out of turn", err, codes.FailedPrecondition)
	_, err = e.counter(thrAuthor, made.ID, "  ", t)
	wantCode(t, "an empty counter", err, codes.InvalidArgument)
	plain := e.add(t, thrCharlie)
	_, err = e.counter(thrAuthor, plain.ID, "x", t)
	wantCode(t, "a counter on a plain comment", err, codes.FailedPrecondition)
	if got := e.core.thread(made.ID).GetSuggestion(); len(got.GetRounds()) != 1 {
		t.Fatalf("rounds = %d, want the refused counters kept out", len(got.GetRounds()))
	}
}

func TestReviewSuggestions_SomeoneOutsideTheReviewIsKeptOutOfACounter(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	before := len(e.core.calls)
	_, err := e.counter(thrOutside, made.ID, "x", t)
	wantCode(t, "an outsider's counter", err, codes.PermissionDenied)
	_, err = e.closeAs(t, thrOutside, made.ID, resolvers.SuggestionOutcomeWithdrawn, "")
	wantCode(t, "an outsider's close", err, codes.PermissionDenied)
	if len(e.core.calls) != before {
		t.Fatalf("core received %v after an outsider acted, want nothing", e.core.calls[before:])
	}
	// another approver on the same run is not the thread's approver; core refuses
	_, err = e.counter(thrAlice, made.ID, "x", t)
	wantCode(t, "another approver's counter", err, codes.PermissionDenied)
}

// closing

func TestReviewSuggestions_TheAuthorChangesItWhichResolvesTheThreadAndRecordsTheText(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	got, err := e.closeAs(t, thrAuthor, made.ID, resolvers.SuggestionOutcomeChanged, "")
	if err != nil {
		t.Fatalf("closeReviewSuggestion: %v", err)
	}
	s := got.Suggestion
	if !got.Resolved || s.Outcome == nil || *s.Outcome != resolvers.SuggestionOutcomeChanged {
		t.Fatalf("thread = %+v, want it resolved with outcome CHANGED", got)
	}
	if s.ClosedText == nil || *s.ClosedText != "six years" || s.ClosedBy == nil || *s.ClosedBy != thrAuthor || s.Reason != nil {
		t.Fatalf("suggestion = %+v, want closedText six years, closedBy Bob, no reason", s)
	}
	if e.core.lastClose.GetOutcome() != corev1.SuggestionOutcome_SUGGESTION_OUTCOME_CHANGED || e.core.lastClose.GetActorSide() != corev1.ReviewSide_REVIEW_SIDE_AUTHOR {
		t.Fatalf("core got %v", e.core.lastClose)
	}
}

func TestReviewSuggestions_TheAuthorRemovesTheNoteAndTheReviewerAgreesOnTheirTurn(t *testing.T) {
	e := newThrEnv(t)
	first := e.propose(t, thrCharlie, "six years")
	got, err := e.closeAs(t, thrAuthor, first.ID, resolvers.SuggestionOutcomeRemoved, "")
	if err != nil || got.Suggestion.Outcome == nil || *got.Suggestion.Outcome != resolvers.SuggestionOutcomeRemoved {
		t.Fatalf("remove = %+v, %v; want REMOVED", got, err)
	}
	second := e.propose(t, thrCharlie, "six years")
	if _, err := e.counter(thrAuthor, second.ID, "five years", t); err != nil {
		t.Fatalf("counter: %v", err)
	}
	agreed, err := e.closeAs(t, thrCharlie, second.ID, resolvers.SuggestionOutcomeAgreed, "")
	if err != nil {
		t.Fatalf("agree: %v", err)
	}
	if *agreed.Suggestion.Outcome != resolvers.SuggestionOutcomeAgreed || *agreed.Suggestion.ClosedText != "five years" || *agreed.Suggestion.ClosedBy != thrCharlie {
		t.Fatalf("agreed = %+v, want AGREED on five years by Charlie", agreed.Suggestion)
	}
}

func TestReviewSuggestions_TheWrongSideCannotUseAnOutcomeThatIsNotTheirs(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	// the reviewer proposed and it is the author's turn: the reviewer cannot agree with themselves
	_, err := e.closeAs(t, thrCharlie, made.ID, resolvers.SuggestionOutcomeAgreed, "")
	wantCode(t, "the reviewer agreeing with themselves", err, codes.FailedPrecondition)
	if _, err := e.counter(thrAuthor, made.ID, "five years", t); err != nil {
		t.Fatalf("counter: %v", err)
	}
	// now it is the reviewer's turn: CHANGED belongs to the author
	_, err = e.closeAs(t, thrAuthor, made.ID, resolvers.SuggestionOutcomeChanged, "")
	wantCode(t, "the author changing out of turn", err, codes.FailedPrecondition)
	if e.core.thread(made.ID).GetSuggestion().GetOutcome() != corev1.SuggestionOutcome_SUGGESTION_OUTCOME_UNSPECIFIED {
		t.Fatalf("a refused close ended the suggestion")
	}
}

func TestReviewSuggestions_NotAgreedNeedsAReasonAndRecordsIt(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	_, err := e.closeAs(t, thrAuthor, made.ID, resolvers.SuggestionOutcomeNotAgreed, "")
	wantCode(t, "not agreed without a reason", err, codes.InvalidArgument)
	_, err = e.closeAs(t, thrAuthor, made.ID, resolvers.SuggestionOutcomeNotAgreed, "   ")
	wantCode(t, "not agreed with a blank reason", err, codes.InvalidArgument)
	got, err := e.closeAs(t, thrAuthor, made.ID, resolvers.SuggestionOutcomeNotAgreed, "Law says seven.")
	if err != nil {
		t.Fatalf("not agreed: %v", err)
	}
	s := got.Suggestion
	if *s.Outcome != resolvers.SuggestionOutcomeNotAgreed || s.Reason == nil || *s.Reason != "Law says seven." {
		t.Fatalf("suggestion = %+v, want NOT_AGREED with the reason", s)
	}
}

func TestReviewSuggestions_TheSideThatProposedFirstWithdrawsWhileItIsNotTheirTurn(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	got, err := e.closeAs(t, thrCharlie, made.ID, resolvers.SuggestionOutcomeWithdrawn, "")
	if err != nil || *got.Suggestion.Outcome != resolvers.SuggestionOutcomeWithdrawn {
		t.Fatalf("withdraw = %+v, %v; want WITHDRAWN", got, err)
	}
	other := e.propose(t, thrCharlie, "six years")
	_, err = e.closeAs(t, thrAuthor, other.ID, resolvers.SuggestionOutcomeWithdrawn, "")
	wantCode(t, "the author withdrawing the reviewer's proposal", err, codes.FailedPrecondition)
}

func TestReviewSuggestions_ACloseOrCounterAfterTheEndIsRefused(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	if _, err := e.closeAs(t, thrAuthor, made.ID, resolvers.SuggestionOutcomeRemoved, ""); err != nil {
		t.Fatalf("remove: %v", err)
	}
	_, err := e.closeAs(t, thrAuthor, made.ID, resolvers.SuggestionOutcomeRemoved, "")
	wantCode(t, "closing twice", err, codes.FailedPrecondition)
	_, err = e.counter(thrAuthor, made.ID, "x", t)
	wantCode(t, "countering a closed suggestion", err, codes.FailedPrecondition)
}

// gateway pre-checks

func TestReviewSuggestions_AnUnknownThreadIsNotFoundAndTheVersionComesFromCore(t *testing.T) {
	e := newThrEnv(t)
	_, err := e.counter(thrAuthor, "missing", "x", t)
	wantCode(t, "counter on an unknown thread", err, codes.NotFound)
	_, err = e.closeAs(t, thrAuthor, "missing", resolvers.SuggestionOutcomeRemoved, "")
	wantCode(t, "close on an unknown thread", err, codes.NotFound)
	made := e.propose(t, thrCharlie, "six years")
	e.core.reads = nil
	if _, err := e.counter(thrAuthor, made.ID, "five years", t); err != nil {
		t.Fatalf("counter: %v", err)
	}
	if len(e.core.reads) != 1 || e.core.reads[0] != made.ID {
		t.Fatalf("core thread reads = %v, want the thread read once before the write", e.core.reads)
	}
}

func TestReviewSuggestions_AnAnonymousCallerIsRefusedBeforeCoreIsAsked(t *testing.T) {
	e := newThrEnv(t)
	_, err := e.r.CounterReviewSuggestionResolver(context.Background(), "t", "x")
	wantCode(t, "anonymous counter", err, codes.Unauthenticated)
	_, err = e.r.CloseReviewSuggestionResolver(context.Background(), "t", resolvers.SuggestionOutcomeRemoved, nil)
	wantCode(t, "anonymous close", err, codes.Unauthenticated)
	if len(e.core.calls) != 0 || len(e.core.reads) != 0 {
		t.Fatalf("core received %v / %v, want nothing", e.core.calls, e.core.reads)
	}
}

func TestReviewSuggestions_AnOutcomeThatIsNotOneOfTheFiveIsRefusedBeforeCore(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	before := len(e.core.calls)
	_, err := e.closeAs(t, thrAuthor, made.ID, resolvers.SuggestionOutcome("NOPE"), "")
	wantCode(t, "an unknown outcome", err, codes.InvalidArgument)
	if len(e.core.calls) != before {
		t.Fatalf("core received %v, want nothing", e.core.calls[before:])
	}
}

func TestReviewSuggestions_ACoreFailureIsRelayed(t *testing.T) {
	e := newThrEnv(t)
	made := e.propose(t, thrCharlie, "six years")
	e.core.getErr = status.Error(codes.Unavailable, "core down")
	_, err := e.counter(thrAuthor, made.ID, "five years", t)
	wantCode(t, "counter while core is down", err, codes.Unavailable)
}

// obfuscated readers

func TestReviewSuggestions_AnObfuscatedReaderGetsNoProposedTextOrRoundText(t *testing.T) {
	pc, gc, _ := breakGlassReadSetup(t, true) // the site admin sees this policy obfuscated
	e := buildThrEnv(pc, gc)
	e.core.threads = []*corev1.ReviewThread{{
		Id: "t-1", PolicyVersionId: thrVersion, Quote: "seven years", Occurrence: 1, ApproverUserId: thrCharlie, CreatedBy: thrCharlie,
		Messages: []*corev1.ReviewMessage{{Id: "m-1", AuthorUserId: thrCharlie, Body: "the secret clause", CreatedAt: timestamppb.Now()}},
		Suggestion: &corev1.ReviewSuggestion{
			Rounds: []*corev1.SuggestionRound{
				{Seq: 1, Side: corev1.ReviewSide_REVIEW_SIDE_REVIEWER, UserId: thrCharlie, Text: "six secret years", CreatedAt: timestamppb.Now()},
				{Seq: 2, Side: corev1.ReviewSide_REVIEW_SIDE_AUTHOR, UserId: thrAuthor, Text: "five secret years", CreatedAt: timestamppb.Now()},
			},
			Outcome: corev1.SuggestionOutcome_SUGGESTION_OUTCOME_AGREED, Reason: "fine", ClosedBy: thrCharlie, ClosedText: "five secret years",
		},
	}}
	syncSuggestion(e.core.threads[0].Suggestion)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "sa", RolesValue: []string{"site-admin"}, IdpGroupsValue: []string{"Admins"}})

	got, err := e.r.ReviewThreadsResolver(ctx, thrVersion)
	if err != nil || len(got) != 1 || got[0].Suggestion == nil {
		t.Fatalf("reviewThreads = %v, %v; want the thread with a suggestion", ids(got), err)
	}
	s := got[0].Suggestion
	if s.Text != "" || len(s.Rounds) != 2 || s.Rounds[0].Text != "" || s.Rounds[1].Text != "" {
		t.Fatalf("suggestion = %+v, want the text and round texts blank with the rounds kept", s)
	}
	if s.ClosedText != nil || s.Outcome == nil || *s.Outcome != resolvers.SuggestionOutcomeAgreed || s.Rounds[0].UserID != thrCharlie || s.Turn != resolvers.SuggestionSideReviewer {
		t.Fatalf("suggestion = %+v, want closedText hidden but the outcome, turn and who kept", s)
	}
}
