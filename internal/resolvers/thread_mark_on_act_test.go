// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"errors"
	"testing"

	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// A seated reviewer who acts on a thread has reviewed the version as it is now
// (#115, the mock's reviewedBy). The author, who holds no seat, moves nobody's
// snapshot, and a refused act moves none either.

func (e *thrEnv) withSnapshots() *snapshotCore {
	core := newSnapshotCore()
	e.r.ReviewSnapshotClient = core
	return core
}

func (e *thrEnv) sinceAs(t *testing.T, user string) []*resolvers.SectionDiff {
	t.Helper()
	got, err := resolvers.VersionChangesSinceReview(snapCtx(t, user), e.r.Log, e.r.ReviewSnapshotClient, e.r.PolicyClient, e.r.CategoryClient, e.r.IdentityAdminClient, e.wf, thrVersion)
	if err != nil {
		t.Fatalf("versionChangesSinceReview as %s: %v", user, err)
	}
	return got
}

// moves for an approver who comments, and only for that approver

func TestThreadMarksReviewed_MovesForTheApproverWhoCommentsAndOnlyThem(t *testing.T) {
	e := newThrEnv(t)
	core := e.withSnapshots()
	e.sinceAs(t, thrCharlie)
	e.sinceAs(t, thrAlice)
	core.edit("steps", "Book through the portal 21 days ahead.")

	e.add(t, thrCharlie)

	if got := e.sinceAs(t, thrCharlie); len(got) != 0 {
		t.Fatalf("charlie sees %d changed sections after commenting, want none", len(got))
	}
	if got := e.sinceAs(t, thrAlice); len(got) == 0 {
		t.Fatal("alice sees no change; her snapshot moved with charlie's comment")
	}
}

func TestThreadMarksReviewed_EveryReviewerActMarksTheActor(t *testing.T) {
	e := newThrEnv(t)
	core := e.withSnapshots()
	started := e.propose(t, thrCharlie, "six years")
	ctx := thrCtx(t, thrCharlie)

	steps := []struct {
		name string
		run  func() error
	}{
		{"reply", func() error { _, err := e.r.ReplyReviewThreadResolver(ctx, started.ID, "More."); return err }},
		{"resolve", func() error { _, err := e.r.SetReviewThreadResolvedResolver(ctx, started.ID, true); return err }},
		{"reopen", func() error { _, err := e.r.SetReviewThreadResolvedResolver(ctx, started.ID, false); return err }},
	}
	for _, s := range steps {
		before := len(core.marks)
		if err := s.run(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if len(core.marks) != before+1 || core.marks[before] != thrCharlie {
			t.Fatalf("%s: marks = %v, want one more for charlie", s.name, core.marks)
		}
	}
	if len(core.marks) != 4 { // the start, then reply, resolve, reopen
		t.Fatalf("marks = %v, want 4 (start, reply, resolve, reopen)", core.marks)
	}
}

func TestThreadMarksReviewed_CounterAndCloseByASeatHolderMarkThem(t *testing.T) {
	e := newThrEnv(t)
	core := e.withSnapshots()
	made := e.propose(t, thrAuthor, "six years") // the author proposes to charlie: no mark
	if len(core.marks) != 0 {
		t.Fatalf("the author's thread marked %v, want nobody", core.marks)
	}
	if _, err := e.counter(thrCharlie, made.ID, "seven and a half", t); err != nil {
		t.Fatalf("counter: %v", err)
	}
	if len(core.marks) != 1 || core.marks[0] != thrCharlie {
		t.Fatalf("after a counter marks = %v, want charlie", core.marks)
	}
	// The author counters back, then charlie agrees on their turn.
	if _, err := e.counter(thrAuthor, made.ID, "seven", t); err != nil {
		t.Fatalf("author counter: %v", err)
	}
	if _, err := e.closeAs(t, thrCharlie, made.ID, resolvers.SuggestionOutcomeAgreed, ""); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(core.marks) != 2 || core.marks[1] != thrCharlie {
		t.Fatalf("after a close marks = %v, want charlie twice in all", core.marks)
	}
}

func TestThreadMarksReviewed_TheAuthorWithNoSeatMovesNobody(t *testing.T) {
	e := newThrEnv(t)
	core := e.withSnapshots()
	started := e.add(t, thrCharlie)
	core.marks = nil
	ctx := thrCtx(t, thrAuthor)
	if _, err := e.r.ReplyReviewThreadResolver(ctx, started.ID, "Fixed."); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if _, err := e.r.SetReviewThreadResolvedResolver(ctx, started.ID, true); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(core.marks) != 0 {
		t.Fatalf("the author's acts marked %v, want nobody", core.marks)
	}
}

func TestThreadMarksReviewed_ARefusedActMarksNothing(t *testing.T) {
	e := newThrEnv(t)
	core := e.withSnapshots()
	started := e.add(t, thrCharlie)
	core.marks = nil
	// Alice is seated but the thread is Charlie's: core refuses her reply.
	if _, err := e.r.ReplyReviewThreadResolver(thrCtx(t, thrAlice), started.ID, "Mine?"); err == nil {
		t.Fatal("alice replied on charlie's thread")
	}
	// Erin takes no part at all.
	if _, err := e.r.ReplyReviewThreadResolver(thrCtx(t, thrOutside), started.ID, "Hi"); err == nil {
		t.Fatal("someone outside the review replied")
	}
	if len(core.marks) != 0 {
		t.Fatalf("refused acts marked %v, want nothing", core.marks)
	}
}

func TestThreadMarksReviewed_AFailedMarkWarnsAndKeepsTheThread(t *testing.T) {
	e := newThrEnv(t)
	core := e.withSnapshots()
	core.markErr = errors.New("core is down")
	logger := newWarnLog()
	e.r.Log = logger

	got := e.add(t, thrCharlie)
	if got.ID == "" || len(e.core.threads) != 1 {
		t.Fatalf("thread = %+v, want it stored despite the failed mark", got)
	}
	if len(logger.warns) != 1 {
		t.Fatalf("warnings = %v, want one", logger.warns)
	}
}

func TestThreadMarksReviewed_WithNoSnapshotClientTheActStillSucceeds(t *testing.T) {
	e := newThrEnv(t)
	if got := e.add(t, thrCharlie); got.ID == "" {
		t.Fatal("no thread")
	}
}
