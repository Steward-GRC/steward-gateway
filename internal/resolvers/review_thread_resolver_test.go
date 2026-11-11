// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// Inline review threads (#79). Core keeps the threads and enforces only the
// rules that need no roles; the gateway decides the caller's side (the author of
// the policy with no seat on the version's run, or a reviewer who holds one),
// checks the approver an author names, filters what each side sees and hides
// message bodies from an obfuscated reader. These tests run the resolvers
// against a fake core that keeps threads and enforces the rules core does, so a
// refusal that must come from the gateway shows as a call core never received.
// They mirror steward-mock-server review-threads.test.ts.

const (
	thrVersion = "pol-1-v1"
	thrAuthor  = "user-bob"
	thrCharlie = "user-charlie"
	thrAlice   = "user-alice"
	thrOutside = "user-erin"
)

// reviewCore is core's ReviewService in memory, with core's own rules: a blank
// quote or body or an occurrence under 1 is InvalidArgument, a reviewer must be
// the thread's approver, and only the starter deletes.
type reviewCore struct {
	corev1.ReviewServiceClient
	threads     []*corev1.ReviewThread
	calls       []string // one entry per call core received: "<rpc> <actor>/<side>"
	lastAdd     *corev1.AddReviewThreadRequest
	lastList    *corev1.ListReviewThreadsRequest
	lastCounter *corev1.CounterReviewSuggestionRequest
	lastClose   *corev1.CloseReviewSuggestionRequest
	next        int
	reads       []string // thread ids core was asked to read
	getErr      error
}

func (c *reviewCore) thread(id string) *corev1.ReviewThread {
	for _, t := range c.threads {
		if t.GetId() == id {
			return t
		}
	}
	return nil
}

func (c *reviewCore) GetReviewThread(_ context.Context, in *corev1.GetReviewThreadRequest, _ ...grpc.CallOption) (*corev1.GetReviewThreadResponse, error) {
	c.reads = append(c.reads, in.GetThreadId())
	if c.getErr != nil {
		return nil, c.getErr
	}
	t := c.thread(in.GetThreadId())
	if t == nil {
		return nil, status.Error(codes.NotFound, "review thread not found")
	}
	return &corev1.GetReviewThreadResponse{Thread: t}, nil
}

func (c *reviewCore) AddReviewThread(_ context.Context, in *corev1.AddReviewThreadRequest, _ ...grpc.CallOption) (*corev1.AddReviewThreadResponse, error) {
	c.calls = append(c.calls, fmt.Sprintf("add %s/%s", in.GetActorUserId(), in.GetActorSide()))
	c.lastAdd = in
	if in.GetActorSide() == corev1.ReviewSide_REVIEW_SIDE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "bad side")
	}
	if strings.TrimSpace(in.GetQuote()) == "" || strings.TrimSpace(in.GetBody()) == "" || in.GetOccurrence() < 1 {
		return nil, status.Error(codes.InvalidArgument, "blank text or occurrence")
	}
	if in.GetActorSide() == corev1.ReviewSide_REVIEW_SIDE_REVIEWER && in.GetApproverUserId() != in.GetActorUserId() {
		return nil, status.Error(codes.InvalidArgument, "a reviewer's thread is with the reviewer")
	}
	if in.GetApproverUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "approver required")
	}
	c.next++
	t := &corev1.ReviewThread{
		Id: fmt.Sprintf("thread-%d", c.next), PolicyVersionId: in.GetPolicyVersionId(), Quote: in.GetQuote(), Occurrence: in.GetOccurrence(),
		CreatedAt: timestamppb.New(time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)), ApproverUserId: in.GetApproverUserId(), CreatedBy: in.GetActorUserId(),
		Messages: []*corev1.ReviewMessage{{Id: "m-1", AuthorUserId: in.GetActorUserId(), Body: in.GetBody(), CreatedAt: timestamppb.New(time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC))}},
	}
	if text := strings.TrimSpace(in.GetSuggestedText()); text != "" && text != strings.TrimSpace(in.GetQuote()) {
		t.Suggestion = &corev1.ReviewSuggestion{Rounds: []*corev1.SuggestionRound{{Seq: 1, Side: in.GetActorSide(), UserId: in.GetActorUserId(), Text: text, CreatedAt: timestamppb.Now()}}}
		syncSuggestion(t.Suggestion)
	}
	c.threads = append(c.threads, t)
	return &corev1.AddReviewThreadResponse{Thread: t}, nil
}

func (c *reviewCore) ListReviewThreads(_ context.Context, in *corev1.ListReviewThreadsRequest, _ ...grpc.CallOption) (*corev1.ListReviewThreadsResponse, error) {
	c.calls = append(c.calls, "list "+in.GetApproverUserId())
	c.lastList = in
	out := []*corev1.ReviewThread{}
	for _, t := range c.threads {
		if t.GetPolicyVersionId() == in.GetPolicyVersionId() && (in.GetApproverUserId() == "" || t.GetApproverUserId() == in.GetApproverUserId()) {
			out = append(out, t)
		}
	}
	return &corev1.ListReviewThreadsResponse{Threads: out}, nil
}

func (c *reviewCore) act(op string, id, actor string, side corev1.ReviewSide) (*corev1.ReviewThread, error) {
	c.calls = append(c.calls, fmt.Sprintf("%s %s/%s", op, actor, side))
	t := c.thread(id)
	if t == nil {
		return nil, status.Error(codes.NotFound, "review thread not found")
	}
	if side == corev1.ReviewSide_REVIEW_SIDE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "bad side")
	}
	if side == corev1.ReviewSide_REVIEW_SIDE_REVIEWER && actor != t.GetApproverUserId() {
		return nil, status.Error(codes.PermissionDenied, "not the thread's approver")
	}
	return t, nil
}

func (c *reviewCore) ReplyReviewThread(_ context.Context, in *corev1.ReplyReviewThreadRequest, _ ...grpc.CallOption) (*corev1.ReplyReviewThreadResponse, error) {
	t, err := c.act("reply", in.GetThreadId(), in.GetActorUserId(), in.GetActorSide())
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.GetBody()) == "" {
		return nil, status.Error(codes.InvalidArgument, "blank body")
	}
	t.Messages = append(t.Messages, &corev1.ReviewMessage{Id: fmt.Sprintf("m-%d", len(t.Messages)+1), AuthorUserId: in.GetActorUserId(), Body: in.GetBody(), CreatedAt: timestamppb.Now()})
	return &corev1.ReplyReviewThreadResponse{Thread: t}, nil
}

func (c *reviewCore) SetReviewThreadResolved(_ context.Context, in *corev1.SetReviewThreadResolvedRequest, _ ...grpc.CallOption) (*corev1.SetReviewThreadResolvedResponse, error) {
	t, err := c.act("resolve", in.GetThreadId(), in.GetActorUserId(), in.GetActorSide())
	if err != nil {
		return nil, err
	}
	t.Resolved = in.GetResolved()
	return &corev1.SetReviewThreadResolvedResponse{Thread: t}, nil
}

func (c *reviewCore) DeleteReviewThread(_ context.Context, in *corev1.DeleteReviewThreadRequest, _ ...grpc.CallOption) (*corev1.DeleteReviewThreadResponse, error) {
	t, err := c.act("delete", in.GetThreadId(), in.GetActorUserId(), in.GetActorSide())
	if err != nil {
		return nil, err
	}
	if t.GetCreatedBy() != in.GetActorUserId() {
		return nil, status.Error(codes.PermissionDenied, "not the starter")
	}
	kept := c.threads[:0]
	for _, x := range c.threads {
		if x.GetId() != t.GetId() {
			kept = append(kept, x)
		}
	}
	c.threads = kept
	return &corev1.DeleteReviewThreadResponse{}, nil
}

// thrIdentity names the people in these tests.
type thrIdentity struct {
	identityv1.IdentityReadServiceClient
	names map[string]string
}

func (i thrIdentity) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	name, ok := i.names[in.GetUserId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such user")
	}
	return &identityv1.GetUserResponse{User: &identityv1.User{Id: in.GetUserId(), Name: name}}, nil
}

type thrEnv struct {
	core *reviewCore
	wf   *fakeWorkflowClient
	r    *resolvers.Resolver
}

// newThrEnv is the policy pol-1 owned by Bob, published version pol-1-v1, and a
// run on it whose first stage seats Charlie and Alice.
func newThrEnv(t *testing.T) *thrEnv {
	t.Helper()
	pc, gc, _ := breakGlassReadSetup(t, false)
	return buildThrEnv(pc, gc)
}

func buildThrEnv(pc *recordingPolicyClient, gc corev1.CategoryServiceClient) *thrEnv {
	pc.policies["pol-1"].OwnerUserId = thrAuthor
	core := &reviewCore{}
	wf := &fakeWorkflowClient{statusResp: &workflowv1.GetStatusResponse{
		RunId: "run-1", Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW, StageNames: []string{"Legal"},
		StageAssignees: []*workflowv1.StageAssignees{{Assignees: []*workflowv1.StageAssignee{
			{UserId: thrCharlie, State: "pending"}, {UserId: thrAlice, State: "pending"},
		}}},
	}}
	return &thrEnv{core: core, wf: wf, r: &resolvers.Resolver{
		ReviewClient: core, PolicyClient: pc, CategoryClient: gc, IdentityAdminClient: noGrant(), WorkflowClient: wf,
		IdentityClient: thrIdentity{names: map[string]string{thrAuthor: "Bob", thrCharlie: "Charlie", thrAlice: "Alice", "sa": "Site Admin"}},
		Log:            log.Nop(),
	}}
}

func thrCtx(t *testing.T, user string) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: user, RolesValue: []string{"reader"}})
}

func (e *thrEnv) add(t *testing.T, user string) *resolvers.ReviewThread {
	t.Helper()
	got, err := e.r.AddReviewThreadResolver(thrCtx(t, user), thrVersion, "seven years", 2, "What is this?", nil, nil)
	if err != nil {
		t.Fatalf("addReviewThread as %s: %v", user, err)
	}
	return got
}

func (e *thrEnv) list(t *testing.T, user string) []*resolvers.ReviewThread {
	t.Helper()
	got, err := e.r.ReviewThreadsResolver(thrCtx(t, user), thrVersion)
	if err != nil {
		t.Fatalf("reviewThreads as %s: %v", user, err)
	}
	if got == nil {
		t.Fatalf("reviewThreads as %s = nil, want an empty list: the field is non-null", user)
	}
	return got
}

func wantCode(t *testing.T, what string, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("%s: err = %v, want %s", what, err, want)
	}
}

func ids(ts []*resolvers.ReviewThread) []string {
	out := []string{}
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return out
}

// inline review threads

func TestReviewThreads_AnApproverStartsAThreadOnAQuoteAndWhichMatchOfIt(t *testing.T) {
	e := newThrEnv(t)
	got := e.add(t, thrCharlie)
	if got.Quote != "seven years" || got.Occurrence != 2 || got.Resolved {
		t.Fatalf("thread = %+v, want quote, occurrence 2, open", got)
	}
	if len(got.Messages) != 1 || got.Messages[0].Body != "What is this?" || got.Messages[0].AuthorUserID != thrCharlie {
		t.Fatalf("messages = %+v, want the first message by charlie", got.Messages)
	}
	if got.Messages[0].AuthorName == nil || *got.Messages[0].AuthorName != "Charlie" {
		t.Fatalf("authorName = %v, want Charlie from identity", got.Messages[0].AuthorName)
	}
	if got.PolicyVersionID != thrVersion || got.ApproverUserID != thrCharlie {
		t.Fatalf("thread = %+v, want the version and charlie as the approver", got)
	}
	// A reviewer acts as REVIEWER, for themselves, whatever the request named.
	if e.core.lastAdd.GetActorSide() != corev1.ReviewSide_REVIEW_SIDE_REVIEWER || e.core.lastAdd.GetApproverUserId() != thrCharlie || e.core.lastAdd.GetActorUserId() != thrCharlie {
		t.Fatalf("core was asked %+v, want charlie as the reviewer and the approver", e.core.lastAdd)
	}
}

func TestReviewThreads_TheDrafterListsTheVersionsThreads(t *testing.T) {
	e := newThrEnv(t)
	started := e.add(t, thrCharlie)
	got := e.list(t, thrAuthor)
	if len(got) != 1 || got[0].ID != started.ID {
		t.Fatalf("drafter sees %v, want the thread", ids(got))
	}
	if e.core.lastList.GetApproverUserId() != "" {
		t.Fatalf("core listed with filter %q, want none for the author side", e.core.lastList.GetApproverUserId())
	}
}

func TestReviewThreads_TheDrafterRepliesResolvesAndReopens(t *testing.T) {
	e := newThrEnv(t)
	started := e.add(t, thrCharlie)
	ctx := thrCtx(t, thrAuthor)

	reply, err := e.r.ReplyReviewThreadResolver(ctx, started.ID, "Fixed in the next draft.")
	if err != nil {
		t.Fatalf("replyReviewThread: %v", err)
	}
	if len(reply.Messages) != 2 || reply.Messages[0].Body != "What is this?" || reply.Messages[1].Body != "Fixed in the next draft." {
		t.Fatalf("messages = %+v, want both in order", reply.Messages)
	}
	if reply.Messages[1].AuthorName == nil || *reply.Messages[1].AuthorName != "Bob" {
		t.Fatalf("reply authorName = %v, want Bob", reply.Messages[1].AuthorName)
	}
	done, err := e.r.SetReviewThreadResolvedResolver(ctx, started.ID, true)
	if err != nil || !done.Resolved {
		t.Fatalf("resolve = %+v, %v; want resolved", done, err)
	}
	again, err := e.r.SetReviewThreadResolvedResolver(ctx, started.ID, false)
	if err != nil || again.Resolved {
		t.Fatalf("reopen = %+v, %v; want open", again, err)
	}
	for _, c := range e.core.calls[1:] { // the first call is charlie's add
		if !strings.Contains(c, thrAuthor+"/REVIEW_SIDE_AUTHOR") {
			t.Fatalf("core call %q, want the drafter acting on the AUTHOR side", c)
		}
	}
}

func TestReviewThreads_AnEmptyCommentAndAnEmptyQuoteAreRefused(t *testing.T) {
	e := newThrEnv(t)
	ctx := thrCtx(t, thrCharlie)
	_, err := e.r.AddReviewThreadResolver(ctx, thrVersion, "x", 1, "  ", nil, nil)
	wantCode(t, "empty comment", err, codes.InvalidArgument)
	_, err = e.r.AddReviewThreadResolver(ctx, thrVersion, " ", 1, "Why?", nil, nil)
	wantCode(t, "empty quote", err, codes.InvalidArgument)
	_, err = e.r.AddReviewThreadResolver(ctx, thrVersion, "x", 0, "Why?", nil, nil)
	wantCode(t, "occurrence under 1", err, codes.InvalidArgument)
	if len(e.core.threads) != 0 {
		t.Fatalf("core stored %d threads from refused requests", len(e.core.threads))
	}
	started := e.add(t, thrCharlie)
	_, err = e.r.ReplyReviewThreadResolver(ctx, started.ID, " ")
	wantCode(t, "empty reply", err, codes.InvalidArgument)
}

func TestReviewThreads_SomeoneOutsideTheReviewCannotStartOrAnswerAThread(t *testing.T) {
	e := newThrEnv(t)
	started := e.add(t, thrCharlie)
	before := len(e.core.calls)
	ctx := thrCtx(t, thrOutside)

	_, err := e.r.AddReviewThreadResolver(ctx, thrVersion, "seven years", 1, "Hi", nil, nil)
	wantCode(t, "outsider add", err, codes.PermissionDenied)
	_, err = e.r.ReplyReviewThreadResolver(ctx, started.ID, "Hi")
	wantCode(t, "outsider reply", err, codes.PermissionDenied)
	_, err = e.r.SetReviewThreadResolvedResolver(ctx, started.ID, true)
	wantCode(t, "outsider resolve", err, codes.PermissionDenied)
	_, err = e.r.DeleteReviewThreadResolver(ctx, started.ID)
	wantCode(t, "outsider delete", err, codes.PermissionDenied)
	if len(e.core.calls) != before {
		t.Fatalf("core received %v for a caller outside the review", e.core.calls[before:])
	}
	if got := e.list(t, thrOutside); len(got) != 0 {
		t.Fatalf("outsider sees %v, want nothing", ids(got))
	}
}

func TestReviewThreads_OnlyThePersonWhoStartedAThreadDeletesIt(t *testing.T) {
	e := newThrEnv(t)
	started := e.add(t, thrCharlie)
	if _, err := e.r.DeleteReviewThreadResolver(thrCtx(t, thrAuthor), started.ID); err == nil {
		t.Fatal("the drafter deleted a thread charlie started")
	}
	ok, err := e.r.DeleteReviewThreadResolver(thrCtx(t, thrCharlie), started.ID)
	if err != nil || !ok {
		t.Fatalf("starter delete = %v, %v; want true", ok, err)
	}
	if got := e.list(t, thrAuthor); len(got) != 0 {
		t.Fatalf("drafter still sees %v after the delete", ids(got))
	}
}

// whose thread it is

func TestReviewThreads_IsWithTheApproverWhoStartedItAndTheAuthorSeesWhoWroteIt(t *testing.T) {
	e := newThrEnv(t)
	started := e.add(t, thrCharlie)
	if started.ApproverUserID != thrCharlie {
		t.Fatalf("approverUserId = %q, want user-charlie", started.ApproverUserID)
	}
	seen := e.list(t, thrAuthor)
	if len(seen) != 1 || seen[0].ID != started.ID {
		t.Fatalf("author sees %v, want the thread", ids(seen))
	}
	m := seen[0].Messages[0]
	if m.AuthorUserID != thrCharlie || m.AuthorName == nil || *m.AuthorName != "Charlie" || m.Body != "What is this?" {
		t.Fatalf("author sees message %+v, want charlie's, with a name", m)
	}
}

func TestReviewThreads_IsNotShownToAnotherApproverOnTheSameStep(t *testing.T) {
	e := newThrEnv(t)
	e.add(t, thrCharlie)
	if got := e.list(t, thrAlice); len(got) != 0 {
		t.Fatalf("alice sees %v, want nothing", ids(got))
	}
	if e.core.lastList.GetApproverUserId() != thrAlice {
		t.Fatalf("core listed with filter %q, want the caller's own id", e.core.lastList.GetApproverUserId())
	}
	if got := e.list(t, thrCharlie); len(got) != 1 {
		t.Fatalf("charlie sees %v, want his thread", ids(got))
	}
}

func TestReviewThreads_CannotBeAnsweredResolvedOrDeletedByAnotherApprover(t *testing.T) {
	e := newThrEnv(t)
	started := e.add(t, thrCharlie)
	ctx := thrCtx(t, thrAlice)
	if _, err := e.r.ReplyReviewThreadResolver(ctx, started.ID, "Me too."); err == nil {
		t.Fatal("alice replied to charlie's thread")
	}
	if _, err := e.r.SetReviewThreadResolvedResolver(ctx, started.ID, true); err == nil {
		t.Fatal("alice resolved charlie's thread")
	}
	if _, err := e.r.DeleteReviewThreadResolver(ctx, started.ID); err == nil {
		t.Fatal("alice deleted charlie's thread")
	}
	// Alice is asked for as a REVIEWER, which core refuses; she is never promoted to the author side.
	for _, c := range e.core.calls[1:] {
		if strings.Contains(c, "AUTHOR") {
			t.Fatalf("core call %q: a seat holder must act as REVIEWER", c)
		}
	}
	if len(e.core.threads) != 1 || len(e.core.threads[0].Messages) != 1 || e.core.threads[0].Resolved {
		t.Fatal("the thread changed")
	}
}

func TestReviewThreads_TheAuthorWritesToOneApproverWhoAloneSeesIt(t *testing.T) {
	e := newThrEnv(t)
	to := thrCharlie
	got, err := e.r.AddReviewThreadResolver(thrCtx(t, thrAuthor), thrVersion, "seven years", 1, "Can you check this wording?", nil, &to)
	if err != nil {
		t.Fatalf("addReviewThread as the author: %v", err)
	}
	if got.ApproverUserID != thrCharlie {
		t.Fatalf("approverUserId = %q, want user-charlie", got.ApproverUserID)
	}
	if e.core.lastAdd.GetActorSide() != corev1.ReviewSide_REVIEW_SIDE_AUTHOR || e.core.lastAdd.GetActorUserId() != thrAuthor || e.core.lastAdd.GetApproverUserId() != thrCharlie {
		t.Fatalf("core was asked %+v, want bob as the author writing to charlie", e.core.lastAdd)
	}
	if n := len(e.list(t, thrCharlie)); n != 1 {
		t.Fatalf("charlie sees %d threads, want 1", n)
	}
	if n := len(e.list(t, thrAlice)); n != 0 {
		t.Fatalf("alice sees %d threads, want none", n)
	}
}

func TestReviewThreads_TheAuthorMustNameAnApproverWhoHasASeat(t *testing.T) {
	e := newThrEnv(t)
	ctx := thrCtx(t, thrAuthor)
	_, err := e.r.AddReviewThreadResolver(ctx, thrVersion, "seven years", 1, "Check?", nil, nil)
	wantCode(t, "no approver named", err, codes.InvalidArgument)
	blank := "  "
	_, err = e.r.AddReviewThreadResolver(ctx, thrVersion, "seven years", 1, "Check?", nil, &blank)
	wantCode(t, "blank approver", err, codes.InvalidArgument)
	stranger := thrOutside
	_, err = e.r.AddReviewThreadResolver(ctx, thrVersion, "seven years", 1, "Check?", nil, &stranger)
	wantCode(t, "approver without a seat", err, codes.InvalidArgument)
	if len(e.core.calls) != 0 {
		t.Fatalf("core received %v for a refused request", e.core.calls)
	}
}

// the gateway's own decisions

func TestReviewThreads_ASeatHolderWhoCanAlsoEditActsAsAReviewer(t *testing.T) {
	e := newThrEnv(t)
	e.wf.statusResp.StageAssignees[0].Assignees = append(e.wf.statusResp.StageAssignees[0].Assignees, &workflowv1.StageAssignee{UserId: thrAuthor, State: "pending"})
	got := e.add(t, thrAuthor)
	if got.ApproverUserID != thrAuthor || e.core.lastAdd.GetActorSide() != corev1.ReviewSide_REVIEW_SIDE_REVIEWER {
		t.Fatalf("thread %+v via %v, want bob acting as a reviewer on his own thread", got, e.core.lastAdd.GetActorSide())
	}
	// And so sees only his own threads.
	e.core.threads = append(e.core.threads, &corev1.ReviewThread{Id: "t-x", PolicyVersionId: thrVersion, ApproverUserId: thrCharlie})
	if n := len(e.list(t, thrAuthor)); n != 1 {
		t.Fatalf("bob sees %d threads, want only his own", n)
	}
}

func TestReviewThreads_AReaderOutsideTheReviewSeesNoThreadsAndCoreIsNotAsked(t *testing.T) {
	e := newThrEnv(t)
	e.add(t, thrCharlie)
	n := len(e.core.calls)
	if got := e.list(t, thrOutside); len(got) != 0 {
		t.Fatalf("outsider sees %v", ids(got))
	}
	if len(e.core.calls) != n {
		t.Fatalf("core was asked %v for a caller with no seat and no edit right", e.core.calls[n:])
	}
}

func TestReviewThreads_AVersionThatCannotBeReadIsNotFound(t *testing.T) {
	pc, gc, _ := breakGlassReadSetup(t, true) // the Admins group is denied the read
	e := buildThrEnv(pc, gc)
	e.core.threads = []*corev1.ReviewThread{{Id: "t-1", PolicyVersionId: thrVersion, ApproverUserId: "u-1"}}
	e.wf.statusResp.StageAssignees[0].Assignees[0].UserId = "u-1"
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", IdpGroupsValue: []string{"Admins"}})

	_, err := e.r.ReviewThreadsResolver(ctx, thrVersion)
	wantCode(t, "list", err, codes.NotFound)
	_, err = e.r.AddReviewThreadResolver(ctx, thrVersion, "q", 1, "b", nil, nil)
	wantCode(t, "add", err, codes.NotFound)
	_, err = e.r.ReplyReviewThreadResolver(ctx, "t-1", "b")
	wantCode(t, "reply", err, codes.NotFound)
	if len(e.core.calls) != 0 {
		t.Fatalf("core was asked %v for a policy the caller cannot read", e.core.calls)
	}
}

func TestReviewThreads_AnUnknownThreadIsNotFound(t *testing.T) {
	e := newThrEnv(t)
	ctx := thrCtx(t, thrCharlie)
	_, err := e.r.ReplyReviewThreadResolver(ctx, "nope", "b")
	wantCode(t, "reply", err, codes.NotFound)
	_, err = e.r.SetReviewThreadResolvedResolver(ctx, "nope", true)
	wantCode(t, "resolve", err, codes.NotFound)
	_, err = e.r.DeleteReviewThreadResolver(ctx, "nope")
	wantCode(t, "delete", err, codes.NotFound)
}

func TestReviewThreads_ACoreErrorOnTheThreadReadIsRelayed(t *testing.T) {
	e := newThrEnv(t)
	started := e.add(t, thrCharlie)
	n := len(e.core.calls)
	ctx := thrCtx(t, thrCharlie)
	for _, want := range []codes.Code{codes.InvalidArgument, codes.Unavailable} {
		e.core.getErr = status.Error(want, "core says no")
		_, err := e.r.ReplyReviewThreadResolver(ctx, started.ID, "b")
		wantCode(t, "reply", err, want)
		_, err = e.r.SetReviewThreadResolvedResolver(ctx, started.ID, true)
		wantCode(t, "resolve", err, want)
		_, err = e.r.DeleteReviewThreadResolver(ctx, started.ID)
		wantCode(t, "delete", err, want)
	}
	if len(e.core.calls) != n {
		t.Fatalf("core received writes %v although the thread could not be read", e.core.calls[n:])
	}
}

func TestReviewThreads_TheVersionComesFromCoreAndARefusedCallerMakesNoWrite(t *testing.T) {
	e := newThrEnv(t)
	started := e.add(t, thrCharlie)
	n := len(e.core.calls)
	if _, err := e.r.ReplyReviewThreadResolver(thrCtx(t, thrOutside), started.ID, "b"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("outsider reply err = %v, want PermissionDenied", err)
	}
	if len(e.core.reads) != 1 || e.core.reads[0] != started.ID || len(e.core.calls) != n {
		t.Fatalf("reads %v, writes %v: want one thread read and no write", e.core.reads, e.core.calls[n:])
	}
}

func TestReviewThreads_NeedASignedInCaller(t *testing.T) {
	e := newThrEnv(t)
	started := e.add(t, thrCharlie)
	n := len(e.core.calls)
	ctx := context.Background()
	_, err := e.r.ReviewThreadsResolver(ctx, thrVersion)
	wantCode(t, "list", err, codes.Unauthenticated)
	_, err = e.r.AddReviewThreadResolver(ctx, thrVersion, "q", 1, "b", nil, nil)
	wantCode(t, "add", err, codes.Unauthenticated)
	_, err = e.r.ReplyReviewThreadResolver(ctx, started.ID, "b")
	wantCode(t, "reply", err, codes.Unauthenticated)
	_, err = e.r.SetReviewThreadResolvedResolver(ctx, started.ID, true)
	wantCode(t, "resolve", err, codes.Unauthenticated)
	_, err = e.r.DeleteReviewThreadResolver(ctx, started.ID)
	wantCode(t, "delete", err, codes.Unauthenticated)
	if len(e.core.calls) != n {
		t.Fatalf("core was asked %v without a caller", e.core.calls[n:])
	}
}

func TestReviewThreads_AWorkflowFailureServesAndWritesNothing(t *testing.T) {
	e := newThrEnv(t)
	started := e.add(t, thrCharlie)
	n := len(e.core.calls)
	e.wf.statusResp, e.wf.statusErr = nil, status.Error(codes.Unavailable, "workflow down")
	ctx := thrCtx(t, thrCharlie)
	_, err := e.r.ReviewThreadsResolver(ctx, thrVersion)
	wantCode(t, "list", err, codes.Unavailable)
	_, err = e.r.AddReviewThreadResolver(ctx, thrVersion, "q", 1, "b", nil, nil)
	wantCode(t, "add", err, codes.Unavailable)
	_, err = e.r.ReplyReviewThreadResolver(ctx, started.ID, "b")
	wantCode(t, "reply", err, codes.Unavailable)
	if len(e.core.calls) != n {
		t.Fatalf("core was asked %v although the seat could not be checked", e.core.calls[n:])
	}
}

func TestReviewThreads_AVersionWithNoRunSeatsNobodyAndOnlyTheAuthorSideRemains(t *testing.T) {
	e := newThrEnv(t)
	e.wf.statusResp, e.wf.statusErr = nil, status.Error(codes.NotFound, "approval run not found")
	_, err := e.r.AddReviewThreadResolver(thrCtx(t, thrCharlie), thrVersion, "q", 1, "b", nil, nil)
	wantCode(t, "approver with no run", err, codes.PermissionDenied)
	to := thrCharlie
	_, err = e.r.AddReviewThreadResolver(thrCtx(t, thrAuthor), thrVersion, "q", 1, "b", nil, &to)
	wantCode(t, "author naming an approver with no run", err, codes.InvalidArgument)
	if len(e.core.calls) != 0 {
		t.Fatalf("core received %v", e.core.calls)
	}
}

func TestReviewThreads_AnObfuscatedReaderGetsNoMessageBodies(t *testing.T) {
	pc, gc, _ := breakGlassReadSetup(t, true) // the site admin sees this policy obfuscated
	e := buildThrEnv(pc, gc)
	e.core.threads = []*corev1.ReviewThread{{
		Id: "t-1", PolicyVersionId: thrVersion, Quote: "seven years", Occurrence: 1, ApproverUserId: thrCharlie, CreatedBy: thrCharlie,
		Messages: []*corev1.ReviewMessage{{Id: "m-1", AuthorUserId: thrCharlie, Body: "the secret clause", CreatedAt: timestamppb.Now()}},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "sa", RolesValue: []string{"site-admin"}, IdpGroupsValue: []string{"Admins"}})

	got, err := e.r.ReviewThreadsResolver(ctx, thrVersion)
	if err != nil || len(got) != 1 {
		t.Fatalf("reviewThreads = %v, %v; want the thread", ids(got), err)
	}
	m := got[0].Messages[0]
	if m.Body != "" || m.AuthorUserID != thrCharlie || m.AuthorName == nil {
		t.Fatalf("message = %+v, want no body but who wrote it", m)
	}
	reply, err := e.r.ReplyReviewThreadResolver(ctx, "t-1", "another secret")
	if err != nil {
		t.Fatalf("replyReviewThread: %v", err)
	}
	for _, msg := range reply.Messages {
		if msg.Body != "" {
			t.Fatalf("reply returned body %q to an obfuscated reader", msg.Body)
		}
	}
}
