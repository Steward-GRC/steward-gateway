// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	collabv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/collab/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// The appendix's own co-editing room (#126). Each test names the mock server
// test it ports (steward-mock-server src/product/appendix-collab.test.ts,
// "an appendix's room and token"), which is the acceptance list.

const apxRoomKey = "appendix:" + apxSeeded

// apxCallLog records the order of calls across the fakes below.
type apxCallLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *apxCallLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, s)
}

func (l *apxCallLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.calls)
}

// apxTokenFake is collab's CollabTokenService. IssueAppendixToken answers the
// way collab does: the room key and the escaped websocket path of the appendix.
type apxTokenFake struct {
	collabv1.CollabTokenServiceClient
	calls     int
	lastReq   *collabv1.IssueAppendixTokenRequest
	lastActor string
	resp      *collabv1.IssueAppendixTokenResponse
	err       error
}

func (f *apxTokenFake) IssueAppendixToken(ctx context.Context, in *collabv1.IssueAppendixTokenRequest, _ ...grpc.CallOption) (*collabv1.IssueAppendixTokenResponse, error) {
	f.calls++
	f.lastReq = in
	if a, ok := grpcactor.FromContext(ctx); ok {
		f.lastActor = a.Subject
	}
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &collabv1.IssueAppendixTokenResponse{
		Token:     "jwt-appendix",
		WsUrl:     "/collab/ws/appendix%3A" + in.GetAppendixId(),
		ExpiresAt: timestamppb.New(time.Date(2026, 11, 11, 12, 5, 0, 0, time.UTC)),
		RoomKey:   "appendix:" + in.GetAppendixId(),
		PolicyId:  apxPolicy,
	}, nil
}

// apxRoomFake is collab's CollabRoomService, logging into the shared order.
type apxRoomFake struct {
	collabv1.CollabRoomServiceClient
	order     *apxCallLog
	flushErr  error
	notifyErr error
	flushes   []*collabv1.FlushDraftRequest
	notifies  []*collabv1.NotifyDraftPublishedRequest
}

func (f *apxRoomFake) FlushDraft(_ context.Context, in *collabv1.FlushDraftRequest, _ ...grpc.CallOption) (*collabv1.FlushDraftResponse, error) {
	f.order.add("flush")
	f.flushes = append(f.flushes, in)
	if f.flushErr != nil {
		return nil, f.flushErr
	}
	return &collabv1.FlushDraftResponse{RoomFound: true, ContentFlushed: true}, nil
}

func (f *apxRoomFake) NotifyDraftPublished(_ context.Context, in *collabv1.NotifyDraftPublishedRequest, _ ...grpc.CallOption) (*collabv1.NotifyDraftPublishedResponse, error) {
	f.order.add("notify")
	f.notifies = append(f.notifies, in)
	if f.notifyErr != nil {
		return nil, f.notifyErr
	}
	return &collabv1.NotifyDraftPublishedResponse{RoomNotified: true}, nil
}

// apxOrderCore is the in-memory core with the publish call logged into the
// shared order.
type apxOrderCore struct {
	*appendixCore
	order      *apxCallLog
	publishErr error
}

func (c *apxOrderCore) PublishAppendix(ctx context.Context, in *corev1.PublishAppendixRequest, opts ...grpc.CallOption) (*corev1.PublishAppendixResponse, error) {
	c.order.add("publish")
	if c.publishErr != nil {
		return nil, c.publishErr
	}
	return c.appendixCore.PublishAppendix(ctx, in, opts...)
}

// withCollab wires a token fake and a room fake onto the env's resolver, with
// core's publish logged into the same order as the room calls.
func (e *apxEnv) withCollab() (*apxTokenFake, *apxRoomFake, *apxCallLog) {
	order := &apxCallLog{}
	tok := &apxTokenFake{}
	room := &apxRoomFake{order: order}
	e.r.CollabClient = tok
	e.r.CollabRoomClient = room
	e.r.PolicyAppendixClient = &apxOrderCore{appendixCore: e.core, order: order}
	return tok, room, order
}

// mock: "is issued to someone who can edit the policy, for the appendix's own path"
func TestIssueAppendixCollabToken_IssuedToEditorForOwnPath(t *testing.T) {
	for _, user := range []string{"bob", "alice"} { // the author and a site admin
		e := newApxEnv(t)
		tok, _, _ := e.withCollab()
		got, err := e.r.Mutation().IssueAppendixCollabToken(apxCtx(t, user), apxSeeded)
		if err != nil {
			t.Fatalf("as %s: %v", user, err)
		}
		if got.Token != "jwt-appendix" || got.ExpiresAt != "2026-11-11T12:05:00Z" {
			t.Fatalf("as %s: token %q expires %q", user, got.Token, got.ExpiresAt)
		}
		if got.WsURL != "/collab/ws/appendix%3A"+apxSeeded {
			t.Fatalf("as %s: wsUrl = %q, want the appendix's escaped path", user, got.WsURL)
		}
		// collab is asked for the appendix only, as the signed-in user
		if tok.lastReq.GetAppendixId() != apxSeeded || tok.lastActor != user {
			t.Fatalf("as %s: collab saw appendix %q actor %q", user, tok.lastReq.GetAppendixId(), tok.lastActor)
		}
	}
}

// mock: "is refused to a reader, and for an appendix that does not exist"
func TestIssueAppendixCollabToken_RefusedToReaderCollabNotAsked(t *testing.T) {
	e := newApxEnv(t)
	tok, _, _ := e.withCollab()
	before := e.core.writes
	_, err := e.r.Mutation().IssueAppendixCollabToken(apxCtx(t, "erin"), apxSeeded)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if tok.calls != 0 || e.core.writes != before {
		t.Fatalf("collab asked %d times, core writes %d -> %d", tok.calls, before, e.core.writes)
	}
}

// mock: "is refused to a reader, and for an appendix that does not exist"
func TestIssueAppendixCollabToken_UnknownAppendixNotFound(t *testing.T) {
	e := newApxEnv(t)
	tok, _, _ := e.withCollab()
	_, err := e.r.Mutation().IssueAppendixCollabToken(apxCtx(t, "bob"), "nope")
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
	if tok.calls != 0 {
		t.Fatal("collab was asked for a token for an unknown appendix")
	}
}

// mock: "is refused for a retired appendix"
func TestIssueAppendixCollabToken_RetiredFailedPreconditionBeforeCollab(t *testing.T) {
	e := newApxEnv(t)
	tok, _, _ := e.withCollab()
	e.core.find0(apxSeeded).retired = true
	_, err := e.r.Mutation().IssueAppendixCollabToken(apxCtx(t, "bob"), apxSeeded)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if tok.calls != 0 {
		t.Fatal("collab was asked for a token for a retired appendix")
	}
	// a reader still learns nothing: the edit check comes first
	_, err = e.r.Mutation().IssueAppendixCollabToken(apxCtx(t, "erin"), apxSeeded)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("reader on a retired appendix: err = %v, want PermissionDenied", err)
	}
}

// mock: "does not open the policy's own room: a token names its own room only"
func TestIssueAppendixCollabToken_NamesOwnRoomNotThePolicys(t *testing.T) {
	e := newApxEnv(t)
	tok, _, _ := e.withCollab()
	got, err := e.r.Mutation().IssueAppendixCollabToken(apxCtx(t, "bob"), apxSeeded)
	if err != nil {
		t.Fatal(err)
	}
	// the request names the appendix and nothing of the policy or a draft
	if tok.lastReq.GetAppendixId() != apxSeeded {
		t.Fatalf("collab request = %v", tok.lastReq)
	}
	if !strings.HasSuffix(got.WsURL, "appendix%3A"+apxSeeded) {
		t.Fatalf("wsUrl = %q, want the appendix room path", got.WsURL)
	}
	for _, other := range []string{apxPolicy, "version-2", "pol-1-v1"} {
		if strings.Contains(got.WsURL, other) {
			t.Fatalf("wsUrl %q names %q, the policy's room", got.WsURL, other)
		}
	}
}

// gateway: signing in is required and nobody is asked without it.
func TestIssueAppendixCollabToken_NeedsSignIn(t *testing.T) {
	e := newApxEnv(t)
	tok, _, _ := e.withCollab()
	_, err := e.r.Mutation().IssueAppendixCollabToken(t.Context(), apxSeeded)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
	if tok.calls != 0 {
		t.Fatal("collab was asked without a signed-in user")
	}
}

// gateway: with no collab wired the call is Unavailable, not a panic.
func TestIssueAppendixCollabToken_NoCollabIsUnavailable(t *testing.T) {
	e := newApxEnv(t)
	_, err := e.r.Mutation().IssueAppendixCollabToken(apxCtx(t, "bob"), apxSeeded)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}

// gateway: each refusal collab can return reaches the caller with its gRPC
// code (the GraphQL kind) and its message, as collab sent it.
func TestIssueAppendixCollabToken_CollabErrorsPassThrough(t *testing.T) {
	cases := []struct {
		reason string
		code   codes.Code
	}{
		{"APPENDIX_ID_REQUIRED", codes.InvalidArgument},
		{"APPENDIX_NOT_FOUND", codes.NotFound},
		{"DRAFT_EDIT_FORBIDDEN", codes.PermissionDenied},
		{"APPENDIX_RETIRED", codes.FailedPrecondition},
		{"POLICY_NOT_FOUND", codes.NotFound},
		{"EDIT_CHECK_UNAVAILABLE", codes.Unavailable},
		{"ACTOR_REQUIRED", codes.Unauthenticated},
	}
	for _, c := range cases {
		t.Run(c.reason, func(t *testing.T) {
			e := newApxEnv(t)
			tok, _, _ := e.withCollab()
			tok.err = status.Error(c.code, c.reason)
			_, err := e.r.Mutation().IssueAppendixCollabToken(apxCtx(t, "bob"), apxSeeded)
			if status.Code(err) != c.code {
				t.Fatalf("code = %v, want %v (err %v)", status.Code(err), c.code, err)
			}
			if status.Convert(err).Message() != c.reason {
				t.Fatalf("message = %q, want collab's %q", status.Convert(err).Message(), c.reason)
			}
		})
	}
}

// publishableApx saves a draft on the seeded appendix so a publish has a
// version 2 to cut.
func publishableApx(t *testing.T, e *apxEnv) {
	t.Helper()
	e.save(t, "bob", apxSeeded, "Per-diem rates", `{"root":{"children":[{"type":"text","text":"Changed."}]}}`)
}

// gateway: publishing flushes the appendix's room, publishes in core, then
// freezes the room, in that order, keyed by the room key.
func TestPublishAppendix_FlushesPublishesThenNotifiesInOrder(t *testing.T) {
	e := newApxEnv(t)
	_, room, order := e.withCollab()
	publishableApx(t, e)
	got := e.publish(t, "bob", apxSeeded)
	if want := []string{"flush", "publish", "notify"}; !slices.Equal(order.snapshot(), want) {
		t.Fatalf("call order = %v, want %v", order.snapshot(), want)
	}
	if len(room.flushes) != 1 || room.flushes[0].GetDraftId() != apxRoomKey || room.flushes[0].GetPolicyId() != apxPolicy {
		t.Fatalf("flush = %v", room.flushes)
	}
	if len(room.notifies) != 1 {
		t.Fatalf("notify calls = %d", len(room.notifies))
	}
	n := room.notifies[0]
	if n.GetDraftId() != apxRoomKey || n.GetPolicyId() != apxPolicy || n.GetVersionNumber() != 2 {
		t.Fatalf("notify = draft %q policy %q version %d, want %q, %q, 2", n.GetDraftId(), n.GetPolicyId(), n.GetVersionNumber(), apxRoomKey, apxPolicy)
	}
	if got.Published == nil || got.Published.VersionNo != 2 {
		t.Fatalf("published = %v", got.Published)
	}
}

// gateway: a failed flush is logged, the appendix is still published and the
// room is still told.
func TestPublishAppendix_FlushFailureDoesNotSkipPublish(t *testing.T) {
	e := newApxEnv(t)
	_, room, order := e.withCollab()
	room.flushErr = status.Error(codes.Unavailable, "collab down")
	publishableApx(t, e)
	got, err := e.r.Mutation().PublishAppendix(apxCtx(t, "bob"), apxSeeded)
	if err != nil {
		t.Fatalf("publish after a failed flush: %v", err)
	}
	if got.Published == nil || got.Published.VersionNo != 2 {
		t.Fatalf("published = %v", got.Published)
	}
	if want := []string{"flush", "publish", "notify"}; !slices.Equal(order.snapshot(), want) {
		t.Fatalf("call order = %v, want %v", order.snapshot(), want)
	}
}

// gateway: a failed notify never turns a successful publish into an error.
func TestPublishAppendix_NotifyFailureStillSucceeds(t *testing.T) {
	e := newApxEnv(t)
	_, room, _ := e.withCollab()
	room.notifyErr = status.Error(codes.DeadlineExceeded, "slow")
	publishableApx(t, e)
	got, err := e.r.Mutation().PublishAppendix(apxCtx(t, "bob"), apxSeeded)
	if err != nil || got.Published == nil || got.Published.VersionNo != 2 {
		t.Fatalf("publish = %v, %v", got, err)
	}
}

// gateway: when core refuses the publish the room is not frozen.
func TestPublishAppendix_CoreFailureDoesNotNotify(t *testing.T) {
	e := newApxEnv(t)
	_, _, order := e.withCollab()
	e.r.PolicyAppendixClient.(*apxOrderCore).publishErr = status.Error(codes.FailedPrecondition, "no draft")
	_, err := e.r.Mutation().PublishAppendix(apxCtx(t, "bob"), apxSeeded)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if want := []string{"flush", "publish"}; !slices.Equal(order.snapshot(), want) {
		t.Fatalf("call order = %v, want %v", order.snapshot(), want)
	}
}

// gateway: a reader's publish never reaches the room or core.
func TestPublishAppendix_ReaderNeverTouchesTheRoom(t *testing.T) {
	e := newApxEnv(t)
	_, _, order := e.withCollab()
	publishableApx(t, e)
	_, err := e.r.Mutation().PublishAppendix(apxCtx(t, "erin"), apxSeeded)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if got := order.snapshot(); len(got) != 0 {
		t.Fatalf("calls = %v, want none", got)
	}
}
