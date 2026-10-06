// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	golog "github.com/Bugs5382/go-log"

	"github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	collabv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/collab/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// A publish cuts the version from whatever core's draft row holds. Keystrokes
// that reached the live collab room since its last debounced checkpoint are
// not there yet, so publishDraft has to flush the room first. The order is
// flush, then core PublishDraft, then the freeze.

// callLog records the cross-service calls of one publish in the order they
// happened, across the core fake and the collab spy.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *callLog) add(call string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, call)
}

func (l *callLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

// flushRoomSpy is a real CollabRoomServiceServer serving both room RPCs.
type flushRoomSpy struct {
	collabv1.UnimplementedCollabRoomServiceServer

	log       *callLog
	roomFound bool
	flushErr  error

	mu      sync.Mutex
	flushes []*collabv1.FlushDraftRequest
	actors  []string
	frozen  int
}

func (s *flushRoomSpy) FlushDraft(ctx context.Context, in *collabv1.FlushDraftRequest) (*collabv1.FlushDraftResponse, error) {
	s.log.add("flush")
	actor := ""
	if a, ok := grpcactor.FromContext(ctx); ok {
		actor = a.Subject
	}
	s.mu.Lock()
	s.flushes = append(s.flushes, in)
	s.actors = append(s.actors, actor)
	s.mu.Unlock()
	if s.flushErr != nil {
		return nil, s.flushErr
	}
	return &collabv1.FlushDraftResponse{RoomFound: s.roomFound, ContentFlushed: s.roomFound}, nil
}

func (s *flushRoomSpy) NotifyDraftPublished(_ context.Context, _ *collabv1.NotifyDraftPublishedRequest) (*collabv1.NotifyDraftPublishedResponse, error) {
	s.log.add("notify")
	s.mu.Lock()
	s.frozen++
	s.mu.Unlock()
	return &collabv1.NotifyDraftPublishedResponse{RoomNotified: s.roomFound}, nil
}

func (s *flushRoomSpy) flushCalls() ([]*collabv1.FlushDraftRequest, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*collabv1.FlushDraftRequest(nil), s.flushes...), append([]string(nil), s.actors...)
}

func (s *flushRoomSpy) notifyCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frozen
}

// flushEnv is publishEnv with a working draft on the policy, so there is a room
// key to flush, and with core's publish recorded on log.
func flushEnv(t *testing.T, log *callLog) (*publishFakePolicy, *raciCategoryClient, context.Context) {
	t.Helper()
	pc, gc, ctx := publishEnv(t, publishedVersion())
	pc.policies["pol"].CurrentDraftVersionId = "draft-1"
	pc.onPublish = func() { log.add("publish") }
	return pc, gc, ctx
}

func codedInfo(t *testing.T, err error) apperrgrpc.Info {
	t.Helper()
	info, ok := apperrgrpc.FromStatus(gatewayStatus(err))
	if !ok {
		t.Fatalf("error carries no coded ErrorInfo: %v", err)
	}
	return info
}

func TestPublishDraft_FlushesTheLiveRoomBeforePublishing(t *testing.T) {
	log := &callLog{}
	spy := &flushRoomSpy{log: log, roomFound: true}
	rooms := startRoomService(t, spy)
	pc, gc, ctx := flushEnv(t, log)

	got, err := resolvers.PublishDraft(ctx, golog.Nop(), pc, gc, rooms, "pol")
	if err != nil {
		t.Fatalf("PublishDraft: %v", err)
	}
	if got == nil || got.ID != "draft-1" {
		t.Fatalf("published version: got %+v", got)
	}

	if order := strings.Join(log.snapshot(), ","); order != "flush,publish,notify" {
		t.Fatalf("call order = %s, want flush,publish,notify", order)
	}
	reqs, actors := spy.flushCalls()
	if len(reqs) != 1 {
		t.Fatalf("flush calls = %d, want 1", len(reqs))
	}
	if reqs[0].GetDraftId() != "draft-1" {
		t.Errorf("flush draft_id = %q, want draft-1 (the policy's current_draft_version_id)", reqs[0].GetDraftId())
	}
	if reqs[0].GetPolicyId() != "pol" {
		t.Errorf("flush policy_id = %q, want pol", reqs[0].GetPolicyId())
	}
	if actors[0] != "u-7" {
		t.Errorf("caller user id seen by collab on flush = %q, want u-7", actors[0])
	}
}

func TestPublishDraft_NoLiveRoomToFlushStillPublishes(t *testing.T) {
	log := &callLog{}
	spy := &flushRoomSpy{log: log, roomFound: false}
	rooms := startRoomService(t, spy)
	pc, gc, ctx := flushEnv(t, log)

	got, err := resolvers.PublishDraft(ctx, golog.Nop(), pc, gc, rooms, "pol")
	if err != nil {
		t.Fatalf("room_found=false blocked the publish: %v", err)
	}
	if got == nil || got.ID != "draft-1" {
		t.Fatalf("published version: got %+v", got)
	}
	if order := strings.Join(log.snapshot(), ","); order != "flush,publish,notify" {
		t.Fatalf("call order = %s, want flush,publish,notify", order)
	}
}

func TestPublishDraft_FlushFailureBlocksThePublish(t *testing.T) {
	cases := []struct {
		name     string
		flushErr error
		wantGRPC codes.Code
		wantCode apperr.Entry
		wantMsg  string
	}{
		{
			name:     "collab could not reach core",
			flushErr: status.Error(codes.Unavailable, "core did not answer the collab room flush: connection refused"),
			wantGRPC: codes.Unavailable,
			wantCode: gatewayEntry(errcodes.CodeCollabFlushUnavailable),
		},
		{
			name:     "core answered too slowly",
			flushErr: status.Error(codes.DeadlineExceeded, "core did not answer the collab room flush: context deadline exceeded"),
			wantGRPC: codes.Unavailable,
			wantCode: gatewayEntry(errcodes.CodeCollabFlushUnavailable),
		},
		{
			name:     "core refused the room's content",
			flushErr: status.Error(codes.FailedPrecondition, "core did not accept the live room's content: title is required"),
			wantGRPC: codes.FailedPrecondition,
			wantCode: gatewayEntry(errcodes.CodeCollabFlushRejected),
			wantMsg:  "core did not accept the live room's content: title is required",
		},
		{
			name:     "room belongs to another policy",
			flushErr: status.Error(codes.FailedPrecondition, "draft does not belong to the given policy"),
			wantGRPC: codes.FailedPrecondition,
			wantCode: gatewayEntry(errcodes.CodeCollabFlushRejected),
			wantMsg:  "draft does not belong to the given policy",
		},
		{
			name:     "collab fault",
			flushErr: status.Error(codes.Internal, "flush collab room"),
			wantGRPC: codes.Internal,
			wantCode: gatewayEntry(errcodes.CodeCollabFlushFailed),
		},
		{
			name:     "collab without FlushDraft",
			flushErr: status.Error(codes.Unimplemented, "method FlushDraft not implemented"),
			wantGRPC: codes.Internal,
			wantCode: gatewayEntry(errcodes.CodeCollabFlushFailed),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := &callLog{}
			spy := &flushRoomSpy{log: log, roomFound: true, flushErr: tc.flushErr}
			rooms := startRoomService(t, spy)
			pc, gc, ctx := flushEnv(t, log)

			_, err := resolvers.PublishDraft(ctx, golog.Nop(), pc, gc, rooms, "pol")
			if err == nil {
				t.Fatal("a failed flush let the publish through; the version would be cut from stale content")
			}
			if got := gatewayStatus(err).Code(); got != tc.wantGRPC {
				t.Errorf("gRPC code = %v, want %v", got, tc.wantGRPC)
			}
			info := codedInfo(t, err)
			if info.Code != tc.wantCode.Code || info.Symbol != tc.wantCode.Symbol || info.Domain != "gateway" {
				t.Errorf("coded error = %d %s (%s), want %d %s (gateway)", info.Code, info.Symbol, info.Domain, tc.wantCode.Code, tc.wantCode.Symbol)
			}
			if tc.wantMsg != "" {
				if !strings.Contains(gatewayStatus(err).Message(), tc.wantMsg) {
					t.Errorf("message = %q, want it to carry %q", gatewayStatus(err).Message(), tc.wantMsg)
				}
				if info.Metadata["reason"] != tc.wantMsg {
					t.Errorf("metadata reason = %q, want %q", info.Metadata["reason"], tc.wantMsg)
				}
			}
			if pc.publishCalls() != 0 {
				t.Errorf("core publish calls = %d, want 0", pc.publishCalls())
			}
			if spy.notifyCalls() != 0 {
				t.Errorf("freeze calls = %d, want 0", spy.notifyCalls())
			}
		})
	}
}

func TestPublishDraft_UnreachableCollabBlocksWithARetryableCode(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	if err := lis.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	rooms := roomClientOver(t, func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	})
	pc, gc, ctx := flushEnv(t, &callLog{})

	_, err := resolvers.PublishDraft(ctx, golog.Nop(), pc, gc, rooms, "pol")
	if err == nil {
		t.Fatal("an unreachable collab let a publish with a live draft through")
	}
	if info := codedInfo(t, err); info.Code != gatewayEntry(errcodes.CodeCollabFlushUnavailable).Code {
		t.Fatalf("codeNum = %d, want %d", info.Code, gatewayEntry(errcodes.CodeCollabFlushUnavailable).Code)
	}
	if pc.publishCalls() != 0 {
		t.Fatalf("core publish calls = %d, want 0", pc.publishCalls())
	}
}

func TestPublishDraft_NoCollabWiredSkipsTheFlush(t *testing.T) {
	log := &callLog{}
	pc, gc, ctx := flushEnv(t, log)

	got, err := resolvers.PublishDraft(ctx, golog.Nop(), pc, gc, nil, "pol")
	if err != nil {
		t.Fatalf("PublishDraft with no collab client: %v", err)
	}
	if got == nil || got.ID != "draft-1" {
		t.Fatalf("published version: got %+v", got)
	}
	if order := strings.Join(log.snapshot(), ","); order != "publish" {
		t.Fatalf("call order = %s, want publish only", order)
	}
}

func TestPublishDraft_NoWorkingDraftSkipsTheFlush(t *testing.T) {
	log := &callLog{}
	spy := &flushRoomSpy{log: log}
	rooms := startRoomService(t, spy)
	pc, gc, ctx := flushEnv(t, log)
	pc.policies["pol"].CurrentDraftVersionId = ""
	pc.err = status.Error(codes.FailedPrecondition, "no draft to publish")

	_, err := resolvers.PublishDraft(ctx, golog.Nop(), pc, gc, rooms, "pol")
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "no draft to publish" {
		t.Fatalf("err = %v, want core's own refusal", err)
	}
	if reqs, _ := spy.flushCalls(); len(reqs) != 0 {
		t.Fatalf("flush calls = %d, want 0: there is no draft id to key a room by", len(reqs))
	}
}

func TestPublishDraft_UnauthorizedCallerNeverFlushes(t *testing.T) {
	log := &callLog{}
	spy := &flushRoomSpy{log: log, roomFound: true}
	rooms := startRoomService(t, spy)

	pc, gc := coAuthMatrixEnv("someone-else", nil, nil)
	pc.policies["pol"].CurrentDraftVersionId = "draft-1"
	pub := &publishFakePolicy{fakePolicyClient: pc, version: publishedVersion()}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-nobody", RolesValue: []string{"reader"}})

	_, err := resolvers.PublishDraft(ctx, golog.Nop(), pub, gc, rooms, "pol")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status code = %v, want PermissionDenied (err: %v)", status.Code(err), err)
	}
	if calls := log.snapshot(); len(calls) != 0 {
		t.Fatalf("calls = %v, want none before the author gate passes", calls)
	}
}
