// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"net"
	"sync"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	log "github.com/Bugs5382/go-log"

	collabv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/collab/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// publishDraft has to tell collab that the draft is published, or a
// live editing session never drops to read-only — it keeps accepting edits
// against a now-immutable version and then checkpoints them against a published
// one. slice D shipped the `draft.published` frame and its client
// handler, but nothing could send it.
//
// Every test here crosses a REAL gRPC connection into a real
// CollabRoomServiceServer, dialled with the same claim-forwarding interceptor
// the production backendDialOpts() baseline installs and served with the same
// claim-reconstructing interceptor collab installs. The two bugs this fixes
// both survived suites that injected state in-process, so "it crossed the wire"
// is the property under test — not "a mock was called".

// publishFakePolicy adds PublishDraft to the shared fakePolicyClient (whose own
// PublishDraft panics, since nothing exercised it before). Embedding keeps
// GetPolicy — which the effective-author gate needs — while shadowing just the
// one method, so no existing fake or test changes.
type publishFakePolicy struct {
	*fakePolicyClient

	version *corev1.PolicyVersion
	err     error
	// onPublish runs inside PublishDraft, after the call is recorded. It models
	// things that happen DURING the publish, e.g. the caller's HTTP request
	// being cancelled.
	onPublish func()

	mu    sync.Mutex
	calls []*corev1.PublishDraftRequest
}

func (f *publishFakePolicy) PublishDraft(_ context.Context, in *corev1.PublishDraftRequest, _ ...grpc.CallOption) (*corev1.PublishDraftResponse, error) {
	f.mu.Lock()
	f.calls = append(f.calls, in)
	f.mu.Unlock()
	if f.onPublish != nil {
		f.onPublish()
	}
	if f.err != nil {
		return nil, f.err
	}
	return &corev1.PublishDraftResponse{Version: f.version}, nil
}

func (f *publishFakePolicy) publishCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// roomSpy is a real CollabRoomServiceServer. It records each request together
// with the caller user id that the forwarded claims reconstructed on the server
// side, so a test can prove the caller's identity survived the hop.
type roomSpy struct {
	collabv1.UnimplementedCollabRoomServiceServer

	roomNotified bool
	err          error

	mu       sync.Mutex
	requests []*collabv1.NotifyDraftPublishedRequest
	actors   []string
}

func (s *roomSpy) NotifyDraftPublished(ctx context.Context, in *collabv1.NotifyDraftPublishedRequest) (*collabv1.NotifyDraftPublishedResponse, error) {
	actor := ""
	if a, ok := grpcactor.FromContext(ctx); ok {
		actor = a.Subject
	}
	s.mu.Lock()
	s.requests = append(s.requests, in)
	s.actors = append(s.actors, actor)
	s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return &collabv1.NotifyDraftPublishedResponse{RoomNotified: s.roomNotified}, nil
}

func (s *roomSpy) snapshot() ([]*collabv1.NotifyDraftPublishedRequest, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*collabv1.NotifyDraftPublishedRequest(nil), s.requests...),
		append([]string(nil), s.actors...)
}

// startRoomService stands spy up on an in-memory listener and returns a client
// dialled the way internal/backend dials collab: with the go-grpc-actor client
// interceptor. The server carries the go-grpc-actor server interceptor, as
// collab does, so the actor really is rebuilt from wire metadata.
func startRoomService(t *testing.T, spy collabv1.CollabRoomServiceServer) collabv1.CollabRoomServiceClient {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(grpcactor.UnaryServerInterceptor(grpcactor.WithTrust(trustAll))))
	collabv1.RegisterCollabRoomServiceServer(srv, spy)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return roomClientOver(t, func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	})
}

// roomClientOver builds a CollabRoomService client over an arbitrary dialer.
func roomClientOver(t *testing.T, dialer func(context.Context, string) (net.Conn, error)) collabv1.CollabRoomServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(grpcactor.UnaryClientInterceptor()),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return collabv1.NewCollabRoomServiceClient(conn)
}

// publishEnv builds the authorized-publisher environment: policy "pol" whose
// primary author is u-7, and a request context carrying u-7's claims.
func publishEnv(t *testing.T, published *corev1.PolicyVersion) (*publishFakePolicy, *raciCategoryClient, context.Context) {
	t.Helper()
	pc, gc := coAuthMatrixEnv("u-7", nil, nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-7", RolesValue: []string{"reader"}})
	return &publishFakePolicy{fakePolicyClient: pc, version: published}, gc, ctx
}

func publishedVersion() *corev1.PolicyVersion {
	// core promotes the draft ROW in place, so the published version's id IS
	// the draft id the collab room is keyed by.
	return &corev1.PolicyVersion{
		Id: "draft-1", PolicyId: "pol", VersionNo: 7,
		Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED,
	}
}

// TestPublishDraft_NotifiesCollabOverGRPC is the regression guard: a publish
// must reach collab, with the draft id / policy id / version number the room
// needs, and carrying the publisher's identity.
func TestPublishDraft_NotifiesCollabOverGRPC(t *testing.T) {
	spy := &roomSpy{roomNotified: true}
	rooms := startRoomService(t, spy)

	pc, gc, ctx := publishEnv(t, publishedVersion())

	got, err := resolvers.PublishDraft(ctx, log.Nop(), pc, gc, rooms, "pol")
	if err != nil {
		t.Fatalf("PublishDraft: %v", err)
	}
	if got == nil || got.ID != "draft-1" || got.VersionNo != 7 {
		t.Fatalf("published version: got %+v", got)
	}

	reqs, actors := spy.snapshot()
	if len(reqs) != 1 {
		t.Fatalf("collab notifications = %d, want 1: publishDraft did not tell collab, "+
			"so a live editing session would keep accepting edits against a published version", len(reqs))
	}
	if reqs[0].GetDraftId() != "draft-1" {
		t.Errorf("draft_id = %q, want draft-1 (the published version's id, which is the room key)", reqs[0].GetDraftId())
	}
	if reqs[0].GetPolicyId() != "pol" {
		t.Errorf("policy_id = %q, want pol", reqs[0].GetPolicyId())
	}
	if reqs[0].GetVersionNumber() != 7 {
		t.Errorf("version_number = %d, want 7", reqs[0].GetVersionNumber())
	}
	// collab authenticates this RPC on the forwarded claims. The notification
	// runs on a context rebuilt with context.WithoutCancel, which preserves
	// values — if that ever became a fresh context.Background() the claims
	// would vanish and collab would answer Unauthenticated.
	if actors[0] != "u-7" {
		t.Errorf("caller user id seen by collab = %q, want u-7: the publisher's claims did not survive the hop", actors[0])
	}
}

// TestPublishDraft_SucceedsWhenCollabErrors: the notification is best-effort.
// The publish has already committed in core by then, so a collab failure must
// not turn a live version into a client-visible error.
func TestPublishDraft_SucceedsWhenCollabErrors(t *testing.T) {
	spy := &roomSpy{err: status.Error(codes.Internal, "collab exploded")}
	rooms := startRoomService(t, spy)

	pc, gc, ctx := publishEnv(t, publishedVersion())

	got, err := resolvers.PublishDraft(ctx, log.Nop(), pc, gc, rooms, "pol")
	if err != nil {
		t.Fatalf("collab error failed the publish: %v — publishing must fail open on the notification", err)
	}
	if got == nil || got.ID != "draft-1" {
		t.Fatalf("published version: got %+v", got)
	}
	if reqs, _ := spy.snapshot(); len(reqs) != 1 {
		t.Fatalf("collab notifications = %d, want 1", len(reqs))
	}
}

// TestPublishDraft_SucceedsWhenCollabIsUnreachable proves fail-open against a
// genuinely dead endpoint rather than a mock that returns an error: the
// listener is closed before the call, so the dial itself fails.
func TestPublishDraft_SucceedsWhenCollabIsUnreachable(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	if err := lis.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	rooms := roomClientOver(t, func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	})

	pc, gc, ctx := publishEnv(t, publishedVersion())

	got, err := resolvers.PublishDraft(ctx, log.Nop(), pc, gc, rooms, "pol")
	if err != nil {
		t.Fatalf("an unreachable collab failed the publish: %v", err)
	}
	if got == nil || got.ID != "draft-1" {
		t.Fatalf("published version: got %+v", got)
	}
	if pc.publishCalls() != 1 {
		t.Fatalf("core publish calls = %d, want 1", pc.publishCalls())
	}
}

// TestPublishDraft_SucceedsWithNoCollabWired: dev/offline builds dial no collab,
// the same shape as a nil IdentityClient elsewhere in these resolvers.
func TestPublishDraft_SucceedsWithNoCollabWired(t *testing.T) {
	pc, gc, ctx := publishEnv(t, publishedVersion())

	got, err := resolvers.PublishDraft(ctx, log.Nop(), pc, gc, nil, "pol")
	if err != nil {
		t.Fatalf("PublishDraft with no collab client: %v", err)
	}
	if got == nil || got.ID != "draft-1" {
		t.Fatalf("published version: got %+v", got)
	}
}

// TestPublishDraft_NoLiveRoomIsNotAnError: collab reports room_notified=false
// when nobody is editing the draft. That is the everyday case and must not
// surface as a failure.
func TestPublishDraft_NoLiveRoomIsNotAnError(t *testing.T) {
	spy := &roomSpy{roomNotified: false}
	rooms := startRoomService(t, spy)

	pc, gc, ctx := publishEnv(t, publishedVersion())

	got, err := resolvers.PublishDraft(ctx, log.Nop(), pc, gc, rooms, "pol")
	if err != nil {
		t.Fatalf("room_notified=false failed the publish: %v", err)
	}
	if got == nil || got.ID != "draft-1" {
		t.Fatalf("published version: got %+v", got)
	}
}

// TestPublishDraft_NotifiesCollabEvenIfTheRequestWasCancelled: the caller's ctx
// is the GraphQL request context. If the browser goes away mid-publish, core
// has still committed — so the room must still be frozen. This is what
// context.WithoutCancel is for; on the request context alone the notification
// would be cancelled and the editor would never be told.
func TestPublishDraft_NotifiesCollabEvenIfTheRequestWasCancelled(t *testing.T) {
	spy := &roomSpy{roomNotified: true}
	rooms := startRoomService(t, spy)

	pc, gc, base := publishEnv(t, publishedVersion())
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	// The publish succeeds, and the caller disappears as it returns.
	pc.onPublish = cancel

	got, err := resolvers.PublishDraft(ctx, log.Nop(), pc, gc, rooms, "pol")
	if err != nil {
		t.Fatalf("PublishDraft: %v", err)
	}
	if got == nil || got.ID != "draft-1" {
		t.Fatalf("published version: got %+v", got)
	}
	reqs, actors := spy.snapshot()
	if len(reqs) != 1 {
		t.Fatalf("collab notifications = %d, want 1: a cancelled request context swallowed the "+
			"notification, so the room was never frozen after a committed publish", len(reqs))
	}
	if actors[0] != "u-7" {
		t.Errorf("caller user id seen by collab = %q, want u-7", actors[0])
	}
}

// TestPublishDraft_DoesNotNotifyCollabWhenCoreRefuses: the ordering contract.
// MarkPublished latches a room read-only irreversibly, so it must never run for
// a publish that did not happen.
func TestPublishDraft_DoesNotNotifyCollabWhenCoreRefuses(t *testing.T) {
	spy := &roomSpy{roomNotified: true}
	rooms := startRoomService(t, spy)

	pc, gc, ctx := publishEnv(t, nil)
	pc.err = status.Error(codes.FailedPrecondition, "no draft to publish")

	if _, err := resolvers.PublishDraft(ctx, log.Nop(), pc, gc, rooms, "pol"); err == nil {
		t.Fatal("expected the core publish error to propagate")
	}
	if reqs, _ := spy.snapshot(); len(reqs) != 0 {
		t.Fatalf("collab notifications = %d, want 0: a FAILED publish froze the room", len(reqs))
	}
}

// TestPublishDraft_UnauthorizedCallerNeverReachesCollab: the effective-author
// gate runs first, so an unauthorized caller neither publishes nor freezes.
func TestPublishDraft_UnauthorizedCallerNeverReachesCollab(t *testing.T) {
	spy := &roomSpy{roomNotified: true}
	rooms := startRoomService(t, spy)

	pc, gc := coAuthMatrixEnv("someone-else", nil, nil)
	pub := &publishFakePolicy{fakePolicyClient: pc, version: publishedVersion()}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-nobody", RolesValue: []string{"reader"}})

	_, err := resolvers.PublishDraft(ctx, log.Nop(), pub, gc, rooms, "pol")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status code = %v, want PermissionDenied (err: %v)", status.Code(err), err)
	}
	if pub.publishCalls() != 0 {
		t.Errorf("core publish calls = %d, want 0", pub.publishCalls())
	}
	if reqs, _ := spy.snapshot(); len(reqs) != 0 {
		t.Errorf("collab notifications = %d, want 0", len(reqs))
	}
}

// trustAll stands in for collab's caller check, which needs mTLS or a workload
// token the in-memory listener doesn't carry.
func trustAll(context.Context, string) bool { return true }
