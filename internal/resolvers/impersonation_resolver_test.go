// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/bff"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// ---- fakes -----------------------------------------------------------------

// fakeImpStore is a minimal in-memory bff.SessionStore for the impersonation
// resolver tests. Only Get/Save are exercised; the lock/create/delete methods
// satisfy the interface.
type fakeImpStore struct {
	sessions  map[string]bff.Session
	getErr    error
	saveErr   error
	saveCalls int
}

func newFakeImpStore() *fakeImpStore {
	return &fakeImpStore{sessions: map[string]bff.Session{}}
}

func (f *fakeImpStore) Get(_ context.Context, id string) (bff.Session, bool, error) {
	if f.getErr != nil {
		return bff.Session{}, false, f.getErr
	}
	s, ok := f.sessions[id]
	return s, ok, nil
}

func (f *fakeImpStore) Save(_ context.Context, id string, sess bff.Session) error {
	f.saveCalls++
	if f.saveErr != nil {
		return f.saveErr
	}
	f.sessions[id] = sess
	return nil
}

func (f *fakeImpStore) Create(ctx context.Context, id string, sess bff.Session) error {
	return f.Save(ctx, id, sess)
}
func (f *fakeImpStore) Delete(_ context.Context, id string) error { delete(f.sessions, id); return nil }
func (f *fakeImpStore) AcquireRefreshLock(context.Context, string, time.Duration) (string, bool, error) {
	return "", false, nil
}
func (f *fakeImpStore) ReleaseRefreshLock(context.Context, string, string) error { return nil }

// fakeImpIdentity is a focused GetUser fake for target validation.
type fakeImpIdentity struct {
	identityv1.IdentityReadServiceClient
	users map[string]*identityv1.User
	err   error
}

func (f *fakeImpIdentity) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	u, ok := f.users[in.GetUserId()]
	if !ok {
		return &identityv1.GetUserResponse{}, nil
	}
	return &identityv1.GetUserResponse{User: u}, nil
}

// fakeAuditSink records emitted lifecycle events.
type fakeAuditSink struct{ events []*auditv1.AuditEvent }

func (f *fakeAuditSink) Emit(_ context.Context, ev *auditv1.AuditEvent) error {
	f.events = append(f.events, ev)
	return nil
}

// ---- helpers ---------------------------------------------------------------

func impAdminCtx(userID string, roles ...string) context.Context {
	return principal.WithClaims(context.Background(), principal.Static{
		UserIDValue: userID,
		RolesValue:  roles,
	})
}

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func enabledUser(id, name string, roles []string, root bool) *identityv1.User {
	return &identityv1.User{Id: id, Name: name, Roles: roles, Enabled: true, IsRoot: root}
}

const testAdminSID = "sess-admin"

func codeOf(t *testing.T, err error) codes.Code {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	return wireStatus(err).Code()
}

// infoOf recovers the ErrorInfo (symbol and code) the client sees for a coded
// gate error, proving it is a registry code and not a bare status.
func infoOf(t *testing.T, err error) apperrgrpc.Info {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	info, ok := apperrgrpc.FromStatus(wireStatus(err))
	if !ok {
		t.Fatalf("status carries no ErrorInfo: %v", err)
	}
	return info
}

// ---- start: guardrails -----------------------------------------------------

func TestStartImpersonation_NonSiteAdminDenied(t *testing.T) {
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{UserID: "u-caller"}
	id := &fakeImpIdentity{users: map[string]*identityv1.User{
		"u-target": enabledUser("u-target", "Target", []string{"author"}, false),
	}}
	ctx := impAdminCtx("u-caller", "author") // not site-admin

	_, err := resolvers.StartImpersonationResolver(ctx, store, testAdminSID, id, &fakeAuditSink{}, fixedNow(time.Now()), "u-target", "debugging")
	if got := codeOf(t, err); got != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v (%v)", got, err)
	}
}

func TestStartImpersonation_SiteAdminTargetDenied(t *testing.T) {
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{UserID: "u-admin"}
	id := &fakeImpIdentity{users: map[string]*identityv1.User{
		"u-target": enabledUser("u-target", "Other Admin", []string{"site-admin"}, false),
	}}
	ctx := impAdminCtx("u-admin", "site-admin")

	_, err := resolvers.StartImpersonationResolver(ctx, store, testAdminSID, id, &fakeAuditSink{}, fixedNow(time.Now()), "u-target", "debugging")
	if got := codeOf(t, err); got != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied for site-admin target, got %v (%v)", got, err)
	}
}

func TestStartImpersonation_RootTargetDenied(t *testing.T) {
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{UserID: "u-admin"}
	id := &fakeImpIdentity{users: map[string]*identityv1.User{
		"u-target": enabledUser("u-target", "Root", nil, true),
	}}
	ctx := impAdminCtx("u-admin", "site-admin")

	_, err := resolvers.StartImpersonationResolver(ctx, store, testAdminSID, id, &fakeAuditSink{}, fixedNow(time.Now()), "u-target", "debugging")
	if got := codeOf(t, err); got != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied for root target, got %v (%v)", got, err)
	}
}

func TestStartImpersonation_EmptyReasonRejected(t *testing.T) {
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{UserID: "u-admin"}
	id := &fakeImpIdentity{users: map[string]*identityv1.User{
		"u-target": enabledUser("u-target", "Target", []string{"author"}, false),
	}}
	ctx := impAdminCtx("u-admin", "site-admin")

	_, err := resolvers.StartImpersonationResolver(ctx, store, testAdminSID, id, &fakeAuditSink{}, fixedNow(time.Now()), "u-target", "")
	if got := codeOf(t, err); got != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for empty reason, got %v (%v)", got, err)
	}
}

func TestStartImpersonation_NestedRejected(t *testing.T) {
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{
		UserID: "u-admin",
		Impersonation: &bff.ImpersonationState{
			TargetUserID: "u-other", AdminUserID: "u-admin",
			Reason: "prev", StartedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute),
		},
	}
	id := &fakeImpIdentity{users: map[string]*identityv1.User{
		"u-target": enabledUser("u-target", "Target", []string{"author"}, false),
	}}
	ctx := impAdminCtx("u-admin", "site-admin")

	_, err := resolvers.StartImpersonationResolver(ctx, store, testAdminSID, id, &fakeAuditSink{}, fixedNow(time.Now()), "u-target", "debugging")
	if got := codeOf(t, err); got != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition for nested start, got %v (%v)", got, err)
	}
}

// ---- start: happy ----------------------------------------------------------

func TestStartImpersonation_Happy(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{UserID: "u-admin"}
	id := &fakeImpIdentity{users: map[string]*identityv1.User{
		"u-target": enabledUser("u-target", "Casey Target", []string{"author"}, false),
	}}
	sink := &fakeAuditSink{}
	ctx := impAdminCtx("u-admin", "site-admin")

	out, err := resolvers.StartImpersonationResolver(ctx, store, testAdminSID, id, sink, fixedNow(now), "u-target", "reproduce RACI gap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TargetUserID != "u-target" || out.TargetName != "Casey Target" || out.Reason != "reproduce RACI gap" {
		t.Fatalf("unexpected session record: %+v", out)
	}
	wantExpiry := now.Add(30 * time.Minute).Format(time.RFC3339)
	if out.ExpiresAt != wantExpiry {
		t.Fatalf("expiresAt = %q, want %q (now+30m)", out.ExpiresAt, wantExpiry)
	}
	if out.StartedAt != now.Format(time.RFC3339) {
		t.Fatalf("startedAt = %q, want %q", out.StartedAt, now.Format(time.RFC3339))
	}

	// The record is persisted on the admin's session.
	saved := store.sessions[testAdminSID]
	if saved.Impersonation == nil {
		t.Fatal("impersonation not saved on session")
	}
	if saved.Impersonation.TargetUserID != "u-target" || saved.Impersonation.AdminUserID != "u-admin" {
		t.Fatalf("saved record wrong: %+v", saved.Impersonation)
	}
	if !saved.Impersonation.ExpiresAt.Equal(now.Add(30 * time.Minute)) {
		t.Fatalf("saved expiresAt = %v, want %v", saved.Impersonation.ExpiresAt, now.Add(30*time.Minute))
	}

	// impersonation.started emitted, attributed to the admin.
	if len(sink.events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Action != "impersonation.started" {
		t.Fatalf("action = %q, want impersonation.started", ev.Action)
	}
	if ev.ActorUserId != "u-admin" {
		t.Fatalf("actor = %q, want u-admin (the real admin)", ev.ActorUserId)
	}
	if ev.Attributes["target_user_id"] != "u-target" || ev.Attributes["reason"] != "reproduce RACI gap" {
		t.Fatalf("attributes = %+v", ev.Attributes)
	}
}

// ---- stop ------------------------------------------------------------------

func TestStopImpersonation_ClearsAndEmits(t *testing.T) {
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{
		UserID: "u-admin",
		Impersonation: &bff.ImpersonationState{
			TargetUserID: "u-target", AdminUserID: "u-admin",
			Reason: "reproduce", StartedAt: time.Now(), ExpiresAt: time.Now().Add(20 * time.Minute),
		},
	}
	sink := &fakeAuditSink{}
	ctx := impAdminCtx("u-admin", "site-admin")

	ok, err := resolvers.StopImpersonationResolver(ctx, store, testAdminSID, sink)
	if err != nil || !ok {
		t.Fatalf("stop: ok=%v err=%v", ok, err)
	}
	if store.sessions[testAdminSID].Impersonation != nil {
		t.Fatal("impersonation not cleared")
	}
	if len(sink.events) != 1 || sink.events[0].Action != "impersonation.stopped" {
		t.Fatalf("want impersonation.stopped, got %+v", sink.events)
	}
	if sink.events[0].ActorUserId != "u-admin" {
		t.Fatalf("stopped actor = %q, want u-admin", sink.events[0].ActorUserId)
	}
}

func TestStopImpersonation_IdempotentWhenNotImpersonating(t *testing.T) {
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{UserID: "u-admin"}
	sink := &fakeAuditSink{}
	ctx := impAdminCtx("u-admin", "site-admin")

	ok, err := resolvers.StopImpersonationResolver(ctx, store, testAdminSID, sink)
	if err != nil || !ok {
		t.Fatalf("stop: ok=%v err=%v", ok, err)
	}
	if len(sink.events) != 0 {
		t.Fatalf("no event expected when nothing to stop, got %+v", sink.events)
	}
}

// ---- status ----------------------------------------------------------------

func TestImpersonationStatus_ReflectsActive(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{
		UserID: "u-admin",
		Impersonation: &bff.ImpersonationState{
			TargetUserID: "u-target", AdminUserID: "u-admin",
			Reason: "reproduce", StartedAt: now, ExpiresAt: now.Add(30 * time.Minute),
		},
	}
	id := &fakeImpIdentity{users: map[string]*identityv1.User{
		"u-target": enabledUser("u-target", "Casey Target", []string{"author"}, false),
	}}

	out, err := resolvers.ImpersonationStatusResolver(context.Background(), store, testAdminSID, id, fixedNow(now.Add(time.Minute)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		t.Fatal("expected an active status, got nil")
	}
	if out.TargetUserID != "u-target" || out.TargetName != "Casey Target" || out.Reason != "reproduce" {
		t.Fatalf("unexpected status: %+v", out)
	}
}

func TestImpersonationStatus_NilWhenNone(t *testing.T) {
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{UserID: "u-admin"}

	out, err := resolvers.ImpersonationStatusResolver(context.Background(), store, testAdminSID, nil, fixedNow(time.Now()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil status, got %+v", out)
	}
}

func TestImpersonationStatus_NilAndClearedWhenExpired(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	store := newFakeImpStore()
	store.sessions[testAdminSID] = bff.Session{
		UserID: "u-admin",
		Impersonation: &bff.ImpersonationState{
			TargetUserID: "u-target", AdminUserID: "u-admin",
			Reason: "reproduce", StartedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-31 * time.Minute),
		},
	}

	out, err := resolvers.ImpersonationStatusResolver(context.Background(), store, testAdminSID, nil, fixedNow(now))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil status for expired record, got %+v", out)
	}
	if store.sessions[testAdminSID].Impersonation != nil {
		t.Fatal("expired record should have been cleared")
	}
}

// TestStartImpersonation_GateErrorsAreCoded proves each start-gate rejection
// rides its registry code (band 1, user-safe), so the gateway presenter relays
// the codeNum to the client and the shared UI helper branches on the code — not
// a message regex.
func TestStartImpersonation_GateErrorsAreCoded(t *testing.T) {
	target := enabledUser("u-target", "Target", []string{"author"}, false)
	protected := enabledUser("u-target", "Other Admin", []string{"site-admin"}, false)

	cases := []struct {
		name    string
		ctx     context.Context
		session bff.Session
		user    *identityv1.User
		reason  string
		want    apperr.Entry
	}{
		{
			name:    "non-site-admin caller",
			ctx:     impAdminCtx("u-caller", "author"),
			session: bff.Session{UserID: "u-caller"},
			user:    target,
			reason:  "debugging",
			want:    gatewayEntry(errcodes.CodeImpersonationNotSiteAdmin),
		},
		{
			name:    "blank reason",
			ctx:     impAdminCtx("u-admin", "site-admin"),
			session: bff.Session{UserID: "u-admin"},
			user:    target,
			reason:  "",
			want:    gatewayEntry(errcodes.CodeImpersonationReasonRequired),
		},
		{
			name:    "protected target",
			ctx:     impAdminCtx("u-admin", "site-admin"),
			session: bff.Session{UserID: "u-admin"},
			user:    protected,
			reason:  "debugging",
			want:    gatewayEntry(errcodes.CodeImpersonationTargetProtected),
		},
		{
			name: "nested start",
			ctx:  impAdminCtx("u-admin", "site-admin"),
			session: bff.Session{UserID: "u-admin", Impersonation: &bff.ImpersonationState{
				TargetUserID: "u-other", AdminUserID: "u-admin", Reason: "prev",
				StartedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute),
			}},
			user:   target,
			reason: "debugging",
			want:   gatewayEntry(errcodes.CodeImpersonationAlreadyActive),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeImpStore()
			store.sessions[testAdminSID] = tc.session
			id := &fakeImpIdentity{users: map[string]*identityv1.User{"u-target": tc.user}}

			_, err := resolvers.StartImpersonationResolver(tc.ctx, store, testAdminSID, id, &fakeAuditSink{}, fixedNow(time.Now()), "u-target", tc.reason)
			info := infoOf(t, err)
			if info.Code != tc.want.Code || info.Symbol != tc.want.Symbol {
				t.Fatalf("coded error = {%d %q}, want {%d %q}", info.Code, info.Symbol, tc.want.Code, tc.want.Symbol)
			}
			if got := wireStatus(err).Code(); got != apperrgrpc.Code(tc.want.Category) {
				t.Fatalf("grpc code = %v, want %v", got, apperrgrpc.Code(tc.want.Category))
			}
		})
	}
}

// Guard: a store error surfaces (not swallowed) on start.
func TestStartImpersonation_StoreGetError(t *testing.T) {
	store := newFakeImpStore()
	store.getErr = errors.New("redis down")
	id := &fakeImpIdentity{users: map[string]*identityv1.User{
		"u-target": enabledUser("u-target", "Target", []string{"author"}, false),
	}}
	ctx := impAdminCtx("u-admin", "site-admin")

	_, err := resolvers.StartImpersonationResolver(ctx, store, testAdminSID, id, &fakeAuditSink{}, fixedNow(time.Now()), "u-target", "debugging")
	if err == nil {
		t.Fatal("expected the store error to surface")
	}
}
