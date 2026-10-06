// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"slices"
	"time"

	authz "github.com/Steward-GRC/steward-authz"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/bff"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// siteAdminRole is the role the act-as start gate requires on the real caller.
const siteAdminRole = string(authz.RoleSiteAdmin)

// impersonationTTL is the fixed 30-minute act-as window (v1: not configurable).
const impersonationTTL = 30 * time.Minute

// userGetter is the minimal identity read surface the resolvers that need to resolve a single user
// by id depend on.
type userGetter interface {
	GetUser(ctx context.Context, in *identityv1.GetUserRequest, opts ...grpc.CallOption) (*identityv1.GetUserResponse, error)
}

// userDisplayName picks the best human label for the banner: Name, else the full name, else email,
// else the id.
func userDisplayName(u *identityv1.User) string {
	if u == nil {
		return ""
	}
	if n := u.GetName(); n != "" {
		return n
	}
	if fn, ln := u.GetFirstName(), u.GetLastName(); fn != "" || ln != "" {
		if fn != "" && ln != "" {
			return fn + " " + ln
		}
		return fn + ln
	}
	if e := u.GetEmail(); e != "" {
		return e
	}
	return u.GetId()
}

// userIsSiteAdmin reports whether the identity user carries the site-admin role.
func userIsSiteAdmin(u *identityv1.User) bool {
	return slices.Contains(u.GetRoles(), siteAdminRole)
}

// impersonationToGraphQL projects a BFF ImpersonationState (+ a resolved target name) onto the
// GraphQL model.
func impersonationToGraphQL(st *bff.ImpersonationState, targetName string) *ImpersonationSession {
	if st == nil {
		return nil
	}
	return &ImpersonationSession{
		TargetUserID: st.TargetUserID,
		TargetName:   targetName,
		Reason:       st.Reason,
		StartedAt:    st.StartedAt.UTC().Format(time.RFC3339),
		ExpiresAt:    st.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

// StartImpersonationResolver backs the startImpersonation mutation.
func StartImpersonationResolver(
	ctx context.Context,
	store bff.SessionStore,
	sessionID string,
	users userGetter,
	emitter AuditEmitter,
	now func() time.Time,
	userID, reason string,
) (*ImpersonationSession, error) {
	c, ok := principal.FromContext(ctx)
	if !ok || c == nil || c.UserID() == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	caller := c.UserID()
	if !principal.HasRole(c, siteAdminRole) {
		return nil, errcodes.New(errcodes.CodeImpersonationNotSiteAdmin)
	}
	if reason == "" {
		return nil, errcodes.New(errcodes.CodeImpersonationReasonRequired)
	}
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "impersonation requires a target user id")
	}
	if userID == caller {
		return nil, status.Error(codes.InvalidArgument, "cannot impersonate yourself")
	}
	if store == nil {
		return nil, status.Error(codes.Unavailable, "session store unavailable")
	}
	if sessionID == "" {
		return nil, status.Error(codes.FailedPrecondition, "no server-side session to record impersonation on")
	}
	if users == nil {
		return nil, status.Error(codes.Unavailable, "identity service unavailable")
	}

	resp, err := users.GetUser(ctx, &identityv1.GetUserRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	u := resp.GetUser()
	if u == nil || u.GetId() == "" {
		return nil, status.Error(codes.NotFound, "target user not found")
	}
	if !u.GetEnabled() {
		return nil, status.Error(codes.FailedPrecondition, "target user is disabled")
	}
	if userIsSiteAdmin(u) || u.GetIsRoot() {
		return nil, errcodes.New(errcodes.CodeImpersonationTargetProtected)
	}

	sess, ok, err := store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "session not found")
	}
	if sess.Impersonation != nil {
		return nil, errcodes.New(errcodes.CodeImpersonationAlreadyActive)
	}

	started := now().UTC()
	st := &bff.ImpersonationState{
		TargetUserID: userID,
		AdminUserID:  caller,
		Reason:       reason,
		StartedAt:    started,
		ExpiresAt:    started.Add(impersonationTTL),
	}
	sess.Impersonation = st
	if err := store.Save(ctx, sessionID, sess); err != nil {
		return nil, err
	}

	emitImpersonationEvent(ctx, emitter, &auditv1.AuditEvent{
		Tier:        auditv1.Tier_TIER_AUDIT,
		Action:      "impersonation.started",
		ActorUserId: caller,
		OccurredAt:  timestamppb.New(started),
		Subject:     userID,
		Attributes: map[string]string{
			"target_user_id": userID,
			"reason":         reason,
		},
	})

	return impersonationToGraphQL(st, userDisplayName(u)), nil
}

// StopImpersonationResolver backs the stopImpersonation mutation: it clears any impersonation
// record on the caller's server-side session, saves it, and emits an impersonation.stopped audit
// event attributed to the admin.
func StopImpersonationResolver(
	ctx context.Context,
	store bff.SessionStore,
	sessionID string,
	emitter AuditEmitter,
) (bool, error) {
	c, ok := principal.FromContext(ctx)
	if !ok || c == nil || c.UserID() == "" {
		return false, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	if store == nil {
		return false, status.Error(codes.Unavailable, "session store unavailable")
	}
	if sessionID == "" {
		return false, status.Error(codes.FailedPrecondition, "no server-side session")
	}
	sess, found, err := store.Get(ctx, sessionID)
	if err != nil {
		return false, err
	}
	if !found || sess.Impersonation == nil {
		return true, nil
	}
	st := sess.Impersonation
	sess.Impersonation = nil
	if err := store.Save(ctx, sessionID, sess); err != nil {
		return false, err
	}
	emitImpersonationEvent(ctx, emitter, &auditv1.AuditEvent{
		Tier:        auditv1.Tier_TIER_AUDIT,
		Action:      "impersonation.stopped",
		ActorUserId: st.AdminUserID,
		OccurredAt:  timestamppb.Now(),
		Subject:     st.TargetUserID,
		Attributes: map[string]string{
			"target_user_id": st.TargetUserID,
		},
	})
	return true, nil
}

// ImpersonationStatusResolver backs the impersonationStatus query.
func ImpersonationStatusResolver(
	ctx context.Context,
	store bff.SessionStore,
	sessionID string,
	users userGetter,
	now func() time.Time,
) (*ImpersonationSession, error) {
	if store == nil || sessionID == "" {
		return nil, nil
	}
	sess, ok, err := store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if !ok || sess.Impersonation == nil {
		return nil, nil
	}
	st := sess.Impersonation
	if !st.Active(now()) {
		sess.Impersonation = nil
		_ = store.Save(ctx, sessionID, sess)
		return nil, nil
	}
	name := st.TargetUserID
	if users != nil {
		if resp, gerr := users.GetUser(ctx, &identityv1.GetUserRequest{UserId: st.TargetUserID}); gerr == nil {
			if n := userDisplayName(resp.GetUser()); n != "" {
				name = n
			}
		}
	}
	return impersonationToGraphQL(st, name), nil
}

// emitImpersonationEvent emits a lifecycle audit event best-effort: a nil emitter (dev/offline) or
// a transient publish error never fails the mutation, because the authoritative state is the
// persisted BFF session record.
func emitImpersonationEvent(ctx context.Context, emitter AuditEmitter, ev *auditv1.AuditEvent) {
	if emitter == nil {
		return
	}
	_ = emitter.Emit(ctx, ev)
}
