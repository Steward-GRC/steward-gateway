// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	authz "github.com/Steward-GRC/steward-gateway/internal/authz"
	"github.com/Steward-GRC/steward-gateway/internal/bff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// sessionToGraphQL maps a proto Session onto the gqlgen-generated Session model.
func sessionToGraphQL(s *identityv1.Session) *Session {
	if s == nil {
		return nil
	}
	gql := &Session{
		SessionID:       s.GetSessionId(),
		UserID:          s.GetUserId(),
		IssuedAt:        s.GetIssuedAt(),
		AuthenticatedAt: s.GetAuthenticatedAt(),
		ExpiresAt:       s.GetExpiresAt(),
		Active:          s.GetActive(),
		UserAgent:       s.GetUserAgent(),
		Current:         s.GetCurrent(),
	}
	if ip := s.GetClientIp(); ip != "" {
		gql.ClientIP = &ip
	}
	if at := s.GetLastSeenAt(); at != "" {
		gql.LastSeenAt = &at
	}
	return gql
}

// ListUserSessionsResolver lists a user's sessions from identity's session API.
func ListUserSessionsResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID string) ([]*Session, error) {
	if err := authorizeOp(ctx, authz.SessionManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := admin.ListUserSessions(ctx, &identityv1.ListUserSessionsRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	out := make([]*Session, 0, len(resp.GetSessions()))
	for _, s := range resp.GetSessions() {
		out = append(out, sessionToGraphQL(s))
	}
	return out, nil
}

// RevokeUserSessionsResolver revokes all active sessions for a user.
func RevokeUserSessionsResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID string, reason *string) (int, error) {
	if err := authorizeOp(ctx, authz.SessionManage); err != nil {
		return 0, err
	}
	if admin == nil {
		return 0, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	req := &identityv1.RevokeUserSessionsRequest{UserId: userID}
	if reason != nil {
		req.Reason = *reason
	}
	resp, err := admin.RevokeUserSessions(ctx, req)
	if err != nil {
		return 0, err
	}
	return int(resp.GetRevoked()), nil
}

// RevokeMySessionsResolver revokes all sessions for the calling user (self-service).
func RevokeMySessionsResolver(ctx context.Context, read identityv1.IdentityReadServiceClient) (int, error) {
	if read == nil {
		return 0, status.Error(codes.Unavailable, "identity service unavailable")
	}
	resp, err := read.RevokeMySessions(ctx, &identityv1.RevokeMySessionsRequest{})
	if err != nil {
		return 0, err
	}
	return int(resp.GetRevoked()), nil
}

// ListMySessionsResolver lists the calling user's active sessions, marking the
// one this request runs on (self-service; identity binds the user to the actor).
func ListMySessionsResolver(ctx context.Context, logger log.Logger, read identityv1.IdentityReadServiceClient) ([]*Session, error) {
	if read == nil {
		return nil, status.Error(codes.Unavailable, "identity service unavailable")
	}
	lg := logger.Ctx(ctx)
	current, _ := bff.KratosSessionIDFromContext(ctx)
	lg.Debug("mySessions: listing", log.F("has_current_session", current != ""))
	resp, err := read.ListMySessions(ctx, &identityv1.ListMySessionsRequest{CurrentSessionId: current})
	if err != nil {
		lg.Error(err, "mySessions: identity ListMySessions failed")
		return nil, err
	}
	out := make([]*Session, 0, len(resp.GetSessions()))
	for _, s := range resp.GetSessions() {
		out = append(out, sessionToGraphQL(s))
	}
	lg.Debug("mySessions: listed", log.F("count", len(out)))
	return out, nil
}

// RevokeMySessionResolver signs out one of the caller's other sessions. Identity
// refuses the current session and a session that is not the caller's; those
// errors are relayed untouched.
func RevokeMySessionResolver(ctx context.Context, logger log.Logger, read identityv1.IdentityReadServiceClient, sessionID string) (int, error) {
	if read == nil {
		return 0, status.Error(codes.Unavailable, "identity service unavailable")
	}
	lg := logger.Ctx(ctx)
	current, _ := bff.KratosSessionIDFromContext(ctx)
	lg.Debug("revokeMySession: revoking", log.F("session_id", sessionID))
	resp, err := read.RevokeMySession(ctx, &identityv1.RevokeMySessionRequest{SessionId: sessionID, CurrentSessionId: current})
	if err != nil {
		lg.Error(err, "revokeMySession: identity RevokeMySession failed", log.F("session_id", sessionID))
		return 0, err
	}
	lg.Info("revokeMySession: done", log.F("session_id", sessionID), log.F("revoked", resp.GetRevoked()))
	return int(resp.GetRevoked()), nil
}
