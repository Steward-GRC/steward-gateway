// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-authz"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
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
