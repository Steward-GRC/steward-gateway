// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

func TestListUserSessionsMapsLastSeen(t *testing.T) {
	admin := &fakeAdminWithSessions{
		listResp: &identityv1.ListUserSessionsResponse{
			Sessions: []*identityv1.Session{
				{SessionId: "sid-1", UserId: "u-1", LastSeenAt: "2026-06-25T10:15:00Z"},
				{SessionId: "sid-2", UserId: "u-1"},
			},
		},
	}
	out, err := resolvers.ListUserSessionsResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), admin, "u-1")
	if err != nil {
		t.Fatalf("ListUserSessionsResolver: %v", err)
	}
	if out[0].LastSeenAt == nil || *out[0].LastSeenAt != "2026-06-25T10:15:00Z" {
		t.Errorf("session 1 lastSeenAt not mapped: %v", out[0].LastSeenAt)
	}
	if out[1].LastSeenAt != nil {
		t.Errorf("a session never seen must have a null lastSeenAt, got %q", *out[1].LastSeenAt)
	}
}
