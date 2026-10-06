// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Steward-GRC/steward-gateway/internal/live"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

func TestLiveEvents_FiltersByTopicPrefix(t *testing.T) {
	bus := live.NewBus()
	ctx, cancel := context.WithCancel(ctxWithRoles(t, "erin", []string{"compliance-admin"}))
	defer cancel()
	out, err := resolvers.LiveEventsResolver(ctx, bus, []string{"policy."})
	if err != nil {
		t.Fatalf("LiveEventsResolver: %v", err)
	}
	bus.Publish(live.Event{Type: "category.created", At: "t1"})
	bus.Publish(live.Event{Type: "policy.published", EntityID: "policy:pol-1", At: "t2"})
	select {
	case ev := <-out:
		if ev.Type != "policy.published" || ev.EntityID == nil || *ev.EntityID != "policy:pol-1" || ev.GroupID != nil {
			t.Fatalf("event: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
}

func TestLiveEvents_RequiresASignedInUser(t *testing.T) {
	if _, err := resolvers.LiveEventsResolver(context.Background(), live.NewBus(), nil); err == nil {
		t.Fatal("a signed-out subscriber must be refused")
	}
}

// The stream carries every audit event, sensitive-policy activity included,
// so only a caller who may read the audit log gets it.
func TestLiveEvents_RequiresAuditRead(t *testing.T) {
	_, err := resolvers.LiveEventsResolver(ctxWithUser(t, "frank"), live.NewBus(), nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied for a caller without audit.read", err)
	}
	for _, role := range []string{"compliance-admin", "site-admin"} {
		ctx, cancel := context.WithCancel(ctxWithRoles(t, "grace", []string{role}))
		if _, err := resolvers.LiveEventsResolver(ctx, live.NewBus(), nil); err != nil {
			t.Errorf("%s: %v, want the stream", role, err)
		}
		cancel()
	}
}
