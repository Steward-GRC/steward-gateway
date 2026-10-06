// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-gateway/internal/live"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

func TestLiveEvents_FiltersByTopicPrefix(t *testing.T) {
	bus := live.NewBus()
	ctx, cancel := context.WithCancel(ctxWithUser(t, "erin"))
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
