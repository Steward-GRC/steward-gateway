// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"strings"

	authz "github.com/Steward-GRC/steward-authz"

	"github.com/Steward-GRC/steward-gateway/internal/live"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// liveEventsResolver streams the domain events whose type starts with one of
// topics (all of them when topics is empty) to a signed-in subscriber, until
// the client goes away.
func liveEventsResolver(ctx context.Context, bus *live.Bus, topics []string) (<-chan *LiveEvent, error) {
	if c, ok := subscriberClaims(ctx); !ok || c.UserID() == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	// Every audit event goes out on this stream, sensitive-policy activity
	// included, so it takes the audit log's own read permission.
	if err := authorizeOp(ctx, authz.AuditRead); err != nil {
		return nil, err
	}
	if bus == nil {
		return nil, fmt.Errorf("live events unavailable")
	}
	in, cancel := bus.Subscribe()
	out := make(chan *LiveEvent, 1)
	go func() {
		defer cancel()
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-in:
				if !ok {
					return
				}
				if !matchTopics(ev.Type, topics) {
					continue
				}
				le := &LiveEvent{Type: ev.Type, At: ev.At}
				if ev.EntityID != "" {
					le.EntityID = &ev.EntityID
				}
				if ev.GroupID != "" {
					le.GroupID = &ev.GroupID
				}
				if ev.ActorUserID != "" {
					le.ActorUserID = &ev.ActorUserID
				}
				select {
				case out <- le:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// matchTopics reports whether eventType matches any topic prefix.
func matchTopics(eventType string, topics []string) bool {
	if len(topics) == 0 {
		return true
	}
	for _, t := range topics {
		if strings.HasPrefix(eventType, t) {
			return true
		}
	}
	return false
}
