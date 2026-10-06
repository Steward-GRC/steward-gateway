// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package live is the gateway's in-process event bus for the liveEvents
// subscription. One RabbitMQ consumer feeds the audit events every service
// publishes into the Bus, which fans them out to each open subscription.
package live

import "sync"

// Event is a domain change broadcast to subscribers. Type is the audit action
// (for example "category.created" or "policy.published"); EntityID and GroupID
// locate it so a client can scope its refetch.
type Event struct {
	Type        string
	EntityID    string
	GroupID     string
	ActorUserID string
	At          string
}

// Bus is a concurrency-safe fan-out broadcaster.
type Bus struct {
	mu   sync.Mutex
	subs map[int]chan Event
	next int
}

// NewBus returns an empty Bus.
func NewBus() *Bus { return &Bus{subs: map[int]chan Event{}} }

// Subscribe registers a subscriber and returns its channel and an unsubscribe
// func. A slow subscriber drops events rather than blocking the publisher:
// live events are hints to refetch, not a durable stream.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	ch := make(chan Event, 64)
	b.subs[id] = ch
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
	}
}

// Publish fans ev out to every subscriber, never blocking on a full one.
func (b *Bus) Publish(ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}
