// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package aijobs bridges the ai operator's job-completion stream on RabbitMQ
// to the gateway's aiJobResult subscription, and reads job results from
// Valkey.
package aijobs

import "sync"

// CompletionEvent mirrors the JSON the operator publishes to the "ai.jobs" topic exchange
// (snake_case keys). The ai operator owns the shape.
type CompletionEvent struct {
	JobID       string `json:"job_id"`
	Operation   string `json:"operation"`
	ActorUserID string `json:"actor_user_id"`
	PolicyID    string `json:"policy_id"`
	VersionID   string `json:"version_id"`
	CategoryID  string `json:"category_id"`
	Phase       string `json:"phase"` // "Succeeded" | "Failed"
	ResultRef   string `json:"result_ref"`
	Error       string `json:"error"`
	FinishedAt  string `json:"finished_at"`
}

// Broker fans job-completion events out to per-subscription channels, filtered at the fan-out seam
// by (jobID, actorUserID): a subscriber only ever receives the completion of its OWN job.
type Broker struct {
	mu   sync.Mutex
	subs map[int]subscription
	next int
}

type subscription struct {
	jobID       string
	actorUserID string
	ch          chan CompletionEvent
}

// NewBroker returns an empty Broker ready for subscribers.
func NewBroker() *Broker { return &Broker{subs: map[int]subscription{}} }

// Subscribe registers interest in a single job on behalf of one authenticated user and returns a
// receive channel plus an unsubscribe func.
func (b *Broker) Subscribe(jobID, actorUserID string) (<-chan CompletionEvent, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	ch := make(chan CompletionEvent, 1)
	b.subs[id] = subscription{jobID: jobID, actorUserID: actorUserID, ch: ch}
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if s, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(s.ch)
		}
	}
}

// Publish delivers ev to every subscriber whose (jobID, actorUserID) matches, never blocking on a
// full or slow subscriber.
func (b *Broker) Publish(ev CompletionEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.subs {
		if s.jobID != ev.JobID || s.actorUserID != ev.ActorUserID {
			continue
		}
		select {
		case s.ch <- ev:
		default:
		}
	}
}
