// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package aijobs

import (
	"encoding/json"
	"testing"
	"time"
)

// recv reads one event from ch within a short deadline, or reports ok=false.
func recv(t *testing.T, ch <-chan CompletionEvent) (CompletionEvent, bool) {
	t.Helper()
	select {
	case ev, ok := <-ch:
		return ev, ok
	case <-time.After(time.Second):
		return CompletionEvent{}, false
	}
}

// assertNoEvent fails if ch delivers within a short window.
func assertNoEvent(t *testing.T, ch <-chan CompletionEvent) {
	t.Helper()
	select {
	case ev := <-ch:
		t.Fatalf("expected no delivery, got %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestBroker_DeliversToMatchingSubscriber(t *testing.T) {
	b := NewBroker()
	ch, cancel := b.Subscribe("job-1", "user-a")
	defer cancel()

	b.Publish(CompletionEvent{JobID: "job-1", ActorUserID: "user-a", Phase: "Succeeded", ResultRef: "ai:job-result:job-1:DRAFT"})

	ev, ok := recv(t, ch)
	if !ok {
		t.Fatal("matching subscriber received nothing")
	}
	if ev.ResultRef != "ai:job-result:job-1:DRAFT" || ev.Phase != "Succeeded" {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestBroker_DoesNotDeliverToOtherUser(t *testing.T) {
	b := NewBroker()
	// A different user subscribed to the same job id must never see the event:
	// the completion belongs to its submitter (user-a).
	other, cancelOther := b.Subscribe("job-1", "user-b")
	defer cancelOther()
	owner, cancelOwner := b.Subscribe("job-1", "user-a")
	defer cancelOwner()

	b.Publish(CompletionEvent{JobID: "job-1", ActorUserID: "user-a", Phase: "Succeeded"})

	if _, ok := recv(t, owner); !ok {
		t.Fatal("owner (user-a) received nothing")
	}
	assertNoEvent(t, other)
}

func TestBroker_DoesNotDeliverForOtherJob(t *testing.T) {
	b := NewBroker()
	ch, cancel := b.Subscribe("job-1", "user-a")
	defer cancel()

	b.Publish(CompletionEvent{JobID: "job-2", ActorUserID: "user-a", Phase: "Succeeded"})
	assertNoEvent(t, ch)
}

func TestBroker_UnsubscribeClosesChannelAndStopsDelivery(t *testing.T) {
	b := NewBroker()
	ch, cancel := b.Subscribe("job-1", "user-a")
	cancel()

	if _, ok := <-ch; ok {
		t.Fatal("channel should be closed after unsubscribe")
	}
	// Publishing after unsubscribe must not panic (no send on closed channel).
	b.Publish(CompletionEvent{JobID: "job-1", ActorUserID: "user-a", Phase: "Succeeded"})
}

func TestBroker_PublishNeverBlocksOnFullSubscriber(t *testing.T) {
	b := NewBroker()
	ch, cancel := b.Subscribe("job-1", "user-a")
	defer cancel()

	// Buffer depth is 1; a second unread publish must be dropped, not block.
	b.Publish(CompletionEvent{JobID: "job-1", ActorUserID: "user-a", Phase: "Succeeded"})
	done := make(chan struct{})
	go func() {
		b.Publish(CompletionEvent{JobID: "job-1", ActorUserID: "user-a", Phase: "Failed"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a full subscriber")
	}
	if _, ok := recv(t, ch); !ok {
		t.Fatal("expected the first buffered event")
	}
	_ = ch
}

// TestCompletionEvent_DecodesOperatorWireFormat simulates the fake-mq decode
// path the consumer runs: a JSON body in the operator's on-the-wire shape
// (snake_case keys) unmarshals into
// the gateway's CompletionEvent, and Publish routes it to the owner.
func TestCompletionEvent_DecodesOperatorWireFormat(t *testing.T) {
	body := []byte(`{
		"job_id": "aijob-xyz",
		"operation": "DRAFT",
		"actor_user_id": "user-a",
		"policy_id": "pol-1",
		"version_id": "ver-1",
		"category_id": "cat-1",
		"phase": "Succeeded",
		"result_ref": "ai:job-result:aijob-xyz:DRAFT",
		"finished_at": "2026-07-23T10:00:00Z"
	}`)

	var ev CompletionEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.JobID != "aijob-xyz" || ev.ActorUserID != "user-a" || ev.Phase != "Succeeded" ||
		ev.ResultRef != "ai:job-result:aijob-xyz:DRAFT" || ev.FinishedAt != "2026-07-23T10:00:00Z" {
		t.Fatalf("decoded event mismatch: %+v", ev)
	}

	b := NewBroker()
	ch, cancel := b.Subscribe("aijob-xyz", "user-a")
	defer cancel()
	b.Publish(ev)
	if got, ok := recv(t, ch); !ok || got.JobID != "aijob-xyz" {
		t.Fatalf("owner did not receive decoded event: ok=%v got=%+v", ok, got)
	}
}
