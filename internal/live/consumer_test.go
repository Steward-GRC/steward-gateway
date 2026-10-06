// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package live

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
)

func TestEventFromBody_DecodesAnAuditEvent(t *testing.T) {
	body, err := proto.Marshal(&auditv1.AuditEvent{
		Tier: auditv1.Tier_TIER_AUDIT, Action: "policy.published", ActorUserId: "bob", Subject: "policy:pol-1",
		GroupId: "cat-1", OccurredAt: timestamppb.New(time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{"reason": "not forwarded"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, ok := eventFromBody(body)
	if !ok {
		t.Fatal("expected the event to decode")
	}
	want := Event{Type: "policy.published", EntityID: "policy:pol-1", GroupID: "cat-1", ActorUserID: "bob", At: "2026-09-04T00:00:00Z"}
	if ev != want {
		t.Fatalf("event = %+v, want %+v", ev, want)
	}
}

func TestEventFromBody_SkipsWhatIsNotAnEvent(t *testing.T) {
	noAction, _ := proto.Marshal(&auditv1.AuditEvent{Tier: auditv1.Tier_TIER_AUDIT})
	for name, body := range map[string][]byte{"json": []byte(`{"action":"policy.published"}`), "no action": noAction} {
		if _, ok := eventFromBody(body); ok {
			t.Errorf("%s: expected no event", name)
		}
	}
}

func TestBus_FansOutAndDropsForAFullSubscriber(t *testing.T) {
	b := NewBus()
	a, cancelA := b.Subscribe()
	defer cancelA()
	c, cancelC := b.Subscribe()
	for range 70 {
		b.Publish(Event{Type: "x"})
	}
	if len(a) != 64 || len(c) != 64 {
		t.Fatalf("each subscriber buffers 64 and drops the rest: %d %d", len(a), len(c))
	}
	cancelC()
	if _, open := <-drain(c); open {
		t.Fatal("unsubscribe closes the channel")
	}
}

func drain(ch <-chan Event) <-chan Event {
	for range len(ch) {
		<-ch
	}
	return ch
}
