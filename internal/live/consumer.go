// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package live

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Bugs5382/go-rabbitmq"
	"google.golang.org/protobuf/proto"

	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
)

// Exchange is the topic exchange every service publishes its audit events to,
// as steward-audit's AuditEvent in protobuf binary.
const Exchange = "audit"

// BindingKey binds both tiers (audit.audit and audit.activity).
const BindingKey = "audit.#"

// eventFromBody decodes one AuditEvent body into a live Event. It reports
// false for a body that is not an AuditEvent with an action. Attributes are
// never forwarded.
func eventFromBody(body []byte) (Event, bool) {
	var ev auditv1.AuditEvent
	if err := proto.Unmarshal(body, &ev); err != nil || ev.GetAction() == "" {
		return Event{}, false
	}
	at := ""
	if ev.GetOccurredAt() != nil {
		at = ev.GetOccurredAt().AsTime().UTC().Format(time.RFC3339)
	}
	return Event{
		Type:        ev.GetAction(),
		EntityID:    ev.GetSubject(),
		GroupID:     ev.GetGroupId(),
		ActorUserID: ev.GetActorUserId(),
		At:          at,
	}, true
}

// RunConsumer binds a server-named, exclusive, auto-delete queue to Exchange
// and republishes each event to bus. Each replica gets its own queue, so every
// replica sees every event. go-rabbitmq reconnects and re-binds in place:
// RunConsumer returns only when ctx ends or the connection is closed, and the
// caller must not wrap it in a retry loop.
func RunConsumer(ctx context.Context, conn *rabbitmq.Conn, bus *Bus, logger log.Logger) error {
	logger.Info("consuming audit events for live subscriptions", log.F("exchange", Exchange), log.F("binding_key", BindingKey))
	return conn.Consume(ctx, rabbitmq.ConsumerConfig{
		Queue: rabbitmq.QueueConfig{
			Type:       rabbitmq.QueueClassic,
			AutoDelete: true,
			Exclusive:  true,
		}.Transient(),
		Bindings:  []rabbitmq.BindingConfig{{Exchange: Exchange, RoutingKey: BindingKey}},
		AutoAck:   true,
		Exclusive: true,
	}, func(_ context.Context, d rabbitmq.Delivery) error {
		ev, ok := eventFromBody(d.Body)
		if !ok {
			logger.Debug("skipped an audit delivery that is not an AuditEvent", log.F("routing_key", d.RoutingKey))
			return nil
		}
		bus.Publish(ev)
		return nil
	})
}
