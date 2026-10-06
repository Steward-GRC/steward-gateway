// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package audit publishes the gateway's own audit events (act-as start and
// stop) in steward-audit's contract: a steward.audit.v1.AuditEvent, as
// protobuf binary, to the "audit" topic exchange with routing key
// audit.<tier>. Wire a go-rabbitmq publisher on Exchange that sets
// ContentType as the Publisher.
package audit

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
)

// Exchange is the topic exchange audit consumes from.
const Exchange = "audit"

// ContentType is the AMQP content type every event is published with.
const ContentType = "application/protobuf; proto=steward.audit.v1.AuditEvent"

var routingKeys = map[auditv1.Tier]string{
	auditv1.Tier_TIER_AUDIT:    "audit.audit",
	auditv1.Tier_TIER_ACTIVITY: "audit.activity",
}

// Publisher sends one message to the audit exchange.
type Publisher interface {
	Publish(ctx context.Context, routingKey string, body []byte) error
}

// Emitter publishes events. It implements resolvers.AuditEmitter.
type Emitter struct{ pub Publisher }

// New returns an Emitter on pub.
func New(pub Publisher) *Emitter { return &Emitter{pub: pub} }

var (
	errNoEvent  = errors.New("audit: no event")
	errNoTier   = errors.New("audit: event has no valid tier")
	errNoAction = errors.New("audit: event has no action")
)

// Emit publishes ev, stamping the current time when it has none. ev itself is
// left unchanged.
func (e *Emitter) Emit(ctx context.Context, ev *auditv1.AuditEvent) error {
	if ev == nil {
		return errNoEvent
	}
	key, ok := routingKeys[ev.GetTier()]
	if !ok {
		return errNoTier
	}
	if ev.GetAction() == "" {
		return errNoAction
	}
	if ev.GetOccurredAt() == nil {
		ev = proto.CloneOf(ev)
		ev.OccurredAt = timestamppb.Now()
	}
	body, err := proto.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: encode event: %w", err)
	}
	return e.pub.Publish(ctx, key, body)
}
