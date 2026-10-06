// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	"github.com/Steward-GRC/steward-gateway/internal/audit"
)

type published struct {
	key  string
	body []byte
}

type capture struct {
	got []published
	err error
}

func (c *capture) Publish(_ context.Context, key string, body []byte) error {
	c.got = append(c.got, published{key, body})
	return c.err
}

func TestEmitPublishesAuditsProtoEvent(t *testing.T) {
	c := &capture{}
	at := time.Date(2026, 10, 4, 9, 30, 0, 0, time.UTC)
	err := audit.New(c).Emit(context.Background(), &auditv1.AuditEvent{
		Tier: auditv1.Tier_TIER_AUDIT, Action: "impersonation.started", ActorUserId: "alice", Subject: "bob",
		Attributes: map[string]string{"target_user_id": "bob"}, OccurredAt: timestamppb.New(at),
	})
	require.NoError(t, err)
	require.Len(t, c.got, 1)
	require.Equal(t, "audit.audit", c.got[0].key)

	var ev auditv1.AuditEvent
	require.NoError(t, proto.Unmarshal(c.got[0].body, &ev))
	require.Equal(t, auditv1.Tier_TIER_AUDIT, ev.GetTier())
	require.Equal(t, "impersonation.started", ev.GetAction())
	require.Equal(t, "alice", ev.GetActorUserId())
	require.Equal(t, "bob", ev.GetSubject())
	require.Equal(t, map[string]string{"target_user_id": "bob"}, ev.GetAttributes())
	require.True(t, at.Equal(ev.GetOccurredAt().AsTime()))
}

func TestEmitStampsTheTimeAndRoutesTheActivityTier(t *testing.T) {
	c := &capture{}
	before := time.Now().UTC()
	require.NoError(t, audit.New(c).Emit(context.Background(), &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_ACTIVITY, Action: "policy.viewed"}))
	require.Equal(t, "audit.activity", c.got[0].key)
	var ev auditv1.AuditEvent
	require.NoError(t, proto.Unmarshal(c.got[0].body, &ev))
	require.False(t, ev.GetOccurredAt().AsTime().Before(before), "an unset time is stamped at emit")
}

func TestEmitRefusesAnEventWithoutATierOrAction(t *testing.T) {
	c := &capture{}
	require.Error(t, audit.New(c).Emit(context.Background(), &auditv1.AuditEvent{Action: "policy.viewed"}))
	require.Error(t, audit.New(c).Emit(context.Background(), &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_AUDIT}))
	require.Error(t, audit.New(c).Emit(context.Background(), nil))
	require.Empty(t, c.got)
}

func TestEmitReturnsThePublishError(t *testing.T) {
	boom := errors.New("broker down")
	err := audit.New(&capture{err: boom}).Emit(context.Background(), &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_AUDIT, Action: "impersonation.stopped"})
	require.ErrorIs(t, err, boom)
}

func TestEmitDoesNotChangeTheCallersEvent(t *testing.T) {
	ev := &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_AUDIT, Action: "impersonation.stopped"}
	require.NoError(t, audit.New(&capture{}).Emit(context.Background(), ev))
	require.Nil(t, ev.GetOccurredAt())
}

func TestContentTypeNamesTheMessage(t *testing.T) {
	require.Equal(t, "application/protobuf; proto=steward.audit.v1.AuditEvent", audit.ContentType)
	require.Equal(t, "audit", audit.Exchange)
}
