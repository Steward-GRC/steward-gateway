// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Issues #55 and #77: the obligations service sends due_at; the gateway
// forwards it as a nullable ISO-8601 string and leaves it null when unset.

func TestMyObligations_DueAt(t *testing.T) {
	future := time.Date(2026, 12, 1, 9, 30, 0, 0, time.UTC)
	past := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	client := &fakeObligationClient{
		myObligationsResp: &obligationsv1.GetMyObligationsResponse{
			Obligations: []*obligationsv1.ObligationItem{
				{PolicyId: "p1", PolicyVersionId: "pv1", DueAt: timestamppb.New(future)},
				{PolicyId: "p2", PolicyVersionId: "pv2"},
				{PolicyId: "p3", PolicyVersionId: "pv3", DueAt: timestamppb.New(past)},
			},
		},
	}
	out, err := resolvers.MyObligationsResolver(ctxWithUser(t, "u-1"), client)
	if err != nil {
		t.Fatalf("MyObligations: %v", err)
	}
	if out[0].DueAt == nil || *out[0].DueAt != "2026-12-01T09:30:00Z" {
		t.Errorf("future due date: %v", out[0].DueAt)
	}
	if out[1].DueAt != nil {
		t.Errorf("no due date must be null; got %q", *out[1].DueAt)
	}
	if out[2].DueAt == nil || *out[2].DueAt != "2026-10-01T00:00:00Z" {
		t.Errorf("past due date is still sent as is: %v", out[2].DueAt)
	}
}

func TestAckRosterResolver_DueAtOnPendingOnly(t *testing.T) {
	due := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	reporting := &fakeReportingClient{roster: &obligationsv1.GetAckRosterResponse{
		Acked:   []*obligationsv1.AckRosterEntry{{UserId: "u1", Email: "u1@example.org", AckedAt: timestamppb.New(due)}},
		Pending: []*obligationsv1.AckRosterEntry{{UserId: "u2", Email: "u2@example.org", DueAt: timestamppb.New(due)}, {UserId: "u3", Email: "u3@example.org"}},
	}}
	out, err := resolvers.AckRosterResolver(ctxWithRoles(t, "u", []string{"compliance-admin"}), log.Nop(), reporting, &fakeComplianceIdentityClient{}, "pv1", nil)
	if err != nil {
		t.Fatalf("roster: %v", err)
	}
	if out.Acked[0].DueAt != nil {
		t.Errorf("acknowledged entry must have no due date; got %q", *out.Acked[0].DueAt)
	}
	if out.Pending[0].DueAt == nil || *out.Pending[0].DueAt != "2026-11-20T12:00:00Z" {
		t.Errorf("pending due date: %v", out.Pending[0].DueAt)
	}
	if out.Pending[1].DueAt != nil {
		t.Errorf("pending without a date must be null; got %q", *out.Pending[1].DueAt)
	}
}

func TestGetCompletionReportResolver_OverdueDueAt(t *testing.T) {
	due := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	reporting := &fakeReportingClient{reportResp: &obligationsv1.GetCompletionReportResponse{
		Overdue: []*obligationsv1.OverdueEntry{
			{UserId: "u1", Email: "u1@example.org", DueAt: timestamppb.New(due)},
			{UserId: "u2", Email: "u2@example.org"},
		},
	}}
	out, err := resolvers.GetCompletionReportResolver(ctxWithRoles(t, "u", []string{"compliance-admin"}), reporting, &fakeComplianceIdentityClient{}, "pv1", nil)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if out.Overdue[0].DueAt == nil || *out.Overdue[0].DueAt != "2026-11-01T08:00:00Z" {
		t.Errorf("overdue due date: %v", out.Overdue[0].DueAt)
	}
	if out.Overdue[1].DueAt != nil {
		t.Errorf("overdue without a date must be null; got %q", *out.Overdue[1].DueAt)
	}
}
