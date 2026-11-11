// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	deliveryv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/delivery/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// failingAuditSink refuses every event.
type failingAuditSink struct{ err error }

func (f failingAuditSink) Emit(context.Context, *auditv1.AuditEvent) error { return f.err }

// exportEnv is the break-glass read setup with pol-1 marked sensitive or not.
func exportEnv(t *testing.T, sensitive bool) (*recordingPolicyClient, corev1.CategoryServiceClient) {
	t.Helper()
	pc, groups, _ := breakGlassReadSetup(t, false)
	if sensitive {
		pc.policies["pol-1"].Sensitivity = corev1.Sensitivity_SENSITIVITY_SENSITIVE
	}
	return pc, groups
}

func clearedCtx() context.Context {
	return principal.WithClaims(context.Background(), principal.Static{
		UserIDValue: "u-1", RolesValue: []string{"reader"}, ReadSensitiveValue: true,
	})
}

func TestRecordPolicyExport_SensitivePrintIsAudited(t *testing.T) {
	pc, groups := exportEnv(t, true)
	sink := &fakeAuditSink{}

	ok, err := resolvers.RecordPolicyExport(clearedCtx(), pc, groups, noGrant(), sink, "pol-1", resolvers.PolicyExportKindPrint, true)
	if err != nil || !ok {
		t.Fatalf("RecordPolicyExport = %v, %v; want true, nil", ok, err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("events = %d, want 1", len(sink.events))
	}
	ev := sink.events[0]
	if ev.GetTier() != auditv1.Tier_TIER_AUDIT || ev.GetAction() != "policy.exported" {
		t.Fatalf("event = %v / %q, want audit tier policy.exported", ev.GetTier(), ev.GetAction())
	}
	if ev.GetActorUserId() != "u-1" || ev.GetSubject() != "policy:pol-1" || ev.GetOccurredAt() == nil {
		t.Fatalf("event actor/subject/time = %q / %q / %v", ev.GetActorUserId(), ev.GetSubject(), ev.GetOccurredAt())
	}
	want := map[string]string{"policy_id": "pol-1", "version_id": "pol-1-v1", "kind": "print", "include_history": "true"}
	attrs := ev.GetAttributes()
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("attribute %s = %q, want %q", k, attrs[k], v)
		}
	}
	for k, v := range attrs {
		if strings.Contains(v, "secret clause") {
			t.Errorf("attribute %s carries document content", k)
		}
	}
}

func TestRecordPolicyExport_StandardPolicyRecordsNothing(t *testing.T) {
	pc, groups := exportEnv(t, false)
	sink := &fakeAuditSink{}

	ok, err := resolvers.RecordPolicyExport(clearedCtx(), pc, groups, noGrant(), sink, "pol-1", resolvers.PolicyExportKindPrint, false)
	if err != nil || ok {
		t.Fatalf("RecordPolicyExport = %v, %v; want false, nil", ok, err)
	}
	if len(sink.events) != 0 {
		t.Fatalf("events = %d, want none for a standard policy", len(sink.events))
	}
}

func TestRecordPolicyExport_PdfKindIsLabelled(t *testing.T) {
	pc, groups := exportEnv(t, true)
	sink := &fakeAuditSink{}
	if _, err := resolvers.RecordPolicyExport(clearedCtx(), pc, groups, noGrant(), sink, "pol-1", resolvers.PolicyExportKindPDF, false); err != nil {
		t.Fatal(err)
	}
	if got := sink.events[0].GetAttributes()["kind"]; got != "pdf" {
		t.Fatalf("kind = %q, want pdf", got)
	}
}

func TestRecordPolicyExport_CallerWhoCannotReadIsRefused(t *testing.T) {
	pc, groups := exportEnv(t, true)
	sink := &fakeAuditSink{}
	noClearance := principal.WithClaims(context.Background(), principal.Static{UserIDValue: "u-2", RolesValue: []string{"reader"}})

	ok, err := resolvers.RecordPolicyExport(noClearance, pc, groups, noGrant(), sink, "pol-1", resolvers.PolicyExportKindPrint, false)
	if ok || status.Code(err) != codes.NotFound {
		t.Fatalf("RecordPolicyExport = %v, %v; want NotFound", ok, err)
	}
	if len(sink.events) != 0 {
		t.Fatalf("events = %d, want none for a refused caller", len(sink.events))
	}
}

func TestRecordPolicyExport_UnauthenticatedIsRefused(t *testing.T) {
	pc, groups := exportEnv(t, true)
	sink := &fakeAuditSink{}
	if _, err := resolvers.RecordPolicyExport(context.Background(), pc, groups, noGrant(), sink, "pol-1", resolvers.PolicyExportKindPrint, false); err == nil {
		t.Fatal("expected an error without a caller")
	}
	if len(sink.events) != 0 {
		t.Fatal("an unauthenticated call was recorded")
	}
}

func TestRecordPolicyExport_ActingAdminIsTheActor(t *testing.T) {
	pc, groups := exportEnv(t, true)
	sink := &fakeAuditSink{}
	target := principal.Static{UserIDValue: "u-1", RolesValue: []string{"reader"}, ReadSensitiveValue: true}
	ctx := principal.WithClaims(context.Background(), target)
	ctx = principal.WithImpersonator(ctx, principal.Static{UserIDValue: "admin-9", RolesValue: []string{"site-admin"}})

	if _, err := resolvers.RecordPolicyExport(ctx, pc, groups, noGrant(), sink, "pol-1", resolvers.PolicyExportKindPrint, false); err != nil {
		t.Fatal(err)
	}
	ev := sink.events[0]
	if ev.GetActorUserId() != "admin-9" || ev.GetAttributes()["acting_as"] != "u-1" {
		t.Fatalf("actor = %q acting_as = %q, want the real admin acting as u-1", ev.GetActorUserId(), ev.GetAttributes()["acting_as"])
	}
}

// A sensitive export that cannot be recorded does not report success.
func TestRecordPolicyExport_FailsClosedWhenTheAuditIsUnavailable(t *testing.T) {
	pc, groups := exportEnv(t, true)
	boom := errors.New("broker down")

	if ok, err := resolvers.RecordPolicyExport(clearedCtx(), pc, groups, noGrant(), failingAuditSink{boom}, "pol-1", resolvers.PolicyExportKindPrint, false); ok || err == nil {
		t.Fatalf("with a failing sink = %v, %v; want an error", ok, err)
	}
	if ok, err := resolvers.RecordPolicyExport(clearedCtx(), pc, groups, noGrant(), nil, "pol-1", resolvers.PolicyExportKindPrint, false); ok || status.Code(err) != codes.Unavailable {
		t.Fatalf("with no sink = %v, %v; want Unavailable", ok, err)
	}
}

// requestPDFExport records a sensitive export on the server, so no client can skip it.
func TestRequestPDFExport_SensitiveIsAuditedBeforeTheJobStarts(t *testing.T) {
	pc, groups := exportEnv(t, true)
	pc.versions["pv-1"] = &corev1.PolicyVersion{Id: "pv-1", PolicyId: "pol-1", Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED}
	sink := &fakeAuditSink{}
	client := &fakeDeliveryClient{requestPDFResp: &deliveryv1.RequestPDFExportResponse{JobId: "job-1"}}

	if _, err := resolvers.RequestPDFExport(clearedCtx(), client, pc, groups, noGrant(), nil, sink, "pv-1"); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("events = %d, want 1", len(sink.events))
	}
	a := sink.events[0].GetAttributes()
	if sink.events[0].GetAction() != "policy.exported" || a["kind"] != "pdf" || a["version_id"] != "pv-1" || a["policy_id"] != "pol-1" {
		t.Fatalf("event = %v %v", sink.events[0].GetAction(), a)
	}

	client.lastRequestPDFReq = nil
	if _, err := resolvers.RequestPDFExport(clearedCtx(), client, pc, groups, noGrant(), nil, failingAuditSink{errors.New("down")}, "pv-1"); err == nil {
		t.Fatal("expected the export to fail when it cannot be recorded")
	}
	if client.lastRequestPDFReq != nil {
		t.Fatal("a job was started for an unrecorded sensitive export")
	}
}

func TestRequestPDFExport_StandardPolicyIsNotAudited(t *testing.T) {
	pc, groups := exportEnv(t, false)
	pc.versions["pv-1"] = &corev1.PolicyVersion{Id: "pv-1", PolicyId: "pol-1", Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED}
	sink := &fakeAuditSink{}
	client := &fakeDeliveryClient{requestPDFResp: &deliveryv1.RequestPDFExportResponse{JobId: "job-1"}}

	if _, err := resolvers.RequestPDFExport(clearedCtx(), client, pc, groups, noGrant(), nil, sink, "pv-1"); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 0 {
		t.Fatalf("events = %d, want none", len(sink.events))
	}
}
