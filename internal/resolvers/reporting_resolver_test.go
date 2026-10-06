// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"github.com/Bugs5382/go-redis/ratelimit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	reportingv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/reporting/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

var receivedAt = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

func reporterView() *reportingv1.ReporterView {
	return &reportingv1.ReporterView{
		CaseCode: "7KQ-42M-RX",
		Status:   reportingv1.CaseStatus_CASE_STATUS_NEEDS_REPORTER_REPLY,
		Details: &reportingv1.ReportDetails{
			WhatHappened: "A visitor list was left at the front desk.", Location: "Facilities",
			InformationKinds: []reportingv1.InformationKind{reportingv1.InformationKind_INFORMATION_KIND_CONTACT},
			StillHappening:   reportingv1.Answer_ANSWER_NO,
		},
		Thread: []*reportingv1.ThreadMessage{{
			Id: "m1", Author: reportingv1.MessageAuthor_MESSAGE_AUTHOR_OFFICER, OfficerUserId: "grace",
			Body: "When was this?", CreatedAt: timestamppb.New(receivedAt),
		}},
		ReceivedAt: timestamppb.New(receivedAt),
	}
}

type fakeIntake struct {
	reportingv1.IntakeServiceClient
	actorSeen  bool
	actor      string
	lastAnon   *reportingv1.SubmitAnonymousReportRequest
	lastCheck  *reportingv1.CheckReportRequest
	lastReply  *reportingv1.ReplyToReportRequest
	lastNamed  *reportingv1.SubmitNamedReportRequest
	checkErr   error
	checkCalls int
}

func (f *fakeIntake) see(ctx context.Context) {
	if a, ok := grpcactor.FromContext(ctx); ok {
		f.actorSeen, f.actor = true, a.Subject
	}
	if _, ok := principal.FromContext(ctx); ok {
		f.actorSeen = true
	}
}

func (f *fakeIntake) SubmitAnonymousReport(ctx context.Context, in *reportingv1.SubmitAnonymousReportRequest, _ ...grpc.CallOption) (*reportingv1.SubmitAnonymousReportResponse, error) {
	f.see(ctx)
	f.lastAnon = in
	return &reportingv1.SubmitAnonymousReportResponse{CaseCode: "7KQ-42M-RX"}, nil
}

func (f *fakeIntake) CheckReport(ctx context.Context, in *reportingv1.CheckReportRequest, _ ...grpc.CallOption) (*reportingv1.CheckReportResponse, error) {
	f.see(ctx)
	f.lastCheck = in
	f.checkCalls++
	if f.checkErr != nil {
		return nil, f.checkErr
	}
	return &reportingv1.CheckReportResponse{Report: reporterView()}, nil
}

func (f *fakeIntake) ReplyToReport(ctx context.Context, in *reportingv1.ReplyToReportRequest, _ ...grpc.CallOption) (*reportingv1.ReplyToReportResponse, error) {
	f.see(ctx)
	f.lastReply = in
	return &reportingv1.ReplyToReportResponse{Report: reporterView()}, nil
}

func (f *fakeIntake) SubmitNamedReport(ctx context.Context, in *reportingv1.SubmitNamedReportRequest, _ ...grpc.CallOption) (*reportingv1.SubmitNamedReportResponse, error) {
	f.see(ctx)
	f.lastNamed = in
	return &reportingv1.SubmitNamedReportResponse{CaseId: "case-1", CaseCode: "7KQ-42M-RX"}, nil
}

func (f *fakeIntake) ListMyReports(ctx context.Context, _ *reportingv1.ListMyReportsRequest, _ ...grpc.CallOption) (*reportingv1.ListMyReportsResponse, error) {
	f.see(ctx)
	return &reportingv1.ListMyReportsResponse{Reports: []*reportingv1.MyReport{{CaseId: "case-1", Report: reporterView()}}}, nil
}

type fakeLimiter struct {
	keys  []string
	deny  map[string]bool
	err   error
	limit []ratelimit.Limit
}

func (f *fakeLimiter) Allow(_ context.Context, key string, limit ratelimit.Limit) (ratelimit.Result, error) {
	f.keys = append(f.keys, key)
	f.limit = append(f.limit, limit)
	if f.err != nil {
		return ratelimit.Result{}, f.err
	}
	return ratelimit.Result{Allowed: !f.deny[key]}, nil
}

func signedInCarol(t *testing.T) context.Context {
	return ctxWithStubClaims(t, principal.Static{UserIDValue: "carol", EmailValue: "carol@example.org", RolesValue: []string{"approver"}})
}

func TestSubmitAnonymousReport_SendsNothingThatIdentifiesTheCaller(t *testing.T) {
	intake := &fakeIntake{}
	r := &resolvers.Resolver{IntakeClient: intake}
	stillHappening := resolvers.ReportAnswerNotSure
	got, err := r.SubmitAnonymousReportResolver(signedInCarol(t), resolvers.ReportDetailsInput{
		WhatHappened:     "A visitor list was left at the front desk.",
		InformationKinds: []resolvers.InformationKind{resolvers.InformationKindContact},
		StillHappening:   &stillHappening,
	}, "correct horse battery", []*resolvers.ReportAttachmentInput{{
		Filename: "photo.png", ContentType: "image/png", Data: base64.StdEncoding.EncodeToString([]byte("png-bytes")),
	}})
	if err != nil {
		t.Fatalf("SubmitAnonymousReportResolver: %v", err)
	}
	if got.CaseCode != "7KQ-42M-RX" {
		t.Fatalf("case code: %q", got.CaseCode)
	}
	if intake.actorSeen {
		t.Fatal("an anonymous report must reach reporting with no actor, even from a signed-in user")
	}
	d := intake.lastAnon.GetDetails()
	if d.GetWhatHappened() == "" || d.GetInformationKinds()[0] != reportingv1.InformationKind_INFORMATION_KIND_CONTACT ||
		d.GetStillHappening() != reportingv1.Answer_ANSWER_NOT_SURE || intake.lastAnon.GetPassphrase() != "correct horse battery" {
		t.Fatalf("request not mapped: %+v", intake.lastAnon)
	}
	if a := intake.lastAnon.GetAttachments()[0]; string(a.GetData()) != "png-bytes" || a.GetContentType() != "image/png" {
		t.Fatalf("attachment not decoded: %+v", a)
	}
}

func TestSubmitAnonymousReport_RefusesBadBase64(t *testing.T) {
	intake := &fakeIntake{}
	r := &resolvers.Resolver{IntakeClient: intake}
	_, err := r.SubmitAnonymousReportResolver(context.Background(), resolvers.ReportDetailsInput{WhatHappened: "x"}, "correct horse battery",
		[]*resolvers.ReportAttachmentInput{{Filename: "a.txt", ContentType: "text/plain", Data: "not base64!"}})
	if status.Code(err) != codes.InvalidArgument || intake.lastAnon != nil {
		t.Fatalf("expected InvalidArgument before reporting is called, got %v", err)
	}
}

func TestCheckReport_IsThrottledPerCodeAndOverall(t *testing.T) {
	intake := &fakeIntake{}
	lim := &fakeLimiter{}
	r := &resolvers.Resolver{IntakeClient: intake, ReportLimiter: lim}
	view, err := r.CheckReportResolver(signedInCarol(t), "7kq-42m rx", "correct horse battery")
	if err != nil {
		t.Fatalf("CheckReportResolver: %v", err)
	}
	if intake.actorSeen {
		t.Fatal("checkReport must reach reporting with no actor")
	}
	if view.CaseCode != "7KQ-42M-RX" || view.Status != resolvers.CaseStatusNeedsReporterReply || view.Details.StillHappening == nil ||
		*view.Details.StillHappening != resolvers.ReportAnswerNo || view.ReceivedAt != "2026-10-02T09:00:00Z" {
		t.Fatalf("view not mapped: %+v", view)
	}
	if view.Thread[0].OfficerUserID != nil || view.Thread[0].Author != resolvers.MessageAuthorOfficer {
		t.Fatalf("a reporter view never names the officer: %+v", view.Thread[0])
	}
	if len(lim.keys) != 2 {
		t.Fatalf("expected a per-code and an overall throttle, got %v", lim.keys)
	}
	for _, k := range lim.keys {
		if k == "7KQ42MRX" || k == "7kq-42m rx" {
			t.Fatalf("the throttle key must not be the case code itself: %q", k)
		}
	}

	again := &fakeLimiter{}
	r2 := &resolvers.Resolver{IntakeClient: &fakeIntake{}, ReportLimiter: again}
	if _, err := r2.CheckReportResolver(context.Background(), "7KQ42MRX", "x"); err != nil {
		t.Fatalf("CheckReportResolver: %v", err)
	}
	if again.keys[0] != lim.keys[0] {
		t.Fatalf("the per-code key ignores case, spaces and dashes: %q vs %q", again.keys[0], lim.keys[0])
	}
}

func TestCheckReport_ThrottledIsRefusedBeforeReporting(t *testing.T) {
	for name, deny := range map[string]func(keys []string) map[string]bool{
		"per code": func(k []string) map[string]bool { return map[string]bool{k[0]: true} },
		"overall":  func(k []string) map[string]bool { return map[string]bool{k[1]: true} },
	} {
		t.Run(name, func(t *testing.T) {
			probe := &fakeLimiter{}
			_, _ = (&resolvers.Resolver{IntakeClient: &fakeIntake{}, ReportLimiter: probe}).CheckReportResolver(context.Background(), "7KQ42MRX", "x")
			intake := &fakeIntake{}
			r := &resolvers.Resolver{IntakeClient: intake, ReportLimiter: &fakeLimiter{deny: deny(probe.keys)}}
			_, err := r.CheckReportResolver(context.Background(), "7KQ42MRX", "x")
			if code, _ := apperr.Code(err); code != errcodes.CodeReportChecksThrottled {
				t.Fatalf("expected REPORT_CHECKS_THROTTLED, got %v", err)
			}
			if intake.checkCalls != 0 {
				t.Fatal("reporting must not be called once throttled")
			}
		})
	}
}

func TestCheckReport_FailsClosedWithoutTheThrottle(t *testing.T) {
	for name, lim := range map[string]resolvers.ReportLimiter{"store down": &fakeLimiter{err: errors.New("valkey down")}, "not wired": nil} {
		t.Run(name, func(t *testing.T) {
			intake := &fakeIntake{}
			r := &resolvers.Resolver{IntakeClient: intake, ReportLimiter: lim}
			_, err := r.CheckReportResolver(context.Background(), "7KQ42MRX", "x")
			if code, _ := apperr.Code(err); code != errcodes.CodeReportThrottleUnavailable || intake.checkCalls != 0 {
				t.Fatalf("expected REPORT_THROTTLE_UNAVAILABLE without calling reporting, got %v", err)
			}
		})
	}
}

func TestCheckReport_RelaysReportingsRefusal(t *testing.T) {
	notFound := backendCodedErr(codes.NotFound, 8103, "REPORT_NOT_FOUND", "reporting", nil)
	r := &resolvers.Resolver{IntakeClient: &fakeIntake{checkErr: notFound}, ReportLimiter: &fakeLimiter{}}
	_, err := r.CheckReportResolver(context.Background(), "7KQ42MRX", "wrong")
	info, ok := apperrgrpc.FromError(err)
	if !ok || info.Symbol != "REPORT_NOT_FOUND" || info.Domain != "reporting" {
		t.Fatalf("expected reporting's refusal relayed unchanged, got %v", err)
	}
}

func TestReplyToReport_ThrottledAndAnonymous(t *testing.T) {
	intake := &fakeIntake{}
	lim := &fakeLimiter{}
	r := &resolvers.Resolver{IntakeClient: intake, ReportLimiter: lim}
	if _, err := r.ReplyToReportResolver(signedInCarol(t), "7KQ42MRX", "correct horse battery", "It was Monday."); err != nil {
		t.Fatalf("ReplyToReportResolver: %v", err)
	}
	if intake.actorSeen || intake.lastReply.GetBody() != "It was Monday." || len(lim.keys) != 2 {
		t.Fatalf("reply: actor %v, req %+v, keys %v", intake.actorSeen, intake.lastReply, lim.keys)
	}
}

func TestSubmitNamedReport_ActsForTheSignedInUser(t *testing.T) {
	intake := &fakeIntake{}
	r := &resolvers.Resolver{IntakeClient: intake}
	got, err := r.SubmitNamedReportResolver(signedInCarol(t), resolvers.ReportDetailsInput{WhatHappened: "x"}, nil)
	if err != nil {
		t.Fatalf("SubmitNamedReportResolver: %v", err)
	}
	if got.CaseID != "case-1" || intake.actor != "carol" {
		t.Fatalf("named report: %+v, actor %q", got, intake.actor)
	}
	if _, err := r.SubmitNamedReportResolver(context.Background(), resolvers.ReportDetailsInput{WhatHappened: "x"}, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a named report needs a signed-in user, got %v", err)
	}
}

func TestMyReports_ListsTheCallersReports(t *testing.T) {
	intake := &fakeIntake{}
	r := &resolvers.Resolver{IntakeClient: intake}
	got, err := r.MyReportsResolver(signedInCarol(t))
	if err != nil {
		t.Fatalf("MyReportsResolver: %v", err)
	}
	if len(got) != 1 || got[0].CaseID != "case-1" || got[0].Report.CaseCode != "7KQ-42M-RX" || intake.actor != "carol" {
		t.Fatalf("my reports: %+v", got)
	}
}

type fakeCases struct {
	reportingv1.CaseServiceClient
	actor     string
	lastList  *reportingv1.ListCasesRequest
	lastClose *reportingv1.CloseCaseRequest
	lastRisk  *reportingv1.RecordRiskAssessmentRequest
	lastAsg   *reportingv1.AssignCaseRequest
}

func (f *fakeCases) see(ctx context.Context) {
	if a, ok := grpcactor.FromContext(ctx); ok {
		f.actor = a.Subject
	}
}

func fullCase() *reportingv1.Case {
	return &reportingv1.Case{
		Id: "case-1", CaseCode: "7KQ-42M-RX", Kind: reportingv1.ReportKind_REPORT_KIND_NAMED,
		Status: reportingv1.CaseStatus_CASE_STATUS_CLOSED, Details: reporterView().GetDetails(), ReporterUserId: "carol",
		ReceivedAt: timestamppb.New(receivedAt), DiscoveredOn: "2026-10-01",
		Attachments: []*reportingv1.Attachment{{Id: "a1", Filename: "attachment-1.png", ContentType: "image/png", SizeBytes: 42, MetadataStripped: true}},
		Thread:      reporterView().GetThread(),
		Notes:       []*reportingv1.Note{{Id: "n1", AuthorUserId: "grace", Body: "Spoke to Facilities.", CreatedAt: timestamppb.New(receivedAt)}},
		Assessment: &reportingv1.RiskAssessment{
			Factors: &reportingv1.RiskFactors{Information: []reportingv1.InformationKind{reportingv1.InformationKind_INFORMATION_KIND_CONTACT},
				Recipient: reportingv1.Recipient_RECIPIENT_STAFF_ONLY, Viewed: reportingv1.Viewed_VIEWED_NO, Mitigation: reportingv1.Mitigation_MITIGATION_FULLY},
			Suggestion: reportingv1.Suggestion_SUGGESTION_LOW_PROBABILITY_OF_COMPROMISE, Decision: reportingv1.BreachDecision_BREACH_DECISION_NOT_REPORTABLE,
			Reason: "Only staff saw it.", DecidedByUserId: "grace", DecidedAt: timestamppb.New(receivedAt),
		},
		Notices:           []*reportingv1.Notice{{Id: "no1", Recipient: reportingv1.NoticeRecipient_NOTICE_RECIPIENT_OTHER, Label: "Front desk", DaysAllowed: 60, DueOn: "2026-11-30", Status: reportingv1.NoticeStatus_NOTICE_STATUS_NOT_NEEDED}},
		Outcome:           reportingv1.Outcome_OUTCOME_SUBSTANTIATED,
		CorrectiveActions: []*reportingv1.CorrectiveAction{{Description: "Lock the visitor book away."}, {Description: "Update the policy.", PolicyId: "pol-1"}},
		ClosedAt:          timestamppb.New(receivedAt.Add(48 * time.Hour)),
	}
}

func (f *fakeCases) ListCases(ctx context.Context, in *reportingv1.ListCasesRequest, _ ...grpc.CallOption) (*reportingv1.ListCasesResponse, error) {
	f.see(ctx)
	f.lastList = in
	return &reportingv1.ListCasesResponse{
		Cases:  []*reportingv1.CaseSummary{{Id: "case-1", CaseCode: "7KQ-42M-RX", Kind: reportingv1.ReportKind_REPORT_KIND_ANONYMOUS, Status: reportingv1.CaseStatus_CASE_STATUS_NEW, Summary: "A visitor list", ReceivedAt: timestamppb.New(receivedAt)}},
		Counts: []*reportingv1.StatusCount{{Status: reportingv1.CaseStatus_CASE_STATUS_NEW, Count: 3}},
	}, nil
}

func (f *fakeCases) GetCase(ctx context.Context, _ *reportingv1.GetCaseRequest, _ ...grpc.CallOption) (*reportingv1.GetCaseResponse, error) {
	f.see(ctx)
	return &reportingv1.GetCaseResponse{Case: fullCase()}, nil
}

func (f *fakeCases) GetAttachment(ctx context.Context, in *reportingv1.GetAttachmentRequest, _ ...grpc.CallOption) (*reportingv1.GetAttachmentResponse, error) {
	f.see(ctx)
	return &reportingv1.GetAttachmentResponse{Attachment: fullCase().GetAttachments()[0], Data: []byte("png-bytes")}, nil
}

func (f *fakeCases) AssignCase(ctx context.Context, in *reportingv1.AssignCaseRequest, _ ...grpc.CallOption) (*reportingv1.AssignCaseResponse, error) {
	f.see(ctx)
	f.lastAsg = in
	return &reportingv1.AssignCaseResponse{Case: fullCase()}, nil
}

func (f *fakeCases) RecordRiskAssessment(ctx context.Context, in *reportingv1.RecordRiskAssessmentRequest, _ ...grpc.CallOption) (*reportingv1.RecordRiskAssessmentResponse, error) {
	f.see(ctx)
	f.lastRisk = in
	return &reportingv1.RecordRiskAssessmentResponse{Assessment: fullCase().GetAssessment()}, nil
}

func (f *fakeCases) CloseCase(ctx context.Context, in *reportingv1.CloseCaseRequest, _ ...grpc.CallOption) (*reportingv1.CloseCaseResponse, error) {
	f.see(ctx)
	f.lastClose = in
	return &reportingv1.CloseCaseResponse{Case: fullCase()}, nil
}

func officerGrace(t *testing.T) context.Context {
	return ctxWithStubClaims(t, principal.Static{UserIDValue: "grace", RolesValue: []string{"compliance-admin"}})
}

func TestReportCases_MapsTheQueue(t *testing.T) {
	cases := &fakeCases{}
	r := &resolvers.Resolver{CaseClient: cases}
	assignee := "grace"
	got, err := r.ReportCasesResolver(officerGrace(t), []resolvers.CaseStatus{resolvers.CaseStatusNew, resolvers.CaseStatusInReview}, &assignee)
	if err != nil {
		t.Fatalf("ReportCasesResolver: %v", err)
	}
	if cases.actor != "grace" || cases.lastList.GetAssigneeUserId() != "grace" || len(cases.lastList.GetStatuses()) != 2 ||
		cases.lastList.GetStatuses()[1] != reportingv1.CaseStatus_CASE_STATUS_IN_REVIEW {
		t.Fatalf("list request: %+v (actor %q)", cases.lastList, cases.actor)
	}
	if got.Cases[0].Kind != resolvers.ReportKindAnonymous || got.Cases[0].AssigneeUserID != nil || got.Cases[0].NextDeadline != nil ||
		got.Counts[0].Status != resolvers.CaseStatusNew || got.Counts[0].Count != 3 {
		t.Fatalf("queue: %+v %+v", got.Cases[0], got.Counts[0])
	}
}

func TestReportCase_MapsTheWholeCase(t *testing.T) {
	r := &resolvers.Resolver{CaseClient: &fakeCases{}}
	c, err := r.ReportCaseResolver(officerGrace(t), "case-1")
	if err != nil {
		t.Fatalf("ReportCaseResolver: %v", err)
	}
	if c.ReporterUserID == nil || *c.ReporterUserID != "carol" || c.Status != resolvers.CaseStatusClosed || c.DiscoveredOn == nil ||
		c.Attachments[0].SizeBytes != 42 || !c.Attachments[0].MetadataStripped || c.Notes[0].AuthorUserID != "grace" ||
		c.Thread[0].OfficerUserID == nil || *c.Thread[0].OfficerUserID != "grace" {
		t.Fatalf("case: %+v", c)
	}
	a := c.Assessment
	if a == nil || a.Decision == nil || *a.Decision != resolvers.BreachDecisionNotReportable || a.Suggestion == nil ||
		*a.Suggestion != resolvers.RiskSuggestionLowProbabilityOfCompromise || a.Factors.Recipient == nil || *a.Factors.Recipient != resolvers.RiskRecipientStaffOnly {
		t.Fatalf("assessment: %+v", a)
	}
	if c.Notices[0].Status != resolvers.NoticeStatusNotNeeded || c.Notices[0].SentOn != nil || c.Outcome == nil || *c.Outcome != resolvers.CaseOutcomeSubstantiated ||
		c.CorrectiveActions[0].PolicyID != nil || *c.CorrectiveActions[1].PolicyID != "pol-1" || c.ClosedAt == nil {
		t.Fatalf("close-out: %+v", c)
	}
}

func TestReportAttachment_EncodesTheBytes(t *testing.T) {
	r := &resolvers.Resolver{CaseClient: &fakeCases{}}
	got, err := r.ReportAttachmentResolver(officerGrace(t), "case-1", "a1")
	if err != nil {
		t.Fatalf("ReportAttachmentResolver: %v", err)
	}
	if got.Data != base64.StdEncoding.EncodeToString([]byte("png-bytes")) || got.Attachment.Filename != "attachment-1.png" {
		t.Fatalf("attachment: %+v", got)
	}
}

func TestCaseMutations_MapTheirInputs(t *testing.T) {
	cases := &fakeCases{}
	r := &resolvers.Resolver{CaseClient: cases}
	ctx := officerGrace(t)
	if _, err := r.AssignCaseResolver(ctx, "case-1", nil); err != nil || cases.lastAsg.GetAssigneeUserId() != "" {
		t.Fatalf("a null assignee clears it: %v %+v", err, cases.lastAsg)
	}
	if _, err := r.RecordRiskAssessmentResolver(ctx, "case-1", resolvers.RiskFactorsInput{
		Information: []resolvers.InformationKind{resolvers.InformationKindFinancial}, Recipient: resolvers.RiskRecipientAnotherOrganisation,
		Viewed: resolvers.RiskViewedProbably, Mitigation: resolvers.RiskMitigationPartly,
	}, resolvers.BreachDecisionReportable, "Sent outside."); err != nil {
		t.Fatalf("RecordRiskAssessmentResolver: %v", err)
	}
	f := cases.lastRisk.GetFactors()
	if f.GetRecipient() != reportingv1.Recipient_RECIPIENT_ANOTHER_ORGANISATION || f.GetViewed() != reportingv1.Viewed_VIEWED_PROBABLY ||
		f.GetMitigation() != reportingv1.Mitigation_MITIGATION_PARTLY || cases.lastRisk.GetDecision() != reportingv1.BreachDecision_BREACH_DECISION_REPORTABLE {
		t.Fatalf("risk request: %+v", cases.lastRisk)
	}
	policy := "pol-1"
	msg := "Thank you."
	if _, err := r.CloseCaseResolver(ctx, "case-1", resolvers.CaseOutcomeInconclusive,
		[]*resolvers.CorrectiveActionInput{{Description: "Train staff.", PolicyID: &policy}}, &msg); err != nil {
		t.Fatalf("CloseCaseResolver: %v", err)
	}
	if cases.lastClose.GetOutcome() != reportingv1.Outcome_OUTCOME_INCONCLUSIVE || cases.lastClose.GetCorrectiveActions()[0].GetPolicyId() != "pol-1" ||
		cases.lastClose.GetClosingMessage() != "Thank you." || cases.actor != "grace" {
		t.Fatalf("close request: %+v", cases.lastClose)
	}
}

func TestCaseCalls_NeedASignedInUser(t *testing.T) {
	cases := &fakeCases{}
	r := &resolvers.Resolver{CaseClient: cases}
	if _, err := r.ReportCaseResolver(context.Background(), "case-1"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}
