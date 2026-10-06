// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Bugs5382/go-redis/ratelimit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	reportingv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/reporting/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

// ReportLimiter throttles anonymous report checks and replies;
// *ratelimit.Limiter from go-redis implements it.
type ReportLimiter interface {
	Allow(ctx context.Context, key string, limit ratelimit.Limit) (ratelimit.Result, error)
}

// The anonymous check and reply throttle. Keys are never an address or a
// person: one is the hash of the normalised case code (so guessing the
// passphrase of one case is slow), the other is shared by every case (so
// guessing case codes is slow too). reporting adds its own slow hash on top.
var (
	reportPerCodeLimit = ratelimit.Limit{Rate: 10, Period: time.Hour, Burst: 5}
	reportOverallLimit = ratelimit.PerMinute(300)
)

const reportOverallKey = "report-check:all"

// reportCodeKey is the per-case throttle key: the SHA-256 of the case code
// with case, spaces and dashes ignored, as reporting matches it.
func reportCodeKey(caseCode string) string {
	norm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(caseCode))
	sum := sha256.Sum256([]byte(norm))
	return "report-check:" + hex.EncodeToString(sum[:])
}

// throttleReportCheck refuses an anonymous check or reply over either limit.
// It fails closed: without the throttle store nothing gets through.
func (r *Resolver) throttleReportCheck(ctx context.Context, caseCode string) error {
	if r.ReportLimiter == nil {
		return errcodes.New(errcodes.CodeReportThrottleUnavailable)
	}
	for _, c := range []struct {
		key   string
		limit ratelimit.Limit
	}{{reportCodeKey(caseCode), reportPerCodeLimit}, {reportOverallKey, reportOverallLimit}} {
		res, err := r.ReportLimiter.Allow(ctx, c.key, c.limit)
		if err != nil {
			r.logger().Error(err, "report check throttle unavailable")
			return errcodes.New(errcodes.CodeReportThrottleUnavailable)
		}
		if !res.Allowed {
			r.logger().Info("report check throttled", log.F("overall", c.key == reportOverallKey))
			return errcodes.New(errcodes.CodeReportChecksThrottled)
		}
	}
	return nil
}

// anonymousContext is ctx with nothing of the caller on it: no principal, so
// no go-grpc-actor actor and nothing else that could identify a reporter. It
// is cancelled with ctx and keeps its deadline.
func anonymousContext(ctx context.Context) (context.Context, context.CancelFunc) {
	anon, cancel := context.WithCancel(context.Background())
	if d, ok := ctx.Deadline(); ok {
		var cancelDeadline context.CancelFunc
		anon, cancelDeadline = context.WithDeadline(anon, d)
		prev := cancel
		cancel = func() { cancelDeadline(); prev() }
	}
	stop := context.AfterFunc(ctx, cancel)
	return anon, func() { stop(); cancel() }
}

func reportTime(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}

func reportTimePtr(ts *timestamppb.Timestamp) *string { return nilIfEmpty(reportTime(ts)) }

// protoEnum maps a GraphQL enum value onto the proto enum whose names are the
// GraphQL ones behind prefix.
func protoEnum[T ~int32](values map[string]int32, prefix, v string) T {
	return T(values[prefix+v])
}

// gqlEnum maps a proto enum name onto the GraphQL value; ok is false for the
// unspecified value.
func gqlEnum[T ~string](name, prefix string) (T, bool) {
	v := strings.TrimPrefix(name, prefix)
	return T(v), v != "UNSPECIFIED" && v != name
}

func gqlEnumPtr[T ~string](name, prefix string) *T {
	if v, ok := gqlEnum[T](name, prefix); ok {
		return &v
	}
	return nil
}

func caseStatusFromProto(s reportingv1.CaseStatus) CaseStatus {
	v, _ := gqlEnum[CaseStatus](s.String(), "CASE_STATUS_")
	return v
}

func caseStatusToProto(s CaseStatus) reportingv1.CaseStatus {
	return protoEnum[reportingv1.CaseStatus](reportingv1.CaseStatus_value, "CASE_STATUS_", string(s))
}

func reportDetailsFromProto(d *reportingv1.ReportDetails) *ReportDetails {
	kinds := make([]InformationKind, 0, len(d.GetInformationKinds()))
	for _, k := range d.GetInformationKinds() {
		if v, ok := gqlEnum[InformationKind](k.String(), "INFORMATION_KIND_"); ok {
			kinds = append(kinds, v)
		}
	}
	return &ReportDetails{
		WhatHappened:     d.GetWhatHappened(),
		Occurred:         d.GetOccurred(),
		Location:         d.GetLocation(),
		InformationKinds: kinds,
		StillHappening:   gqlEnumPtr[ReportAnswer](d.GetStillHappening().String(), "ANSWER_"),
	}
}

func reportDetailsToProto(in ReportDetailsInput) *reportingv1.ReportDetails {
	d := &reportingv1.ReportDetails{
		WhatHappened: in.WhatHappened,
		Occurred:     derefOrEmpty(in.Occurred),
		Location:     derefOrEmpty(in.Location),
	}
	for _, k := range in.InformationKinds {
		d.InformationKinds = append(d.InformationKinds, protoEnum[reportingv1.InformationKind](reportingv1.InformationKind_value, "INFORMATION_KIND_", string(k)))
	}
	if in.StillHappening != nil {
		d.StillHappening = protoEnum[reportingv1.Answer](reportingv1.Answer_value, "ANSWER_", string(*in.StillHappening))
	}
	return d
}

func reportAttachmentsToProto(in []*ReportAttachmentInput) ([]*reportingv1.AttachmentUpload, error) {
	out := make([]*reportingv1.AttachmentUpload, 0, len(in))
	for i, a := range in {
		data, err := base64.StdEncoding.DecodeString(a.Data)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "attachment %d is not valid base64", i+1)
		}
		out = append(out, &reportingv1.AttachmentUpload{Filename: a.Filename, ContentType: a.ContentType, Data: data})
	}
	return out, nil
}

// threadFromProto maps a thread. forReporter drops the officer ids, which a
// reporter never sees.
func threadFromProto(msgs []*reportingv1.ThreadMessage, forReporter bool) []*ThreadMessage {
	out := make([]*ThreadMessage, 0, len(msgs))
	for _, m := range msgs {
		author, _ := gqlEnum[MessageAuthor](m.GetAuthor().String(), "MESSAGE_AUTHOR_")
		tm := &ThreadMessage{ID: m.GetId(), Author: author, Body: m.GetBody(), CreatedAt: reportTime(m.GetCreatedAt())}
		if !forReporter {
			tm.OfficerUserID = nilIfEmpty(m.GetOfficerUserId())
		}
		out = append(out, tm)
	}
	return out
}

func reporterViewFromProto(v *reportingv1.ReporterView) *ReporterView {
	return &ReporterView{
		CaseCode:   v.GetCaseCode(),
		Status:     caseStatusFromProto(v.GetStatus()),
		Details:    reportDetailsFromProto(v.GetDetails()),
		Thread:     threadFromProto(v.GetThread(), true),
		ReceivedAt: reportTime(v.GetReceivedAt()),
	}
}

func reportAttachmentFromProto(a *reportingv1.Attachment) *ReportAttachment {
	return &ReportAttachment{
		ID: a.GetId(), Filename: a.GetFilename(), ContentType: a.GetContentType(),
		SizeBytes: int(a.GetSizeBytes()), MetadataStripped: a.GetMetadataStripped(),
	}
}

func riskFactorsFromProto(f *reportingv1.RiskFactors) *RiskFactors {
	info := make([]InformationKind, 0, len(f.GetInformation()))
	for _, k := range f.GetInformation() {
		if v, ok := gqlEnum[InformationKind](k.String(), "INFORMATION_KIND_"); ok {
			info = append(info, v)
		}
	}
	return &RiskFactors{
		Information: info,
		Recipient:   gqlEnumPtr[RiskRecipient](f.GetRecipient().String(), "RECIPIENT_"),
		Viewed:      gqlEnumPtr[RiskViewed](f.GetViewed().String(), "VIEWED_"),
		Mitigation:  gqlEnumPtr[RiskMitigation](f.GetMitigation().String(), "MITIGATION_"),
	}
}

func riskAssessmentFromProto(a *reportingv1.RiskAssessment) *RiskAssessment {
	if a == nil {
		return nil
	}
	return &RiskAssessment{
		Factors:         riskFactorsFromProto(a.GetFactors()),
		Suggestion:      gqlEnumPtr[RiskSuggestion](a.GetSuggestion().String(), "SUGGESTION_"),
		Decision:        gqlEnumPtr[BreachDecision](a.GetDecision().String(), "BREACH_DECISION_"),
		Reason:          a.GetReason(),
		DecidedByUserID: a.GetDecidedByUserId(),
		DecidedAt:       reportTime(a.GetDecidedAt()),
	}
}

func caseNoticeFromProto(n *reportingv1.Notice) *CaseNotice {
	recipient, _ := gqlEnum[NoticeRecipient](n.GetRecipient().String(), "NOTICE_RECIPIENT_")
	st, _ := gqlEnum[NoticeStatus](n.GetStatus().String(), "NOTICE_STATUS_")
	return &CaseNotice{
		ID: n.GetId(), Recipient: recipient, Label: n.GetLabel(), Method: n.GetMethod(),
		DaysAllowed: int(n.GetDaysAllowed()), DueOn: n.GetDueOn(), Status: st, SentOn: nilIfEmpty(n.GetSentOn()),
	}
}

func reportCaseFromProto(c *reportingv1.Case) *ReportCase {
	kind, _ := gqlEnum[ReportKind](c.GetKind().String(), "REPORT_KIND_")
	out := &ReportCase{
		ID: c.GetId(), CaseCode: c.GetCaseCode(), Kind: kind, Status: caseStatusFromProto(c.GetStatus()),
		Details:        reportDetailsFromProto(c.GetDetails()),
		ReporterUserID: nilIfEmpty(c.GetReporterUserId()),
		AssigneeUserID: nilIfEmpty(c.GetAssigneeUserId()),
		ReceivedAt:     reportTime(c.GetReceivedAt()),
		DiscoveredOn:   nilIfEmpty(c.GetDiscoveredOn()),
		Thread:         threadFromProto(c.GetThread(), false),
		Assessment:     riskAssessmentFromProto(c.GetAssessment()),
		Outcome:        gqlEnumPtr[CaseOutcome](c.GetOutcome().String(), "OUTCOME_"),
		ClosedAt:       reportTimePtr(c.GetClosedAt()),
	}
	for _, a := range c.GetAttachments() {
		out.Attachments = append(out.Attachments, reportAttachmentFromProto(a))
	}
	for _, n := range c.GetNotes() {
		out.Notes = append(out.Notes, &CaseNote{ID: n.GetId(), AuthorUserID: n.GetAuthorUserId(), Body: n.GetBody(), CreatedAt: reportTime(n.GetCreatedAt())})
	}
	for _, n := range c.GetNotices() {
		out.Notices = append(out.Notices, caseNoticeFromProto(n))
	}
	for _, a := range c.GetCorrectiveActions() {
		out.CorrectiveActions = append(out.CorrectiveActions, &CorrectiveAction{Description: a.GetDescription(), PolicyID: nilIfEmpty(a.GetPolicyId())})
	}
	out.Attachments, out.Notes = orEmpty(out.Attachments), orEmpty(out.Notes)
	out.Notices, out.CorrectiveActions = orEmpty(out.Notices), orEmpty(out.CorrectiveActions)
	return out
}

// SubmitAnonymousReportResolver files an anonymous report. It works signed
// out, and a signed-in caller stays anonymous: reporting is called with no
// actor.
func (r *Resolver) SubmitAnonymousReportResolver(ctx context.Context, details ReportDetailsInput, passphrase string, attachments []*ReportAttachmentInput) (*AnonymousReportReceipt, error) {
	uploads, err := reportAttachmentsToProto(attachments)
	if err != nil {
		return nil, err
	}
	anon, cancel := anonymousContext(ctx)
	defer cancel()
	resp, err := r.IntakeClient.SubmitAnonymousReport(anon, &reportingv1.SubmitAnonymousReportRequest{
		Details: reportDetailsToProto(details), Passphrase: passphrase, Attachments: uploads,
	})
	if err != nil {
		return nil, err
	}
	return &AnonymousReportReceipt{CaseCode: resp.GetCaseCode()}, nil
}

// CheckReportResolver opens an anonymous report by case code and passphrase,
// throttled.
func (r *Resolver) CheckReportResolver(ctx context.Context, caseCode, passphrase string) (*ReporterView, error) {
	if err := r.throttleReportCheck(ctx, caseCode); err != nil {
		return nil, err
	}
	anon, cancel := anonymousContext(ctx)
	defer cancel()
	resp, err := r.IntakeClient.CheckReport(anon, &reportingv1.CheckReportRequest{CaseCode: caseCode, Passphrase: passphrase})
	if err != nil {
		return nil, err
	}
	return reporterViewFromProto(resp.GetReport()), nil
}

// ReplyToReportResolver adds the anonymous reporter's reply, throttled.
func (r *Resolver) ReplyToReportResolver(ctx context.Context, caseCode, passphrase, body string) (*ReporterView, error) {
	if err := r.throttleReportCheck(ctx, caseCode); err != nil {
		return nil, err
	}
	anon, cancel := anonymousContext(ctx)
	defer cancel()
	resp, err := r.IntakeClient.ReplyToReport(anon, &reportingv1.ReplyToReportRequest{CaseCode: caseCode, Passphrase: passphrase, Body: body})
	if err != nil {
		return nil, err
	}
	return reporterViewFromProto(resp.GetReport()), nil
}

// SubmitNamedReportResolver files a report as the signed-in user.
func (r *Resolver) SubmitNamedReportResolver(ctx context.Context, details ReportDetailsInput, attachments []*ReportAttachmentInput) (*NamedReportReceipt, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	uploads, err := reportAttachmentsToProto(attachments)
	if err != nil {
		return nil, err
	}
	resp, err := r.IntakeClient.SubmitNamedReport(ctx, &reportingv1.SubmitNamedReportRequest{Details: reportDetailsToProto(details), Attachments: uploads})
	if err != nil {
		return nil, err
	}
	return &NamedReportReceipt{CaseID: resp.GetCaseId(), CaseCode: resp.GetCaseCode()}, nil
}

// MyReportsResolver lists the signed-in user's own named reports.
func (r *Resolver) MyReportsResolver(ctx context.Context) ([]*MyReport, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.IntakeClient.ListMyReports(ctx, &reportingv1.ListMyReportsRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]*MyReport, 0, len(resp.GetReports()))
	for _, m := range resp.GetReports() {
		out = append(out, &MyReport{CaseID: m.GetCaseId(), Report: reporterViewFromProto(m.GetReport())})
	}
	return out, nil
}

// MyReportResolver opens one of the signed-in user's own named reports.
func (r *Resolver) MyReportResolver(ctx context.Context, caseID string) (*ReporterView, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.IntakeClient.GetMyReport(ctx, &reportingv1.GetMyReportRequest{CaseId: caseID})
	if err != nil {
		return nil, err
	}
	return reporterViewFromProto(resp.GetReport()), nil
}

// ReplyToMyReportResolver adds the signed-in reporter's reply.
func (r *Resolver) ReplyToMyReportResolver(ctx context.Context, caseID, body string) (*ReporterView, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.IntakeClient.ReplyToMyReport(ctx, &reportingv1.ReplyToMyReportRequest{CaseId: caseID, Body: body})
	if err != nil {
		return nil, err
	}
	return reporterViewFromProto(resp.GetReport()), nil
}

// The officer calls below need a signed-in user; reporting decides whether
// they are an officer.

// ReportCasesResolver is the officer's case queue.
func (r *Resolver) ReportCasesResolver(ctx context.Context, statuses []CaseStatus, assigneeUserID *string) (*CaseQueue, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	req := &reportingv1.ListCasesRequest{AssigneeUserId: derefOrEmpty(assigneeUserID)}
	for _, s := range statuses {
		req.Statuses = append(req.Statuses, caseStatusToProto(s))
	}
	resp, err := r.CaseClient.ListCases(ctx, req)
	if err != nil {
		return nil, err
	}
	q := &CaseQueue{Cases: []*CaseSummary{}, Counts: []*CaseStatusCount{}}
	for _, c := range resp.GetCases() {
		kind, _ := gqlEnum[ReportKind](c.GetKind().String(), "REPORT_KIND_")
		q.Cases = append(q.Cases, &CaseSummary{
			ID: c.GetId(), CaseCode: c.GetCaseCode(), Kind: kind, Status: caseStatusFromProto(c.GetStatus()),
			Summary: c.GetSummary(), AssigneeUserID: nilIfEmpty(c.GetAssigneeUserId()),
			ReceivedAt: reportTime(c.GetReceivedAt()), NextDeadline: nilIfEmpty(c.GetNextDeadline()),
		})
	}
	for _, n := range resp.GetCounts() {
		q.Counts = append(q.Counts, &CaseStatusCount{Status: caseStatusFromProto(n.GetStatus()), Count: int(n.GetCount())})
	}
	return q, nil
}

// ReportCaseResolver opens one case.
func (r *Resolver) ReportCaseResolver(ctx context.Context, caseID string) (*ReportCase, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.CaseClient.GetCase(ctx, &reportingv1.GetCaseRequest{CaseId: caseID})
	if err != nil {
		return nil, err
	}
	return reportCaseFromProto(resp.GetCase()), nil
}

// ReportAttachmentResolver returns a stored attachment, base64.
func (r *Resolver) ReportAttachmentResolver(ctx context.Context, caseID, attachmentID string) (*ReportAttachmentContent, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.CaseClient.GetAttachment(ctx, &reportingv1.GetAttachmentRequest{CaseId: caseID, AttachmentId: attachmentID})
	if err != nil {
		return nil, err
	}
	return &ReportAttachmentContent{
		Attachment: reportAttachmentFromProto(resp.GetAttachment()),
		Data:       base64.StdEncoding.EncodeToString(resp.GetData()),
	}, nil
}

// PostCaseMessageResolver writes to the reporter's thread.
func (r *Resolver) PostCaseMessageResolver(ctx context.Context, caseID, body string) (*ThreadMessage, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.CaseClient.PostMessage(ctx, &reportingv1.PostMessageRequest{CaseId: caseID, Body: body})
	if err != nil {
		return nil, err
	}
	return threadFromProto([]*reportingv1.ThreadMessage{resp.GetMessage()}, false)[0], nil
}

// AddCaseNoteResolver adds an internal note.
func (r *Resolver) AddCaseNoteResolver(ctx context.Context, caseID, body string) (*CaseNote, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.CaseClient.AddNote(ctx, &reportingv1.AddNoteRequest{CaseId: caseID, Body: body})
	if err != nil {
		return nil, err
	}
	n := resp.GetNote()
	return &CaseNote{ID: n.GetId(), AuthorUserID: n.GetAuthorUserId(), Body: n.GetBody(), CreatedAt: reportTime(n.GetCreatedAt())}, nil
}

// AssignCaseResolver sets or (nil) clears the assignee.
func (r *Resolver) AssignCaseResolver(ctx context.Context, caseID string, assigneeUserID *string) (*ReportCase, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.CaseClient.AssignCase(ctx, &reportingv1.AssignCaseRequest{CaseId: caseID, AssigneeUserId: derefOrEmpty(assigneeUserID)})
	if err != nil {
		return nil, err
	}
	return reportCaseFromProto(resp.GetCase()), nil
}

// SetCaseStatusResolver moves an open case to any status but closed.
func (r *Resolver) SetCaseStatusResolver(ctx context.Context, caseID string, st CaseStatus) (*ReportCase, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.CaseClient.SetCaseStatus(ctx, &reportingv1.SetCaseStatusRequest{CaseId: caseID, Status: caseStatusToProto(st)})
	if err != nil {
		return nil, err
	}
	return reportCaseFromProto(resp.GetCase()), nil
}

// SetCaseDiscoveryDateResolver sets when the incident was discovered.
func (r *Resolver) SetCaseDiscoveryDateResolver(ctx context.Context, caseID, discoveredOn string) (*ReportCase, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.CaseClient.SetDiscoveryDate(ctx, &reportingv1.SetDiscoveryDateRequest{CaseId: caseID, DiscoveredOn: discoveredOn})
	if err != nil {
		return nil, err
	}
	return reportCaseFromProto(resp.GetCase()), nil
}

// RecordRiskAssessmentResolver records the guided assessment and decision.
func (r *Resolver) RecordRiskAssessmentResolver(ctx context.Context, caseID string, factors RiskFactorsInput, decision BreachDecision, reason string) (*RiskAssessment, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	f := &reportingv1.RiskFactors{
		Recipient:  protoEnum[reportingv1.Recipient](reportingv1.Recipient_value, "RECIPIENT_", string(factors.Recipient)),
		Viewed:     protoEnum[reportingv1.Viewed](reportingv1.Viewed_value, "VIEWED_", string(factors.Viewed)),
		Mitigation: protoEnum[reportingv1.Mitigation](reportingv1.Mitigation_value, "MITIGATION_", string(factors.Mitigation)),
	}
	for _, k := range factors.Information {
		f.Information = append(f.Information, protoEnum[reportingv1.InformationKind](reportingv1.InformationKind_value, "INFORMATION_KIND_", string(k)))
	}
	resp, err := r.CaseClient.RecordRiskAssessment(ctx, &reportingv1.RecordRiskAssessmentRequest{
		CaseId: caseID, Factors: f, Reason: reason,
		Decision: protoEnum[reportingv1.BreachDecision](reportingv1.BreachDecision_value, "BREACH_DECISION_", string(decision)),
	})
	if err != nil {
		return nil, err
	}
	return riskAssessmentFromProto(resp.GetAssessment()), nil
}

// AddCaseNoticeResolver adds a notice to track.
func (r *Resolver) AddCaseNoticeResolver(ctx context.Context, caseID string, recipient NoticeRecipient, label, method *string) (*CaseNotice, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.CaseClient.AddNotice(ctx, &reportingv1.AddNoticeRequest{
		CaseId:    caseID,
		Recipient: protoEnum[reportingv1.NoticeRecipient](reportingv1.NoticeRecipient_value, "NOTICE_RECIPIENT_", string(recipient)),
		Label:     derefOrEmpty(label),
		Method:    derefOrEmpty(method),
	})
	if err != nil {
		return nil, err
	}
	return caseNoticeFromProto(resp.GetNotice()), nil
}

// UpdateCaseNoticeResolver records a notice's progress.
func (r *Resolver) UpdateCaseNoticeResolver(ctx context.Context, caseID, noticeID string, st NoticeStatus, sentOn *string) (*CaseNotice, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	resp, err := r.CaseClient.UpdateNotice(ctx, &reportingv1.UpdateNoticeRequest{
		CaseId:   caseID,
		NoticeId: noticeID,
		Status:   protoEnum[reportingv1.NoticeStatus](reportingv1.NoticeStatus_value, "NOTICE_STATUS_", string(st)),
		SentOn:   derefOrEmpty(sentOn),
	})
	if err != nil {
		return nil, err
	}
	return caseNoticeFromProto(resp.GetNotice()), nil
}

// CloseCaseResolver records the outcome and corrective actions.
func (r *Resolver) CloseCaseResolver(ctx context.Context, caseID string, outcome CaseOutcome, actions []*CorrectiveActionInput, closingMessage *string) (*ReportCase, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	req := &reportingv1.CloseCaseRequest{
		CaseId:         caseID,
		Outcome:        protoEnum[reportingv1.Outcome](reportingv1.Outcome_value, "OUTCOME_", string(outcome)),
		ClosingMessage: derefOrEmpty(closingMessage),
	}
	for _, a := range actions {
		req.CorrectiveActions = append(req.CorrectiveActions, &reportingv1.CorrectiveAction{Description: a.Description, PolicyId: derefOrEmpty(a.PolicyID)})
	}
	resp, err := r.CaseClient.CloseCase(ctx, req)
	if err != nil {
		return nil, err
	}
	return reportCaseFromProto(resp.GetCase()), nil
}
