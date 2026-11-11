// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// Row 56 of the Go parity plan (steward-gateway#48): core files a policy's
// creation and a discarded draft under policy:<id>, and its draft saves and
// publishes under policy_version:<id>; workflow files every run event under
// policy_version:<id>. policyHistory joins them into one timeline.

// subjectAudit is audit as it serves a query: the records of one exact subject
// in id order, a page at a time after the token's id, at most perPage a page.
type subjectAudit struct {
	auditv1.AuditServiceClient
	bySubject map[string][]*auditv1.AuditRecord
	perPage   int
	requests  []*auditv1.QueryAuditLogRequest
	err       error
}

func (s *subjectAudit) QueryAuditLog(_ context.Context, in *auditv1.QueryAuditLogRequest, _ ...grpc.CallOption) (*auditv1.QueryAuditLogResponse, error) {
	s.requests = append(s.requests, in)
	if s.err != nil {
		return nil, s.err
	}
	var after int64
	if in.GetPageToken() != "" {
		after, _ = strconv.ParseInt(in.GetPageToken(), 10, 64)
	}
	limit := int(in.GetPageSize())
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if s.perPage > 0 && s.perPage < limit {
		limit = s.perPage
	}
	resp := &auditv1.QueryAuditLogResponse{}
	for _, r := range s.bySubject[in.GetSubject()] {
		if r.GetId() > after && len(resp.Records) < limit {
			resp.Records = append(resp.Records, r)
		}
	}
	if len(resp.Records) == limit {
		resp.NextPageToken = strconv.FormatInt(resp.Records[len(resp.Records)-1].GetId(), 10)
	}
	return resp, nil
}

func auditRec(id int64, action, subject string, versionNo int32) *auditv1.AuditRecord {
	return &auditv1.AuditRecord{
		Id: id, RecordUuid: "rec-" + strconv.FormatInt(id, 10), Tier: "audit", Action: action,
		ActorUserId: "u-1", Subject: subject, GroupId: "g-cat", VersionNumber: versionNo,
		OccurredAt: timestamppb.New(time.Date(2026, 11, 1, 9, 0, int(id), 0, time.UTC)),
	}
}

// historyAudit is the audit log of policy "pol" (see draftPointerEnv): version 1
// is published as pub-1, version 2 is the working draft draft-1.
func historyAudit() *subjectAudit {
	return &subjectAudit{bySubject: map[string][]*auditv1.AuditRecord{
		"policy:pol": {
			auditRec(1, "policy.created", "policy:pol", 0),
			auditRec(9, "policy.draft_discarded", "policy:pol", 0),
		},
		"policy_version:pub-1": {
			auditRec(2, "policy.draft_saved", "policy_version:pub-1", 1),
			auditRec(3, "workflow.submitted", "policy_version:pub-1", 1),
			auditRec(4, "workflow.decision.approved", "policy_version:pub-1", 1),
			auditRec(5, "policy.published", "policy_version:pub-1", 1),
		},
		"policy_version:draft-1": {
			auditRec(6, "policy.draft_saved", "policy_version:draft-1", 2),
			auditRec(7, "workflow.submitted", "policy_version:draft-1", 2),
		},
		// Another policy's records are never asked for.
		"policy_version:other": {auditRec(8, "policy.published", "policy_version:other", 1)},
	}}
}

func historyIDs(page *resolvers.AuditQueryPage) []string {
	out := make([]string, 0, len(page.Records))
	for _, r := range page.Records {
		out = append(out, r.ID)
	}
	return out
}

func readHistory(ctx context.Context, au auditv1.AuditServiceClient, pc corev1.PolicyServiceClient, gc corev1.CategoryServiceClient, wf workflowv1.WorkflowServiceClient, pageSize *int, token *string) (*resolvers.AuditQueryPage, error) {
	return resolvers.PolicyHistoryResolver(ctx, log.Nop(), au, nil, gc, pc, nil, noGrant(), wf, "pol", pageSize, token)
}

func authorCtx(t *testing.T) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: "editor-u", RolesValue: []string{"reader"}})
}

func editorEnv() (*recordingPolicyClient, *raciCategoryClient) {
	pc, gc := draftPointerEnv([]*corev1.CategoryRule{authorRule("editor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	return &recordingPolicyClient{fakePolicyClient: pc}, gc
}

func TestPolicyHistory_MergesPolicyAndVersionSubjectsNewestFirst(t *testing.T) {
	pc, gc := editorEnv()
	au := historyAudit()

	page, err := readHistory(authorCtx(t), au, pc, gc, nil, nil, nil)
	if err != nil {
		t.Fatalf("PolicyHistoryResolver: %v", err)
	}
	want := []string{"9", "7", "6", "5", "4", "3", "2", "1"}
	if got := historyIDs(page); !slices.Equal(got, want) {
		t.Fatalf("record ids = %v, want %v (both subjects, newest first)", got, want)
	}
	if page.NextPageToken != "" {
		t.Fatalf("nextPageToken = %q, want none on the last page", page.NextPageToken)
	}
	byID := map[string]*resolvers.AuditRecord{}
	for _, r := range page.Records {
		byID[r.ID] = r
	}
	if byID["1"].VersionNumber != nil {
		t.Fatalf("a policy-level record carries version %d, want null", *byID["1"].VersionNumber)
	}
	if v := byID["4"].VersionNumber; v == nil || *v != 1 {
		t.Fatalf("approval versionNumber = %v, want 1", v)
	}
	if v := byID["7"].VersionNumber; v == nil || *v != 2 {
		t.Fatalf("draft submission versionNumber = %v, want 2", v)
	}
}

func TestPolicyHistory_AsksAuditForExactSubjectsAsTheCaller(t *testing.T) {
	pc, gc := editorEnv()
	au := historyAudit()
	if _, err := readHistory(authorCtx(t), au, pc, gc, nil, nil, nil); err != nil {
		t.Fatalf("PolicyHistoryResolver: %v", err)
	}
	var subjects []string
	for _, r := range au.requests {
		subjects = append(subjects, r.GetSubject())
		if r.GetRequester().GetUserId() != "editor-u" {
			t.Fatalf("requester = %q, want the signed-in caller", r.GetRequester().GetUserId())
		}
		if !slices.Contains(r.GetRequester().GetRoles(), "compliance-admin") {
			t.Fatalf("requester roles = %v, want a role that holds audit.read once the policy read passed", r.GetRequester().GetRoles())
		}
	}
	slices.Sort(subjects)
	want := []string{"policy:pol", "policy_version:draft-1", "policy_version:pub-1"}
	if !slices.Equal(subjects, want) {
		t.Fatalf("subjects asked = %v, want %v", subjects, want)
	}
}

func TestPolicyHistory_FollowsAuditPagesWithinASubject(t *testing.T) {
	pc, gc := editorEnv()
	au := historyAudit()
	au.perPage = 1
	page, err := readHistory(authorCtx(t), au, pc, gc, nil, nil, nil)
	if err != nil {
		t.Fatalf("PolicyHistoryResolver: %v", err)
	}
	if got := historyIDs(page); len(got) != 8 {
		t.Fatalf("record ids = %v, want all 8 across audit's one-record pages", got)
	}
}

func TestPolicyHistory_PagesTheMergedTimeline(t *testing.T) {
	pc, gc := editorEnv()
	au := historyAudit()
	size := 3
	var got []string
	token := (*string)(nil)
	for range 5 {
		page, err := readHistory(authorCtx(t), au, pc, gc, nil, &size, token)
		if err != nil {
			t.Fatalf("PolicyHistoryResolver: %v", err)
		}
		if len(page.Records) > size {
			t.Fatalf("page has %d records, want at most %d", len(page.Records), size)
		}
		got = append(got, historyIDs(page)...)
		if page.NextPageToken == "" {
			break
		}
		next := page.NextPageToken
		token = &next
	}
	want := []string{"9", "7", "6", "5", "4", "3", "2", "1"}
	if !slices.Equal(got, want) {
		t.Fatalf("paged ids = %v, want %v with no repeat or gap", got, want)
	}
}

func TestPolicyHistory_RejectsAPageTokenItDidNotIssue(t *testing.T) {
	pc, gc := editorEnv()
	bad := "not-a-cursor"
	page, err := readHistory(authorCtx(t), historyAudit(), pc, gc, nil, nil, &bad)
	if page != nil || status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %+v, %v; want InvalidArgument", page, err)
	}
}

func TestPolicyHistory_PlainReaderSeesPublishedHistoryNotTheDraft(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	rc := &recordingPolicyClient{fakePolicyClient: pc}
	au := historyAudit()
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u", RolesValue: []string{"reader"}})

	page, err := readHistory(ctx, au, rc, gc, nil, nil, nil)
	if err != nil {
		t.Fatalf("PolicyHistoryResolver: %v", err)
	}
	want := []string{"9", "5", "4", "3", "2", "1"}
	if got := historyIDs(page); !slices.Equal(got, want) {
		t.Fatalf("record ids = %v, want %v (the draft's records left out)", got, want)
	}
	for _, r := range au.requests {
		if r.GetSubject() == "policy_version:draft-1" {
			t.Fatalf("audit was asked for the draft's records")
		}
	}
}

func TestPolicyHistory_PendingApproverSeesTheDraftTheyHoldASeatOn(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	rc := &recordingPolicyClient{fakePolicyClient: pc}
	wf := seatsOn("draft-1")
	page, err := readHistory(approverCtx(t), historyAudit(), rc, gc, wf, nil, nil)
	if err != nil {
		t.Fatalf("PolicyHistoryResolver: %v", err)
	}
	want := []string{"9", "7", "6", "5", "4", "3", "2", "1"}
	if got := historyIDs(page); !slices.Equal(got, want) {
		t.Fatalf("record ids = %v, want %v for a pending approver", got, want)
	}
}

func TestPolicyHistory_ApproverWithoutASeatOnTheDraftDoesNotSeeIt(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	rc := &recordingPolicyClient{fakePolicyClient: pc}
	wf := seatsOn("some-other-version")
	page, err := readHistory(approverCtx(t), historyAudit(), rc, gc, wf, nil, nil)
	if err != nil {
		t.Fatalf("PolicyHistoryResolver: %v", err)
	}
	for _, id := range historyIDs(page) {
		if id == "6" || id == "7" {
			t.Fatalf("record %s of the draft shown without a seat on it", id)
		}
	}
}

func TestPolicyHistory_ReaderWhoCannotReadThePolicyGetsNotFoundAndAuditIsNotAsked(t *testing.T) {
	pc, gc, _ := breakGlassReadSetup(t, true)
	au := &subjectAudit{bySubject: map[string][]*auditv1.AuditRecord{
		"policy:pol-1": {auditRec(1, "policy.created", "policy:pol-1", 0)},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", IdpGroupsValue: []string{"Admins"}})

	page, err := resolvers.PolicyHistoryResolver(ctx, log.Nop(), au, nil, gc, pc, nil, noGrant(), nil, "pol-1", nil, nil)
	if page != nil || status.Code(err) != codes.NotFound {
		t.Fatalf("got %+v, %v; want NotFound", page, err)
	}
	if len(au.requests) != 0 {
		t.Fatalf("audit asked %d times for a refused read, want 0", len(au.requests))
	}
}

func TestPolicyHistory_UnknownPolicyIsNotFound(t *testing.T) {
	pc, gc := editorEnv()
	page, err := resolvers.PolicyHistoryResolver(authorCtx(t), log.Nop(), historyAudit(), nil, gc, pc, nil, noGrant(), nil, "no-such-policy", nil, nil)
	if page != nil || err == nil {
		t.Fatalf("got %+v, %v; want an error", page, err)
	}
}

func TestPolicyHistory_RefusesAnUnauthenticatedCaller(t *testing.T) {
	pc, gc := editorEnv()
	au := historyAudit()
	page, err := readHistory(context.Background(), au, pc, gc, nil, nil, nil)
	if page != nil || err == nil {
		t.Fatalf("got %+v, %v; want an error", page, err)
	}
	if len(au.requests) != 0 {
		t.Fatalf("audit asked %d times with no caller, want 0", len(au.requests))
	}
}

func TestPolicyHistory_AuditFailureFailsTheQuery(t *testing.T) {
	pc, gc := editorEnv()
	au := historyAudit()
	au.err = status.Error(codes.Unavailable, "audit down")
	page, err := readHistory(authorCtx(t), au, pc, gc, nil, nil, nil)
	if page != nil || err == nil {
		t.Fatalf("got %+v, %v; want an error and no partial timeline", page, err)
	}
}
