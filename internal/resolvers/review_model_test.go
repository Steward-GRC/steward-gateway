// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"github.com/Steward-GRC/steward-gateway/internal/server"
)

// The review model on the gateway (#104). The mock server is the reference for
// what steward-web sees: steward-mock-server src/product/author-loop.test.ts
// ("submitting a draft for review" and "deciding an approval") and
// src/product/error-codes.test.ts. Each test below is one row of the parity
// table in the PR; its name says which mock test it follows.

// Version statuses reach steward-web without core's POLICY_VERSION_STATUS_
// prefix, as the mock spells them: the web reads Policy.currentVersionStatus
// by its bare name (packages/api-client/src/edge/assemble.ts policyStatusOf)
// and the draft's status the same way (apps/staff authoring.server.ts), so a
// prefixed IN_REVIEW would show as a plain draft.
const (
	reviewAuthor   = "author-u"
	reviewApprover = "charlie-u"
	reviewOther    = "dave-u"
	inReviewName   = "IN_REVIEW"
	rejectedName   = "REJECTED"
)

// reviewWorkflow is the workflow fake with the calls it saw in order, a
// history per stage and a Signal error to hand back.
type reviewWorkflow struct {
	*fakeWorkflowClient
	calls        *[]string
	history      map[int32][]*workflowv1.AssignmentHistoryEntry
	historyErrOn bool
	historyAsked []int32
}

func newReviewWorkflow(calls *[]string) *reviewWorkflow {
	return &reviewWorkflow{fakeWorkflowClient: &fakeWorkflowClient{}, calls: calls}
}

func (w *reviewWorkflow) Signal(ctx context.Context, in *workflowv1.SignalRequest, opts ...grpc.CallOption) (*workflowv1.SignalResponse, error) {
	*w.calls = append(*w.calls, "workflow.signal:"+in.GetSignal().String())
	return w.fakeWorkflowClient.Signal(ctx, in, opts...)
}

func (w *reviewWorkflow) GetAssignmentHistory(_ context.Context, in *workflowv1.GetAssignmentHistoryRequest, _ ...grpc.CallOption) (*workflowv1.GetAssignmentHistoryResponse, error) {
	w.historyAsked = append(w.historyAsked, in.GetStageIndex())
	if w.historyErrOn {
		return nil, status.Error(codes.Unavailable, "workflow history is down")
	}
	return &workflowv1.GetAssignmentHistoryResponse{Entries: w.history[in.GetStageIndex()]}, nil
}

// reviewPolicy is the core fake with the calls it saw in order, the draft
// SaveDraft hands back, and no draft left once DiscardDraft ran.
type reviewPolicy struct {
	*fakePolicyClient
	calls      *[]string
	savedDraft *corev1.PolicyVersion
}

func (p *reviewPolicy) DiscardDraft(ctx context.Context, in *corev1.DiscardDraftRequest, opts ...grpc.CallOption) (*corev1.DiscardDraftResponse, error) {
	*p.calls = append(*p.calls, "core.discard")
	return p.fakePolicyClient.DiscardDraft(ctx, in, opts...)
}

func (p *reviewPolicy) SaveDraft(ctx context.Context, in *corev1.SaveDraftRequest, opts ...grpc.CallOption) (*corev1.SaveDraftResponse, error) {
	p.lastSave = in
	return &corev1.SaveDraftResponse{Version: p.savedDraft}, nil
}

// reviewFixture is policy "pol" owned by reviewAuthor, in category g-cat that
// everyone may read. Its version "v-review" is the draft slot holder.
func reviewFixture(versionStatus corev1.PolicyVersionStatus) (*reviewPolicy, *raciCategoryClient, *[]string) {
	pc, gc := draftPointerEnv(nil)
	pc.policies["pol"].OwnerUserId = reviewAuthor
	pc.policies["pol"].CurrentDraftVersionId = "v-review"
	pc.policies["pol"].CurrentPublishedVersionId = ""
	pc.versions = map[string]*corev1.PolicyVersion{
		"v-review": {Id: "v-review", PolicyId: "pol", VersionNo: 1, Status: versionStatus, ContentJson: `{"root":{"secret":"in review"}}`},
	}
	calls := []string{}
	return &reviewPolicy{fakePolicyClient: pc, calls: &calls}, gc, &calls
}

func userCtx(t *testing.T, uid string) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: uid, RolesValue: []string{"reader"}})
}

type gqlFailure struct {
	Message    string         `json:"message"`
	Extensions map[string]any `json:"extensions"`
}

// reviewGQL runs a query through the generated schema with the gateway's own
// error presenter, so extensions.code is what steward-web reads.
func reviewGQL(t *testing.T, ctx context.Context, r *resolvers.Resolver, query string) (json.RawMessage, []gqlFailure) {
	t.Helper()
	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{Resolvers: r}))
	srv.AddTransport(transport.POST{})
	srv.SetErrorPresenter(server.ErrorPresenter(log.Nop()))
	body, err := json.Marshal(map[string]any{"query": query})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest("POST", "/query", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var out struct {
		Data   json.RawMessage `json:"data"`
		Errors []gqlFailure    `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v\n%s", err, rec.Body.String())
	}
	return out.Data, out.Errors
}

func errCodeOf(t *testing.T, errs []gqlFailure) string {
	t.Helper()
	if len(errs) == 0 {
		t.Fatal("want a GraphQL error, got none")
	}
	code, _ := errs[0].Extensions["code"].(string)
	return code
}

const submitMutation = `mutation { submitWorkflow(policyVersionId: "v-review", policyId: "pol", categoryId: "g-cat", ancestorCategoryIds: []) { runId } }`

func signalMutation(signal, comment string) string {
	return `mutation { signalWorkflow(policyVersionId: "v-review", runId: "run-1", taskId: "task-1", signal: ` + signal + `, comment: "` + comment + `") }`
}

// --- submitting a draft for review ---

// mock: "starts a run on the home category's workflow and gives the approver a
// task". The run is IN_REVIEW, the policy reports the version in review, and
// the gateway hands the run id back.
func TestReviewParity_SubmitStartsRunAndTheVersionIsInReview(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_IN_REVIEW)
	pc.policies["pol"].CurrentVersionStatus = corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_IN_REVIEW
	pc.policies["pol"].CurrentVersionNo = 1
	wf := newReviewWorkflow(calls)
	wf.submitResp = &workflowv1.SubmitResponse{RunId: "run-1"}
	wf.statusResp = &workflowv1.GetStatusResponse{
		RunId: "run-1", Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW, StageNames: []string{"Review"},
		StageAssignees: []*workflowv1.StageAssignees{{Assignees: []*workflowv1.StageAssignee{{UserId: reviewApprover, State: "pending"}}}},
	}
	ctx := userCtx(t, reviewAuthor)

	res, err := resolvers.SubmitWorkflowResolver(ctx, log.Nop(), wf, gc, pc, "v-review", "pol", "g-cat", nil)
	if err != nil || res.RunID != "run-1" {
		t.Fatalf("submit = %+v, %v; want run-1", res, err)
	}
	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, wf, "pol")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.CurrentVersionStatus == nil || *p.CurrentVersionStatus != inReviewName {
		t.Fatalf("currentVersionStatus = %v, want %s", p.CurrentVersionStatus, inReviewName)
	}
	v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, wf, "v-review")
	if err != nil || v.Status != inReviewName {
		t.Fatalf("policyVersion = %+v, %v; want status %s for the author", v, err, inReviewName)
	}
	st, err := workflowStatus(ctx, wf.fakeWorkflowClient, pc, gc, noGrant(), "v-review")
	if err != nil || st.Status != resolvers.ApprovalStatusApprovalStatusInReview || len(st.StageAssignees) != 1 || st.StageAssignees[0][0].UserID != reviewApprover {
		t.Fatalf("workflowStatus = %s, %v; want IN_REVIEW with the approver's seat", statusJSON(st), err)
	}
}

// A version in review is not published, so it reads like a draft: only an
// editor or the holder of a pending seat on it. Without this the submit would
// open the text to every reader the moment core stores in_review.
func TestReviewParity_InReviewVersionReadsLikeADraft(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_IN_REVIEW)
	seat := newReviewWorkflow(calls)
	seat.pendingResp = &workflowv1.ListPendingTasksResponse{Tasks: []*workflowv1.PendingTask{{TaskId: "t", RunId: "r", PolicyVersionId: "v-review"}}}
	noSeat := newReviewWorkflow(calls)
	noSeat.pendingResp = &workflowv1.ListPendingTasksResponse{}

	if _, err := resolvers.GetPolicyVersion(userCtx(t, reviewOther), pc, gc, nil, noSeat, "v-review"); status.Code(err) != codes.NotFound {
		t.Fatalf("a reader without a seat read the in-review version: %v, want NotFound", err)
	}
	if v, err := resolvers.GetPolicyVersion(userCtx(t, reviewApprover), pc, gc, nil, seat, "v-review"); err != nil || v.Status != inReviewName {
		t.Fatalf("the seat holder = %+v, %v; want the in-review version", v, err)
	}
	if v, err := resolvers.GetPolicyVersion(userCtx(t, reviewAuthor), pc, gc, nil, noSeat, "v-review"); err != nil || v.ContentJSON == "" {
		t.Fatalf("the author = %+v, %v; want the in-review version", v, err)
	}
}

// mock: "refuses someone who can't edit the policy" -> PermissionDenied.
func TestReviewParity_SubmitRefusesSomeoneWhoCannotEdit(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT)
	wf := newReviewWorkflow(calls)
	wf.submitResp = &workflowv1.SubmitResponse{RunId: "run-1"}
	r := &resolvers.Resolver{WorkflowClient: wf, PolicyClient: pc, CategoryClient: gc}

	_, errs := reviewGQL(t, userCtx(t, reviewOther), r, submitMutation)
	if got := errCodeOf(t, errs); got != "PermissionDenied" {
		t.Fatalf("extensions.code = %q, want PermissionDenied", got)
	}
}

// mock: "refuses a policy whose category has no workflow" -> FailedPrecondition.
func TestReviewParity_SubmitWithNoWorkflowIsFailedPrecondition(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT)
	wf := newReviewWorkflow(calls)
	wf.submitErr = status.Error(codes.FailedPrecondition, "no workflow is attached to this category")
	r := &resolvers.Resolver{WorkflowClient: wf, PolicyClient: pc, CategoryClient: gc}

	_, errs := reviewGQL(t, userCtx(t, reviewAuthor), r, submitMutation)
	if got := errCodeOf(t, errs); got != "FailedPrecondition" {
		t.Fatalf("extensions.code = %q, want FailedPrecondition", got)
	}
}

// mock: "a document with no text can never go for review" ->
// FailedPrecondition ("A document with no content can't be submitted."). Core
// refuses the empty submit with InvalidArgument; the gateway shows the mock's
// code, and leaves every other InvalidArgument alone.
func TestReviewParity_EmptySubmitIsFailedPrecondition(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT)

	t.Run("core's empty-document refusal", func(t *testing.T) {
		wf := newReviewWorkflow(calls)
		wf.submitErr = status.Error(codes.InvalidArgument, "submit refused: the document holds no text")
		r := &resolvers.Resolver{WorkflowClient: wf, PolicyClient: pc, CategoryClient: gc}
		_, errs := reviewGQL(t, userCtx(t, reviewAuthor), r, submitMutation)
		if got := errCodeOf(t, errs); got != "FailedPrecondition" {
			t.Fatalf("extensions.code = %q, want FailedPrecondition", got)
		}
	})
	t.Run("another invalid argument stays InvalidArgument", func(t *testing.T) {
		wf := newReviewWorkflow(calls)
		wf.submitErr = status.Error(codes.InvalidArgument, "policy_version_id is not a uuid")
		r := &resolvers.Resolver{WorkflowClient: wf, PolicyClient: pc, CategoryClient: gc}
		_, errs := reviewGQL(t, userCtx(t, reviewAuthor), r, submitMutation)
		if got := errCodeOf(t, errs); got != "InvalidArgument" {
			t.Fatalf("extensions.code = %q, want InvalidArgument", got)
		}
	})
}

// --- deciding an approval ---

// mock: "publishes the policy on the last approval" (status PUBLISHED, the
// policy's published pointer is the version) and "moves a multi-stage run on
// stage by stage". The gateway relays the run and the policy as they are.
func TestReviewParity_LastApprovalPublishes(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED)
	pc.policies["pol"].CurrentDraftVersionId = ""
	pc.policies["pol"].CurrentPublishedVersionId = "v-review"
	pc.policies["pol"].CurrentVersionStatus = corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED
	pc.policies["pol"].CurrentVersionNo = 4
	wf := newReviewWorkflow(calls)
	wf.statusResp = &workflowv1.GetStatusResponse{RunId: "run-1", Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_PUBLISHED, StageNames: []string{"Review"}}
	ctx := userCtx(t, reviewOther)

	st, err := workflowStatus(ctx, wf.fakeWorkflowClient, pc, gc, noGrant(), "v-review")
	if err != nil || st.Status != resolvers.ApprovalStatusApprovalStatusPublished {
		t.Fatalf("workflowStatus = %s, %v; want PUBLISHED", statusJSON(st), err)
	}
	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, wf, "pol")
	if err != nil || p.CurrentPublishedVersionID == nil || *p.CurrentPublishedVersionID != "v-review" || *p.CurrentVersionStatus != "PUBLISHED" {
		t.Fatalf("policy = %+v, %v; want the version published", p, err)
	}
}

// mock: "ends the run as soon as the approvals still possible cannot reach the
// quorum" and "ends it on a reject after an approve": run REJECTED, the policy's
// currentVersionStatus REJECTED, nothing published.
func TestReviewParity_RejectedRunLeavesThePolicyRejectedWithNothingPublished(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_REJECTED)
	pc.policies["pol"].CurrentDraftVersionId = ""
	pc.policies["pol"].CurrentVersionStatus = corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_REJECTED
	wf := newReviewWorkflow(calls)
	wf.statusResp = &workflowv1.GetStatusResponse{
		RunId: "run-1", Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_REJECTED, StageNames: []string{"Review"},
		StageAssignees: []*workflowv1.StageAssignees{{Assignees: []*workflowv1.StageAssignee{
			{UserId: reviewApprover, State: "rejected", Comment: "The labels need examples."},
			{UserId: reviewOther, State: "superseded"},
		}}},
	}
	ctx := userCtx(t, reviewAuthor)

	st, err := workflowStatus(ctx, wf.fakeWorkflowClient, pc, gc, noGrant(), "v-review")
	if err != nil || st.Status != resolvers.ApprovalStatusApprovalStatusRejected || st.StageAssignees[0][0].State != "rejected" {
		t.Fatalf("workflowStatus = %s, %v; want REJECTED with the rejecting seat", statusJSON(st), err)
	}
	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, wf, "pol")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.CurrentVersionStatus == nil || *p.CurrentVersionStatus != rejectedName {
		t.Fatalf("currentVersionStatus = %v, want %s", p.CurrentVersionStatus, rejectedName)
	}
	if p.CurrentPublishedVersionID != nil {
		t.Fatalf("currentPublishedVersionId = %q, want none", *p.CurrentPublishedVersionID)
	}
}

// mock: "counts a rejection as a vote while the quorum can still be reached":
// one rejecting seat and the run still IN_REVIEW with the other seats open. The
// gateway shows the seats as workflow reports them.
func TestReviewParity_ARejectionCountsAsAVoteWhileTheQuorumIsReachable(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_IN_REVIEW)
	wf := newReviewWorkflow(calls)
	wf.statusResp = &workflowv1.GetStatusResponse{
		RunId: "run-1", Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW, StageNames: []string{"Review"},
		StageAssignees: []*workflowv1.StageAssignees{{Assignees: []*workflowv1.StageAssignee{
			{UserId: reviewApprover, State: "rejected", Comment: "Not sure."},
			{UserId: reviewOther, State: "pending"},
			{UserId: "alice-u", State: "pending"},
		}}},
	}
	st, err := workflowStatus(userCtx(t, reviewAuthor), wf.fakeWorkflowClient, pc, gc, noGrant(), "v-review")
	if err != nil || st.Status != resolvers.ApprovalStatusApprovalStatusInReview {
		t.Fatalf("workflowStatus = %s, %v; want the run still IN_REVIEW", statusJSON(st), err)
	}
	row := st.StageAssignees[0]
	if row[0].State != "rejected" || row[0].Comment == nil || *row[0].Comment != "Not sure." || row[1].State != "pending" || row[2].State != "pending" {
		t.Fatalf("seats = %s, want the rejection kept and the other seats open", statusJSON(st))
	}
}

// mock: "makes a rejection final: the author's next save starts a new draft,
// the rejected version stays". SaveDraft hands back core's new draft (a new id,
// status DRAFT); the rejected version is still there for its editor, as
// REJECTED, and still hidden from a plain reader.
func TestReviewParity_ARejectionIsFinalAndTheNextSaveIsANewDraft(t *testing.T) {
	pc, gc, _ := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_REJECTED)
	pc.policies["pol"].CurrentDraftVersionId = ""
	pc.savedDraft = &corev1.PolicyVersion{Id: "v-new", PolicyId: "pol", VersionNo: 2, Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT}
	ctx := userCtx(t, reviewAuthor)

	saved, err := resolvers.SaveDraft(ctx, pc, gc, "pol", `{"root":{}}`, "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}
	if saved.ID == "v-review" || saved.Status != "DRAFT" {
		t.Fatalf("saved = %+v, want a new draft, not the rejected version", saved)
	}
	old, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, nil, "v-review")
	if err != nil || old.Status != rejectedName {
		t.Fatalf("rejected version = %+v, %v; want it kept as %s", old, err, rejectedName)
	}
	if _, err := resolvers.GetPolicyVersion(userCtx(t, reviewOther), pc, gc, nil, nil, "v-review"); status.Code(err) != codes.NotFound {
		t.Fatalf("a reader read the rejected version: %v, want NotFound", err)
	}
}

// mock: "returns a withdrawn submission to Draft": the withdraw signal reaches
// workflow with the signed-in actor, and the run reads WITHDRAWN.
func TestReviewParity_WithdrawReturnsTheSubmissionToDraft(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT)
	wf := newReviewWorkflow(calls)
	wf.statusResp = &workflowv1.GetStatusResponse{RunId: "run-1", Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_WITHDRAWN}
	r := &resolvers.Resolver{WorkflowClient: wf, PolicyClient: pc, CategoryClient: gc}
	ctx := userCtx(t, reviewAuthor)

	if _, errs := reviewGQL(t, ctx, r, signalMutation("SIGNAL_TYPE_WITHDRAW", "")); len(errs) > 0 {
		t.Fatalf("withdraw refused: %+v", errs)
	}
	if got := wf.lastSignal; got.GetSignal() != workflowv1.SignalType_SIGNAL_TYPE_WITHDRAW || got.GetActorUserId() != reviewAuthor || got.GetPolicyVersionId() != "v-review" {
		t.Fatalf("signal = %+v, want a withdraw by %s on v-review", got, reviewAuthor)
	}
	st, err := workflowStatus(ctx, wf.fakeWorkflowClient, pc, gc, noGrant(), "v-review")
	if err != nil || st.Status != resolvers.ApprovalStatusApprovalStatusWithdrawn {
		t.Fatalf("workflowStatus = %s, %v; want WITHDRAWN", statusJSON(st), err)
	}
}

// mock: "refuses to decide a task twice" and "refuses a decision on a run that
// has ended": FailedPrecondition. mock: "wants a comment with an approval":
// InvalidArgument. The code is the gRPC status name, as the mock spells it.
func TestReviewParity_DecisionRefusalsKeepTheMocksCodes(t *testing.T) {
	cases := []struct {
		name   string
		mock   string
		err    error
		signal string
		want   string
	}{
		{"decide twice", "refuses to decide a task twice", status.Error(codes.FailedPrecondition, "this approval is no longer active; refresh your inbox"), "SIGNAL_TYPE_REJECT", "FailedPrecondition"},
		{"ended run", "refuses a decision on a run that has ended", status.Error(codes.FailedPrecondition, "this approval is no longer active; refresh your inbox (run is rejected)"), "SIGNAL_TYPE_APPROVE", "FailedPrecondition"},
		{"blank comment", "wants a comment with an approval", status.Error(codes.InvalidArgument, "comment is required for approve/reject"), "SIGNAL_TYPE_APPROVE", "InvalidArgument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_IN_REVIEW)
			wf := newReviewWorkflow(calls)
			wf.signalErr = tc.err
			r := &resolvers.Resolver{WorkflowClient: wf, PolicyClient: pc, CategoryClient: gc}
			_, errs := reviewGQL(t, userCtx(t, reviewApprover), r, signalMutation(tc.signal, " "))
			if got := errCodeOf(t, errs); got != tc.want {
				t.Fatalf("%s: extensions.code = %q, want %q", tc.mock, got, tc.want)
			}
			if errs[0].Message == "" || errs[0].Message == server.ServerFaultMessage {
				t.Fatalf("%s: message = %q, want workflow's own text", tc.mock, errs[0].Message)
			}
		})
	}
}

// --- sending changes back ---

// mock: SIGNAL_TYPE_REQUEST_CHANGES is an approver's act that needs no status
// change. The signal reaches workflow with the comment and the signed-in actor.
func TestReviewParity_RequestChangesReachesWorkflowWithTheComment(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_IN_REVIEW)
	wf := newReviewWorkflow(calls)
	r := &resolvers.Resolver{WorkflowClient: wf, PolicyClient: pc, CategoryClient: gc}

	if _, errs := reviewGQL(t, userCtx(t, reviewApprover), r, signalMutation("SIGNAL_TYPE_REQUEST_CHANGES", "Please add examples.")); len(errs) > 0 {
		t.Fatalf("request changes refused: %+v", errs)
	}
	got := wf.lastSignal
	if got.GetSignal() != workflowv1.SignalType_SIGNAL_TYPE_REQUEST_CHANGES || got.GetComment() != "Please add examples." || got.GetActorUserId() != reviewApprover {
		t.Fatalf("signal = %+v, want request changes with the comment by %s", got, reviewApprover)
	}
}

func changesRequested(id int64, actor, impersonated, comment string, at time.Time) *workflowv1.AssignmentHistoryEntry {
	return &workflowv1.AssignmentHistoryEntry{
		Id: id, AssignmentId: "a-" + actor, Event: "changes_requested", ActorUserId: actor,
		ImpersonatedUserId: impersonated, Reason: comment, CreatedAt: timestamppb.New(at),
	}
}

// The comment of a request for changes is kept in the seat's history only, so
// workflowStatus reads the history of the current stage and shows it on the
// seat that sent it. The seat stays pending.
func TestReviewParity_RequestChangesCommentShowsOnTheSeat(t *testing.T) {
	pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_IN_REVIEW)
	at := time.Date(2026, 11, 11, 9, 30, 0, 0, time.UTC)
	newWf := func() *reviewWorkflow {
		wf := newReviewWorkflow(calls)
		wf.statusResp = &workflowv1.GetStatusResponse{
			RunId: "run-1", Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW, CurrentStageIdx: 1,
			StageNames: []string{"Draft check", "Review"},
			StageAssignees: []*workflowv1.StageAssignees{
				{Assignees: []*workflowv1.StageAssignee{{UserId: "alice-u", State: "approved", Comment: "ok"}}},
				{Assignees: []*workflowv1.StageAssignee{
					{UserId: reviewApprover, State: "pending"},
					{UserId: reviewOther, State: "pending"},
				}},
			},
		}
		wf.history = map[int32][]*workflowv1.AssignmentHistoryEntry{1: {
			changesRequested(1, reviewApprover, "", "Please add examples.", at.Add(-time.Hour)),
			changesRequested(2, reviewApprover, "", "The labels still need examples.", at),
			{Id: 3, AssignmentId: "a-" + reviewOther, Event: "created", ActorUserId: reviewAuthor, CreatedAt: timestamppb.New(at)},
		}}
		return wf
	}

	t.Run("the latest comment, on the seat that sent it, which stays pending", func(t *testing.T) {
		wf := newWf()
		st, err := resolvers.WorkflowStatusResolver(userCtx(t, reviewAuthor), log.Nop(), wf, statusIdentity(), pc, gc, noGrant(), "v-review")
		if err != nil {
			t.Fatalf("WorkflowStatusResolver: %v", err)
		}
		seat := st.StageAssignees[1][0]
		if seat.State != "pending" || seat.Comment != nil {
			t.Fatalf("seat = %+v, want it pending with no decision comment", seat)
		}
		if seat.ChangesRequested == nil || *seat.ChangesRequested != "The labels still need examples." {
			t.Fatalf("changesRequested = %v, want the latest comment", seat.ChangesRequested)
		}
		if seat.ChangesRequestedAt == nil || *seat.ChangesRequestedAt != "2026-11-11T09:30:00Z" {
			t.Fatalf("changesRequestedAt = %v, want the time of the latest comment", seat.ChangesRequestedAt)
		}
		if other := st.StageAssignees[1][1]; other.ChangesRequested != nil {
			t.Fatalf("another seat shows %q, want nothing", *other.ChangesRequested)
		}
		if len(wf.historyAsked) != 1 || wf.historyAsked[0] != 1 {
			t.Fatalf("history asked for stages %v, want only the current stage 1", wf.historyAsked)
		}
	})
	t.Run("an admin acting as the approver shows on the approver's seat", func(t *testing.T) {
		wf := newWf()
		wf.history = map[int32][]*workflowv1.AssignmentHistoryEntry{1: {changesRequested(1, "admin-u", reviewOther, "Act-as note.", at)}}
		st, err := resolvers.WorkflowStatusResolver(userCtx(t, reviewAuthor), log.Nop(), wf, statusIdentity(), pc, gc, noGrant(), "v-review")
		if err != nil {
			t.Fatalf("WorkflowStatusResolver: %v", err)
		}
		if got := st.StageAssignees[1][1].ChangesRequested; got == nil || *got != "Act-as note." {
			t.Fatalf("changesRequested = %v, want it on %s's seat", got, reviewOther)
		}
		if got := st.StageAssignees[1][0].ChangesRequested; got != nil {
			t.Fatalf("the admin's own seat shows %q, want nothing", *got)
		}
	})
	t.Run("a history that cannot be read does not fail the status", func(t *testing.T) {
		wf := newWf()
		wf.historyErrOn = true
		st, err := resolvers.WorkflowStatusResolver(userCtx(t, reviewAuthor), log.Nop(), wf, statusIdentity(), pc, gc, noGrant(), "v-review")
		if err != nil || st.RunID != "run-1" || st.StageAssignees[1][0].ChangesRequested != nil {
			t.Fatalf("status = %s, %v; want the run without the comment", statusJSON(st), err)
		}
	})
	t.Run("an obfuscated reader gets no comment and workflow is not asked", func(t *testing.T) {
		opc, ogc, octx := statusReadSetup(t, true)
		wf := newWf()
		st, err := resolvers.WorkflowStatusResolver(octx, log.Nop(), wf, statusIdentity(), opc, ogc, noGrant(), "pol-1-v1")
		if err != nil {
			t.Fatalf("WorkflowStatusResolver: %v", err)
		}
		for _, row := range st.StageAssignees {
			for _, a := range row {
				if a.ChangesRequested != nil || a.ChangesRequestedAt != nil {
					t.Fatalf("an obfuscated reader sees the changes-requested comment %q", *a.ChangesRequested)
				}
			}
		}
		if len(wf.historyAsked) != 0 {
			t.Fatalf("history asked for stages %v, want none for an obfuscated reader", wf.historyAsked)
		}
	})
}

// --- discarding a draft that is in review ---

// mock: discardDraft ends the version's open run (cancelRuns marks it
// WITHDRAWN and closes its seats) and then deletes the draft, so no approver is
// left holding a task on a version that no longer exists. The gateway does the
// same: it withdraws the open run first, then discards, and when the run cannot
// be withdrawn it discards nothing.
func TestReviewParity_DiscardingADraftInReviewWithdrawsItsRunFirst(t *testing.T) {
	inReview := func() *workflowv1.GetStatusResponse {
		return &workflowv1.GetStatusResponse{RunId: "run-1", Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW}
	}

	t.Run("an open run is withdrawn, then the draft is discarded", func(t *testing.T) {
		pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_IN_REVIEW)
		wf := newReviewWorkflow(calls)
		wf.statusResp = inReview()
		ok, err := resolvers.DiscardDraft(userCtx(t, reviewAuthor), log.Nop(), pc, gc, wf, "pol")
		if err != nil || !ok {
			t.Fatalf("DiscardDraft = %v, %v", ok, err)
		}
		want := []string{"workflow.signal:SIGNAL_TYPE_WITHDRAW", "core.discard"}
		if len(*calls) != 2 || (*calls)[0] != want[0] || (*calls)[1] != want[1] {
			t.Fatalf("calls = %v, want %v", *calls, want)
		}
		if got := wf.lastSignal; got.GetActorUserId() != reviewAuthor || got.GetPolicyVersionId() != "v-review" {
			t.Fatalf("withdraw = %+v, want it by %s on v-review", got, reviewAuthor)
		}
	})
	t.Run("a run that cannot be withdrawn keeps the draft", func(t *testing.T) {
		pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_IN_REVIEW)
		wf := newReviewWorkflow(calls)
		wf.statusResp = inReview()
		wf.signalErr = status.Error(codes.Unavailable, "workflow is down")
		if ok, err := resolvers.DiscardDraft(userCtx(t, reviewAuthor), log.Nop(), pc, gc, wf, "pol"); err == nil || ok {
			t.Fatalf("DiscardDraft = %v, %v; want it refused", ok, err)
		}
		for _, c := range *calls {
			if c == "core.discard" {
				t.Fatalf("calls = %v, want no discard after a failed withdraw", *calls)
			}
		}
	})
	t.Run("no run, or a run that has ended, is just discarded", func(t *testing.T) {
		for name, st := range map[string]*workflowv1.GetStatusResponse{
			"no run":    nil,
			"ended run": {RunId: "run-1", Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_WITHDRAWN},
		} {
			pc, gc, calls := reviewFixture(corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT)
			wf := newReviewWorkflow(calls)
			wf.statusResp, wf.statusErr = st, nil
			if st == nil {
				wf.statusErr = status.Error(codes.NotFound, "no approval run for this version")
			}
			if ok, err := resolvers.DiscardDraft(userCtx(t, reviewAuthor), log.Nop(), pc, gc, wf, "pol"); err != nil || !ok {
				t.Fatalf("%s: DiscardDraft = %v, %v", name, ok, err)
			}
			if len(*calls) != 1 || (*calls)[0] != "core.discard" {
				t.Fatalf("%s: calls = %v, want only the discard", name, *calls)
			}
		}
	})
}
