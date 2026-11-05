// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// An approver holding a pending seat on a draft reads that draft and its run
// until they decide (#44). The fixture is draftPointerEnv: policy "pol" with
// draft "draft-1" and published "pub-1", everyone reads, nobody but an
// explicit author edits.

const (
	approverID   = "approver-u"
	draftContent = `{"root":{"secret":"draft"}}`
)

// seatWorkflow is the workflow fake with ListPendingTasks counted, so a test
// can tell how often the gateway asked for the caller's seats.
type seatWorkflow struct {
	*fakeWorkflowClient
	pendingCalls int
}

func (s *seatWorkflow) ListPendingTasks(ctx context.Context, in *workflowv1.ListPendingTasksRequest, opts ...grpc.CallOption) (*workflowv1.ListPendingTasksResponse, error) {
	s.pendingCalls++
	return s.fakeWorkflowClient.ListPendingTasks(ctx, in, opts...)
}

// seatsOn is workflow with the caller's pending seats on versionIDs, and a run
// on draft-1 where the approver has not decided yet.
func seatsOn(versionIDs ...string) *seatWorkflow {
	tasks := make([]*workflowv1.PendingTask, 0, len(versionIDs))
	for i, id := range versionIDs {
		tasks = append(tasks, &workflowv1.PendingTask{TaskId: "task-" + id, RunId: "run-" + id, PolicyVersionId: id, StageIndex: int32(i)})
	}
	return &seatWorkflow{fakeWorkflowClient: &fakeWorkflowClient{
		pendingResp: &workflowv1.ListPendingTasksResponse{Tasks: tasks},
		statusResp: &workflowv1.GetStatusResponse{
			RunId:      "run-draft-1",
			Status:     workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW,
			StageNames: []string{"Legal"},
			StageAssignees: []*workflowv1.StageAssignees{{Assignees: []*workflowv1.StageAssignee{
				{UserId: "carol", State: "approved", Comment: statusComment},
				{UserId: approverID, State: "pending"},
			}}},
		},
	}}
}

func approverCtx(t *testing.T) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: approverID, RolesValue: []string{"reader"}})
}

func approverStatus(ctx context.Context, wf *seatWorkflow, pc corev1.PolicyServiceClient, gc corev1.CategoryServiceClient, versionID string) (*resolvers.WorkflowStatus, error) {
	return resolvers.WorkflowStatusResolver(ctx, log.Nop(), wf, statusIdentity(), pc, gc, noGrant(), versionID)
}

// assertDraftHidden checks the caller gets what a plain reader gets: the
// policy without its draft pointer, and NotFound on the draft and its run,
// with workflow's GetStatus never asked.
func assertDraftHidden(t *testing.T, ctx context.Context, wf *seatWorkflow, pc *fakePolicyClient, gc corev1.CategoryServiceClient) {
	t.Helper()
	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, wf, "pol")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.CurrentDraftVersionID != nil {
		t.Fatalf("currentDraftVersionId = %q, want it cleared", *p.CurrentDraftVersionID)
	}
	if v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, wf, "draft-1"); status.Code(err) != codes.NotFound {
		t.Fatalf("policyVersion(draft-1) = %+v, %v; want NotFound", v, err)
	}
	out, err := approverStatus(ctx, wf, pc, gc, "draft-1")
	if out != nil || status.Code(err) != codes.NotFound || status.Convert(err).Message() != "policy version not found" {
		t.Fatalf("workflowStatus(draft-1) = %+v, %v; want NotFound \"policy version not found\"", out, err)
	}
	if wf.lastStatus != nil {
		t.Fatalf("workflow GetStatus called for %q, want no call for a refused read", wf.lastStatus.GetPolicyVersionId())
	}
}

func TestApproverWithPendingSeat_ReadsTheDraftAndItsRun(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	pc.listResult = []string{"pol"}
	ctx := approverCtx(t)

	t.Run("policy", func(t *testing.T) {
		wf := seatsOn("draft-1")
		p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, wf, "pol")
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if p.CurrentDraftVersionID == nil || *p.CurrentDraftVersionID != "draft-1" {
			t.Fatalf("currentDraftVersionId = %v, want draft-1 for the pending approver", p.CurrentDraftVersionID)
		}
		if p.ViewerCan.Edit || p.ViewerCan.ContentObfuscated {
			t.Fatalf("viewerCan = %+v, want a plain reader's: the seat grants no edit", p.ViewerCan)
		}
		if wf.lastPending.GetApproverUserId() != approverID || wf.pendingCalls != 1 {
			t.Fatalf("ListPendingTasks calls = %d for %q, want one for %s", wf.pendingCalls, wf.lastPending.GetApproverUserId(), approverID)
		}
	})
	t.Run("policyByNumber", func(t *testing.T) {
		wf := seatsOn("draft-1")
		p, err := resolvers.PolicyByNumber(ctx, pc, gc, nil, nil, wf, "POL-CAT-1")
		if err != nil {
			t.Fatalf("PolicyByNumber: %v", err)
		}
		if p.CurrentDraftVersionID == nil || *p.CurrentDraftVersionID != "draft-1" {
			t.Fatalf("currentDraftVersionId = %v, want draft-1", p.CurrentDraftVersionID)
		}
	})
	// steward-web's approval page finds the policy through the policies list.
	t.Run("policies", func(t *testing.T) {
		wf := seatsOn("draft-1")
		out, err := resolvers.ListPolicies(ctx, pc, gc, nil, nil, wf, "g-cat", new(true), nil)
		if err != nil {
			t.Fatalf("ListPolicies: %v", err)
		}
		if len(out) != 1 || out[0].CurrentDraftVersionID == nil || *out[0].CurrentDraftVersionID != "draft-1" {
			t.Fatalf("list = %+v, want pol with currentDraftVersionId draft-1", out)
		}
	})
	t.Run("policyVersion", func(t *testing.T) {
		wf := seatsOn("draft-1")
		v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, wf, "draft-1")
		if err != nil {
			t.Fatalf("GetPolicyVersion(draft-1): %v", err)
		}
		if v.ContentJSON != draftContent {
			t.Fatalf("content = %q, want the draft's real content", v.ContentJSON)
		}
		if wf.pendingCalls != 1 {
			t.Fatalf("ListPendingTasks calls = %d, want 1", wf.pendingCalls)
		}
	})
	t.Run("workflowStatus", func(t *testing.T) {
		wf := seatsOn("draft-1")
		out, err := approverStatus(ctx, wf, pc, gc, "draft-1")
		if err != nil {
			t.Fatalf("WorkflowStatusResolver(draft-1): %v", err)
		}
		if out.RunID != "run-draft-1" || out.Status != resolvers.ApprovalStatusApprovalStatusInReview {
			t.Fatalf("status = %s, want the draft's run", statusJSON(out))
		}
		if c := out.StageAssignees[0][0].Comment; c == nil || *c != statusComment {
			t.Fatalf("comment = %v, want the real comment for an allowed reader", c)
		}
		if wf.lastStatus.GetPolicyVersionId() != "draft-1" || wf.pendingCalls != 1 {
			t.Fatalf("GetStatus for %q with %d seat lookups, want draft-1 and 1", wf.lastStatus.GetPolicyVersionId(), wf.pendingCalls)
		}
	})
}

// A first version has nothing published: a plain reader never learns it
// exists, but its pending approver sees it with its draft.
func TestApproverWithPendingSeat_SeesANeverPublishedPolicy(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	pc.policies["pol"].CurrentPublishedVersionId = ""
	pc.listResult = []string{"pol"}

	reader := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u", RolesValue: []string{"reader"}})
	if _, err := resolvers.GetPolicy(reader, pc, gc, nil, nil, seatsOn(), "pol"); status.Code(err) != codes.NotFound {
		t.Fatalf("plain reader GetPolicy = %v, want NotFound for a never-published policy", err)
	}

	ctx := approverCtx(t)
	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, seatsOn("draft-1"), "pol")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.CurrentDraftVersionID == nil || *p.CurrentDraftVersionID != "draft-1" {
		t.Fatalf("currentDraftVersionId = %v, want draft-1", p.CurrentDraftVersionID)
	}
	out, err := resolvers.ListPolicies(ctx, pc, gc, nil, nil, seatsOn("draft-1"), "g-cat", new(true), nil)
	if err != nil || len(out) != 1 {
		t.Fatalf("ListPolicies = %+v, %v; want pol listed for its pending approver", out, err)
	}
}

func TestApproverAfterDeciding_IsBackToTheNormalRules(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	// Workflow lists only open seats; once decided, the draft is not there.
	assertDraftHidden(t, approverCtx(t), seatsOn(), pc, gc)
}

func TestApproverOnAnotherVersion_IsRefused(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	assertDraftHidden(t, approverCtx(t), seatsOn("other-draft"), pc, gc)
}

func TestApproverSeatLookupFailure_FailsClosed(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	wf := seatsOn("draft-1")
	wf.pendingResp, wf.pendingErr = nil, errors.New("workflow unavailable")
	assertDraftHidden(t, approverCtx(t), wf, pc, gc)
}

// The seat lifts the editors-only rule on a draft; it is not clearance. A
// sensitive policy's pending approver without read-sensitive is refused
// everywhere, as any reader without clearance is; with it, they read.
func TestApproverWithPendingSeat_GetsNoSensitiveClearance(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	pc.policies["pol"].Sensitivity = corev1.Sensitivity_SENSITIVITY_SENSITIVE
	pc.listResult = []string{"pol"}

	t.Run("without clearance", func(t *testing.T) {
		ctx, wf := approverCtx(t), seatsOn("draft-1")
		if _, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, wf, "pol"); status.Code(err) != codes.NotFound {
			t.Fatalf("GetPolicy = %v, want NotFound", err)
		}
		if out, err := resolvers.ListPolicies(ctx, pc, gc, nil, nil, wf, "g-cat", new(true), nil); err != nil || len(out) != 0 {
			t.Fatalf("ListPolicies = %+v, %v; want the sensitive policy left out", out, err)
		}
		if _, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, wf, "draft-1"); status.Code(err) != codes.NotFound {
			t.Fatalf("policyVersion(draft-1) = %v, want NotFound", err)
		}
		if out, err := approverStatus(ctx, wf, pc, gc, "draft-1"); out != nil || status.Code(err) != codes.NotFound {
			t.Fatalf("workflowStatus(draft-1) = %+v, %v; want NotFound", out, err)
		}
		if wf.lastStatus != nil {
			t.Fatal("workflow GetStatus called for a refused read")
		}
	})
	t.Run("with clearance", func(t *testing.T) {
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: approverID, RolesValue: []string{"reader"}, ReadSensitiveValue: true})
		wf := seatsOn("draft-1")
		p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, wf, "pol")
		if err != nil || p.CurrentDraftVersionID == nil || *p.CurrentDraftVersionID != "draft-1" {
			t.Fatalf("GetPolicy = %+v, %v; want draft-1 for a cleared pending approver", p, err)
		}
		v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, wf, "draft-1")
		if err != nil || v.ContentJSON != draftContent {
			t.Fatalf("policyVersion(draft-1) = %+v, %v; want the real draft", v, err)
		}
	})
}

// Editors and plain readers of published content never cost a seat lookup;
// a plain reader on a draft costs one per request and is still refused.
func TestApproverSeatRule_LeavesEditorsAndReadersUnchanged(t *testing.T) {
	t.Run("editor", func(t *testing.T) {
		pc, gc := draftPointerEnv([]*corev1.CategoryRule{authorRule("editor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
		pc.listResult = []string{"pol"}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "editor-u", RolesValue: []string{"reader"}})
		wf := seatsOn()
		p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, wf, "pol")
		if err != nil || p.CurrentDraftVersionID == nil || *p.CurrentDraftVersionID != "draft-1" {
			t.Fatalf("GetPolicy = %+v, %v; want draft-1 for the editor", p, err)
		}
		if _, err := resolvers.ListPolicies(ctx, pc, gc, nil, nil, wf, "g-cat", new(true), nil); err != nil {
			t.Fatalf("ListPolicies: %v", err)
		}
		if v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, wf, "draft-1"); err != nil || v.ContentJSON != draftContent {
			t.Fatalf("policyVersion(draft-1) = %+v, %v; want the draft", v, err)
		}
		if _, err := approverStatus(ctx, wf, pc, gc, "draft-1"); err != nil {
			t.Fatalf("workflowStatus(draft-1): %v", err)
		}
		if wf.pendingCalls != 0 {
			t.Fatalf("ListPendingTasks calls = %d, want 0 for an editor", wf.pendingCalls)
		}
	})
	t.Run("reader on published content", func(t *testing.T) {
		pc, gc := draftPointerEnv(nil)
		pc.policies["pol"].CurrentDraftVersionId = ""
		pc.listResult = []string{"pol"}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u", RolesValue: []string{"reader"}})
		wf := seatsOn()
		if _, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, wf, "pol"); err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if _, err := resolvers.ListPolicies(ctx, pc, gc, nil, nil, wf, "g-cat", new(true), nil); err != nil {
			t.Fatalf("ListPolicies: %v", err)
		}
		if v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, wf, "pub-1"); err != nil || v.ContentJSON != `{"root":{"public":"pub"}}` {
			t.Fatalf("policyVersion(pub-1) = %+v, %v; want the published content", v, err)
		}
		if _, err := approverStatus(ctx, wf, pc, gc, "pub-1"); err != nil {
			t.Fatalf("workflowStatus(pub-1): %v", err)
		}
		if wf.pendingCalls != 0 {
			t.Fatalf("ListPendingTasks calls = %d, want 0 for published content", wf.pendingCalls)
		}
	})
	t.Run("reader on a draft", func(t *testing.T) {
		pc, gc := draftPointerEnv(nil)
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u", RolesValue: []string{"reader"}})
		assertDraftHidden(t, ctx, seatsOn(), pc, gc)
	})
}

// A list asks workflow once however many drafts the rules hide.
func TestApproverSeatRule_OneLookupPerList(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	pc.policies["pol-2"] = &corev1.Policy{Id: "pol-2", HomeCategoryId: "g-cat", Number: "POL-CAT-2", Title: "Q", OwnerUserId: "creator-other", CurrentDraftVersionId: "draft-2", CurrentPublishedVersionId: "pub-1"}
	pc.listResult = []string{"pol", "pol-2"}
	wf := seatsOn("draft-2")

	out, err := resolvers.ListPolicies(approverCtx(t), pc, gc, nil, nil, wf, "g-cat", new(true), nil)
	if err != nil || len(out) != 2 {
		t.Fatalf("ListPolicies = %+v, %v; want both policies", out, err)
	}
	drafts := map[string]string{}
	for _, p := range out {
		if p.CurrentDraftVersionID != nil {
			drafts[p.ID] = *p.CurrentDraftVersionID
		}
	}
	if len(drafts) != 1 || drafts["pol-2"] != "draft-2" {
		t.Fatalf("draft pointers = %v, want only pol-2's draft-2", drafts)
	}
	if wf.pendingCalls != 1 {
		t.Fatalf("ListPendingTasks calls = %d, want 1 for the whole list", wf.pendingCalls)
	}
}
