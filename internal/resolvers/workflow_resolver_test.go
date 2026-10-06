// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestResolveEffectiveWorkflow_WalksLineageAndDelegates verifies the gateway
// builds the policy's group lineage leaf→root and delegates resolution to the
// workflow service — and maps an empty def id to hasWorkflow=false (a policy
// that can't be submitted until a workflow is attached).
func TestResolveEffectiveWorkflow_WalksLineageAndDelegates(t *testing.T) {
	pol := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-1": {Id: "pol-1", HomeCategoryId: "subcat"},
	}}
	grp := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"subcat": {Id: "subcat", ParentId: "cat"},
		"cat":    {Id: "cat", ParentId: "root"},
		"root":   {Id: "root"},
	}}
	wf := &fakeWorkflowClient{resolveResp: &workflowv1.ResolveWorkflowResponse{WorkflowDefId: "def-cat"}}

	ew, err := resolvers.ResolveEffectiveWorkflowResolver(context.Background(), pol, grp, wf, "pol-1")
	if err != nil {
		t.Fatalf("ResolveEffectiveWorkflowResolver: %v", err)
	}
	if !ew.HasWorkflow || ew.WorkflowDefID == nil || *ew.WorkflowDefID != "def-cat" {
		t.Fatalf("expected workflow def-cat, got %+v", ew)
	}
	if got := wf.lastResolve.GetAncestorCategoryIds(); len(got) != 3 || got[0] != "subcat" || got[2] != "root" {
		t.Fatalf("expected lineage [subcat cat root], got %v", got)
	}

	// No workflow attached/inherited → not submittable.
	wf.resolveResp = &workflowv1.ResolveWorkflowResponse{WorkflowDefId: ""}
	ew, err = resolvers.ResolveEffectiveWorkflowResolver(context.Background(), pol, grp, wf, "pol-1")
	if err != nil {
		t.Fatalf("ResolveEffectiveWorkflowResolver(empty): %v", err)
	}
	if ew.HasWorkflow || ew.WorkflowDefID != nil {
		t.Fatalf("expected no workflow, got %+v", ew)
	}
}

// TestResolveEffectiveWorkflow_Usable_AllStagesStaffed verifies that when the
// resolved def has every stage staffed (individual OR group approver), usable is
// true and firstUnstaffedStage is nil.
func TestResolveEffectiveWorkflow_Usable_AllStagesStaffed(t *testing.T) {
	pol := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-1": {Id: "pol-1", HomeCategoryId: "root"},
	}}
	grp := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"root": {Id: "root"},
	}}
	wf := &fakeWorkflowClient{
		resolveResp: &workflowv1.ResolveWorkflowResponse{WorkflowDefId: "def-1"},
		getDefResp: &workflowv1.GetWorkflowDefResponse{Def: &workflowv1.WorkflowDef{
			Id: "def-1", Name: "Standard",
			Stages: []*workflowv1.WorkflowStage{
				{Id: "s1", Name: "Review", ApproverIds: []string{"u1"}},
				{Id: "s2", Name: "Approval", ApproversByCategory: map[string]*workflowv1.ApproverList{
					"g1": {UserIds: []string{"u2"}},
				}},
			},
		}},
	}

	ew, err := resolvers.ResolveEffectiveWorkflowResolver(context.Background(), pol, grp, wf, "pol-1")
	if err != nil {
		t.Fatalf("ResolveEffectiveWorkflowResolver: %v", err)
	}
	if !ew.HasWorkflow {
		t.Fatalf("expected hasWorkflow=true, got %+v", ew)
	}
	if !ew.Usable {
		t.Fatalf("expected usable=true when every stage is staffed, got %+v", ew)
	}
	if ew.FirstUnstaffedStage != nil {
		t.Fatalf("expected firstUnstaffedStage=nil, got %v", *ew.FirstUnstaffedStage)
	}
}

// TestResolveEffectiveWorkflow_Unusable_UnstaffedStage verifies that a def with
// a stage lacking any approver reports usable=false and names that stage.
func TestResolveEffectiveWorkflow_Unusable_UnstaffedStage(t *testing.T) {
	pol := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-1": {Id: "pol-1", HomeCategoryId: "root"},
	}}
	grp := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"root": {Id: "root"},
	}}
	wf := &fakeWorkflowClient{
		resolveResp: &workflowv1.ResolveWorkflowResponse{WorkflowDefId: "def-1"},
		getDefResp: &workflowv1.GetWorkflowDefResponse{Def: &workflowv1.WorkflowDef{
			Id: "def-1", Name: "Standard",
			Stages: []*workflowv1.WorkflowStage{
				{Id: "s1", Name: "Review", ApproverIds: []string{"u1"}},
				{Id: "s2", Name: "Approval"}, // no individual and no group approver
			},
		}},
	}

	ew, err := resolvers.ResolveEffectiveWorkflowResolver(context.Background(), pol, grp, wf, "pol-1")
	if err != nil {
		t.Fatalf("ResolveEffectiveWorkflowResolver: %v", err)
	}
	if ew.Usable {
		t.Fatalf("expected usable=false when a stage is unstaffed, got %+v", ew)
	}
	if ew.FirstUnstaffedStage == nil || *ew.FirstUnstaffedStage != "Approval" {
		t.Fatalf("expected firstUnstaffedStage=Approval, got %v", ew.FirstUnstaffedStage)
	}
}

// TestResolveEffectiveWorkflow_NoWorkflow_Usable verifies that when no workflow
// is attached/inherited there is nothing to gate on: usable=true,
// firstUnstaffedStage=nil, and GetWorkflowDef is never called.
func TestResolveEffectiveWorkflow_NoWorkflow_Usable(t *testing.T) {
	pol := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-1": {Id: "pol-1", HomeCategoryId: "root"},
	}}
	grp := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"root": {Id: "root"},
	}}
	wf := &fakeWorkflowClient{
		resolveResp: &workflowv1.ResolveWorkflowResponse{WorkflowDefId: ""},
		getDefErr:   errors.New("GetWorkflowDef must not be called when hasWorkflow=false"),
	}

	ew, err := resolvers.ResolveEffectiveWorkflowResolver(context.Background(), pol, grp, wf, "pol-1")
	if err != nil {
		t.Fatalf("ResolveEffectiveWorkflowResolver: %v", err)
	}
	if ew.HasWorkflow {
		t.Fatalf("expected hasWorkflow=false, got %+v", ew)
	}
	if !ew.Usable || ew.FirstUnstaffedStage != nil {
		t.Fatalf("expected usable=true + no unstaffed stage when no workflow, got %+v", ew)
	}
}

// --- SwapAssigneeResolver ---

func TestSwapAssigneeResolver_DerivesAdminRole(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.SwapAssigneeResolver(
		ctxWithClaims(t, "ops", "site-admin"), c,
		resolvers.SwapAssigneeInput{
			PolicyVersionID: "pv-1", StageIndex: 0,
			CurrentUserID: "u1", NewUserID: "u2", Reason: "x",
		},
	)
	if err != nil {
		t.Fatalf("SwapAssignee: %v", err)
	}
	if c.lastSwap.GetInitiatorRole() != workflowv1.InitiatorRole_INITIATOR_ROLE_ADMIN {
		t.Fatalf("role: %v", c.lastSwap.GetInitiatorRole())
	}
}

func TestSwapAssigneeResolver_DerivesSelfDelegate(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.SwapAssigneeResolver(
		ctxWithClaims(t, "u1", "site-admin"), c,
		resolvers.SwapAssigneeInput{
			PolicyVersionID: "pv-1", StageIndex: 0,
			CurrentUserID: "u1", NewUserID: "u2", Reason: "x",
		},
	)
	if err != nil {
		t.Fatalf("SwapAssignee: %v", err)
	}
	if c.lastSwap.GetInitiatorRole() != workflowv1.InitiatorRole_INITIATOR_ROLE_SELF_DELEGATE {
		t.Fatalf("role: %v", c.lastSwap.GetInitiatorRole())
	}
}

// Steward has no separate admin role: a caller past the workflow.manage gate
// swapping someone else's seat is an admin to workflow.
func TestSwapAssigneeResolver_OtherSeatIsAdmin(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.SwapAssigneeResolver(
		ctxWithClaims(t, "author", "template-admin"), c,
		resolvers.SwapAssigneeInput{
			PolicyVersionID: "pv-1", StageIndex: 0,
			CurrentUserID: "u1", NewUserID: "u2", Reason: "x",
		},
	)
	if err != nil {
		t.Fatalf("SwapAssignee: %v", err)
	}
	if c.lastSwap.GetInitiatorRole() != workflowv1.InitiatorRole_INITIATOR_ROLE_ADMIN {
		t.Fatalf("role: %v", c.lastSwap.GetInitiatorRole())
	}
}

func TestSwapAssigneeResolver_Unauthenticated(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.SwapAssigneeResolver(
		context.Background(), c,
		resolvers.SwapAssigneeInput{CurrentUserID: "u1", NewUserID: "u2", Reason: "x"},
	)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
}

func TestSwapAssigneeResolver_PropagatesGRPCError(t *testing.T) {
	c := &fakeWorkflowClient{swapErr: errors.New("rpc fail")}
	_, err := resolvers.SwapAssigneeResolver(
		ctxWithClaims(t, "ops", "site-admin"), c,
		resolvers.SwapAssigneeInput{CurrentUserID: "u1", NewUserID: "u2", Reason: "x"},
	)
	if err == nil {
		t.Fatal("expected grpc error to propagate")
	}
}

func TestSwapAssigneeResolver_OutOfEligibilityAckForwarded(t *testing.T) {
	c := &fakeWorkflowClient{}
	ack := true
	_, err := resolvers.SwapAssigneeResolver(
		ctxWithClaims(t, "ops", "site-admin"), c,
		resolvers.SwapAssigneeInput{
			PolicyVersionID: "pv-1", StageIndex: 0,
			CurrentUserID: "u1", NewUserID: "u-outside", Reason: "x",
			OutOfEligibilityAck: &ack,
		},
	)
	if err != nil {
		t.Fatalf("SwapAssignee: %v", err)
	}
	if !c.lastSwap.GetOutOfEligibilityAck() {
		t.Fatal("expected out_of_eligibility_ack=true")
	}
}

// --- BulkDecideResolver ---

func TestBulkDecideResolver_ForwardsDecisions(t *testing.T) {
	c := &fakeWorkflowClient{
		bulkResp: &workflowv1.BulkDecideResponse{
			BulkBatchId: "b-1",
			Results: []*workflowv1.DecisionResult{
				{PolicyVersionId: "pv-1", StageIndex: 0, Ok: true, AssignmentId: "a1"},
			},
		},
	}
	out, err := resolvers.BulkDecideResolver(
		ctxWithClaims(t, "u1", "site-admin"), c,
		resolvers.BulkDecideInput{
			Decisions: []*resolvers.DecisionInput{
				{
					PolicyVersionID: "pv-1", StageIndex: 0,
					Decision: resolvers.DecisionTypeDecisionTypeApprove, Comment: "ok",
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("BulkDecide: %v", err)
	}
	if out.BulkBatchID != "b-1" {
		t.Fatalf("batch: %q", out.BulkBatchID)
	}
	if len(out.Results) != 1 || !out.Results[0].Ok {
		t.Fatalf("results: %+v", out.Results)
	}
	if c.lastBulk.GetDecisions()[0].GetDecision() != workflowv1.DecisionType_DECISION_TYPE_APPROVE {
		t.Fatal("decision not approve")
	}
}

func TestBulkDecideResolver_Unauthenticated(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.BulkDecideResolver(context.Background(), c, resolvers.BulkDecideInput{})
	if err == nil {
		t.Fatal("expected unauthenticated")
	}
}

// A caller who holds no policy.approve capability but IS a workflow stage
// assignee (bug D5a) must NOT be blocked at the gateway: the gateway no longer
// gates BulkDecide on policy.approve, it forwards to the workflow service, which
// authoritatively decides each row only against the caller's own pending
// assignment. So the request must reach the workflow service.
func TestBulkDecideResolver_ForwardsWithoutApproveCapability(t *testing.T) {
	c := &fakeWorkflowClient{bulkResp: &workflowv1.BulkDecideResponse{BulkBatchId: "b"}}
	_, err := resolvers.BulkDecideResolver(ctxWithClaims(t, "u1", "reader"), c, resolvers.BulkDecideInput{
		Decisions: []*resolvers.DecisionInput{
			{
				PolicyVersionID: "pv-1", StageIndex: 0,
				Decision: resolvers.DecisionTypeDecisionTypeApprove, Comment: "ok",
			},
		},
	})
	if err != nil {
		t.Fatalf("a stage assignee without the approve capability must not be blocked at the gateway: %v", err)
	}
	if c.lastBulk == nil {
		t.Fatal("workflow service must be called so it can enforce the assignee-only check")
	}
}

func TestBulkDecideResolver_AllowsApprover(t *testing.T) {
	c := &fakeWorkflowClient{bulkResp: &workflowv1.BulkDecideResponse{BulkBatchId: "b"}}
	_, err := resolvers.BulkDecideResolver(ctxWithClaims(t, "u1", "approver"), c, resolvers.BulkDecideInput{})
	if err != nil {
		t.Fatalf("approver should pass: %v", err)
	}
}

func TestBulkDecideResolver_PropagatesError(t *testing.T) {
	c := &fakeWorkflowClient{bulkErr: errors.New("svc down")}
	_, err := resolvers.BulkDecideResolver(ctxWithClaims(t, "u1", "site-admin"), c, resolvers.BulkDecideInput{})
	if err == nil {
		t.Fatal("expected error to propagate")
	}
}

// --- AssignmentHistoryResolver ---

func TestAssignmentHistoryResolver_ConvertsEntries(t *testing.T) {
	c := &fakeWorkflowClient{
		historyResp: &workflowv1.GetAssignmentHistoryResponse{
			Entries: []*workflowv1.AssignmentHistoryEntry{
				{Id: 42, AssignmentId: "a1", Event: "created", ActorUserId: "u1"},
				{Id: 43, AssignmentId: "a1", Event: "swapped_out", ActorUserId: "admin", PreviousUserId: "u1", NewUserId: "u2", OutOfEligibility: true, Reason: "PTO"},
			},
		},
	}
	out, err := resolvers.AssignmentHistoryResolver(
		ctxWithClaims(t, "admin", "site-admin", "admin"), c, nil, nil, "pv-1", 0,
	)
	if err != nil {
		t.Fatalf("AssignmentHistory: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("entries: %d", len(out))
	}
	if out[0].ID != "42" || out[1].ID != "43" {
		t.Fatalf("ids: %q %q", out[0].ID, out[1].ID)
	}
	if out[1].PreviousUserID == nil || *out[1].PreviousUserID != "u1" {
		t.Fatalf("previous: %v", out[1].PreviousUserID)
	}
	if !out[1].OutOfEligibility {
		t.Fatal("expected out_of_eligibility")
	}
}

func TestAssignmentHistoryResolver_Unauthenticated(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.AssignmentHistoryResolver(context.Background(), c, nil, nil, "pv-1", 0)
	if err == nil {
		t.Fatal("expected unauthenticated")
	}
}

func TestAssignmentHistoryResolver_DeniesWithoutApprove(t *testing.T) {
	c := &fakeWorkflowClient{historyResp: &workflowv1.GetAssignmentHistoryResponse{}}
	_, err := resolvers.AssignmentHistoryResolver(ctxWithClaims(t, "u1", "reader"), c, nil, nil, "pv-1", 0)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("reader should be denied, got %v", err)
	}
	if c.lastHistory != nil {
		t.Fatal("workflow service must not be called when caller lacks policy.approve")
	}
}

func TestAssignmentHistoryResolver_OwnerInheritedAllowed(t *testing.T) {
	// A group OWNER has no explicit approver grant (owner-inheritance is resolved
	// dynamically from core groups.owners, not carried in the JWT claims the
	// capability check reads). The owned-group fallback must let them see their
	// group's approval status — otherwise the shared status view is blank for the
	// very people who need it for escalation.
	c := &fakeWorkflowClient{historyResp: &workflowv1.GetAssignmentHistoryResponse{
		Entries: []*workflowv1.AssignmentHistoryEntry{
			{Id: 1, AssignmentId: "a1", Event: "created", ActorUserId: "u1"},
		},
	}}
	groups := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"g1": {Id: "g1", Name: "Medical", ParentId: "", Owners: []string{"u1"}},
	}}
	out, err := resolvers.AssignmentHistoryResolver(ctxWithClaims(t, "u1", "reader"), c, nil, groups, "pv-1", 0)
	if err != nil {
		t.Fatalf("owner-inherited caller should be allowed, got %v", err)
	}
	if len(out) != 1 || out[0].ID != "1" {
		t.Fatalf("expected the group owner to see the history, got %#v", out)
	}
}

// --- SignalWorkflowResolver (comment now required) ---

func TestSignalWorkflowResolver_ForwardsComment(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.SignalWorkflowResolver(
		ctxWithClaims(t, "u1"), c, "pv1", "r1", "t1",
		resolvers.SignalTypeSignalTypeApprove, "lgtm",
	)
	if err != nil {
		t.Fatalf("Signal: %v", err)
	}
	if c.lastSignal.GetComment() != "lgtm" {
		t.Fatalf("comment: %q", c.lastSignal.GetComment())
	}
	if c.lastSignal.GetPolicyVersionId() != "pv1" {
		t.Fatalf("policy_version_id forwarded: %q", c.lastSignal.GetPolicyVersionId())
	}
}

func TestSignalWorkflowResolver_Unauthenticated(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.SignalWorkflowResolver(
		context.Background(), c, "pv1", "r1", "t1",
		resolvers.SignalTypeSignalTypeApprove, "lgtm",
	)
	if err == nil {
		t.Fatal("expected unauthenticated")
	}
}
