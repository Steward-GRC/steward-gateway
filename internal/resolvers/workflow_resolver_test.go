// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// --- WorkflowStatusResolver: the run is read under the version's read decision (#42) ---

const statusComment = "clause 4 exposes the payroll data"

// coreLikeVersions answers a version core doesn't hold the way core does:
// NotFound "policy version not found".
type coreLikeVersions struct {
	*recordingPolicyClient
}

func (c coreLikeVersions) GetPolicyVersion(ctx context.Context, in *corev1.GetPolicyVersionRequest, opts ...grpc.CallOption) (*corev1.GetPolicyVersionResponse, error) {
	if _, ok := c.versions[in.GetId()]; !ok {
		return nil, status.Error(codes.NotFound, "policy version not found")
	}
	return c.recordingPolicyClient.GetPolicyVersion(ctx, in, opts...)
}

// statusRun is a run on pol-1-v1 where carol approved with a comment and dave
// has not decided yet.
func statusRun() *fakeWorkflowClient {
	return &fakeWorkflowClient{statusResp: &workflowv1.GetStatusResponse{
		RunId:           "run-1",
		Status:          workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW,
		CurrentStageIdx: 0,
		StageNames:      []string{"Legal"},
		StageAssignees: []*workflowv1.StageAssignees{{Assignees: []*workflowv1.StageAssignee{
			{UserId: "carol", State: "approved", Comment: statusComment, DecidedAt: timestamppb.New(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))},
			{UserId: "dave", State: "pending"},
		}}},
	}}
}

func statusIdentity() *labelIdentityFake {
	return &labelIdentityFake{users: map[string]*identityv1.User{
		"carol": {Id: "carol", Name: "Carol Approver"},
		"dave":  {Id: "dave", Name: "Dave Approver"},
	}}
}

// statusReadSetup is breakGlassReadSetup with core's NotFound for an unknown
// version: one published standard policy pol-1 (version pol-1-v1) in IT.
// denySiteAdmin denies the Admins group, so the site admin "sa" sees the
// policy obfuscated and a non-admin in Admins is denied.
func statusReadSetup(t *testing.T, denySiteAdmin bool) (coreLikeVersions, corev1.CategoryServiceClient, context.Context) {
	t.Helper()
	pc, groups, ctx := breakGlassReadSetup(t, denySiteAdmin)
	return coreLikeVersions{recordingPolicyClient: pc}, groups, ctx
}

func readerCtx(t *testing.T) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", RolesValue: []string{"reader"}})
}

func workflowStatus(ctx context.Context, wf *fakeWorkflowClient, pc corev1.PolicyServiceClient, groups corev1.CategoryServiceClient, admin *fakeBreakGlassAdmin, versionID string) (*resolvers.WorkflowStatus, error) {
	return resolvers.WorkflowStatusResolver(ctx, log.Nop(), wf, statusIdentity(), pc, groups, admin, versionID)
}

// assertSameRefusal checks err is the refusal the caller gets reading the
// version directly (policyVersion), and that workflow was never asked.
func assertSameRefusal(t *testing.T, ctx context.Context, err error, wf *fakeWorkflowClient, pc corev1.PolicyServiceClient, groups corev1.CategoryServiceClient, versionID string) {
	t.Helper()
	_, direct := resolvers.GetPolicyVersion(ctx, pc, groups, noGrant(), nil, versionID)
	if status.Code(direct) != codes.NotFound {
		t.Fatalf("fixture: reading %s directly = %v, want NotFound", versionID, direct)
	}
	if status.Code(err) != status.Code(direct) || status.Convert(err).Message() != status.Convert(direct).Message() {
		t.Fatalf("err = %v, want the direct read's refusal %v", err, direct)
	}
	if wf.lastStatus != nil {
		t.Fatalf("workflow GetStatus called for %q, want no call for a refused read", wf.lastStatus.GetPolicyVersionId())
	}
}

func TestWorkflowStatusResolver_ReaderRefusedOnSensitivePolicy(t *testing.T) {
	pc, groups, _ := statusReadSetup(t, false)
	pc.policies["pol-1"].Sensitivity = corev1.Sensitivity_SENSITIVITY_SENSITIVE
	ctx := readerCtx(t)
	if _, err := resolvers.GetPolicy(ctx, pc, groups, noGrant(), nil, nil, "pol-1"); status.Code(err) != codes.NotFound {
		t.Fatalf("fixture: reading the sensitive policy = %v, want NotFound", err)
	}
	wf := statusRun()

	out, err := workflowStatus(ctx, wf, pc, groups, noGrant(), "pol-1-v1")
	if out != nil {
		t.Fatalf("served the run of a sensitive policy to a reader without clearance: %+v", out)
	}
	assertSameRefusal(t, ctx, err, wf, pc, groups, "pol-1-v1")
}

func TestWorkflowStatusResolver_ReaderAllowedOnStandardPolicyUnchanged(t *testing.T) {
	pc, groups, _ := statusReadSetup(t, false)
	wf := statusRun()

	out, err := workflowStatus(readerCtx(t), wf, pc, groups, noGrant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("WorkflowStatusResolver: %v", err)
	}
	comment, decided := statusComment, "2026-10-01T09:00:00Z"
	carol, dave := "Carol Approver", "Dave Approver"
	want := &resolvers.WorkflowStatus{
		Status:          resolvers.ApprovalStatusApprovalStatusInReview,
		RunID:           "run-1",
		CurrentStageIdx: 0,
		StageNames:      []string{"Legal"},
		StageAssignees: [][]*resolvers.StageAssignee{{
			{UserID: "carol", State: "approved", Name: &carol, Comment: &comment, DecidedAt: &decided},
			{UserID: "dave", State: "pending", Name: &dave},
		}},
		StageUnitProgress: [][]*resolvers.StageUnitProgress{},
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("status = %s, want %s", statusJSON(out), statusJSON(want))
	}
	if wf.lastStatus.GetPolicyVersionId() != "pol-1-v1" {
		t.Fatalf("workflow asked for %q, want pol-1-v1", wf.lastStatus.GetPolicyVersionId())
	}
	if len(pc.recorded) != 0 {
		t.Fatalf("recorded = %v, want none: the rules already allow this read", pc.recorded)
	}
}

func TestWorkflowStatusResolver_DraftRunIsForEditorsOnly(t *testing.T) {
	pc, groups, _ := statusReadSetup(t, false)
	pc.policies["pol-1"].OwnerUserId = "author-u"
	pc.policies["pol-1"].CurrentDraftVersionId = "pol-1-v2"
	pc.versions["pol-1-v2"] = &corev1.PolicyVersion{Id: "pol-1-v2", PolicyId: "pol-1", VersionNo: 2, Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT}

	t.Run("non-editor refused", func(t *testing.T) {
		ctx, wf := readerCtx(t), statusRun()
		out, err := workflowStatus(ctx, wf, pc, groups, noGrant(), "pol-1-v2")
		if out != nil {
			t.Fatalf("served a draft's run to a non-editor: %+v", out)
		}
		assertSameRefusal(t, ctx, err, wf, pc, groups, "pol-1-v2")
	})
	t.Run("editor served", func(t *testing.T) {
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-u", RolesValue: []string{"reader"}})
		wf := statusRun()
		out, err := workflowStatus(ctx, wf, pc, groups, noGrant(), "pol-1-v2")
		if err != nil {
			t.Fatalf("WorkflowStatusResolver: %v", err)
		}
		if out.RunID != "run-1" || out.StageAssignees[0][0].Comment == nil {
			t.Fatalf("status = %s, want the run with its comments for the draft's editor", statusJSON(out))
		}
	})
}

func TestWorkflowStatusResolver_ObfuscatedViewerGetsNoComments(t *testing.T) {
	pc, groups, ctx := statusReadSetup(t, true)
	if p, err := resolvers.GetPolicy(ctx, pc, groups, noGrant(), nil, nil, "pol-1"); err != nil || !p.ViewerCan.ContentObfuscated {
		t.Fatalf("fixture: the site admin must see pol-1 obfuscated, got %+v, %v", p, err)
	}

	out, err := workflowStatus(ctx, statusRun(), pc, groups, noGrant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("WorkflowStatusResolver: %v", err)
	}
	if out.RunID != "run-1" || out.Status != resolvers.ApprovalStatusApprovalStatusInReview || len(out.StageNames) != 1 {
		t.Fatalf("status = %s, want the run's shape kept", statusJSON(out))
	}
	carol, dave := out.StageAssignees[0][0], out.StageAssignees[0][1]
	if carol.Comment != nil || dave.Comment != nil {
		t.Fatalf("comment served to an obfuscated viewer: %q", *carol.Comment)
	}
	if carol.Name == nil || *carol.Name != "Carol Approver" || carol.State != "approved" || carol.DecidedAt == nil {
		t.Fatalf("assignee = %+v, want the name, state and decision time kept (metadata, as the policy's owner name is)", carol)
	}
	if len(pc.recorded) != 0 {
		t.Fatalf("recorded = %v, want none without a grant", pc.recorded)
	}
}

func TestWorkflowStatusResolver_BreakGlassReadIsRecordedAndServesComments(t *testing.T) {
	pc, groups, ctx := statusReadSetup(t, true)

	out, err := workflowStatus(ctx, statusRun(), pc, groups, grant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("WorkflowStatusResolver: %v", err)
	}
	if c := out.StageAssignees[0][0].Comment; c == nil || *c != statusComment {
		t.Fatalf("comment = %v, want the real comment under the grant", c)
	}
	if len(pc.recorded) != 1 || pc.recorded[0].GetPolicyVersionId() != "pol-1-v1" {
		t.Fatalf("recorded = %v, want the grant-only read recorded once", pc.recorded)
	}
}

// Workflow holds no run for a version core doesn't know, which used to come
// back as APPROVAL_STATUS_UNSPECIFIED; it is now the read path's NotFound, the
// same answer a refused caller gets, so the two can't be told apart.
func TestWorkflowStatusResolver_UnknownVersionIsTheReadPathsNotFound(t *testing.T) {
	pc, groups, _ := statusReadSetup(t, false)
	ctx := readerCtx(t)
	wf := &fakeWorkflowClient{statusErr: status.Error(codes.NotFound, "no approval run for policy version")}

	out, err := workflowStatus(ctx, wf, pc, groups, noGrant(), "missing")
	if out != nil {
		t.Fatalf("status = %+v, want none for an unknown version", out)
	}
	assertSameRefusal(t, ctx, err, wf, pc, groups, "missing")
}

func TestWorkflowStatusResolver_ReadableVersionWithoutARunIsUnspecified(t *testing.T) {
	pc, groups, _ := statusReadSetup(t, false)
	wf := &fakeWorkflowClient{statusErr: status.Error(codes.NotFound, "no approval run for policy version")}

	out, err := workflowStatus(readerCtx(t), wf, pc, groups, noGrant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("WorkflowStatusResolver: %v", err)
	}
	if out.Status != resolvers.ApprovalStatusApprovalStatusUnspecified || out.RunID != "" || len(out.StageAssignees) != 0 {
		t.Fatalf("status = %s, want APPROVAL_STATUS_UNSPECIFIED with no run", statusJSON(out))
	}
}

// statusJSON renders a status with its pointers followed, for failure messages.
func statusJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
