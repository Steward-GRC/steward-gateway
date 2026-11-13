// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

type groupNameIdentity struct {
	identityv1.IdentityReadServiceClient
	groups map[string]string
}

func (f *groupNameIdentity) GetGroup(_ context.Context, in *identityv1.GetGroupRequest, _ ...grpc.CallOption) (*identityv1.GetGroupResponse, error) {
	name, ok := f.groups[in.GetGroupId()]
	if !ok {
		return nil, errors.New("not found")
	}
	return &identityv1.GetGroupResponse{Group: &identityv1.Group{Id: in.GetGroupId(), Name: name}}, nil
}

func (f *groupNameIdentity) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	return &identityv1.GetUserResponse{User: &identityv1.User{Id: in.GetUserId()}}, nil
}

func TestCreateWorkflowDefResolver_GroupUnitsForwarded(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.CreateWorkflowDefResolver(
		ctxWithRoles(t, "frank", []string{"template-admin"}), c, "Finance sign-off", nil,
		[]*resolvers.WorkflowStageInput{{
			Name: "Approval", Quorum: "all",
			GroupUnits: []*resolvers.GroupUnitInput{{GroupID: "approvers", InternalQuorum: "majority", MemberUserIds: []string{"carol", "dave"}}},
		}},
	)
	if err != nil {
		t.Fatalf("CreateWorkflowDefResolver: %v", err)
	}
	units := c.lastCreateDef.GetStages()[0].GetGroupUnits()
	if len(units) != 1 || units[0].GetGroupId() != "approvers" || units[0].GetInternalQuorum() != "majority" || len(units[0].GetMemberUserIds()) != 2 {
		t.Fatalf("group units not forwarded: %+v", units)
	}
}

func TestWorkflowDefResolver_GroupUnitsMapped(t *testing.T) {
	c := &fakeWorkflowClient{getDefResp: &workflowv1.GetWorkflowDefResponse{Def: &workflowv1.WorkflowDef{
		Id: "d1", Name: "Finance sign-off", Version: 1, Stages: []*workflowv1.WorkflowStage{{
			Id: "s1", Name: "Approval", Quorum: "all",
			GroupUnits: []*workflowv1.GroupUnit{{GroupId: "approvers", InternalQuorum: "one", MemberUserIds: []string{"carol"}}},
		}},
	}}}
	out, err := resolvers.WorkflowDefResolver(context.Background(), c, "d1")
	if err != nil {
		t.Fatalf("WorkflowDefResolver: %v", err)
	}
	units := out.Stages[0].GroupUnits
	if len(units) != 1 || units[0].GroupID != "approvers" || units[0].InternalQuorum != "one" || units[0].MemberUserIds[0] != "carol" {
		t.Fatalf("group units: %+v", units)
	}
	if out.Stages[0].ApproversByCategory == nil {
		t.Fatal("approversByCategory must be a non-nil list")
	}
}

func TestResolveEffectiveWorkflow_GroupUnitStaffsAStage(t *testing.T) {
	pol := &fakePolicyClient{policies: map[string]*corev1.Policy{"pol-1": {Id: "pol-1", HomeCategoryId: "root"}}}
	cat := &fakeCategoryClient{groups: map[string]*corev1.Category{"root": {Id: "root"}}}
	wf := &fakeWorkflowClient{
		resolveResp: &workflowv1.ResolveWorkflowResponse{WorkflowDefId: "def-1"},
		getDefResp: &workflowv1.GetWorkflowDefResponse{Def: &workflowv1.WorkflowDef{Id: "def-1", Stages: []*workflowv1.WorkflowStage{
			{Id: "s1", Name: "Approval", GroupUnits: []*workflowv1.GroupUnit{{GroupId: "approvers", InternalQuorum: "one"}}},
		}}},
	}
	ew, err := resolvers.ResolveEffectiveWorkflowResolver(adminCtx(t), log.Nop(), pol, cat, wf, "pol-1")
	if err != nil {
		t.Fatalf("ResolveEffectiveWorkflowResolver: %v", err)
	}
	if !ew.Usable {
		t.Fatalf("a stage staffed by a group unit is usable: %+v", ew)
	}
}

func TestWorkflowStatusResolver_GroupSeatsAndUnitNames(t *testing.T) {
	wf := &fakeWorkflowClient{statusResp: &workflowv1.GetStatusResponse{
		Status:     workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW,
		StageNames: []string{"Approval"},
		StageAssignees: []*workflowv1.StageAssignees{{Assignees: []*workflowv1.StageAssignee{
			{UserId: "carol", State: "pending", GroupId: "approvers"},
			{UserId: "dave", State: "pending"},
		}}},
		StageUnitProgress: []*workflowv1.StageUnitProgressList{{Units: []*workflowv1.StageUnitProgress{
			{GroupId: "approvers", Quorum: "one", Required: 1, Pending: 1, Roster: 1, Status: "PENDING"},
		}}},
	}}
	id := &groupNameIdentity{groups: map[string]string{"approvers": "Approvers"}}
	pc, groups, _ := statusReadSetup(t, false)
	out, err := resolvers.WorkflowStatusResolver(readerCtx(t), log.Nop(), wf, id, pc, groups, noGrant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("WorkflowStatusResolver: %v", err)
	}
	row := out.StageAssignees[0]
	if row[0].GroupID == nil || *row[0].GroupID != "approvers" || row[1].GroupID != nil {
		t.Fatalf("group seats: %+v %+v", row[0], row[1])
	}
	unit := out.StageUnitProgress[0][0]
	if unit.GroupName == nil || *unit.GroupName != "Approvers" {
		t.Fatalf("unit group name resolved from identity: %+v", unit)
	}
}

func TestPendingTasksResolver_TitleFromCore(t *testing.T) {
	wf := &fakeWorkflowClient{pendingResp: &workflowv1.ListPendingTasksResponse{Tasks: []*workflowv1.PendingTask{
		{TaskId: "t1", RunId: "r1", PolicyVersionId: "pv-1"},
		{TaskId: "t2", RunId: "r2", PolicyVersionId: "pv-missing"},
	}}}
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{"pol-1": {Id: "pol-1", Title: "Desk Booking Policy"}},
		versions: map[string]*corev1.PolicyVersion{"pv-1": {Id: "pv-1", PolicyId: "pol-1"}},
	}
	out, err := resolvers.PendingTasksResolver(ctxWithRoles(t, "carol", nil), wf, pc)
	if err != nil {
		t.Fatalf("PendingTasksResolver: %v", err)
	}
	if out[0].PolicyTitle != "Desk Booking Policy" || out[1].PolicyTitle != "" {
		t.Fatalf("titles: %q %q", out[0].PolicyTitle, out[1].PolicyTitle)
	}
	if wf.lastPending.GetApproverUserId() != "carol" {
		t.Fatalf("approver bound from the signed-in user: %q", wf.lastPending.GetApproverUserId())
	}
}

func TestWorkflowStatusResolver_SubmitterAndStageProgress(t *testing.T) {
	submitted := time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)
	due := time.Date(2026, 10, 8, 17, 0, 0, 0, time.UTC)
	wf := &fakeWorkflowClient{statusResp: &workflowv1.GetStatusResponse{
		Status:      workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW,
		RunId:       "run-1",
		StageNames:  []string{"Legal", "Security", "Board", "Exec"},
		SubmittedBy: "bob",
		SubmittedAt: timestamppb.New(submitted),
		StageProgress: []*workflowv1.StageProgress{
			{DueAt: timestamppb.New(due), Quorum: "one", Approvals: 1, Required: 1},
			{Quorum: "majority", Approvals: 0, Required: 2},
			{Quorum: "all", Approvals: 1, Required: 3},
			{Quorum: "nofm", QuorumN: 2, Approvals: 0, Required: 2},
		},
	}}
	pc, groups, _ := statusReadSetup(t, false)
	out, err := resolvers.WorkflowStatusResolver(readerCtx(t), log.Nop(), wf, &groupNameIdentity{}, pc, groups, noGrant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("WorkflowStatusResolver: %v", err)
	}
	if out.SubmittedBy == nil || *out.SubmittedBy != "bob" {
		t.Fatalf("submittedBy = %v, want bob", out.SubmittedBy)
	}
	if out.SubmittedAt == nil || *out.SubmittedAt != "2026-10-01T09:30:00Z" {
		t.Fatalf("submittedAt = %v, want 2026-10-01T09:30:00Z", out.SubmittedAt)
	}
	if len(out.StageProgress) != len(out.StageNames) {
		t.Fatalf("stageProgress has %d entries for %d stages", len(out.StageProgress), len(out.StageNames))
	}
	first := out.StageProgress[0]
	if first.DueAt == nil || *first.DueAt != "2026-10-08T17:00:00Z" || first.Quorum != "one" || first.Approvals != 1 || first.Required != 1 {
		t.Fatalf("stage 0: %+v", first)
	}
	for i, wantQuorum := range []string{"one", "majority", "all", "nofm"} {
		if got := out.StageProgress[i].Quorum; got != wantQuorum {
			t.Fatalf("stage %d quorum = %q, want %q", i, got, wantQuorum)
		}
	}
	for i := 1; i < 4; i++ {
		if out.StageProgress[i].DueAt != nil {
			t.Fatalf("stage %d dueAt = %q, want null before the stage is entered", i, *out.StageProgress[i].DueAt)
		}
	}
	if m := out.StageProgress[1]; m.Approvals != 0 || m.Required != 2 {
		t.Fatalf("majority stage counts: %+v", m)
	}
	if n := out.StageProgress[3]; n.QuorumN != 2 || n.Required != 2 {
		t.Fatalf("nofm stage counts: %+v", n)
	}
}

func TestWorkflowStatusResolver_NoStageProgressIsAnEmptyList(t *testing.T) {
	wf := &fakeWorkflowClient{statusResp: &workflowv1.GetStatusResponse{
		Status:     workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW,
		StageNames: []string{"Legal"},
	}}
	pc, groups, _ := statusReadSetup(t, false)
	out, err := resolvers.WorkflowStatusResolver(readerCtx(t), log.Nop(), wf, &groupNameIdentity{}, pc, groups, noGrant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("WorkflowStatusResolver: %v", err)
	}
	if out.StageProgress == nil || len(out.StageProgress) != 0 {
		t.Fatalf("stageProgress = %#v, want a non-nil empty list", out.StageProgress)
	}
	if out.SubmittedBy != nil || out.SubmittedAt != nil {
		t.Fatalf("an unset submitter and time are null: %v %v", out.SubmittedBy, out.SubmittedAt)
	}
}

func TestWorkflowStatusResolver_TargetVersionAndChangeType(t *testing.T) {
	pc, groups, _ := statusReadSetup(t, false)
	pc.versions["pol-1-v1"].SemanticVersion = &corev1.SemanticVersion{Major: 3, Minor: 0, Fix: 0, Text: "3.0.0"}
	pc.versions["pol-1-v1"].ChangeType = corev1.ChangeType_CHANGE_TYPE_MAJOR

	// A caller who can read the run but holds no workflow-definition access: the
	// reader role. The target comes from core's version, not from the definition.
	out, err := resolvers.WorkflowStatusResolver(readerCtx(t), log.Nop(), statusRun(), &groupNameIdentity{}, pc, groups, noGrant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("WorkflowStatusResolver: %v", err)
	}
	if out.TargetSemanticVersion == nil || *out.TargetSemanticVersion != "3.0.0" {
		t.Fatalf("targetSemanticVersion = %v, want 3.0.0", out.TargetSemanticVersion)
	}
	if out.TargetChangeType == nil || *out.TargetChangeType != resolvers.ChangeTypeMajor {
		t.Fatalf("targetChangeType = %v, want MAJOR", out.TargetChangeType)
	}
}

func TestWorkflowStatusResolver_TargetVersionNullWhenCoreHasNone(t *testing.T) {
	pc, groups, _ := statusReadSetup(t, false)
	out, err := resolvers.WorkflowStatusResolver(readerCtx(t), log.Nop(), statusRun(), &groupNameIdentity{}, pc, groups, noGrant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("WorkflowStatusResolver: %v", err)
	}
	if out.TargetSemanticVersion != nil || out.TargetChangeType != nil {
		t.Fatalf("target = %v %v, want null when core sent none", out.TargetSemanticVersion, out.TargetChangeType)
	}
}

func TestWorkflowStatusResolver_NoRunHasNoTarget(t *testing.T) {
	pc, groups, _ := statusReadSetup(t, false)
	pc.versions["pol-1-v1"].SemanticVersion = &corev1.SemanticVersion{Major: 3, Text: "3.0.0"}
	wf := &fakeWorkflowClient{statusErr: status.Error(codes.NotFound, "no approval run")}
	out, err := resolvers.WorkflowStatusResolver(readerCtx(t), log.Nop(), wf, &groupNameIdentity{}, pc, groups, noGrant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("WorkflowStatusResolver: %v", err)
	}
	if out.TargetSemanticVersion != nil || out.TargetChangeType != nil {
		t.Fatalf("a version with no run shows no target: %v %v", out.TargetSemanticVersion, out.TargetChangeType)
	}
}
