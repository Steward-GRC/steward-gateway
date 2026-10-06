// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

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
	ew, err := resolvers.ResolveEffectiveWorkflowResolver(context.Background(), pol, cat, wf, "pol-1")
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
	out, err := resolvers.WorkflowStatusResolver(context.Background(), wf, id, nil, "pv-1")
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
