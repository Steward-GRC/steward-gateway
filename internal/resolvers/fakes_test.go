// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// raciCategoryClient is a minimal GroupServiceClient stub used only by RACI tests.
type raciCategoryClient struct {
	corev1.CategoryServiceClient
	groups   map[string]*corev1.Category
	rulesets map[string][]*corev1.CategoryRule // keyed by categoryId
}

func (f *raciCategoryClient) GetCategory(_ context.Context, in *corev1.GetCategoryRequest, _ ...grpc.CallOption) (*corev1.GetCategoryResponse, error) {
	g, ok := f.groups[in.Id]
	if !ok {
		return nil, errors.New("group not found") // any non-nil error
	}
	return &corev1.GetCategoryResponse{Category: g}, nil
}

func (f *raciCategoryClient) ListCategoryChildren(_ context.Context, _ *corev1.ListCategoryChildrenRequest, _ ...grpc.CallOption) (*corev1.ListCategoryChildrenResponse, error) {
	return &corev1.ListCategoryChildrenResponse{}, nil
}

func (f *raciCategoryClient) CreateCategory(_ context.Context, _ *corev1.CreateCategoryRequest, _ ...grpc.CallOption) (*corev1.CreateCategoryResponse, error) {
	return nil, nil
}

func (f *raciCategoryClient) SetCategoryDefaults(_ context.Context, _ *corev1.SetCategoryDefaultsRequest, _ ...grpc.CallOption) (*corev1.SetCategoryDefaultsResponse, error) {
	return nil, nil
}

func (f *raciCategoryClient) RenameCategory(_ context.Context, _ *corev1.RenameCategoryRequest, _ ...grpc.CallOption) (*corev1.RenameCategoryResponse, error) {
	return nil, nil
}

func (f *raciCategoryClient) DeleteCategory(_ context.Context, _ *corev1.DeleteCategoryRequest, _ ...grpc.CallOption) (*corev1.DeleteCategoryResponse, error) {
	return nil, nil
}

func (f *raciCategoryClient) MoveCategory(_ context.Context, _ *corev1.MoveCategoryRequest, _ ...grpc.CallOption) (*corev1.MoveCategoryResponse, error) {
	return nil, nil
}

func (f *raciCategoryClient) SetGovernance(_ context.Context, _ *corev1.SetGovernanceRequest, _ ...grpc.CallOption) (*corev1.SetGovernanceResponse, error) {
	return nil, nil
}

func (f *raciCategoryClient) GetEffectiveGovernance(_ context.Context, _ *corev1.GetEffectiveGovernanceRequest, _ ...grpc.CallOption) (*corev1.GetEffectiveGovernanceResponse, error) {
	return &corev1.GetEffectiveGovernanceResponse{}, nil
}

func (f *raciCategoryClient) GetCategoryRuleset(_ context.Context, in *corev1.GetCategoryRulesetRequest, _ ...grpc.CallOption) (*corev1.GetCategoryRulesetResponse, error) {
	rules := f.rulesets[in.CategoryId]
	return &corev1.GetCategoryRulesetResponse{Rules: rules}, nil
}

func (f *raciCategoryClient) SetCategoryRuleset(_ context.Context, in *corev1.SetCategoryRulesetRequest, _ ...grpc.CallOption) (*corev1.SetCategoryRulesetResponse, error) {
	f.rulesets[in.CategoryId] = in.Rules
	return &corev1.SetCategoryRulesetResponse{Rules: in.Rules}, nil
}

// fakeWorkflowClient stubs the bits of workflowv1.WorkflowServiceClient that
// the Phase 5 resolvers exercise (SwapAssignee / BulkDecide /
// GetAssignmentHistory / SignalWorkflow) and the Task 9 WorkflowDef CRUD.
type fakeWorkflowClient struct {
	workflowv1.WorkflowServiceClient
	swapResp     *workflowv1.SwapAssigneeResponse
	swapErr      error
	lastSwap     *workflowv1.SwapAssigneeRequest
	bulkResp     *workflowv1.BulkDecideResponse
	bulkErr      error
	lastBulk     *workflowv1.BulkDecideRequest
	historyResp  *workflowv1.GetAssignmentHistoryResponse
	historyErr   error
	lastHistory  *workflowv1.GetAssignmentHistoryRequest
	signalResp   *workflowv1.SignalResponse
	signalErr    error
	lastSignal   *workflowv1.SignalRequest
	submitResp   *workflowv1.SubmitResponse
	submitErr    error
	resolveResp  *workflowv1.ResolveWorkflowResponse
	resolveErr   error
	lastResolve  *workflowv1.ResolveWorkflowRequest
	statusResp   *workflowv1.GetStatusResponse
	statusErr    error
	lastStatus   *workflowv1.GetStatusRequest
	pendingResp  *workflowv1.ListPendingTasksResponse
	pendingErr   error
	lastPending  *workflowv1.ListPendingTasksRequest
	upcomingResp *workflowv1.ListUpcomingTasksResponse
	upcomingErr  error
	lastUpcoming *workflowv1.ListUpcomingTasksRequest
	poolResp     *workflowv1.GetStageEligiblePoolResponse
	poolErr      error
	lastPool     *workflowv1.GetStageEligiblePoolRequest

	// WorkflowDef CRUD stubs (Task 9)
	listDefsResp   *workflowv1.ListWorkflowDefsResponse
	listDefsErr    error
	getDefResp     *workflowv1.GetWorkflowDefResponse
	getDefErr      error
	createDefResp  *workflowv1.CreateWorkflowDefResponse
	createDefErr   error
	lastCreateDef  *workflowv1.CreateWorkflowDefRequest
	updateDefResp  *workflowv1.UpdateWorkflowDefResponse
	updateDefErr   error
	lastUpdateDef  *workflowv1.UpdateWorkflowDefRequest
	archiveDefErr  error
	lastArchiveDef *workflowv1.ArchiveWorkflowDefRequest
}

func (f *fakeWorkflowClient) Submit(_ context.Context, _ *workflowv1.SubmitRequest, _ ...grpc.CallOption) (*workflowv1.SubmitResponse, error) {
	return f.submitResp, f.submitErr
}

func (f *fakeWorkflowClient) ResolveWorkflow(_ context.Context, in *workflowv1.ResolveWorkflowRequest, _ ...grpc.CallOption) (*workflowv1.ResolveWorkflowResponse, error) {
	f.lastResolve = in
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	if f.resolveResp != nil {
		return f.resolveResp, nil
	}
	return &workflowv1.ResolveWorkflowResponse{}, nil
}

func (f *fakeWorkflowClient) Signal(_ context.Context, in *workflowv1.SignalRequest, _ ...grpc.CallOption) (*workflowv1.SignalResponse, error) {
	f.lastSignal = in
	if f.signalErr != nil {
		return nil, f.signalErr
	}
	if f.signalResp == nil {
		return &workflowv1.SignalResponse{}, nil
	}
	return f.signalResp, nil
}

func (f *fakeWorkflowClient) GetStatus(_ context.Context, in *workflowv1.GetStatusRequest, _ ...grpc.CallOption) (*workflowv1.GetStatusResponse, error) {
	f.lastStatus = in
	return f.statusResp, f.statusErr
}

func (f *fakeWorkflowClient) ListPendingTasks(_ context.Context, in *workflowv1.ListPendingTasksRequest, _ ...grpc.CallOption) (*workflowv1.ListPendingTasksResponse, error) {
	f.lastPending = in
	return f.pendingResp, f.pendingErr
}

func (f *fakeWorkflowClient) ListUpcomingTasks(_ context.Context, in *workflowv1.ListUpcomingTasksRequest, _ ...grpc.CallOption) (*workflowv1.ListUpcomingTasksResponse, error) {
	f.lastUpcoming = in
	return f.upcomingResp, f.upcomingErr
}

func (f *fakeWorkflowClient) SwapAssignee(_ context.Context, in *workflowv1.SwapAssigneeRequest, _ ...grpc.CallOption) (*workflowv1.SwapAssigneeResponse, error) {
	f.lastSwap = in
	if f.swapErr != nil {
		return nil, f.swapErr
	}
	if f.swapResp == nil {
		return &workflowv1.SwapAssigneeResponse{NewAssignmentId: "a-new"}, nil
	}
	return f.swapResp, nil
}

func (f *fakeWorkflowClient) BulkDecide(_ context.Context, in *workflowv1.BulkDecideRequest, _ ...grpc.CallOption) (*workflowv1.BulkDecideResponse, error) {
	f.lastBulk = in
	if f.bulkErr != nil {
		return nil, f.bulkErr
	}
	if f.bulkResp == nil {
		return &workflowv1.BulkDecideResponse{BulkBatchId: "batch-1"}, nil
	}
	return f.bulkResp, nil
}

func (f *fakeWorkflowClient) GetAssignmentHistory(_ context.Context, in *workflowv1.GetAssignmentHistoryRequest, _ ...grpc.CallOption) (*workflowv1.GetAssignmentHistoryResponse, error) {
	f.lastHistory = in
	if f.historyErr != nil {
		return nil, f.historyErr
	}
	if f.historyResp == nil {
		return &workflowv1.GetAssignmentHistoryResponse{}, nil
	}
	return f.historyResp, nil
}

func (f *fakeWorkflowClient) ListWorkflowDefs(_ context.Context, _ *workflowv1.ListWorkflowDefsRequest, _ ...grpc.CallOption) (*workflowv1.ListWorkflowDefsResponse, error) {
	if f.listDefsErr != nil {
		return nil, f.listDefsErr
	}
	if f.listDefsResp == nil {
		return &workflowv1.ListWorkflowDefsResponse{}, nil
	}
	return f.listDefsResp, nil
}

func (f *fakeWorkflowClient) GetWorkflowDef(_ context.Context, _ *workflowv1.GetWorkflowDefRequest, _ ...grpc.CallOption) (*workflowv1.GetWorkflowDefResponse, error) {
	if f.getDefErr != nil {
		return nil, f.getDefErr
	}
	if f.getDefResp == nil {
		return &workflowv1.GetWorkflowDefResponse{}, nil
	}
	return f.getDefResp, nil
}

func (f *fakeWorkflowClient) CreateWorkflowDef(_ context.Context, in *workflowv1.CreateWorkflowDefRequest, _ ...grpc.CallOption) (*workflowv1.CreateWorkflowDefResponse, error) {
	f.lastCreateDef = in
	if f.createDefErr != nil {
		return nil, f.createDefErr
	}
	if f.createDefResp == nil {
		desc := in.GetDescription()
		return &workflowv1.CreateWorkflowDefResponse{Def: &workflowv1.WorkflowDef{
			Id: "def-new", Name: in.GetName(), Description: desc, Version: 1, Stages: in.GetStages(),
		}}, nil
	}
	return f.createDefResp, nil
}

func (f *fakeWorkflowClient) UpdateWorkflowDef(_ context.Context, in *workflowv1.UpdateWorkflowDefRequest, _ ...grpc.CallOption) (*workflowv1.UpdateWorkflowDefResponse, error) {
	f.lastUpdateDef = in
	if f.updateDefErr != nil {
		return nil, f.updateDefErr
	}
	if f.updateDefResp == nil {
		desc := in.GetDescription()
		return &workflowv1.UpdateWorkflowDefResponse{Def: &workflowv1.WorkflowDef{
			Id: in.GetId(), Name: in.GetName(), Description: desc, Version: 2, Stages: in.GetStages(),
		}}, nil
	}
	return f.updateDefResp, nil
}

func (f *fakeWorkflowClient) ArchiveWorkflowDef(_ context.Context, in *workflowv1.ArchiveWorkflowDefRequest, _ ...grpc.CallOption) (*workflowv1.ArchiveWorkflowDefResponse, error) {
	f.lastArchiveDef = in
	if f.archiveDefErr != nil {
		return nil, f.archiveDefErr
	}
	return &workflowv1.ArchiveWorkflowDefResponse{}, nil
}

func (f *fakeWorkflowClient) GetStageEligiblePool(_ context.Context, in *workflowv1.GetStageEligiblePoolRequest, _ ...grpc.CallOption) (*workflowv1.GetStageEligiblePoolResponse, error) {
	f.lastPool = in
	if f.poolErr != nil {
		return nil, f.poolErr
	}
	if f.poolResp == nil {
		return nil, status.Error(codes.Unimplemented, "GetStageEligiblePool not stubbed")
	}
	return f.poolResp, nil
}
