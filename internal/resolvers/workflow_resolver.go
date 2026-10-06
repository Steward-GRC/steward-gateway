// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// ResolveEffectiveWorkflowResolver computes the approval workflow EFFECTIVE for a policy: it loads
// the policy's home group, walks the group lineage leaf→root, and asks the workflow service to
// resolve it (per-policy override, else the first group assignment up the chain).
func ResolveEffectiveWorkflowResolver(
	ctx context.Context,
	policyClient corev1.PolicyServiceClient,
	categoryClient corev1.CategoryServiceClient,
	workflowClient workflowv1.WorkflowServiceClient,
	policyID string,
) (*EffectiveWorkflow, error) {
	pol, err := policyClient.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: policyID})
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}
	ancestors, err := categoryLineage(ctx, categoryClient, pol.GetPolicy().GetHomeCategoryId())
	if err != nil {
		return nil, err
	}
	resp, err := workflowClient.ResolveWorkflow(ctx, &workflowv1.ResolveWorkflowRequest{
		PolicyId:            policyID,
		AncestorCategoryIds: ancestors,
	})
	if err != nil {
		return nil, fmt.Errorf("resolve workflow: %w", err)
	}
	defID := resp.GetWorkflowDefId()
	ew := &EffectiveWorkflow{HasWorkflow: defID != ""}
	if defID != "" {
		ew.WorkflowDefID = &defID
	}
	if defID == "" {
		ew.Usable = true
		return ew, nil
	}
	def, err := workflowClient.GetWorkflowDef(ctx, &workflowv1.GetWorkflowDefRequest{Id: defID})
	if err != nil {
		return nil, fmt.Errorf("get workflow def: %w", err)
	}
	ew.Usable, ew.FirstUnstaffedStage = workflowUsability(def.GetDef())
	return ew, nil
}

// workflowUsability reports whether a resolved workflow definition is USABLE and, when it is not,
// the name of the first stage that has no approver.
func workflowUsability(def *workflowv1.WorkflowDef) (usable bool, firstUnstaffed *string) {
	for _, s := range def.GetStages() {
		if len(s.GetApproverIds()) == 0 && len(s.GetApproversByCategory()) == 0 && len(s.GetGroupUnits()) == 0 {
			name := s.GetName()
			return false, &name
		}
	}
	return true, nil
}

// SubmitWorkflowResolver starts an approval saga for a policy version.
func SubmitWorkflowResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	categoryClient corev1.CategoryServiceClient,
	policyClient corev1.PolicyServiceClient,
	policyVersionID, policyID, categoryID string,
	ancestorCategoryIDs []string,
) (*WorkflowSubmitResult, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	if _, err := authorizeEffectiveAuthor(ctx, policyClient, categoryClient, policyID); err != nil {
		return nil, err
	}
	lineage, err := categoryLineage(ctx, categoryClient, categoryID)
	if err != nil {
		return nil, err
	}
	if len(lineage) == 0 {
		lineage = ancestorCategoryIDs
	}
	resp, err := client.Submit(ctx, &workflowv1.SubmitRequest{
		PolicyVersionId:     policyVersionID,
		PolicyId:            policyID,
		CategoryId:          categoryID,
		SubmittedBy:         claims.UserID(),
		AncestorCategoryIds: lineage,
	})
	if err != nil {
		return nil, fmt.Errorf("workflow submit: %w", err)
	}
	return &WorkflowSubmitResult{RunID: resp.GetRunId()}, nil
}

// SignalWorkflowResolver delivers an approver decision to an active run.
func SignalWorkflowResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	policyVersionID, runID, taskID string,
	signal SignalType,
	comment string,
) (bool, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return false, fmt.Errorf("unauthenticated")
	}
	_, err := client.Signal(ctx, &workflowv1.SignalRequest{
		PolicyVersionId: policyVersionID,
		RunId:           runID,
		TaskId:          taskID,
		Signal:          signalGQLToProto(signal),
		ActorUserId:     claims.UserID(),
		Comment:         comment,
	})
	if err != nil {
		return false, fmt.Errorf("workflow signal: %w", err)
	}
	return true, nil
}

// SwapAssigneeResolver wires the swapAssignee mutation.
func SwapAssigneeResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	input SwapAssigneeInput,
) (*SwapAssigneeResult, error) {
	if err := authorizeOp(ctx, authz.WorkflowManage); err != nil {
		return nil, err
	}
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}

	role := deriveInitiatorRole(claims, input.CurrentUserID)

	outOfElig := false
	if input.OutOfEligibilityAck != nil {
		outOfElig = *input.OutOfEligibilityAck
	}

	resp, err := client.SwapAssignee(ctx, &workflowv1.SwapAssigneeRequest{
		PolicyVersionId:     input.PolicyVersionID,
		StageIndex:          toInt32(input.StageIndex),
		CurrentUserId:       input.CurrentUserID,
		NewUserId:           input.NewUserID,
		Reason:              input.Reason,
		InitiatorRole:       role,
		OutOfEligibilityAck: outOfElig,
	})
	if err != nil {
		return nil, fmt.Errorf("workflow swap: %w", err)
	}
	out := &SwapAssigneeResult{
		NewAssignmentID: resp.GetNewAssignmentId(),
	}
	if ts := resp.GetNewSlaDeadlineAt(); ts != nil {
		out.NewSLADeadlineAt = ts.AsTime().UTC().Format(time.RFC3339)
	}
	return out, nil
}

// BulkDecideResolver wires the bulkDecide mutation.
func BulkDecideResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	input BulkDecideInput,
) (*BulkDecideResult, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	decisions := make([]*workflowv1.Decision, 0, len(input.Decisions))
	for _, d := range input.Decisions {
		decisions = append(decisions, &workflowv1.Decision{
			PolicyVersionId: d.PolicyVersionID,
			StageIndex:      toInt32(d.StageIndex),
			Decision:        decisionGQLToProto(d.Decision),
			Comment:         d.Comment,
		})
	}
	resp, err := client.BulkDecide(ctx, &workflowv1.BulkDecideRequest{Decisions: decisions})
	if err != nil {
		return nil, fmt.Errorf("workflow bulk decide: %w", err)
	}
	out := &BulkDecideResult{
		BulkBatchID: resp.GetBulkBatchId(),
		Results:     make([]*DecisionResult, 0, len(resp.GetResults())),
	}
	for _, r := range resp.GetResults() {
		dr := &DecisionResult{
			PolicyVersionID: r.GetPolicyVersionId(),
			StageIndex:      int(r.GetStageIndex()),
			Ok:              r.GetOk(),
		}
		if e := r.GetError(); e != "" {
			ee := e
			dr.Error = &ee
		}
		if a := r.GetAssignmentId(); a != "" {
			aa := a
			dr.AssignmentID = &aa
		}
		out.Results = append(out.Results, dr)
	}
	return out, nil
}

// AssignmentHistoryResolver wires the assignmentHistory query.
func AssignmentHistoryResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	identity identityv1.IdentityReadServiceClient,
	categoryClient corev1.CategoryServiceClient,
	policyVersionID string,
	stageIndex int,
) ([]*AssignmentHistoryEntry, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	if err := authorizeCapability(ctx, authz.PolicyApprove); err != nil {
		if categoryClient == nil || len(ownedGroupNames(ctx, categoryClient, claims.UserID())) == 0 {
			return nil, err
		}
	}
	resp, err := client.GetAssignmentHistory(ctx, &workflowv1.GetAssignmentHistoryRequest{
		PolicyVersionId: policyVersionID,
		StageIndex:      toInt32(stageIndex),
	})
	if err != nil {
		return nil, fmt.Errorf("workflow assignment history: %w", err)
	}
	labels := newLabelResolver(identity, nil, nil, nil)
	out := make([]*AssignmentHistoryEntry, 0, len(resp.GetEntries()))
	for _, e := range resp.GetEntries() {
		entry := &AssignmentHistoryEntry{
			ID:               strconv.FormatInt(e.GetId(), 10),
			AssignmentID:     e.GetAssignmentId(),
			Event:            e.GetEvent(),
			ActorUserID:      e.GetActorUserId(),
			OutOfEligibility: e.GetOutOfEligibility(),
		}
		if v := e.GetActorRole(); v != "" {
			s := v
			entry.ActorRole = &s
		}
		if v := e.GetPreviousUserId(); v != "" {
			s := v
			entry.PreviousUserID = &s
		}
		if v := e.GetNewUserId(); v != "" {
			s := v
			entry.NewUserID = &s
		}
		if v := e.GetReason(); v != "" {
			s := v
			entry.Reason = &s
		}
		if ts := e.GetCreatedAt(); ts != nil {
			entry.CreatedAt = ts.AsTime().UTC().Format(time.RFC3339)
		}
		entry.ActorName = nilIfEmpty(labels.userName(ctx, e.GetActorUserId()))
		entry.PreviousUserName = nilIfEmpty(labels.userName(ctx, e.GetPreviousUserId()))
		entry.NewUserName = nilIfEmpty(labels.userName(ctx, e.GetNewUserId()))
		out = append(out, entry)
	}
	return out, nil
}

// StageEligibleAssigneesResolver returns one stage's eligible-assignee pool, the ids SwapAssignee
// accepts without an out-of-eligibility ack, resolved to labels in definition order.
func StageEligibleAssigneesResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	identity identityv1.IdentityReadServiceClient,
	policyVersionID string,
	stageIndex int,
) (*StageEligibleAssignees, error) {
	if err := authorizeOp(ctx, authz.WorkflowManage); err != nil {
		return nil, err
	}
	resp, err := client.GetStageEligiblePool(ctx, &workflowv1.GetStageEligiblePoolRequest{
		PolicyVersionId: policyVersionID,
		StageIndex:      toInt32(stageIndex),
	})
	if err != nil {
		return nil, fmt.Errorf("workflow stage eligible pool: %w", err)
	}
	labels := newLabelResolver(identity, nil, nil, nil)
	out := &StageEligibleAssignees{
		StageIndex: int(resp.GetStageIndex()),
		StageName:  resp.GetStageName(),
		Assignees:  make([]*UserLabel, 0, len(resp.GetEligibleUserIds())),
	}
	for _, id := range resp.GetEligibleUserIds() {
		name, email := labels.userLabelFields(ctx, id)
		if name == "" {
			name = id
		}
		out.Assignees = append(out.Assignees, &UserLabel{ID: id, Name: name, Email: nilIfEmpty(email)})
	}
	return out, nil
}

// WorkflowStatusResolver returns the current approval status + active stage for a policy version.
func WorkflowStatusResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	identity identityv1.IdentityReadServiceClient,
	categoryClient corev1.CategoryServiceClient,
	policyVersionID string,
) (*WorkflowStatus, error) {
	resp, err := client.GetStatus(ctx, &workflowv1.GetStatusRequest{PolicyVersionId: policyVersionID})
	if err != nil {
		if st, ok := status.FromError(err); (ok && st.Code() == codes.NotFound) ||
			strings.Contains(err.Error(), "no approval run") {
			return &WorkflowStatus{
				Status:            ApprovalStatusApprovalStatusUnspecified,
				StageNames:        []string{},
				StageAssignees:    [][]*StageAssignee{},
				StageUnitProgress: [][]*StageUnitProgress{},
			}, nil
		}
		return nil, fmt.Errorf("workflow get status: %w", err)
	}
	labels := newLabelResolver(identity, nil, nil, nil)
	stageAssignees := make([][]*StageAssignee, 0, len(resp.GetStageAssignees()))
	for _, sa := range resp.GetStageAssignees() {
		row := make([]*StageAssignee, 0, len(sa.GetAssignees()))
		for _, a := range sa.GetAssignees() {
			entry := &StageAssignee{
				UserID:  a.GetUserId(),
				State:   a.GetState(),
				Name:    nilIfEmpty(labels.userName(ctx, a.GetUserId())),
				GroupID: nilIfEmpty(a.GetGroupId()),
			}
			if c := a.GetComment(); c != "" {
				s := c
				entry.Comment = &s
			}
			if ts := a.GetDecidedAt(); ts != nil {
				s := ts.AsTime().UTC().Format(time.RFC3339)
				entry.DecidedAt = &s
			}
			row = append(row, entry)
		}
		stageAssignees = append(stageAssignees, row)
	}
	groupNames := map[string]string{}
	resolveGroupName := func(gid string) *string {
		if gid == "" {
			return nil
		}
		if n, ok := groupNames[gid]; ok {
			return nilIfEmpty(n)
		}
		name := ""
		if identity != nil {
			if g, gerr := identity.GetGroup(ctx, &identityv1.GetGroupRequest{GroupId: gid}); gerr == nil {
				name = g.GetGroup().GetName()
			}
		}
		groupNames[gid] = name
		return nilIfEmpty(name)
	}
	stageUnitProgress := make([][]*StageUnitProgress, 0, len(resp.GetStageUnitProgress()))
	for _, upl := range resp.GetStageUnitProgress() {
		row := make([]*StageUnitProgress, 0, len(upl.GetUnits()))
		for _, u := range upl.GetUnits() {
			row = append(row, &StageUnitProgress{
				GroupID:   u.GetGroupId(),
				GroupName: resolveGroupName(u.GetGroupId()),
				Quorum:    u.GetQuorum(),
				Required:  int(u.GetRequired()),
				Approvals: int(u.GetApprovals()),
				Pending:   int(u.GetPending()),
				Roster:    int(u.GetRoster()),
				Status:    u.GetStatus(),
			})
		}
		stageUnitProgress = append(stageUnitProgress, row)
	}
	return &WorkflowStatus{
		Status:            approvalStatusProtoToGQL(resp.GetStatus()),
		RunID:             resp.GetRunId(),
		CurrentStageIdx:   int(resp.GetCurrentStageIdx()),
		StageNames:        resp.GetStageNames(),
		StageAssignees:    stageAssignees,
		StageUnitProgress: stageUnitProgress,
	}, nil
}

// PendingTasksResolver lists approval tasks awaiting the authenticated user.
func PendingTasksResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	policies corev1.PolicyServiceClient,
) ([]*PendingTask, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.ListPendingTasks(ctx, &workflowv1.ListPendingTasksRequest{
		ApproverUserId: claims.UserID(),
	})
	if err != nil {
		return nil, fmt.Errorf("workflow list pending tasks: %w", err)
	}
	titles := newVersionTitles(policies)
	out := make([]*PendingTask, 0, len(resp.GetTasks()))
	for _, t := range resp.GetTasks() {
		var dueAt *string
		if ts := t.GetDueAt(); ts != nil {
			s := ts.AsTime().UTC().Format(time.RFC3339)
			dueAt = &s
		}
		out = append(out, &PendingTask{
			TaskID:          t.GetTaskId(),
			RunID:           t.GetRunId(),
			PolicyVersionID: t.GetPolicyVersionId(),
			PolicyTitle:     titles.of(ctx, t.GetPolicyVersionId()),
			StageIndex:      int(t.GetStageIndex()),
			DueAt:           dueAt,
		})
	}
	return out, nil
}

// UpcomingApprovalsResolver returns approvals where the authenticated user is an approver on a
// FUTURE (not-yet-reached) stage of an active run — a heads-up before it's their turn.
func UpcomingApprovalsResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	policies corev1.PolicyServiceClient,
) ([]*UpcomingApproval, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.ListUpcomingTasks(ctx, &workflowv1.ListUpcomingTasksRequest{
		ApproverUserId: claims.UserID(),
	})
	if err != nil {
		return nil, fmt.Errorf("workflow list upcoming tasks: %w", err)
	}
	titles := newVersionTitles(policies)
	out := make([]*UpcomingApproval, 0, len(resp.GetTasks()))
	for _, t := range resp.GetTasks() {
		out = append(out, &UpcomingApproval{
			PolicyVersionID: t.GetPolicyVersionId(),
			PolicyTitle:     titles.of(ctx, t.GetPolicyVersionId()),
			StageIndex:      int(t.GetStageIndex()),
			StageName:       t.GetStageName(),
		})
	}
	return out, nil
}

// deriveInitiatorRole picks the swap initiator role workflow checks: the
// seat's own holder delegating, else an admin (workflow.manage), else the
// workflow's author.
func deriveInitiatorRole(claims principal.Claims, currentUserID string) workflowv1.InitiatorRole {
	if claims.UserID() == currentUserID {
		return workflowv1.InitiatorRole_INITIATOR_ROLE_SELF_DELEGATE
	}
	roles := make([]authz.Role, 0, len(claims.Roles()))
	for _, r := range claims.Roles() {
		roles = append(roles, authz.Role(r))
	}
	if slices.Contains(authz.RolePermissions(roles...), authz.WorkflowManage) {
		return workflowv1.InitiatorRole_INITIATOR_ROLE_ADMIN
	}
	return workflowv1.InitiatorRole_INITIATOR_ROLE_WORKFLOW_AUTHOR
}

// signalGQLToProto maps the gqlgen-generated SignalType to the workflow proto enum.
func signalGQLToProto(s SignalType) workflowv1.SignalType {
	switch s {
	case SignalTypeSignalTypeApprove:
		return workflowv1.SignalType_SIGNAL_TYPE_APPROVE
	case SignalTypeSignalTypeReject:
		return workflowv1.SignalType_SIGNAL_TYPE_REJECT
	case SignalTypeSignalTypeRequestChanges:
		return workflowv1.SignalType_SIGNAL_TYPE_REQUEST_CHANGES
	case SignalTypeSignalTypeWithdraw:
		return workflowv1.SignalType_SIGNAL_TYPE_WITHDRAW
	case SignalTypeSignalTypeRetire:
		return workflowv1.SignalType_SIGNAL_TYPE_RETIRE
	default:
		return workflowv1.SignalType_SIGNAL_TYPE_UNSPECIFIED
	}
}

// decisionGQLToProto maps the bulk-decide enum to the proto enum.
func decisionGQLToProto(d DecisionType) workflowv1.DecisionType {
	switch d {
	case DecisionTypeDecisionTypeApprove:
		return workflowv1.DecisionType_DECISION_TYPE_APPROVE
	case DecisionTypeDecisionTypeReject:
		return workflowv1.DecisionType_DECISION_TYPE_REJECT
	default:
		return workflowv1.DecisionType_DECISION_TYPE_UNSPECIFIED
	}
}

// approvalStatusProtoToGQL maps the workflow proto ApprovalStatus enum back to the gqlgen-generated
// GraphQL enum.
func approvalStatusProtoToGQL(s workflowv1.ApprovalStatus) ApprovalStatus {
	switch s {
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_DRAFT:
		return ApprovalStatusApprovalStatusDraft
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW:
		return ApprovalStatusApprovalStatusInReview
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_APPROVED:
		return ApprovalStatusApprovalStatusApproved
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_SCHEDULED:
		return ApprovalStatusApprovalStatusScheduled
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_PUBLISHED:
		return ApprovalStatusApprovalStatusPublished
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_SUPERSEDED:
		return ApprovalStatusApprovalStatusSuperseded
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_REJECTED:
		return ApprovalStatusApprovalStatusRejected
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_WITHDRAWN:
		return ApprovalStatusApprovalStatusWithdrawn
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_ARCHIVED:
		return ApprovalStatusApprovalStatusArchived
	default:
		return ApprovalStatusApprovalStatusUnspecified
	}
}

// versionTitles resolves a policy version id to its policy's title through
// core, cached per request; "" on a miss. Workflow keeps no titles.
type versionTitles struct {
	policies corev1.PolicyServiceClient
	cache    map[string]string
}

func newVersionTitles(policies corev1.PolicyServiceClient) *versionTitles {
	return &versionTitles{policies: policies, cache: map[string]string{}}
}

func (v *versionTitles) of(ctx context.Context, versionID string) string {
	if t, ok := v.cache[versionID]; ok {
		return t
	}
	t := ""
	if v.policies != nil {
		if vr, err := v.policies.GetPolicyVersion(ctx, &corev1.GetPolicyVersionRequest{Id: versionID}); err == nil {
			if pr, err := v.policies.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: vr.GetVersion().GetPolicyId()}); err == nil {
				t = pr.GetPolicy().GetTitle()
			}
		}
	}
	v.cache[versionID] = t
	return t
}
