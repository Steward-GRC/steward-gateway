// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"sort"
	"strconv"

	log "github.com/Bugs5382/go-log"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	authz "github.com/Steward-GRC/steward-gateway/internal/authz"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

// workflowDefFromProto maps a workflowv1.WorkflowDef proto onto the gqlgen WorkflowDef model.
func workflowDefFromProto(d *workflowv1.WorkflowDef) *WorkflowDef {
	if d == nil {
		return nil
	}
	stages := make([]*WorkflowStageDef, 0, len(d.GetStages()))
	for _, s := range d.GetStages() {
		stages = append(stages, workflowStageDefFromProto(s))
	}
	return &WorkflowDef{
		ID:          d.GetId(),
		Name:        d.GetName(),
		Description: nilIfEmpty(d.GetDescription()),
		Version:     int(d.GetVersion()),
		Stages:      stages,
	}
}

// workflowStageDefFromProto maps a workflowv1.WorkflowStage proto onto the gqlgen WorkflowStageDef
// model.
func workflowStageDefFromProto(s *workflowv1.WorkflowStage) *WorkflowStageDef {
	if s == nil {
		return nil
	}
	approvers := s.GetApproverIds()
	if approvers == nil {
		approvers = []string{}
	}
	out := &WorkflowStageDef{
		ID:                  s.GetId(),
		Name:                s.GetName(),
		Approvers:           approvers,
		ApproversByCategory: categoryApproversFromProto(s.GetApproversByCategory()),
		GroupUnits:          groupUnitsFromProto(s.GetGroupUnits()),
		Quorum:              s.GetQuorum(),
		VetoUserIds:         orEmpty(s.GetVetoUserIds()),
		RemindEveryDays:     int(s.GetRemindEveryDays()),
		EscalateAfterDays:   int(s.GetEscalateAfterDays()),
	}
	if v := s.GetSlaDays(); v != 0 {
		iv := int(v)
		out.SLADays = &iv
	}
	if s.GetRejectOnSlaBreach() {
		b := true
		out.RejectOnSLABreach = &b
	}
	if s.GetId() != "" {
		b := s.GetPinnedLast()
		out.PinnedLast = &b
	}
	return out
}

// workflowStageInputToProto maps a gqlgen WorkflowStageInput to the workflowv1.WorkflowStage proto
// used in Create/Update requests.
func workflowStageInputToProto(in *WorkflowStageInput) *workflowv1.WorkflowStage {
	if in == nil {
		return nil
	}
	approvers := in.Approvers
	if approvers == nil {
		approvers = []string{}
	}
	s := &workflowv1.WorkflowStage{
		Id:                  derefOrEmpty(in.ID),
		Name:                in.Name,
		ApproverIds:         approvers,
		ApproversByCategory: categoryApproversInputToProto(in.ApproversByCategory),
		GroupUnits:          groupUnitsInputToProto(in.GroupUnits),
		Quorum:              in.Quorum,
		VetoUserIds:         in.VetoUserIds,
	}
	if in.RemindEveryDays != nil {
		s.RemindEveryDays = toInt32KeepSign(*in.RemindEveryDays)
	}
	if in.EscalateAfterDays != nil {
		s.EscalateAfterDays = toInt32KeepSign(*in.EscalateAfterDays)
	}
	if in.SLADays != nil {
		s.SlaDays = toInt32(*in.SLADays)
	}
	if in.RejectOnSLABreach != nil {
		s.RejectOnSlaBreach = *in.RejectOnSLABreach
	}
	if in.PinnedLast != nil {
		s.PinnedLast = *in.PinnedLast
	}
	return s
}

// categoryApproversFromProto maps the per-category approver map to a list
// sorted by category id.
func categoryApproversFromProto(m map[string]*workflowv1.ApproverList) []*CategoryApprovers {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*CategoryApprovers, 0, len(m))
	for _, id := range ids {
		out = append(out, &CategoryApprovers{CategoryID: id, ApproverIds: orEmpty(m[id].GetUserIds())})
	}
	return out
}

func categoryApproversInputToProto(in []*CategoryApproversInput) map[string]*workflowv1.ApproverList {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*workflowv1.ApproverList, len(in))
	for _, c := range in {
		if c == nil {
			continue
		}
		out[c.CategoryID] = &workflowv1.ApproverList{UserIds: orEmpty(c.ApproverIds)}
	}
	return out
}

func groupUnitsFromProto(units []*workflowv1.GroupUnit) []*GroupUnit {
	out := make([]*GroupUnit, 0, len(units))
	for _, u := range units {
		out = append(out, &GroupUnit{GroupID: u.GetGroupId(), InternalQuorum: u.GetInternalQuorum(), MemberUserIds: orEmpty(u.GetMemberUserIds())})
	}
	return out
}

func groupUnitsInputToProto(in []*GroupUnitInput) []*workflowv1.GroupUnit {
	if len(in) == 0 {
		return nil
	}
	out := make([]*workflowv1.GroupUnit, 0, len(in))
	for _, u := range in {
		if u == nil {
			continue
		}
		out = append(out, &workflowv1.GroupUnit{GroupId: u.GroupID, InternalQuorum: u.InternalQuorum, MemberUserIds: orEmpty(u.MemberUserIds)})
	}
	return out
}

// WorkflowDefsResolver lists all workflow definitions.
func WorkflowDefsResolver(ctx context.Context, client workflowv1.WorkflowServiceClient) ([]*WorkflowDef, error) {
	resp, err := client.ListWorkflowDefs(ctx, &workflowv1.ListWorkflowDefsRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]*WorkflowDef, 0, len(resp.GetDefs()))
	for _, d := range resp.GetDefs() {
		out = append(out, workflowDefFromProto(d))
	}
	return out, nil
}

// WorkflowDefResolver fetches a single WorkflowDef by id.
func WorkflowDefResolver(ctx context.Context, client workflowv1.WorkflowServiceClient, id string) (*WorkflowDef, error) {
	resp, err := client.GetWorkflowDef(ctx, &workflowv1.GetWorkflowDefRequest{Id: id})
	if err != nil {
		return nil, err
	}
	return workflowDefFromProto(resp.GetDef()), nil
}

// CreateWorkflowDefResolver creates a new WorkflowDef.
func CreateWorkflowDefResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	name string,
	description *string,
	stages []*WorkflowStageInput,
) (*WorkflowDef, error) {
	if err := authorizeOp(ctx, authz.WorkflowManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	protoStages := make([]*workflowv1.WorkflowStage, 0, len(stages))
	for _, s := range stages {
		protoStages = append(protoStages, workflowStageInputToProto(s))
	}
	resp, err := client.CreateWorkflowDef(ctx, &workflowv1.CreateWorkflowDefRequest{
		Name:        name,
		Description: derefOrEmpty(description),
		Stages:      protoStages,
		ActorUserId: uid,
	})
	if err != nil {
		return nil, err
	}
	return workflowDefFromProto(resp.GetDef()), nil
}

// UpdateWorkflowDefResolver replaces a WorkflowDef's mutable fields.
func UpdateWorkflowDefResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	id, name string,
	description *string,
	stages []*WorkflowStageInput,
) (*WorkflowDef, error) {
	if err := authorizeOp(ctx, authz.WorkflowManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	protoStages := make([]*workflowv1.WorkflowStage, 0, len(stages))
	for _, s := range stages {
		protoStages = append(protoStages, workflowStageInputToProto(s))
	}
	resp, err := client.UpdateWorkflowDef(ctx, &workflowv1.UpdateWorkflowDefRequest{
		Id:          id,
		Name:        name,
		Description: derefOrEmpty(description),
		Stages:      protoStages,
		ActorUserId: uid,
	})
	if err != nil {
		return nil, err
	}
	return workflowDefFromProto(resp.GetDef()), nil
}

// ArchiveWorkflowDefResolver marks a WorkflowDef as archived.
func ArchiveWorkflowDefResolver(
	ctx context.Context,
	client workflowv1.WorkflowServiceClient,
	id string,
) (bool, error) {
	if err := authorizeOp(ctx, authz.WorkflowManage); err != nil {
		return false, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return false, err
	}
	_, err = client.ArchiveWorkflowDef(ctx, &workflowv1.ArchiveWorkflowDefRequest{Id: id, ActorUserId: uid})
	if err != nil {
		return false, err
	}
	return true, nil
}

// DeleteWorkflowDefResolver deletes a WorkflowDef that nothing uses. The gateway checks its own
// side first: a category whose default workflow is the id refuses the delete with
// WORKFLOW_DEF_IN_USE_BY_CATEGORY and the count, and workflow is not called. Workflow then
// refuses a definition any run ever pinned (6013, with run and override counts) or an unknown id
// (6014); both pass through unchanged for the error presenter.
func DeleteWorkflowDefResolver(
	ctx context.Context,
	lg log.Logger,
	client workflowv1.WorkflowServiceClient,
	categories corev1.CategoryServiceClient,
	id string,
) (bool, error) {
	l := lg.Ctx(ctx)
	l.Debug("workflow def delete: start", log.F("workflow_id", id))
	if err := authorizeOp(ctx, authz.WorkflowManage); err != nil {
		l.Debug("workflow def delete: refused, missing permission", log.F("workflow_id", id))
		return false, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return false, err
	}
	attached, err := categoriesUsingWorkflow(ctx, categories, id)
	if err != nil {
		l.Error(err, "workflow def delete: could not list categories", log.F("workflow_id", id))
		return false, err
	}
	if len(attached) > 0 {
		l.Info("workflow def delete: refused, categories use it as their default",
			log.F("workflow_id", id), log.F("category_count", len(attached)))
		return false, errcodes.New(errcodes.CodeWorkflowDefInUseByCategory,
			"id", id, "category_count", strconv.Itoa(len(attached)))
	}
	l.Debug("workflow def delete: no category default, calling workflow", log.F("workflow_id", id))
	if _, err := client.DeleteWorkflowDef(ctx, &workflowv1.DeleteWorkflowDefRequest{Id: id, ActorUserId: uid}); err != nil {
		l.Info("workflow def delete: workflow refused or failed", log.F("workflow_id", id), log.F("error", err.Error()))
		return false, err
	}
	l.Info("workflow def delete: deleted", log.F("workflow_id", id))
	return true, nil
}
