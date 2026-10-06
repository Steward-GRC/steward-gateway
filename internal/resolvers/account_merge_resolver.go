// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// mergeItemKindFromProto maps the proto MergeItemKind onto the GraphQL enum.
func mergeItemKindFromProto(k identityv1.MergeItemKind) MergeItemKind {
	switch k {
	case identityv1.MergeItemKind_MERGE_ITEM_KIND_POLICY_OWNER:
		return MergeItemKindPolicyOwner
	case identityv1.MergeItemKind_MERGE_ITEM_KIND_RACI_GRANT:
		return MergeItemKindRaciGrant
	case identityv1.MergeItemKind_MERGE_ITEM_KIND_ACKNOWLEDGMENT:
		return MergeItemKindAcknowledgment
	case identityv1.MergeItemKind_MERGE_ITEM_KIND_WORKFLOW_ITEM:
		return MergeItemKindWorkflowItem
	case identityv1.MergeItemKind_MERGE_ITEM_KIND_PREFERENCE:
		return MergeItemKindPreference
	default:
		return MergeItemKindPolicyOwner
	}
}

// mergeStatusFromProto maps the proto MergeStatus onto the GraphQL enum.
func mergeStatusFromProto(s identityv1.MergeStatus) MergeStatus {
	switch s {
	case identityv1.MergeStatus_MERGE_STATUS_COMPLETED:
		return MergeStatusCompleted
	case identityv1.MergeStatus_MERGE_STATUS_PARTIAL:
		return MergeStatusPartial
	default:
		return MergeStatusFailed
	}
}

// mergeStepStatusFromProto maps the proto MergeStepStatus onto the GraphQL enum.
func mergeStepStatusFromProto(s identityv1.MergeStepStatus) MergeStepStatus {
	switch s {
	case identityv1.MergeStepStatus_MERGE_STEP_STATUS_PENDING:
		return MergeStepStatusPending
	case identityv1.MergeStepStatus_MERGE_STEP_STATUS_COMPLETED:
		return MergeStepStatusCompleted
	case identityv1.MergeStepStatus_MERGE_STEP_STATUS_SKIPPED:
		return MergeStepStatusSkipped
	default:
		return MergeStepStatusFailed
	}
}

// mergeCountsFromProto maps the proto MergeCounts onto the GraphQL model.
func mergeCountsFromProto(c *identityv1.MergeCounts) *MergeCounts {
	if c == nil {
		return &MergeCounts{}
	}
	return &MergeCounts{
		PoliciesOwned:          int(c.GetPoliciesOwned()),
		RaciGrants:             int(c.GetRaciGrants()),
		AcknowledgmentsMoved:   int(c.GetAcknowledgmentsMoved()),
		AcknowledgmentsDeduped: int(c.GetAcknowledgmentsDeduped()),
		WorkflowItems:          int(c.GetWorkflowItems()),
		Preferences:            int(c.GetPreferences()),
	}
}

// PreviewAccountMergeResolver returns a read-only, side-effect-free projection of what merging
// sourceUserID INTO targetUserID would move/dedupe.
func PreviewAccountMergeResolver(ctx context.Context, adminClient identityv1.IdentityAdminServiceClient, sourceUserID, targetUserID string) (*AccountMergePreview, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	if adminClient == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := adminClient.PreviewAccountMerge(ctx, &identityv1.PreviewAccountMergeRequest{
		SourceUserId: sourceUserID,
		TargetUserId: targetUserID,
	})
	if err != nil {
		return nil, err
	}
	p := resp.GetPreview()
	out := &AccountMergePreview{
		SourceUserID:              p.GetSourceUserId(),
		TargetUserID:              p.GetTargetUserId(),
		Counts:                    mergeCountsFromProto(p.GetCounts()),
		Items:                     make([]*MergePreviewItem, 0, len(p.GetItems())),
		Warnings:                  make([]*MergeWarning, 0, len(p.GetWarnings())),
		RequiresPrivilegedConfirm: p.GetRequiresPrivilegedConfirm(),
	}
	for _, it := range p.GetItems() {
		out.Items = append(out.Items, &MergePreviewItem{
			Kind:   mergeItemKindFromProto(it.GetKind()),
			RefID:  it.GetRefId(),
			Label:  it.GetLabel(),
			Detail: it.GetDetail(),
		})
	}
	for _, w := range p.GetWarnings() {
		out.Warnings = append(out.Warnings, &MergeWarning{
			Code:    w.GetCode(),
			Message: w.GetMessage(),
		})
	}
	return out, nil
}

// MergeAccountsResolver merges sourceUserID INTO targetUserID in one auditable admin op.
func MergeAccountsResolver(ctx context.Context, adminClient identityv1.IdentityAdminServiceClient, sourceUserID, targetUserID string, confirmPrivileged *bool, idempotencyKey *string) (*MergeAccountsResult, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	if adminClient == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := adminClient.MergeAccounts(ctx, &identityv1.MergeAccountsRequest{
		SourceUserId:      sourceUserID,
		TargetUserId:      targetUserID,
		ConfirmPrivileged: derefBool(confirmPrivileged),
		IdempotencyKey:    derefOrEmpty(idempotencyKey),
	})
	if err != nil {
		return nil, err
	}
	out := &MergeAccountsResult{
		MergeOperationID: resp.GetMergeOperationId(),
		Status:           mergeStatusFromProto(resp.GetStatus()),
		Counts:           mergeCountsFromProto(resp.GetCounts()),
		Steps:            make([]*MergeStepResult, 0, len(resp.GetSteps())),
	}
	for _, s := range resp.GetSteps() {
		out.Steps = append(out.Steps, &MergeStepResult{
			Step:   s.GetStep(),
			Status: mergeStepStatusFromProto(s.GetStatus()),
			Detail: s.GetDetail(),
			Error:  s.GetError(),
		})
	}
	return out, nil
}
