// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPreviewAccountMerge_RequiresSiteAdmin(t *testing.T) {
	admin := &fakeAdminClient{}
	ctx := ctxWithRoles(t, "u-1", []string{"policy-author"})
	if _, err := resolvers.PreviewAccountMergeResolver(ctx, admin, "src", "dst"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if admin.lastPreviewMerge != nil {
		t.Fatal("must not call identity when unauthorized")
	}
}

func TestPreviewAccountMerge_MapsProjection(t *testing.T) {
	admin := &fakeAdminClient{previewMergeResp: &identityv1.PreviewAccountMergeResponse{
		Preview: &identityv1.AccountMergePreview{
			SourceUserId: "src",
			TargetUserId: "dst",
			Counts: &identityv1.MergeCounts{
				PoliciesOwned:          2,
				RaciGrants:             3,
				AcknowledgmentsMoved:   4,
				AcknowledgmentsDeduped: 1,
				WorkflowItems:          5,
				Preferences:            6,
			},
			Items: []*identityv1.MergePreviewItem{
				{
					Kind:   identityv1.MergeItemKind_MERGE_ITEM_KIND_POLICY_OWNER,
					RefId:  "p1",
					Label:  "Policy 1",
					Detail: "owner re-points to dst",
				},
			},
			Warnings: []*identityv1.MergeWarning{
				{Code: "DEDUPE", Message: "one acknowledgement deduped"},
			},
			RequiresPrivilegedConfirm: true,
		},
	}}
	ctx := ctxWithRoles(t, "admin-1", []string{"site-admin"})
	out, err := resolvers.PreviewAccountMergeResolver(ctx, admin, "src", "dst")
	if err != nil {
		t.Fatalf("PreviewAccountMergeResolver: %v", err)
	}
	if admin.lastPreviewMerge.GetSourceUserId() != "src" || admin.lastPreviewMerge.GetTargetUserId() != "dst" {
		t.Fatalf("request not forwarded: %+v", admin.lastPreviewMerge)
	}
	if out.SourceUserID != "src" || out.TargetUserID != "dst" || !out.RequiresPrivilegedConfirm {
		t.Fatalf("preview scalars not mapped: %+v", out)
	}
	c := out.Counts
	if c == nil || c.PoliciesOwned != 2 || c.RaciGrants != 3 || c.AcknowledgmentsMoved != 4 ||
		c.AcknowledgmentsDeduped != 1 || c.WorkflowItems != 5 || c.Preferences != 6 {
		t.Fatalf("counts not mapped: %+v", c)
	}
	if len(out.Items) != 1 {
		t.Fatalf("want 1 item, got %d", len(out.Items))
	}
	if out.Items[0].Kind != resolvers.MergeItemKindPolicyOwner ||
		out.Items[0].RefID != "p1" || out.Items[0].Label != "Policy 1" || out.Items[0].Detail != "owner re-points to dst" {
		t.Fatalf("item not mapped: %+v", out.Items[0])
	}
	if len(out.Warnings) != 1 || out.Warnings[0].Code != "DEDUPE" || out.Warnings[0].Message != "one acknowledgement deduped" {
		t.Fatalf("warning not mapped: %+v", out.Warnings)
	}
}

func TestMergeAccounts_RequiresSiteAdmin(t *testing.T) {
	admin := &fakeAdminClient{}
	ctx := ctxWithRoles(t, "u-1", []string{"policy-author"})
	if _, err := resolvers.MergeAccountsResolver(ctx, admin, "src", "dst", nil, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if admin.lastMerge != nil {
		t.Fatal("must not call identity when unauthorized")
	}
}

func TestMergeAccounts_ForwardsActorAndMaps(t *testing.T) {
	admin := &fakeAdminClient{mergeAccountsResp: &identityv1.MergeAccountsResponse{
		MergeOperationId: "merge-op-7",
		Status:           identityv1.MergeStatus_MERGE_STATUS_PARTIAL,
		Counts: &identityv1.MergeCounts{
			PoliciesOwned: 2,
			RaciGrants:    3,
		},
		Steps: []*identityv1.MergeStepResult{
			{
				Step:   "policies",
				Status: identityv1.MergeStepStatus_MERGE_STEP_STATUS_COMPLETED,
				Detail: "2 re-pointed",
			},
			{
				Step:   "acknowledgments",
				Status: identityv1.MergeStepStatus_MERGE_STEP_STATUS_FAILED,
				Error:  "transient",
			},
		},
	}}
	ctx := ctxWithRoles(t, "admin-9", []string{"site-admin"})
	confirm := true
	key := "idem-123"
	out, err := resolvers.MergeAccountsResolver(ctx, admin, "src", "dst", &confirm, &key)
	if err != nil {
		t.Fatalf("MergeAccountsResolver: %v", err)
	}
	if admin.lastMerge.GetSourceUserId() != "src" || admin.lastMerge.GetTargetUserId() != "dst" {
		t.Fatalf("src/dst not forwarded: %+v", admin.lastMerge)
	}
	if admin.lastMergeActor != "admin-9" {
		t.Fatalf("actor not bound from claims; got %q", admin.lastMergeActor)
	}
	if !admin.lastMerge.GetConfirmPrivileged() {
		t.Fatal("confirmPrivileged not forwarded")
	}
	if admin.lastMerge.GetIdempotencyKey() != "idem-123" {
		t.Fatalf("idempotencyKey not forwarded; got %q", admin.lastMerge.GetIdempotencyKey())
	}
	if out.MergeOperationID != "merge-op-7" || out.Status != resolvers.MergeStatusPartial {
		t.Fatalf("result scalars not mapped: %+v", out)
	}
	if out.Counts == nil || out.Counts.PoliciesOwned != 2 || out.Counts.RaciGrants != 3 {
		t.Fatalf("counts not mapped: %+v", out.Counts)
	}
	if len(out.Steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(out.Steps))
	}
	if out.Steps[0].Step != "policies" || out.Steps[0].Status != resolvers.MergeStepStatusCompleted || out.Steps[0].Detail != "2 re-pointed" {
		t.Fatalf("step 0 not mapped: %+v", out.Steps[0])
	}
	if out.Steps[1].Step != "acknowledgments" || out.Steps[1].Status != resolvers.MergeStepStatusFailed || out.Steps[1].Error != "transient" {
		t.Fatalf("step 1 not mapped: %+v", out.Steps[1])
	}
}
