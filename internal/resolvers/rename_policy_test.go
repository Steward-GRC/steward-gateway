// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// An effective author (here the primary author) may rename. A never-published
// policy comes back from core with staged=false and no draft id.
func TestRenamePolicy_EditorNeverPublished(t *testing.T) {
	pc, gc := coAuthMatrixEnv("creator-u", nil, nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}})

	res, err := resolvers.RenamePolicy(ctx, pc, gc, &fakeWorkflowClient{}, "pol", "Brand New Title")
	if err != nil {
		t.Fatalf("expected rename allowed, got %v", err)
	}
	if pc.lastRename == nil {
		t.Fatal("expected core RenamePolicy to be called")
	}
	if pc.lastRename.GetNewTitle() != "Brand New Title" {
		t.Fatalf("new_title forwarded: got %q", pc.lastRename.GetNewTitle())
	}
	if pc.lastRename.GetActorUserId() != "creator-u" {
		t.Fatalf("actor bound from claims: got %q want %q", pc.lastRename.GetActorUserId(), "creator-u")
	}
	if res.Staged {
		t.Fatalf("expected staged=false for never-published")
	}
	if res.DraftVersionID != nil {
		t.Fatalf("expected nil draftVersionId, got %q", *res.DraftVersionID)
	}
	if res.Policy == nil || res.Policy.Title != "Brand New Title" {
		t.Fatalf("expected policy title updated in result")
	}
}

// An effective author renaming a PUBLISHED policy gets staged=true plus the
// draft version id core created for the staged rename.
func TestRenamePolicy_EditorPublishedStaged(t *testing.T) {
	pc, gc := coAuthMatrixEnv("creator-u", nil, nil)
	pc.renameResp = &corev1.RenamePolicyResponse{
		Policy:         &corev1.Policy{Id: "pol", Title: "P"}, // title stays live
		Staged:         true,
		DraftVersionId: "draft-123",
	}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}})

	res, err := resolvers.RenamePolicy(ctx, pc, gc, &fakeWorkflowClient{}, "pol", "Proposed Title")
	if err != nil {
		t.Fatalf("expected rename allowed, got %v", err)
	}
	if !res.Staged {
		t.Fatalf("expected staged=true for published policy")
	}
	if res.DraftVersionID == nil || *res.DraftVersionID != "draft-123" {
		t.Fatalf("expected draftVersionId=draft-123, got %v", res.DraftVersionID)
	}
}

// Defensive backstop: even when the gateway's own workflow check does not fire
// (here the policy has no draft, so no workflow status is consulted) and core
// itself refuses the rename with FailedPrecondition, the resolver must surface
// that status VERBATIM — same code and message — so the sanitizing presenter
// passes the block message to the client. It must not swallow it into a generic
// internal error..
func TestRenamePolicy_PendingApprovalSurfacesError(t *testing.T) {
	const msg = "A change is pending approval. Resolve or withdraw that draft before renaming."
	pc, gc := coAuthMatrixEnv("creator-u", nil, nil)
	pc.renameErr = status.Error(codes.FailedPrecondition, msg)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}})

	_, err := resolvers.RenamePolicy(ctx, pc, gc, &fakeWorkflowClient{}, "pol", "Whatever")
	if err == nil {
		t.Fatal("expected an error when core returns FailedPrecondition")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v (%v)", status.Code(err), err)
	}
	if got := status.Convert(err).Message(); got != msg {
		t.Fatalf("message not surfaced verbatim: got %q want %q", got, msg)
	}
	if pc.lastRename == nil {
		t.Fatal("expected core RenamePolicy to be called")
	}
}

// A non-author is denied with PermissionDenied and core is NEVER called.
func TestRenamePolicy_NonEditorDenied(t *testing.T) {
	pc, gc := coAuthMatrixEnv("creator-other", nil,
		[]*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}})

	_, err := resolvers.RenamePolicy(ctx, pc, gc, &fakeWorkflowClient{}, "pol", "Nope")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
	if pc.lastRename != nil {
		t.Fatal("core RenamePolicy must NOT be called when denied")
	}
}

// AUTHORITATIVE gateway block. When the policy has a current draft AND
// the Workflow service reports that draft is IN_REVIEW, the gateway must refuse
// the rename with FailedPrecondition + the exact block message BEFORE calling
// core (core's version status is still `draft`, so core cannot see this). The
// gateway queries workflow status for the DRAFT version id.
func TestRenamePolicy_GatewayBlocksWhenDraftInReview(t *testing.T) {
	const msg = "A change is pending approval. Resolve or withdraw that draft before renaming."
	pc, gc := coAuthMatrixEnv("creator-u", nil, nil)
	pc.policies["pol"].CurrentDraftVersionId = "draft-999"
	wf := &fakeWorkflowClient{statusResp: &workflowv1.GetStatusResponse{
		Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW,
	}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}})

	_, err := resolvers.RenamePolicy(ctx, pc, gc, wf, "pol", "Whatever")
	if err == nil {
		t.Fatal("expected FailedPrecondition when the draft is in review")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v (%v)", status.Code(err), err)
	}
	if got := status.Convert(err).Message(); got != msg {
		t.Fatalf("block message not exact: got %q want %q", got, msg)
	}
	if wf.lastStatus == nil || wf.lastStatus.GetPolicyVersionId() != "draft-999" {
		t.Fatalf("expected workflow status queried for draft-999, got %+v", wf.lastStatus)
	}
	if pc.lastRename != nil {
		t.Fatal("core RenamePolicy must NOT be called when a change is pending approval")
	}
}

// A policy WITH a current draft but whose draft has NO active approval run
// (workflow status DRAFT — submitted-then-withdrawn or never submitted) is not
// blocked: the gateway proceeds and core RenamePolicy IS called.
func TestRenamePolicy_DraftNotInReviewProceeds(t *testing.T) {
	pc, gc := coAuthMatrixEnv("creator-u", nil, nil)
	pc.policies["pol"].CurrentDraftVersionId = "draft-777"
	wf := &fakeWorkflowClient{statusResp: &workflowv1.GetStatusResponse{
		Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_DRAFT,
	}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}})

	_, err := resolvers.RenamePolicy(ctx, pc, gc, wf, "pol", "Fresh Title")
	if err != nil {
		t.Fatalf("expected rename allowed when draft is not in review, got %v", err)
	}
	if wf.lastStatus == nil || wf.lastStatus.GetPolicyVersionId() != "draft-777" {
		t.Fatalf("expected workflow status queried for draft-777, got %+v", wf.lastStatus)
	}
	if pc.lastRename == nil {
		t.Fatal("expected core RenamePolicy to be called when no active approval")
	}
}
