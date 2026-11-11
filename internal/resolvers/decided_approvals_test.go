// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// countedVersions is core counting its version reads, and answering the
// version ids in failIDs with a non-NotFound error.
type countedVersions struct {
	coreLikeVersions
	failIDs map[string]bool
	reads   int
}

func (f *countedVersions) GetPolicyVersion(ctx context.Context, in *corev1.GetPolicyVersionRequest, opts ...grpc.CallOption) (*corev1.GetPolicyVersionResponse, error) {
	f.reads++
	if f.failIDs[in.GetId()] {
		return nil, status.Error(codes.Unavailable, "core down")
	}
	return f.coreLikeVersions.GetPolicyVersion(ctx, in, opts...)
}

// decidedCore is core with two published policies: pol-open (readable by
// everyone) and pol-hidden (its category denies the Admins group).
func decidedCore() (coreLikeVersions, corev1.CategoryServiceClient) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{"g-open": {Id: "g-open", Name: "Open"}, "g-hidden": {Id: "g-hidden", Name: "Hidden"}},
		map[string][]*corev1.CategoryRule{
			"g-open":   {allowEveryoneRule()},
			"g-hidden": {denyGroupRule("Admins"), allowEveryoneRule()},
		})
	pub := corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED
	pc := coreLikeVersions{&recordingPolicyClient{fakePolicyClient: &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol-open":   {Id: "pol-open", HomeCategoryId: "g-open", Number: "POL-OP-1", Title: "Desk Booking Policy"},
			"pol-hidden": {Id: "pol-hidden", HomeCategoryId: "g-hidden", Number: "POL-HD-1", Title: "Board Minutes Policy"},
		},
		versions: map[string]*corev1.PolicyVersion{
			"pv-open-1":   {Id: "pv-open-1", PolicyId: "pol-open", VersionNo: 1, Status: pub},
			"pv-open-2":   {Id: "pv-open-2", PolicyId: "pol-open", VersionNo: 2, Status: pub},
			"pv-hidden-1": {Id: "pv-hidden-1", PolicyId: "pol-hidden", VersionNo: 1, Status: pub},
		},
	}}}
	return pc, groups
}

func decidedWorkflow(entries ...*workflowv1.DecidedApproval) *fakeWorkflowClient {
	return &fakeWorkflowClient{decidedResp: &workflowv1.ListDecidedApprovalsResponse{Approvals: entries}}
}

func decide(t *testing.T, ctx context.Context, wf *fakeWorkflowClient, pc corev1.PolicyServiceClient, groups corev1.CategoryServiceClient) ([]*resolvers.DecidedApproval, error) {
	t.Helper()
	return resolvers.DecidedApprovalsResolver(ctx, log.Nop(), wf, pc, groups, noGrant())
}

func TestDecidedApprovalsResolver_MapsTheCallersDecisionWithTheTitle(t *testing.T) {
	decidedAt := time.Date(2026, 9, 30, 14, 5, 0, 0, time.UTC)
	wf := decidedWorkflow(&workflowv1.DecidedApproval{
		PolicyVersionId: "pv-open-1", RunId: "run-1", CurrentStageIdx: 1, StageCount: 3,
		Decision: "approved", DecidedAt: timestamppb.New(decidedAt),
	})
	pc, groups := decidedCore()
	out, err := decide(t, readerCtx(t), wf, pc, groups)
	if err != nil {
		t.Fatalf("DecidedApprovalsResolver: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("entries = %d, want 1", len(out))
	}
	got := out[0]
	if got.PolicyVersionID != "pv-open-1" || got.PolicyTitle != "Desk Booking Policy" || got.RunID != "run-1" {
		t.Fatalf("identity fields: %+v", got)
	}
	if got.CurrentStageIdx != 1 || got.StageCount != 3 || got.Decision != "approved" {
		t.Fatalf("stage and decision: %+v", got)
	}
	if got.DecidedAt != "2026-09-30T14:05:00Z" {
		t.Fatalf("decidedAt = %q, want 2026-09-30T14:05:00Z", got.DecidedAt)
	}
}

func TestDecidedApprovalsResolver_MapsARejectionAndAnUnreadableStageCount(t *testing.T) {
	wf := decidedWorkflow(&workflowv1.DecidedApproval{
		PolicyVersionId: "pv-open-1", RunId: "run-1", CurrentStageIdx: 0, StageCount: 0,
		Decision: "rejected", DecidedAt: timestamppb.New(time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)),
	})
	pc, groups := decidedCore()
	out, err := decide(t, readerCtx(t), wf, pc, groups)
	if err != nil {
		t.Fatalf("DecidedApprovalsResolver: %v", err)
	}
	if len(out) != 1 || out[0].Decision != "rejected" || out[0].StageCount != 0 || out[0].CurrentStageIdx != 0 {
		t.Fatalf("got %+v", out)
	}
}

func TestDecidedApprovalsResolver_AsksWorkflowForTheSignedInUserOnly(t *testing.T) {
	wf := decidedWorkflow()
	pc, groups := decidedCore()
	if _, err := decide(t, ctxWithRoles(t, "carol", []string{"reader"}), wf, pc, groups); err != nil {
		t.Fatalf("DecidedApprovalsResolver: %v", err)
	}
	if wf.decidedCalls != 1 || wf.lastDecided.GetUserId() != "carol" {
		t.Fatalf("ListDecidedApprovals calls = %d for %q, want one for carol", wf.decidedCalls, wf.lastDecided.GetUserId())
	}
}

func TestDecidedApprovalsResolver_EmptyListIsEmptyNotNil(t *testing.T) {
	pc, groups := decidedCore()
	out, err := decide(t, readerCtx(t), decidedWorkflow(), pc, groups)
	if err != nil {
		t.Fatalf("DecidedApprovalsResolver: %v", err)
	}
	if out == nil || len(out) != 0 {
		t.Fatalf("got %#v, want an empty non-nil list", out)
	}
}

func TestDecidedApprovalsResolver_DropsAPolicyTheCallerCanNoLongerRead(t *testing.T) {
	wf := decidedWorkflow(
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-hidden-1", RunId: "run-h", Decision: "approved"},
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-1", RunId: "run-o", Decision: "approved"},
	)
	pc, groups := decidedCore()
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", RolesValue: []string{"reader"}, IdpGroupsValue: []string{"Admins"}})
	out, err := decide(t, ctx, wf, pc, groups)
	if err != nil {
		t.Fatalf("DecidedApprovalsResolver: %v", err)
	}
	if len(out) != 1 || out[0].RunID != "run-o" {
		t.Fatalf("got %+v, want only the readable policy's entry", out)
	}
	for _, e := range out {
		if e.PolicyTitle == "Board Minutes Policy" {
			t.Fatalf("title of an unreadable policy leaked: %+v", e)
		}
	}
}

func TestDecidedApprovalsResolver_DropsAnEntryCoreDoesNotKnow(t *testing.T) {
	wf := decidedWorkflow(
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-gone", RunId: "run-g", Decision: "approved"},
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-1", RunId: "run-o", Decision: "approved"},
	)
	pc, groups := decidedCore()
	out, err := decide(t, readerCtx(t), wf, pc, groups)
	if err != nil {
		t.Fatalf("a NotFound entry must not fail the query: %v", err)
	}
	if len(out) != 1 || out[0].RunID != "run-o" {
		t.Fatalf("got %+v, want only the entry core knows", out)
	}
}

func TestDecidedApprovalsResolver_AnotherCoreErrorFailsTheQuery(t *testing.T) {
	wf := decidedWorkflow(
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-1", RunId: "run-o", Decision: "approved"},
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-2", RunId: "run-2", Decision: "approved"},
	)
	core, groups := decidedCore()
	pc := &countedVersions{coreLikeVersions: core, failIDs: map[string]bool{"pv-open-2": true}}
	got, gerr := decide(t, readerCtx(t), wf, pc, groups)
	if gerr == nil || got != nil {
		t.Fatalf("got %+v, %v; want an error and no list", got, gerr)
	}
	if status.Code(gerr) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable carried through", status.Code(gerr))
	}
}

func TestDecidedApprovalsResolver_WorkflowErrorFailsTheQuery(t *testing.T) {
	wf := &fakeWorkflowClient{decidedErr: status.Error(codes.Unavailable, "workflow down")}
	pc, groups := decidedCore()
	out, err := decide(t, readerCtx(t), wf, pc, groups)
	if err == nil || out != nil {
		t.Fatalf("got %+v, %v; want an error", out, err)
	}
}

func TestDecidedApprovalsResolver_AsksCoreOncePerVersionAndPolicy(t *testing.T) {
	wf := decidedWorkflow(
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-1", RunId: "run-a", Decision: "approved"},
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-2", RunId: "run-b", Decision: "rejected"},
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-1", RunId: "run-c", Decision: "approved"},
	)
	core, groups := decidedCore()
	pc := &countedVersions{coreLikeVersions: core}
	out, err := decide(t, readerCtx(t), wf, pc, groups)
	if err != nil || len(out) != 3 {
		t.Fatalf("got %d entries, %v; want 3", len(out), err)
	}
	if n := pc.reads; n != 2 {
		t.Fatalf("GetPolicyVersion calls = %d, want 2 (one per distinct version)", n)
	}
}

func TestDecidedApprovalsResolver_UnauthenticatedIsRefused(t *testing.T) {
	wf := decidedWorkflow(&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-1", RunId: "run-o", Decision: "approved"})
	pc, groups := decidedCore()
	out, err := decide(t, context.Background(), wf, pc, groups)
	if err == nil || out != nil {
		t.Fatalf("got %+v, %v; want unauthenticated", out, err)
	}
	if wf.decidedCalls != 0 {
		t.Fatalf("workflow asked %d times for an unauthenticated caller", wf.decidedCalls)
	}
}

// secondReadFails is core answering GetPolicy normally the first time a policy
// is read and with err every time after, the way a core outage between the
// resolver's own read and the read decision's read looks.
type secondReadFails struct {
	coreLikeVersions
	err   error
	reads map[string]int
}

func (f *secondReadFails) GetPolicy(ctx context.Context, in *corev1.GetPolicyRequest, opts ...grpc.CallOption) (*corev1.GetPolicyResponse, error) {
	if f.reads == nil {
		f.reads = map[string]int{}
	}
	f.reads[in.GetId()]++
	if f.reads[in.GetId()] > 1 {
		return nil, f.err
	}
	return f.coreLikeVersions.GetPolicy(ctx, in, opts...)
}

func TestDecidedApprovalsResolver_AFailingPolicyReadDuringTheDecisionFailsTheQuery(t *testing.T) {
	for _, code := range []codes.Code{codes.Internal, codes.Unavailable} {
		t.Run(code.String(), func(t *testing.T) {
			wf := decidedWorkflow(
				&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-1", RunId: "run-o", Decision: "approved"},
			)
			core, groups := decidedCore()
			pc := &secondReadFails{coreLikeVersions: core, err: status.Error(code, "core down")}
			got, err := decide(t, readerCtx(t), wf, pc, groups)
			if err == nil || got != nil {
				t.Fatalf("got %+v, %v; want an error and no list", got, err)
			}
			if status.Code(err) != code {
				t.Fatalf("code = %v, want %v carried through", status.Code(err), code)
			}
		})
	}
}

func TestDecidedApprovalsResolver_APolicyGoneDuringTheDecisionDropsTheEntry(t *testing.T) {
	wf := decidedWorkflow(
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-1", RunId: "run-o", Decision: "approved"},
	)
	core, groups := decidedCore()
	pc := &secondReadFails{coreLikeVersions: core, err: status.Error(codes.NotFound, "policy not found")}
	got, err := decide(t, readerCtx(t), wf, pc, groups)
	if err != nil {
		t.Fatalf("a NotFound policy must not fail the query: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want the entry dropped", got)
	}
}

func TestDecidedApprovalsResolver_ARealReadDenyStillDropsTheEntryWithoutFailing(t *testing.T) {
	wf := decidedWorkflow(
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-hidden-1", RunId: "run-h", Decision: "approved"},
		&workflowv1.DecidedApproval{PolicyVersionId: "pv-open-1", RunId: "run-o", Decision: "approved"},
	)
	core, groups := decidedCore()
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", RolesValue: []string{"reader"}, IdpGroupsValue: []string{"Admins"}})
	got, err := decide(t, ctx, wf, core, groups)
	if err != nil {
		t.Fatalf("a read deny must not fail the query: %v", err)
	}
	if len(got) != 1 || got[0].RunID != "run-o" {
		t.Fatalf("got %+v, want only the readable policy's entry", got)
	}
}
