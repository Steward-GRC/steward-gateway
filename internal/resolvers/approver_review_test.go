// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// A pending approver gets the full review of the draft they hold a seat on:
// the diff against the published version, the rendered content, the PDF
// export and the AI summary. The fixture is draftPointerEnv, as in
// approver_read_test.go.

// reviewPolicyClient adds core's DiffVersions to draftPointerEnv's policy
// fake and counts the calls.
type reviewPolicyClient struct {
	*fakePolicyClient
	diffCalls int
}

func (r *reviewPolicyClient) DiffVersions(_ context.Context, _ *corev1.DiffVersionsRequest, _ ...grpc.CallOption) (*corev1.DiffVersionsResponse, error) {
	r.diffCalls++
	return &corev1.DiffVersionsResponse{Diffs: []*corev1.SectionDiff{{
		SectionKey:   "scope",
		SectionTitle: "Scope",
		ChangeType:   "modified",
		WordDiffHtml: "<ins>the secret clause</ins>",
	}}}, nil
}

func reviewEnv(extra []*corev1.CategoryRule) (*reviewPolicyClient, corev1.CategoryServiceClient) {
	pc, gc := draftPointerEnv(extra)
	return &reviewPolicyClient{fakePolicyClient: pc}, gc
}

// reviewCase is one review path on draft-1; served reports whether the real
// content came back.
type reviewCase struct {
	name string
	run  func(ctx context.Context, pc *reviewPolicyClient, gc corev1.CategoryServiceClient, wf *seatWorkflow, d *countingDeliveryClient, ai *fakeAIClient) (served bool, err error)
}

func reviewCases() []reviewCase {
	return []reviewCase{
		{"diffVersions", func(ctx context.Context, pc *reviewPolicyClient, gc corev1.CategoryServiceClient, wf *seatWorkflow, _ *countingDeliveryClient, _ *fakeAIClient) (bool, error) {
			diffs, err := resolvers.DiffVersions(ctx, pc, gc, nil, wf, "pub-1", "draft-1")
			return len(diffs) == 1 && diffs[0].WordDiffHTML != nil, err
		}},
		{"policyDiff", func(ctx context.Context, pc *reviewPolicyClient, gc corev1.CategoryServiceClient, wf *seatWorkflow, d *countingDeliveryClient, _ *fakeAIClient) (bool, error) {
			pd, err := resolvers.GetPolicyDiff(ctx, d, pc, gc, nil, wf, "pub-1", "draft-1")
			return pd != nil && len(pd.Sections) == 1 && pd.Sections[0].WordDiffHTML != nil, err
		}},
		{"renderedContent", func(ctx context.Context, pc *reviewPolicyClient, gc corev1.CategoryServiceClient, wf *seatWorkflow, d *countingDeliveryClient, _ *fakeAIClient) (bool, error) {
			rc, err := resolvers.GetRenderedContent(ctx, d, pc, gc, nil, wf, "draft-1")
			return rc != nil && rc.HTML != "", err
		}},
		{"requestPDFExport", func(ctx context.Context, pc *reviewPolicyClient, gc corev1.CategoryServiceClient, wf *seatWorkflow, d *countingDeliveryClient, _ *fakeAIClient) (bool, error) {
			job, err := resolvers.RequestPDFExport(ctx, d, pc, gc, nil, wf, &fakeAuditSink{}, "draft-1")
			return job != nil, err
		}},
		{"policyVersionSummary", func(ctx context.Context, pc *reviewPolicyClient, gc corev1.CategoryServiceClient, wf *seatWorkflow, _ *countingDeliveryClient, ai *fakeAIClient) (bool, error) {
			s, err := resolvers.PolicyVersionSummaryResolver(ctx, ai, pc, gc, nil, wf, "draft-1")
			return s != nil && s.SummaryText != "", err
		}},
	}
}

// reviewBackendCalls is how often the content backend behind the case was
// asked.
func reviewBackendCalls(c reviewCase, pc *reviewPolicyClient, d *countingDeliveryClient, ai *fakeAIClient) int {
	switch c.name {
	case "diffVersions":
		return pc.diffCalls
	case "policyVersionSummary":
		if ai.lastPolicySummaryReq == nil {
			return 0
		}
		return 1
	}
	return d.calls
}

// assertReviewRefused checks every review path refuses the caller as it did
// before the seat rule: NotFound (no summary for policyVersionSummary), with
// no backend asked.
func assertReviewRefused(t *testing.T, ctx context.Context, wf func() *seatWorkflow, extra []*corev1.CategoryRule, sensitive bool) {
	t.Helper()
	for _, c := range reviewCases() {
		t.Run(c.name, func(t *testing.T) {
			pc, gc := reviewEnv(extra)
			if sensitive {
				pc.policies["pol"].Sensitivity = corev1.Sensitivity_SENSITIVITY_SENSITIVE
			}
			d, ai := contentDelivery(), contentAI()

			served, err := c.run(ctx, pc, gc, wf(), d, ai)
			if served {
				t.Fatalf("served the draft (err %v), want it refused", err)
			}
			if c.name == "policyVersionSummary" {
				if err != nil {
					t.Fatalf("err = %v, want no summary and no error", err)
				}
			} else if status.Code(err) != codes.NotFound {
				t.Fatalf("err = %v, want NotFound", err)
			}
			if n := reviewBackendCalls(c, pc, d, ai); n != 0 {
				t.Fatalf("backend called %d times, want 0 for a refused read", n)
			}
		})
	}
}

func TestApproverWithPendingSeat_GetsTheFullReview(t *testing.T) {
	for _, c := range reviewCases() {
		t.Run(c.name, func(t *testing.T) {
			pc, gc := reviewEnv(nil)
			wf, d, ai := seatsOn("draft-1"), contentDelivery(), contentAI()

			served, err := c.run(approverCtx(t), pc, gc, wf, d, ai)
			if err != nil || !served {
				t.Fatalf("served = %v, err = %v; want the real content for the pending approver", served, err)
			}
			if n := reviewBackendCalls(c, pc, d, ai); n != 1 {
				t.Fatalf("backend called %d times, want 1", n)
			}
			if wf.pendingCalls != 1 || wf.lastPending.GetApproverUserId() != approverID {
				t.Fatalf("ListPendingTasks calls = %d for %q, want one for %s", wf.pendingCalls, wf.lastPending.GetApproverUserId(), approverID)
			}
		})
	}
}

func TestApproverAfterDeciding_LosesTheReview(t *testing.T) {
	assertReviewRefused(t, approverCtx(t), func() *seatWorkflow { return seatsOn() }, nil, false)
}

func TestApproverOnAnotherVersion_GetsNoReview(t *testing.T) {
	assertReviewRefused(t, approverCtx(t), func() *seatWorkflow { return seatsOn("other-draft") }, nil, false)
}

func TestApproverSeatLookupFailure_GetsNoReview(t *testing.T) {
	assertReviewRefused(t, approverCtx(t), func() *seatWorkflow {
		wf := seatsOn("draft-1")
		wf.pendingResp, wf.pendingErr = nil, errors.New("workflow unavailable")
		return wf
	}, nil, false)
}

func TestApproverReviewOfASensitiveDraft_NeedsClearance(t *testing.T) {
	t.Run("without clearance", func(t *testing.T) {
		assertReviewRefused(t, approverCtx(t), func() *seatWorkflow { return seatsOn("draft-1") }, nil, true)
	})
	t.Run("with clearance", func(t *testing.T) {
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: approverID, RolesValue: []string{"reader"}, ReadSensitiveValue: true})
		for _, c := range reviewCases() {
			t.Run(c.name, func(t *testing.T) {
				pc, gc := reviewEnv(nil)
				pc.policies["pol"].Sensitivity = corev1.Sensitivity_SENSITIVITY_SENSITIVE
				if served, err := c.run(ctx, pc, gc, seatsOn("draft-1"), contentDelivery(), contentAI()); err != nil || !served {
					t.Fatalf("served = %v, err = %v; want the draft for a cleared pending approver", served, err)
				}
			})
		}
	})
}

// Editors keep the review as before and never cost a seat lookup.
func TestApproverReviewRule_LeavesEditorsUnchanged(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "editor-u", RolesValue: []string{"reader"}})
	for _, c := range reviewCases() {
		t.Run(c.name, func(t *testing.T) {
			pc, gc := reviewEnv([]*corev1.CategoryRule{authorRule("editor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
			wf, d, ai := seatsOn(), contentDelivery(), contentAI()

			if served, err := c.run(ctx, pc, gc, wf, d, ai); err != nil || !served {
				t.Fatalf("served = %v, err = %v; want the draft for the editor", served, err)
			}
			if wf.pendingCalls != 0 {
				t.Fatalf("ListPendingTasks calls = %d, want 0 for an editor", wf.pendingCalls)
			}
		})
	}
}

// Magic links were not part of the decision: a pending approver still gets
// none for the draft.
func TestApproverWithPendingSeat_GetsNoMagicLink(t *testing.T) {
	pc, gc := reviewEnv(nil)
	d := contentDelivery()
	link, err := resolvers.CreateMagicLinkResolver(approverCtx(t), d, pc, gc, nil, "draft-1", false)
	if link != nil || status.Code(err) != codes.NotFound {
		t.Fatalf("createMagicLink(draft-1) = %+v, %v; want NotFound", link, err)
	}
	if d.calls != 0 {
		t.Fatalf("delivery called %d times, want 0", d.calls)
	}
}
