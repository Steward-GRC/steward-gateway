// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	deliveryv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/delivery/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// countingDeliveryClient counts the content calls, so a test can tell whether
// delivery was asked at all.
type countingDeliveryClient struct {
	*fakeDeliveryClient
	calls int
}

func (c *countingDeliveryClient) GetRenderedContent(ctx context.Context, in *deliveryv1.GetRenderedContentRequest, opts ...grpc.CallOption) (*deliveryv1.GetRenderedContentResponse, error) {
	c.calls++
	return c.fakeDeliveryClient.GetRenderedContent(ctx, in, opts...)
}

func (c *countingDeliveryClient) GetDiff(ctx context.Context, in *deliveryv1.GetDiffRequest, opts ...grpc.CallOption) (*deliveryv1.GetDiffResponse, error) {
	c.calls++
	return c.fakeDeliveryClient.GetDiff(ctx, in, opts...)
}

func (c *countingDeliveryClient) RequestPDFExport(ctx context.Context, in *deliveryv1.RequestPDFExportRequest, opts ...grpc.CallOption) (*deliveryv1.RequestPDFExportResponse, error) {
	c.calls++
	return c.fakeDeliveryClient.RequestPDFExport(ctx, in, opts...)
}

func contentDelivery() *countingDeliveryClient {
	return &countingDeliveryClient{fakeDeliveryClient: &fakeDeliveryClient{
		renderedResp:   &deliveryv1.GetRenderedContentResponse{Html: "<p>the secret clause</p>"},
		diffResp:       &deliveryv1.GetDiffResponse{Sections: []*deliveryv1.SectionDiff{{SectionKey: "scope", ChangeType: "modified", DiffHtml: "<ins>the secret clause</ins>"}}},
		requestPDFResp: &deliveryv1.RequestPDFExportResponse{JobId: "job-1"},
	}}
}

func contentAI() *fakeAIClient {
	return &fakeAIClient{policySummaryResp: &aiv1.GetPolicySummaryResponse{Found: true, SummaryText: "the secret clause"}}
}

// readCase is one content resolver driven through the read decision: serve
// reports whether real content came back.
type readCase struct {
	name string
	run  func(ctx context.Context, pc *diffingPolicyClient, groups corev1.CategoryServiceClient, admin *fakeBreakGlassAdmin, d *countingDeliveryClient, ai *fakeAIClient) (served bool, err error)
}

func contentReadCases() []readCase {
	return []readCase{
		{"renderedContent", func(ctx context.Context, pc *diffingPolicyClient, groups corev1.CategoryServiceClient, admin *fakeBreakGlassAdmin, d *countingDeliveryClient, _ *fakeAIClient) (bool, error) {
			rc, err := resolvers.GetRenderedContent(ctx, d, pc, groups, admin, "pol-1-v1")
			return rc != nil && rc.HTML != "", err
		}},
		{"policyDiff", func(ctx context.Context, pc *diffingPolicyClient, groups corev1.CategoryServiceClient, admin *fakeBreakGlassAdmin, d *countingDeliveryClient, _ *fakeAIClient) (bool, error) {
			pd, err := resolvers.GetPolicyDiff(ctx, d, pc, groups, admin, "pol-1-v1", "pol-1-v2")
			return pd != nil && len(pd.Sections) == 1 && pd.Sections[0].WordDiffHTML != nil, err
		}},
		{"requestPDFExport", func(ctx context.Context, pc *diffingPolicyClient, groups corev1.CategoryServiceClient, admin *fakeBreakGlassAdmin, d *countingDeliveryClient, _ *fakeAIClient) (bool, error) {
			job, err := resolvers.RequestPDFExport(ctx, d, pc, groups, admin, "pol-1-v1")
			return job != nil, err
		}},
		{"policyVersionSummary", func(ctx context.Context, pc *diffingPolicyClient, groups corev1.CategoryServiceClient, admin *fakeBreakGlassAdmin, _ *countingDeliveryClient, ai *fakeAIClient) (bool, error) {
			s, err := resolvers.PolicyVersionSummaryResolver(ctx, ai, pc, groups, admin, "pol-1-v1")
			return s != nil && s.SummaryText != "", err
		}},
	}
}

// backendCalls is how often the content backend behind the case was asked.
func backendCalls(c readCase, d *countingDeliveryClient, ai *fakeAIClient) int {
	if c.name == "policyVersionSummary" {
		if ai.lastPolicySummaryReq == nil {
			return 0
		}
		return 1
	}
	return d.calls
}

func TestContentReadsDeniedReaderGetsNothingAndTheBackendIsNotAsked(t *testing.T) {
	for _, c := range contentReadCases() {
		t.Run(c.name, func(t *testing.T) {
			pc, groups, _ := diffSetup(t, true)
			ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", IdpGroupsValue: []string{"Admins"}})
			d, ai := contentDelivery(), contentAI()

			served, err := c.run(ctx, pc, groups, noGrant(), d, ai)
			if served {
				t.Fatalf("served content to a denied reader (err %v)", err)
			}
			if c.name != "policyVersionSummary" && status.Code(err) != codes.NotFound {
				t.Fatalf("err = %v, want NotFound", err)
			}
			if n := backendCalls(c, d, ai); n != 0 {
				t.Fatalf("backend called %d times, want 0", n)
			}
		})
	}
}

func TestContentReadsDraftIsForEditorsOnly(t *testing.T) {
	for _, c := range contentReadCases() {
		t.Run(c.name, func(t *testing.T) {
			pc, groups, _ := diffSetup(t, false)
			pc.versions["pol-1-v1"].Status = corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT
			ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1"})
			d, ai := contentDelivery(), contentAI()

			if served, err := c.run(ctx, pc, groups, noGrant(), d, ai); served {
				t.Fatalf("served a draft to a reader (err %v)", err)
			}
			if n := backendCalls(c, d, ai); n != 0 {
				t.Fatalf("backend called %d times, want 0", n)
			}
		})
	}
}

func TestContentReadsAllowedReaderIsServedUnrecorded(t *testing.T) {
	for _, c := range contentReadCases() {
		t.Run(c.name, func(t *testing.T) {
			pc, groups, ctx := diffSetup(t, false)

			served, err := c.run(ctx, pc, groups, grant(), contentDelivery(), contentAI())
			if err != nil || !served {
				t.Fatalf("served = %v, err = %v; want the content", served, err)
			}
			if len(pc.recorded) != 0 {
				t.Fatalf("recorded = %v, want none: the rules already allow this read", pc.recorded)
			}
		})
	}
}

func TestContentReadsObfuscatedReaderGetsNoRealContent(t *testing.T) {
	for _, c := range contentReadCases() {
		t.Run(c.name, func(t *testing.T) {
			pc, groups, ctx := diffSetup(t, true)

			if served, err := c.run(ctx, pc, groups, noGrant(), contentDelivery(), contentAI()); served {
				t.Fatalf("served real content to an obfuscated reader (err %v)", err)
			}
			if len(pc.recorded) != 0 {
				t.Fatalf("recorded = %v, want none without a grant", pc.recorded)
			}
		})
	}
}

func TestContentReadsGrantOnlyReadIsRecordedFirst(t *testing.T) {
	for _, c := range contentReadCases() {
		t.Run(c.name, func(t *testing.T) {
			pc, groups, ctx := diffSetup(t, true)

			served, err := c.run(ctx, pc, groups, grant(), contentDelivery(), contentAI())
			if err != nil || !served {
				t.Fatalf("served = %v, err = %v; want the content under the grant", served, err)
			}
			if len(pc.recorded) == 0 || pc.recorded[0].GetPolicyVersionId() != "pol-1-v1" {
				t.Fatalf("recorded = %v, want the read recorded", pc.recorded)
			}
		})
	}
}

func TestContentReadsServeNothingWhenTheReadIsNotRecorded(t *testing.T) {
	for _, c := range contentReadCases() {
		t.Run(c.name, func(t *testing.T) {
			pc, groups, ctx := diffSetup(t, true)
			pc.recordErr = status.Error(codes.Unavailable, "audit down")
			d, ai := contentDelivery(), contentAI()

			if served, err := c.run(ctx, pc, groups, grant(), d, ai); served {
				t.Fatalf("served unrecorded content (err %v)", err)
			}
			if n := backendCalls(c, d, ai); n != 0 {
				t.Fatalf("backend called %d times, want 0 on an unrecorded read", n)
			}
		})
	}
}

// openVersions is a policy fake whose versions pv-1 and pv-2 everyone may read,
// for tests about what a content resolver does once the read is allowed.
func openVersions(t *testing.T) (*recordingPolicyClient, corev1.CategoryServiceClient, *fakeBreakGlassAdmin) {
	t.Helper()
	pc, groups, _ := breakGlassReadSetup(t, false)
	for _, id := range []string{"pv-1", "pv-2"} {
		pc.versions[id] = &corev1.PolicyVersion{Id: id, PolicyId: "pol-1", Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED}
	}
	return pc, groups, noGrant()
}
