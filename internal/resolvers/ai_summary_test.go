// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// summaryInput decodes the input_json a SUMMARIZE job was submitted with.
func summaryInput(t *testing.T, req *aiv1.SubmitAIJobRequest) map[string]any {
	t.Helper()
	var in map[string]any
	if err := json.Unmarshal([]byte(req.GetInputJson()), &in); err != nil {
		t.Fatalf("input_json is not JSON: %v", err)
	}
	return in
}

func TestSummarizeChangesSubmitsASummarizeJobWithTheDiff(t *testing.T) {
	pc, groups, ctx := diffSetup(t, false)
	ai := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "job-1"}}

	res, err := resolvers.SummarizeChangesResolver(ctx, ai, pc, groups, noGrant(), nil, "pol-1-v1", "pol-1-v2", nil)
	if err != nil {
		t.Fatalf("SummarizeChanges: %v", err)
	}
	if res.JobID != "job-1" {
		t.Fatalf("jobId = %q, want job-1", res.JobID)
	}
	req := ai.lastSubmitReq
	if req.GetOperation() != aiv1.JobOperation_JOB_OPERATION_SUMMARIZE {
		t.Fatalf("operation = %v, want SUMMARIZE", req.GetOperation())
	}
	if req.GetPolicyId() != "pol-1" || req.GetVersionId() != "pol-1-v2" {
		t.Fatalf("policy/version = %q/%q", req.GetPolicyId(), req.GetVersionId())
	}
	if req.GetScope() == nil {
		t.Fatal("read scope not derived")
	}
	in := summaryInput(t, req)
	if in["scope"] != "changes" || in["fromVersionId"] != "pol-1-v1" || in["toVersionId"] != "pol-1-v2" {
		t.Fatalf("input = %v", in)
	}
	if d, _ := in["diff"].(string); !strings.Contains(d, "+ the secret clause") || !strings.Contains(d, "Scope") {
		t.Fatalf("diff = %q, want the added text under its section", in["diff"])
	}
	if _, set := in["regenerate"]; set {
		t.Fatalf("regenerate should be omitted by default: %v", in)
	}
}

func TestSummarizeChangesRegenerateIsForwarded(t *testing.T) {
	pc, groups, ctx := diffSetup(t, false)
	ai := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "job-1"}}
	yes := true

	if _, err := resolvers.SummarizeChangesResolver(ctx, ai, pc, groups, noGrant(), nil, "pol-1-v1", "pol-1-v2", &yes); err != nil {
		t.Fatalf("SummarizeChanges: %v", err)
	}
	if in := summaryInput(t, ai.lastSubmitReq); in["regenerate"] != true {
		t.Fatalf("input = %v, want regenerate true", in)
	}
}

func TestSummarizeChangesDeniedReaderSubmitsNothing(t *testing.T) {
	pc, groups, _ := diffSetup(t, true)
	ctx := ctxWithUser(t, "u-1")
	ai := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "job-1"}}

	_, err := resolvers.SummarizeChangesResolver(ctx, ai, pc, groups, noGrant(), nil, "pol-1-v1", "missing", nil)
	if err == nil {
		t.Fatal("expected the unreadable version to be refused")
	}
	if ai.lastSubmitReq != nil || pc.diffCalls != 0 {
		t.Fatal("nothing may be diffed or submitted for a refused read")
	}
}

func TestSummarizeChangesNeverSummarisesObfuscatedContent(t *testing.T) {
	pc, groups, ctx := diffSetup(t, true)
	ai := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "job-1"}}

	_, err := resolvers.SummarizeChangesResolver(ctx, ai, pc, groups, noGrant(), nil, "pol-1-v1", "pol-1-v2", nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if ai.lastSubmitReq != nil || pc.diffCalls != 0 {
		t.Fatal("an obfuscated read must not reach the diff or the AI service")
	}
}

func TestSummarizeChangesUnauthenticated(t *testing.T) {
	pc, groups, _ := diffSetup(t, false)
	ai := &fakeAIClient{}
	if _, err := resolvers.SummarizeChangesResolver(context.Background(), ai, pc, groups, noGrant(), nil, "pol-1-v1", "pol-1-v2", nil); err == nil {
		t.Fatal("expected unauthenticated error")
	}
}

func TestSummarizeChangesAIUnavailableFailsCleanly(t *testing.T) {
	pc, groups, ctx := diffSetup(t, false)
	ai := &fakeAIClient{submitErr: status.Error(codes.Unavailable, "ai down")}

	res, err := resolvers.SummarizeChangesResolver(ctx, ai, pc, groups, noGrant(), nil, "pol-1-v1", "pol-1-v2", nil)
	if err == nil || res != nil {
		t.Fatalf("got %v, %v; want an error and no job", res, err)
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want the AI status passed through", status.Code(err))
	}
}

func TestSummarizeChangesNoChangesIsRefused(t *testing.T) {
	pc, groups, ctx := diffSetup(t, false)
	pc.noDiffs = true
	ai := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "job-1"}}

	_, err := resolvers.SummarizeChangesResolver(ctx, ai, pc, groups, noGrant(), nil, "pol-1-v1", "pol-1-v2", nil)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if ai.lastSubmitReq != nil {
		t.Fatal("no job for versions with no differences")
	}
}

func TestRegenerateVersionSummarySubmitsAVersionScopeJob(t *testing.T) {
	pc, groups, ctx := diffSetup(t, false)
	pc.versions["pol-1-v2"].ContentJson = `{"root":{"type":"root","children":[{"type":"paragraph","children":[{"type":"text","text":"Keep devices locked."}]},{"type":"paragraph","children":[{"type":"text","text":"Report loss."}]}]}}`
	ai := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "job-2"}}

	res, err := resolvers.RegenerateVersionSummaryResolver(ctx, ai, pc, groups, noGrant(), nil, "pol-1-v2")
	if err != nil {
		t.Fatalf("RegenerateVersionSummary: %v", err)
	}
	if res.JobID != "job-2" {
		t.Fatalf("jobId = %q", res.JobID)
	}
	req := ai.lastSubmitReq
	if req.GetOperation() != aiv1.JobOperation_JOB_OPERATION_SUMMARIZE || req.GetPolicyId() != "pol-1" || req.GetVersionId() != "pol-1-v2" {
		t.Fatalf("request = %v", req)
	}
	in := summaryInput(t, req)
	if in["scope"] != "version" || in["versionId"] != "pol-1-v2" || in["policyId"] != "pol-1" || in["policyTitle"] != "Sec" || in["regenerate"] != true {
		t.Fatalf("input = %v", in)
	}
	if txt, _ := in["text"].(string); !strings.Contains(txt, "Keep devices locked.") || !strings.Contains(txt, "Report loss.") {
		t.Fatalf("text = %q, want the version's plain text", txt)
	}
}

func TestRegenerateVersionSummaryRefusals(t *testing.T) {
	t.Run("obfuscated", func(t *testing.T) {
		pc, groups, ctx := diffSetup(t, true)
		ai := &fakeAIClient{}
		_, err := resolvers.RegenerateVersionSummaryResolver(ctx, ai, pc, groups, noGrant(), nil, "pol-1-v2")
		if status.Code(err) != codes.PermissionDenied || ai.lastSubmitReq != nil {
			t.Fatalf("err = %v, submitted = %v; want PermissionDenied and no job", err, ai.lastSubmitReq)
		}
	})
	t.Run("unreadable draft", func(t *testing.T) {
		pc, groups, _ := diffSetup(t, false)
		pc.versions["pol-1-v2"].Status = corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT
		ctx := ctxWithUser(t, "u-1")
		ai := &fakeAIClient{}
		_, err := resolvers.RegenerateVersionSummaryResolver(ctx, ai, pc, groups, noGrant(), nil, "pol-1-v2")
		if status.Code(err) != codes.NotFound || ai.lastSubmitReq != nil {
			t.Fatalf("err = %v, want NotFound and no job", err)
		}
	})
	t.Run("unauthenticated", func(t *testing.T) {
		pc, groups, _ := diffSetup(t, false)
		if _, err := resolvers.RegenerateVersionSummaryResolver(context.Background(), &fakeAIClient{}, pc, groups, noGrant(), nil, "pol-1-v2"); err == nil {
			t.Fatal("expected unauthenticated error")
		}
	})
	t.Run("ai unavailable", func(t *testing.T) {
		pc, groups, ctx := diffSetup(t, false)
		ai := &fakeAIClient{submitErr: status.Error(codes.Unavailable, "ai down")}
		res, err := resolvers.RegenerateVersionSummaryResolver(ctx, ai, pc, groups, noGrant(), nil, "pol-1-v2")
		if err == nil || res != nil || status.Code(err) != codes.Unavailable {
			t.Fatalf("got %v, %v; want Unavailable and no job", res, err)
		}
	})
}
