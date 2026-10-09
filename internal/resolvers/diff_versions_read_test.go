// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// diffingPolicyClient adds DiffVersions to the break-glass recording fake and
// counts the calls, so a test can tell whether core was asked at all.
type diffingPolicyClient struct {
	*recordingPolicyClient
	diffCalls int
}

func (d *diffingPolicyClient) DiffVersions(_ context.Context, _ *corev1.DiffVersionsRequest, _ ...grpc.CallOption) (*corev1.DiffVersionsResponse, error) {
	d.diffCalls++
	return &corev1.DiffVersionsResponse{Diffs: []*corev1.SectionDiff{{
		SectionKey:   "scope",
		SectionTitle: "Scope",
		ChangeType:   "modified",
		WordDiffHtml: "<ins>the secret clause</ins>",
	}}}, nil
}

func diffSetup(t *testing.T, denySiteAdmin bool) (*diffingPolicyClient, corev1.CategoryServiceClient, context.Context) {
	t.Helper()
	pc, groups, ctx := breakGlassReadSetup(t, denySiteAdmin)
	pc.versions["pol-1-v2"] = &corev1.PolicyVersion{Id: "pol-1-v2", PolicyId: "pol-1", VersionNo: 2, Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED, ContentJson: breakGlassSecret}
	return &diffingPolicyClient{recordingPolicyClient: pc}, groups, ctx
}

func noGrant() *fakeBreakGlassAdmin {
	return &fakeBreakGlassAdmin{activeResp: &identityv1.ActiveBreakGlassResponse{}}
}

func TestDiffVersionsDeniedReaderGetsNotFoundAndCoreIsNotAsked(t *testing.T) {
	pc, groups, _ := diffSetup(t, true)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", IdpGroupsValue: []string{"Admins"}})

	diffs, err := resolvers.DiffVersions(ctx, pc, groups, noGrant(), "pol-1-v1", "pol-1-v2")
	if status.Code(err) != codes.NotFound || diffs != nil {
		t.Fatalf("got %v, %v; want NotFound and no diff", diffs, err)
	}
	if pc.diffCalls != 0 {
		t.Fatalf("core DiffVersions called %d times, want 0 for a denied read", pc.diffCalls)
	}
}

func TestDiffVersionsUnknownVersionServesNothing(t *testing.T) {
	pc, groups, ctx := diffSetup(t, false)

	if diffs, err := resolvers.DiffVersions(ctx, pc, groups, noGrant(), "pol-1-v1", "missing"); err == nil || diffs != nil {
		t.Fatalf("got %v, %v; want the lookup error and no diff", diffs, err)
	}
	if pc.diffCalls != 0 {
		t.Fatalf("core DiffVersions called %d times, want 0", pc.diffCalls)
	}
}

func TestDiffVersionsDraftIsForEditorsOnly(t *testing.T) {
	pc, groups, _ := diffSetup(t, false)
	pc.versions["pol-1-v2"].Status = corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1"})

	if _, err := resolvers.DiffVersions(ctx, pc, groups, noGrant(), "pol-1-v1", "pol-1-v2"); status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound for a reader diffing a draft", err)
	}
	if pc.diffCalls != 0 {
		t.Fatalf("core DiffVersions called %d times, want 0", pc.diffCalls)
	}
}

func TestDiffVersionsAllowedReaderGetsTheDiffUnrecorded(t *testing.T) {
	pc, groups, ctx := diffSetup(t, false)

	diffs, err := resolvers.DiffVersions(ctx, pc, groups, grant(), "pol-1-v1", "pol-1-v2")
	if err != nil {
		t.Fatalf("DiffVersions: %v", err)
	}
	if len(diffs) != 1 || diffs[0].WordDiffHTML == nil || *diffs[0].WordDiffHTML != "<ins>the secret clause</ins>" {
		t.Fatalf("diffs = %+v, want the real word diff", diffs)
	}
	if len(pc.recorded) != 0 {
		t.Fatalf("recorded = %v, want none: the rules already allow this read", pc.recorded)
	}
}

func TestDiffVersionsObfuscatedReaderGetsNoContent(t *testing.T) {
	pc, groups, ctx := diffSetup(t, true)

	diffs, err := resolvers.DiffVersions(ctx, pc, groups, noGrant(), "pol-1-v1", "pol-1-v2")
	if err != nil {
		t.Fatalf("DiffVersions: %v", err)
	}
	if len(diffs) != 1 || diffs[0].WordDiffHTML != nil {
		t.Fatalf("diffs = %+v, want the section without its word diff", diffs)
	}
	if diffs[0].SectionTitle == "Scope" || strings.Contains(diffs[0].SectionTitle, "Scope") {
		t.Fatalf("section title = %q, want it obfuscated", diffs[0].SectionTitle)
	}
	if len(pc.recorded) != 0 {
		t.Fatalf("recorded = %v, want none without a grant", pc.recorded)
	}
}

func TestDiffVersionsGrantOnlyReadRecordsBothVersions(t *testing.T) {
	pc, groups, ctx := diffSetup(t, true)

	diffs, err := resolvers.DiffVersions(ctx, pc, groups, grant(), "pol-1-v1", "pol-1-v2")
	if err != nil {
		t.Fatalf("DiffVersions: %v", err)
	}
	if len(diffs) != 1 || diffs[0].WordDiffHTML == nil {
		t.Fatalf("diffs = %+v, want the real diff under the grant", diffs)
	}
	if len(pc.recorded) != 2 || pc.recorded[0].GetPolicyVersionId() != "pol-1-v1" || pc.recorded[1].GetPolicyVersionId() != "pol-1-v2" {
		t.Fatalf("recorded = %v, want one record per version", pc.recorded)
	}
}

func TestDiffVersionsServesNothingWhenTheReadIsNotRecorded(t *testing.T) {
	pc, groups, ctx := diffSetup(t, true)
	pc.recordErr = status.Error(codes.Unavailable, "audit down")

	diffs, err := resolvers.DiffVersions(ctx, pc, groups, grant(), "pol-1-v1", "pol-1-v2")
	if status.Code(err) != codes.Unavailable || diffs != nil {
		t.Fatalf("got %v, %v; want Unavailable and no diff", diffs, err)
	}
	if pc.diffCalls != 0 {
		t.Fatalf("core DiffVersions called %d times, want 0 on an unrecorded read", pc.diffCalls)
	}
}
