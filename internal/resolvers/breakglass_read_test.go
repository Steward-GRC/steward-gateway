// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
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

const breakGlassSecret = `{"root":{"children":[{"type":"text","text":"the secret clause"}]}}`

// recordingPolicyClient adds RecordBreakGlassRead and ListPolicyVersions to the
// shared policy fake.
type recordingPolicyClient struct {
	*fakePolicyClient
	recorded  []*corev1.RecordBreakGlassReadRequest
	recordErr error
}

func (r *recordingPolicyClient) RecordBreakGlassRead(_ context.Context, in *corev1.RecordBreakGlassReadRequest, _ ...grpc.CallOption) (*corev1.RecordBreakGlassReadResponse, error) {
	r.recorded = append(r.recorded, in)
	if r.recordErr != nil {
		return nil, r.recordErr
	}
	return &corev1.RecordBreakGlassReadResponse{}, nil
}

func (r *recordingPolicyClient) ListPolicyVersions(_ context.Context, in *corev1.ListPolicyVersionsRequest, _ ...grpc.CallOption) (*corev1.ListPolicyVersionsResponse, error) {
	var out []*corev1.PolicyVersion
	for _, v := range r.versions {
		if v.GetPolicyId() == in.GetPolicyId() {
			out = append(out, v)
		}
	}
	return &corev1.ListPolicyVersionsResponse{Versions: out}, nil
}

func breakGlassReadSetup(t *testing.T, denySiteAdmin bool) (*recordingPolicyClient, corev1.CategoryServiceClient, context.Context) {
	t.Helper()
	rules := []*corev1.CategoryRule{allowEveryoneRule()}
	if denySiteAdmin {
		rules = []*corev1.CategoryRule{denyGroupRule("Admins"), allowEveryoneRule()}
	}
	groups := newRaciReadClient(map[string]*corev1.Category{"g-it": {Id: "g-it", Name: "IT"}},
		map[string][]*corev1.CategoryRule{"g-it": rules})
	pc := &recordingPolicyClient{fakePolicyClient: &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol-1": {Id: "pol-1", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "Sec", CurrentPublishedVersionId: "pol-1-v1"},
		},
		versions: map[string]*corev1.PolicyVersion{
			"pol-1-v1": {Id: "pol-1-v1", PolicyId: "pol-1", VersionNo: 1, Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED, ContentJson: breakGlassSecret},
		},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "sa", RolesValue: []string{"site-admin"}, IdpGroupsValue: []string{"Admins"},
	})
	return pc, groups, ctx
}

func grant() *fakeBreakGlassAdmin {
	return &fakeBreakGlassAdmin{activeResp: &identityv1.ActiveBreakGlassResponse{PolicyNumbers: []string{"POL-IT-1"}}}
}

func TestGetPolicyVersionRecordsABreakGlassRead(t *testing.T) {
	pc, groups, ctx := breakGlassReadSetup(t, true)

	v, err := resolvers.GetPolicyVersion(ctx, pc, groups, grant(), "pol-1-v1")
	if err != nil {
		t.Fatalf("GetPolicyVersion: %v", err)
	}
	if v.ContentJSON != breakGlassSecret {
		t.Fatalf("content = %q, want the real content under the grant", v.ContentJSON)
	}
	if len(pc.recorded) != 1 || pc.recorded[0].GetPolicyId() != "pol-1" || pc.recorded[0].GetPolicyVersionId() != "pol-1-v1" {
		t.Fatalf("recorded = %v, want one record for pol-1 / pol-1-v1", pc.recorded)
	}
}

func TestGetPolicyVersionWithoutAGrantStaysObfuscatedAndUnrecorded(t *testing.T) {
	pc, groups, ctx := breakGlassReadSetup(t, true)

	v, err := resolvers.GetPolicyVersion(ctx, pc, groups, &fakeBreakGlassAdmin{activeResp: &identityv1.ActiveBreakGlassResponse{}}, "pol-1-v1")
	if err != nil {
		t.Fatalf("GetPolicyVersion: %v", err)
	}
	if strings.Contains(v.ContentJSON, "the secret clause") {
		t.Fatal("content must stay obfuscated without a grant")
	}
	if len(pc.recorded) != 0 {
		t.Fatalf("recorded = %v, want none", pc.recorded)
	}
}

func TestGetPolicyVersionReadableWithoutTheGrantIsNotABreakGlassRead(t *testing.T) {
	pc, groups, ctx := breakGlassReadSetup(t, false)

	if _, err := resolvers.GetPolicyVersion(ctx, pc, groups, grant(), "pol-1-v1"); err != nil {
		t.Fatalf("GetPolicyVersion: %v", err)
	}
	if len(pc.recorded) != 0 {
		t.Fatalf("recorded = %v, want none: the rules already allow this read", pc.recorded)
	}
}

func TestGetPolicyVersionServesNothingWhenTheReadIsNotRecorded(t *testing.T) {
	pc, groups, ctx := breakGlassReadSetup(t, true)
	pc.recordErr = status.Error(codes.Unavailable, "audit down")

	v, err := resolvers.GetPolicyVersion(ctx, pc, groups, grant(), "pol-1-v1")
	if status.Code(err) != codes.Unavailable || v != nil {
		t.Fatalf("got %v, %v; want Unavailable and no version", v, err)
	}
}

func TestListPolicyVersionsRecordsOneBreakGlassRead(t *testing.T) {
	pc, groups, ctx := breakGlassReadSetup(t, true)

	vs, err := resolvers.ListPolicyVersions(ctx, pc, groups, grant(), "pol-1")
	if err != nil {
		t.Fatalf("ListPolicyVersions: %v", err)
	}
	if len(vs) != 1 || vs[0].ContentJSON != breakGlassSecret {
		t.Fatalf("versions = %+v, want the real content", vs)
	}
	if len(pc.recorded) != 1 || pc.recorded[0].GetPolicyId() != "pol-1" || pc.recorded[0].GetPolicyVersionId() != "" {
		t.Fatalf("recorded = %v, want one record for the list", pc.recorded)
	}

	pc.recordErr = errors.New("down")
	if _, err := resolvers.ListPolicyVersions(ctx, pc, groups, grant(), "pol-1"); err == nil {
		t.Fatal("an unrecorded break-glass list must fail")
	}
}
