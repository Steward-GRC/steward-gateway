// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeBreakGlassAdmin is a focused IdentityAdminServiceClient fake that records
// the BreakGlassReveal call and returns a configurable response/error. All other
// methods panic so an unexpected call surfaces immediately.
type fakeBreakGlassAdmin struct {
	identityv1.IdentityAdminServiceClient // embed so unused methods are nil-call panics

	revealResp *identityv1.BreakGlassRevealResponse
	revealErr  error
	lastReveal *identityv1.BreakGlassRevealRequest

	activeResp *identityv1.ActiveBreakGlassResponse
	activeErr  error
	activeCnt  int
}

func (f *fakeBreakGlassAdmin) BreakGlassReveal(_ context.Context, in *identityv1.BreakGlassRevealRequest, _ ...grpc.CallOption) (*identityv1.BreakGlassRevealResponse, error) {
	f.lastReveal = in
	if f.revealErr != nil {
		return nil, f.revealErr
	}
	return f.revealResp, nil
}

func (f *fakeBreakGlassAdmin) ActiveBreakGlass(_ context.Context, _ *identityv1.ActiveBreakGlassRequest, _ ...grpc.CallOption) (*identityv1.ActiveBreakGlassResponse, error) {
	f.activeCnt++
	if f.activeErr != nil {
		return nil, f.activeErr
	}
	return f.activeResp, nil
}

// TestBreakGlassReveal_HappyPath verifies the resolver maps policyId→policy
// number via the policy client and calls the identity RPC with the policy
// number + reason, returning grantedUntil.
func TestBreakGlassReveal_HappyPath(t *testing.T) {
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-1": {Id: "pol-1", Number: "POL-IT-1", HomeCategoryId: "g-it"},
	}}
	admin := &fakeBreakGlassAdmin{
		revealResp: &identityv1.BreakGlassRevealResponse{GrantedUntil: "2026-06-30T12:15:00Z"},
	}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "sa",
		RolesValue:  []string{"site-admin"},
	})
	out, err := resolvers.BreakGlassRevealResolver(ctx, admin, pc, "pol-1", "investigating incident")
	if err != nil {
		t.Fatalf("BreakGlassRevealResolver: %v", err)
	}
	if admin.lastReveal == nil {
		t.Fatal("BreakGlassReveal RPC was not called")
	}
	if admin.lastReveal.PolicyNumber != "POL-IT-1" {
		t.Errorf("PolicyNumber: got %q want %q", admin.lastReveal.PolicyNumber, "POL-IT-1")
	}
	if admin.lastReveal.Reason != "investigating incident" {
		t.Errorf("Reason: got %q", admin.lastReveal.Reason)
	}
	if out == nil || out.GrantedUntil != "2026-06-30T12:15:00Z" {
		t.Errorf("unexpected result: %+v", out)
	}
}

// TestBreakGlassReveal_EmptyReason verifies an empty reason is rejected at the
// gateway with InvalidArgument and the RPC is never called.
func TestBreakGlassReveal_EmptyReason(t *testing.T) {
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-1": {Id: "pol-1", Number: "POL-IT-1"},
	}}
	admin := &fakeBreakGlassAdmin{}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "sa",
		RolesValue:  []string{"site-admin"},
	})
	_, err := resolvers.BreakGlassRevealResolver(ctx, admin, pc, "pol-1", "")
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v (err=%v)", status.Code(err), err)
	}
	if admin.lastReveal != nil {
		t.Errorf("RPC must not be called for an empty reason: %+v", admin.lastReveal)
	}
}

// TestBreakGlassReveal_PolicyNotFound verifies an unknown policyId yields the
// policy client's error and the RPC is never called.
func TestBreakGlassReveal_PolicyNotFound(t *testing.T) {
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{}}
	admin := &fakeBreakGlassAdmin{}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "sa",
		RolesValue:  []string{"site-admin"},
	})
	_, err := resolvers.BreakGlassRevealResolver(ctx, admin, pc, "missing", "reason")
	if err == nil {
		t.Fatal("expected an error for an unknown policy id")
	}
	if admin.lastReveal != nil {
		t.Errorf("RPC must not be called when the policy lookup fails: %+v", admin.lastReveal)
	}
}

// TestActiveBreakGlass_ThreadsIntoReadDecision verifies that an active
// break-glass grant flips a RACI-denied site-admin's read decision from
// obfuscate back to real content (contentObfuscated=false). Exclusion is
// expressed as a RACI deny-read rule for the site-admin's group.
func TestActiveBreakGlass_ThreadsIntoReadDecision(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			// Deny the site-admin's AD group so they obfuscate without break-glass.
			"g-it": {denyGroupRule("Admins"), allowEveryoneRule()},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-1": {Id: "pol-1", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "Sec", CurrentPublishedVersionId: "pol-1-v1"},
	}}
	// Active grant for POL-IT-1 → the RACI-denied site-admin sees real content.
	admin := &fakeBreakGlassAdmin{
		activeResp: &identityv1.ActiveBreakGlassResponse{PolicyNumbers: []string{"POL-IT-1"}},
	}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:    "sa",
		RolesValue:     []string{"site-admin"},
		IdpGroupsValue: []string{"Admins"}, // AD group name that matches the deny rule
	})
	p, err := resolvers.GetPolicy(ctx, pc, groups, admin, nil, "pol-1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil {
		t.Fatal("viewerCan must be populated")
	}
	if p.ViewerCan.ContentObfuscated {
		t.Fatal("active break-glass must flip contentObfuscated to false")
	}
	if admin.activeCnt == 0 {
		t.Error("ActiveBreakGlass should have been consulted for a site-admin")
	}
}

// TestActiveBreakGlass_SkippedForNonSiteAdmin verifies the perf guard: a
// non-site-admin never triggers an ActiveBreakGlass lookup.
func TestActiveBreakGlass_SkippedForNonSiteAdmin(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {allowEveryoneRule()},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-1": {Id: "pol-1", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "Sec", CurrentPublishedVersionId: "pol-1-v1"},
	}}
	admin := &fakeBreakGlassAdmin{activeErr: errors.New("must not be called")}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "r",
		RolesValue:  []string{"reader"},
	})
	if _, err := resolvers.GetPolicy(ctx, pc, groups, admin, nil, "pol-1"); err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if admin.activeCnt != 0 {
		t.Errorf("ActiveBreakGlass must not be called for a non-site-admin; called %d times", admin.activeCnt)
	}
}
