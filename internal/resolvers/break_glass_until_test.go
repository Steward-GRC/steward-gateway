// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"errors"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

const grantEnds = "2026-11-11T22:44:00Z"

func breakGlassUntilFixtures(t *testing.T) (*fakePolicyClient, corev1.CategoryServiceClient) {
	t.Helper()
	groups := newRaciReadClient(
		map[string]*corev1.Category{"g-it": {Id: "g-it", Name: "IT"}},
		map[string][]*corev1.CategoryRule{"g-it": {denyGroupRule("Admins"), allowEveryoneRule()}},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-1": {Id: "pol-1", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "Sec", CurrentPublishedVersionId: "pol-1-v1"},
	}}
	return pc, groups
}

func grantAdminClaims(t *testing.T) (c principal.Static) {
	t.Helper()
	return principal.Static{UserIDValue: "sa", RolesValue: []string{"site-admin"}, IdpGroupsValue: []string{"Admins"}}
}

// An active grant tells the reader when it ends.
func TestViewerCanBreakGlassUntil_ActiveGrant(t *testing.T) {
	pc, groups := breakGlassUntilFixtures(t)
	admin := &fakeBreakGlassAdmin{activeResp: &identityv1.ActiveBreakGlassResponse{
		PolicyNumbers: []string{"POL-IT-1"},
		Grants:        []*identityv1.ActiveBreakGlassGrant{{PolicyNumber: "POL-IT-1", ExpiresAt: grantEnds}},
	}}
	p, err := resolvers.GetPolicy(ctxWithStubClaims(t, grantAdminClaims(t)), pc, groups, admin, nil, nil, "pol-1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan.BreakGlassUntil == nil || *p.ViewerCan.BreakGlassUntil != grantEnds {
		t.Fatalf("breakGlassUntil = %v, want %s", p.ViewerCan.BreakGlassUntil, grantEnds)
	}
	if p.ViewerCan.ContentObfuscated {
		t.Fatal("an active grant must still reveal the content")
	}
}

// A grant that has ended is not reported by identity, so the field is null and
// the content is obfuscated again.
func TestViewerCanBreakGlassUntil_EndedGrantIsNull(t *testing.T) {
	pc, groups := breakGlassUntilFixtures(t)
	admin := &fakeBreakGlassAdmin{activeResp: &identityv1.ActiveBreakGlassResponse{}}
	p, err := resolvers.GetPolicy(ctxWithStubClaims(t, grantAdminClaims(t)), pc, groups, admin, nil, nil, "pol-1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan.BreakGlassUntil != nil {
		t.Fatalf("breakGlassUntil = %v, want null", *p.ViewerCan.BreakGlassUntil)
	}
	if !p.ViewerCan.ContentObfuscated {
		t.Fatal("no grant: content must be obfuscated")
	}
}

// A grant on a different policy says nothing about this one.
func TestViewerCanBreakGlassUntil_OtherPolicyGrantIsNull(t *testing.T) {
	pc, groups := breakGlassUntilFixtures(t)
	admin := &fakeBreakGlassAdmin{activeResp: &identityv1.ActiveBreakGlassResponse{
		PolicyNumbers: []string{"POL-OTHER-9"},
		Grants:        []*identityv1.ActiveBreakGlassGrant{{PolicyNumber: "POL-OTHER-9", ExpiresAt: grantEnds}},
	}}
	p, err := resolvers.GetPolicy(ctxWithStubClaims(t, grantAdminClaims(t)), pc, groups, admin, nil, nil, "pol-1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan.BreakGlassUntil != nil {
		t.Fatalf("breakGlassUntil = %v, want null", *p.ViewerCan.BreakGlassUntil)
	}
}

// A lookup failure is no grant: null, content stays obfuscated.
func TestViewerCanBreakGlassUntil_LookupFailureIsNull(t *testing.T) {
	pc, groups := breakGlassUntilFixtures(t)
	admin := &fakeBreakGlassAdmin{activeErr: errors.New("lookup failed")}
	p, err := resolvers.GetPolicy(ctxWithStubClaims(t, grantAdminClaims(t)), pc, groups, admin, nil, nil, "pol-1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan.BreakGlassUntil != nil {
		t.Fatal("lookup failure must read as no grant")
	}
}

// A non-admin never has a grant and identity is not asked.
func TestViewerCanBreakGlassUntil_NonAdminIsNull(t *testing.T) {
	pc, groups := breakGlassUntilFixtures(t)
	admin := &fakeBreakGlassAdmin{activeErr: errors.New("lookup failed")}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "r", RolesValue: []string{"reader"}})
	p, err := resolvers.GetPolicy(ctx, pc, groups, admin, nil, nil, "pol-1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan.BreakGlassUntil != nil || admin.activeCnt != 0 {
		t.Fatalf("non-admin: until=%v lookups=%d", p.ViewerCan.BreakGlassUntil, admin.activeCnt)
	}
}
