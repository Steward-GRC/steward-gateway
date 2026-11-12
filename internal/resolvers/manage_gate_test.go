// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// Manage gates moving documents (steward-gateway#201). A person may move a
// document when the category rules allow Manage in the document's category and
// Author in the target category, or when the old gate allows (the site-admin
// role): the new gate is a superset, so no existing right is taken away.

func ruleFor(userID string, mod func(*corev1.CategoryRule)) *corev1.CategoryRule {
	r := &corev1.CategoryRule{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER, SubjectRef: userID}
	mod(r)
	return r
}

func manageRule(userID string, effect corev1.GrantEffect) *corev1.CategoryRule {
	return ruleFor(userID, func(r *corev1.CategoryRule) { r.Manage = effect })
}

func authorOnlyRule(userID string) *corev1.CategoryRule {
	return ruleFor(userID, func(r *corev1.CategoryRule) { r.Author = corev1.GrantEffect_GRANT_EFFECT_ALLOW })
}

const (
	allowCell = corev1.GrantEffect_GRANT_EFFECT_ALLOW
	denyCell  = corev1.GrantEffect_GRANT_EFFECT_DENY
)

// moveGateCore records the move calls the gate lets through.
type moveGateCore struct {
	*fakePolicyClient
	previewed int
	bulkMoved []*corev1.MovePoliciesRequest
}

func (f *moveGateCore) MovePolicies(_ context.Context, in *corev1.MovePoliciesRequest, _ ...grpc.CallOption) (*corev1.MovePoliciesResponse, error) {
	f.bulkMoved = append(f.bulkMoved, in)
	return &corev1.MovePoliciesResponse{}, nil
}

func (f *moveGateCore) PreviewMovePolicies(_ context.Context, _ *corev1.PreviewMovePoliciesRequest, _ ...grpc.CallOption) (*corev1.PreviewMovePoliciesResponse, error) {
	f.previewed++
	return &corev1.PreviewMovePoliciesResponse{}, nil
}

type moveCase struct {
	name      string
	claims    principal.Static
	src, dst  []*corev1.CategoryRule
	srcOwners []string
	dstOwners []string
	wantAllow bool
}

func moveCases() []moveCase {
	reader := principal.Static{UserIDValue: "u", RolesValue: []string{"reader"}}
	return []moveCase{
		{name: "manage in the source and author in the target", claims: reader,
			src: []*corev1.CategoryRule{manageRule("u", allowCell)}, dst: []*corev1.CategoryRule{authorOnlyRule("u")}, wantAllow: true},
		{name: "manage in both", claims: reader,
			src: []*corev1.CategoryRule{manageRule("u", allowCell)}, dst: []*corev1.CategoryRule{manageRule("u", allowCell)}, wantAllow: true},
		{name: "owner of both categories", claims: reader, srcOwners: []string{"u"}, dstOwners: []string{"u"}, wantAllow: true},
		{name: "manage in the source but nothing in the target", claims: reader,
			src: []*corev1.CategoryRule{manageRule("u", allowCell)}, wantAllow: false},
		{name: "manage in the target only", claims: reader,
			dst: []*corev1.CategoryRule{manageRule("u", allowCell)}, wantAllow: false},
		{name: "author in both is not manage", claims: reader,
			src: []*corev1.CategoryRule{authorOnlyRule("u")}, dst: []*corev1.CategoryRule{authorOnlyRule("u")}, wantAllow: false},
		{name: "manage denied in the source", claims: reader,
			src: []*corev1.CategoryRule{manageRule("u", denyCell)}, dst: []*corev1.CategoryRule{authorOnlyRule("u")}, wantAllow: false},
		{name: "reader with no rules", claims: reader, wantAllow: false},
		{name: "site admin with no rule keeps the old right", claims: principal.Static{UserIDValue: "u", RolesValue: []string{"site-admin"}}, wantAllow: true},
		{name: "root holds manage and author everywhere", claims: principal.Static{UserIDValue: "u", IsRootValue: true}, wantAllow: true},
	}
}

func moveEnv(tc moveCase) (*moveGateCore, *raciCategoryClient) {
	pc := &moveGateCore{fakePolicyClient: &fakePolicyClient{policies: map[string]*corev1.Policy{
		"p1": {Id: "p1", HomeCategoryId: "c-src", Number: "POL-SRC-1", Title: "One", OwnerUserId: "someone"},
		"p2": {Id: "p2", HomeCategoryId: "c-src", Number: "POL-SRC-2", Title: "Two", OwnerUserId: "someone"},
		"p3": {Id: "p3", HomeCategoryId: "c-other", Number: "POL-OTH-1", Title: "Three", OwnerUserId: "someone"},
	}}}
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"c-src":   {Id: "c-src", Name: "SRC", Owners: tc.srcOwners},
			"c-dst":   {Id: "c-dst", Name: "DST", Owners: tc.dstOwners},
			"c-other": {Id: "c-other", Name: "OTH"},
		},
		map[string][]*corev1.CategoryRule{"c-src": tc.src, "c-dst": tc.dst, "c-other": nil},
	)
	return pc, gc
}

func TestMovePolicy_ManageGate(t *testing.T) {
	for _, tc := range moveCases() {
		t.Run(tc.name, func(t *testing.T) {
			pc, gc := moveEnv(tc)
			_, err := resolvers.MovePolicy(ctxWithStubClaims(t, tc.claims), pc, gc, nil, nil, nil, "p1", "c-dst")
			if tc.wantAllow {
				require.NoError(t, err)
				require.NotNil(t, pc.lastMove)
				require.Equal(t, "u", pc.lastMove.GetActorUserId())
				return
			}
			require.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
			require.Nil(t, pc.lastMove, "core must not be called when the gate refuses")
		})
	}
}

func TestMovePolicies_ManageGate(t *testing.T) {
	for _, tc := range moveCases() {
		t.Run(tc.name, func(t *testing.T) {
			pc, gc := moveEnv(tc)
			ctx := ctxWithStubClaims(t, tc.claims)
			_, perr := resolvers.PreviewMovePolicies(ctx, pc, gc, []string{"p1", "p2"}, "c-dst")
			_, merr := resolvers.MovePolicies(ctx, pc, gc, []string{"p1", "p2"}, "c-dst")
			if tc.wantAllow {
				require.NoError(t, perr)
				require.NoError(t, merr)
				require.Equal(t, 1, pc.previewed)
				require.Len(t, pc.bulkMoved, 1)
				require.Equal(t, "u", pc.bulkMoved[0].GetActorUserId())
				return
			}
			require.Equal(t, codes.PermissionDenied, status.Code(perr))
			require.Equal(t, codes.PermissionDenied, status.Code(merr))
			require.Zero(t, pc.previewed)
			require.Empty(t, pc.bulkMoved)
		})
	}
}

// One document the person may not manage refuses the whole batch.
func TestMovePolicies_OneUnmanagedDocumentRefusesTheBatch(t *testing.T) {
	tc := moveCase{
		claims: principal.Static{UserIDValue: "u", RolesValue: []string{"reader"}},
		src:    []*corev1.CategoryRule{manageRule("u", allowCell)},
		dst:    []*corev1.CategoryRule{authorOnlyRule("u")},
	}
	pc, gc := moveEnv(tc)
	_, err := resolvers.MovePolicies(ctxWithStubClaims(t, tc.claims), pc, gc, []string{"p1", "p3"}, "c-dst")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Empty(t, pc.bulkMoved)
}

// Manage does not open the rules or the governance of a category (global admin only).
func TestManage_DoesNotGateRulesOrGovernance(t *testing.T) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{"c-src": {Id: "c-src", Name: "SRC", Owners: []string{"u"}}},
		map[string][]*corev1.CategoryRule{"c-src": {manageRule("u", allowCell)}},
	)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u", RolesValue: []string{"reader"}})
	_, err := resolvers.SetCategoryRulesetResolver(ctx, gc, "c-src", nil)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}
