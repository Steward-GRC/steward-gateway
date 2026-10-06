// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"fmt"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakePolicyClient is a hand-rolled stub of corev1.PolicyServiceClient.
// Only SetAck (and GetPolicy as a helper) are wired; all others panic so
// an unintended call surfaces immediately in tests.
type fakePolicyClient struct {
	corev1.PolicyServiceClient
	policies     map[string]*corev1.Policy
	versions     map[string]*corev1.PolicyVersion // version id → version, for GetPolicyVersion
	listResult   []string                         // policy ids returned by ListPolicies, in order
	lastList     *corev1.ListPoliciesRequest      // last ListPolicies request seen
	lastSetAck   *corev1.SetAckRequest
	lastSave     *corev1.SaveDraftRequest
	lastDiscard  *corev1.DiscardDraftRequest
	discardErr   error
	lastDelete   *corev1.DeletePolicyRequest
	deleteErr    error
	lastRetire   *corev1.RetirePolicyRequest
	retireResp   *corev1.RetirePolicyResponse
	retireErr    error
	lastSetOwner *corev1.SetPolicyOwnerRequest
	setOwnerResp *corev1.SetPolicyOwnerResponse
	lastMove     *corev1.MovePolicyRequest
	moveResp     *corev1.MovePolicyResponse
	lastRename   *corev1.RenamePolicyRequest
	renameResp   *corev1.RenamePolicyResponse
	renameErr    error
	lastSetSens  *corev1.SetPolicySensitivityRequest
	lastCreate   *corev1.CreatePolicyRequest
	lastSetTmpl  *corev1.SetPolicyTemplateRequest

	lastReindexPolicy  *corev1.ReindexPolicyRequest
	lastReindexVersion *corev1.ReindexPolicyVersionRequest

	lastListByOwner *corev1.ListPoliciesByOwnerRequest
	byOwnerResp     *corev1.ListPoliciesByOwnerResponse
	byOwnerErr      error
	lastReassign    *corev1.ReassignUserPoliciesRequest
	reassignResp    *corev1.ReassignUserPoliciesResponse
	reassignErr     error
}

func (f *fakePolicyClient) ListPoliciesByOwner(_ context.Context, in *corev1.ListPoliciesByOwnerRequest, _ ...grpc.CallOption) (*corev1.ListPoliciesByOwnerResponse, error) {
	f.lastListByOwner = in
	if f.byOwnerErr != nil {
		return nil, f.byOwnerErr
	}
	if f.byOwnerResp != nil {
		return f.byOwnerResp, nil
	}
	return &corev1.ListPoliciesByOwnerResponse{}, nil
}

func (f *fakePolicyClient) ReassignUserPolicies(_ context.Context, in *corev1.ReassignUserPoliciesRequest, _ ...grpc.CallOption) (*corev1.ReassignUserPoliciesResponse, error) {
	f.lastReassign = in
	if f.reassignErr != nil {
		return nil, f.reassignErr
	}
	if f.reassignResp != nil {
		return f.reassignResp, nil
	}
	return &corev1.ReassignUserPoliciesResponse{}, nil
}

func (f *fakePolicyClient) CreatePolicy(_ context.Context, in *corev1.CreatePolicyRequest, _ ...grpc.CallOption) (*corev1.CreatePolicyResponse, error) {
	f.lastCreate = in
	return &corev1.CreatePolicyResponse{Policy: &corev1.Policy{
		Id:             "new-pol",
		HomeCategoryId: in.HomeCategoryId,
		Title:          in.Title,
		Sensitivity:    in.Sensitivity,
		OwnerUserId:    in.OwnerUserId,
	}}, nil
}

func (f *fakePolicyClient) GetPolicy(_ context.Context, in *corev1.GetPolicyRequest, _ ...grpc.CallOption) (*corev1.GetPolicyResponse, error) {
	p, ok := f.policies[in.Id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", in.Id)
	}
	return &corev1.GetPolicyResponse{Policy: p}, nil
}

func (f *fakePolicyClient) ListPolicies(_ context.Context, in *corev1.ListPoliciesRequest, _ ...grpc.CallOption) (*corev1.ListPoliciesResponse, error) {
	f.lastList = in
	out := make([]*corev1.Policy, 0, len(f.listResult))
	for _, id := range f.listResult {
		if p, ok := f.policies[id]; ok {
			out = append(out, p)
		}
	}
	return &corev1.ListPoliciesResponse{Policies: out}, nil
}

func (f *fakePolicyClient) GetPolicyVersion(_ context.Context, in *corev1.GetPolicyVersionRequest, _ ...grpc.CallOption) (*corev1.GetPolicyVersionResponse, error) {
	if f.versions == nil {
		// createdAt resolution calls this for any policy with a version id; when a
		// test doesn't stub versions the lookup is simply a non-fatal miss (the
		// read model tolerates a missing createdAt).
		return nil, fmt.Errorf("not found: %s", in.Id)
	}
	v, ok := f.versions[in.Id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", in.Id)
	}
	return &corev1.GetPolicyVersionResponse{Version: v}, nil
}

func (f *fakePolicyClient) SaveDraft(_ context.Context, in *corev1.SaveDraftRequest, _ ...grpc.CallOption) (*corev1.SaveDraftResponse, error) {
	f.lastSave = in
	return &corev1.SaveDraftResponse{Version: &corev1.PolicyVersion{PolicyId: in.PolicyId}}, nil
}

func (f *fakePolicyClient) DiscardDraft(_ context.Context, in *corev1.DiscardDraftRequest, _ ...grpc.CallOption) (*corev1.DiscardDraftResponse, error) {
	f.lastDiscard = in
	if f.discardErr != nil {
		return nil, f.discardErr
	}
	return &corev1.DiscardDraftResponse{}, nil
}

func (f *fakePolicyClient) DeletePolicy(_ context.Context, in *corev1.DeletePolicyRequest, _ ...grpc.CallOption) (*corev1.DeletePolicyResponse, error) {
	f.lastDelete = in
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return &corev1.DeletePolicyResponse{Deleted: true}, nil
}

func (f *fakePolicyClient) RetirePolicy(_ context.Context, in *corev1.RetirePolicyRequest, _ ...grpc.CallOption) (*corev1.RetirePolicyResponse, error) {
	f.lastRetire = in
	if f.retireErr != nil {
		return nil, f.retireErr
	}
	if f.retireResp != nil {
		return f.retireResp, nil
	}
	return &corev1.RetirePolicyResponse{Policy: &corev1.Policy{Id: in.PolicyId, RetiredAt: "2026-08-25T00:00:00Z"}}, nil
}

func (f *fakePolicyClient) SetPolicyOwner(_ context.Context, in *corev1.SetPolicyOwnerRequest, _ ...grpc.CallOption) (*corev1.SetPolicyOwnerResponse, error) {
	f.lastSetOwner = in
	if f.setOwnerResp != nil {
		return f.setOwnerResp, nil
	}
	return &corev1.SetPolicyOwnerResponse{Policy: &corev1.Policy{Id: in.PolicyId, OwnerUserId: in.OwnerUserId}}, nil
}

func (f *fakePolicyClient) SetPolicySensitivity(_ context.Context, in *corev1.SetPolicySensitivityRequest, _ ...grpc.CallOption) (*corev1.SetPolicySensitivityResponse, error) {
	f.lastSetSens = in
	// Echo the flipped classification back the same way core does.
	return &corev1.SetPolicySensitivityResponse{
		Policy: &corev1.Policy{Id: in.PolicyId, Sensitivity: in.Sensitivity},
	}, nil
}

func (f *fakePolicyClient) SetPolicyTemplate(_ context.Context, in *corev1.SetPolicyTemplateRequest, _ ...grpc.CallOption) (*corev1.SetPolicyTemplateResponse, error) {
	f.lastSetTmpl = in
	return &corev1.SetPolicyTemplateResponse{Policy: &corev1.Policy{
		Id:           in.PolicyId,
		TemplateId:   in.TemplateId,
		TemplateNone: in.None,
	}}, nil
}

func (f *fakePolicyClient) MovePolicy(_ context.Context, in *corev1.MovePolicyRequest, _ ...grpc.CallOption) (*corev1.MovePolicyResponse, error) {
	f.lastMove = in
	if f.moveResp != nil {
		return f.moveResp, nil
	}
	return &corev1.MovePolicyResponse{Policy: &corev1.Policy{Id: in.PolicyId, HomeCategoryId: in.HomeCategoryId, Number: "POL-FIN-000001"}}, nil
}

func (f *fakePolicyClient) ReindexPolicy(_ context.Context, in *corev1.ReindexPolicyRequest, _ ...grpc.CallOption) (*corev1.ReindexPolicyResponse, error) {
	f.lastReindexPolicy = in
	return &corev1.ReindexPolicyResponse{VersionId: "ver-1", Sections: 3, RemovedPrior: 1}, nil
}

func (f *fakePolicyClient) ReindexPolicyVersion(_ context.Context, in *corev1.ReindexPolicyVersionRequest, _ ...grpc.CallOption) (*corev1.ReindexPolicyVersionResponse, error) {
	f.lastReindexVersion = in
	return &corev1.ReindexPolicyVersionResponse{VersionId: in.PolicyVersionId, Sections: 2, RemovedPrior: 0}, nil
}

func (f *fakePolicyClient) ReindexAllPublished(_ context.Context, _ *corev1.ReindexAllPublishedRequest, _ ...grpc.CallOption) (*corev1.ReindexAllPublishedResponse, error) {
	return &corev1.ReindexAllPublishedResponse{}, nil
}

func (f *fakePolicyClient) RenamePolicy(_ context.Context, in *corev1.RenamePolicyRequest, _ ...grpc.CallOption) (*corev1.RenamePolicyResponse, error) {
	f.lastRename = in
	if f.renameErr != nil {
		return nil, f.renameErr
	}
	if f.renameResp != nil {
		return f.renameResp, nil
	}
	// Default: echo the policy with the new title, in-place (staged=false).
	return &corev1.RenamePolicyResponse{
		Policy: &corev1.Policy{Id: in.PolicyId, Title: in.NewTitle},
		Staged: false,
	}, nil
}

func (f *fakePolicyClient) SetAck(_ context.Context, in *corev1.SetAckRequest, _ ...grpc.CallOption) (*corev1.SetAckResponse, error) {
	f.lastSetAck = in
	p, ok := f.policies[in.PolicyId]
	if !ok {
		return nil, fmt.Errorf("not found: %s", in.PolicyId)
	}
	// Simulate server applying the request to the policy.
	p.AckTriggers = in.AckTriggers
	p.AckTriggersSet = in.AckTriggersSet
	p.AckAudienceOverride = in.AckAudienceOverride
	return &corev1.SetAckResponse{Policy: p}, nil
}

// ptr returns a pointer to the provided AckTrigger value (test helper).
//
//go:fix inline
func ptr(t resolvers.AckTrigger) *resolvers.AckTrigger { return new(t) }

// TestSetPolicyAck_WithAckTrigger verifies:
//  1. Non-nil ackTriggers → proto ack_triggers_set=true and correct ack_triggers enum.
//  2. The returned GQL Policy surfaces ackTriggers as non-nil (the mapped enum).
//  3. ackAudienceOverride nil → empty slice on the wire.
func TestSetPolicyAck_WithAckTrigger(t *testing.T) {
	client := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol-1": {
				Id:             "pol-1",
				HomeCategoryId: "g1",
				Number:         "POL-001",
				Title:          "Test Policy",
			},
		},
	}

	p, err := resolvers.SetPolicyAck(ctxWithRoles(t, "u", []string{"compliance-admin"}), client, "pol-1", ptr(resolvers.AckTriggerOnPublish), nil)
	if err != nil {
		t.Fatalf("SetPolicyAck: %v", err)
	}

	// Assert wire request fields.
	if client.lastSetAck == nil {
		t.Fatal("expected SetAck to be called")
	}
	if client.lastSetAck.PolicyId != "pol-1" {
		t.Fatalf("want PolicyId=pol-1; got %q", client.lastSetAck.PolicyId)
	}
	if !client.lastSetAck.AckTriggersSet {
		t.Fatal("non-nil ackTriggers must set ack_triggers_set=true")
	}
	if client.lastSetAck.AckTriggers != corev1.AckTrigger_ACK_TRIGGER_ON_PUBLISH {
		t.Fatalf("GQL ON_PUBLISH must map to ACK_TRIGGER_ON_PUBLISH; got %v", client.lastSetAck.AckTriggers)
	}

	// Assert GQL projection: ackTriggers must be non-nil and equal ON_PUBLISH.
	if p.AckTriggers == nil {
		t.Fatal("ack_triggers_set=true must produce non-nil GQL ackTriggers")
	}
	if *p.AckTriggers != resolvers.AckTriggerOnPublish {
		t.Fatalf("returned AckTriggers want ON_PUBLISH; got %v", *p.AckTriggers)
	}
	if p.AckAudienceOverride != nil {
		t.Fatalf("nil ackAudienceOverride must produce nil/empty slice in GQL; got %v", p.AckAudienceOverride)
	}
}

// TestSetPolicyAck_NilAckTrigger verifies:
//  1. nil ackTriggers → proto ack_triggers_set=false (inherit group default).
//  2. The returned GQL Policy surfaces ackTriggers as nil (not set).
//  3. ackAudienceOverride forwarded when non-nil.
func TestSetPolicyAck_NilAckTrigger(t *testing.T) {
	client := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol-2": {
				Id:             "pol-2",
				HomeCategoryId: "g1",
				Number:         "POL-002",
				Title:          "Inherit Policy",
			},
		},
	}

	override := []string{"grp-a", "grp-b"}
	p, err := resolvers.SetPolicyAck(ctxWithRoles(t, "u", []string{"site-admin"}), client, "pol-2", nil, override)
	if err != nil {
		t.Fatalf("SetPolicyAck: %v", err)
	}

	// Assert wire request: ack_triggers_set must be false.
	if client.lastSetAck == nil {
		t.Fatal("expected SetAck to be called")
	}
	if client.lastSetAck.AckTriggersSet {
		t.Fatal("nil ackTriggers must set ack_triggers_set=false")
	}

	// Assert GQL projection: ackTriggers must be nil when ack_triggers_set=false.
	if p.AckTriggers != nil {
		t.Fatalf("ack_triggers_set=false must produce nil GQL ackTriggers; got %v", p.AckTriggers)
	}

	// ackAudienceOverride forwarded.
	if len(p.AckAudienceOverride) != 2 || p.AckAudienceOverride[0] != "grp-a" || p.AckAudienceOverride[1] != "grp-b" {
		t.Fatalf("ackAudienceOverride not forwarded; got %v", p.AckAudienceOverride)
	}
}

// TestGetPolicy_ViewerCan_ExcludedSiteAdminObfuscated verifies an excluded
// site-admin's read decision is obfuscate: the policy is still visible
// (viewerCan.read) but contentObfuscated=true and canBreakGlass=true.
// Exclusion is expressed as a RACI deny-read rule for the site-admin's group.
func TestGetPolicy_ViewerCan_ExcludedSiteAdminObfuscated(t *testing.T) {
	// The site-admin is in the "Admins" AD group, which is explicitly denied read.
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {
				denyGroupRule("Admins"), // deny site-admin's group first
				allowEveryoneRule(),     // then allow everyone else
			},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-1": {Id: "pol-1", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "Sec", Sensitivity: corev1.Sensitivity_SENSITIVITY_STANDARD},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:    "sa",
		RolesValue:     []string{"site-admin"},
		IdpGroupsValue: []string{"Admins"}, // AD group name that matches the deny rule
	})
	p, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil {
		t.Fatal("viewerCan must be populated")
	}
	if !p.ViewerCan.Read {
		t.Fatal("RACI-denied site-admin must still see the policy (read=true)")
	}
	if !p.ViewerCan.ContentObfuscated {
		t.Fatal("RACI-denied site-admin must get contentObfuscated=true")
	}
	if !p.ViewerCan.CanBreakGlass {
		t.Fatal("obfuscated site-admin must get canBreakGlass=true")
	}
}

// TestGetPolicy_ViewerCan_ScopedAuthor verifies a scoped author's edit
// capability is true in-category and false out-of-category.
func TestGetPolicy_ViewerCan_ScopedAuthor(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
			"g-hr": {Id: "g-hr", Name: "HR", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {allowEveryoneRule()},
			"g-hr": {allowEveryoneRule()},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
		"pol-hr": {Id: "pol-hr", HomeCategoryId: "g-hr", Number: "POL-HR-1", Title: "HR pol", CurrentPublishedVersionId: "pol-hr-v1"},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:      "auth",
		RolesValue:       []string{"author"},
		ScopedRolesValue: []principal.ScopedRole{{Role: "author", Category: "IT"}},
	})
	// In-category: edit allowed.
	itp, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy it: %v", err)
	}
	if itp.ViewerCan == nil || !itp.ViewerCan.Edit {
		t.Fatalf("scoped author in-category must have edit=true; got %+v", itp.ViewerCan)
	}
	// Out-of-category: edit denied.
	hrp, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-hr")
	if err != nil {
		t.Fatalf("GetPolicy hr: %v", err)
	}
	if hrp.ViewerCan == nil || hrp.ViewerCan.Edit {
		t.Fatalf("scoped author out-of-category must have edit=false; got %+v", hrp.ViewerCan)
	}
}

// TestGetPolicy_ViewerCan_GroupOwnerInheritsApprover verifies D5b: a group owner
// (core groups.owners) inherits the approver role for their own group's policies
// WITHOUT holding an explicit approver grant — viewerCan.approve must be true.
// Owner auto-read via RACI means no explicit "everyone allow" is needed for the
// owner to see and approve the policy.
func TestGetPolicy_ViewerCan_GroupOwnerInheritsApprover(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: "", Owners: []string{"owner-u"}},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {}, // no explicit rules — owner auto-reads via chain ownership
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	// Caller owns g-it but holds NO roles and NO scoped grants.
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "owner-u",
	})
	p, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil || !p.ViewerCan.Approve {
		t.Fatalf("group owner must inherit approve=true; got %+v", p.ViewerCan)
	}
}

// TestGetPolicy_ViewerCan_OwnerOfAncestorInheritsApprover verifies ownership of
// an ANCESTOR group in the lineage confers approver on the descendant policy
// (governance inherits down the tree). Ancestor owners auto-read/approve via
// the RACI chain even with no explicit rules.
func TestGetPolicy_ViewerCan_OwnerOfAncestorInheritsApprover(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-root":  {Id: "g-root", Name: "IT", ParentId: "", Owners: []string{"owner-u"}},
			"g-child": {Id: "g-child", Name: "Networking", ParentId: "g-root"},
		},
		map[string][]*corev1.CategoryRule{
			"g-root":  {},
			"g-child": {},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-c": {Id: "pol-c", HomeCategoryId: "g-child", Number: "POL-NET-1", Title: "child pol"},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "owner-u"})
	p, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-c")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil || !p.ViewerCan.Approve {
		t.Fatalf("owner of ancestor group must inherit approve=true on descendant; got %+v", p.ViewerCan)
	}
}

// TestGetPolicy_ViewerCan_NonOwnerNonApproverDenied verifies a caller who neither
// owns the group nor holds an approver grant does NOT get approve.
func TestGetPolicy_ViewerCan_NonOwnerNonApproverDenied(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: "", Owners: []string{"someone-else"}},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {allowEveryoneRule()},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "reader-u",
		RolesValue:  []string{"reader"},
	})
	p, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil {
		t.Fatal("viewerCan must be populated")
	}
	if p.ViewerCan.Approve {
		t.Fatalf("non-owner non-approver must have approve=false; got %+v", p.ViewerCan)
	}
}

// TestGetPolicy_ViewerCan_SiteAdminNotBlanketApprover verifies site-admin is NOT
// an automatic approver: it can author/submit globally, but approval eligibility
// must come from group ownership (grantOwnerApprover) or an explicit approver
// grant. A site-admin who does NOT own the policy's home group cannot approve.
func TestGetPolicy_ViewerCan_SiteAdminNotBlanketApprover(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: "", Owners: []string{"someone-else"}},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {allowEveryoneRule()},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "sa",
		RolesValue:  []string{"site-admin"},
	})
	p, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil {
		t.Fatal("viewerCan must be populated")
	}
	// Authoring stays global for site-admin.
	if !p.ViewerCan.Edit || !p.ViewerCan.Submit {
		t.Fatalf("site-admin must author/submit globally; got %+v", p.ViewerCan)
	}
	// But approval requires ownership/explicit grant — this site-admin has neither.
	if p.ViewerCan.Approve {
		t.Fatalf("site-admin without ownership must NOT approve; got %+v", p.ViewerCan)
	}
}

// TestGetPolicy_ViewerCan_SiteAdminApprovesOwnedGroup verifies a site-admin who
// OWNS the policy's home group can approve (grantOwnerApprover supplies the
// approver ScopedGrant that authz now requires, and RACI also grants approve
// via owner-chain).
func TestGetPolicy_ViewerCan_SiteAdminApprovesOwnedGroup(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: "", Owners: []string{"sa"}},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue: "sa",
		RolesValue:  []string{"site-admin"},
	})
	p, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil || !p.ViewerCan.Approve {
		t.Fatalf("site-admin owning the home group must approve; got %+v", p.ViewerCan)
	}
}

// TestListPolicies_FiltersHiddenRows verifies a RACI-denied reader's policy is
// omitted from the list while a visible one remains. The reader is in the
// "Contractors" group, which is denied read in the IT category but not HR.
func TestListPolicies_FiltersHiddenRows(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
			"g-hr": {Id: "g-hr", Name: "HR", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			// IT: deny Contractors, then allow everyone else
			"g-it": {denyGroupRule("Contractors"), allowEveryoneRule()},
			// HR: allow everyone
			"g-hr": {allowEveryoneRule()},
		},
	)
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
			"pol-hr": {Id: "pol-hr", HomeCategoryId: "g-hr", Number: "POL-HR-1", Title: "HR pol", CurrentPublishedVersionId: "pol-hr-v1"},
		},
		listResult: []string{"pol-it", "pol-hr"},
	}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:    "r",
		RolesValue:     []string{"reader"},
		IdpGroupsValue: []string{"Contractors"}, // AD group name that matches the RACI deny rule
	})
	out, err := resolvers.ListPolicies(ctx, pc, groups, nil, nil, "g-it", new(true), nil)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	for _, p := range out {
		if p.ID == "pol-it" {
			t.Fatal("RACI-denied reader's policy must be filtered out of the list")
		}
	}
	found := false
	for _, p := range out {
		if p.ID == "pol-hr" {
			found = true
		}
	}
	if !found {
		t.Fatal("visible policy must remain in the list")
	}
}

// TestGetPolicy_Hidden_NotFound verifies a RACI-denied policy (Contractors group
// denied read in IT category) yields NotFound for a normal reader rather than
// leaking existence.
func TestGetPolicy_Hidden_NotFound(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{
			"g-it": {Id: "g-it", Name: "IT", ParentId: ""},
		},
		map[string][]*corev1.CategoryRule{
			"g-it": {denyGroupRule("Contractors"), allowEveryoneRule()},
		},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
	}}
	ctx := ctxWithStubClaims(t, principal.Static{
		UserIDValue:    "r",
		RolesValue:     []string{"reader"},
		IdpGroupsValue: []string{"Contractors"},
	})
	if _, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-it"); status.Code(err) != codes.NotFound {
		t.Fatalf("RACI-denied policy must yield NotFound; got %v", err)
	}
}

// TestDiscardDraft_NoAuthorGrantDenied rejects a caller with no author grant
// on the policy's category and never reaches core. DiscardDraft is now
// authorized at the author tier (authorizeEffectiveAuthor) — same as
// SaveDraft/DeletePolicy — so a caller who isn't site-admin, the primary
// author, or a covered category author is still correctly denied.
func TestDiscardDraft_NoAuthorGrantDenied(t *testing.T) {
	pc, gc := coAuthMatrixEnv("creator-other", nil,
		[]*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", RolesValue: []string{"policy-author"}})
	_, err := resolvers.DiscardDraft(ctx, pc, gc, "pol")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if pc.lastDiscard != nil {
		t.Fatal("must not call core when unauthorized")
	}
}

// TestDiscardDraft_CategoryAuthorAllowed verifies the RACI-author-tier fix
// : a category author
// who is NOT the primary author, a category owner, or a site-admin — but
// whose RACI author grant covers the policy's category — may discard the
// draft, and core IS called with the actor bound from claims.
func TestDiscardDraft_CategoryAuthorAllowed(t *testing.T) {
	pc, gc := coAuthMatrixEnv("creator-other", nil,
		[]*corev1.CategoryRule{authorRule("coauthor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "coauthor-u", RolesValue: []string{"reader"}})
	ok, err := resolvers.DiscardDraft(ctx, pc, gc, "pol")
	if err != nil {
		t.Fatalf("expected category author to be allowed to discard, got %v", err)
	}
	if !ok {
		t.Fatal("expected true on success")
	}
	if pc.lastDiscard == nil {
		t.Fatal("expected core DiscardDraft to be called")
	}
	if pc.lastDiscard.PolicyId != "pol" {
		t.Fatalf("PolicyId: got %q want pol", pc.lastDiscard.PolicyId)
	}
	if pc.lastDiscard.ActorUserId != "coauthor-u" {
		t.Fatalf("actor must be bound from claims; got %q", pc.lastDiscard.ActorUserId)
	}
}

// TestDiscardDraft_ForwardsPolicyIDAndBindsActor verifies the discardDraft
// resolver forwards the policy id to core and binds the actor from claims
// (never from input), returning true on success.
func TestDiscardDraft_ForwardsPolicyIDAndBindsActor(t *testing.T) {
	// user-42 is the PRIMARY author (policy owner) — authorized via the
	// effective-author gate. categoryClient nil: the primary-author short-circuit
	// fires before any chain lookup.
	client := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-9": {Id: "pol-9", OwnerUserId: "user-42"},
	}}
	ok, err := resolvers.DiscardDraft(ctxWithRoles(t, "user-42", []string{"policy-author"}), client, nil, "pol-9")
	if err != nil {
		t.Fatalf("DiscardDraft: %v", err)
	}
	if !ok {
		t.Fatal("expected true on success")
	}
	if client.lastDiscard == nil {
		t.Fatal("expected DiscardDraft to be called")
	}
	if client.lastDiscard.PolicyId != "pol-9" {
		t.Fatalf("PolicyId: got %q want pol-9", client.lastDiscard.PolicyId)
	}
	if client.lastDiscard.ActorUserId != "user-42" {
		t.Fatalf("actor must be bound from claims; got %q", client.lastDiscard.ActorUserId)
	}
}

// TestDiscardDraft_Unauthenticated rejects a call with no authenticated user.
func TestDiscardDraft_Unauthenticated(t *testing.T) {
	client := &fakePolicyClient{}
	if _, err := resolvers.DiscardDraft(context.Background(), client, nil, "pol-9"); err == nil {
		t.Fatal("expected error with no authenticated user")
	}
	if client.lastDiscard != nil {
		t.Fatal("must not call core without an authenticated actor")
	}
}

// TestDeletePolicy_NoAuthorGrantDenied rejects a caller with no author grant
// on the policy's category (a bare role with no RACI author rule covering it)
// and never reaches core. DeletePolicy is authorized at the author tier
// (authorizeEffectiveAuthor) — same as SaveDraft/DiscardDraft — so a caller
// who isn't site-admin, the primary author, or a covered category author is
// still correctly denied.
func TestDeletePolicy_NoAuthorGrantDenied(t *testing.T) {
	pc, gc := coAuthMatrixEnv("creator-other", nil,
		[]*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", RolesValue: []string{"policy-author"}})
	_, err := resolvers.DeletePolicy(ctx, pc, gc, "pol")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if pc.lastDelete != nil {
		t.Fatal("must not call core when unauthorized")
	}
}

// TestDeletePolicy_CategoryAuthorAllowed verifies the RACI-author-tier fix: a
// category author who is NOT the primary author, a category owner, or a
// site-admin — but whose RACI author grant covers the policy's category — may
// delete the (never-published) policy, and core IS called with the actor
// bound from claims.
func TestDeletePolicy_CategoryAuthorAllowed(t *testing.T) {
	pc, gc := coAuthMatrixEnv("creator-other", nil,
		[]*corev1.CategoryRule{authorRule("coauthor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "coauthor-u", RolesValue: []string{"reader"}})
	ok, err := resolvers.DeletePolicy(ctx, pc, gc, "pol")
	if err != nil {
		t.Fatalf("expected category author to be allowed to delete, got %v", err)
	}
	if !ok {
		t.Fatal("expected true on success")
	}
	if pc.lastDelete == nil {
		t.Fatal("expected core DeletePolicy to be called")
	}
	if pc.lastDelete.PolicyId != "pol" {
		t.Fatalf("PolicyId: got %q want pol", pc.lastDelete.PolicyId)
	}
	if pc.lastDelete.ActorUserId != "coauthor-u" {
		t.Fatalf("actor must be bound from claims; got %q", pc.lastDelete.ActorUserId)
	}
}

// TestDeletePolicy_ForwardsPolicyIDAndBindsActor verifies the deletePolicy
// resolver forwards the policy id to core and binds the actor from claims
// (never from input), returning true on success. Site-admin is always
// authorized regardless of category grants (deny never applies), so
// categoryClient is nil here — the site-admin short-circuit in
// authorizeEffectiveAuthor fires before any chain lookup.
func TestDeletePolicy_ForwardsPolicyIDAndBindsActor(t *testing.T) {
	client := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-9": {Id: "pol-9"},
	}}
	ok, err := resolvers.DeletePolicy(ctxWithRoles(t, "admin-42", []string{"site-admin"}), client, nil, "pol-9")
	if err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if !ok {
		t.Fatal("expected true on success")
	}
	if client.lastDelete == nil {
		t.Fatal("expected DeletePolicy to be called")
	}
	if client.lastDelete.PolicyId != "pol-9" {
		t.Fatalf("PolicyId: got %q want pol-9", client.lastDelete.PolicyId)
	}
	if client.lastDelete.ActorUserId != "admin-42" {
		t.Fatalf("actor must be bound from claims; got %q", client.lastDelete.ActorUserId)
	}
}

// TestDeletePolicy_Unauthenticated rejects a call with no authenticated user
// and never reaches core.
func TestDeletePolicy_Unauthenticated(t *testing.T) {
	client := &fakePolicyClient{}
	if _, err := resolvers.DeletePolicy(context.Background(), client, nil, "pol-9"); err == nil {
		t.Fatal("expected error with no authenticated user")
	}
	if client.lastDelete != nil {
		t.Fatal("must not call core without an authenticated actor")
	}
}

// TestRetirePolicy_NoAuthorGrantDenied rejects a caller with no author grant on
// the policy's category and never reaches core. RetirePolicy is authorized at
// the author tier (authorizeEffectiveAuthor) — the SAME gate as
// SaveDraft/DiscardDraft/DeletePolicy — so a caller who isn't site-admin, the
// primary author, or a covered category author is denied before the downstream
// call.
func TestRetirePolicy_NoAuthorGrantDenied(t *testing.T) {
	pc, gc := coAuthMatrixEnv("creator-other", nil,
		[]*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", RolesValue: []string{"policy-author"}})
	_, err := resolvers.RetirePolicy(ctx, pc, gc, "pol")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if pc.lastRetire != nil {
		t.Fatal("must not call core when unauthorized")
	}
}

// TestRetirePolicy_CategoryAuthorAllowed verifies a category author who is NOT
// the primary author, a category owner, or a site-admin — but whose RACI author
// grant covers the policy's category — may retire the policy, and core IS called
// with the actor bound from claims.
func TestRetirePolicy_CategoryAuthorAllowed(t *testing.T) {
	pc, gc := coAuthMatrixEnv("creator-other", nil,
		[]*corev1.CategoryRule{authorRule("coauthor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "coauthor-u", RolesValue: []string{"reader"}})
	p, err := resolvers.RetirePolicy(ctx, pc, gc, "pol")
	if err != nil {
		t.Fatalf("expected category author to be allowed to retire, got %v", err)
	}
	if p == nil {
		t.Fatal("expected a policy on success")
	}
	if pc.lastRetire == nil {
		t.Fatal("expected core RetirePolicy to be called")
	}
	if pc.lastRetire.PolicyId != "pol" {
		t.Fatalf("PolicyId: got %q want pol", pc.lastRetire.PolicyId)
	}
	if pc.lastRetire.ActorUserId != "coauthor-u" {
		t.Fatalf("actor must be bound from claims; got %q", pc.lastRetire.ActorUserId)
	}
}

// TestRetirePolicy_PrimaryAuthorAllowed verifies the primary author (policy
// owner) is authorized via the effective-author gate; categoryClient nil since the
// primary-author short-circuit fires before any chain lookup. The resolved
// actor and retiredAt are surfaced.
func TestRetirePolicy_PrimaryAuthorAllowed(t *testing.T) {
	client := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-9": {Id: "pol-9", OwnerUserId: "user-42"},
	}}
	p, err := resolvers.RetirePolicy(ctxWithRoles(t, "user-42", []string{"policy-author"}), client, nil, "pol-9")
	if err != nil {
		t.Fatalf("RetirePolicy: %v", err)
	}
	if p == nil || p.RetiredAt == nil {
		t.Fatal("expected a retired policy with retiredAt set")
	}
	if client.lastRetire == nil {
		t.Fatal("expected RetirePolicy to be called")
	}
	if client.lastRetire.PolicyId != "pol-9" {
		t.Fatalf("PolicyId: got %q want pol-9", client.lastRetire.PolicyId)
	}
	if client.lastRetire.ActorUserId != "user-42" {
		t.Fatalf("actor must be bound from claims; got %q", client.lastRetire.ActorUserId)
	}
}

// TestRetirePolicy_SiteAdminAllowed verifies site-admin is always authorized
// (deny never applies) and the actor is forwarded from claims. categoryClient nil:
// the site-admin short-circuit fires before any chain lookup.
func TestRetirePolicy_SiteAdminAllowed(t *testing.T) {
	client := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-9": {Id: "pol-9"},
	}}
	p, err := resolvers.RetirePolicy(ctxWithRoles(t, "admin-42", []string{"site-admin"}), client, nil, "pol-9")
	if err != nil {
		t.Fatalf("RetirePolicy: %v", err)
	}
	if p == nil {
		t.Fatal("expected a policy on success")
	}
	if client.lastRetire == nil {
		t.Fatal("expected RetirePolicy to be called")
	}
	if client.lastRetire.ActorUserId != "admin-42" {
		t.Fatalf("actor must be bound from claims; got %q", client.lastRetire.ActorUserId)
	}
}

// TestRetirePolicy_Unauthenticated rejects a call with no authenticated user and
// never reaches core.
func TestRetirePolicy_Unauthenticated(t *testing.T) {
	client := &fakePolicyClient{}
	if _, err := resolvers.RetirePolicy(context.Background(), client, nil, "pol-9"); err == nil {
		t.Fatal("expected error with no authenticated user")
	}
	if client.lastRetire != nil {
		t.Fatal("must not call core without an authenticated actor")
	}
}

// TestSetPolicyOwner_RequiresSiteAdmin rejects a non-site-admin caller and never
// reaches core.
func TestSetPolicyOwner_RequiresSiteAdmin(t *testing.T) {
	client := &fakePolicyClient{}
	ctx := ctxWithRoles(t, "u-1", []string{"policy-author"})
	_, err := resolvers.SetPolicyOwner(ctx, client, "pol-1", "owner-1")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.lastSetOwner != nil {
		t.Fatal("must not call core when unauthorized")
	}
}

// TestSetPolicyOwner_HappyPath forwards ids, binds the actor from claims, and
// maps the returned policy.
func TestSetPolicyOwner_HappyPath(t *testing.T) {
	client := &fakePolicyClient{
		setOwnerResp: &corev1.SetPolicyOwnerResponse{Policy: &corev1.Policy{Id: "pol-1", OwnerUserId: "new-owner"}},
	}
	ctx := ctxWithRoles(t, "admin-1", []string{"site-admin"})
	out, err := resolvers.SetPolicyOwner(ctx, client, "pol-1", "new-owner")
	if err != nil {
		t.Fatalf("SetPolicyOwner: %v", err)
	}
	if out.OwnerUserID != "new-owner" {
		t.Fatalf("owner not mapped: got %q", out.OwnerUserID)
	}
	if client.lastSetOwner.GetActorUserId() != "admin-1" {
		t.Fatalf("actor not bound from claims; got %q", client.lastSetOwner.GetActorUserId())
	}
}

// TestMovePolicy_RequiresSiteAdmin rejects a non-site-admin caller.
func TestMovePolicy_RequiresSiteAdmin(t *testing.T) {
	client := &fakePolicyClient{}
	ctx := ctxWithRoles(t, "u-1", []string{"policy-author"})
	_, err := resolvers.MovePolicy(ctx, client, "pol-1", "grp-1")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.lastMove != nil {
		t.Fatal("must not call core when unauthorized")
	}
}

// TestMovePolicy_HappyPath forwards ids, binds the actor, and returns the
// renumbered policy.
func TestMovePolicy_HappyPath(t *testing.T) {
	client := &fakePolicyClient{
		moveResp: &corev1.MovePolicyResponse{Policy: &corev1.Policy{Id: "pol-1", HomeCategoryId: "grp-2", Number: "POL-FIN-000004"}},
	}
	ctx := ctxWithRoles(t, "admin-1", []string{"site-admin"})
	out, err := resolvers.MovePolicy(ctx, client, "pol-1", "grp-2")
	if err != nil {
		t.Fatalf("MovePolicy: %v", err)
	}
	if out.Number != "POL-FIN-000004" {
		t.Fatalf("number not mapped: got %q", out.Number)
	}
	if client.lastMove.GetActorUserId() != "admin-1" {
		t.Fatalf("actor not bound from claims; got %q", client.lastMove.GetActorUserId())
	}
}

// draftPointerEnv builds a policy "pol" in category CAT with a current draft
// version, an everyone-read rule (so any reader may READ the policy) and the
// given extra rules (e.g. an author grant to make a specific user an editor).
// versions is pre-populated with a DRAFT and a PUBLISHED version so createdAt
// resolution / version reads have something to fetch.
func draftPointerEnv(extra []*corev1.CategoryRule) (*fakePolicyClient, *raciCategoryClient) {
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol": {
				Id:                        "pol",
				HomeCategoryId:            "g-cat",
				Number:                    "POL-CAT-1",
				Title:                     "P",
				OwnerUserId:               "creator-other",
				CurrentDraftVersionId:     "draft-1",
				CurrentPublishedVersionId: "pub-1",
			},
		},
		versions: map[string]*corev1.PolicyVersion{
			"draft-1": {Id: "draft-1", PolicyId: "pol", VersionNo: 2, Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT, ContentJson: `{"root":{"secret":"draft"}}`},
			"pub-1":   {Id: "pub-1", PolicyId: "pol", VersionNo: 1, Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED, ContentJson: `{"root":{"public":"pub"}}`},
		},
	}
	rules := append([]*corev1.CategoryRule{allowEveryoneRule()}, extra...)
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT", ParentId: ""}},
		map[string][]*corev1.CategoryRule{"g-cat": rules},
	)
	return pc, gc
}

// TestGetPolicy_DraftPointer_HiddenFromNonEditor verifies a read-only
// viewer (read via everyone-allow, NO author grant) sees the policy but its
// currentDraftVersionId is omitted (the draft's existence is oversight-only).
func TestGetPolicy_DraftPointer_HiddenFromNonEditor(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u", RolesValue: []string{"reader"}})

	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil || p.ViewerCan.Edit {
		t.Fatalf("read-only viewer must have edit=false; got %+v", p.ViewerCan)
	}
	if p.CurrentDraftVersionID != nil {
		t.Fatalf("non-editor must NOT see currentDraftVersionId; got %q", *p.CurrentDraftVersionID)
	}
}

// TestGetPolicy_DraftPointer_VisibleToEditor verifies a viewer WITH
// edit (a non-denied category author) keeps currentDraftVersionId so the
// authoring UI can load the draft.
func TestGetPolicy_DraftPointer_VisibleToEditor(t *testing.T) {
	pc, gc := draftPointerEnv([]*corev1.CategoryRule{authorRule("editor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "editor-u", RolesValue: []string{"reader"}})

	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.ViewerCan == nil || !p.ViewerCan.Edit {
		t.Fatalf("category author must have edit=true; got %+v", p.ViewerCan)
	}
	if p.CurrentDraftVersionID == nil || *p.CurrentDraftVersionID != "draft-1" {
		t.Fatalf("editor must see currentDraftVersionId=draft-1; got %v", p.CurrentDraftVersionID)
	}
}

// TestListPolicies_DraftPointer_HiddenFromNonEditor verifies the same omission
// applies on the LIST read model path, not only detail.
func TestListPolicies_DraftPointer_HiddenFromNonEditor(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	pc.listResult = []string{"pol"}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u", RolesValue: []string{"reader"}})

	out, err := resolvers.ListPolicies(ctx, pc, gc, nil, nil, "g-cat", new(true), nil)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(out) != 1 || out[0].ID != "pol" {
		t.Fatalf("expected the policy visible in list; got %+v", out)
	}
	if out[0].CurrentDraftVersionID != nil {
		t.Fatalf("non-editor list row must omit currentDraftVersionId; got %q", *out[0].CurrentDraftVersionID)
	}
}

// TestGetPolicyVersion_DraftDeniedToNonEditor verifies a read-only
// viewer who knows (or guesses) a draft version id cannot fetch it — the draft is
// oversight-only, so a non-editor gets NotFound (never the draft body).
func TestGetPolicyVersion_DraftDeniedToNonEditor(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u", RolesValue: []string{"reader"}})

	if _, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, "draft-1"); status.Code(err) != codes.NotFound {
		t.Fatalf("non-editor must not read a DRAFT version; want NotFound, got %v", err)
	}
}

// TestGetPolicyVersion_DraftReadableByEditor verifies a viewer WITH edit (a
// non-denied category author) can read the draft version content.
func TestGetPolicyVersion_DraftReadableByEditor(t *testing.T) {
	pc, gc := draftPointerEnv([]*corev1.CategoryRule{authorRule("editor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "editor-u", RolesValue: []string{"reader"}})

	v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, "draft-1")
	if err != nil {
		t.Fatalf("editor GetPolicyVersion(draft): %v", err)
	}
	if v.ContentJSON != `{"root":{"secret":"draft"}}` {
		t.Fatalf("editor must get real draft content; got %q", v.ContentJSON)
	}
}

// TestGetPolicyVersion_PublishedReadableByReader verifies a PUBLISHED version is
// still readable by a normal reader (the draft gate applies only to drafts).
func TestGetPolicyVersion_PublishedReadableByReader(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u", RolesValue: []string{"reader"}})

	v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, "pub-1")
	if err != nil {
		t.Fatalf("reader GetPolicyVersion(published): %v", err)
	}
	if v.ContentJSON != `{"root":{"public":"pub"}}` {
		t.Fatalf("reader must get real published content; got %q", v.ContentJSON)
	}
}

// TestSetPolicyTemplate_EditGate verifies setPolicyTemplate is gated
// on the effective-author (edit) model. A non-editor is denied and core is never
// called; an editor is allowed and the actor is bound from claims.
func TestSetPolicyTemplate_EditGate(t *testing.T) {
	t.Run("non-editor denied, core untouched", func(t *testing.T) {
		// stranger has read (everyone-allow) but no author grant → not an editor.
		pc, gc := draftPointerEnv(nil)
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}})

		tmpl := "tmpl-9"
		_, err := resolvers.SetPolicyTemplate(ctx, pc, gc, "pol", &tmpl, false)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("non-editor must be denied; want PermissionDenied, got %v", err)
		}
		if pc.lastSetTmpl != nil {
			t.Fatal("core SetPolicyTemplate must NOT be called when denied")
		}
	})

	t.Run("editor allowed, actor bound", func(t *testing.T) {
		pc, gc := draftPointerEnv([]*corev1.CategoryRule{authorRule("editor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "editor-u", RolesValue: []string{"reader"}})

		tmpl := "tmpl-9"
		got, err := resolvers.SetPolicyTemplate(ctx, pc, gc, "pol", &tmpl, false)
		if err != nil {
			t.Fatalf("editor SetPolicyTemplate: %v", err)
		}
		if pc.lastSetTmpl == nil {
			t.Fatal("expected core SetPolicyTemplate to be called for an editor")
		}
		if pc.lastSetTmpl.GetActorUserId() != "editor-u" {
			t.Fatalf("actor must be bound from claims; got %q", pc.lastSetTmpl.GetActorUserId())
		}
		if pc.lastSetTmpl.GetTemplateId() != "tmpl-9" {
			t.Fatalf("template id forwarded; got %q", pc.lastSetTmpl.GetTemplateId())
		}
		if got == nil {
			t.Fatal("expected a policy back")
		}
	})
}

// docTypePtr returns a pointer to the provided DocumentType (test helper).
//
//go:fix inline
func docTypePtr(d resolvers.DocumentType) *resolvers.DocumentType { return new(d) }

// TestListPolicies_ForwardsDocumentTypeFilter verifies the documentType filter
// is forwarded to the core ListPolicies request: an explicit PROCEDURE
// filter maps to DOCUMENT_TYPE_PROCEDURE, and a nil filter maps to UNSPECIFIED
// (policies-only back-compat, spec §2.8).
func TestListPolicies_ForwardsDocumentTypeFilter(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{"g-it": {Id: "g-it", Name: "IT", ParentId: ""}},
		map[string][]*corev1.CategoryRule{"g-it": {allowEveryoneRule()}},
	)
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1"},
		},
		listResult: []string{"pol-it"},
	}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "r", RolesValue: []string{"reader"}})

	// Explicit PROCEDURE filter → proto DOCUMENT_TYPE_PROCEDURE.
	if _, err := resolvers.ListPolicies(ctx, pc, groups, nil, nil, "g-it", new(true), docTypePtr(resolvers.DocumentTypeProcedure)); err != nil {
		t.Fatalf("ListPolicies(PROCEDURE): %v", err)
	}
	if pc.lastList == nil {
		t.Fatal("expected core ListPolicies to be called")
	}
	if pc.lastList.GetDocumentType() != corev1.DocumentType_DOCUMENT_TYPE_PROCEDURE {
		t.Fatalf("PROCEDURE filter must forward DOCUMENT_TYPE_PROCEDURE; got %v", pc.lastList.GetDocumentType())
	}

	// nil filter → proto UNSPECIFIED (policies-only back-compat).
	if _, err := resolvers.ListPolicies(ctx, pc, groups, nil, nil, "g-it", new(true), nil); err != nil {
		t.Fatalf("ListPolicies(nil): %v", err)
	}
	if pc.lastList.GetDocumentType() != corev1.DocumentType_DOCUMENT_TYPE_UNSPECIFIED {
		t.Fatalf("nil filter must forward DOCUMENT_TYPE_UNSPECIFIED; got %v", pc.lastList.GetDocumentType())
	}
}

// TestPolicyFromProto_MapsDocumentType verifies the read model maps the proto
// document_type onto the GQL Policy.documentType: PROCEDURE surfaces as
// PROCEDURE, and the UNSPECIFIED wire default maps to POLICY (back-compat).
// Exercised through the exported GetPolicy path (policyFromProto is unexported).
func TestPolicyFromProto_MapsDocumentType(t *testing.T) {
	groups := newRaciReadClient(
		map[string]*corev1.Category{"g-it": {Id: "g-it", Name: "IT", ParentId: ""}},
		map[string][]*corev1.CategoryRule{"g-it": {allowEveryoneRule()}},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-proc": {Id: "pol-proc", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "Proc", CurrentPublishedVersionId: "v1", DocumentType: corev1.DocumentType_DOCUMENT_TYPE_PROCEDURE},
		"pol-uns":  {Id: "pol-uns", HomeCategoryId: "g-it", Number: "POL-IT-2", Title: "Legacy", CurrentPublishedVersionId: "v2"}, // UNSPECIFIED wire default
	}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "r", RolesValue: []string{"reader"}})

	proc, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-proc")
	if err != nil {
		t.Fatalf("GetPolicy(proc): %v", err)
	}
	if proc.DocumentType != resolvers.DocumentTypeProcedure {
		t.Fatalf("proto PROCEDURE must map to GQL PROCEDURE; got %v", proc.DocumentType)
	}

	uns, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-uns")
	if err != nil {
		t.Fatalf("GetPolicy(unspecified): %v", err)
	}
	if uns.DocumentType != resolvers.DocumentTypePolicy {
		t.Fatalf("proto UNSPECIFIED must map to GQL POLICY; got %v", uns.DocumentType)
	}
}

// TestReindexPolicy_AdminGatedAndForwardsActor asserts the reindex resolver is
// site-admin gated and forwards the caller as actor_user_id.
func TestReindexPolicy_AdminGatedAndForwardsActor(t *testing.T) {
	pc := &fakePolicyClient{}

	// Non-admin is refused and no RPC is made.
	if _, err := resolvers.ReindexPolicy(ctxWithRoles(t, "u", []string{"author"}), pc, "pol-1"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin: want PermissionDenied, got %v (code %s)", err, status.Code(err))
	}
	if pc.lastReindexPolicy != nil {
		t.Fatal("non-admin must not reach core")
	}

	// Site-admin succeeds; actor forwarded; result mapped from proto.
	res, err := resolvers.ReindexPolicy(ctxWithRoles(t, "admin-u", []string{"site-admin"}), pc, "pol-1")
	if err != nil {
		t.Fatalf("ReindexPolicy: %v", err)
	}
	if pc.lastReindexPolicy.GetPolicyId() != "pol-1" || pc.lastReindexPolicy.GetActorUserId() != "admin-u" {
		t.Fatalf("forwarded req: got policy=%q actor=%q", pc.lastReindexPolicy.GetPolicyId(), pc.lastReindexPolicy.GetActorUserId())
	}
	if res.VersionID != "ver-1" || res.Sections != 3 || res.RemovedPrior != 1 {
		t.Fatalf("result mapping: %+v", res)
	}
}

// TestReindexPolicyVersion_AdminGatedAndForwardsActor mirrors the above for the
// per-version resolver.
func TestReindexPolicyVersion_AdminGatedAndForwardsActor(t *testing.T) {
	pc := &fakePolicyClient{}

	if _, err := resolvers.ReindexPolicyVersion(ctxWithRoles(t, "u", []string{"author"}), pc, "ver-9"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin: want PermissionDenied, got %v (code %s)", err, status.Code(err))
	}
	if pc.lastReindexVersion != nil {
		t.Fatal("non-admin must not reach core")
	}

	res, err := resolvers.ReindexPolicyVersion(ctxWithRoles(t, "admin-u", []string{"site-admin"}), pc, "ver-9")
	if err != nil {
		t.Fatalf("ReindexPolicyVersion: %v", err)
	}
	if pc.lastReindexVersion.GetPolicyVersionId() != "ver-9" || pc.lastReindexVersion.GetActorUserId() != "admin-u" {
		t.Fatalf("forwarded req: got version=%q actor=%q", pc.lastReindexVersion.GetPolicyVersionId(), pc.lastReindexVersion.GetActorUserId())
	}
	if res.VersionID != "ver-9" || res.Sections != 2 {
		t.Fatalf("result mapping: %+v", res)
	}
}
