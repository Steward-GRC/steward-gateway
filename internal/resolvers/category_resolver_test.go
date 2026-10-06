// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"fmt"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

// fakeCategoryClient is a hand-rolled stub of corev1.CategoryServiceClient used to
// verify that the resolver helpers correctly translate proto responses into
// gqlgen models. Keeping the fake in-package (and minimal) avoids pulling in a
// mocking library for what is fundamentally a thin shim layer.
type fakeCategoryClient struct {
	corev1.CategoryServiceClient
	groups              map[string]*corev1.Category
	lastCreate          *corev1.CreateCategoryRequest
	lastDefaults        *corev1.SetCategoryDefaultsRequest
	lastGovernance      *corev1.SetGovernanceRequest
	effectiveGovernance *corev1.GetEffectiveGovernanceResponse
}

func (f *fakeCategoryClient) GetCategory(_ context.Context, in *corev1.GetCategoryRequest, _ ...grpc.CallOption) (*corev1.GetCategoryResponse, error) {
	g, ok := f.groups[in.Id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", in.Id)
	}
	return &corev1.GetCategoryResponse{Category: g}, nil
}

func (f *fakeCategoryClient) ListCategoryChildren(_ context.Context, in *corev1.ListCategoryChildrenRequest, _ ...grpc.CallOption) (*corev1.ListCategoryChildrenResponse, error) {
	var out []*corev1.Category
	for _, g := range f.groups {
		if g.ParentId == in.ParentId {
			out = append(out, g)
		}
	}
	return &corev1.ListCategoryChildrenResponse{Categories: out}, nil
}

func (f *fakeCategoryClient) CreateCategory(_ context.Context, in *corev1.CreateCategoryRequest, _ ...grpc.CallOption) (*corev1.CreateCategoryResponse, error) {
	f.lastCreate = in
	g := &corev1.Category{Id: "new-id", Name: in.Name, Slug: in.Slug, ParentId: in.ParentId}
	if f.groups == nil {
		f.groups = map[string]*corev1.Category{}
	}
	f.groups[g.Id] = g
	return &corev1.CreateCategoryResponse{Category: g}, nil
}

func (f *fakeCategoryClient) SetCategoryDefaults(_ context.Context, in *corev1.SetCategoryDefaultsRequest, _ ...grpc.CallOption) (*corev1.SetCategoryDefaultsResponse, error) {
	f.lastDefaults = in
	g, ok := f.groups[in.Id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", in.Id)
	}
	g.DefaultTemplateId = in.DefaultTemplateId
	g.DefaultWorkflowId = in.DefaultWorkflowId
	return &corev1.SetCategoryDefaultsResponse{Category: g}, nil
}

func (f *fakeCategoryClient) SetGovernance(_ context.Context, in *corev1.SetGovernanceRequest, _ ...grpc.CallOption) (*corev1.SetGovernanceResponse, error) {
	f.lastGovernance = in
	g, ok := f.groups[in.Id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", in.Id)
	}
	g.Owners = in.Owners
	g.AudienceGroupIds = in.AudienceGroupIds
	g.AckTriggers = in.AckTriggers
	g.ReviewCadence = in.ReviewCadence
	g.ReviewDate = in.ReviewDate
	if in.ExclusionGroupIdsProvided {
		g.ExclusionGroupIds = in.ExclusionGroupIds
		g.ExclusionGroupIdsSet = true
	}
	if in.AudienceGroupIdsProvided {
		g.AudienceGroupIdsSet = true
	}
	return &corev1.SetGovernanceResponse{Category: g}, nil
}

func (f *fakeCategoryClient) RenameCategory(_ context.Context, in *corev1.RenameCategoryRequest, _ ...grpc.CallOption) (*corev1.RenameCategoryResponse, error) {
	g, ok := f.groups[in.Id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", in.Id)
	}
	g.Name = in.Name
	g.Slug = in.Slug
	return &corev1.RenameCategoryResponse{Category: g}, nil
}

func (f *fakeCategoryClient) DeleteCategory(_ context.Context, in *corev1.DeleteCategoryRequest, _ ...grpc.CallOption) (*corev1.DeleteCategoryResponse, error) {
	if _, ok := f.groups[in.Id]; !ok {
		return nil, fmt.Errorf("not found: %s", in.Id)
	}
	delete(f.groups, in.Id)
	return &corev1.DeleteCategoryResponse{Deleted: true}, nil
}

func (f *fakeCategoryClient) MoveCategory(_ context.Context, in *corev1.MoveCategoryRequest, _ ...grpc.CallOption) (*corev1.MoveCategoryResponse, error) {
	g, ok := f.groups[in.CategoryId]
	if !ok {
		return nil, fmt.Errorf("not found: %s", in.CategoryId)
	}
	g.ParentId = in.NewParentId
	return &corev1.MoveCategoryResponse{Category: g, AffectedCount: 1}, nil
}

func (f *fakeCategoryClient) GetEffectiveGovernance(_ context.Context, _ *corev1.GetEffectiveGovernanceRequest, _ ...grpc.CallOption) (*corev1.GetEffectiveGovernanceResponse, error) {
	if f.effectiveGovernance != nil {
		return f.effectiveGovernance, nil
	}
	return &corev1.GetEffectiveGovernanceResponse{}, nil
}

func (f *fakeCategoryClient) GetCategoryRuleset(_ context.Context, _ *corev1.GetCategoryRulesetRequest, _ ...grpc.CallOption) (*corev1.GetCategoryRulesetResponse, error) {
	return &corev1.GetCategoryRulesetResponse{}, nil
}

func (f *fakeCategoryClient) SetCategoryRuleset(_ context.Context, in *corev1.SetCategoryRulesetRequest, _ ...grpc.CallOption) (*corev1.SetCategoryRulesetResponse, error) {
	return &corev1.SetCategoryRulesetResponse{Rules: in.Rules}, nil
}

func TestGetCategoryHappyPath(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"abc": {Id: "abc", Name: "HR", Slug: "hr"},
	}}
	g, err := resolvers.GetCategory(ctxWithRoles(t, "u", []string{"site-admin"}), client, "abc")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if g.ID != "abc" || g.Name != "HR" || g.Slug != "hr" {
		t.Fatalf("unexpected group: %+v", g)
	}
	if g.ParentID != nil {
		t.Fatalf("expected nil ParentID for empty parent_id, got %v", *g.ParentID)
	}
}

func TestGetCategoryNotFoundPropagates(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{}}
	if _, err := resolvers.GetCategory(ctxWithRoles(t, "u", []string{"site-admin"}), client, "missing"); err == nil {
		t.Fatal("expected error for missing group")
	}
}

func TestListCategoryChildrenNilParentTreatedAsRoot(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"root1": {Id: "root1", Name: "Root1", Slug: "root1", ParentId: ""},
		"root2": {Id: "root2", Name: "Root2", Slug: "root2", ParentId: ""},
		"kid":   {Id: "kid", Name: "Kid", Slug: "kid", ParentId: "root1"},
	}}
	roots, err := resolvers.ListCategoryChildren(context.Background(), client, nil)
	if err != nil {
		t.Fatalf("ListGroupChildren: %v", err)
	}
	if len(roots) != 2 {
		t.Fatalf("expected 2 roots, got %d", len(roots))
	}
}

func TestCreateCategoryForwardsParent(t *testing.T) {
	client := &fakeCategoryClient{}
	parent := "p-id"
	g, err := resolvers.CreateCategory(ctxWithRoles(t, "u", []string{"site-admin"}), client, "Eng", "eng", &parent)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if g.Name != "Eng" || g.Slug != "eng" {
		t.Fatalf("unexpected returned group: %+v", g)
	}
	if client.lastCreate == nil || client.lastCreate.ParentId != "p-id" {
		t.Fatalf("expected parent_id 'p-id' forwarded; got %+v", client.lastCreate)
	}
}

func TestSetCategoryDefaultsTranslatesNilToEmpty(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"abc": {Id: "abc", Name: "HR", Slug: "hr"},
	}}
	tmpl := "tmpl-1"
	// SetGroupDefaults requires group.manage; template-admin no longer holds it
	// (dropped in platform fix(authz)). Use site-admin which holds all permissions.
	g, err := resolvers.SetCategoryDefaults(ctxWithRoles(t, "u", []string{"site-admin"}), client, "abc", &tmpl, nil, nil)
	if err != nil {
		t.Fatalf("SetGroupDefaults: %v", err)
	}
	if client.lastDefaults.DefaultTemplateId != "tmpl-1" {
		t.Fatalf("expected default_template_id 'tmpl-1'; got %q", client.lastDefaults.DefaultTemplateId)
	}
	if client.lastDefaults.DefaultWorkflowId != "" {
		t.Fatalf("expected empty default_workflow_id when nil; got %q", client.lastDefaults.DefaultWorkflowId)
	}
	if g.DefaultTemplateID == nil || *g.DefaultTemplateID != "tmpl-1" {
		t.Fatalf("expected returned model DefaultTemplateID 'tmpl-1'; got %v", g.DefaultTemplateID)
	}
	if g.DefaultWorkflowID != nil {
		t.Fatalf("expected nil DefaultWorkflowID; got %v", *g.DefaultWorkflowID)
	}
}

// TestSetCategoryGovernance_EnumMappingAndReturn verifies:
//  1. GQL AckTrigger (ON_CHANGE) maps to proto ACK_TRIGGER_ON_CHANGE on the wire.
//  2. GQL ReviewCadence (ANNUAL) maps to proto REVIEW_CADENCE_ANNUAL on the wire.
//  3. The returned GQL Category surfaces all five governance fields correctly.
//  4. Proto UNSPECIFIED (0) maps back to GQL NONE.
func TestSetCategoryGovernance_EnumMappingAndReturn(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"g1": {Id: "g1", Name: "Eng", Slug: "eng"},
	}}
	reviewDate := "2026-01-01"
	g, err := resolvers.SetCategoryGovernance(ctxWithRoles(t, "u", []string{"site-admin"}), client, "g1",
		[]string{"owner-1"}, []string{"AD-A"}, []string{},
		resolvers.AckTriggerOnChange, resolvers.ReviewCadenceAnnual, &reviewDate, nil)
	if err != nil {
		t.Fatalf("SetGroupGovernance: %v", err)
	}

	// Assert gql→proto enum mapping (wire values sent to gRPC)
	if client.lastGovernance == nil {
		t.Fatal("expected SetGovernance to be called on fake client")
	}
	if client.lastGovernance.AckTriggers != corev1.AckTrigger_ACK_TRIGGER_ON_CHANGE {
		t.Fatalf("gql ON_CHANGE must map to ACK_TRIGGER_ON_CHANGE; got %v", client.lastGovernance.AckTriggers)
	}
	if client.lastGovernance.ReviewCadence != corev1.ReviewCadence_REVIEW_CADENCE_ANNUAL {
		t.Fatalf("gql ANNUAL must map to REVIEW_CADENCE_ANNUAL; got %v", client.lastGovernance.ReviewCadence)
	}
	if len(client.lastGovernance.AudienceGroupIds) != 1 || client.lastGovernance.AudienceGroupIds[0] != "AD-A" {
		t.Fatalf("ad_group_ids not forwarded; got %v", client.lastGovernance.AudienceGroupIds)
	}
	if len(client.lastGovernance.Owners) != 1 || client.lastGovernance.Owners[0] != "owner-1" {
		t.Fatalf("owners not forwarded; got %v", client.lastGovernance.Owners)
	}

	// Assert proto→gql mapping (returned GQL Category)
	if g.AckTriggers != resolvers.AckTriggerOnChange {
		t.Fatalf("returned AckTriggers want ON_CHANGE, got %v", g.AckTriggers)
	}
	if g.ReviewCadence != resolvers.ReviewCadenceAnnual {
		t.Fatalf("returned ReviewCadence want ANNUAL, got %v", g.ReviewCadence)
	}
	if g.ReviewDate == nil || *g.ReviewDate != "2026-01-01" {
		t.Fatalf("returned ReviewDate want 2026-01-01, got %v", g.ReviewDate)
	}
	if len(g.Owners) != 1 || g.Owners[0] != "owner-1" {
		t.Fatalf("returned Owners want [owner-1], got %v", g.Owners)
	}
	if len(g.IdpGroupIds) != 1 || g.IdpGroupIds[0] != "AD-A" {
		t.Fatalf("returned IdpGroupIds want [AD-A], got %v", g.IdpGroupIds)
	}
}

// TestSetCategoryGovernance_ProtoUnspecifiedMapsToNone verifies UNSPECIFIED (0) → GQL NONE.
func TestSetCategoryGovernance_ProtoUnspecifiedMapsToNone(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"g2": {
			Id:            "g2",
			Name:          "Finance",
			Slug:          "finance",
			AckTriggers:   corev1.AckTrigger_ACK_TRIGGER_UNSPECIFIED,
			ReviewCadence: corev1.ReviewCadence_REVIEW_CADENCE_UNSPECIFIED,
		},
	}}
	g, err := resolvers.SetCategoryGovernance(ctxWithRoles(t, "u", []string{"site-admin"}), client, "g2",
		nil, nil, nil,
		resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil)
	if err != nil {
		t.Fatalf("SetGroupGovernance: %v", err)
	}
	// The fake returns the stored group which has UNSPECIFIED; the mapper must treat it as NONE.
	if g.AckTriggers != resolvers.AckTriggerNone {
		t.Fatalf("UNSPECIFIED proto ack_triggers must map to GQL NONE; got %v", g.AckTriggers)
	}
	if g.ReviewCadence != resolvers.ReviewCadenceNone {
		t.Fatalf("UNSPECIFIED proto review_cadence must map to GQL NONE; got %v", g.ReviewCadence)
	}
	if g.ReviewDate != nil {
		t.Fatalf("empty review_date must map to nil; got %v", g.ReviewDate)
	}
}

// TestSetCategoryGovernance_ExclusionGroupsForwarded verifies that
// exclusionGroupIds are forwarded to the proto request with
// ExclusionGroupIdsProvided=true, and that the returned GQL Category
// carries the exclusion groups.
func TestSetCategoryGovernance_ExclusionGroupsForwarded(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"g3": {Id: "g3", Name: "Legal", Slug: "legal"},
	}}
	g, err := resolvers.SetCategoryGovernance(
		ctxWithRoles(t, "u", []string{"site-admin"}), client, "g3",
		[]string{}, []string{"audience-group"}, []string{"excluded-group"},
		resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil,
	)
	if err != nil {
		t.Fatalf("SetGroupGovernance: %v", err)
	}
	// Verify wire: ExclusionGroupIdsProvided and exclusion_group_ids are set.
	if client.lastGovernance == nil {
		t.Fatal("expected SetGovernance to be called on fake client")
	}
	if !client.lastGovernance.ExclusionGroupIdsProvided {
		t.Fatal("ExclusionGroupIdsProvided must be true when exclusionGroupIds is supplied")
	}
	if len(client.lastGovernance.ExclusionGroupIds) != 1 || client.lastGovernance.ExclusionGroupIds[0] != "excluded-group" {
		t.Fatalf("exclusion_group_ids not forwarded; got %v", client.lastGovernance.ExclusionGroupIds)
	}
	// Verify returned model: ExclusionGroupIds is non-nil since ExclusionGroupIdsSet=true.
	if g.ExclusionGroupIds == nil {
		t.Fatal("expected non-nil ExclusionGroupIds in returned Group (ExclusionGroupIdsSet=true)")
	}
	if len(g.ExclusionGroupIds) != 1 || g.ExclusionGroupIds[0] != "excluded-group" {
		t.Fatalf("returned ExclusionGroupIds: want [excluded-group], got %v", g.ExclusionGroupIds)
	}
}

// TestSetCategoryGovernance_NilArgs_ProvidedFalse verifies the T11 fix: when the
// GraphQL client sends null for adGroupIds / exclusionGroupIds (arg is nil), the
// resolver forwards *Provided=false so core leaves the stored (possibly
// inherited) value untouched. This is the case that occurs when a user saves an
// UNRELATED governance field on a group whose audience/exclusion is inherited —
// the inherited value must NOT be rewritten to explicit-empty.
func TestSetCategoryGovernance_NilArgs_ProvidedFalse(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"gnil": {Id: "gnil", Name: "Eng", Slug: "eng"},
	}}
	_, err := resolvers.SetCategoryGovernance(
		ctxWithRoles(t, "u", []string{"site-admin"}), client, "gnil",
		[]string{"owner-1"}, nil, nil,
		resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil,
	)
	if err != nil {
		t.Fatalf("SetGroupGovernance: %v", err)
	}
	if client.lastGovernance == nil {
		t.Fatal("expected SetGovernance to be called on fake client")
	}
	if client.lastGovernance.AudienceGroupIdsProvided {
		t.Fatal("nil adGroupIds must send AudienceGroupIdsProvided=false (keep inherited)")
	}
	if client.lastGovernance.ExclusionGroupIdsProvided {
		t.Fatal("nil exclusionGroupIds must send ExclusionGroupIdsProvided=false (keep inherited)")
	}
}

// TestSetCategoryGovernance_EmptyArgs_ProvidedTrue verifies the other side of the
// tri-state: a non-nil but EMPTY slice is a real "no audience" / "no exclusions"
// override, so *Provided=true is forwarded (distinct from the nil/keep-inherited
// case above).
func TestSetCategoryGovernance_EmptyArgs_ProvidedTrue(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"gempty": {Id: "gempty", Name: "Eng", Slug: "eng"},
	}}
	_, err := resolvers.SetCategoryGovernance(
		ctxWithRoles(t, "u", []string{"site-admin"}), client, "gempty",
		[]string{"owner-1"}, []string{}, []string{},
		resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil,
	)
	if err != nil {
		t.Fatalf("SetGroupGovernance: %v", err)
	}
	if client.lastGovernance == nil {
		t.Fatal("expected SetGovernance to be called on fake client")
	}
	if !client.lastGovernance.AudienceGroupIdsProvided {
		t.Fatal("explicit empty adGroupIds must send AudienceGroupIdsProvided=true (override)")
	}
	if !client.lastGovernance.ExclusionGroupIdsProvided {
		t.Fatal("explicit empty exclusionGroupIds must send ExclusionGroupIdsProvided=true (override)")
	}
}

// TestGetEffectiveGovernance_AudienceSet verifies that when the fake returns
// an audience, the resolver maps it to non-nil AckAudienceGroups.
func TestGetEffectiveGovernance_AudienceSet(t *testing.T) {
	client := &fakeCategoryClient{
		groups: map[string]*corev1.Category{
			"g4": {Id: "g4", Name: "Dept", Slug: "dept"},
		},
		effectiveGovernance: &corev1.GetEffectiveGovernanceResponse{
			AckAudienceGroups: []string{"all-staff"},
			AudienceSet:       true,
			ExclusionSet:      false,
		},
	}
	eg, err := resolvers.GetEffectiveGovernance(
		ctxWithRoles(t, "u", []string{"site-admin"}), client, "g4",
	)
	if err != nil {
		t.Fatalf("GetEffectiveGovernance: %v", err)
	}
	if eg.AckAudienceGroups == nil {
		t.Fatal("expected non-nil AckAudienceGroups when AudienceSet=true")
	}
	if len(eg.AckAudienceGroups) != 1 || eg.AckAudienceGroups[0] != "all-staff" {
		t.Fatalf("AckAudienceGroups: want [all-staff], got %v", eg.AckAudienceGroups)
	}
	if eg.ExclusionGroups != nil {
		t.Fatalf("expected nil ExclusionGroups when ExclusionSet=false, got %v", eg.ExclusionGroups)
	}
}

// TestGetEffectiveGovernance_NothingSet verifies that when neither audience
// nor exclusion is set in the chain, both fields in the response are nil.
func TestGetEffectiveGovernance_NothingSet(t *testing.T) {
	client := &fakeCategoryClient{
		groups: map[string]*corev1.Category{
			"g5": {Id: "g5", Name: "Isolated", Slug: "isolated"},
		},
		effectiveGovernance: &corev1.GetEffectiveGovernanceResponse{
			AudienceSet:  false,
			ExclusionSet: false,
		},
	}
	eg, err := resolvers.GetEffectiveGovernance(
		ctxWithRoles(t, "u", []string{"site-admin"}), client, "g5",
	)
	if err != nil {
		t.Fatalf("GetEffectiveGovernance: %v", err)
	}
	if eg.AckAudienceGroups != nil {
		t.Fatalf("expected nil AckAudienceGroups when AudienceSet=false, got %v", eg.AckAudienceGroups)
	}
	if eg.ExclusionGroups != nil {
		t.Fatalf("expected nil ExclusionGroups when ExclusionSet=false, got %v", eg.ExclusionGroups)
	}
}

// TestSetCategoryGovernance_ExclusionGroupIds_GroupFromProto_Nil verifies that
// when ExclusionGroupIdsSet=false in the returned proto Category, the GQL model
// has nil ExclusionGroupIds (representing "inherit from ancestor").
func TestSetCategoryGovernance_ExclusionGroupIds_GroupFromProto_Nil(t *testing.T) {
	// Fake that does NOT set ExclusionGroupIdsSet on the returned group.
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"g6": {Id: "g6", Name: "Ops", Slug: "ops", ExclusionGroupIdsSet: false},
	}}
	g, err := resolvers.GetCategory(ctxWithRoles(t, "u", []string{"site-admin"}), client, "g6")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if g.ExclusionGroupIds != nil {
		t.Fatalf("expected nil ExclusionGroupIds when ExclusionGroupIdsSet=false; got %v", g.ExclusionGroupIds)
	}
}

// TestCategoryFromProto_IdpGroupIds_NilWhenNotSet verifies that when AudienceGroupIdsSet=false
// in the returned proto Category, the GQL model has nil IdpGroupIds (representing
// "inherit from ancestor"). Mirrors the exclusion handling in
// TestSetCategoryGovernance_ExclusionGroupIds_GroupFromProto_Nil.
func TestCategoryFromProto_IdpGroupIds_NilWhenNotSet(t *testing.T) {
	// Fake that does NOT set AudienceGroupIdsSet on the returned group.
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"ga": {Id: "ga", Name: "Mktg", Slug: "mktg", AudienceGroupIdsSet: false},
	}}
	g, err := resolvers.GetCategory(ctxWithRoles(t, "u", []string{"site-admin"}), client, "ga")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if g.IdpGroupIds != nil {
		t.Fatalf("expected nil IdpGroupIds when AudienceGroupIdsSet=false; got %v", g.IdpGroupIds)
	}
}

// TestCategoryFromProto_IdpGroupIds_NonNilWhenSet verifies that when AudienceGroupIdsSet=true
// in the proto Category, the GQL model has a non-nil IdpGroupIds slice (even when empty).
func TestCategoryFromProto_IdpGroupIds_NonNilWhenSet(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"gb": {Id: "gb", Name: "Legal", Slug: "legal", AudienceGroupIdsSet: true, AudienceGroupIds: []string{}},
	}}
	g, err := resolvers.GetCategory(ctxWithRoles(t, "u", []string{"site-admin"}), client, "gb")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if g.IdpGroupIds == nil {
		t.Fatal("expected non-nil IdpGroupIds when AudienceGroupIdsSet=true (explicit empty override)")
	}
	if len(g.IdpGroupIds) != 0 {
		t.Fatalf("expected empty IdpGroupIds; got %v", g.IdpGroupIds)
	}
}

func TestMoveCategoryForwardsNewParent(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"child": {Id: "child", Name: "Child", Slug: "child", ParentId: "old"},
		"new":   {Id: "new", Name: "New", Slug: "new"},
	}}
	newParent := "new"
	g, err := resolvers.MoveCategory(ctxWithRoles(t, "u", []string{"site-admin"}), client, "child", &newParent)
	if err != nil {
		t.Fatalf("MoveGroup: %v", err)
	}
	if g.ParentID == nil || *g.ParentID != "new" {
		t.Fatalf("expected parent 'new', got %v", g.ParentID)
	}
}

func TestMoveCategoryToRootForwardsEmptyParent(t *testing.T) {
	client := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"child": {Id: "child", Name: "Child", Slug: "child", ParentId: "old"},
	}}
	g, err := resolvers.MoveCategory(ctxWithRoles(t, "u", []string{"site-admin"}), client, "child", nil)
	if err != nil {
		t.Fatalf("MoveGroup to root: %v", err)
	}
	if g.ParentID != nil {
		t.Fatalf("expected nil parent (root), got %v", *g.ParentID)
	}
}
