// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- WorkflowDefsResolver (list, ungated) ---

func TestWorkflowDefsResolver_ReturnsList(t *testing.T) {
	c := &fakeWorkflowClient{
		listDefsResp: &workflowv1.ListWorkflowDefsResponse{
			Defs: []*workflowv1.WorkflowDef{
				{Id: "d1", Name: "Standard", Description: "desc", Version: 1, Stages: []*workflowv1.WorkflowStage{
					{Id: "s1", Name: "Review", ApproverIds: []string{"u1"}, Quorum: "all"},
				}},
				{Id: "d2", Name: "Fast Track", Version: 1, Stages: []*workflowv1.WorkflowStage{}},
			},
		},
	}
	out, err := resolvers.WorkflowDefsResolver(context.Background(), c)
	if err != nil {
		t.Fatalf("WorkflowDefsResolver: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 defs, got %d", len(out))
	}
	if out[0].ID != "d1" || out[0].Name != "Standard" {
		t.Fatalf("unexpected first def: %+v", out[0])
	}
	if out[0].Description == nil || *out[0].Description != "desc" {
		t.Fatalf("expected description 'desc'; got %v", out[0].Description)
	}
	if len(out[0].Stages) != 1 {
		t.Fatalf("expected 1 stage on first def; got %d", len(out[0].Stages))
	}
	if out[0].Stages[0].ID != "s1" || out[0].Stages[0].Quorum != "all" {
		t.Fatalf("unexpected stage: %+v", out[0].Stages[0])
	}
	if out[1].Description != nil {
		t.Fatalf("expected nil description for empty proto string; got %v", out[1].Description)
	}
}

func TestWorkflowDefsResolver_EmptyListOK(t *testing.T) {
	c := &fakeWorkflowClient{}
	out, err := resolvers.WorkflowDefsResolver(context.Background(), c)
	if err != nil {
		t.Fatalf("WorkflowDefsResolver: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty list; got %d", len(out))
	}
}

// --- WorkflowDefResolver (get by id, ungated) ---

func TestWorkflowDefResolver_ReturnsNilWhenNotFound(t *testing.T) {
	c := &fakeWorkflowClient{
		getDefResp: &workflowv1.GetWorkflowDefResponse{Def: nil},
	}
	out, err := resolvers.WorkflowDefResolver(context.Background(), c, "missing")
	if err != nil {
		t.Fatalf("WorkflowDefResolver: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil for missing def; got %+v", out)
	}
}

func TestWorkflowDefResolver_MapsOptionalFields(t *testing.T) {
	slaDays := int32(3)
	rejectBreach := true
	pinnedLast := false
	c := &fakeWorkflowClient{
		getDefResp: &workflowv1.GetWorkflowDefResponse{Def: &workflowv1.WorkflowDef{
			Id: "d1", Name: "Full", Version: 2, Stages: []*workflowv1.WorkflowStage{
				{
					Id: "s1", Name: "Stage1", ApproverIds: []string{"u1", "u2"},
					Quorum: "majority", SlaDays: slaDays,
					RejectOnSlaBreach: rejectBreach, PinnedLast: pinnedLast,
				},
			},
		}},
	}
	out, err := resolvers.WorkflowDefResolver(context.Background(), c, "d1")
	if err != nil {
		t.Fatalf("WorkflowDefResolver: %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil def")
	}
	if out.Version != 2 {
		t.Fatalf("version: %d", out.Version)
	}
	s := out.Stages[0]
	if s.SLADays == nil || *s.SLADays != 3 {
		t.Fatalf("SLADays: %v", s.SLADays)
	}
	if s.RejectOnSLABreach == nil || !*s.RejectOnSLABreach {
		t.Fatalf("RejectOnSLABreach: %v", s.RejectOnSLABreach)
	}
	if s.PinnedLast == nil || *s.PinnedLast != false {
		t.Fatalf("PinnedLast: %v", s.PinnedLast)
	}
}

// --- CreateWorkflowDefResolver (requires template-admin or site-admin) ---

func TestCreateWorkflowDefResolver_TemplateAdminSucceeds(t *testing.T) {
	c := &fakeWorkflowClient{}
	desc := "my desc"
	out, err := resolvers.CreateWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"template-admin"}), c,
		"Approval Flow", &desc,
		[]*resolvers.WorkflowStageInput{
			{Name: "Review", Approvers: []string{"u2"}, Quorum: "all"},
		},
	)
	if err != nil {
		t.Fatalf("CreateWorkflowDefResolver: %v", err)
	}
	if out.Name != "Approval Flow" {
		t.Fatalf("unexpected name: %q", out.Name)
	}
	if c.lastCreateDef == nil {
		t.Fatal("expected CreateWorkflowDef to be called")
	}
	if c.lastCreateDef.GetName() != "Approval Flow" {
		t.Fatalf("forwarded name: %q", c.lastCreateDef.GetName())
	}
	if c.lastCreateDef.GetDescription() != "my desc" {
		t.Fatalf("forwarded description: %q", c.lastCreateDef.GetDescription())
	}
	if len(c.lastCreateDef.GetStages()) != 1 {
		t.Fatalf("forwarded stages: %d", len(c.lastCreateDef.GetStages()))
	}
	if c.lastCreateDef.GetStages()[0].GetName() != "Review" {
		t.Fatalf("stage name: %q", c.lastCreateDef.GetStages()[0].GetName())
	}
}

func TestCreateWorkflowDefResolver_SiteAdminSucceeds(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.CreateWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"site-admin"}), c,
		"Flow", nil, []*resolvers.WorkflowStageInput{},
	)
	if err != nil {
		t.Fatalf("CreateWorkflowDefResolver site-admin: %v", err)
	}
}

func TestCreateWorkflowDefResolver_AuthorDenied(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.CreateWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"author"}), c,
		"Flow", nil, []*resolvers.WorkflowStageInput{},
	)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for author; got %v", err)
	}
}

func TestCreateWorkflowDefResolver_Unauthenticated(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.CreateWorkflowDefResolver(
		context.Background(), c, "Flow", nil, []*resolvers.WorkflowStageInput{},
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated; got %v", err)
	}
}

func TestCreateWorkflowDefResolver_NilDescriptionPassedAsEmpty(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.CreateWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"template-admin"}), c,
		"Flow", nil, []*resolvers.WorkflowStageInput{},
	)
	if err != nil {
		t.Fatalf("CreateWorkflowDefResolver: %v", err)
	}
	if c.lastCreateDef.GetDescription() != "" {
		t.Fatalf("nil description should forward as empty string; got %q", c.lastCreateDef.GetDescription())
	}
}

// --- UpdateWorkflowDefResolver ---

func TestUpdateWorkflowDefResolver_TemplateAdminSucceeds(t *testing.T) {
	c := &fakeWorkflowClient{}
	desc := "updated"
	out, err := resolvers.UpdateWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"template-admin"}), c,
		"def-1", "New Name", &desc,
		[]*resolvers.WorkflowStageInput{
			{Name: "Stage A", Approvers: []string{"u3"}, Quorum: "one"},
		},
	)
	if err != nil {
		t.Fatalf("UpdateWorkflowDefResolver: %v", err)
	}
	if out.ID != "def-1" {
		t.Fatalf("id: %q", out.ID)
	}
	if c.lastUpdateDef == nil {
		t.Fatal("expected UpdateWorkflowDef to be called")
	}
	if c.lastUpdateDef.GetId() != "def-1" {
		t.Fatalf("forwarded id: %q", c.lastUpdateDef.GetId())
	}
	if c.lastUpdateDef.GetDescription() != "updated" {
		t.Fatalf("forwarded description: %q", c.lastUpdateDef.GetDescription())
	}
}

func TestUpdateWorkflowDefResolver_AuthorDenied(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.UpdateWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"author"}), c,
		"def-1", "Name", nil, []*resolvers.WorkflowStageInput{},
	)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied; got %v", err)
	}
}

func TestUpdateWorkflowDefResolver_Unauthenticated(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.UpdateWorkflowDefResolver(
		context.Background(), c, "def-1", "Name", nil, []*resolvers.WorkflowStageInput{},
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated; got %v", err)
	}
}

// --- ArchiveWorkflowDefResolver ---

func TestArchiveWorkflowDefResolver_TemplateAdminSucceeds(t *testing.T) {
	c := &fakeWorkflowClient{}
	ok, err := resolvers.ArchiveWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"template-admin"}), c, "def-1",
	)
	if err != nil {
		t.Fatalf("ArchiveWorkflowDefResolver: %v", err)
	}
	if !ok {
		t.Fatal("expected true on success")
	}
	if c.lastArchiveDef == nil || c.lastArchiveDef.GetId() != "def-1" {
		t.Fatalf("expected ArchiveWorkflowDef called with id 'def-1'; got %+v", c.lastArchiveDef)
	}
}

func TestArchiveWorkflowDefResolver_SiteAdminSucceeds(t *testing.T) {
	c := &fakeWorkflowClient{}
	ok, err := resolvers.ArchiveWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"site-admin"}), c, "def-2",
	)
	if err != nil {
		t.Fatalf("ArchiveWorkflowDefResolver: %v", err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestArchiveWorkflowDefResolver_AuthorDenied(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.ArchiveWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"author"}), c, "def-1",
	)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied; got %v", err)
	}
}

func TestArchiveWorkflowDefResolver_Unauthenticated(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.ArchiveWorkflowDefResolver(context.Background(), c, "def-1")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated; got %v", err)
	}
}

// --- per-category approvers (approversByGroup) ---

func TestCreateWorkflowDefResolver_ApproversByCategoryForwardedAsProtoMap(t *testing.T) {
	c := &fakeWorkflowClient{}
	_, err := resolvers.CreateWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"template-admin"}), c,
		"Flow", nil,
		[]*resolvers.WorkflowStageInput{
			{
				Name:   "Review",
				Quorum: "all",
				ApproversByCategory: []*resolvers.CategoryApproversInput{
					{CategoryID: "finance", ApproverIds: []string{"ceo", "owner-fin"}},
					{CategoryID: "it", ApproverIds: []string{"carol"}},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("CreateWorkflowDefResolver: %v", err)
	}
	stage := c.lastCreateDef.GetStages()[0]
	abg := stage.GetApproversByCategory()
	if len(abg) != 2 {
		t.Fatalf("expected 2 group entries; got %d", len(abg))
	}
	if abg["finance"] == nil || len(abg["finance"].GetUserIds()) != 2 ||
		abg["finance"].GetUserIds()[0] != "ceo" || abg["finance"].GetUserIds()[1] != "owner-fin" {
		t.Fatalf("finance approvers: %+v", abg["finance"])
	}
	if abg["it"] == nil || len(abg["it"].GetUserIds()) != 1 || abg["it"].GetUserIds()[0] != "carol" {
		t.Fatalf("it approvers: %+v", abg["it"])
	}
}

func TestWorkflowDefResolver_ApproversByCategoryMappedSorted(t *testing.T) {
	c := &fakeWorkflowClient{
		getDefResp: &workflowv1.GetWorkflowDefResponse{Def: &workflowv1.WorkflowDef{
			Id: "d1", Name: "Full", Version: 1, Stages: []*workflowv1.WorkflowStage{
				{
					Id: "s1", Name: "Review", Quorum: "all",
					ApproversByCategory: map[string]*workflowv1.ApproverList{
						"it":      {UserIds: []string{"carol"}},
						"finance": {UserIds: []string{"ceo", "owner-fin"}},
					},
				},
			},
		}},
	}
	out, err := resolvers.WorkflowDefResolver(context.Background(), c, "d1")
	if err != nil {
		t.Fatalf("WorkflowDefResolver: %v", err)
	}
	abg := out.Stages[0].ApproversByCategory
	if len(abg) != 2 {
		t.Fatalf("expected 2 group entries; got %d", len(abg))
	}
	// Deterministic order: sorted by groupId (finance < it).
	if abg[0].CategoryID != "finance" {
		t.Fatalf("expected first category 'finance' (sorted); got %q", abg[0].CategoryID)
	}
	if len(abg[0].ApproverIds) != 2 || abg[0].ApproverIds[0] != "ceo" || abg[0].ApproverIds[1] != "owner-fin" {
		t.Fatalf("finance approvers: %+v", abg[0].ApproverIds)
	}
	if abg[1].CategoryID != "it" || len(abg[1].ApproverIds) != 1 || abg[1].ApproverIds[0] != "carol" {
		t.Fatalf("it approvers: %+v", abg[1])
	}
}

func TestWorkflowDefResolver_ApproversByCategoryEmptyWhenAbsent(t *testing.T) {
	c := &fakeWorkflowClient{
		getDefResp: &workflowv1.GetWorkflowDefResponse{Def: &workflowv1.WorkflowDef{
			Id: "d1", Name: "Full", Version: 1, Stages: []*workflowv1.WorkflowStage{
				{Id: "s1", Name: "Review", ApproverIds: []string{"u1"}, Quorum: "all"},
			},
		}},
	}
	out, err := resolvers.WorkflowDefResolver(context.Background(), c, "d1")
	if err != nil {
		t.Fatalf("WorkflowDefResolver: %v", err)
	}
	// Non-null list per schema ([GroupApprovers!]!).
	if out.Stages[0].ApproversByCategory == nil {
		t.Fatal("expected non-nil (empty) ApproversByCategory slice")
	}
	if len(out.Stages[0].ApproversByCategory) != 0 {
		t.Fatalf("expected empty ApproversByCategory; got %d", len(out.Stages[0].ApproversByCategory))
	}
}

// --- QuorumAndOptionalInt passthrough ---

func TestCreateWorkflowDefResolver_QuorumPassthrough(t *testing.T) {
	c := &fakeWorkflowClient{}
	slaDays := 5
	rejectBreach := true
	_, err := resolvers.CreateWorkflowDefResolver(
		ctxWithRoles(t, "u1", []string{"template-admin"}), c,
		"Flow", nil,
		[]*resolvers.WorkflowStageInput{
			{Name: "Stage", Approvers: []string{"u1"}, Quorum: "majority", SLADays: &slaDays, RejectOnSLABreach: &rejectBreach},
		},
	)
	if err != nil {
		t.Fatalf("CreateWorkflowDefResolver: %v", err)
	}
	stage := c.lastCreateDef.GetStages()[0]
	if stage.GetQuorum() != "majority" {
		t.Fatalf("quorum: %q", stage.GetQuorum())
	}
	if stage.GetSlaDays() != 5 {
		t.Fatalf("sla_days: %d", stage.GetSlaDays())
	}
	if !stage.GetRejectOnSlaBreach() {
		t.Fatal("reject_on_sla_breach should be true")
	}
}
