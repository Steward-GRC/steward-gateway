// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

var errLabelUnused = errors.New("label fake: method not used")

type labelIdentityFake struct {
	identityv1.IdentityReadServiceClient
	users     map[string]*identityv1.User // user id -> user (missing = NotFound-ish)
	getUserN  int
	getUserMu []string // ids requested, in order
}

func (f *labelIdentityFake) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	f.getUserN++
	f.getUserMu = append(f.getUserMu, in.GetUserId())
	u, ok := f.users[in.GetUserId()]
	if !ok {
		return nil, errors.New("not found")
	}
	return &identityv1.GetUserResponse{User: u}, nil
}

type labelGroupFake struct {
	corev1.CategoryServiceClient
	groups map[string]string // group id -> name
}

func (f *labelGroupFake) GetCategory(_ context.Context, in *corev1.GetCategoryRequest, _ ...grpc.CallOption) (*corev1.GetCategoryResponse, error) {
	name, ok := f.groups[in.GetId()]
	if !ok {
		return nil, errors.New("not found")
	}
	return &corev1.GetCategoryResponse{Category: &corev1.Category{Id: in.GetId(), Name: name}}, nil
}

type labelPolicyFake struct {
	corev1.PolicyServiceClient
	policies map[string]*corev1.Policy        // policy id -> policy
	versions map[string]*corev1.PolicyVersion // version id -> version
}

func (f *labelPolicyFake) GetPolicy(_ context.Context, in *corev1.GetPolicyRequest, _ ...grpc.CallOption) (*corev1.GetPolicyResponse, error) {
	p, ok := f.policies[in.GetId()]
	if !ok {
		return nil, errors.New("not found")
	}
	return &corev1.GetPolicyResponse{Policy: p}, nil
}
func (f *labelPolicyFake) GetPolicyVersion(_ context.Context, in *corev1.GetPolicyVersionRequest, _ ...grpc.CallOption) (*corev1.GetPolicyVersionResponse, error) {
	v, ok := f.versions[in.GetId()]
	if !ok {
		return nil, errors.New("not found")
	}
	return &corev1.GetPolicyVersionResponse{Version: v}, nil
}

type labelTemplateFake struct {
	corev1.TemplateServiceClient
	templates []*corev1.Template                   // all templates (ListTemplates)
	versions  map[string][]*corev1.TemplateVersion // template id -> versions
}

func (f *labelTemplateFake) ListTemplates(context.Context, *corev1.ListTemplatesRequest, ...grpc.CallOption) (*corev1.ListTemplatesResponse, error) {
	return &corev1.ListTemplatesResponse{Templates: f.templates}, nil
}
func (f *labelTemplateFake) ListTemplateVersions(_ context.Context, in *corev1.ListTemplateVersionsRequest, _ ...grpc.CallOption) (*corev1.ListTemplateVersionsResponse, error) {
	return &corev1.ListTemplateVersionsResponse{Versions: f.versions[in.GetTemplateId()]}, nil
}

func auditClientWith(records ...*auditv1.AuditRecord) *fakeAuditClient {
	return &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{Records: records}}
}

func TestAuditLogEnrichesLabels(t *testing.T) {
	identity := &labelIdentityFake{users: map[string]*identityv1.User{
		"u-1": {Id: "u-1", Name: "Alice Example"},
		"u-2": {Id: "u-2", Email: "grace@example.org"}, // no name -> email fallback
	}}
	groups := &labelGroupFake{groups: map[string]string{"g-1": "Information Technology"}}
	policies := &labelPolicyFake{
		policies: map[string]*corev1.Policy{"p-1": {Id: "p-1", Number: "POL-0012", Title: "Acceptable Use"}},
		versions: map[string]*corev1.PolicyVersion{"pv-1": {Id: "pv-1", PolicyId: "p-1"}},
	}
	tmpls := &labelTemplateFake{
		templates: []*corev1.Template{{Id: "t-1", Name: "Security Baseline", Code: "TPL-SEC"}},
		versions:  map[string][]*corev1.TemplateVersion{"t-1": {{Id: "tv-9", TemplateId: "t-1", VersionNo: 5}}},
	}

	ctx := ctxWithRoles(t, "auditor-1", []string{"site-admin"})
	client := auditClientWith(
		&auditv1.AuditRecord{Id: 1, ActorUserId: "u-1", GroupId: "g-1", Subject: "policy_version:pv-1"},
		&auditv1.AuditRecord{Id: 2, ActorUserId: "u-2", GroupId: "g-1", Subject: "group:g-1"},
		&auditv1.AuditRecord{Id: 3, ActorUserId: "u-1", GroupId: "g-1", Subject: "template_version:tv-9"},
	)

	out, err := resolvers.QueryAuditLogResolver(ctx, client, identity, groups, policies, tmpls,
		nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	if len(out.Records) != 3 {
		t.Fatalf("records: %d", len(out.Records))
	}

	r0 := out.Records[0]
	if r0.ActorName == nil || *r0.ActorName != "Alice Example" {
		t.Fatalf("r0 actorName: %v", r0.ActorName)
	}
	if r0.GroupName == nil || *r0.GroupName != "Information Technology" {
		t.Fatalf("r0 groupName: %v", r0.GroupName)
	}
	// policy_version subject -> document-type-aware number + version note
	// (gateway#62). p-1 has no document_type -> defaults to Policy.
	if r0.SubjectLabel == nil || *r0.SubjectLabel != "Policy POL-0012 (version)" {
		t.Fatalf("r0 subjectLabel: %v", r0.SubjectLabel)
	}

	r1 := out.Records[1]
	if r1.ActorName == nil || *r1.ActorName != "grace@example.org" {
		t.Fatalf("r1 actorName (email fallback): %v", r1.ActorName)
	}
	if r1.SubjectLabel == nil || *r1.SubjectLabel != "Information Technology" {
		t.Fatalf("r1 subjectLabel (group): %v", r1.SubjectLabel)
	}

	r2 := out.Records[2]
	if r2.SubjectLabel == nil || *r2.SubjectLabel != "Security Baseline (TPL-SEC) v5" {
		t.Fatalf("r2 subjectLabel (template version): %v", r2.SubjectLabel)
	}

	// Dedupe: u-1 appears on records 0 and 2 but must be fetched once.
	uCount := 0
	for _, id := range identity.getUserMu {
		if id == "u-1" {
			uCount++
		}
	}
	if uCount != 1 {
		t.Fatalf("u-1 GetUser calls: got %d, want 1 (dedupe)", uCount)
	}
}

func TestAuditLogFallsBackOnMiss(t *testing.T) {
	// Unresolvable ids: unknown user, unknown group, unparseable subject.
	identity := &labelIdentityFake{users: map[string]*identityv1.User{}}
	groups := &labelGroupFake{groups: map[string]string{}}
	policies := &labelPolicyFake{}
	tmpls := &labelTemplateFake{}

	ctx := ctxWithRoles(t, "auditor-1", []string{"site-admin"})
	client := auditClientWith(
		&auditv1.AuditRecord{Id: 1, ActorUserId: "u-missing", GroupId: "g-missing", Subject: "policy_version:pv-missing"},
	)
	out, err := resolvers.QueryAuditLogResolver(ctx, client, identity, groups, policies, tmpls,
		nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	r := out.Records[0]
	// All label fields nil -> client renders the raw id. Raw ids still present.
	if r.ActorName != nil || r.GroupName != nil || r.SubjectLabel != nil {
		t.Fatalf("expected nil labels on miss: actor=%v group=%v subject=%v", r.ActorName, r.GroupName, r.SubjectLabel)
	}
	if r.ActorUserID != "u-missing" || r.GroupID != "g-missing" || r.Subject != "policy_version:pv-missing" {
		t.Fatalf("raw ids should survive: %+v", r)
	}
}

func TestAuditLogNilClientsDoNotError(t *testing.T) {
	// Offline / dev mode: no identity/core clients wired. Page must still render
	// (no labels), never error.
	ctx := ctxWithRoles(t, "auditor-1", []string{"site-admin"})
	client := auditClientWith(&auditv1.AuditRecord{Id: 1, ActorUserId: "u-1", GroupId: "g-1", Subject: "group:g-1"})
	out, err := resolvers.QueryAuditLogResolver(ctx, client, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("QueryAuditLog with nil clients: %v", err)
	}
	if out.Records[0].ActorName != nil {
		t.Fatalf("expected nil actorName with nil identity client")
	}
}

func TestAuditLogUntypedSubjectPassesThrough(t *testing.T) {
	identity := &labelIdentityFake{users: map[string]*identityv1.User{}}
	ctx := ctxWithRoles(t, "auditor-1", []string{"site-admin"})
	// A legacy, already-readable subject ("POL-0012") with no "type:uuid" shape
	// is surfaced unchanged as the label.
	client := auditClientWith(&auditv1.AuditRecord{Id: 1, Subject: "POL-0012"})
	out, err := resolvers.QueryAuditLogResolver(ctx, client, identity, nil, nil, nil,
		nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	if out.Records[0].SubjectLabel == nil || *out.Records[0].SubjectLabel != "POL-0012" {
		t.Fatalf("untyped subject should pass through: %v", out.Records[0].SubjectLabel)
	}
}

// TestAuditLogPolicySubjectsAreDocTypeAware pins the gateway#62 behaviour: a
// policy / policy_version subject enriches to a document-type-aware label built
// from the human NUMBER (never the raw version uuid), and a version subject is
// noted as such.
func TestAuditLogPolicySubjectsAreDocTypeAware(t *testing.T) {
	identity := &labelIdentityFake{users: map[string]*identityv1.User{}}
	policies := &labelPolicyFake{
		policies: map[string]*corev1.Policy{
			// Explicit POLICY.
			"pol": {Id: "pol", Number: "POL-0012", Title: "Acceptable Use", DocumentType: corev1.DocumentType_DOCUMENT_TYPE_POLICY},
			// PROCEDURE.
			"prc": {Id: "prc", Number: "PRC-0003", Title: "Desk Booking Policy", DocumentType: corev1.DocumentType_DOCUMENT_TYPE_PROCEDURE},
			// Unspecified document type -> treated as a policy (back-compat).
			"uns": {Id: "uns", Number: "POL-0099", Title: "Legacy"},
			// Unnumbered draft -> title fallback, still human (no raw uuid).
			"draft": {Id: "draft", Title: "New Draft", DocumentType: corev1.DocumentType_DOCUMENT_TYPE_PROCEDURE},
		},
		versions: map[string]*corev1.PolicyVersion{
			"v-pol": {Id: "v-pol", PolicyId: "pol"},
			"v-prc": {Id: "v-prc", PolicyId: "prc"},
		},
	}

	ctx := ctxWithRoles(t, "auditor-1", []string{"site-admin"})
	client := auditClientWith(
		&auditv1.AuditRecord{Id: 1, Subject: "policy:pol"},
		&auditv1.AuditRecord{Id: 2, Subject: "policy:prc"},
		&auditv1.AuditRecord{Id: 3, Subject: "policy:uns"},
		&auditv1.AuditRecord{Id: 4, Subject: "policy:draft"},
		&auditv1.AuditRecord{Id: 5, Subject: "policy_version:v-pol"},
		&auditv1.AuditRecord{Id: 6, Subject: "policy_version:v-prc"},
	)

	out, err := resolvers.QueryAuditLogResolver(ctx, client, identity, nil, policies, nil,
		nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}

	want := []string{
		"Policy POL-0012",
		"Procedure PRC-0003",
		"Policy POL-0099",
		"Procedure: New Draft",
		"Policy POL-0012 (version)",
		"Procedure PRC-0003 (version)",
	}
	for i, w := range want {
		got := out.Records[i].SubjectLabel
		if got == nil || *got != w {
			t.Fatalf("record %d subjectLabel: got %v, want %q", i+1, got, w)
		}
	}
}

func TestAssignmentHistoryResolvesActorNames(t *testing.T) {
	identity := &labelIdentityFake{users: map[string]*identityv1.User{
		"u1":    {Id: "u1", Name: "Alice Example"},
		"u2":    {Id: "u2", Name: "Grace Example"},
		"admin": {Id: "admin", Name: "Root Admin"},
	}}
	c := &fakeWorkflowClient{
		historyResp: &workflowv1.GetAssignmentHistoryResponse{
			Entries: []*workflowv1.AssignmentHistoryEntry{
				{Id: 42, AssignmentId: "a1", Event: "created", ActorUserId: "u1"},
				{Id: 43, AssignmentId: "a1", Event: "swapped_out", ActorUserId: "admin", PreviousUserId: "u1", NewUserId: "u2"},
			},
		},
	}
	out, err := resolvers.AssignmentHistoryResolver(
		ctxWithClaims(t, "admin", "site-admin"), c, identity, nil, "pv-1", 0,
	)
	if err != nil {
		t.Fatalf("AssignmentHistory: %v", err)
	}
	if out[0].ActorName == nil || *out[0].ActorName != "Alice Example" {
		t.Fatalf("entry0 actorName: %v", out[0].ActorName)
	}
	if out[1].ActorName == nil || *out[1].ActorName != "Root Admin" {
		t.Fatalf("entry1 actorName: %v", out[1].ActorName)
	}
	if out[1].PreviousUserName == nil || *out[1].PreviousUserName != "Alice Example" {
		t.Fatalf("entry1 previousUserName: %v", out[1].PreviousUserName)
	}
	if out[1].NewUserName == nil || *out[1].NewUserName != "Grace Example" {
		t.Fatalf("entry1 newUserName: %v", out[1].NewUserName)
	}
	// u1 appears as actor on entry0 and previous on entry1 -> one GetUser only.
	u1Count := 0
	for _, id := range identity.getUserMu {
		if id == "u1" {
			u1Count++
		}
	}
	if u1Count != 1 {
		t.Fatalf("u1 GetUser calls: got %d, want 1 (dedupe)", u1Count)
	}
}

func TestAssignmentHistoryActorNameNilOnMiss(t *testing.T) {
	identity := &labelIdentityFake{users: map[string]*identityv1.User{}}
	c := &fakeWorkflowClient{
		historyResp: &workflowv1.GetAssignmentHistoryResponse{
			Entries: []*workflowv1.AssignmentHistoryEntry{
				{Id: 1, AssignmentId: "a1", Event: "created", ActorUserId: "u-unknown"},
			},
		},
	}
	out, err := resolvers.AssignmentHistoryResolver(
		ctxWithClaims(t, "admin", "site-admin"), c, identity, nil, "pv-1", 0,
	)
	if err != nil {
		t.Fatalf("AssignmentHistory: %v", err)
	}
	if out[0].ActorName != nil {
		t.Fatalf("expected nil actorName on miss, got %v", out[0].ActorName)
	}
	if out[0].ActorUserID != "u-unknown" {
		t.Fatalf("raw actor id should survive: %q", out[0].ActorUserID)
	}
}
