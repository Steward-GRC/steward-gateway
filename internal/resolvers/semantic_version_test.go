// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// Semantic versions (steward-gateway#66, row 51): policy and template versions
// carry MAJOR.MINOR.FIX and the change type behind it, and the author's pick
// at submit goes through to workflow.

func semver(major, minor, fix int32) *corev1.SemanticVersion {
	return &corev1.SemanticVersion{Major: major, Minor: minor, Fix: fix, Text: ""}
}

func ptrStr(s string) *string { return &s }

// A policy version with the whole change-type story: core's suggestion, the
// author's lowering waiting for the approvers, who set it and who agreed.
func TestPolicyVersion_CarriesSemanticVersionAndChangeType(t *testing.T) {
	pc, gc := draftPointerEnv([]*corev1.CategoryRule{authorRule("editor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	pc.versions["draft-1"].SemanticVersion = &corev1.SemanticVersion{Major: 2, Minor: 1, Fix: 0, Text: "2.1.0"}
	pc.versions["draft-1"].SuggestedChangeType = corev1.ChangeType_CHANGE_TYPE_MAJOR
	pc.versions["draft-1"].ChangeType = corev1.ChangeType_CHANGE_TYPE_MAJOR
	pc.versions["draft-1"].RequestedChangeType = corev1.ChangeType_CHANGE_TYPE_MINOR
	pc.versions["draft-1"].ChangeTypeReason = "wording only"
	pc.versions["draft-1"].ChangeTypeSetBy = "editor-u"
	pc.versions["draft-1"].ChangeTypeAgreedBy = []string{"approver-1", "approver-2"}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "editor-u", RolesValue: []string{"reader"}})

	v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, nil, "draft-1")
	if err != nil {
		t.Fatalf("GetPolicyVersion: %v", err)
	}
	if v.SemanticVersion == nil || *v.SemanticVersion != "2.1.0" {
		t.Fatalf("semanticVersion = %v, want 2.1.0", v.SemanticVersion)
	}
	if v.VersionNo != 2 {
		t.Fatalf("versionNo = %d, want 2 (the ordinal stays)", v.VersionNo)
	}
	if v.SuggestedChangeType == nil || *v.SuggestedChangeType != resolvers.ChangeTypeMajor {
		t.Fatalf("suggestedChangeType = %v, want MAJOR", v.SuggestedChangeType)
	}
	if v.ChangeType == nil || *v.ChangeType != resolvers.ChangeTypeMajor {
		t.Fatalf("changeType = %v, want MAJOR", v.ChangeType)
	}
	if v.RequestedChangeType == nil || *v.RequestedChangeType != resolvers.ChangeTypeMinor {
		t.Fatalf("requestedChangeType = %v, want MINOR", v.RequestedChangeType)
	}
	if v.ChangeTypeReason == nil || *v.ChangeTypeReason != "wording only" {
		t.Fatalf("changeTypeReason = %v", v.ChangeTypeReason)
	}
	if v.ChangeTypeSetByUserID == nil || *v.ChangeTypeSetByUserID != "editor-u" {
		t.Fatalf("changeTypeSetByUserId = %v", v.ChangeTypeSetByUserID)
	}
	if len(v.ChangeTypeAgreedByUserIds) != 2 || v.ChangeTypeAgreedByUserIds[1] != "approver-2" {
		t.Fatalf("changeTypeAgreedByUserIds = %v", v.ChangeTypeAgreedByUserIds)
	}
}

// Core leaves the fields unset for a version published before change types
// were stored (and the first version has no suggestion); the gateway sends
// null, never an invented value, and the agreed list is empty, not null.
func TestPolicyVersion_UnsetSemanticFieldsAreNull(t *testing.T) {
	pc, gc := draftPointerEnv([]*corev1.CategoryRule{authorRule("editor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "editor-u", RolesValue: []string{"reader"}})

	v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, nil, "pub-1")
	if err != nil {
		t.Fatalf("GetPolicyVersion: %v", err)
	}
	if v.SemanticVersion != nil || v.SuggestedChangeType != nil || v.ChangeType != nil || v.RequestedChangeType != nil ||
		v.ChangeTypeReason != nil || v.ChangeTypeSetByUserID != nil {
		t.Fatalf("unset fields must be null, got %+v", v)
	}
	if v.ChangeTypeAgreedByUserIds == nil || len(v.ChangeTypeAgreedByUserIds) != 0 {
		t.Fatalf("changeTypeAgreedByUserIds = %#v, want an empty list", v.ChangeTypeAgreedByUserIds)
	}
}

// One test per change type, so each enum value maps.
func TestPolicyVersion_ChangeTypeMapsEachValue(t *testing.T) {
	cases := map[corev1.ChangeType]resolvers.ChangeType{
		corev1.ChangeType_CHANGE_TYPE_MAJOR: resolvers.ChangeTypeMajor,
		corev1.ChangeType_CHANGE_TYPE_MINOR: resolvers.ChangeTypeMinor,
		corev1.ChangeType_CHANGE_TYPE_FIX:   resolvers.ChangeTypeFix,
	}
	for in, want := range cases {
		pc, gc := draftPointerEnv([]*corev1.CategoryRule{authorRule("editor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
		pc.versions["pub-1"].ChangeType = in
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "editor-u", RolesValue: []string{"reader"}})
		v, err := resolvers.GetPolicyVersion(ctx, pc, gc, nil, nil, "pub-1")
		if err != nil {
			t.Fatalf("%v: %v", in, err)
		}
		if v.ChangeType == nil || *v.ChangeType != want {
			t.Errorf("%v -> %v, want %v", in, v.ChangeType, want)
		}
	}
}

// Template versions: semantic version, the change type a draft would publish
// as, createdAt and publishedAt; and Template.updatedAt.
func TestTemplates_CarryVersionTimestampsAndSemanticVersion(t *testing.T) {
	tc, gc := templateVisibilityEnv("author-a")
	created := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	published := time.Date(2026, 3, 2, 10, 30, 0, 0, time.UTC)
	updated := time.Date(2026, 3, 5, 8, 15, 0, 0, time.UTC)
	tc.templates[0].UpdatedAt = timestamppb.New(updated)
	tc.versions["TPL-A"] = []*corev1.TemplateVersion{
		{Id: "TV-A1", TemplateId: "TPL-A", VersionNo: 1, SemanticVersion: semver(2, 0, 0), ChangeType: corev1.ChangeType_CHANGE_TYPE_MAJOR,
			CreatedAt: timestamppb.New(created), PublishedAt: timestamppb.New(published)},
		{Id: "TV-A2", TemplateId: "TPL-A", VersionNo: 2, SemanticVersion: semver(2, 1, 0), ChangeType: corev1.ChangeType_CHANGE_TYPE_MINOR,
			CreatedAt: timestamppb.New(created)},
	}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-u", RolesValue: []string{"site-admin"}, IsRootValue: true})

	ts, err := resolvers.ListTemplates(ctx, tc, gc, nil)
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	var a, b *resolvers.Template
	for _, x := range ts {
		switch x.ID {
		case "TPL-A":
			a = x
		case "TPL-B":
			b = x
		}
	}
	if a == nil || a.UpdatedAt == nil || *a.UpdatedAt != "2026-03-05T08:15:00Z" {
		t.Fatalf("TPL-A updatedAt = %v, want 2026-03-05T08:15:00Z", a)
	}
	if b == nil || b.UpdatedAt != nil {
		t.Fatalf("TPL-B has no updatedAt in core, want null, got %+v", b)
	}

	vs, err := resolvers.ListTemplateVersions(ctx, tc, gc, "TPL-A")
	if err != nil {
		t.Fatalf("ListTemplateVersions: %v", err)
	}
	if len(vs) != 2 {
		t.Fatalf("got %d versions, want 2", len(vs))
	}
	v1, v2 := vs[0], vs[1]
	if v1.SemanticVersion == nil || *v1.SemanticVersion != "2.0.0" || v1.ChangeType == nil || *v1.ChangeType != resolvers.ChangeTypeMajor {
		t.Fatalf("v1 = %+v, want 2.0.0 MAJOR", v1)
	}
	if v1.VersionNo != 1 {
		t.Fatalf("versionNo = %d, want 1 (kept)", v1.VersionNo)
	}
	if v1.CreatedAt == nil || *v1.CreatedAt != "2026-03-01T09:00:00Z" || v1.PublishedAt == nil || *v1.PublishedAt != "2026-03-02T10:30:00Z" {
		t.Fatalf("v1 timestamps = %v / %v", v1.CreatedAt, v1.PublishedAt)
	}
	if v2.SemanticVersion == nil || *v2.SemanticVersion != "2.1.0" || v2.ChangeType == nil || *v2.ChangeType != resolvers.ChangeTypeMinor {
		t.Fatalf("v2 = %+v, want 2.1.0 MINOR", v2)
	}
	if v2.PublishedAt != nil {
		t.Fatalf("an unpublished version has publishedAt null, got %v", *v2.PublishedAt)
	}
}

// A template version from before the fields existed maps to nulls.
func TestTemplateVersion_UnsetSemanticFieldsAreNull(t *testing.T) {
	tc, gc := templateVisibilityEnv("author-a")
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-u", RolesValue: []string{"site-admin"}, IsRootValue: true})
	vs, err := resolvers.ListTemplateVersions(ctx, tc, gc, "TPL-A")
	if err != nil || len(vs) != 1 {
		t.Fatalf("ListTemplateVersions = %v, %v", vs, err)
	}
	v := vs[0]
	if v.SemanticVersion != nil || v.ChangeType != nil || v.CreatedAt != nil || v.PublishedAt != nil {
		t.Fatalf("unset fields must be null, got %+v", v)
	}
}

// The author's pick and reason at submit reach workflow, enum for enum.
func TestSubmitWorkflow_PassesTheAuthorsChangeType(t *testing.T) {
	cases := map[resolvers.ChangeType]workflowv1.ChangeType{
		resolvers.ChangeTypeMajor: workflowv1.ChangeType_CHANGE_TYPE_MAJOR,
		resolvers.ChangeTypeMinor: workflowv1.ChangeType_CHANGE_TYPE_MINOR,
		resolvers.ChangeTypeFix:   workflowv1.ChangeType_CHANGE_TYPE_FIX,
	}
	for in, want := range cases {
		pc, gc := coAuthMatrixEnv("u-1", nil, nil)
		wf := &fakeWorkflowClient{submitResp: &workflowv1.SubmitResponse{RunId: "run-1"}}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", RolesValue: []string{"policy-author"}})
		pick := in
		res, err := resolvers.SubmitWorkflowResolver(ctx, log.Nop(), wf, gc, pc, "v-1", "pol", "g-cat", nil, &pick, ptrStr("typo fixes only"))
		if err != nil || res == nil {
			t.Fatalf("%v: submit = %+v, %v", in, res, err)
		}
		if wf.lastSubmit.GetChangeType() != want {
			t.Errorf("%v: workflow change type = %v, want %v", in, wf.lastSubmit.GetChangeType(), want)
		}
		if wf.lastSubmit.GetChangeTypeReason() != "typo fixes only" {
			t.Errorf("%v: workflow reason = %q", in, wf.lastSubmit.GetChangeTypeReason())
		}
	}
}

// No pick leaves core's suggestion standing: workflow gets the unset value
// and no reason.
func TestSubmitWorkflow_NoPickLeavesTheSuggestion(t *testing.T) {
	pc, gc := coAuthMatrixEnv("u-1", nil, nil)
	wf := &fakeWorkflowClient{submitResp: &workflowv1.SubmitResponse{RunId: "run-1"}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", RolesValue: []string{"policy-author"}})
	if _, err := resolvers.SubmitWorkflowResolver(ctx, log.Nop(), wf, gc, pc, "v-1", "pol", "g-cat", nil, nil, nil); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if wf.lastSubmit.GetChangeType() != workflowv1.ChangeType_CHANGE_TYPE_UNSPECIFIED || wf.lastSubmit.GetChangeTypeReason() != "" {
		t.Fatalf("want unset pick, got %v / %q", wf.lastSubmit.GetChangeType(), wf.lastSubmit.GetChangeTypeReason())
	}
}
