// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"encoding/json"
	"testing"

	log "github.com/Bugs5382/go-log"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// skeletonPolicyFake plays core after PR 72: the new or repinned draft is pinned to the
// effective template and holds content {} until someone saves into it.
type skeletonPolicyFake struct {
	*fakePolicyClient
	effective *corev1.GetEffectiveTemplateResponse
	saves     []*corev1.SaveDraftRequest
	saveErr   error
}

func (f *skeletonPolicyFake) CreatePolicy(ctx context.Context, in *corev1.CreatePolicyRequest, opts ...grpc.CallOption) (*corev1.CreatePolicyResponse, error) {
	resp, err := f.fakePolicyClient.CreatePolicy(ctx, in, opts...)
	if err == nil {
		resp.Policy.CurrentDraftVersionId = "draft-1"
	}
	return resp, err
}

func (f *skeletonPolicyFake) GetEffectiveTemplate(context.Context, *corev1.GetEffectiveTemplateRequest, ...grpc.CallOption) (*corev1.GetEffectiveTemplateResponse, error) {
	return f.effective, nil
}

func (f *skeletonPolicyFake) SetPolicyTemplate(ctx context.Context, in *corev1.SetPolicyTemplateRequest, opts ...grpc.CallOption) (*corev1.SetPolicyTemplateResponse, error) {
	resp, err := f.fakePolicyClient.SetPolicyTemplate(ctx, in, opts...)
	if err == nil {
		resp.Policy.CurrentDraftVersionId = "draft-1"
	}
	return resp, err
}

func (f *skeletonPolicyFake) SaveDraft(ctx context.Context, in *corev1.SaveDraftRequest, opts ...grpc.CallOption) (*corev1.SaveDraftResponse, error) {
	if f.saveErr != nil {
		return nil, f.saveErr
	}
	f.saves = append(f.saves, in)
	return f.fakePolicyClient.SaveDraft(ctx, in, opts...)
}

func skeletonTemplates() *labelTemplateFake {
	section := func(key, title string, order int32) *corev1.Section {
		return &corev1.Section{Key: key, Title: title, Order: order}
	}
	return &labelTemplateFake{versions: map[string][]*corev1.TemplateVersion{
		"tmpl-1": {{Id: "tv-1", TemplateId: "tmpl-1", Sections: []*corev1.Section{
			section("scope", "Scope", 2), section("purpose", "Purpose", 1),
		}}},
		"tmpl-3": {{Id: "tv-3", TemplateId: "tmpl-3", Sections: []*corev1.Section{
			section("intro", "Introduction", 1),
		}}},
	}}
}

func skeletonEnv(draftContent string, effective *corev1.GetEffectiveTemplateResponse) (*skeletonPolicyFake, *raciCategoryClient) {
	pc, gc := draftPointerEnv([]*corev1.CategoryRule{authorRule("bob", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	pc.versions["draft-1"] = &corev1.PolicyVersion{Id: "draft-1", PolicyId: "pol", Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT, ContentJson: draftContent}
	pc.policies["new-pol"] = &corev1.Policy{Id: "new-pol", HomeCategoryId: "g-cat", CurrentDraftVersionId: "draft-1"}
	return &skeletonPolicyFake{fakePolicyClient: pc, effective: effective}, gc
}

// headingTexts reads the heading titles out of the saved editor JSON.
func headingTexts(t *testing.T, content string) []string {
	t.Helper()
	var doc struct {
		Root struct {
			Children []struct {
				Type     string `json:"type"`
				Tag      string `json:"tag"`
				Children []struct {
					Text string `json:"text"`
				} `json:"children"`
			} `json:"children"`
		} `json:"root"`
	}
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatalf("saved content is not editor JSON: %v", err)
	}
	var out []string
	for _, n := range doc.Root.Children {
		if n.Type == "heading" {
			if n.Tag != "h1" {
				t.Fatalf("heading tag = %q, want h1", n.Tag)
			}
			out = append(out, n.Children[0].Text)
		}
	}
	return out
}

func bobCtx(t *testing.T) context.Context {
	return ctxWithStubClaims(t, principal.Static{UserIDValue: "bob", RolesValue: []string{"reader"}})
}

// mock: "the template a new policy starts from is the category's default when none is chosen".
func TestCreatePolicy_StartsFromCategoryDefaultTemplate(t *testing.T) {
	pc, gc := skeletonEnv("{}", &corev1.GetEffectiveTemplateResponse{TemplateId: "tmpl-1", TemplateVersionId: "tv-1"})

	got, err := resolvers.CreatePolicyWithSkeleton(bobCtx(t), log.Nop(), pc, gc, skeletonTemplates(), nil, nil, nil, "g-cat", "Hello", resolvers.SensitivityStandard, nil, nil)
	if err != nil {
		t.Fatalf("CreatePolicyWithSkeleton: %v", err)
	}
	if got == nil || got.ID != "new-pol" {
		t.Fatalf("policy = %+v", got)
	}
	if len(pc.saves) != 1 {
		t.Fatalf("want one skeleton save, got %d", len(pc.saves))
	}
	save := pc.saves[0]
	if save.GetPolicyId() != "new-pol" || save.GetTemplateVersionId() != "tv-1" || save.GetActorUserId() != "bob" {
		t.Fatalf("save = %+v", save)
	}
	if heads := headingTexts(t, save.GetContentJson()); len(heads) != 2 || heads[0] != "Purpose" || heads[1] != "Scope" {
		t.Fatalf("headings = %v, want [Purpose Scope] in section order", heads)
	}
}

// mock: "making a policy freeform: blanks the untouched starting draft" - nothing to write.
func TestSetPolicyTemplate_FreeformWritesNoSkeleton(t *testing.T) {
	pc, gc := skeletonEnv("{}", &corev1.GetEffectiveTemplateResponse{None: true})

	got, err := resolvers.SetPolicyTemplateWithSkeleton(bobCtx(t), log.Nop(), pc, gc, skeletonTemplates(), "pol", nil, true)
	if err != nil {
		t.Fatalf("freeform: %v", err)
	}
	if got == nil || !got.TemplateNone {
		t.Fatalf("policy = %+v, want templateNone", got)
	}
	if pc.lastSetTmpl == nil || !pc.lastSetTmpl.GetNone() {
		t.Fatal("core must be told none=true")
	}
	if len(pc.saves) != 0 {
		t.Fatalf("a freeform draft stays blank, got %d saves", len(pc.saves))
	}
}

// mock: "leaves a draft the author has already written alone".
func TestSetPolicyTemplate_WrittenDraftKeepsItsText(t *testing.T) {
	written := `{"root":{"children":[{"type":"paragraph","children":[{"type":"text","text":"My own words."}]}],"type":"root"}}`
	pc, gc := skeletonEnv(written, &corev1.GetEffectiveTemplateResponse{TemplateId: "tmpl-3", TemplateVersionId: "tv-3"})
	tmpl := "tmpl-3"

	if _, err := resolvers.SetPolicyTemplateWithSkeleton(bobCtx(t), log.Nop(), pc, gc, skeletonTemplates(), "pol", &tmpl, false); err != nil {
		t.Fatalf("SetPolicyTemplateWithSkeleton: %v", err)
	}
	if len(pc.saves) != 0 {
		t.Fatalf("a written draft must not be overwritten, got %d saves", len(pc.saves))
	}
}

// mock: "starts the untouched draft from another template when one is chosen".
func TestSetPolicyTemplate_UntouchedDraftStartsFromChosenTemplate(t *testing.T) {
	pc, gc := skeletonEnv("{}", &corev1.GetEffectiveTemplateResponse{TemplateId: "tmpl-3", TemplateVersionId: "tv-3"})
	tmpl := "tmpl-3"

	got, err := resolvers.SetPolicyTemplateWithSkeleton(bobCtx(t), log.Nop(), pc, gc, skeletonTemplates(), "pol", &tmpl, false)
	if err != nil {
		t.Fatalf("SetPolicyTemplateWithSkeleton: %v", err)
	}
	if got.TemplateID == nil || *got.TemplateID != "tmpl-3" {
		t.Fatalf("templateId = %v", got.TemplateID)
	}
	if len(pc.saves) != 1 || pc.saves[0].GetTemplateVersionId() != "tv-3" || pc.saves[0].GetPolicyId() != "pol" {
		t.Fatalf("saves = %+v", pc.saves)
	}
	if heads := headingTexts(t, pc.saves[0].GetContentJson()); len(heads) != 1 || heads[0] != "Introduction" {
		t.Fatalf("headings = %v", heads)
	}
}

// mock: "is for the policy's authors only" (freeform included).
func TestSetPolicyTemplate_FreeformIsForAuthorsOnly(t *testing.T) {
	pc, gc := skeletonEnv("{}", &corev1.GetEffectiveTemplateResponse{None: true})
	erin := ctxWithStubClaims(t, principal.Static{UserIDValue: "erin", RolesValue: []string{"reader"}})

	_, err := resolvers.SetPolicyTemplateWithSkeleton(erin, log.Nop(), pc, gc, skeletonTemplates(), "pol", nil, true)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if pc.lastSetTmpl != nil || len(pc.saves) != 0 {
		t.Fatal("core must not be called for a non-author")
	}
}

// The policy exists once core answers, so a template read that fails must not fail the create.
func TestCreatePolicy_SkeletonFailureKeepsThePolicy(t *testing.T) {
	pc, gc := skeletonEnv("{}", &corev1.GetEffectiveTemplateResponse{TemplateId: "tmpl-9", TemplateVersionId: "tv-9"})

	got, err := resolvers.CreatePolicyWithSkeleton(bobCtx(t), log.Nop(), pc, gc, skeletonTemplates(), nil, nil, nil, "g-cat", "Hello", resolvers.SensitivityStandard, nil, nil)
	if err != nil || got == nil || got.ID != "new-pol" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if len(pc.saves) != 0 {
		t.Fatalf("unknown template version writes nothing, got %d saves", len(pc.saves))
	}
}
