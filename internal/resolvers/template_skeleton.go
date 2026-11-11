// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Core pins a starting draft to its template version but stores content {} because it has no
// renderer from a template to editor JSON. The gateway builds the skeleton headings here, so a
// new policy, or an untouched draft switched to another template, opens on the template's
// sections (steward-gateway#129, #61).

// CreatePolicyWithSkeleton is CreatePolicy plus the starting headings of the template core
// pinned the new draft to. The skeleton is best effort: the policy exists once core has
// answered, so a failure here is logged and the policy is still returned (with a blank draft).
// The policy comes back through the same read model as the queries, because Policy.viewerCan is
// non-null in the schema and a bare core projection fails the response with INTERNAL (#149).
func CreatePolicyWithSkeleton(ctx context.Context, lg log.Logger, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, templates corev1.TemplateServiceClient, adminClient identityv1.IdentityAdminServiceClient, identity identityv1.IdentityReadServiceClient, workflow workflowv1.WorkflowServiceClient, homeCategoryID, title string, sensitivity Sensitivity, templateID *string, documentType *DocumentType) (*Policy, error) {
	policy, err := CreatePolicy(ctx, client, categoryClient, homeCategoryID, title, sensitivity, templateID, documentType)
	if err != nil {
		return nil, err
	}
	lg.Debug("policy created; seeding the starting skeleton", log.F("policy_id", policy.ID), log.F("template_chosen", templateID != nil && *templateID != ""))
	seedSkeleton(ctx, lg, client, templates, policy)
	visible, err := resolvePolicyReadModel(ctx, []*Policy{policy}, client, categoryClient, adminClient, identity, workflow)
	if err != nil {
		return nil, err
	}
	if len(visible) == 0 {
		// The write has already happened, so this must not look like an empty success.
		err := status.Error(codes.Internal, "created policy is not visible to its creator")
		lg.Error(err, "create policy: the new policy was filtered out of the read model", log.F("policy_id", policy.ID))
		return nil, err
	}
	return visible[0], nil
}

// SetPolicyTemplateWithSkeleton is SetPolicyTemplate plus the starting headings when core
// repinned an untouched draft to a template. Freeform (none) writes nothing: core blanks it.
func SetPolicyTemplateWithSkeleton(ctx context.Context, lg log.Logger, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, templates corev1.TemplateServiceClient, adminClient identityv1.IdentityAdminServiceClient, identity identityv1.IdentityReadServiceClient, workflow workflowv1.WorkflowServiceClient, policyID string, templateID *string, none bool) (*Policy, error) {
	policy, err := SetPolicyTemplate(ctx, client, categoryClient, adminClient, identity, workflow, policyID, templateID, none)
	if err != nil {
		return nil, err
	}
	if none {
		lg.Debug("policy made freeform; no skeleton", log.F("policy_id", policyID))
		return policy, nil
	}
	seedSkeleton(ctx, lg, client, templates, policy)
	return policy, nil
}

// seedSkeleton writes the headings of the policy's effective template into its draft when the
// draft still holds nothing (content empty or {}). A draft with any content is never touched.
func seedSkeleton(ctx context.Context, lg log.Logger, client corev1.PolicyServiceClient, templates corev1.TemplateServiceClient, policy *Policy) {
	if templates == nil || policy == nil || policy.CurrentDraftVersionID == nil || *policy.CurrentDraftVersionID == "" {
		lg.Debug("skeleton skipped: no template client or no draft", log.F("policy_id", policyIDOf(policy)))
		return
	}
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return
	}
	start := time.Now()
	draftID := *policy.CurrentDraftVersionID
	eff, err := client.GetEffectiveTemplate(ctx, &corev1.GetEffectiveTemplateRequest{PolicyId: policy.ID})
	if err != nil {
		lg.Warn("skeleton skipped: effective template lookup failed", log.F("policy_id", policy.ID), log.F("error", err.Error()))
		return
	}
	if eff.GetNone() || eff.GetTemplateId() == "" || eff.GetTemplateVersionId() == "" {
		lg.Debug("skeleton skipped: freeform or no effective template", log.F("policy_id", policy.ID))
		return
	}
	draft, err := client.GetPolicyVersion(ctx, &corev1.GetPolicyVersionRequest{Id: draftID})
	if err != nil {
		lg.Warn("skeleton skipped: draft lookup failed", log.F("policy_id", policy.ID), log.F("error", err.Error()))
		return
	}
	if !draftIsBlank(draft.GetVersion().GetContentJson()) {
		lg.Debug("skeleton skipped: the draft already has content", log.F("policy_id", policy.ID), log.F("version_id", draftID))
		return
	}
	versions, err := templates.ListTemplateVersions(ctx, &corev1.ListTemplateVersionsRequest{TemplateId: eff.GetTemplateId()})
	if err != nil {
		lg.Warn("skeleton skipped: template versions lookup failed", log.F("policy_id", policy.ID), log.F("template_id", eff.GetTemplateId()), log.F("error", err.Error()))
		return
	}
	var sections []*corev1.Section
	found := false
	for _, v := range versions.GetVersions() {
		if v.GetId() == eff.GetTemplateVersionId() {
			sections, found = v.GetSections(), true
			break
		}
	}
	if !found {
		lg.Warn("skeleton skipped: pinned template version not found", log.F("policy_id", policy.ID), log.F("template_version_id", eff.GetTemplateVersionId()))
		return
	}
	content, err := skeletonJSON(sections)
	if err != nil {
		lg.Error(err, "skeleton build failed", log.F("policy_id", policy.ID), log.F("error", err.Error()))
		return
	}
	if _, err := client.SaveDraft(ctx, &corev1.SaveDraftRequest{
		PolicyId:          policy.ID,
		ContentJson:       content,
		TemplateVersionId: eff.GetTemplateVersionId(),
		ActorUserId:       claims.UserID(),
	}); err != nil {
		lg.Warn("skeleton save failed; the draft stays blank", log.F("policy_id", policy.ID), log.F("error", err.Error()))
		return
	}
	lg.Info("starting skeleton written", log.F("policy_id", policy.ID), log.F("template_version_id", eff.GetTemplateVersionId()),
		log.F("sections", len(sections)), log.F("duration_ms", time.Since(start).Milliseconds()))
}

func policyIDOf(p *Policy) string {
	if p == nil {
		return ""
	}
	return p.ID
}

// draftIsBlank reports whether a draft's content is what core seeds: nothing, or {}.
func draftIsBlank(content string) bool {
	c := strings.TrimSpace(content)
	return c == "" || c == "{}" || c == "null"
}

// skeletonJSON is the editor document for a template: an h1 and an empty paragraph per section,
// in section order, the same shape the mock server scaffolds.
func skeletonJSON(sections []*corev1.Section) (string, error) {
	ordered := append([]*corev1.Section(nil), sections...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].GetOrder() < ordered[j].GetOrder() })
	children := make([]map[string]any, 0, len(ordered)*2)
	for _, s := range ordered {
		children = append(children,
			map[string]any{
				"children": []map[string]any{{
					"detail": 0, "format": 0, "mode": "normal", "style": "", "text": s.GetTitle(), "type": "text", "version": 1,
				}},
				"direction": nil, "format": "", "indent": 0, "tag": "h1", "type": "heading", "version": 1,
			},
			map[string]any{
				"children":  []map[string]any{},
				"direction": nil, "format": "", "indent": 0, "textFormat": 0, "textStyle": "", "type": "paragraph", "version": 1,
			},
		)
	}
	doc := map[string]any{"root": map[string]any{
		"children": children, "direction": nil, "format": "", "indent": 0, "type": "root", "version": 1,
	}}
	b, err := json.Marshal(doc)
	return string(b), err
}
