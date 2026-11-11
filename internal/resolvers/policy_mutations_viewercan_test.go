// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Every mutation that returns a Policy must return the read model, with viewerCan filled,
// because Policy.viewerCan is non-null in the schema. A bare core projection makes the response
// fail with INTERNAL after the write has already happened (#152, the family of #149).

const mutationAuthor = "creator-u"

// mutationEnv is one published policy "pol" in category CAT (and a second category to move to),
// owned by mutationAuthor.
func mutationEnv() (*fakePolicyClient, *raciCategoryClient) {
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol": {
			Id: "pol", HomeCategoryId: "g-cat", Number: "POL-CAT-1", Title: "P",
			OwnerUserId: mutationAuthor, CurrentPublishedVersionId: "ver-pub",
		},
	}}
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT"}, "g-dest": {Id: "g-dest", Name: "DEST"}},
		map[string][]*corev1.CategoryRule{"g-cat": {allowEveryoneRule(), authorRule(mutationAuthor, corev1.GrantEffect_GRANT_EFFECT_ALLOW)}},
	)
	return pc, gc
}

func authorOwnerCtx(t *testing.T) context.Context {
	return ctxWithStubClaims(t, principal.Static{UserIDValue: mutationAuthor, RolesValue: []string{"reader"}})
}

func requireViewerCan(t *testing.T, name string, p *resolvers.Policy) {
	t.Helper()
	if p == nil || p.ViewerCan == nil {
		t.Fatalf("%s must return viewerCan (non-null in the schema); got %+v", name, p)
	}
	if !p.ViewerCan.Read {
		t.Fatalf("%s: the caller can read the policy they just changed; got %+v", name, p.ViewerCan)
	}
}

func TestSetPolicyTemplate_FillsViewerCan(t *testing.T) {
	pc, gc := mutationEnv()
	tmpl := "tmpl-1"
	got, err := resolvers.SetPolicyTemplate(authorOwnerCtx(t), pc, gc, nil, nil, nil, "pol", &tmpl, false)
	if err != nil {
		t.Fatalf("set template: %v", err)
	}
	requireViewerCan(t, "setPolicyTemplate", got)
}

func TestSetPolicyTemplateWithSkeleton_FillsViewerCan(t *testing.T) {
	for name, none := range map[string]bool{"template": false, "freeform": true} {
		t.Run(name, func(t *testing.T) {
			pc, gc := mutationEnv()
			tmpl := "tmpl-1"
			got, err := resolvers.SetPolicyTemplateWithSkeleton(authorOwnerCtx(t), log.Nop(), pc, gc, skeletonTemplates(), nil, nil, nil, "pol", &tmpl, none)
			if err != nil {
				t.Fatalf("set template: %v", err)
			}
			requireViewerCan(t, "setPolicyTemplate", got)
		})
	}
}

func TestSetPolicySensitivity_FillsViewerCan(t *testing.T) {
	pc, gc := mutationEnv()
	got, err := resolvers.SetPolicySensitivity(authorOwnerCtx(t), pc, gc, nil, nil, nil, "pol", resolvers.SensitivityStandard)
	if err != nil {
		t.Fatalf("set sensitivity: %v", err)
	}
	requireViewerCan(t, "setPolicySensitivity", got)
}

func TestSetPolicyOwner_FillsViewerCan(t *testing.T) {
	pc, gc := mutationEnv()
	got, err := resolvers.SetPolicyOwner(siteAdminCtx(t), pc, gc, nil, nil, nil, "pol", "new-owner")
	if err != nil {
		t.Fatalf("set owner: %v", err)
	}
	requireViewerCan(t, "setPolicyOwner", got)
}

func TestMovePolicy_FillsViewerCan(t *testing.T) {
	pc, gc := mutationEnv()
	got, err := resolvers.MovePolicy(siteAdminCtx(t), pc, gc, nil, nil, nil, "pol", "g-dest")
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	requireViewerCan(t, "movePolicy", got)
}

// retirePolicy hides the policy from listings, not from the person who retired it: the mock
// answers with the retired policy and the caller's viewerCan, and so does the gateway.
func TestRetirePolicy_FillsViewerCan(t *testing.T) {
	pc, gc := mutationEnv()
	got, err := resolvers.RetirePolicy(authorOwnerCtx(t), pc, gc, nil, nil, nil, "pol")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	requireViewerCan(t, "retirePolicy", got)
	if got.RetiredAt == nil || *got.RetiredAt == "" {
		t.Fatalf("the retired policy must still carry retiredAt; got %+v", got)
	}
}

func TestSetPolicyAck_FillsViewerCan(t *testing.T) {
	pc, gc := mutationEnv()
	got, err := resolvers.SetPolicyAck(siteAdminCtx(t), pc, gc, nil, nil, nil, "pol", new(resolvers.AckTriggerOnPublish), nil)
	if err != nil {
		t.Fatalf("set ack: %v", err)
	}
	requireViewerCan(t, "setPolicyAck", got)
}

func TestRenamePolicy_FillsViewerCan(t *testing.T) {
	pc, gc := mutationEnv()
	got, err := resolvers.RenamePolicy(authorOwnerCtx(t), pc, gc, nil, nil, &fakeWorkflowClient{}, "pol", "New Title")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	requireViewerCan(t, "renamePolicy", got.Policy)
}

// policiesByOwner returns [Policy!]!, so each row needs viewerCan too.
func TestListPoliciesByOwner_FillsViewerCan(t *testing.T) {
	pc, gc := mutationEnv()
	pc.byOwnerResp = &corev1.ListPoliciesByOwnerResponse{Policies: []*corev1.Policy{pc.policies["pol"]}}
	got, err := resolvers.ListPoliciesByOwner(siteAdminCtx(t), pc, gc, nil, nil, nil, mutationAuthor, nil)
	if err != nil {
		t.Fatalf("list by owner: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want the owner's policy; got %+v", got)
	}
	requireViewerCan(t, "policiesByOwner", got[0])
}

// An editor who flips a policy to SENSITIVE can no longer read it. The mock answers with the
// policy and the caller's viewerCan as it now stands, so the gateway answers the same way and
// does not turn a write that happened into an error.
func TestSetPolicySensitivity_CallerLosesReadStillAnswers(t *testing.T) {
	pc, gc := mutationEnv()
	pc.policies["pol"].OwnerUserId = "someone-else"
	got, err := resolvers.SetPolicySensitivity(authorOwnerCtx(t), pc, gc, nil, nil, nil, "pol", resolvers.SensitivitySensitive)
	if err != nil {
		t.Fatalf("a flip the caller lost read on must still answer: %v", err)
	}
	if got == nil || got.ViewerCan == nil {
		t.Fatalf("want the policy with viewerCan; got %+v", got)
	}
	if got.ViewerCan.Read {
		t.Fatalf("the caller can no longer read the sensitive policy; got %+v", got.ViewerCan)
	}
}

// setPolicyAck is gated by a role, not by a read grant, so it does not answer with a policy the
// caller may not read; the write has happened, so it fails loud rather than succeed empty.
func TestSetPolicyAck_CallerCannotReadFailsLoud(t *testing.T) {
	pc, gc := mutationEnv()
	pc.policies["pol"].Sensitivity = corev1.Sensitivity_SENSITIVITY_SENSITIVE
	pc.policies["pol"].OwnerUserId = "someone-else"
	_, err := resolvers.SetPolicyAck(ctxWithRoles(t, "u", []string{"compliance-admin"}), pc, gc, nil, nil, nil, "pol", new(resolvers.AckTriggerOnPublish), nil)
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal; got %v", err)
	}
}
