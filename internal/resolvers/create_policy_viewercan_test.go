// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	log "github.com/Bugs5382/go-log"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// TestCreatePolicyWithSkeleton_FillsViewerCan: createPolicy must return the read model, with
// viewerCan filled, because Policy.viewerCan is non-null in the schema. Without it
// the policy is created in core and the response fails with INTERNAL (#149).
func TestCreatePolicyWithSkeleton_FillsViewerCan(t *testing.T) {
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{}}
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT"}},
		map[string][]*corev1.CategoryRule{"g-cat": {authorRule(bobID, corev1.GrantEffect_GRANT_EFFECT_ALLOW)}},
	)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: bobID})

	got, err := resolvers.CreatePolicyWithSkeleton(ctx, log.Nop(), pc, gc, skeletonTemplates(), nil, nil, nil, "g-cat", "New Policy", resolvers.SensitivityStandard, nil, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got == nil || got.ViewerCan == nil {
		t.Fatalf("createPolicy must return viewerCan (non-null in the schema); got %+v", got)
	}
	if !got.ViewerCan.Read || !got.ViewerCan.Edit {
		t.Fatalf("the creator must be able to read and edit the new policy; got %+v", got.ViewerCan)
	}
}
