// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// PolicyVersion.reacknowledge (steward-gateway#231): true only for a policy whose
// acknowledgement trigger is ON_CHANGE and whose change type is MAJOR.

// obligationPolicyClient answers ResolvePolicyObligation from a fixed response and
// counts the calls.
type obligationPolicyClient struct {
	*fakePolicyClient
	obligation *corev1.ResolvePolicyObligationResponse
	calls      int
}

func (o *obligationPolicyClient) ResolvePolicyObligation(_ context.Context, _ *corev1.ResolvePolicyObligationRequest, _ ...grpc.CallOption) (*corev1.ResolvePolicyObligationResponse, error) {
	o.calls++
	return o.obligation, nil
}

func reackEnv(t *testing.T, docType corev1.DocumentType, ob *corev1.ResolvePolicyObligationResponse) (*resolvers.Resolver, *obligationPolicyClient, context.Context) {
	t.Helper()
	pc, groups, ctx := breakGlassReadSetup(t, false)
	pc.policies["pol-1"].DocumentType = docType
	opc := &obligationPolicyClient{fakePolicyClient: pc.fakePolicyClient, obligation: ob}
	return &resolvers.Resolver{PolicyClient: opc, CategoryClient: groups, IdentityAdminClient: noGrant(), Log: log.Nop()}, opc, ctx
}

func ct(c resolvers.ChangeType) *resolvers.ChangeType { return &c }

func TestReacknowledge(t *testing.T) {
	onChange := &corev1.ResolvePolicyObligationResponse{RequiresAck: true, OnChange: true}
	onPublish := &corev1.ResolvePolicyObligationResponse{RequiresAck: true, OnChange: false}
	noAck := &corev1.ResolvePolicyObligationResponse{}
	policy, procedure := corev1.DocumentType_DOCUMENT_TYPE_POLICY, corev1.DocumentType_DOCUMENT_TYPE_PROCEDURE

	cases := []struct {
		name    string
		doc     corev1.DocumentType
		ob      *corev1.ResolvePolicyObligationResponse
		version *resolvers.PolicyVersion
		pick    *resolvers.ChangeType
		want    bool
	}{
		{"on change and major (version type)", policy, onChange, &resolvers.PolicyVersion{ChangeType: ct(resolvers.ChangeTypeMajor)}, nil, true},
		{"on change and major (suggestion only)", policy, onChange, &resolvers.PolicyVersion{SuggestedChangeType: ct(resolvers.ChangeTypeMajor)}, nil, true},
		{"on change and major (author pick)", policy, onChange, &resolvers.PolicyVersion{ChangeType: ct(resolvers.ChangeTypeMinor)}, ct(resolvers.ChangeTypeMajor), true},
		{"on change and minor", policy, onChange, &resolvers.PolicyVersion{ChangeType: ct(resolvers.ChangeTypeMinor)}, nil, false},
		{"on change and fix", policy, onChange, &resolvers.PolicyVersion{ChangeType: ct(resolvers.ChangeTypeFix)}, nil, false},
		{"pick lowers major to fix", policy, onChange, &resolvers.PolicyVersion{ChangeType: ct(resolvers.ChangeTypeMajor)}, ct(resolvers.ChangeTypeFix), false},
		{"on publish only and major", policy, onPublish, &resolvers.PolicyVersion{ChangeType: ct(resolvers.ChangeTypeMajor)}, nil, false},
		{"no acknowledgement and major", policy, noAck, &resolvers.PolicyVersion{ChangeType: ct(resolvers.ChangeTypeMajor)}, nil, false},
		{"procedure and major", procedure, noAck, &resolvers.PolicyVersion{ChangeType: ct(resolvers.ChangeTypeMajor)}, nil, false},
		{"procedure even if core says on change", procedure, onChange, &resolvers.PolicyVersion{ChangeType: ct(resolvers.ChangeTypeMajor)}, ct(resolvers.ChangeTypeMajor), false},
		{"unknown change type", policy, onChange, &resolvers.PolicyVersion{}, nil, false},
		{"unrecognised pick", policy, onChange, &resolvers.PolicyVersion{}, ct(resolvers.ChangeType("HUGE")), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _, ctx := reackEnv(t, c.doc, c.ob)
			c.version.ID, c.version.PolicyID = "pol-1-v1", "pol-1"
			got, err := r.PolicyVersion().Reacknowledge(ctx, c.version, c.pick)
			if err != nil {
				t.Fatalf("Reacknowledge: %v", err)
			}
			if got != c.want {
				t.Fatalf("reacknowledge = %v, want %v", got, c.want)
			}
		})
	}
}

func TestReacknowledgeFollowsTheReadDecision(t *testing.T) {
	pc, groups, ctx := breakGlassReadSetup(t, false)
	opc := &obligationPolicyClient{fakePolicyClient: pc.fakePolicyClient, obligation: &corev1.ResolvePolicyObligationResponse{RequiresAck: true, OnChange: true}}
	r := &resolvers.Resolver{PolicyClient: opc, CategoryClient: groups, IdentityAdminClient: noGrant(), Log: log.Nop()}

	_, err := r.PolicyVersion().Reacknowledge(ctx, &resolvers.PolicyVersion{ID: "x", PolicyID: "no-such-policy", ChangeType: ct(resolvers.ChangeTypeMajor)}, nil)
	if err == nil {
		t.Fatal("want a not found error for a policy the caller cannot read")
	}
	if opc.calls != 0 {
		t.Fatalf("core was asked for the obligation %d times, want 0", opc.calls)
	}
}
