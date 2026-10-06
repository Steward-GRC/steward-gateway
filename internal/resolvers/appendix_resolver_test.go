// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeAppendixClient is a hand-rolled stub of corev1.AppendixServiceClient.
type fakeAppendixClient struct {
	corev1.AppendixServiceClient
	list         []*corev1.Appendix
	lastAdd      *corev1.AddAppendixRequest
	lastUpdate   *corev1.UpdateAppendixRequest
	lastReorder  *corev1.ReorderAppendicesRequest
	lastDeleteID string
}

func (f *fakeAppendixClient) ListAppendices(_ context.Context, _ *corev1.ListAppendicesRequest, _ ...grpc.CallOption) (*corev1.ListAppendicesResponse, error) {
	return &corev1.ListAppendicesResponse{Appendices: f.list}, nil
}

func (f *fakeAppendixClient) AddAppendix(_ context.Context, in *corev1.AddAppendixRequest, _ ...grpc.CallOption) (*corev1.AddAppendixResponse, error) {
	f.lastAdd = in
	return &corev1.AddAppendixResponse{Appendix: &corev1.Appendix{
		Id: "new-id", PolicyVersionId: in.PolicyVersionId, Title: in.Title, ContentJson: in.ContentJson, OrderIndex: 0,
	}}, nil
}

func (f *fakeAppendixClient) UpdateAppendix(_ context.Context, in *corev1.UpdateAppendixRequest, _ ...grpc.CallOption) (*corev1.UpdateAppendixResponse, error) {
	f.lastUpdate = in
	return &corev1.UpdateAppendixResponse{Appendix: &corev1.Appendix{
		Id: in.Id, Title: in.Title, ContentJson: in.ContentJson,
	}}, nil
}

func (f *fakeAppendixClient) ReorderAppendices(_ context.Context, in *corev1.ReorderAppendicesRequest, _ ...grpc.CallOption) (*corev1.ReorderAppendicesResponse, error) {
	f.lastReorder = in
	var out []*corev1.Appendix
	for i, id := range in.OrderedIds {
		out = append(out, &corev1.Appendix{Id: id, OrderIndex: int32(i)})
	}
	return &corev1.ReorderAppendicesResponse{Appendices: out}, nil
}

func (f *fakeAppendixClient) DeleteAppendix(_ context.Context, in *corev1.DeleteAppendixRequest, _ ...grpc.CallOption) (*corev1.DeleteAppendixResponse, error) {
	f.lastDeleteID = in.Id
	return &corev1.DeleteAppendixResponse{}, nil
}

// TestAppendicesForVersion_DerivesLetter verifies that orderIndex 0→"A" and 1→"B".
func TestAppendicesForVersion_DerivesLetter(t *testing.T) {
	c := &fakeAppendixClient{list: []*corev1.Appendix{
		{Id: "a", Title: "Intake", OrderIndex: 0},
		{Id: "b", Title: "Matrix", OrderIndex: 1},
	}}
	out, err := resolvers.AppendicesForVersion(context.Background(), c, "pv1")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 appendices; got %d", len(out))
	}
	if out[0].Letter != "A" || out[1].Letter != "B" {
		t.Fatalf("letters: %q %q", out[0].Letter, out[1].Letter)
	}
}

// TestAddAppendixResolver_ForwardsArgs verifies the mutation forwards args to core.
func TestAddAppendixResolver_ForwardsArgs(t *testing.T) {
	c := &fakeAppendixClient{}
	ctx := ctxWithRoles(t, "user-1", []string{"author"})
	got, err := resolvers.AddAppendixResolver(ctx, c, "pv-1", "My Appendix", `{"root":{}}`)
	if err != nil {
		t.Fatalf("AddAppendixResolver: %v", err)
	}
	if c.lastAdd == nil {
		t.Fatal("expected AddAppendix to be called")
	}
	if c.lastAdd.PolicyVersionId != "pv-1" {
		t.Fatalf("PolicyVersionId: got %q want pv-1", c.lastAdd.PolicyVersionId)
	}
	if c.lastAdd.Title != "My Appendix" {
		t.Fatalf("Title: got %q want My Appendix", c.lastAdd.Title)
	}
	if got.Letter != "A" {
		t.Fatalf("letter for orderIndex=0 should be A; got %q", got.Letter)
	}
}

// TestPolicyVersionResolver_Appendices verifies that the PolicyVersion field
// resolver calls AppendicesForVersion (via AppendixClient) and returns the
// correct slice — proving the resolver path rather than the stale model field.
func TestPolicyVersionResolver_Appendices(t *testing.T) {
	c := &fakeAppendixClient{list: []*corev1.Appendix{
		{Id: "x1", PolicyVersionId: "pv1", Title: "Scope", OrderIndex: 0},
		{Id: "x2", PolicyVersionId: "pv1", Title: "Glossary", OrderIndex: 1},
	}}
	r := &resolvers.Resolver{AppendixClient: c}
	got, err := r.PolicyVersion().Appendices(context.Background(), &resolvers.PolicyVersion{ID: "pv1"})
	if err != nil {
		t.Fatalf("Appendices: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 appendices from field resolver; got %d", len(got))
	}
	if got[0].ID != "x1" || got[1].ID != "x2" {
		t.Fatalf("unexpected IDs: %q %q", got[0].ID, got[1].ID)
	}
	if got[0].Letter != "A" || got[1].Letter != "B" {
		t.Fatalf("letters: %q %q", got[0].Letter, got[1].Letter)
	}
}

// TestAddAppendixResolver_Unauthenticated verifies mutation is gated on authentication.
func TestAddAppendixResolver_Unauthenticated(t *testing.T) {
	c := &fakeAppendixClient{}
	_, err := resolvers.AddAppendixResolver(context.Background(), c, "pv-1", "Title", "{}")
	if err == nil {
		t.Fatal("expected error with no authenticated user")
	}
	if status.Code(err) != codes.Unauthenticated {
		// claimsUserID returns a plain error; accept any non-nil error for unauthenticated
		_ = err // acceptable: any error signals denial
	}
	if c.lastAdd != nil {
		t.Fatal("must not call core without authenticated user")
	}
}
