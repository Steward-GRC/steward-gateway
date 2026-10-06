// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeReferenceClient is a hand-rolled corev1.ReferenceServiceClient for the
// References/Standards library resolver tests. `library` is what ListReferences
// returns (used both by the reads and by the creator-OR-admin fetch); the last*
// fields record the requests so tests can assert core was / was not called and
// that the actor was bound from claims.
type fakeReferenceClient struct {
	corev1.ReferenceServiceClient
	library     []*corev1.Reference
	attached    []*corev1.Reference
	lastCreate  *corev1.CreateReferenceRequest
	lastUpdate  *corev1.UpdateReferenceRequest
	lastDelete  *corev1.DeleteReferenceRequest
	lastArchive *corev1.SetReferenceArchivedRequest
	lastSetPol  *corev1.SetPolicyReferencesRequest
}

func (f *fakeReferenceClient) ListReferences(_ context.Context, _ *corev1.ListReferencesRequest, _ ...grpc.CallOption) (*corev1.ListReferencesResponse, error) {
	return &corev1.ListReferencesResponse{References: f.library}, nil
}

func (f *fakeReferenceClient) CreateReference(_ context.Context, in *corev1.CreateReferenceRequest, _ ...grpc.CallOption) (*corev1.CreateReferenceResponse, error) {
	f.lastCreate = in
	return &corev1.CreateReferenceResponse{Reference: &corev1.Reference{
		Id: "new-ref", Label: in.GetInput().GetLabel(), Kind: in.GetInput().GetKind(), CreatedByUserId: in.GetActorUserId(),
	}}, nil
}

func (f *fakeReferenceClient) UpdateReference(_ context.Context, in *corev1.UpdateReferenceRequest, _ ...grpc.CallOption) (*corev1.UpdateReferenceResponse, error) {
	f.lastUpdate = in
	return &corev1.UpdateReferenceResponse{Reference: &corev1.Reference{Id: in.GetId(), Label: in.GetInput().GetLabel(), Kind: in.GetInput().GetKind()}}, nil
}

func (f *fakeReferenceClient) DeleteReference(_ context.Context, in *corev1.DeleteReferenceRequest, _ ...grpc.CallOption) (*corev1.DeleteReferenceResponse, error) {
	f.lastDelete = in
	return &corev1.DeleteReferenceResponse{}, nil
}

func (f *fakeReferenceClient) SetReferenceArchived(_ context.Context, in *corev1.SetReferenceArchivedRequest, _ ...grpc.CallOption) (*corev1.SetReferenceArchivedResponse, error) {
	f.lastArchive = in
	return &corev1.SetReferenceArchivedResponse{Reference: &corev1.Reference{Id: in.GetId(), Archived: in.GetArchived()}}, nil
}

func (f *fakeReferenceClient) ListPolicyReferences(_ context.Context, _ *corev1.ListPolicyReferencesRequest, _ ...grpc.CallOption) (*corev1.ListPolicyReferencesResponse, error) {
	return &corev1.ListPolicyReferencesResponse{References: f.attached}, nil
}

func (f *fakeReferenceClient) SetPolicyReferences(_ context.Context, in *corev1.SetPolicyReferencesRequest, _ ...grpc.CallOption) (*corev1.SetPolicyReferencesResponse, error) {
	f.lastSetPol = in
	out := make([]*corev1.Reference, len(in.GetReferenceIds()))
	for i, id := range in.GetReferenceIds() {
		out[i] = &corev1.Reference{Id: id}
	}
	return &corev1.SetPolicyReferencesResponse{References: out}, nil
}

// refLibrary returns a one-entry library owned by creator-u, used by the
// creator-OR-admin fetch in the mutation gate.
func refLibrary() []*corev1.Reference {
	return []*corev1.Reference{{
		Id: "ref-1", Label: "ISO 27001", Kind: corev1.ReferenceKind_REFERENCE_KIND_STANDARD,
		Clause: "§A.9", CreatedByUserId: "creator-u", UsedByCount: 3,
	}}
}

func TestReferenceFromProto_MapsFields(t *testing.T) {
	c := &fakeReferenceClient{library: []*corev1.Reference{{
		Id: "ref-1", Label: "ISO 27001", Kind: corev1.ReferenceKind_REFERENCE_KIND_LINK,
		Url: "https://standards.example.org", Clause: "§A.9", Body: "", Archived: true, CreatedByUserId: "creator-u", UsedByCount: 7,
	}}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u"})
	out, err := resolvers.ReferencesResolver(ctx, c, true)
	if err != nil {
		t.Fatalf("ReferencesResolver: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 reference, got %d", len(out))
	}
	r := out[0]
	if r.Kind != resolvers.ReferenceKindLink {
		t.Fatalf("kind: got %q want LINK", r.Kind)
	}
	if r.URL == nil || *r.URL != "https://standards.example.org" {
		t.Fatalf("url not mapped: %+v", r.URL)
	}
	if r.Body != nil {
		t.Fatalf("empty body should map to nil, got %v", *r.Body)
	}
	if r.CreatedByUserID == nil || *r.CreatedByUserID != "creator-u" {
		t.Fatalf("createdByUserId not mapped: %+v", r.CreatedByUserID)
	}
	if !r.Archived || r.UsedByCount != 7 {
		t.Fatalf("archived/usedByCount not mapped: archived=%v used=%d", r.Archived, r.UsedByCount)
	}
}

func TestReferencesResolver_RequiresAuth(t *testing.T) {
	c := &fakeReferenceClient{library: refLibrary()}
	if _, err := resolvers.ReferencesResolver(context.Background(), c, false); err == nil {
		t.Fatal("expected error with no authenticated user")
	}
}

// CreateReference is open to any authenticated author (non-admin); the actor is
// bound from claims and recorded as created_by. An unauthenticated caller is
// rejected before core is dialed.
func TestCreateReferenceResolver_AnyAuthenticatedAuthor(t *testing.T) {
	t.Run("plain author may create", func(t *testing.T) {
		c := &fakeReferenceClient{}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-u", RolesValue: []string{"reader"}})
		_, err := resolvers.CreateReferenceResolver(ctx, c, &resolvers.ReferenceInput{Label: "Sample Standard A", Kind: resolvers.ReferenceKindStandard})
		if err != nil {
			t.Fatalf("expected create allowed for author, got %v", err)
		}
		if c.lastCreate == nil || c.lastCreate.GetActorUserId() != "author-u" {
			t.Fatalf("actor not bound from claims: %+v", c.lastCreate)
		}
	})
	t.Run("unauthenticated denied", func(t *testing.T) {
		c := &fakeReferenceClient{}
		if _, err := resolvers.CreateReferenceResolver(context.Background(), c, &resolvers.ReferenceInput{Label: "x", Kind: resolvers.ReferenceKindStandard}); err == nil {
			t.Fatal("expected error with no authenticated user")
		}
		if c.lastCreate != nil {
			t.Fatal("core CreateReference must NOT be called when unauthenticated")
		}
	})
}

// TestUpdateReferenceResolver_CreatorOrAdminMatrix is the authorization matrix
// for the library edit gate: the tri-admin set (site/template/compliance admin)
// OR the entry's own creator may edit; a non-creator non-admin is denied and
// core is never called. (delete / setReferenceArchived share the exact same gate
// via authorizeReferenceMutation — see the archive sub-case.)
func TestUpdateReferenceResolver_CreatorOrAdminMatrix(t *testing.T) {
	cases := []struct {
		name      string
		claims    principal.Static
		wantAllow bool
		wantActor string
	}{
		{"site-admin edits", principal.Static{UserIDValue: "admin-u", RolesValue: []string{"site-admin"}}, true, "admin-u"},
		{"template-admin edits", principal.Static{UserIDValue: "tmpl-u", RolesValue: []string{"template-admin"}}, true, "tmpl-u"},
		{"compliance-admin edits", principal.Static{UserIDValue: "comp-u", RolesValue: []string{"compliance-admin"}}, true, "comp-u"},
		{"creator edits own entry", principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}}, true, "creator-u"},
		{"non-creator non-admin denied", principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeReferenceClient{library: refLibrary()}
			ctx := ctxWithStubClaims(t, tc.claims)
			_, err := resolvers.UpdateReferenceResolver(ctx, c, "ref-1", &resolvers.ReferenceInput{Label: "ISO 27001 rev", Kind: resolvers.ReferenceKindStandard})
			if tc.wantAllow {
				if err != nil {
					t.Fatalf("expected edit allowed, got %v", err)
				}
				if c.lastUpdate == nil {
					t.Fatal("expected core UpdateReference to be called")
				}
				if c.lastUpdate.GetActorUserId() != tc.wantActor {
					t.Fatalf("actor: got %q want %q", c.lastUpdate.GetActorUserId(), tc.wantActor)
				}
			} else {
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("expected PermissionDenied, got %v", err)
				}
				if c.lastUpdate != nil {
					t.Fatal("core UpdateReference must NOT be called when denied")
				}
			}
		})
	}
}

// TestDeleteAndArchive_ShareCreatorOrAdminGate confirms delete + archive route
// through the same creator-OR-admin gate: creator allowed, non-creator denied.
func TestDeleteAndArchive_ShareCreatorOrAdminGate(t *testing.T) {
	t.Run("creator may delete", func(t *testing.T) {
		c := &fakeReferenceClient{library: refLibrary()}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}})
		ok, err := resolvers.DeleteReferenceResolver(ctx, c, "ref-1")
		if err != nil || !ok {
			t.Fatalf("expected delete allowed, got ok=%v err=%v", ok, err)
		}
		if c.lastDelete == nil || c.lastDelete.GetActorUserId() != "creator-u" {
			t.Fatalf("actor not bound on delete: %+v", c.lastDelete)
		}
	})
	t.Run("non-creator non-admin denied on archive", func(t *testing.T) {
		c := &fakeReferenceClient{library: refLibrary()}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}})
		_, err := resolvers.SetReferenceArchivedResolver(ctx, c, "ref-1", true)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied, got %v", err)
		}
		if c.lastArchive != nil {
			t.Fatal("core SetReferenceArchived must NOT be called when denied")
		}
	})
	t.Run("admin may archive any entry", func(t *testing.T) {
		c := &fakeReferenceClient{library: refLibrary()}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-u", RolesValue: []string{"site-admin"}})
		if _, err := resolvers.SetReferenceArchivedResolver(ctx, c, "ref-1", true); err != nil {
			t.Fatalf("expected admin archive allowed, got %v", err)
		}
		if c.lastArchive == nil || !c.lastArchive.GetArchived() {
			t.Fatalf("core SetReferenceArchived not called as expected: %+v", c.lastArchive)
		}
	})
}

// TestSetPolicyReferencesResolver_EditGate confirms attach/detach is gated on
// the policy's EDIT access (authorizeEffectiveAuthor) — the same gate as
// setPolicySensitivity / saveDraft: an editor may set them (actor bound from
// claims), a non-editor is denied and core is never called.
func TestSetPolicyReferencesResolver_EditGate(t *testing.T) {
	t.Run("editor may attach", func(t *testing.T) {
		claims := principal.Static{UserIDValue: "coauthor-u", RolesValue: []string{"reader"}}
		rules := []*corev1.CategoryRule{authorRule("coauthor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)}
		pc, gc := coAuthMatrixEnv("creator-other", nil, rules)
		c := &fakeReferenceClient{}
		ctx := ctxWithStubClaims(t, claims)
		out, err := resolvers.SetPolicyReferencesResolver(ctx, c, pc, gc, "pol", []string{"ref-1", "ref-2"})
		if err != nil {
			t.Fatalf("expected attach allowed, got %v", err)
		}
		if len(out) != 2 {
			t.Fatalf("want 2 attached, got %d", len(out))
		}
		if c.lastSetPol == nil || c.lastSetPol.GetActorUserId() != "coauthor-u" {
			t.Fatalf("actor not bound from claims: %+v", c.lastSetPol)
		}
	})
	t.Run("non-editor denied", func(t *testing.T) {
		claims := principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}}
		rules := []*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)}
		pc, gc := coAuthMatrixEnv("creator-other", nil, rules)
		c := &fakeReferenceClient{}
		ctx := ctxWithStubClaims(t, claims)
		_, err := resolvers.SetPolicyReferencesResolver(ctx, c, pc, gc, "pol", []string{"ref-1"})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied, got %v", err)
		}
		if c.lastSetPol != nil {
			t.Fatal("core SetPolicyReferences must NOT be called when denied")
		}
	})
}
