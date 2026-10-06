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

// fakeDefinitionLibraryClient is a hand-rolled
// corev1.DefinitionLibraryServiceClient for the category-scoped Definitions
// library resolver tests. `library` is what ListDefinitionEntries returns (used
// both by the reads and by the creator-OR-admin fetch); the last* fields record
// the requests so tests can assert core was / was not called and that the actor
// was bound from claims.
type fakeDefinitionLibraryClient struct {
	corev1.DefinitionLibraryServiceClient
	library    []*corev1.DefinitionEntry
	candidates []*corev1.DefinitionEntry
	attached   []*corev1.DefinitionEntry
	lastList   *corev1.ListDefinitionEntriesRequest
	lastCreate *corev1.CreateDefinitionEntryRequest
	lastUpdate *corev1.UpdateDefinitionEntryRequest
	lastDelete *corev1.DeleteDefinitionEntryRequest
	lastArch   *corev1.SetDefinitionEntryArchivedRequest
	lastSetPol *corev1.SetPolicyDefinitionEntriesRequest
}

func (f *fakeDefinitionLibraryClient) ListDefinitionEntries(_ context.Context, in *corev1.ListDefinitionEntriesRequest, _ ...grpc.CallOption) (*corev1.ListDefinitionEntriesResponse, error) {
	f.lastList = in
	return &corev1.ListDefinitionEntriesResponse{Definitions: f.library}, nil
}

func (f *fakeDefinitionLibraryClient) ListPolicyDefinitionCandidates(_ context.Context, _ *corev1.ListPolicyDefinitionCandidatesRequest, _ ...grpc.CallOption) (*corev1.ListPolicyDefinitionCandidatesResponse, error) {
	return &corev1.ListPolicyDefinitionCandidatesResponse{Definitions: f.candidates}, nil
}

func (f *fakeDefinitionLibraryClient) CreateDefinitionEntry(_ context.Context, in *corev1.CreateDefinitionEntryRequest, _ ...grpc.CallOption) (*corev1.CreateDefinitionEntryResponse, error) {
	f.lastCreate = in
	return &corev1.CreateDefinitionEntryResponse{Definition: &corev1.DefinitionEntry{
		Id: "new-def", CategoryId: in.GetInput().GetCategoryId(), Term: in.GetInput().GetTerm(),
		Definition: in.GetInput().GetDefinition(), CreatedByUserId: in.GetActorUserId(),
	}}, nil
}

func (f *fakeDefinitionLibraryClient) UpdateDefinitionEntry(_ context.Context, in *corev1.UpdateDefinitionEntryRequest, _ ...grpc.CallOption) (*corev1.UpdateDefinitionEntryResponse, error) {
	f.lastUpdate = in
	return &corev1.UpdateDefinitionEntryResponse{Definition: &corev1.DefinitionEntry{Id: in.GetId(), Term: in.GetInput().GetTerm(), Definition: in.GetInput().GetDefinition()}}, nil
}

func (f *fakeDefinitionLibraryClient) DeleteDefinitionEntry(_ context.Context, in *corev1.DeleteDefinitionEntryRequest, _ ...grpc.CallOption) (*corev1.DeleteDefinitionEntryResponse, error) {
	f.lastDelete = in
	return &corev1.DeleteDefinitionEntryResponse{}, nil
}

func (f *fakeDefinitionLibraryClient) SetDefinitionEntryArchived(_ context.Context, in *corev1.SetDefinitionEntryArchivedRequest, _ ...grpc.CallOption) (*corev1.SetDefinitionEntryArchivedResponse, error) {
	f.lastArch = in
	return &corev1.SetDefinitionEntryArchivedResponse{Definition: &corev1.DefinitionEntry{Id: in.GetId(), Archived: in.GetArchived()}}, nil
}

func (f *fakeDefinitionLibraryClient) ListPolicyDefinitionEntries(_ context.Context, _ *corev1.ListPolicyDefinitionEntriesRequest, _ ...grpc.CallOption) (*corev1.ListPolicyDefinitionEntriesResponse, error) {
	return &corev1.ListPolicyDefinitionEntriesResponse{Definitions: f.attached}, nil
}

func (f *fakeDefinitionLibraryClient) SetPolicyDefinitionEntries(_ context.Context, in *corev1.SetPolicyDefinitionEntriesRequest, _ ...grpc.CallOption) (*corev1.SetPolicyDefinitionEntriesResponse, error) {
	f.lastSetPol = in
	out := make([]*corev1.DefinitionEntry, len(in.GetDefinitionIds()))
	for i, id := range in.GetDefinitionIds() {
		out[i] = &corev1.DefinitionEntry{Id: id}
	}
	return &corev1.SetPolicyDefinitionEntriesResponse{Definitions: out}, nil
}

// defLibrary returns a one-entry library owned by creator-u, used by the
// creator-OR-admin fetch in the mutation gate.
func defLibrary() []*corev1.DefinitionEntry {
	return []*corev1.DefinitionEntry{{
		Id: "def-1", CategoryId: "cat-1", Term: "SLA", Definition: "service level agreement",
		CreatedByUserId: "creator-u", UsedByCount: 3,
	}}
}

func TestDefinitionEntryFromProto_MapsFieldsAndCategoryFilter(t *testing.T) {
	c := &fakeDefinitionLibraryClient{library: []*corev1.DefinitionEntry{{
		Id: "def-1", CategoryId: "cat-9", Term: "RTO", Definition: "recovery time objective",
		Archived: true, CreatedByUserId: "creator-u", UsedByCount: 7,
	}}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u"})
	cat := "cat-9"
	out, err := resolvers.DefinitionLibraryResolver(ctx, c, &cat, true)
	if err != nil {
		t.Fatalf("DefinitionLibraryResolver: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 definition, got %d", len(out))
	}
	d := out[0]
	if d.CategoryID != "cat-9" || d.Term != "RTO" || d.Definition != "recovery time objective" {
		t.Fatalf("fields not mapped: %+v", d)
	}
	if !d.Archived || d.UsedByCount != 7 {
		t.Fatalf("archived/usedByCount not mapped: archived=%v used=%d", d.Archived, d.UsedByCount)
	}
	if d.CreatedByUserID == nil || *d.CreatedByUserID != "creator-u" {
		t.Fatalf("createdByUserId not mapped: %+v", d.CreatedByUserID)
	}
	// categoryId + includeArchived forwarded to core.
	if c.lastList == nil || c.lastList.GetCategoryId() != "cat-9" || !c.lastList.GetIncludeArchived() {
		t.Fatalf("category/includeArchived not forwarded: %+v", c.lastList)
	}
}

func TestDefinitionLibraryResolver_RequiresAuth(t *testing.T) {
	c := &fakeDefinitionLibraryClient{library: defLibrary()}
	if _, err := resolvers.DefinitionLibraryResolver(context.Background(), c, nil, false); err == nil {
		t.Fatal("expected error with no authenticated user")
	}
}

func TestCreateDefinitionResolver_AnyAuthenticatedAuthor(t *testing.T) {
	t.Run("plain author may create", func(t *testing.T) {
		c := &fakeDefinitionLibraryClient{}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-u", RolesValue: []string{"reader"}})
		_, err := resolvers.CreateDefinitionResolver(ctx, c, &resolvers.DefinitionEntryInput{CategoryID: "cat-1", Term: "MTTR", Definition: "mean time to repair"})
		if err != nil {
			t.Fatalf("expected create allowed for author, got %v", err)
		}
		if c.lastCreate == nil || c.lastCreate.GetActorUserId() != "author-u" {
			t.Fatalf("actor not bound from claims: %+v", c.lastCreate)
		}
	})
	t.Run("unauthenticated denied", func(t *testing.T) {
		c := &fakeDefinitionLibraryClient{}
		if _, err := resolvers.CreateDefinitionResolver(context.Background(), c, &resolvers.DefinitionEntryInput{CategoryID: "cat-1", Term: "x", Definition: "y"}); err == nil {
			t.Fatal("expected error with no authenticated user")
		}
		if c.lastCreate != nil {
			t.Fatal("core CreateDefinitionEntry must NOT be called when unauthenticated")
		}
	})
}

// The library edit gate: the tri-admin set OR the entry's own creator may edit;
// a non-creator non-admin is denied and core is never called. (delete /
// setDefinitionArchived share the same gate via authorizeDefinitionMutation.)
func TestUpdateDefinitionResolver_CreatorOrAdminMatrix(t *testing.T) {
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
			c := &fakeDefinitionLibraryClient{library: defLibrary()}
			ctx := ctxWithStubClaims(t, tc.claims)
			_, err := resolvers.UpdateDefinitionResolver(ctx, c, "def-1", &resolvers.DefinitionEntryInput{CategoryID: "cat-1", Term: "SLA", Definition: "revised"})
			if tc.wantAllow {
				if err != nil {
					t.Fatalf("expected edit allowed, got %v", err)
				}
				if c.lastUpdate == nil || c.lastUpdate.GetActorUserId() != tc.wantActor {
					t.Fatalf("actor: got %+v want %q", c.lastUpdate, tc.wantActor)
				}
			} else {
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("expected PermissionDenied, got %v", err)
				}
				if c.lastUpdate != nil {
					t.Fatal("core UpdateDefinitionEntry must NOT be called when denied")
				}
			}
		})
	}
}

func TestDeleteAndArchiveDefinition_ShareCreatorOrAdminGate(t *testing.T) {
	t.Run("creator may delete", func(t *testing.T) {
		c := &fakeDefinitionLibraryClient{library: defLibrary()}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}})
		ok, err := resolvers.DeleteDefinitionResolver(ctx, c, "def-1")
		if err != nil || !ok {
			t.Fatalf("expected delete allowed, got ok=%v err=%v", ok, err)
		}
		if c.lastDelete == nil || c.lastDelete.GetActorUserId() != "creator-u" {
			t.Fatalf("actor not bound on delete: %+v", c.lastDelete)
		}
	})
	t.Run("non-creator non-admin denied on archive", func(t *testing.T) {
		c := &fakeDefinitionLibraryClient{library: defLibrary()}
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}})
		_, err := resolvers.SetDefinitionArchivedResolver(ctx, c, "def-1", true)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied, got %v", err)
		}
		if c.lastArch != nil {
			t.Fatal("core SetDefinitionEntryArchived must NOT be called when denied")
		}
	})
}

func TestSetPolicyDefinitionEntriesResolver_EditGate(t *testing.T) {
	t.Run("editor may attach", func(t *testing.T) {
		claims := principal.Static{UserIDValue: "coauthor-u", RolesValue: []string{"reader"}}
		rules := []*corev1.CategoryRule{authorRule("coauthor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)}
		pc, gc := coAuthMatrixEnv("creator-other", nil, rules)
		c := &fakeDefinitionLibraryClient{}
		ctx := ctxWithStubClaims(t, claims)
		out, err := resolvers.SetPolicyDefinitionEntriesResolver(ctx, c, pc, gc, "pol", []string{"def-1", "def-2"})
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
		c := &fakeDefinitionLibraryClient{}
		ctx := ctxWithStubClaims(t, claims)
		_, err := resolvers.SetPolicyDefinitionEntriesResolver(ctx, c, pc, gc, "pol", []string{"def-1"})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied, got %v", err)
		}
		if c.lastSetPol != nil {
			t.Fatal("core SetPolicyDefinitionEntries must NOT be called when denied")
		}
	})
}
