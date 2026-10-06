// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// template visibility is gated on the caller's AUTHOR capability in
// the template's attached category (Template.OwnerCategoryId), reusing the exact
// per-category decision as createPolicy (canAuthorCategory / authorizeCategoryAuthor).
//
// The environment models two sibling categories:
//   - g-a: the caller holds an author grant (may create/author policies here).
//   - g-b: the caller is read-only (everyone-read rule, NO author grant).
// with a template attached to each. A template is visible iff the caller can
// author in its attached category.

// templateVisibilityEnv builds a group client with an author category (g-a) and a
// read-only category (g-b), plus a template client holding one template attached
// to each category (TPL-A→g-a, TPL-B→g-b) with a version for each.
func templateVisibilityEnv(authorUser string) (*labelTemplateFake, *raciCategoryClient) {
	gc := newRaciReadClient(
		map[string]*corev1.Category{
			"g-a": {Id: "g-a", Name: "Alpha"},
			"g-b": {Id: "g-b", Name: "Bravo"},
		},
		map[string][]*corev1.CategoryRule{
			// g-a: the user is a (non-denied) category author.
			"g-a": {authorRule(authorUser, corev1.GrantEffect_GRANT_EFFECT_ALLOW)},
			// g-b: everyone can READ, but nobody has an author grant → read-only.
			"g-b": {allowEveryoneRule()},
		},
	)
	tc := &labelTemplateFake{
		templates: []*corev1.Template{
			{Id: "TPL-A", Code: "TPL-A", Name: "Alpha Template", OwnerCategoryId: "g-a"},
			{Id: "TPL-B", Code: "TPL-B", Name: "Bravo Template", OwnerCategoryId: "g-b"},
		},
		versions: map[string][]*corev1.TemplateVersion{
			"TPL-A": {{Id: "TV-A1", TemplateId: "TPL-A", VersionNo: 1}},
			"TPL-B": {{Id: "TV-B1", TemplateId: "TPL-B", VersionNo: 1}},
		},
	}
	return tc, gc
}

func templateIDs(ts []*resolvers.Template) map[string]bool {
	out := make(map[string]bool, len(ts))
	for _, t := range ts {
		out[t.ID] = true
	}
	return out
}

// TestListTemplates_VisibleOnlyForAuthorCategory confirms a category author sees
// templates attached to their author-category (g-a) but NOT templates attached to
// a category where they are read-only (g-b).
func TestListTemplates_VisibleOnlyForAuthorCategory(t *testing.T) {
	tc, gc := templateVisibilityEnv("author-a")
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-a", RolesValue: []string{"reader"}})

	got, err := resolvers.ListTemplates(ctx, tc, gc, nil)
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	ids := templateIDs(got)
	if !ids["TPL-A"] {
		t.Errorf("author must see TPL-A (attached to their author-category g-a); got %v", ids)
	}
	if ids["TPL-B"] {
		t.Errorf("author must NOT see TPL-B (attached to read-only category g-b); got %v", ids)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly the one author-category template; got %d", len(got))
	}
}

// TestListTemplates_SiteAdminSeesAll confirms a site-admin sees every template
// regardless of category author grants.
func TestListTemplates_SiteAdminSeesAll(t *testing.T) {
	tc, gc := templateVisibilityEnv("author-a")
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-u", RolesValue: []string{"site-admin"}})

	got, err := resolvers.ListTemplates(ctx, tc, gc, nil)
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	ids := templateIDs(got)
	if !ids["TPL-A"] || !ids["TPL-B"] {
		t.Fatalf("site-admin must see all templates; got %v", ids)
	}
}

// TestListTemplates_NoAuthorCategoriesEmpty confirms a user who can author in NO
// category gets an empty list — never an error, never all templates.
func TestListTemplates_NoAuthorCategoriesEmpty(t *testing.T) {
	// This user has no author grant in g-a (grant is for "author-a"); g-b is
	// read-only for everyone. So the caller can author nowhere.
	tc, gc := templateVisibilityEnv("author-a")
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "reader-u", RolesValue: []string{"reader"}})

	got, err := resolvers.ListTemplates(ctx, tc, gc, nil)
	if err != nil {
		t.Fatalf("ListTemplates must not error for a no-author user; got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("user with no author-categories must get an empty list; got %v", templateIDs(got))
	}
}

// TestTemplateRead_GatedOnAuthorCategory confirms the per-template read path
// (latestTemplateVersion / templateVersions) allows a template in the caller's
// author-category and DENIES one outside it (PermissionDenied, existence hidden).
func TestTemplateRead_GatedOnAuthorCategory(t *testing.T) {
	tc, gc := templateVisibilityEnv("author-a")
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-a", RolesValue: []string{"reader"}})

	// Allowed: TPL-A is attached to g-a, where the caller authors.
	vers, err := resolvers.ListTemplateVersions(ctx, tc, gc, "TPL-A")
	if err != nil {
		t.Fatalf("templateVersions for author-category template must be allowed; got %v", err)
	}
	if len(vers) != 1 || vers[0].ID != "TV-A1" {
		t.Fatalf("expected TPL-A versions; got %+v", vers)
	}

	// Denied: TPL-B is attached to g-b, where the caller is read-only.
	if _, err := resolvers.ListTemplateVersions(ctx, tc, gc, "TPL-B"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("templateVersions for a non-author-category template must be denied; got %v", err)
	}
	if _, err := resolvers.LatestTemplateVersion(ctx, tc, gc, "TPL-B"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("latestTemplateVersion for a non-author-category template must be denied; got %v", err)
	}
}
