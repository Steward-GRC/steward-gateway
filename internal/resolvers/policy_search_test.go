// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// searchPolicyClient answers SearchPolicies from an ordered list of canned hits, paged the way
// core pages them, and records every call.
type searchPolicyClient struct {
	*fakePolicyClient
	hits  []*corev1.PolicySearchHit
	calls []*corev1.SearchPoliciesRequest
	err   error
}

func (s *searchPolicyClient) SearchPolicies(_ context.Context, in *corev1.SearchPoliciesRequest, _ ...grpc.CallOption) (*corev1.SearchPoliciesResponse, error) {
	s.calls = append(s.calls, in)
	if s.err != nil {
		return nil, s.err
	}
	lo := min(int(in.GetOffset()), len(s.hits))
	hi := min(lo+int(in.GetLimit()), len(s.hits))
	return &corev1.SearchPoliciesResponse{Hits: s.hits[lo:hi], HasMore: hi < len(s.hits)}, nil
}

const (
	openCat   = "g-open"
	hiddenCat = "g-hidden"
)

func searchPolicy(id, title, cat string) *corev1.Policy {
	return &corev1.Policy{Id: id, HomeCategoryId: cat, Number: "POL-" + strings.ToUpper(id), Title: title, CurrentPublishedVersionId: id + "-v1"}
}

func textHit(p *corev1.Policy) *corev1.PolicySearchHit {
	return &corev1.PolicySearchHit{
		Policy: p, Rank: 0.4,
		Snippet: &corev1.PolicySearchSnippet{Text: "attach a photo", Matches: []*corev1.SearchMatch{{Start: 9, Length: 5}}},
	}
}

func titleHit(p *corev1.Policy) *corev1.PolicySearchHit {
	return &corev1.PolicySearchHit{Policy: p, Rank: 1.9, TitleMatch: true, TitleRank: 1.5}
}

// searchEnv: g-open is readable by everyone but obfuscated for site admins in group Admins;
// g-hidden is denied to group Readers.
func newSearchEnv(hits ...*corev1.PolicySearchHit) (*searchPolicyClient, *raciCategoryClient) {
	pols := map[string]*corev1.Policy{}
	for _, h := range hits {
		pols[h.Policy.Id] = h.Policy
	}
	pc := &searchPolicyClient{fakePolicyClient: &fakePolicyClient{policies: pols}, hits: hits}
	gc := newRaciReadClient(
		map[string]*corev1.Category{openCat: {Id: openCat, Name: "OPEN"}, hiddenCat: {Id: hiddenCat, Name: "HIDDEN"}},
		map[string][]*corev1.CategoryRule{
			openCat:   {denyGroupRule("Admins"), allowEveryoneRule()},
			hiddenCat: {denyGroupRule("Readers"), allowEveryoneRule()},
		},
	)
	return pc, gc
}

func searchReaderCtx(t *testing.T) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: "reader", RolesValue: []string{"reader"}, IdpGroupsValue: []string{"Readers"}})
}

func searchAdminCtx(t *testing.T) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: "admin", RolesValue: []string{"site-admin"}, IdpGroupsValue: []string{"Admins"}})
}

func runSearch(ctx context.Context, pc *searchPolicyClient, gc *raciCategoryClient, admin identityv1.IdentityAdminServiceClient, query string, first *int, after *string) (*resolvers.PolicySearchPage, error) {
	return resolvers.SearchPolicies(ctx, pc, gc, admin, nil, nil, query, nil, first, after)
}

func hitIDs(p *resolvers.PolicySearchPage) []string {
	out := make([]string, 0, len(p.Hits))
	for _, h := range p.Hits {
		out = append(out, h.Policy.ID)
	}
	return out
}

func searchPtr[T any](v T) *T { return &v }

func TestSearchPolicies_ReadableMatchHasSnippetAndMarks(t *testing.T) {
	pc, gc := newSearchEnv(textHit(searchPolicy("a", "Expense Claims Policy", openCat)))
	page, err := runSearch(searchReaderCtx(t), pc, gc, nil, "photo", nil, nil)
	if err != nil {
		t.Fatalf("SearchPolicies: %v", err)
	}
	if len(page.Hits) != 1 || page.NextPageToken != "" {
		t.Fatalf("page = %+v", page)
	}
	h := page.Hits[0]
	if h.Policy.Title != "Expense Claims Policy" || h.Policy.ViewerCan == nil || !h.Policy.ViewerCan.Read || h.Rank != 0.4 {
		t.Fatalf("hit = %+v", h)
	}
	if h.Snippet == nil || h.Snippet.Text != "attach a photo" || len(h.Snippet.Matches) != 1 ||
		h.Snippet.Matches[0].Start != 9 || h.Snippet.Matches[0].Length != 5 {
		t.Fatalf("snippet = %+v", h.Snippet)
	}
	if c := pc.calls[0]; c.GetQuery() != "photo" || c.GetOffset() != 0 {
		t.Fatalf("core call = %v", c)
	}
}

func TestSearchPolicies_LeavesOutAPolicyTheViewerCannotRead(t *testing.T) {
	pc, gc := newSearchEnv(textHit(searchPolicy("hid", "Hidden Policy", hiddenCat)), textHit(searchPolicy("a", "Open Policy", openCat)))
	page, err := runSearch(searchReaderCtx(t), pc, gc, nil, "photo", nil, nil)
	if err != nil {
		t.Fatalf("SearchPolicies: %v", err)
	}
	if got := hitIDs(page); len(got) != 1 || got[0] != "a" {
		t.Fatalf("hits = %v, want only a", got)
	}
}

func TestSearchPolicies_ObfuscatedViewerMatchesOnTitleAndNumberOnly(t *testing.T) {
	text := textHit(searchPolicy("body", "Archive Access Policy", openCat)) // "archive quarter": quarter only in the text
	title := titleHit(searchPolicy("head", "Archive Policy", openCat))
	pc, gc := newSearchEnv(text, title)
	page, err := runSearch(searchAdminCtx(t), pc, gc, nil, "archive", nil, nil)
	if err != nil {
		t.Fatalf("SearchPolicies: %v", err)
	}
	if got := hitIDs(page); len(got) != 1 || got[0] != "head" {
		t.Fatalf("hits = %v, want only the title match", got)
	}
	h := page.Hits[0]
	if h.Snippet != nil {
		t.Fatalf("an obfuscated viewer got a snippet: %+v", h.Snippet)
	}
	if !h.Policy.ViewerCan.ContentObfuscated || h.Rank != 1.5 {
		t.Fatalf("obfuscated = %v rank = %v, want true and the title rank 1.5", h.Policy.ViewerCan.ContentObfuscated, h.Rank)
	}
}

func TestSearchPolicies_BreakGlassReadIsSearchedLikeAnObfuscatedOne(t *testing.T) {
	text := textHit(searchPolicy("body", "Archive Access Policy", openCat))
	title := titleHit(searchPolicy("head", "Archive Policy", openCat))
	pc, gc := newSearchEnv(text, title)
	admin := &fakeBreakGlassAdmin{activeResp: &identityv1.ActiveBreakGlassResponse{PolicyNumbers: []string{"POL-BODY", "POL-HEAD"}}}
	// An admin the category rules do not exclude reads in full, but a grant-only read must not
	// reach the text through search.
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin", RolesValue: []string{"site-admin"}})
	page, err := runSearch(ctx, pc, gc, admin, "archive", nil, nil)
	if err != nil {
		t.Fatalf("SearchPolicies: %v", err)
	}
	if got := hitIDs(page); len(got) != 1 || got[0] != "head" || page.Hits[0].Snippet != nil {
		t.Fatalf("hits = %v snippet = %+v", got, page.Hits)
	}
}

func TestSearchPolicies_PagesAcrossHitsTheViewerCannotRead(t *testing.T) {
	var hits []*corev1.PolicySearchHit
	for _, id := range []string{"a", "hid1", "b", "hid2", "hid3", "c", "d"} {
		cat := openCat
		if strings.HasPrefix(id, "hid") {
			cat = hiddenCat
		}
		hits = append(hits, textHit(searchPolicy(id, "Policy "+id, cat)))
	}
	pc, gc := newSearchEnv(hits...)
	ctx := searchReaderCtx(t)

	var seen []string
	var after *string
	for range 5 {
		page, err := runSearch(ctx, pc, gc, nil, "photo", searchPtr(2), after)
		if err != nil {
			t.Fatalf("SearchPolicies: %v", err)
		}
		seen = append(seen, hitIDs(page)...)
		if page.NextPageToken == "" {
			break
		}
		if len(page.Hits) != 2 {
			t.Fatalf("a page with another behind it held %d hits", len(page.Hits))
		}
		after = searchPtr(page.NextPageToken)
	}
	if strings.Join(seen, ",") != "a,b,c,d" {
		t.Fatalf("paged hits = %v, want a,b,c,d", seen)
	}
}

func TestSearchPolicies_FirstPageOfTwoCarriesAToken(t *testing.T) {
	pc, gc := newSearchEnv(textHit(searchPolicy("a", "A", openCat)), textHit(searchPolicy("b", "B", openCat)), textHit(searchPolicy("c", "C", openCat)))
	page, err := runSearch(searchReaderCtx(t), pc, gc, nil, "x", searchPtr(2), nil)
	if err != nil || len(page.Hits) != 2 || page.NextPageToken == "" {
		t.Fatalf("page = %+v err = %v", page, err)
	}
}

func TestSearchPolicies_RefusesABadTokenOrPageSize(t *testing.T) {
	pc, gc := newSearchEnv(textHit(searchPolicy("a", "A", openCat)))
	cases := map[string]struct {
		first *int
		after *string
	}{
		"not base64":   {after: searchPtr("not-a-token")},
		"wrong prefix": {after: searchPtr(base64.RawURLEncoding.EncodeToString([]byte("other:3")))},
		"negative":     {after: searchPtr(base64.RawURLEncoding.EncodeToString([]byte("search:-1")))},
		"zero first":   {first: searchPtr(0)},
		"negative one": {first: searchPtr(-1)},
	}
	for name, c := range cases {
		if _, err := runSearch(searchReaderCtx(t), pc, gc, nil, "x", c.first, c.after); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: code = %v (%v), want InvalidArgument", name, status.Code(err), err)
		}
	}
	if len(pc.calls) != 0 {
		t.Fatalf("a refused request reached core %d times", len(pc.calls))
	}
}

func TestSearchPolicies_BlankQueryFindsNothingWithoutAskingCore(t *testing.T) {
	pc, gc := newSearchEnv(textHit(searchPolicy("a", "A", openCat)))
	page, err := runSearch(searchReaderCtx(t), pc, gc, nil, "  ", nil, nil)
	if err != nil || len(page.Hits) != 0 || page.NextPageToken != "" || len(pc.calls) != 0 {
		t.Fatalf("page = %+v err = %v calls = %d", page, err, len(pc.calls))
	}
}

func TestSearchPolicies_PassesTheDocumentTypeAndCapsThePageSize(t *testing.T) {
	pc, gc := newSearchEnv(textHit(searchPolicy("a", "A", openCat)))
	dt := resolvers.DocumentTypeProcedure
	if _, err := resolvers.SearchPolicies(searchReaderCtx(t), pc, gc, nil, nil, nil, "x", &dt, searchPtr(500), nil); err != nil {
		t.Fatalf("SearchPolicies: %v", err)
	}
	c := pc.calls[0]
	if c.GetDocumentType() != corev1.DocumentType_DOCUMENT_TYPE_PROCEDURE || c.GetLimit() > 100 {
		t.Fatalf("core call = %v", c)
	}
}

func TestSearchPolicies_NeedsASignedInUserAndRelaysACoreFault(t *testing.T) {
	pc, gc := newSearchEnv()
	if _, err := runSearch(context.Background(), pc, gc, nil, "x", nil, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous: %v", err)
	}
	pc.err = status.Error(codes.Unavailable, "core down")
	if _, err := runSearch(searchReaderCtx(t), pc, gc, nil, "x", nil, nil); status.Code(err) != codes.Unavailable {
		t.Fatalf("core fault: %v", err)
	}
}
