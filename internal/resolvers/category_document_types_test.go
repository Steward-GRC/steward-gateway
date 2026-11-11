// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// These tests map the mock server's category-document-types cases
// (steward-mock-server src/product/category-document-types.test.ts) onto the
// gateway. Core decides every refusal (steward-core#34, #78): the gateway
// exposes the setting, forwards the set and count calls for a site admin, and
// relays core's coded 4007 and 4008 to the client untouched.

// typesCategoryClient holds categories by id and answers like core: it keeps
// the setting, refuses a narrowing with 4008 when the id is in held, and
// counts from counts.
type typesCategoryClient struct {
	corev1.CategoryServiceClient
	cats      map[string]*corev1.Category
	held      map[string]*corev1.CountCategoryDocumentsResponse
	lastSet   *corev1.SetCategoryDocumentTypesRequest
	lastCount *corev1.CountCategoryDocumentsRequest
	setErr    error
}

func (f *typesCategoryClient) GetCategory(_ context.Context, in *corev1.GetCategoryRequest, _ ...grpc.CallOption) (*corev1.GetCategoryResponse, error) {
	return &corev1.GetCategoryResponse{Category: f.cats[in.GetId()]}, nil
}

func (f *typesCategoryClient) SetCategoryDocumentTypes(_ context.Context, in *corev1.SetCategoryDocumentTypesRequest, _ ...grpc.CallOption) (*corev1.SetCategoryDocumentTypesResponse, error) {
	f.lastSet = in
	if f.setErr != nil {
		return nil, f.setErr
	}
	c := f.cats[in.GetId()]
	c.DocumentTypes = in.GetDocumentTypes()
	return &corev1.SetCategoryDocumentTypesResponse{Category: c}, nil
}

func (f *typesCategoryClient) CountCategoryDocuments(_ context.Context, in *corev1.CountCategoryDocumentsRequest, _ ...grpc.CallOption) (*corev1.CountCategoryDocumentsResponse, error) {
	f.lastCount = in
	if n, ok := f.held[in.GetCategoryId()]; ok {
		return n, nil
	}
	return &corev1.CountCategoryDocumentsResponse{}, nil
}

func newTypesClient() *typesCategoryClient {
	return &typesCategoryClient{
		cats: map[string]*corev1.Category{
			"category-expenses":   {Id: "category-expenses", DocumentTypes: corev1.CategoryDocumentTypes_CATEGORY_DOCUMENT_TYPES_POLICIES},
			"category-conduct":    {Id: "category-conduct", DocumentTypes: corev1.CategoryDocumentTypes_CATEGORY_DOCUMENT_TYPES_PROCEDURES},
			"category-workplace":  {Id: "category-workplace", DocumentTypes: corev1.CategoryDocumentTypes_CATEGORY_DOCUMENT_TYPES_NONE},
			"category-finance":    {Id: "category-finance", DocumentTypes: corev1.CategoryDocumentTypes_CATEGORY_DOCUMENT_TYPES_BOTH},
			"category-purchasing": {Id: "category-purchasing"},
		},
		held: map[string]*corev1.CountCategoryDocumentsResponse{
			"category-expenses": {Policies: 3, Procedures: 0},
		},
	}
}

var refusesTypeMeta = func(types, accepts, hint string) map[string]string {
	return map[string]string{"category": "Expenses", "type": "procedure", "types": types, "accepts": accepts, "hint": hint}
}

// --- reading the setting -----------------------------------------------------------------

// Mock: "has one category of each kind" and "reads through the gateway's
// category fields". Every setting maps to its GraphQL value; a category stored
// before the setting existed (UNSPECIFIED) reads as BOTH, as core reads it.
func TestCategoryDocumentTypes_ReadMapsEveryValue(t *testing.T) {
	cc := newTypesClient()
	want := map[string]string{
		"category-expenses":   "POLICIES",
		"category-conduct":    "PROCEDURES",
		"category-workplace":  "NONE",
		"category-finance":    "BOTH",
		"category-purchasing": "BOTH",
	}
	for id, w := range want {
		t.Run(id, func(t *testing.T) {
			out := lockGraphQL(t, ctxWithRoles(t, "alice", []string{"site-admin"}), &resolvers.Resolver{CategoryClient: cc},
				`query ($id: ID!) { category(id: $id) { documentTypes } }`, map[string]any{"id": id})
			if len(out.Errors) != 0 {
				t.Fatalf("errors: %+v", out.Errors)
			}
			var got struct {
				DocumentTypes string `json:"documentTypes"`
			}
			if err := json.Unmarshal(out.Data["category"], &got); err != nil {
				t.Fatal(err)
			}
			if got.DocumentTypes != w {
				t.Fatalf("documentTypes = %q, want %q", got.DocumentTypes, w)
			}
		})
	}
}

// --- creating and moving -----------------------------------------------------------------

// typesPolicyClient refuses create and move like core does for a category that
// does not take the type, and records what reached it.
type typesPolicyClient struct {
	*fakePolicyClient
	moveErr  error
	lastMove *corev1.MovePolicyRequest
}

func (f *typesPolicyClient) MovePolicy(_ context.Context, in *corev1.MovePolicyRequest, _ ...grpc.CallOption) (*corev1.MovePolicyResponse, error) {
	f.lastMove = in
	if f.moveErr != nil {
		return nil, f.moveErr
	}
	return &corev1.MovePolicyResponse{Policy: &corev1.Policy{Id: in.GetPolicyId(), HomeCategoryId: in.GetHomeCategoryId()}}, nil
}

// Mock: "refuses a procedure in a policies-only category and a policy in a
// procedures-only one" and "refuses any document in a container and says to
// pick a child category". Core refuses with 4007 on createPolicy; the client
// sees the symbol, the number, core's message (the container hint included) and
// the metadata keys.
func TestCreatePolicy_RefusedTypeReachesTheClientCoded(t *testing.T) {
	cases := []struct {
		name, category, docType, msg string
		md                           map[string]string
	}{
		{"procedure in policies-only", "category-expenses", "PROCEDURE",
			"Category Expenses does not accept procedures. It holds policies only.", refusesTypeMeta("procedures", "policies", "It holds policies only.")},
		{"policy in procedures-only", "category-conduct", "POLICY",
			"Category Conduct does not accept policies. It holds procedures only.", refusesTypeMeta("policies", "procedures", "It holds procedures only.")},
		{"anything in a container", "category-workplace", "POLICY",
			"Category Workplace does not accept policies. It only holds other categories. Pick a child category.", refusesTypeMeta("policies", "none", "It only holds other categories. Pick a child category.")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, gc := draftPointerEnv(nil)
			lp := &lockPolicyClient{fakePolicyClient: pc, createErr: codedCoreError(t, codes.FailedPrecondition, 4007, "CATEGORY_REFUSES_TYPE", tc.msg, tc.md)}
			out := lockGraphQL(t, ctxWithRoles(t, "bob", []string{"site-admin"}), &resolvers.Resolver{PolicyClient: lp, CategoryClient: gc},
				`mutation ($home: ID!, $type: DocumentType) { createPolicy(homeCategoryId: $home, documentType: $type, sensitivity: STANDARD, title: "A document") { id } }`,
				map[string]any{"home": tc.category, "type": tc.docType})
			wantCoded(t, out, 4007, "CATEGORY_REFUSES_TYPE", tc.msg)
			for k, v := range tc.md {
				if out.Errors[0].Extensions[k] != v {
					t.Errorf("extensions %s = %v, want %q", k, out.Errors[0].Extensions[k], v)
				}
			}
			if pc.lastCreate.GetHomeCategoryId() != tc.category {
				t.Fatalf("the home category must reach core as asked, got %q", pc.lastCreate.GetHomeCategoryId())
			}
		})
	}
}

// Mock: "accepts a document of the kind the category holds". The gateway holds
// no type rule: it forwards the asked type and category for core to decide.
func TestCreatePolicy_ForwardsTheDocumentTypeForCoreToCheck(t *testing.T) {
	pc := &fakePolicyClient{}
	dt := resolvers.DocumentTypeProcedure
	if _, err := resolvers.CreatePolicy(ctxWithRoles(t, "bob", []string{"site-admin"}), pc, nil, "category-conduct", "A document", resolvers.SensitivityStandard, nil, &dt); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if pc.lastCreate.GetDocumentType() != corev1.DocumentType_DOCUMENT_TYPE_PROCEDURE || pc.lastCreate.GetHomeCategoryId() != "category-conduct" {
		t.Fatalf("request: %+v", pc.lastCreate)
	}
}

// Mock: "refuses to move a document into a category that does not hold its
// type". Core's 4007 on movePolicy reaches the client coded.
func TestMovePolicy_RefusedTypeReachesTheClientCoded(t *testing.T) {
	msg := "Category Conduct does not accept policies. It holds procedures only."
	pc := &typesPolicyClient{
		fakePolicyClient: &fakePolicyClient{},
		moveErr:          codedCoreError(t, codes.FailedPrecondition, 4007, "CATEGORY_REFUSES_TYPE", msg, refusesTypeMeta("policies", "procedures", "It holds procedures only.")),
	}
	out := lockGraphQL(t, ctxWithRoles(t, "alice", []string{"site-admin"}), &resolvers.Resolver{PolicyClient: pc},
		`mutation { movePolicy(policyId: "pol", homeCategoryId: "category-conduct") { id } }`, nil)
	wantCoded(t, out, 4007, "CATEGORY_REFUSES_TYPE", msg)
	if pc.lastMove.GetHomeCategoryId() != "category-conduct" {
		t.Fatalf("target must reach core as asked: %+v", pc.lastMove)
	}
}

// --- counting ----------------------------------------------------------------------------

// Mock: "counts the policies and procedures a category holds".
func TestCountCategoryDocuments_ReturnsBothCounts(t *testing.T) {
	cc := newTypesClient()
	got, err := resolvers.CountCategoryDocuments(ctxWithRoles(t, "alice", []string{"site-admin"}), cc, "category-expenses")
	if err != nil {
		t.Fatalf("CountCategoryDocuments: %v", err)
	}
	if cc.lastCount.GetCategoryId() != "category-expenses" {
		t.Fatalf("forwarded request: %+v", cc.lastCount)
	}
	if got.Policies != 3 || got.Procedures != 0 {
		t.Fatalf("counts: %+v", got)
	}
}

func TestCountCategoryDocuments_OverGraphQL(t *testing.T) {
	cc := newTypesClient()
	out := lockGraphQL(t, ctxWithRoles(t, "alice", []string{"site-admin"}), &resolvers.Resolver{CategoryClient: cc},
		`query ($c: ID!) { categoryDocumentCounts(categoryId: $c) { policies procedures } }`, map[string]any{"c": "category-expenses"})
	if len(out.Errors) != 0 {
		t.Fatalf("errors: %+v", out.Errors)
	}
	var got struct{ Policies, Procedures int }
	if err := json.Unmarshal(out.Data["categoryDocumentCounts"], &got); err != nil {
		t.Fatal(err)
	}
	if got.Policies != 3 || got.Procedures != 0 {
		t.Fatalf("counts: %+v", got)
	}
}

// The count feeds the admin form, so it is for a site admin like the other
// category settings, and a refused caller never reaches core.
func TestCountCategoryDocuments_RequiresSiteAdmin(t *testing.T) {
	cc := newTypesClient()
	_, err := resolvers.CountCategoryDocuments(ctxWithRoles(t, "bob", []string{"policy-author"}), cc, "category-expenses")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if cc.lastCount != nil {
		t.Fatal("a refused caller must not reach core")
	}
}

// --- setting -----------------------------------------------------------------------------

// Mock: "narrows an empty category and widens any category". Each GraphQL value
// reaches core as its proto value with the signed-in user as the actor.
func TestSetCategoryDocumentTypes_ForwardsEveryValue(t *testing.T) {
	cases := map[resolvers.CategoryDocumentTypes]corev1.CategoryDocumentTypes{
		resolvers.CategoryDocumentTypesBoth:       corev1.CategoryDocumentTypes_CATEGORY_DOCUMENT_TYPES_BOTH,
		resolvers.CategoryDocumentTypesPolicies:   corev1.CategoryDocumentTypes_CATEGORY_DOCUMENT_TYPES_POLICIES,
		resolvers.CategoryDocumentTypesProcedures: corev1.CategoryDocumentTypes_CATEGORY_DOCUMENT_TYPES_PROCEDURES,
		resolvers.CategoryDocumentTypesNone:       corev1.CategoryDocumentTypes_CATEGORY_DOCUMENT_TYPES_NONE,
	}
	for in, want := range cases {
		t.Run(string(in), func(t *testing.T) {
			cc := newTypesClient()
			got, err := resolvers.SetCategoryDocumentTypes(ctxWithRoles(t, "alice", []string{"site-admin"}), cc, "category-purchasing", in)
			if err != nil {
				t.Fatalf("SetCategoryDocumentTypes: %v", err)
			}
			if cc.lastSet.GetId() != "category-purchasing" || cc.lastSet.GetDocumentTypes() != want || cc.lastSet.GetActorUserId() != "alice" {
				t.Fatalf("forwarded request: %+v", cc.lastSet)
			}
			if got.DocumentTypes != in {
				t.Fatalf("returned documentTypes = %q, want %q", got.DocumentTypes, in)
			}
		})
	}
}

// Mock: "is for a site admin only".
func TestSetCategoryDocumentTypes_RequiresSiteAdmin(t *testing.T) {
	cc := newTypesClient()
	_, err := resolvers.SetCategoryDocumentTypes(ctxWithRoles(t, "bob", []string{"policy-author"}), cc, "category-workplace", resolvers.CategoryDocumentTypesBoth)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if cc.lastSet != nil {
		t.Fatal("a refused caller must not reach core")
	}
}

// Mock: "refuses to narrow while documents would be stranded, with the count".
// Core refuses with 4008 and the counts in the metadata; the client sees the
// symbol, the number, core's message and count, policies and procedures as
// extensions, so the form can link to a bulk move.
func TestSetCategoryDocumentTypes_HoldsDocumentsReachesTheClientCoded(t *testing.T) {
	msg := "Can't change what Expenses accepts: it holds 3 documents the new setting would not accept (3 policies, 0 procedures). Move them to another category first."
	cc := newTypesClient()
	cc.setErr = codedCoreError(t, codes.FailedPrecondition, 4008, "CATEGORY_HOLDS_DOCUMENTS", msg,
		map[string]string{"category": "Expenses", "count": "3", "policies": "3", "procedures": "0"})
	out := lockGraphQL(t, ctxWithRoles(t, "alice", []string{"site-admin"}), &resolvers.Resolver{CategoryClient: cc},
		`mutation { setCategoryDocumentTypes(id: "category-expenses", documentTypes: PROCEDURES) { id documentTypes } }`, nil)
	wantCoded(t, out, 4008, "CATEGORY_HOLDS_DOCUMENTS", msg)
	ext := out.Errors[0].Extensions
	if ext["count"] != "3" || ext["policies"] != "3" || ext["procedures"] != "0" || ext["category"] != "Expenses" {
		t.Errorf("count metadata missing from extensions: %+v", ext)
	}
	if cc.cats["category-expenses"].DocumentTypes != corev1.CategoryDocumentTypes_CATEGORY_DOCUMENT_TYPES_POLICIES {
		t.Fatal("a refused narrowing must leave the setting alone")
	}
}

func TestSetCategoryDocumentTypes_OverGraphQL(t *testing.T) {
	cc := newTypesClient()
	out := lockGraphQL(t, ctxWithRoles(t, "alice", []string{"site-admin"}), &resolvers.Resolver{CategoryClient: cc},
		`mutation ($id: ID!, $t: CategoryDocumentTypes!) { setCategoryDocumentTypes(id: $id, documentTypes: $t) { id documentTypes } }`,
		map[string]any{"id": "category-workplace", "t": "BOTH"})
	if len(out.Errors) != 0 {
		t.Fatalf("errors: %+v", out.Errors)
	}
	var got struct{ ID, DocumentTypes string }
	if err := json.Unmarshal(out.Data["setCategoryDocumentTypes"], &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "category-workplace" || got.DocumentTypes != "BOTH" {
		t.Fatalf("answer: %+v", got)
	}
}
