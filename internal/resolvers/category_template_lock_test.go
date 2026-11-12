// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"github.com/Steward-GRC/steward-gateway/internal/server"
)

// These tests map the mock server's category-template-lock cases
// (steward-mock-server src/product/category-template-lock.test.ts) onto the
// gateway. Core decides every lock refusal (steward-core#74), so the gateway's
// job is: expose the flag, forward the lock call for a site admin, forward the
// create/set-template asks untouched, and relay core's coded refusals.

// lockCategoryClient is a category service that holds one lock flag and
// refuses like core does.
type lockCategoryClient struct {
	corev1.CategoryServiceClient
	cat      *corev1.Category
	lastLock *corev1.SetCategoryTemplateLockRequest
	err      error
}

func (f *lockCategoryClient) GetCategory(context.Context, *corev1.GetCategoryRequest, ...grpc.CallOption) (*corev1.GetCategoryResponse, error) {
	return &corev1.GetCategoryResponse{Category: f.cat}, nil
}

func (f *lockCategoryClient) SetCategoryTemplateLock(_ context.Context, in *corev1.SetCategoryTemplateLockRequest, _ ...grpc.CallOption) (*corev1.SetCategoryTemplateLockResponse, error) {
	f.lastLock = in
	if f.err != nil {
		return nil, f.err
	}
	f.cat.DefaultTemplateLocked = in.GetLocked()
	return &corev1.SetCategoryTemplateLockResponse{Category: f.cat}, nil
}

// codedCoreError is an error as core sends it: a gRPC status carrying the
// apperr ErrorInfo detail with the numeric code, symbol and metadata.
func codedCoreError(t *testing.T, c codes.Code, num int, symbol, message string, md map[string]string) error {
	t.Helper()
	meta := map[string]string{apperrgrpc.MetaCodeNum: strconv.Itoa(num)}
	for k, v := range md {
		meta[k] = v
	}
	st, err := status.New(c, message).WithDetails(&errdetails.ErrorInfo{Reason: symbol, Domain: "core", Metadata: meta})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

var errTemplateLocked = func(t *testing.T) error {
	return codedCoreError(t, codes.FailedPrecondition, 4004, "CATEGORY_TEMPLATE_LOCKED",
		"This category requires the Standard Policy template.", map[string]string{"template": "Standard Policy"})
}

// lockPolicyClient wraps the shared policy fake and refuses template asks the
// way core does when told to.
type lockPolicyClient struct {
	*fakePolicyClient
	setErr    error
	createErr error
}

func (f *lockPolicyClient) SetPolicyTemplate(ctx context.Context, in *corev1.SetPolicyTemplateRequest, opts ...grpc.CallOption) (*corev1.SetPolicyTemplateResponse, error) {
	if f.setErr != nil {
		f.lastSetTmpl = in
		return nil, f.setErr
	}
	return f.fakePolicyClient.SetPolicyTemplate(ctx, in, opts...)
}

func (f *lockPolicyClient) CreatePolicy(ctx context.Context, in *corev1.CreatePolicyRequest, opts ...grpc.CallOption) (*corev1.CreatePolicyResponse, error) {
	if f.createErr != nil {
		f.lastCreate = in
		return nil, f.createErr
	}
	return f.fakePolicyClient.CreatePolicy(ctx, in, opts...)
}

// --- setting the lock ---------------------------------------------------------------------

// Mock: "locks a category that names a default template".
func TestSetCategoryTemplateLock_LocksAndReturnsTheFlag(t *testing.T) {
	cc := &lockCategoryClient{cat: &corev1.Category{Id: "category-finance", DefaultTemplateId: "template-1"}}
	got, err := resolvers.SetCategoryTemplateLock(ctxWithRoles(t, "alice", []string{"site-admin"}), cc, "category-finance", true)
	if err != nil {
		t.Fatalf("SetCategoryTemplateLock: %v", err)
	}
	if cc.lastLock.GetId() != "category-finance" || !cc.lastLock.GetLocked() {
		t.Fatalf("forwarded request: %+v", cc.lastLock)
	}
	if cc.lastLock.GetActorUserId() != "alice" {
		t.Fatalf("actor must be the signed-in user, got %q", cc.lastLock.GetActorUserId())
	}
	if !got.DefaultTemplateLocked || got.DefaultTemplateID == nil || *got.DefaultTemplateID != "template-1" {
		t.Fatalf("returned category: %+v", got)
	}
}

// Mock: "is for a site admin".
func TestSetCategoryTemplateLock_RequiresSiteAdmin(t *testing.T) {
	cc := &lockCategoryClient{cat: &corev1.Category{Id: "category-finance", DefaultTemplateId: "template-1"}}
	_, err := resolvers.SetCategoryTemplateLock(ctxWithRoles(t, "bob", []string{"policy-author"}), cc, "category-finance", true)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if cc.lastLock != nil {
		t.Fatal("a refused caller must not reach core")
	}
}

// Mock: "needs a default template to lock". Core refuses with 4005; the
// resolver hands the coded error up untouched.
func TestSetCategoryTemplateLock_PassesThroughNeedsDefault(t *testing.T) {
	refusal := codedCoreError(t, codes.FailedPrecondition, 4005, "TEMPLATE_LOCK_NEEDS_DEFAULT",
		"Choose a default template for Travel before locking it.", map[string]string{"category": "Travel"})
	cc := &lockCategoryClient{cat: &corev1.Category{Id: "category-travel"}, err: refusal}
	_, err := resolvers.SetCategoryTemplateLock(ctxWithRoles(t, "alice", []string{"site-admin"}), cc, "category-travel", true)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
}

// Mock: "can be lifted again".
func TestSetCategoryTemplateLock_LiftsTheLock(t *testing.T) {
	cc := &lockCategoryClient{cat: &corev1.Category{Id: "category-finance", DefaultTemplateId: "template-1", DefaultTemplateLocked: true}}
	got, err := resolvers.SetCategoryTemplateLock(ctxWithRoles(t, "alice", []string{"site-admin"}), cc, "category-finance", false)
	if err != nil {
		t.Fatalf("SetCategoryTemplateLock: %v", err)
	}
	if cc.lastLock.GetLocked() {
		t.Fatal("locked=false must reach core as false")
	}
	if got.DefaultTemplateLocked {
		t.Fatal("the returned category must read unlocked")
	}
}

// The flag is part of every category read.
func TestCategoryReadsCarryTheTemplateLock(t *testing.T) {
	cc := &lockCategoryClient{cat: &corev1.Category{Id: "category-finance", DefaultTemplateId: "template-1", DefaultTemplateLocked: true}}
	got, err := resolvers.GetCategory(ctxWithRoles(t, "alice", []string{"site-admin"}), cc, "category-finance")
	if err != nil {
		t.Fatalf("GetCategory: %v", err)
	}
	if !got.DefaultTemplateLocked {
		t.Fatal("defaultTemplateLocked must be read from core")
	}
}

// --- creating under a locked category -----------------------------------------------------

// Mock: "uses the category's template when none is asked for". With no template
// asked for the gateway sends none; core inherits the locked template (it is
// allowed under a lock, steward-core#74).
func TestCreatePolicy_LockedCategory_InheritForwardsNoTemplate(t *testing.T) {
	pc := &lockPolicyClient{fakePolicyClient: &fakePolicyClient{}}
	if _, err := resolvers.CreatePolicy(ctxRoot(t, "bob"), pc, nil, "category-finance", "A document", resolvers.SensitivityStandard, nil, nil); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if pc.lastCreate.GetTemplateId() != "" {
		t.Fatalf("no template asked for must reach core empty, got %q", pc.lastCreate.GetTemplateId())
	}
}

// Mock: "accepts the locked template when it is named" and "lets any template
// through once the lock is lifted". The gateway holds no lock state, so it
// forwards the asked template and lets core decide.
func TestCreatePolicy_ForwardsTheNamedTemplate(t *testing.T) {
	pc := &lockPolicyClient{fakePolicyClient: &fakePolicyClient{}}
	tmpl := "template-1"
	if _, err := resolvers.CreatePolicy(ctxRoot(t, "bob"), pc, nil, "category-finance", "A document", resolvers.SensitivityStandard, &tmpl, nil); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if pc.lastCreate.GetTemplateId() != "template-1" {
		t.Fatalf("template forwarded: %q", pc.lastCreate.GetTemplateId())
	}
}

// Mock: "refuses another template" and "holds under a category that inherits
// the template". Core refuses with 4004 for the child category; the error
// reaches the caller as the same coded status.
func TestCreatePolicy_PassesThroughTemplateLocked(t *testing.T) {
	for _, home := range []string{"category-finance", "category-expenses"} {
		t.Run(home, func(t *testing.T) {
			pc := &lockPolicyClient{fakePolicyClient: &fakePolicyClient{}, createErr: errTemplateLocked(t)}
			other := "template-2"
			_, err := resolvers.CreatePolicy(ctxRoot(t, "bob"), pc, nil, home, "A document", resolvers.SensitivityStandard, &other, nil)
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("want FailedPrecondition, got %v", err)
			}
			if pc.lastCreate.GetHomeCategoryId() != home {
				t.Fatalf("the home category must reach core as asked, got %q", pc.lastCreate.GetHomeCategoryId())
			}
		})
	}
}

// --- changing the template afterwards ------------------------------------------------------

// Mock: "refuses freeform and another template, and allows the locked one".
// Freeform and another template are refused by core with 4004; the locked
// template is forwarded and succeeds. The asks reach core exactly as made.
func TestSetPolicyTemplate_LockedCategory(t *testing.T) {
	locked := "template-1"
	other := "template-2"
	cases := []struct {
		name    string
		tmpl    *string
		none    bool
		refused bool
	}{
		{"freeform is refused", nil, true, true},
		{"another template is refused", &other, false, true},
		{"the locked template is allowed", &locked, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, gc := draftPointerEnv(nil)
			lp := &lockPolicyClient{fakePolicyClient: pc}
			if tc.refused {
				lp.setErr = errTemplateLocked(t)
			}
			_, err := resolvers.SetPolicyTemplate(ctxRoot(t, "bob"), lp, gc, nil, nil, nil, "pol", tc.tmpl, tc.none)
			if tc.refused && status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("want FailedPrecondition, got %v", err)
			}
			if !tc.refused && err != nil {
				t.Fatalf("SetPolicyTemplate: %v", err)
			}
			if pc.lastSetTmpl.GetNone() != tc.none || pc.lastSetTmpl.GetTemplateId() != lockDeref(tc.tmpl) {
				t.Fatalf("ask reached core changed: %+v", pc.lastSetTmpl)
			}
		})
	}
}

// Core allows inheriting the category default under a lock (steward-core#74),
// where the mock refuses it. The gateway forwards "neither" untouched.
func TestSetPolicyTemplate_LockedCategory_InheritIsForwarded(t *testing.T) {
	pc, gc := draftPointerEnv(nil)
	lp := &lockPolicyClient{fakePolicyClient: pc}
	if _, err := resolvers.SetPolicyTemplate(ctxRoot(t, "bob"), lp, gc, nil, nil, nil, "pol", nil, false); err != nil {
		t.Fatalf("SetPolicyTemplate: %v", err)
	}
	if pc.lastSetTmpl.GetNone() || pc.lastSetTmpl.GetTemplateId() != "" {
		t.Fatalf("inherit must reach core as neither none nor a template: %+v", pc.lastSetTmpl)
	}
}

func lockDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- over GraphQL ---------------------------------------------------------------------------

type gqlAnswer struct {
	Data   map[string]json.RawMessage `json:"data"`
	Errors []struct {
		Message    string         `json:"message"`
		Extensions map[string]any `json:"extensions"`
	} `json:"errors"`
}

// lockGraphQL runs one operation through the generated schema with the
// server's error presenter, so the response is what the client would see.
func lockGraphQL(t *testing.T, ctx context.Context, res *resolvers.Resolver, query string, vars map[string]any) gqlAnswer {
	t.Helper()
	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{Resolvers: res}))
	srv.AddTransport(transport.POST{})
	srv.SetErrorPresenter(server.ErrorPresenter(log.Nop()))
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/query", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var out gqlAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, rec.Body.String())
	}
	return out
}

// The schema exposes setCategoryTemplateLock and Category.defaultTemplateLocked.
func TestSetCategoryTemplateLock_OverGraphQL(t *testing.T) {
	cc := &lockCategoryClient{cat: &corev1.Category{Id: "category-finance", DefaultTemplateId: "template-1"}}
	out := lockGraphQL(t, ctxWithRoles(t, "alice", []string{"site-admin"}), &resolvers.Resolver{CategoryClient: cc},
		`mutation ($id: ID!, $locked: Boolean!) {
			setCategoryTemplateLock(id: $id, locked: $locked) { id defaultTemplateId defaultTemplateLocked }
		}`, map[string]any{"id": "category-finance", "locked": true})
	if len(out.Errors) != 0 {
		t.Fatalf("errors: %+v", out.Errors)
	}
	var got struct {
		ID                    string `json:"id"`
		DefaultTemplateID     string `json:"defaultTemplateId"`
		DefaultTemplateLocked bool   `json:"defaultTemplateLocked"`
	}
	if err := json.Unmarshal(out.Data["setCategoryTemplateLock"], &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "category-finance" || got.DefaultTemplateID != "template-1" || !got.DefaultTemplateLocked {
		t.Fatalf("answer: %+v", got)
	}
}

// Core's 4004 and 4005 reach the client with their code symbol, number, domain
// and the business kind, and core's own message.
func TestTemplateLockRefusals_ReachTheClientCoded(t *testing.T) {
	t.Run("setPolicyTemplate 4004", func(t *testing.T) {
		pc, gc := draftPointerEnv(nil)
		lp := &lockPolicyClient{fakePolicyClient: pc, setErr: errTemplateLocked(t)}
		out := lockGraphQL(t, ctxRoot(t, "bob"), &resolvers.Resolver{PolicyClient: lp, CategoryClient: gc},
			`mutation { setPolicyTemplate(policyId: "pol", none: true) { id } }`, nil)
		wantCoded(t, out, 4004, "CATEGORY_TEMPLATE_LOCKED", "This category requires the Standard Policy template.")
	})
	t.Run("createPolicy 4004", func(t *testing.T) {
		pc, gc := draftPointerEnv(nil)
		lp := &lockPolicyClient{fakePolicyClient: pc, createErr: errTemplateLocked(t)}
		out := lockGraphQL(t, ctxRoot(t, "bob"), &resolvers.Resolver{PolicyClient: lp, CategoryClient: gc},
			`mutation { createPolicy(homeCategoryId: "g-cat", title: "T", sensitivity: STANDARD, templateId: "template-2") { id } }`, nil)
		wantCoded(t, out, 4004, "CATEGORY_TEMPLATE_LOCKED", "This category requires the Standard Policy template.")
	})
	t.Run("setCategoryTemplateLock 4005", func(t *testing.T) {
		refusal := codedCoreError(t, codes.FailedPrecondition, 4005, "TEMPLATE_LOCK_NEEDS_DEFAULT",
			"Choose a default template for Travel before locking it.", map[string]string{"category": "Travel"})
		cc := &lockCategoryClient{cat: &corev1.Category{Id: "category-travel"}, err: refusal}
		out := lockGraphQL(t, ctxRoot(t, "alice"), &resolvers.Resolver{CategoryClient: cc},
			`mutation { setCategoryTemplateLock(id: "category-travel", locked: true) { id } }`, nil)
		wantCoded(t, out, 4005, "TEMPLATE_LOCK_NEEDS_DEFAULT", "Choose a default template for Travel before locking it.")
	})
}

func wantCoded(t *testing.T, out gqlAnswer, num int, symbol, message string) {
	t.Helper()
	if len(out.Errors) != 1 {
		t.Fatalf("want one error, got %+v", out.Errors)
	}
	e := out.Errors[0]
	if e.Message != message {
		t.Errorf("message = %q, want %q", e.Message, message)
	}
	if e.Extensions["code"] != symbol {
		t.Errorf("code = %v, want %s", e.Extensions["code"], symbol)
	}
	if got, _ := e.Extensions["codeNum"].(float64); int(got) != num {
		t.Errorf("codeNum = %v, want %d", e.Extensions["codeNum"], num)
	}
	if e.Extensions["domain"] != "core" || e.Extensions["kind"] != "business" {
		t.Errorf("domain/kind = %v/%v, want core/business", e.Extensions["domain"], e.Extensions["kind"])
	}
}
