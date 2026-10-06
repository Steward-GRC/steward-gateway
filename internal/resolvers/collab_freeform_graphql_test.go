// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	collabv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/collab/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// issueCollabTokenOverGraphQL drives a real issueCollabToken mutation through
// the generated executable schema, so input coercion — the part that enforces
// IssueCollabTokenInput's nullability — is exercised rather than bypassed.
// Returns the GraphQL error messages (empty when the mutation succeeded) and
// the request the collab fake received.
func issueCollabTokenOverGraphQL(t *testing.T, uid string, input map[string]any) ([]string, *collabv1.IssueTokenRequest) {
	t.Helper()
	collab := &fakeCollabClient{
		resp: &collabv1.IssueTokenResponse{Token: "jwt-gql", WsUrl: "wss://collab/ws/d-1"},
	}
	pc, gc := coAuthMatrixEnv(uid, nil, nil)

	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{
		Resolvers: &resolvers.Resolver{CollabClient: collab, PolicyClient: pc, CategoryClient: gc},
	}))
	srv.AddTransport(transport.POST{})

	body, err := json.Marshal(map[string]any{
		"query": `mutation($input: IssueCollabTokenInput!) {
			issueCollabToken(input: $input) { token wsUrl }
		}`,
		"variables": map[string]any{"input": input},
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest("POST", "/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithUser(t, uid))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	// A variable-coercion failure is reported as HTTP 422 with GRAPHQL_
	// VALIDATION_FAILED, a resolver error as 200 with an errors array. Both are
	// legitimate outcomes for this helper, so only anything else is a fault.
	if rec.Code != 200 && rec.Code != 422 {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, rec.Body.String())
	}
	msgs := make([]string, 0, len(out.Errors))
	for _, e := range out.Errors {
		msgs = append(msgs, e.Message)
	}
	return msgs, collab.lastReq
}

// TestIssueCollabTokenGraphQL_FreeFormOmitsTemplateVersion is the decisive
// gateway test. templateVersionId was declared ID!, so a client
// could not express "this policy has no template" at all: gqlgen's input
// coercion rejected the mutation before any resolver ran, and since most
// policies are free-form that made co-editing unavailable for the normal case.
//
// With the field nullable, omitting it must be accepted and must reach collab
// as the empty sentinel.
func TestIssueCollabTokenGraphQL_FreeFormOmitsTemplateVersion(t *testing.T) {
	errs, req := issueCollabTokenOverGraphQL(t, "u-7", map[string]any{
		"policyId": "pol",
		"draftId":  "d-1",
		// templateVersionId omitted: this policy is free-form.
	})
	if len(errs) > 0 {
		t.Fatalf("omitting templateVersionId must be accepted; got GraphQL errors: %v", errs)
	}
	if req == nil {
		t.Fatal("expected collab IssueToken to be invoked")
	}
	if req.GetTemplateVersionId() != "" {
		t.Fatalf("template_version_id: got %q want empty", req.GetTemplateVersionId())
	}
}

// TestIssueCollabTokenGraphQL_FreeFormExplicitNull covers the explicit form:
// templateVersionId: null. Under ID! this was equally inexpressible.
func TestIssueCollabTokenGraphQL_FreeFormExplicitNull(t *testing.T) {
	errs, req := issueCollabTokenOverGraphQL(t, "u-7", map[string]any{
		"policyId":          "pol",
		"draftId":           "d-1",
		"templateVersionId": nil,
	})
	if len(errs) > 0 {
		t.Fatalf("an explicit null templateVersionId must be accepted; got: %v", errs)
	}
	if req == nil {
		t.Fatal("expected collab IssueToken to be invoked")
	}
	if req.GetTemplateVersionId() != "" {
		t.Fatalf("template_version_id: got %q want empty", req.GetTemplateVersionId())
	}
}

// TestIssueCollabTokenGraphQL_TemplatedStillPassesThrough is the unchanged
// case: a templated policy still sends its pinned id and it still arrives
// verbatim, so core's pin check sees the real value.
func TestIssueCollabTokenGraphQL_TemplatedStillPassesThrough(t *testing.T) {
	errs, req := issueCollabTokenOverGraphQL(t, "u-7", map[string]any{
		"policyId":          "pol",
		"draftId":           "d-1",
		"templateVersionId": "tv-1",
	})
	if len(errs) > 0 {
		t.Fatalf("unexpected GraphQL errors: %v", errs)
	}
	if req == nil {
		t.Fatal("expected collab IssueToken to be invoked")
	}
	if req.GetTemplateVersionId() != "tv-1" {
		t.Fatalf("template_version_id: got %q want tv-1", req.GetTemplateVersionId())
	}
}

// TestIssueCollabTokenGraphQL_StillRequiresPolicyAndDraft confirms policyId and
// draftId remain non-null in the SDL: coercion must still refuse them, and
// collab must never be called.
func TestIssueCollabTokenGraphQL_StillRequiresPolicyAndDraft(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input map[string]any
	}{
		{"no policyId", map[string]any{"draftId": "d-1"}},
		{"no draftId", map[string]any{"policyId": "pol"}},
		{"null policyId", map[string]any{"policyId": nil, "draftId": "d-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs, req := issueCollabTokenOverGraphQL(t, "u-7", tc.input)
			if len(errs) == 0 {
				t.Fatal("expected a GraphQL coercion error, got none")
			}
			if req != nil {
				t.Fatalf("collab must not be called on a coercion failure; got %+v", req)
			}
		})
	}
}
