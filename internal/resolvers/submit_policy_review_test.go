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
	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// TestSubmitPolicyReviewResolver_bindsClaimsAndEncodesInput checks the direct
// resolver path: actor from claims, group scope-hint honoured, policyId/
// versionId passed through, and the REVIEW input JSON-encoded into
// SubmitAIJobRequest.input_json.
func TestSubmitPolicyReviewResolver_bindsClaimsAndEncodesInput(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "aijob-rev-1"}}

	groupID := "g-7"
	title := "Onboarding Policy"
	res, err := resolvers.SubmitPolicyReviewResolver(
		ctxWithUser(t, "u-42"), client, aiAuthorCategory("g-7", "u-42"), nil,
		resolvers.SubmitPolicyReviewInput{
			PolicyID:   "pol-1",
			VersionID:  "ver-1",
			CategoryID: &groupID,
			Title:      &title,
			Sections: []*resolvers.SubmitPolicyReviewSectionInput{
				{Key: "purpose", Title: "Purpose", Content: "This policy establishes onboarding requirements."},
			},
			StandardsRefs:     []string{"ISO 27001 §7.2"},
			RelatedPolicyRefs: []string{"Contractor Access Policy"},
		},
	)
	if err != nil {
		t.Fatalf("SubmitPolicyReview: %v", err)
	}
	if res.JobID != "aijob-rev-1" {
		t.Fatalf("jobId: got %q", res.JobID)
	}

	req := client.lastSubmitReq
	if req == nil {
		t.Fatal("AI client SubmitAIJob never invoked")
	}
	if client.lastActor != "u-42" {
		t.Fatalf("actor not bound from claims: %q", client.lastActor)
	}
	if req.CategoryId != "g-7" {
		t.Fatalf("group id: got %q", req.CategoryId)
	}
	if req.PolicyId != "pol-1" || req.VersionId != "ver-1" {
		t.Fatalf("policy/version id not passed through: %+v", req)
	}
	if req.Operation != aiv1.JobOperation_JOB_OPERATION_REVIEW {
		t.Fatalf("operation: got %v", req.Operation)
	}

	// input_json must decode to the REVIEW payload shape the operator expects.
	var payload struct {
		Title    string `json:"title"`
		Sections []struct {
			Key     string `json:"key"`
			Title   string `json:"title"`
			Content string `json:"content"`
		} `json:"sections"`
		StandardsRefs     []string `json:"standardsRefs"`
		RelatedPolicyRefs []string `json:"relatedPolicyRefs"`
	}
	if err := json.Unmarshal([]byte(req.InputJson), &payload); err != nil {
		t.Fatalf("input_json is not valid JSON: %v (%q)", err, req.InputJson)
	}
	if payload.Title != "Onboarding Policy" {
		t.Fatalf("title not encoded: %+v", payload)
	}
	if len(payload.Sections) != 1 || payload.Sections[0].Content != "This policy establishes onboarding requirements." {
		t.Fatalf("sections not encoded with content: %+v", payload.Sections)
	}
	if len(payload.StandardsRefs) != 1 || len(payload.RelatedPolicyRefs) != 1 {
		t.Fatalf("standards/related-policy refs not encoded: %+v", payload)
	}
}

// TestSubmitPolicyReviewResolver_rejectsForeignGroup ensures an out-of-scope
// groupId hint is refused before the AI service is dialed.
func TestSubmitPolicyReviewResolver_rejectsForeignGroup(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "nope"}}

	foreign := "g-999"
	_, err := resolvers.SubmitPolicyReviewResolver(
		ctxWithUser(t, "u-1"), client, nil, nil,
		resolvers.SubmitPolicyReviewInput{
			PolicyID: "pol-1", VersionID: "ver-1", CategoryID: &foreign,
			Sections: []*resolvers.SubmitPolicyReviewSectionInput{{Key: "purpose", Title: "Purpose", Content: "body"}},
		},
	)
	if err == nil {
		t.Fatal("expected permission denied for a group the caller is not in")
	}
	if client.lastSubmitReq != nil {
		t.Fatal("AI service must not be dialed when the group check fails")
	}
}

// TestSubmitPolicyReviewResolver_requiresAuth rejects an unauthenticated caller.
func TestSubmitPolicyReviewResolver_requiresAuth(t *testing.T) {
	client := &fakeAIClient{}
	_, err := resolvers.SubmitPolicyReviewResolver(
		t.Context(), client, nil, nil,
		resolvers.SubmitPolicyReviewInput{PolicyID: "pol-1", VersionID: "ver-1"},
	)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
}

// TestSubmitPolicyReviewGraphQLEndToEnd drives a real GraphQL mutation
// through the generated executable schema (variable coercion,
// unmarshalInputSubmitPolicyReview*, Mutation dispatch, result marshaling)
// — the hand-maintained parts of generated.go.
func TestSubmitPolicyReviewGraphQLEndToEnd(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "aijob-rev-e2e"}}

	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{
		Resolvers: &resolvers.Resolver{AIClient: client, CategoryClient: aiAuthorCategory("g-7", "u-42")},
	}))
	srv.AddTransport(transport.POST{})

	body, err := json.Marshal(map[string]any{
		"query": `mutation($input: SubmitPolicyReviewInput!) {
			submitPolicyReview(input: $input) { jobId }
		}`,
		"variables": map[string]any{
			"input": map[string]any{
				"policyId":   "pol-1",
				"versionId":  "ver-1",
				"categoryId": "g-7",
				"title":      "Onboarding Policy",
				"sections": []map[string]any{
					{"key": "purpose", "title": "Purpose", "content": "This policy establishes onboarding requirements."},
				},
				"standardsRefs":     []string{"ISO 27001 §7.2"},
				"relatedPolicyRefs": []string{"Contractor Access Policy"},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest("POST", "/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithUser(t, "u-42"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data struct {
			SubmitPolicyReview struct {
				JobID string `json:"jobId"`
			} `json:"submitPolicyReview"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, rec.Body.String())
	}
	if len(out.Errors) > 0 {
		t.Fatalf("unexpected GraphQL errors: %+v\nbody: %s", out.Errors, rec.Body.String())
	}
	if out.Data.SubmitPolicyReview.JobID != "aijob-rev-e2e" {
		t.Fatalf("jobId: got %q", out.Data.SubmitPolicyReview.JobID)
	}

	// Confirm the input really flowed through GraphQL unmarshaling into the proto.
	if client.lastSubmitReq == nil || client.lastActor != "u-42" {
		t.Fatalf("actor not bound through GraphQL path: %+v", client.lastSubmitReq)
	}
	if client.lastSubmitReq.Operation != aiv1.JobOperation_JOB_OPERATION_REVIEW {
		t.Fatalf("operation not REVIEW: %v", client.lastSubmitReq.Operation)
	}
	if client.lastSubmitReq.PolicyId != "pol-1" || client.lastSubmitReq.VersionId != "ver-1" {
		t.Fatalf("policy/version id not passed through GraphQL path: %+v", client.lastSubmitReq)
	}
}
