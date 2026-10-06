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

// TestSubmitPolicyRevisionResolver_bindsClaimsAndEncodesInput checks the
// direct resolver path: actor from claims, authorized-group projection
// carried through (there is no groupId scope hint on this mutation),
// policyId/versionId passed through, and the REVISE input JSON-encoded into
// SubmitAIJobRequest.input_json with the fixed shape the ai operator decodes
// (instruction, policyId, versionId, sections[key,title,content,order]).
func TestSubmitPolicyRevisionResolver_bindsClaimsAndEncodesInput(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "aijob-revise-1"}}

	res, err := resolvers.SubmitPolicyRevisionResolver(
		ctxWithUser(t, "u-42"), client, aiReadableCategory("g-7"), nil,
		resolvers.SubmitPolicyRevisionInput{
			PolicyID:    "pol-1",
			VersionID:   "ver-1",
			Instruction: "Add a data retention clause to section 3 and update the summary to match.",
			Sections: []*resolvers.PolicyRevisionSectionInput{
				{Key: "purpose", Title: "Purpose", Content: "This policy establishes onboarding requirements.", Order: 1},
				{Key: "retention", Title: "Data Retention", Content: "Data is retained for 7 years.", Order: 2},
			},
		},
	)
	if err != nil {
		t.Fatalf("SubmitPolicyRevision: %v", err)
	}
	if res.JobID != "aijob-revise-1" {
		t.Fatalf("jobId: got %q", res.JobID)
	}

	req := client.lastSubmitReq
	if req == nil {
		t.Fatal("AI client SubmitAIJob never invoked")
	}
	if client.lastActor != "u-42" {
		t.Fatalf("actor not bound from claims: %q", client.lastActor)
	}
	if ids := req.GetScope().GetCategoryIds(); len(ids) != 1 || ids[0] != "g-7" {
		t.Fatalf("read scope not carried through: %+v", req.GetScope())
	}
	if req.PolicyId != "pol-1" || req.VersionId != "ver-1" {
		t.Fatalf("policy/version id not passed through: %+v", req)
	}
	if req.Operation != aiv1.JobOperation_JOB_OPERATION_REVISE {
		t.Fatalf("operation: got %v, want JOB_OPERATION_REVISE", req.Operation)
	}

	// input_json must decode to the fixed REVISE payload shape the ai
	// operator expects: instruction, policyId, versionId, sections[...].
	var payload struct {
		Instruction string `json:"instruction"`
		PolicyID    string `json:"policyId"`
		VersionID   string `json:"versionId"`
		Sections    []struct {
			Key     string `json:"key"`
			Title   string `json:"title"`
			Content string `json:"content"`
			Order   int    `json:"order"`
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(req.InputJson), &payload); err != nil {
		t.Fatalf("input_json is not valid JSON: %v (%q)", err, req.InputJson)
	}
	if payload.Instruction != "Add a data retention clause to section 3 and update the summary to match." {
		t.Fatalf("instruction not encoded: %+v", payload)
	}
	if payload.PolicyID != "pol-1" || payload.VersionID != "ver-1" {
		t.Fatalf("policyId/versionId not encoded: %+v", payload)
	}
	if len(payload.Sections) != 2 ||
		payload.Sections[0].Content != "This policy establishes onboarding requirements." ||
		payload.Sections[1].Key != "retention" || payload.Sections[1].Order != 2 {
		t.Fatalf("sections not encoded with content/order: %+v", payload.Sections)
	}
}

// TestSubmitPolicyRevisionResolver_dropsNilSections ensures a nil entry in
// the sections slice (defensive against malformed GraphQL input coercion) is
// skipped rather than panicking or encoding a zero-value section.
func TestSubmitPolicyRevisionResolver_dropsNilSections(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "aijob-revise-2"}}

	_, err := resolvers.SubmitPolicyRevisionResolver(
		ctxWithUser(t, "u-42"), client, nil, nil,
		resolvers.SubmitPolicyRevisionInput{
			PolicyID:    "pol-1",
			VersionID:   "ver-1",
			Instruction: "tidy up",
			Sections: []*resolvers.PolicyRevisionSectionInput{
				nil,
				{Key: "purpose", Title: "Purpose", Content: "body", Order: 1},
			},
		},
	)
	if err != nil {
		t.Fatalf("SubmitPolicyRevision: %v", err)
	}

	var payload struct {
		Sections []struct {
			Key string `json:"key"`
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(client.lastSubmitReq.InputJson), &payload); err != nil {
		t.Fatalf("input_json is not valid JSON: %v", err)
	}
	if len(payload.Sections) != 1 || payload.Sections[0].Key != "purpose" {
		t.Fatalf("nil section not dropped: %+v", payload.Sections)
	}
}

// TestSubmitPolicyRevisionResolver_requiresAuth rejects an unauthenticated
// caller before the AI service is ever dialed.
func TestSubmitPolicyRevisionResolver_requiresAuth(t *testing.T) {
	client := &fakeAIClient{}
	_, err := resolvers.SubmitPolicyRevisionResolver(
		t.Context(), client, nil, nil,
		resolvers.SubmitPolicyRevisionInput{PolicyID: "pol-1", VersionID: "ver-1", Instruction: "tidy up"},
	)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastSubmitReq != nil {
		t.Fatal("AI service must not be dialed for an unauthenticated caller")
	}
}

// TestSubmitPolicyRevisionGraphQLEndToEnd drives a real GraphQL mutation
// through the generated executable schema (variable coercion,
// unmarshalInputSubmitPolicyRevision*, Mutation dispatch, result marshaling)
// — the hand-maintained parts of generated.go.
func TestSubmitPolicyRevisionGraphQLEndToEnd(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "aijob-revise-e2e"}}

	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{
		Resolvers: &resolvers.Resolver{AIClient: client},
	}))
	srv.AddTransport(transport.POST{})

	body, err := json.Marshal(map[string]any{
		"query": `mutation($input: SubmitPolicyRevisionInput!) {
			submitPolicyRevision(input: $input) { jobId }
		}`,
		"variables": map[string]any{
			"input": map[string]any{
				"policyId":    "pol-1",
				"versionId":   "ver-1",
				"instruction": "Add a data retention clause to section 3.",
				"sections": []map[string]any{
					{"key": "purpose", "title": "Purpose", "content": "This policy establishes onboarding requirements.", "order": 1},
				},
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
			SubmitPolicyRevision struct {
				JobID string `json:"jobId"`
			} `json:"submitPolicyRevision"`
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
	if out.Data.SubmitPolicyRevision.JobID != "aijob-revise-e2e" {
		t.Fatalf("jobId: got %q", out.Data.SubmitPolicyRevision.JobID)
	}

	if client.lastSubmitReq == nil || client.lastActor != "u-42" {
		t.Fatalf("actor not bound through GraphQL path: %+v", client.lastSubmitReq)
	}
	if client.lastSubmitReq.Operation != aiv1.JobOperation_JOB_OPERATION_REVISE {
		t.Fatalf("operation not REVISE: %v", client.lastSubmitReq.Operation)
	}
	if client.lastSubmitReq.PolicyId != "pol-1" || client.lastSubmitReq.VersionId != "ver-1" {
		t.Fatalf("policy/version id not passed through GraphQL path: %+v", client.lastSubmitReq)
	}
}
