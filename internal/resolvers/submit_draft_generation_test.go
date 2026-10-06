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

// TestSubmitDraftGenerationResolver_bindsClaimsAndEncodesInput checks the
// direct resolver path: actor from claims, group scope-hint honoured, and the
// DRAFT input JSON-encoded into SubmitAIJobRequest.input_json.
func TestSubmitDraftGenerationResolver_bindsClaimsAndEncodesInput(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "aijob-xyz"}}

	groupID := "g-7"
	title := "Onboarding Policy"
	guidance := "Who this applies to."
	res, err := resolvers.SubmitDraftGenerationResolver(
		ctxWithUser(t, "u-42"), client, aiAuthorCategory("g-7", "u-42"), nil,
		resolvers.SubmitDraftGenerationInput{
			CategoryID: &groupID,
			Title:      &title,
			Brief:      "Draft an onboarding policy.",
			Sections: []*resolvers.SubmitDraftGenerationSectionInput{
				{Key: "purpose", Title: "Purpose", Order: 1},
				{Key: "scope", Title: "Scope", Guidance: &guidance, Order: 2},
			},
			ReferenceHints: []string{"Prior Onboarding Policy v2"},
			ReferenceDocuments: []*resolvers.ReferenceDocumentInput{
				{Title: "Vendor Security Addendum.pdf", Content: "1. Vendors must encrypt data at rest..."},
			},
		},
	)
	if err != nil {
		t.Fatalf("SubmitDraftGeneration: %v", err)
	}
	if res.JobID != "aijob-xyz" {
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
	if req.Operation != aiv1.JobOperation_JOB_OPERATION_DRAFT {
		t.Fatalf("operation: got %v", req.Operation)
	}

	// input_json must decode to the DRAFT payload shape the operator expects.
	var payload struct {
		Title    string `json:"title"`
		Brief    string `json:"brief"`
		Sections []struct {
			Key      string `json:"key"`
			Title    string `json:"title"`
			Guidance string `json:"guidance"`
			Order    int    `json:"order"`
		} `json:"sections"`
		ReferenceHints     []string `json:"referenceHints"`
		ReferenceDocuments []struct {
			Title   string `json:"title"`
			Content string `json:"content"`
		} `json:"referenceDocuments"`
	}
	if err := json.Unmarshal([]byte(req.InputJson), &payload); err != nil {
		t.Fatalf("input_json is not valid JSON: %v (%q)", err, req.InputJson)
	}
	if payload.Title != "Onboarding Policy" || payload.Brief != "Draft an onboarding policy." {
		t.Fatalf("title/brief not encoded: %+v", payload)
	}
	if len(payload.Sections) != 2 || payload.Sections[1].Guidance != "Who this applies to." {
		t.Fatalf("sections not encoded with guidance: %+v", payload.Sections)
	}
	if len(payload.ReferenceHints) != 1 {
		t.Fatalf("reference hints not encoded: %+v", payload.ReferenceHints)
	}
	if len(payload.ReferenceDocuments) != 1 ||
		payload.ReferenceDocuments[0].Title != "Vendor Security Addendum.pdf" ||
		payload.ReferenceDocuments[0].Content != "1. Vendors must encrypt data at rest..." {
		t.Fatalf("reference documents not encoded: %+v", payload.ReferenceDocuments)
	}
}

// TestSubmitDraftGenerationResolver_rejectsForeignGroup ensures an out-of-scope
// groupId hint is refused before the AI service is dialed.
func TestSubmitDraftGenerationResolver_rejectsForeignGroup(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "nope"}}

	foreign := "g-999"
	_, err := resolvers.SubmitDraftGenerationResolver(
		ctxWithUser(t, "u-1"), client, nil, nil,
		resolvers.SubmitDraftGenerationInput{CategoryID: &foreign, Brief: "b"},
	)
	if err == nil {
		t.Fatal("expected permission denied for a group the caller is not in")
	}
	if client.lastSubmitReq != nil {
		t.Fatal("AI service must not be dialed when the group check fails")
	}
}

// TestSubmitDraftGenerationResolver_requiresAuth rejects an unauthenticated caller.
func TestSubmitDraftGenerationResolver_requiresAuth(t *testing.T) {
	client := &fakeAIClient{}
	_, err := resolvers.SubmitDraftGenerationResolver(
		t.Context(), client, nil, nil,
		resolvers.SubmitDraftGenerationInput{Brief: "b"},
	)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
}

// TestAIJobStatusResolver_mapsProtoStatus checks phase mapping and that empty
// status strings collapse to nil (GraphQL null).
func TestAIJobStatusResolver_mapsProtoStatus(t *testing.T) {
	client := &fakeAIClient{getResp: &aiv1.GetAIJobResponse{
		Phase:     aiv1.JobPhase_JOB_PHASE_SUCCEEDED,
		ResultRef: "ai:job-result:aijob-xyz:DRAFT",
		StartedAt: "2026-07-23T10:00:00Z",
		// Error + FinishedAt intentionally empty → expect nil pointers.
	}}
	res, err := resolvers.AIJobStatusResolver(ctxWithUser(t, "u-1"), client, "aijob-xyz")
	if err != nil {
		t.Fatalf("AIJobStatus: %v", err)
	}
	if client.lastGetReq == nil || client.lastGetReq.JobId != "aijob-xyz" {
		t.Fatalf("job id not passed through: %+v", client.lastGetReq)
	}
	if res.Phase != resolvers.AIJobPhaseAiJobPhaseSucceeded {
		t.Fatalf("phase: got %v", res.Phase)
	}
	if res.ResultRef == nil || *res.ResultRef != "ai:job-result:aijob-xyz:DRAFT" {
		t.Fatalf("resultRef: got %v", res.ResultRef)
	}
	if res.StartedAt == nil || *res.StartedAt != "2026-07-23T10:00:00Z" {
		t.Fatalf("startedAt: got %v", res.StartedAt)
	}
	if res.Error != nil || res.FinishedAt != nil {
		t.Fatalf("empty status fields must be nil, got error=%v finishedAt=%v", res.Error, res.FinishedAt)
	}
}

// TestSubmitDraftGenerationGraphQLEndToEnd drives a real GraphQL mutation
// through the generated executable schema (variable coercion,
// unmarshalInputSubmitDraftGeneration*, Mutation dispatch, result marshaling)
// — the hand-maintained parts of generated.go.
func TestSubmitDraftGenerationGraphQLEndToEnd(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "aijob-e2e"}}

	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{
		Resolvers: &resolvers.Resolver{AIClient: client, CategoryClient: aiAuthorCategory("g-7", "u-42")},
	}))
	srv.AddTransport(transport.POST{})

	body, err := json.Marshal(map[string]any{
		"query": `mutation($input: SubmitDraftGenerationInput!) {
			submitDraftGeneration(input: $input) { jobId }
		}`,
		"variables": map[string]any{
			"input": map[string]any{
				"categoryId": "g-7",
				"title":      "Onboarding Policy",
				"brief":      "Draft an onboarding policy.",
				"sections": []map[string]any{
					{"key": "purpose", "title": "Purpose", "order": 1},
					{"key": "scope", "title": "Scope", "guidance": "Who this applies to.", "order": 2},
				},
				"referenceHints": []string{"Prior Onboarding Policy v2"},
				"referenceDocuments": []map[string]any{
					{"title": "Vendor Security Addendum.pdf", "content": "1. Vendors must encrypt data at rest..."},
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
			SubmitDraftGeneration struct {
				JobID string `json:"jobId"`
			} `json:"submitDraftGeneration"`
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
	if out.Data.SubmitDraftGeneration.JobID != "aijob-e2e" {
		t.Fatalf("jobId: got %q", out.Data.SubmitDraftGeneration.JobID)
	}

	// Confirm the input really flowed through GraphQL unmarshaling into the proto.
	if client.lastSubmitReq == nil || client.lastActor != "u-42" {
		t.Fatalf("actor not bound through GraphQL path: %+v", client.lastSubmitReq)
	}
	if client.lastSubmitReq.Operation != aiv1.JobOperation_JOB_OPERATION_DRAFT {
		t.Fatalf("operation not DRAFT: %v", client.lastSubmitReq.Operation)
	}
}

// TestAIJobGraphQLEndToEnd drives the aiJob query through the executable schema
// (enum + nullable-string marshaling in generated.go).
func TestAIJobGraphQLEndToEnd(t *testing.T) {
	client := &fakeAIClient{getResp: &aiv1.GetAIJobResponse{
		Phase:     aiv1.JobPhase_JOB_PHASE_RUNNING,
		StartedAt: "2026-07-23T10:00:00Z",
	}}

	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{
		Resolvers: &resolvers.Resolver{AIClient: client, CategoryClient: aiAuthorCategory("g-7", "u-42")},
	}))
	srv.AddTransport(transport.POST{})

	body, _ := json.Marshal(map[string]any{
		"query": `query($id: ID!) {
			aiJob(jobId: $id) { jobId phase resultRef error startedAt finishedAt }
		}`,
		"variables": map[string]any{"id": "aijob-e2e"},
	})
	req := httptest.NewRequest("POST", "/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithUser(t, "u-1"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data struct {
			AiJob struct {
				JobID      string  `json:"jobId"`
				Phase      string  `json:"phase"`
				ResultRef  *string `json:"resultRef"`
				Error      *string `json:"error"`
				StartedAt  *string `json:"startedAt"`
				FinishedAt *string `json:"finishedAt"`
			} `json:"aiJob"`
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
	if out.Data.AiJob.Phase != "AI_JOB_PHASE_RUNNING" {
		t.Fatalf("phase enum: got %q", out.Data.AiJob.Phase)
	}
	if out.Data.AiJob.StartedAt == nil || *out.Data.AiJob.StartedAt != "2026-07-23T10:00:00Z" {
		t.Fatalf("startedAt: got %v", out.Data.AiJob.StartedAt)
	}
	if out.Data.AiJob.ResultRef != nil || out.Data.AiJob.Error != nil || out.Data.AiJob.FinishedAt != nil {
		t.Fatalf("empty fields must be null: %+v", out.Data.AiJob)
	}
}
