// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"encoding/json"
	"testing"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// enrichmentPayload is the decode shape of the enrichment blocks the gateway
// folds into the review/revise/suggest job input JSON.
type enrichmentPayload struct {
	Enrichments *struct {
		Definitions []struct {
			Term       string `json:"term"`
			Definition string `json:"definition"`
		} `json:"definitions"`
		References []struct {
			Label string `json:"label"`
			Kind  string `json:"kind"`
		} `json:"references"`
		RelatedPolicies []struct {
			PolicyID string `json:"policyId"`
			Title    string `json:"title"`
		} `json:"relatedPolicies"`
	} `json:"enrichments"`
	EnrichmentOptOut struct {
		Definitions bool `json:"definitions"`
		Related     bool `json:"related"`
		References  bool `json:"references"`
	} `json:"enrichmentOptOut"`
	EnrichmentLibrary *struct {
		Definitions []struct {
			EntryID string `json:"entryId"`
			Term    string `json:"term"`
		} `json:"definitions"`
		References []struct {
			ReferenceID string `json:"referenceId"`
			Label       string `json:"label"`
		} `json:"references"`
	} `json:"enrichmentLibrary"`
}

func enrichFixture() *resolvers.EnrichmentResolver {
	ref := &fakeReferenceClient{
		attached: []*corev1.Reference{{Id: "r1", Label: "Sample Standard A", Kind: corev1.ReferenceKind_REFERENCE_KIND_STANDARD, Clause: "S-6"}},
		library:  []*corev1.Reference{{Id: "r1", Label: "Sample Standard A"}, {Id: "r2", Label: "Sample Guide B", Url: "https://standards.example.org/guide-b"}},
	}
	def := &fakeDefinitionLibraryClient{
		attached: []*corev1.DefinitionEntry{{Id: "d1", Term: "Visitor", Definition: "Anyone on site without a staff badge."}},
		library:  []*corev1.DefinitionEntry{{Id: "d1", Term: "Visitor"}, {Id: "d2", Term: "Least Privilege"}},
	}
	rel := &fakeRelationClient{list: []*corev1.RelatedPolicy{{PolicyId: "p2", Title: "Secure Coding"}}}
	return resolvers.NewEnrichmentResolver(ref, def, rel)
}

// TestReviewResolverFoldsEnrichments proves the review submit carries the
// resolved ingest context + dedupe library + opt-out through the job input JSON.
func TestReviewResolverFoldsEnrichments(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "j1"}}
	optOut := true
	_, err := resolvers.SubmitPolicyReviewResolver(
		ctxWithUser(t, "u-1"), client, nil, enrichFixture(),
		resolvers.SubmitPolicyReviewInput{
			PolicyID:  "pol-1",
			VersionID: "ver-1",
			Sections:  []*resolvers.SubmitPolicyReviewSectionInput{{Key: "s1", Title: "S1", Content: "body"}},
			// Opt OUT references; keep definitions + related.
			EnrichmentOptOut: &resolvers.EnrichmentOptOutInput{References: &optOut},
		},
	)
	if err != nil {
		t.Fatalf("review submit: %v", err)
	}
	var p enrichmentPayload
	if err := json.Unmarshal([]byte(client.lastSubmitReq.InputJson), &p); err != nil {
		t.Fatalf("decode input json: %v", err)
	}
	if p.Enrichments == nil || len(p.Enrichments.Definitions) != 1 || p.Enrichments.Definitions[0].Term != "Visitor" {
		t.Fatalf("ingest definitions not folded in: %+v", p.Enrichments)
	}
	if len(p.Enrichments.References) != 1 || p.Enrichments.References[0].Kind != "STANDARD" {
		t.Fatalf("ingest references not folded in: %+v", p.Enrichments)
	}
	if len(p.Enrichments.RelatedPolicies) != 1 || p.Enrichments.RelatedPolicies[0].Title != "Secure Coding" {
		t.Fatalf("ingest related not folded in: %+v", p.Enrichments)
	}
	if !p.EnrichmentOptOut.References || p.EnrichmentOptOut.Definitions || p.EnrichmentOptOut.Related {
		t.Fatalf("opt-out not passed through correctly: %+v", p.EnrichmentOptOut)
	}
	if p.EnrichmentLibrary == nil || len(p.EnrichmentLibrary.Definitions) != 2 || len(p.EnrichmentLibrary.References) != 2 {
		t.Fatalf("dedupe library not folded in: %+v", p.EnrichmentLibrary)
	}
}

// TestSuggestEnrichmentsResolver submits a standalone SUGGEST_ENRICHMENTS job
// with the library resolved from core and the opt-out threaded through.
func TestSuggestEnrichmentsResolver(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "j-suggest"}}
	res, err := resolvers.SubmitEnrichmentSuggestionsResolver(
		ctxWithUser(t, "u-1"), client, nil, enrichFixture(),
		resolvers.SubmitEnrichmentSuggestionsInput{
			PolicyID: "pol-1",
			Sections: []*resolvers.SubmitEnrichmentSuggestionsSectionInput{{Key: "s1", Title: "S1", Content: "body"}},
		},
	)
	if err != nil {
		t.Fatalf("suggest submit: %v", err)
	}
	if res.JobID != "j-suggest" {
		t.Fatalf("jobId: got %q", res.JobID)
	}
	req := client.lastSubmitReq
	if req.Operation != aiv1.JobOperation_JOB_OPERATION_SUGGEST_ENRICHMENTS {
		t.Fatalf("operation: got %v", req.Operation)
	}
	if req.PolicyId != "pol-1" || client.lastActor != "u-1" {
		t.Fatalf("policy/actor not bound: %+v", req)
	}
	// The suggest input carries the dedupe library under "library".
	var p struct {
		Sections []struct {
			Key string `json:"key"`
		} `json:"sections"`
		Library struct {
			Definitions []struct {
				Term string `json:"term"`
			} `json:"definitions"`
			References []struct {
				Label string `json:"label"`
			} `json:"references"`
		} `json:"library"`
	}
	if err := json.Unmarshal([]byte(req.InputJson), &p); err != nil {
		t.Fatalf("decode suggest input: %v", err)
	}
	if len(p.Sections) != 1 || len(p.Library.Definitions) != 2 || len(p.Library.References) != 2 {
		t.Fatalf("suggest input not built correctly: %+v", p)
	}
}

// TestEnrichmentResolverNilPolicySkips: a draft with no policy id resolves to no
// enrichments (nil resolver-safe), so generation behaves exactly as before.
func TestEnrichmentResolverNilPolicySkips(t *testing.T) {
	client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "j2"}}
	groupID := "g-7"
	_, err := resolvers.SubmitDraftGenerationResolver(
		ctxWithUser(t, "u-1"), client, aiAuthorCategory("g-7", "u-1"), enrichFixture(),
		resolvers.SubmitDraftGenerationInput{CategoryID: &groupID, Brief: "draft it",
			Sections: []*resolvers.SubmitDraftGenerationSectionInput{{Key: "s1", Title: "S1", Order: 1}}},
	)
	if err != nil {
		t.Fatalf("draft submit: %v", err)
	}
	var p enrichmentPayload
	if err := json.Unmarshal([]byte(client.lastSubmitReq.InputJson), &p); err != nil {
		t.Fatalf("decode input json: %v", err)
	}
	if p.Enrichments != nil || p.EnrichmentLibrary != nil {
		t.Fatalf("draft (no policy id) must carry no attached enrichments/library: %+v %+v", p.Enrichments, p.EnrichmentLibrary)
	}
}
