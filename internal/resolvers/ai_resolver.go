// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"fmt"

	authz "github.com/Steward-GRC/steward-authz"
	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// assistOperationToProto maps the GraphQL AssistOperation enum onto the proto enum.
func assistOperationToProto(op AssistOperation) aiv1.AssistOperation {
	switch op {
	case AssistOperationAssistOperationDraft:
		return aiv1.AssistOperation_ASSIST_OPERATION_DRAFT
	case AssistOperationAssistOperationExpand:
		return aiv1.AssistOperation_ASSIST_OPERATION_EXPAND
	case AssistOperationAssistOperationRewrite:
		return aiv1.AssistOperation_ASSIST_OPERATION_REWRITE
	case AssistOperationAssistOperationClarify:
		return aiv1.AssistOperation_ASSIST_OPERATION_CLARIFY
	case AssistOperationAssistOperationSummarize:
		return aiv1.AssistOperation_ASSIST_OPERATION_SUMMARIZE
	default:
		return aiv1.AssistOperation_ASSIST_OPERATION_UNSPECIFIED
	}
}

func citationFromProto(c *aiv1.Citation) *AICitation {
	if c == nil {
		return nil
	}
	chunkID := c.GetChunkId()
	chunkIndex := int(c.GetChunkIndex())
	docType := c.GetDocumentType()
	return &AICitation{
		PolicyID:     c.GetPolicyId(),
		PolicyTitle:  c.GetPolicyTitle(),
		VersionNo:    int(c.GetVersionNo()),
		VersionID:    c.GetVersionId(),
		SectionKey:   c.GetSectionKey(),
		ChunkID:      &chunkID,
		ChunkIndex:   &chunkIndex,
		DocumentType: &docType,
	}
}

// segmentFromProto maps an aiv1.AnswerSegment onto the GraphQL AnswerSegment model.
func segmentFromProto(s *aiv1.AnswerSegment) *AnswerSegment {
	if s == nil {
		return nil
	}
	sources := make([]*SegmentSource, 0, len(s.GetSources()))
	for _, src := range s.GetSources() {
		if src == nil {
			continue
		}
		sources = append(sources, &SegmentSource{
			PolicyID:   src.GetPolicyId(),
			VersionID:  src.GetVersionId(),
			SectionKey: src.GetSectionKey(),
			ChunkID:    src.GetChunkId(),
			ChunkIndex: int(src.GetChunkIndex()),
		})
	}
	return &AnswerSegment{
		Start:   int(s.GetStart()),
		End:     int(s.GetEnd()),
		Sources: sources,
	}
}

// SearchAndAnswerResolver runs a grounded search-and-answer against the AI service.
func SearchAndAnswerResolver(ctx context.Context, client aiv1.AiServiceClient, categoryClient corev1.CategoryServiceClient, question string, categoryID *string) (*SearchAndAnswerResult, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	scope, err := aiReadScope(ctx, categoryClient)
	if err != nil {
		return nil, err
	}
	gid := derefOrEmpty(categoryID)
	if err := authorizeAICategoryScope(ctx, categoryClient, claims, gid, aiScopeRead); err != nil {
		return nil, err
	}
	resp, err := client.SearchAndAnswer(ctx, &aiv1.SearchAndAnswerRequest{
		Question:   question,
		CategoryId: gid,
		Scope:      scope,
	})
	if err != nil {
		return nil, fmt.Errorf("ai search and answer: %w", err)
	}
	cites := make([]*AICitation, 0, len(resp.GetCitations()))
	for _, c := range resp.GetCitations() {
		cites = append(cites, citationFromProto(c))
	}
	segments := make([]*AnswerSegment, 0, len(resp.GetSegments()))
	for _, s := range resp.GetSegments() {
		segments = append(segments, segmentFromProto(s))
	}
	return &SearchAndAnswerResult{
		Answer:             resp.GetAnswer(),
		Citations:          cites,
		NoAuthorizedSource: resp.GetNoAuthorizedSource(),
		Segments:           segments,
		HasSensitiveSource: resp.GetHasSensitiveSource(),
	}, nil
}

// draftJobInputSection mirrors the ai service's generation.DraftJobInputSection JSON shape.
type draftJobInputSection struct {
	Key      string `json:"key"`
	Title    string `json:"title"`
	Guidance string `json:"guidance,omitempty"`
	Order    int    `json:"order"`
}

// draftJobInputReferenceDocument mirrors the ai service's generation.DraftJobInputReferenceDocument
// JSON shape: an author-attached reference document carried alongside (not folded into) the
// free-text brief.
type draftJobInputReferenceDocument struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

// draftJobInput mirrors the ai service's generation.DraftJobInput JSON shape: the
// operation-specific payload carried in SubmitAIJobRequest.input_json for a DRAFT job.
type draftJobInput struct {
	Title              string                           `json:"title,omitempty"`
	Brief              string                           `json:"brief"`
	Sections           []draftJobInputSection           `json:"sections"`
	ReferenceHints     []string                         `json:"referenceHints,omitempty"`
	ReferenceDocuments []draftJobInputReferenceDocument `json:"referenceDocuments,omitempty"`
	Enrichments        *enrichmentContextJSON           `json:"enrichments,omitempty"`
	EnrichmentOptOut   enrichmentOptOutJSON             `json:"enrichmentOptOut"`
	EnrichmentLibrary  *enrichmentLibraryJSON           `json:"enrichmentLibrary,omitempty"`
}

// SubmitDraftGenerationResolver submits whole-draft generation as an async job and returns
// immediately with a jobId.
func SubmitDraftGenerationResolver(ctx context.Context, client aiv1.AiServiceClient, categoryClient corev1.CategoryServiceClient, enrich *EnrichmentResolver, input SubmitDraftGenerationInput) (*SubmitDraftGenerationResult, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	scope, err := aiReadScope(ctx, categoryClient)
	if err != nil {
		return nil, err
	}
	gid := derefOrEmpty(input.CategoryID)
	if err := authorizeAICategoryScope(ctx, categoryClient, claims, gid, aiScopeAuthor); err != nil {
		return nil, err
	}

	sections := make([]draftJobInputSection, 0, len(input.Sections))
	for _, s := range input.Sections {
		if s == nil {
			continue
		}
		sections = append(sections, draftJobInputSection{
			Key:      s.Key,
			Title:    s.Title,
			Guidance: derefOrEmpty(s.Guidance),
			Order:    s.Order,
		})
	}
	referenceDocuments := make([]draftJobInputReferenceDocument, 0, len(input.ReferenceDocuments))
	for _, d := range input.ReferenceDocuments {
		if d == nil {
			continue
		}
		referenceDocuments = append(referenceDocuments, draftJobInputReferenceDocument{
			Title:   d.Title,
			Content: d.Content,
		})
	}
	payload, err := json.Marshal(draftJobInput{
		Title:              derefOrEmpty(input.Title),
		Brief:              input.Brief,
		Sections:           sections,
		ReferenceHints:     input.ReferenceHints,
		ReferenceDocuments: referenceDocuments,
		EnrichmentOptOut:   optOutJSONFromInput(input.EnrichmentOptOut),
	})
	if err != nil {
		return nil, fmt.Errorf("encode draft job input: %w", err)
	}

	resp, err := client.SubmitAIJob(ctx, &aiv1.SubmitAIJobRequest{
		CategoryId: gid,
		Scope:      scope,
		Operation:  aiv1.JobOperation_JOB_OPERATION_DRAFT,
		InputJson:  string(payload),
	})
	if err != nil {
		return nil, fmt.Errorf("ai submit job: %w", err)
	}
	return &SubmitDraftGenerationResult{JobID: resp.GetJobId()}, nil
}

// reviewJobInputSection mirrors the ai service's generation.ReviewJobInputSection JSON shape.
type reviewJobInputSection struct {
	Key     string `json:"key"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

// reviewJobInput mirrors the ai service's generation.ReviewJobInput JSON shape: the
// operation-specific payload carried in SubmitAIJobRequest.input_json for a REVIEW job.
type reviewJobInput struct {
	Title             string                  `json:"title,omitempty"`
	Sections          []reviewJobInputSection `json:"sections"`
	StandardsRefs     []string                `json:"standardsRefs,omitempty"`
	RelatedPolicyRefs []string                `json:"relatedPolicyRefs,omitempty"`
	Enrichments       *enrichmentContextJSON  `json:"enrichments,omitempty"`
	EnrichmentOptOut  enrichmentOptOutJSON    `json:"enrichmentOptOut"`
	EnrichmentLibrary *enrichmentLibraryJSON  `json:"enrichmentLibrary,omitempty"`
}

// SubmitPolicyReviewResolver submits review & gap-analysis of an existing policy draft as an async
// job and returns immediately with a jobId.
func SubmitPolicyReviewResolver(ctx context.Context, client aiv1.AiServiceClient, categoryClient corev1.CategoryServiceClient, enrich *EnrichmentResolver, input SubmitPolicyReviewInput) (*SubmitPolicyReviewResult, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	scope, err := aiReadScope(ctx, categoryClient)
	if err != nil {
		return nil, err
	}
	gid := derefOrEmpty(input.CategoryID)
	if err := authorizeAICategoryScope(ctx, categoryClient, claims, gid, aiScopeAuthor); err != nil {
		return nil, err
	}

	sections := make([]reviewJobInputSection, 0, len(input.Sections))
	for _, s := range input.Sections {
		if s == nil {
			continue
		}
		sections = append(sections, reviewJobInputSection{
			Key:     s.Key,
			Title:   s.Title,
			Content: s.Content,
		})
	}
	ingest, library := enrich.resolve(ctx, input.PolicyID)
	payload, err := json.Marshal(reviewJobInput{
		Title:             derefOrEmpty(input.Title),
		Sections:          sections,
		StandardsRefs:     input.StandardsRefs,
		RelatedPolicyRefs: input.RelatedPolicyRefs,
		Enrichments:       ingest,
		EnrichmentOptOut:  optOutJSONFromInput(input.EnrichmentOptOut),
		EnrichmentLibrary: library,
	})
	if err != nil {
		return nil, fmt.Errorf("encode review job input: %w", err)
	}

	resp, err := client.SubmitAIJob(ctx, &aiv1.SubmitAIJobRequest{
		CategoryId: gid,
		Scope:      scope,
		PolicyId:   input.PolicyID,
		VersionId:  input.VersionID,
		Operation:  aiv1.JobOperation_JOB_OPERATION_REVIEW,
		InputJson:  string(payload),
	})
	if err != nil {
		return nil, fmt.Errorf("ai submit job: %w", err)
	}
	return &SubmitPolicyReviewResult{JobID: resp.GetJobId()}, nil
}

// revisionJobInputSection mirrors the ai service's generation.RevisionJobInputSection JSON shape.
type revisionJobInputSection struct {
	Key     string `json:"key"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Order   int    `json:"order"`
}

// revisionJobInput mirrors the ai service's generation.RevisionJobInput JSON shape: the
// operation-specific payload carried in SubmitAIJobRequest.input_json for a REVISE job.
type revisionJobInput struct {
	Instruction       string                    `json:"instruction"`
	PolicyID          string                    `json:"policyId"`
	VersionID         string                    `json:"versionId"`
	Sections          []revisionJobInputSection `json:"sections"`
	Enrichments       *enrichmentContextJSON    `json:"enrichments,omitempty"`
	EnrichmentOptOut  enrichmentOptOutJSON      `json:"enrichmentOptOut"`
	EnrichmentLibrary *enrichmentLibraryJSON    `json:"enrichmentLibrary,omitempty"`
}

// SubmitPolicyRevisionResolver submits a targeted revision of an existing policy as an async job
// and returns immediately with a jobId.
func SubmitPolicyRevisionResolver(ctx context.Context, client aiv1.AiServiceClient, categoryClient corev1.CategoryServiceClient, enrich *EnrichmentResolver, input SubmitPolicyRevisionInput) (*SubmitDraftGenerationResult, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	scope, err := aiReadScope(ctx, categoryClient)
	if err != nil {
		return nil, err
	}
	gid := ""
	if err := authorizeAICategoryScope(ctx, categoryClient, claims, gid, aiScopeAuthor); err != nil {
		return nil, err
	}

	sections := make([]revisionJobInputSection, 0, len(input.Sections))
	for _, s := range input.Sections {
		if s == nil {
			continue
		}
		sections = append(sections, revisionJobInputSection{
			Key:     s.Key,
			Title:   s.Title,
			Content: s.Content,
			Order:   s.Order,
		})
	}
	ingest, library := enrich.resolve(ctx, input.PolicyID)
	payload, err := json.Marshal(revisionJobInput{
		Instruction:       input.Instruction,
		PolicyID:          input.PolicyID,
		VersionID:         input.VersionID,
		Sections:          sections,
		Enrichments:       ingest,
		EnrichmentOptOut:  optOutJSONFromInput(input.EnrichmentOptOut),
		EnrichmentLibrary: library,
	})
	if err != nil {
		return nil, fmt.Errorf("encode revision job input: %w", err)
	}

	resp, err := client.SubmitAIJob(ctx, &aiv1.SubmitAIJobRequest{
		CategoryId: gid,
		Scope:      scope,
		PolicyId:   input.PolicyID,
		VersionId:  input.VersionID,
		Operation:  aiv1.JobOperation_JOB_OPERATION_REVISE,
		InputJson:  string(payload),
	})
	if err != nil {
		return nil, fmt.Errorf("ai submit job: %w", err)
	}
	return &SubmitDraftGenerationResult{JobID: resp.GetJobId()}, nil
}

// suggestJobInputSection mirrors the ai service's generation.SuggestJobInputSection JSON shape.
type suggestJobInputSection struct {
	Key     string `json:"key"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

// suggestJobInput mirrors the ai service's generation.SuggestJobInput JSON shape: the payload
// carried in SubmitAIJobRequest.input_json for a SUGGEST_ENRICHMENTS job.
type suggestJobInput struct {
	Title    string                   `json:"title,omitempty"`
	Sections []suggestJobInputSection `json:"sections"`
	OptOut   enrichmentOptOutJSON     `json:"optOut"`
	Library  enrichmentLibraryJSON    `json:"library"`
}

// SubmitEnrichmentSuggestionsResolver submits a standalone enrichment-suggestion job and returns
// immediately with a jobId.
func SubmitEnrichmentSuggestionsResolver(ctx context.Context, client aiv1.AiServiceClient, categoryClient corev1.CategoryServiceClient, enrich *EnrichmentResolver, input SubmitEnrichmentSuggestionsInput) (*SubmitDraftGenerationResult, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	scope, err := aiReadScope(ctx, categoryClient)
	if err != nil {
		return nil, err
	}
	gid := derefOrEmpty(input.CategoryID)
	if err := authorizeAICategoryScope(ctx, categoryClient, claims, gid, aiScopeAuthor); err != nil {
		return nil, err
	}

	sections := make([]suggestJobInputSection, 0, len(input.Sections))
	for _, s := range input.Sections {
		if s == nil {
			continue
		}
		sections = append(sections, suggestJobInputSection{Key: s.Key, Title: s.Title, Content: s.Content})
	}

	_, library := enrich.resolve(ctx, input.PolicyID)
	lib := enrichmentLibraryJSON{}
	if library != nil {
		lib = *library
	}
	payload, err := json.Marshal(suggestJobInput{
		Title:    derefOrEmpty(input.Title),
		Sections: sections,
		OptOut:   optOutJSONFromInput(input.EnrichmentOptOut),
		Library:  lib,
	})
	if err != nil {
		return nil, fmt.Errorf("encode suggest job input: %w", err)
	}

	resp, err := client.SubmitAIJob(ctx, &aiv1.SubmitAIJobRequest{
		CategoryId: gid,
		Scope:      scope,
		PolicyId:   input.PolicyID,
		VersionId:  derefOrEmpty(input.VersionID),
		Operation:  aiv1.JobOperation_JOB_OPERATION_SUGGEST_ENRICHMENTS,
		InputJson:  string(payload),
	})
	if err != nil {
		return nil, fmt.Errorf("ai submit job: %w", err)
	}
	return &SubmitDraftGenerationResult{JobID: resp.GetJobId()}, nil
}

// jobPhaseFromProto maps the proto JobPhase onto the GraphQL AIJobPhase enum.
func jobPhaseFromProto(p aiv1.JobPhase) AIJobPhase {
	switch p {
	case aiv1.JobPhase_JOB_PHASE_RUNNING:
		return AIJobPhaseAiJobPhaseRunning
	case aiv1.JobPhase_JOB_PHASE_SUCCEEDED:
		return AIJobPhaseAiJobPhaseSucceeded
	case aiv1.JobPhase_JOB_PHASE_FAILED:
		return AIJobPhaseAiJobPhaseFailed
	default:
		return AIJobPhaseAiJobPhasePending
	}
}

// AIJobStatusResolver polls the status of a previously submitted async AI job.
func AIJobStatusResolver(ctx context.Context, client aiv1.AiServiceClient, jobID string) (*AIJobStatus, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.GetAIJob(ctx, &aiv1.GetAIJobRequest{JobId: jobID})
	if err != nil {
		return nil, fmt.Errorf("ai get job: %w", err)
	}
	return &AIJobStatus{
		JobID:      jobID,
		Phase:      jobPhaseFromProto(resp.GetPhase()),
		ResultRef:  nilIfEmpty(resp.GetResultRef()),
		Error:      nilIfEmpty(resp.GetError()),
		StartedAt:  nilIfEmpty(resp.GetStartedAt()),
		FinishedAt: nilIfEmpty(resp.GetFinishedAt()),
	}, nil
}

// defaultTopPolicyQuestionsLimit mirrors the schema default (topPolicyQuestions limit: Int = 6) for
// the case where limit is nil or explicitly 0.
const defaultTopPolicyQuestionsLimit = 6

// TopPolicyQuestionsResolver returns the top questions actually asked via searchAndAnswer,
// most-frequent first, for a "Try asking" suggestions surface.
func TopPolicyQuestionsResolver(ctx context.Context, client aiv1.AiServiceClient, limit *int) ([]string, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	lim := defaultTopPolicyQuestionsLimit
	if limit != nil && *limit != 0 {
		lim = *limit
	}
	resp, err := client.GetTopQuestions(ctx, &aiv1.GetTopQuestionsRequest{Limit: int32(lim)})
	if err != nil {
		return []string{}, nil
	}
	return resp.GetQuestions(), nil
}

// PolicyVersionSummaryResolver reads a previously-stored, publish-time policy summary for a
// version, so a viewer's summary panel can read it instead of regenerating on every view. The
// summary carries the real content, so it is served only when the version's read decision allows
// the real content; otherwise the panel gets no summary.
func PolicyVersionSummaryResolver(ctx context.Context, client aiv1.AiServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, versionID string) (*PolicySummaryResult, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	if _, effect, err := authorizeVersionReads(ctx, policyClient, categoryClient, adminClient, versionID); err != nil || effect != authz.EffectAllow {
		return nil, nil
	}
	resp, err := client.GetPolicySummary(ctx, &aiv1.GetPolicySummaryRequest{VersionId: versionID})
	if err != nil {
		return nil, nil
	}
	if !resp.GetFound() {
		return nil, nil
	}
	return &PolicySummaryResult{
		SummaryText: resp.GetSummaryText(),
		GeneratedAt: resp.GetGeneratedAt(),
	}, nil
}

// AuthoringAssistResolver invokes one of the authoring-assist operations (draft / expand / rewrite
// / clarify / summarize) against the AI service.
func AuthoringAssistResolver(ctx context.Context, client aiv1.AiServiceClient, input AuthoringAssistInput) (*AuthoringAssistResult, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.AuthoringAssist(ctx, &aiv1.AuthoringAssistRequest{
		PolicyId:        input.PolicyID,
		VersionId:       input.VersionID,
		SectionKey:      input.SectionKey,
		EditableContent: input.EditableContent,
		ContextHint:     derefOrEmpty(input.ContextHint),
		Operation:       assistOperationToProto(input.Operation),
		Instruction:     derefOrEmpty(input.Instruction),
	})
	if err != nil {
		return nil, fmt.Errorf("ai authoring assist: %w", err)
	}
	return &AuthoringAssistResult{
		Suggestion:  resp.GetSuggestion(),
		OperationID: resp.GetOperationId(),
	}, nil
}
