// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeAIClient is an in-package stub of aiv1.AiServiceClient. Captures the
// last request for each method so tests can assert claims-binding.
type fakeAIClient struct {
	aiv1.AiServiceClient
	lastActor     string
	searchResp    *aiv1.SearchAndAnswerResponse
	searchErr     error
	lastSearchReq *aiv1.SearchAndAnswerRequest

	assistResp    *aiv1.AuthoringAssistResponse
	assistErr     error
	lastAssistReq *aiv1.AuthoringAssistRequest

	submitResp    *aiv1.SubmitAIJobResponse
	submitErr     error
	lastSubmitReq *aiv1.SubmitAIJobRequest

	getResp    *aiv1.GetAIJobResponse
	getErr     error
	lastGetReq *aiv1.GetAIJobRequest

	providerStatusResp *aiv1.GetProviderStatusResponse
	providerStatusErr  error

	getEnabledResp *aiv1.GetAIEnabledResponse
	getEnabledErr  error

	setEnabledResp    *aiv1.SetAIEnabledResponse
	setEnabledErr     error
	lastSetEnabledReq *aiv1.SetAIEnabledRequest

	getConfigResp *aiv1.GetAIConfigResponse
	getConfigErr  error

	topQuestionsResp    *aiv1.GetTopQuestionsResponse
	topQuestionsErr     error
	lastTopQuestionsReq *aiv1.GetTopQuestionsRequest

	policySummaryResp    *aiv1.GetPolicySummaryResponse
	policySummaryErr     error
	lastPolicySummaryReq *aiv1.GetPolicySummaryRequest

	setRetrievalResp    *aiv1.SetAIRetrievalConfigResponse
	setRetrievalErr     error
	lastSetRetrievalReq *aiv1.SetAIRetrievalConfigRequest

	setUserLimitResp    *aiv1.SetUserAiQueryLimitResponse
	setUserLimitErr     error
	lastSetUserLimitReq *aiv1.SetUserAiQueryLimitRequest

	relatedResp    *aiv1.GetRelatedPoliciesResponse
	relatedErr     error
	lastRelatedReq *aiv1.GetRelatedPoliciesRequest
}

func (f *fakeAIClient) SearchAndAnswer(ctx context.Context, in *aiv1.SearchAndAnswerRequest, _ ...grpc.CallOption) (*aiv1.SearchAndAnswerResponse, error) {
	f.recordActor(ctx)
	f.lastSearchReq = in
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return f.searchResp, nil
}

func (f *fakeAIClient) AuthoringAssist(ctx context.Context, in *aiv1.AuthoringAssistRequest, _ ...grpc.CallOption) (*aiv1.AuthoringAssistResponse, error) {
	f.recordActor(ctx)
	f.lastAssistReq = in
	if f.assistErr != nil {
		return nil, f.assistErr
	}
	return f.assistResp, nil
}

func (f *fakeAIClient) SubmitAIJob(ctx context.Context, in *aiv1.SubmitAIJobRequest, _ ...grpc.CallOption) (*aiv1.SubmitAIJobResponse, error) {
	f.recordActor(ctx)
	f.lastSubmitReq = in
	if f.submitErr != nil {
		return nil, f.submitErr
	}
	return f.submitResp, nil
}

func (f *fakeAIClient) GetAIJob(_ context.Context, in *aiv1.GetAIJobRequest, _ ...grpc.CallOption) (*aiv1.GetAIJobResponse, error) {
	f.lastGetReq = in
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getResp, nil
}

func (f *fakeAIClient) GetProviderStatus(_ context.Context, _ *aiv1.GetProviderStatusRequest, _ ...grpc.CallOption) (*aiv1.GetProviderStatusResponse, error) {
	if f.providerStatusErr != nil {
		return nil, f.providerStatusErr
	}
	if f.providerStatusResp != nil {
		return f.providerStatusResp, nil
	}
	return &aiv1.GetProviderStatusResponse{Available: true}, nil
}

func (f *fakeAIClient) GetAIEnabled(_ context.Context, _ *aiv1.GetAIEnabledRequest, _ ...grpc.CallOption) (*aiv1.GetAIEnabledResponse, error) {
	if f.getEnabledErr != nil {
		return nil, f.getEnabledErr
	}
	if f.getEnabledResp != nil {
		return f.getEnabledResp, nil
	}
	return &aiv1.GetAIEnabledResponse{Enabled: true}, nil
}

func (f *fakeAIClient) SetAIEnabled(ctx context.Context, in *aiv1.SetAIEnabledRequest, _ ...grpc.CallOption) (*aiv1.SetAIEnabledResponse, error) {
	f.recordActor(ctx)
	f.lastSetEnabledReq = in
	if f.setEnabledErr != nil {
		return nil, f.setEnabledErr
	}
	if f.setEnabledResp != nil {
		return f.setEnabledResp, nil
	}
	return &aiv1.SetAIEnabledResponse{Enabled: in.GetEnabled()}, nil
}

func (f *fakeAIClient) GetAIConfig(_ context.Context, _ *aiv1.GetAIConfigRequest, _ ...grpc.CallOption) (*aiv1.GetAIConfigResponse, error) {
	if f.getConfigErr != nil {
		return nil, f.getConfigErr
	}
	if f.getConfigResp != nil {
		return f.getConfigResp, nil
	}
	return &aiv1.GetAIConfigResponse{Config: &aiv1.AIConfig{Enabled: true}}, nil
}

func (f *fakeAIClient) GetTopQuestions(_ context.Context, in *aiv1.GetTopQuestionsRequest, _ ...grpc.CallOption) (*aiv1.GetTopQuestionsResponse, error) {
	f.lastTopQuestionsReq = in
	if f.topQuestionsErr != nil {
		return nil, f.topQuestionsErr
	}
	return f.topQuestionsResp, nil
}

func (f *fakeAIClient) GetPolicySummary(_ context.Context, in *aiv1.GetPolicySummaryRequest, _ ...grpc.CallOption) (*aiv1.GetPolicySummaryResponse, error) {
	f.lastPolicySummaryReq = in
	if f.policySummaryErr != nil {
		return nil, f.policySummaryErr
	}
	return f.policySummaryResp, nil
}

func (f *fakeAIClient) SetAIRetrievalConfig(ctx context.Context, in *aiv1.SetAIRetrievalConfigRequest, _ ...grpc.CallOption) (*aiv1.SetAIRetrievalConfigResponse, error) {
	f.recordActor(ctx)
	f.lastSetRetrievalReq = in
	if f.setRetrievalErr != nil {
		return nil, f.setRetrievalErr
	}
	if f.setRetrievalResp != nil {
		return f.setRetrievalResp, nil
	}
	return &aiv1.SetAIRetrievalConfigResponse{TopK: in.GetTopK()}, nil
}

func (f *fakeAIClient) SetUserAiQueryLimit(ctx context.Context, in *aiv1.SetUserAiQueryLimitRequest, _ ...grpc.CallOption) (*aiv1.SetUserAiQueryLimitResponse, error) {
	f.recordActor(ctx)
	f.lastSetUserLimitReq = in
	if f.setUserLimitErr != nil {
		return nil, f.setUserLimitErr
	}
	if f.setUserLimitResp != nil {
		return f.setUserLimitResp, nil
	}
	return &aiv1.SetUserAiQueryLimitResponse{EffectiveLimit: in.GetLimit()}, nil
}

func (f *fakeAIClient) GetRelatedPolicies(ctx context.Context, in *aiv1.GetRelatedPoliciesRequest, _ ...grpc.CallOption) (*aiv1.GetRelatedPoliciesResponse, error) {
	f.recordActor(ctx)
	f.lastRelatedReq = in
	if f.relatedErr != nil {
		return nil, f.relatedErr
	}
	if f.relatedResp != nil {
		return f.relatedResp, nil
	}
	return &aiv1.GetRelatedPoliciesResponse{}, nil
}

// aiAuthorCategory is a single readable category in which uid also authors.
func aiAuthorCategory(id, uid string) *viewerCategoryClient {
	c := aiReadableCategory(id)
	c.rulesets[id] = append(c.rulesets[id], authorRule(uid, corev1.GrantEffect_GRANT_EFFECT_ALLOW))
	return c
}

func aiReadableCategory(id string) *viewerCategoryClient {
	cat := &corev1.Category{Id: id, Name: "Facilities"}
	return &viewerCategoryClient{
		raciCategoryClient: *newRaciReadClient(map[string]*corev1.Category{id: cat}, map[string][]*corev1.CategoryRule{id: {allowEveryoneRule()}}),
		children:           map[string][]*corev1.Category{"": {cat}},
	}
}

func TestSearchAndAnswerBindsActorAndReadScope(t *testing.T) {
	client := &fakeAIClient{
		searchResp: &aiv1.SearchAndAnswerResponse{
			Answer:             "the policy says X",
			NoAuthorizedSource: false,
			Citations: []*aiv1.Citation{
				{PolicyId: "p-1", PolicyTitle: "Acceptable Use", VersionNo: 2, VersionId: "pv-1", SectionKey: "scope"},
			},
		},
	}
	groupID := "g-7"
	out, err := resolvers.SearchAndAnswerResolver(
		ctxWithUser(t, "u-42"), client, aiReadableCategory("g-7"),
		"is X allowed?", &groupID,
	)
	if err != nil {
		t.Fatalf("SearchAndAnswer: %v", err)
	}
	if out.Answer != "the policy says X" || len(out.Citations) != 1 {
		t.Fatalf("unexpected payload: %+v", out)
	}
	// actor_user_id must come from claims, never from input.
	if client.lastActor != "u-42" {
		t.Fatalf("actor: got %q want %q", client.lastActor, "u-42")
	}
	if client.lastSearchReq.CategoryId != "g-7" {
		t.Fatalf("group id: got %q", client.lastSearchReq.CategoryId)
	}
	// The read scope is derived at the gateway from the category rules.
	scope := client.lastSearchReq.GetScope()
	if len(scope.GetCategoryIds()) != 1 || scope.GetCategoryIds()[0] != "g-7" || scope.GetAllCategories() {
		t.Fatalf("read scope not derived from the category rules: %+v", scope)
	}
	// No role grants sensitive documents; only the individual grant does.
	if scope.GetIncludeSensitive() {
		t.Fatalf("include_sensitive should be false without the read-sensitive grant")
	}
}

func TestSearchAndAnswerMapsSegmentsAndChunkIDs(t *testing.T) {
	client := &fakeAIClient{
		searchResp: &aiv1.SearchAndAnswerResponse{
			Answer: "A B",
			Segments: []*aiv1.AnswerSegment{
				{
					Start: 0,
					End:   1,
					Sources: []*aiv1.SegmentSource{
						{PolicyId: "p1", VersionId: "v1", SectionKey: "3.2", ChunkId: "c1", ChunkIndex: 0},
						{PolicyId: "p2", VersionId: "v2", SectionKey: "1.4", ChunkId: "c9", ChunkIndex: 2},
					},
				},
				{
					Start: 2,
					End:   3,
					Sources: []*aiv1.SegmentSource{
						{PolicyId: "p3", VersionId: "v3", SectionKey: "9.9", ChunkId: "c3", ChunkIndex: 5},
					},
				},
			},
			Citations: []*aiv1.Citation{
				{PolicyId: "p1", PolicyTitle: "Acceptable Use", VersionNo: 2, VersionId: "v1", SectionKey: "3.2", ChunkId: "c1", ChunkIndex: 0},
			},
		},
	}
	groupID := "g-7"
	out, err := resolvers.SearchAndAnswerResolver(
		ctxWithUser(t, "u-42"), client, aiReadableCategory("g-7"), "q", &groupID,
	)
	if err != nil {
		t.Fatalf("SearchAndAnswer: %v", err)
	}
	if len(out.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(out.Segments))
	}
	if out.Segments[0].Start != 0 || out.Segments[0].End != 1 {
		t.Fatalf("segment offsets not mapped: %+v", out.Segments[0])
	}
	if len(out.Segments[0].Sources) != 2 {
		t.Fatalf("expected 2 sources on segment 0, got %d", len(out.Segments[0].Sources))
	}
	s := out.Segments[0].Sources[1]
	if s.PolicyID != "p2" || s.VersionID != "v2" || s.SectionKey != "1.4" || s.ChunkID != "c9" || s.ChunkIndex != 2 {
		t.Fatalf("segment source not mapped: %+v", s)
	}
	if len(out.Segments[1].Sources) != 1 || out.Segments[1].Sources[0].ChunkID != "c3" {
		t.Fatalf("segment 1 source not mapped: %+v", out.Segments[1])
	}
	if len(out.Citations) != 1 {
		t.Fatalf("expected 1 citation, got %d", len(out.Citations))
	}
	if out.Citations[0].ChunkID == nil || *out.Citations[0].ChunkID != "c1" {
		t.Fatalf("citation chunkId not mapped: %+v", out.Citations[0])
	}
	if out.Citations[0].ChunkIndex == nil || *out.Citations[0].ChunkIndex != 0 {
		t.Fatalf("citation chunkIndex not mapped: %+v", out.Citations[0])
	}
}

// TestSearchAndAnswerMapsCitationDocumentType verifies the resolver threads
// each proto Citation's document_type onto the GraphQL AICitation, so the Ask
// UI can label "Procedure PRC-…" vs "Policy POL-…". Covers both a
// procedure and a policy citation in one response.
func TestSearchAndAnswerMapsCitationDocumentType(t *testing.T) {
	client := &fakeAIClient{
		searchResp: &aiv1.SearchAndAnswerResponse{
			Answer: "answer",
			Citations: []*aiv1.Citation{
				{PolicyId: "p1", PolicyTitle: "Leave Policy", VersionNo: 3, DocumentType: "POLICY"},
				{PolicyId: "p2", PolicyTitle: "Desk Booking Policy", VersionNo: 1, DocumentType: "PROCEDURE"},
			},
		},
	}
	groupID := "g-7"
	out, err := resolvers.SearchAndAnswerResolver(
		ctxWithUser(t, "u-42"), client, aiReadableCategory("g-7"), "q", &groupID,
	)
	if err != nil {
		t.Fatalf("SearchAndAnswer: %v", err)
	}
	if len(out.Citations) != 2 {
		t.Fatalf("expected 2 citations, got %d", len(out.Citations))
	}
	if out.Citations[0].DocumentType == nil || *out.Citations[0].DocumentType != "POLICY" {
		t.Fatalf("policy citation documentType not mapped: %+v", out.Citations[0])
	}
	if out.Citations[1].DocumentType == nil || *out.Citations[1].DocumentType != "PROCEDURE" {
		t.Fatalf("procedure citation documentType not mapped: %+v", out.Citations[1])
	}
}

func TestSearchAndAnswerMapsHasSensitiveSource(t *testing.T) {
	client := &fakeAIClient{
		searchResp: &aiv1.SearchAndAnswerResponse{
			Answer:             "grounded answer",
			HasSensitiveSource: true,
		},
	}
	groupID := "g-7"
	out, err := resolvers.SearchAndAnswerResolver(
		ctxWithUser(t, "u-42"), client, aiReadableCategory("g-7"), "q", &groupID,
	)
	if err != nil {
		t.Fatalf("SearchAndAnswer: %v", err)
	}
	if !out.HasSensitiveSource {
		t.Fatalf("expected HasSensitiveSource=true to propagate from gRPC response, got false")
	}
}

func TestSearchAndAnswerScopeGroupMustBeAuthorized(t *testing.T) {
	client := &fakeAIClient{searchResp: &aiv1.SearchAndAnswerResponse{}}
	notMine := "g-not-mine"
	_, err := resolvers.SearchAndAnswerResolver(
		ctxWithUser(t, "u-1"), client, nil, "q", &notMine,
	)
	if err == nil {
		t.Fatal("expected permission-denied error when the caller cannot read the scope category")
	}
	if client.lastSearchReq != nil {
		t.Fatal("AI client must not be called when scope check fails")
	}
}

func TestSearchAndAnswerSiteAdminReadsAllCategories(t *testing.T) {
	client := &fakeAIClient{searchResp: &aiv1.SearchAndAnswerResponse{}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "alice", RolesValue: []string{"site-admin"}, ReadSensitiveValue: true})
	if _, err := resolvers.SearchAndAnswerResolver(ctx, client, nil, "q", nil); err != nil {
		t.Fatalf("SearchAndAnswer: %v", err)
	}
	scope := client.lastSearchReq.GetScope()
	if !scope.GetAllCategories() || !scope.GetIncludeSensitive() {
		t.Fatalf("site admin with the read-sensitive grant: %+v", scope)
	}
}

func TestSearchAndAnswerUnauthenticated(t *testing.T) {
	client := &fakeAIClient{}
	_, err := resolvers.SearchAndAnswerResolver(context.Background(), client, nil, "q", nil)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastSearchReq != nil {
		t.Fatal("SearchAndAnswer should not be invoked without claims")
	}
}

func TestAuthoringAssistMapsOperation(t *testing.T) {
	client := &fakeAIClient{
		assistResp: &aiv1.AuthoringAssistResponse{
			Suggestion:  "rewritten text",
			OperationId: "op-1",
		},
	}
	contextHint := "section title: Scope"
	instruction := "be concise"
	out, err := resolvers.AuthoringAssistResolver(
		ctxWithUser(t, "u-1"), client,
		resolvers.AuthoringAssistInput{
			PolicyID:        "p-1",
			VersionID:       "pv-1",
			SectionKey:      "scope",
			EditableContent: "original text",
			ContextHint:     &contextHint,
			Operation:       resolvers.AssistOperationAssistOperationRewrite,
			Instruction:     &instruction,
		},
	)
	if err != nil {
		t.Fatalf("AuthoringAssist: %v", err)
	}
	if out.Suggestion != "rewritten text" || out.OperationID != "op-1" {
		t.Fatalf("unexpected payload: %+v", out)
	}
	if client.lastActor != "u-1" {
		t.Fatalf("actor not bound from claims: %q", client.lastActor)
	}
	if client.lastAssistReq.Operation != aiv1.AssistOperation_ASSIST_OPERATION_REWRITE {
		t.Fatalf("operation mapping: got %v", client.lastAssistReq.Operation)
	}
	if client.lastAssistReq.ContextHint != contextHint || client.lastAssistReq.Instruction != instruction {
		t.Fatalf("optional fields lost: %+v", client.lastAssistReq)
	}
}

func TestAuthoringAssistNilOptionalsCollapse(t *testing.T) {
	client := &fakeAIClient{
		assistResp: &aiv1.AuthoringAssistResponse{Suggestion: "x", OperationId: "op"},
	}
	_, err := resolvers.AuthoringAssistResolver(
		ctxWithUser(t, "u-1"), client,
		resolvers.AuthoringAssistInput{
			PolicyID:        "p-1",
			VersionID:       "pv-1",
			SectionKey:      "scope",
			EditableContent: "x",
			Operation:       resolvers.AssistOperationAssistOperationDraft,
		},
	)
	if err != nil {
		t.Fatalf("AuthoringAssist: %v", err)
	}
	// Nil GraphQL strings must collapse to the proto empty-string sentinel.
	if client.lastAssistReq.ContextHint != "" || client.lastAssistReq.Instruction != "" {
		t.Fatalf("nil optionals should be empty strings: %+v", client.lastAssistReq)
	}
}

func TestTopPolicyQuestionsReturnsQuestions(t *testing.T) {
	client := &fakeAIClient{
		topQuestionsResp: &aiv1.GetTopQuestionsResponse{
			Questions: []string{"can I use my personal phone for work?", "how do I request an exception?"},
		},
	}
	limit := 3
	out, err := resolvers.TopPolicyQuestionsResolver(ctxWithUser(t, "u-1"), client, &limit)
	if err != nil {
		t.Fatalf("TopPolicyQuestions: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("unexpected questions: %+v", out)
	}
	if client.lastTopQuestionsReq.Limit != 3 {
		t.Fatalf("limit not forwarded: got %d", client.lastTopQuestionsReq.Limit)
	}
}

func TestTopPolicyQuestionsDefaultsLimitWhenNilOrZero(t *testing.T) {
	client := &fakeAIClient{topQuestionsResp: &aiv1.GetTopQuestionsResponse{}}
	if _, err := resolvers.TopPolicyQuestionsResolver(ctxWithUser(t, "u-1"), client, nil); err != nil {
		t.Fatalf("TopPolicyQuestions: %v", err)
	}
	if client.lastTopQuestionsReq.Limit != 6 {
		t.Fatalf("expected default limit 6 for nil, got %d", client.lastTopQuestionsReq.Limit)
	}
	zero := 0
	if _, err := resolvers.TopPolicyQuestionsResolver(ctxWithUser(t, "u-1"), client, &zero); err != nil {
		t.Fatalf("TopPolicyQuestions: %v", err)
	}
	if client.lastTopQuestionsReq.Limit != 6 {
		t.Fatalf("expected default limit 6 for zero, got %d", client.lastTopQuestionsReq.Limit)
	}
}

// TestTopPolicyQuestionsDegradesToEmptyOnError proves the best-effort
// contract: any ai-service error (including Unimplemented before the ai
// service ships GetTopQuestions) must resolve to an empty slice, never a
// GraphQL error, so a "Try asking" suggestions widget never breaks the page.
func TestTopPolicyQuestionsDegradesToEmptyOnError(t *testing.T) {
	client := &fakeAIClient{topQuestionsErr: status.Error(codes.Unimplemented, "method GetTopQuestions not implemented")}
	out, err := resolvers.TopPolicyQuestionsResolver(ctxWithUser(t, "u-1"), client, nil)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty slice on error, got: %+v", out)
	}
}

func TestTopPolicyQuestionsUnauthenticated(t *testing.T) {
	client := &fakeAIClient{}
	_, err := resolvers.TopPolicyQuestionsResolver(context.Background(), client, nil)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastTopQuestionsReq != nil {
		t.Fatal("GetTopQuestions should not be invoked without claims")
	}
}

func TestPolicyVersionSummaryFound(t *testing.T) {
	client := &fakeAIClient{
		policySummaryResp: &aiv1.GetPolicySummaryResponse{
			Found:       true,
			SummaryText: "this policy governs acceptable use of company devices",
			GeneratedAt: "2026-07-01T00:00:00Z",
		},
	}
	out, err := resolvers.PolicyVersionSummaryResolver(ctxWithUser(t, "u-1"), client, "pv-1")
	if err != nil {
		t.Fatalf("PolicyVersionSummary: %v", err)
	}
	if out == nil || out.SummaryText != "this policy governs acceptable use of company devices" || out.GeneratedAt != "2026-07-01T00:00:00Z" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if client.lastPolicySummaryReq.VersionId != "pv-1" {
		t.Fatalf("version id not forwarded: %+v", client.lastPolicySummaryReq)
	}
}

func TestPolicyVersionSummaryNotFoundReturnsNil(t *testing.T) {
	client := &fakeAIClient{
		policySummaryResp: &aiv1.GetPolicySummaryResponse{Found: false},
	}
	out, err := resolvers.PolicyVersionSummaryResolver(ctxWithUser(t, "u-1"), client, "pv-1")
	if err != nil {
		t.Fatalf("PolicyVersionSummary: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil when no summary stored, got: %+v", out)
	}
}

// TestPolicyVersionSummaryDegradesToNilOnError proves the graceful contract:
// any ai-service error (including Unimplemented before the ai service ships
// GetPolicySummary) must resolve to nil, never a GraphQL error, so a summary
// panel never breaks the page.
func TestPolicyVersionSummaryDegradesToNilOnError(t *testing.T) {
	client := &fakeAIClient{policySummaryErr: status.Error(codes.Unimplemented, "method GetPolicySummary not implemented")}
	out, err := resolvers.PolicyVersionSummaryResolver(ctxWithUser(t, "u-1"), client, "pv-1")
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil on error, got: %+v", out)
	}
}

func TestPolicyVersionSummaryUnauthenticated(t *testing.T) {
	client := &fakeAIClient{}
	_, err := resolvers.PolicyVersionSummaryResolver(context.Background(), client, "pv-1")
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastPolicySummaryReq != nil {
		t.Fatal("GetPolicySummary should not be invoked without claims")
	}
}

func (f *fakeAIClient) recordActor(ctx context.Context) {
	if a, ok := grpcactor.FromContext(ctx); ok {
		f.lastActor = a.Subject
	}
}
