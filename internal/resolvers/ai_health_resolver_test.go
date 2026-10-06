// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAIHealthResolver_healthy(t *testing.T) {
	client := &fakeAIClient{}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})

	got, err := resolvers.AIHealthResolver(ctx, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Available || got.Reason != nil {
		t.Fatalf("expected available with no reason, got %+v", got)
	}
}

func TestAIHealthResolver_aiServiceUnreachable_appliesToEveryone(t *testing.T) {
	client := &fakeAIClient{getEnabledErr: errors.New("dial tcp: connection refused")}

	for _, tc := range []struct {
		name  string
		roles []string
	}{
		{"regular user", nil},
		{"site-admin", []string{"site-admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1", RolesValue: tc.roles})
			got, err := resolvers.AIHealthResolver(ctx, client)
			if err != nil {
				t.Fatalf("aiHealth must never itself error on a downstream failure, got: %v", err)
			}
			if got.Available {
				t.Fatal("expected unavailable when the ai svc is unreachable")
			}
			if got.Reason == nil || *got.Reason != "ai_service_unavailable" {
				t.Fatalf("expected reason ai_service_unavailable, got %+v", got)
			}
		})
	}
}

// ai refuses every intake call while the module is off, site admins included,
// so the site-admin bypass is gone.
func TestAIHealthResolver_disabledByAdmin_appliesToEveryone(t *testing.T) {
	client := &fakeAIClient{getEnabledResp: &aiv1.GetAIEnabledResponse{Enabled: false}}

	regularCtx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
	got, err := resolvers.AIHealthResolver(regularCtx, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Available || got.Reason == nil || *got.Reason != "disabled_by_admin" {
		t.Fatalf("expected regular user unavailable/disabled_by_admin, got %+v", got)
	}

	adminCtx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-1", RolesValue: []string{"site-admin"}})
	got, err = resolvers.AIHealthResolver(adminCtx, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Available || got.Reason == nil || *got.Reason != "disabled_by_admin" {
		t.Fatalf("expected a site-admin to see the module off too, got %+v", got)
	}
}

func TestAIHealthResolver_providerUnavailable_appliesToEveryoneIncludingSiteAdmin(t *testing.T) {
	client := &fakeAIClient{
		providerStatusResp: &aiv1.GetProviderStatusResponse{Available: false, Reason: "auth_failed"},
	}

	adminCtx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-1", RolesValue: []string{"site-admin"}})
	got, err := resolvers.AIHealthResolver(adminCtx, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Available || got.Reason == nil || *got.Reason != "provider_unavailable" {
		t.Fatalf("expected a provider outage to apply even to a site-admin, got %+v", got)
	}
}

func TestAIEnabledResolver_readsRawFlag(t *testing.T) {
	client := &fakeAIClient{getEnabledResp: &aiv1.GetAIEnabledResponse{Enabled: false}}
	got, err := resolvers.AIEnabledResolver(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected aiEnabled to reflect the raw flag (false)")
	}
}

func TestSetAIEnabledResolver_requiresSiteAdmin(t *testing.T) {
	client := &fakeAIClient{}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"}) // no site-admin role
	_, err := resolvers.SetAIEnabledResolver(ctx, client, false)
	if err == nil {
		t.Fatal("expected a non-site-admin caller to be refused")
	}
	if client.lastSetEnabledReq != nil {
		t.Fatal("expected the ai service never to be called for an unauthorized caller")
	}
}

func TestSetAIEnabledResolver_siteAdminTogglesAndBindsActor(t *testing.T) {
	client := &fakeAIClient{}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-1", RolesValue: []string{"site-admin"}})

	got, err := resolvers.SetAIEnabledResolver(ctx, client, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected the echoed value to be false")
	}
	if client.lastSetEnabledReq == nil || client.lastActor != "admin-1" || client.lastSetEnabledReq.GetEnabled() != false {
		t.Fatalf("expected actor bound server-side from claims, got %+v", client.lastSetEnabledReq)
	}
}

func TestAIRetrievalConfigResolver_readsEffectiveTopK(t *testing.T) {
	client := &fakeAIClient{getConfigResp: &aiv1.GetAIConfigResponse{Config: &aiv1.AIConfig{Enabled: true, TopK: 42}}}
	got, err := resolvers.AIRetrievalConfigResolver(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.TopK != 42 {
		t.Fatalf("expected aiRetrievalConfig.topK to map through from GetAIConfig.top_k, got %+v", got)
	}
}

func TestSetAIRetrievalConfigResolver_requiresSiteAdmin(t *testing.T) {
	client := &fakeAIClient{}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"}) // no site-admin role
	_, err := resolvers.SetAIRetrievalConfigResolver(ctx, client, 25)
	if err == nil {
		t.Fatal("expected a non-site-admin caller to be refused")
	}
	if client.lastSetRetrievalReq != nil {
		t.Fatal("expected the ai service never to be called for an unauthorized caller")
	}
}

func TestSetAIRetrievalConfigResolver_siteAdminBindsActorAndForwardsTopK(t *testing.T) {
	// Server echoes a clamped value; the resolver returns whatever the ai
	// service reports as now-effective, not the requested value.
	client := &fakeAIClient{setRetrievalResp: &aiv1.SetAIRetrievalConfigResponse{TopK: 100}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-1", RolesValue: []string{"site-admin"}})

	got, err := resolvers.SetAIRetrievalConfigResolver(ctx, client, 250)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.TopK != 100 {
		t.Fatalf("expected the echoed (clamped) top_k returned, got %+v", got)
	}
	if client.lastSetRetrievalReq == nil || client.lastActor != "admin-1" || client.lastSetRetrievalReq.GetTopK() != 250 {
		t.Fatalf("expected actor bound server-side from claims and the requested top_k forwarded, got %+v", client.lastSetRetrievalReq)
	}
}

func TestSetUserAiQueryLimitResolver_requiresSiteAdmin(t *testing.T) {
	client := &fakeAIClient{}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"}) // no site-admin role
	_, err := resolvers.SetUserAiQueryLimitResolver(ctx, client, "target-9", 25)
	if err == nil {
		t.Fatal("expected a non-site-admin caller to be refused")
	}
	if client.lastSetUserLimitReq != nil {
		t.Fatal("expected the ai service never to be called for an unauthorized caller")
	}
}

func TestSetUserAiQueryLimitResolver_siteAdminBindsActorAndForwards(t *testing.T) {
	client := &fakeAIClient{setUserLimitResp: &aiv1.SetUserAiQueryLimitResponse{EffectiveLimit: 25, Unlimited: false, IsDefault: false}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-1", RolesValue: []string{"site-admin"}})

	got, err := resolvers.SetUserAiQueryLimitResolver(ctx, client, "target-9", 25)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.EffectiveLimit != 25 || got.Unlimited || got.IsDefault {
		t.Fatalf("expected the ai-service state mapped through, got %+v", got)
	}
	req := client.lastSetUserLimitReq
	if req == nil || client.lastActor != "admin-1" || req.GetTargetUserId() != "target-9" || req.GetLimit() != 25 {
		t.Fatalf("expected actor bound from claims and target/limit forwarded, got %+v", req)
	}
}

func TestSetUserAiQueryLimitResolver_unlimitedSentinelSurvivesConversion(t *testing.T) {
	// -1 (unlimited) must reach the ai service verbatim, NOT be clamped to 0.
	client := &fakeAIClient{setUserLimitResp: &aiv1.SetUserAiQueryLimitResponse{Unlimited: true}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-1", RolesValue: []string{"site-admin"}})

	got, err := resolvers.SetUserAiQueryLimitResolver(ctx, client, "vip", -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || !got.Unlimited {
		t.Fatalf("expected unlimited mapped through, got %+v", got)
	}
	if client.lastSetUserLimitReq == nil || client.lastSetUserLimitReq.GetLimit() != -1 {
		t.Fatalf("expected limit=-1 forwarded verbatim, got %+v", client.lastSetUserLimitReq)
	}
}

type fakeAIProviderClient struct {
	fakeAIClient
	lastProviderConfig *aiv1.SetProviderConfigRequest
	lastCredential     *aiv1.SetProviderCredentialRequest
	lastNotice         *aiv1.AcceptDataNoticeRequest
}

func (f *fakeAIProviderClient) SetProviderConfig(_ context.Context, in *aiv1.SetProviderConfigRequest, _ ...grpc.CallOption) (*aiv1.SetProviderConfigResponse, error) {
	f.lastProviderConfig = in
	return &aiv1.SetProviderConfigResponse{Config: &aiv1.AIConfig{Provider: in.GetProvider(), Model: "default-model", BaseUrl: in.GetBaseUrl()}}, nil
}

func (f *fakeAIProviderClient) SetProviderCredential(_ context.Context, in *aiv1.SetProviderCredentialRequest, _ ...grpc.CallOption) (*aiv1.SetProviderCredentialResponse, error) {
	f.lastCredential = in
	return &aiv1.SetProviderCredentialResponse{CredentialSet: in.GetCredential() != "", CredentialLast4: "-ab1"}, nil
}

func (f *fakeAIProviderClient) TestProvider(context.Context, *aiv1.TestProviderRequest, ...grpc.CallOption) (*aiv1.TestProviderResponse, error) {
	return &aiv1.TestProviderResponse{Ok: false, Reason: "auth_failed", LatencyMs: 120}, nil
}

func (f *fakeAIProviderClient) AcceptDataNotice(_ context.Context, in *aiv1.AcceptDataNoticeRequest, _ ...grpc.CallOption) (*aiv1.AcceptDataNoticeResponse, error) {
	f.lastNotice = in
	return &aiv1.AcceptDataNoticeResponse{DataNotice: &aiv1.DataNotice{CurrentVersion: in.GetNoticeVersion(), AcceptedVersion: in.GetNoticeVersion(), AcceptedBy: "alice"}}, nil
}

func TestAIConfigResolver_mapsSettingsWithoutTheCredential(t *testing.T) {
	client := &fakeAIClient{getConfigResp: &aiv1.GetAIConfigResponse{Config: &aiv1.AIConfig{
		Enabled: true, Provider: aiv1.Provider_PROVIDER_BEDROCK, Model: "m-1", Region: "eu-west-1",
		CredentialSet: true, CredentialLast4: "-ab1", TopK: 50, DataNotice: &aiv1.DataNotice{CurrentVersion: "1"},
	}}}
	got, err := resolvers.AIConfigResolver(ctxWithRoles(t, "alice", []string{"site-admin"}), client)
	if err != nil {
		t.Fatalf("AIConfigResolver: %v", err)
	}
	if got.Provider == nil || *got.Provider != resolvers.AIProviderBedrock || got.Model != "m-1" || got.Region != "eu-west-1" ||
		!got.CredentialSet || got.CredentialLast4 != "-ab1" || got.TopK != 50 || got.DataNotice.CurrentVersion != "1" || got.DataNotice.AcceptedAt != nil {
		t.Fatalf("config not mapped: %+v", got)
	}
	if _, err := resolvers.AIConfigResolver(ctxWithRoles(t, "erin", []string{"reader"}), client); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a reader must be refused, got %v", err)
	}
}

func TestSetAIProviderConfigResolver_forwardsAndRequiresSiteAdmin(t *testing.T) {
	client := &fakeAIProviderClient{}
	url := "https://models.example.org"
	got, err := resolvers.SetAIProviderConfigResolver(ctxWithRoles(t, "alice", []string{"site-admin"}), client,
		resolvers.AIProviderConfigInput{Provider: resolvers.AIProviderOpenaiCompatible, BaseURL: &url})
	if err != nil {
		t.Fatalf("SetAIProviderConfigResolver: %v", err)
	}
	if client.lastProviderConfig.GetProvider() != aiv1.Provider_PROVIDER_OPENAI_COMPATIBLE || client.lastProviderConfig.GetBaseUrl() != url || client.lastProviderConfig.GetModel() != "" {
		t.Fatalf("request not forwarded: %+v", client.lastProviderConfig)
	}
	if got.Provider == nil || *got.Provider != resolvers.AIProviderOpenaiCompatible || got.Model != "default-model" {
		t.Fatalf("returned config: %+v", got)
	}
	other := &fakeAIProviderClient{}
	if _, err := resolvers.SetAIProviderConfigResolver(ctxWithRoles(t, "frank", []string{"template-admin"}), other,
		resolvers.AIProviderConfigInput{Provider: resolvers.AIProviderOpenai}); err == nil || other.lastProviderConfig != nil {
		t.Fatalf("a non-site-admin must be refused before ai is called, got %v", err)
	}
}

func TestSetAIProviderCredentialResolver_neverEchoesTheCredential(t *testing.T) {
	client := &fakeAIProviderClient{}
	got, err := resolvers.SetAIProviderCredentialResolver(ctxWithRoles(t, "alice", []string{"site-admin"}), client, "test-key-1")
	if err != nil {
		t.Fatalf("SetAIProviderCredentialResolver: %v", err)
	}
	if client.lastCredential.GetCredential() != "test-key-1" || !got.CredentialSet || got.CredentialLast4 != "-ab1" {
		t.Fatalf("credential status: %+v", got)
	}
}

func TestTestAIProviderResolver_reportsTheOutcome(t *testing.T) {
	got, err := resolvers.TestAIProviderResolver(ctxWithRoles(t, "alice", []string{"site-admin"}), &fakeAIProviderClient{})
	if err != nil {
		t.Fatalf("TestAIProviderResolver: %v", err)
	}
	if got.Ok || got.Reason == nil || *got.Reason != "auth_failed" || got.LatencyMs != 120 {
		t.Fatalf("outcome: %+v", got)
	}
}

func TestAcceptAIDataNoticeResolver_forwardsTheVersion(t *testing.T) {
	client := &fakeAIProviderClient{}
	got, err := resolvers.AcceptAIDataNoticeResolver(ctxWithRoles(t, "alice", []string{"site-admin"}), client, "2")
	if err != nil {
		t.Fatalf("AcceptAIDataNoticeResolver: %v", err)
	}
	if client.lastNotice.GetNoticeVersion() != "2" || got.AcceptedVersion != "2" || got.AcceptedBy == nil || *got.AcceptedBy != "alice" {
		t.Fatalf("notice: %+v", got)
	}
}
