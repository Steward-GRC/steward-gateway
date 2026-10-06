// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-authz"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
)

// AIHealthResolver reports whether AI is usable right now, so the web can turn
// AI features off instead of failing. It never errors on a downstream failure:
// the rest of the app keeps working whatever state ai is in.
func AIHealthResolver(ctx context.Context, client aiv1.AiServiceClient) (*AIHealth, error) {
	unavailable := func(reason string) (*AIHealth, error) {
		return &AIHealth{Available: false, Reason: &reason}, nil
	}
	enabledResp, err := client.GetAIEnabled(ctx, &aiv1.GetAIEnabledRequest{})
	if err != nil {
		return unavailable("ai_service_unavailable")
	}
	if !enabledResp.GetEnabled() {
		return unavailable("disabled_by_admin")
	}
	statusResp, err := client.GetProviderStatus(ctx, &aiv1.GetProviderStatusRequest{})
	if err != nil {
		return unavailable("ai_service_unavailable")
	}
	if !statusResp.GetAvailable() {
		return unavailable("provider_unavailable")
	}
	return &AIHealth{Available: true}, nil
}

// AIEnabledResolver reads the module switch.
func AIEnabledResolver(ctx context.Context, client aiv1.AiServiceClient) (bool, error) {
	resp, err := client.GetAIEnabled(ctx, &aiv1.GetAIEnabledRequest{})
	if err != nil {
		return false, err
	}
	return resp.GetEnabled(), nil
}

// SetAIEnabledResolver turns the module on or off (site admin). ai refuses
// turning it on until the current data notice is accepted.
func SetAIEnabledResolver(ctx context.Context, client aiv1.AiServiceClient, enabled bool) (bool, error) {
	if err := requireRole(ctx, string(authz.RoleSiteAdmin)); err != nil {
		return false, err
	}
	resp, err := client.SetAIEnabled(ctx, &aiv1.SetAIEnabledRequest{Enabled: enabled})
	if err != nil {
		return false, err
	}
	return resp.GetEnabled(), nil
}

var aiProviders = map[aiv1.Provider]AIProvider{
	aiv1.Provider_PROVIDER_ANTHROPIC:         AIProviderAnthropic,
	aiv1.Provider_PROVIDER_OPENAI:            AIProviderOpenai,
	aiv1.Provider_PROVIDER_AZURE_OPENAI:      AIProviderAzureOpenai,
	aiv1.Provider_PROVIDER_GEMINI:            AIProviderGemini,
	aiv1.Provider_PROVIDER_BEDROCK:           AIProviderBedrock,
	aiv1.Provider_PROVIDER_OPENAI_COMPATIBLE: AIProviderOpenaiCompatible,
}

func aiProviderToProto(p AIProvider) aiv1.Provider {
	for k, v := range aiProviders {
		if v == p {
			return k
		}
	}
	return aiv1.Provider_PROVIDER_UNSPECIFIED
}

func aiDataNoticeFromProto(n *aiv1.DataNotice) *AIDataNotice {
	return &AIDataNotice{
		CurrentVersion:  n.GetCurrentVersion(),
		AcceptedVersion: n.GetAcceptedVersion(),
		AcceptedBy:      nilIfEmpty(n.GetAcceptedBy()),
		AcceptedAt:      nilIfEmpty(n.GetAcceptedAt()),
	}
}

func aiConfigFromProto(c *aiv1.AIConfig) *AIConfig {
	out := &AIConfig{
		Enabled:         c.GetEnabled(),
		Model:           c.GetModel(),
		BaseURL:         c.GetBaseUrl(),
		Region:          c.GetRegion(),
		Deployment:      c.GetDeployment(),
		CredentialSet:   c.GetCredentialSet(),
		CredentialLast4: c.GetCredentialLast4(),
		TopK:            int(c.GetTopK()),
		DataNotice:      aiDataNoticeFromProto(c.GetDataNotice()),
	}
	if p, ok := aiProviders[c.GetProvider()]; ok {
		out.Provider = &p
	}
	return out
}

// AIConfigResolver reads the module's settings (site admin). The credential
// is never returned.
func AIConfigResolver(ctx context.Context, client aiv1.AiServiceClient) (*AIConfig, error) {
	if err := requireRole(ctx, string(authz.RoleSiteAdmin)); err != nil {
		return nil, err
	}
	resp, err := client.GetAIConfig(ctx, &aiv1.GetAIConfigRequest{})
	if err != nil {
		return nil, err
	}
	return aiConfigFromProto(resp.GetConfig()), nil
}

// SetAIProviderConfigResolver sets the generative provider and its
// non-secret settings (site admin).
func SetAIProviderConfigResolver(ctx context.Context, client aiv1.AiServiceClient, input AIProviderConfigInput) (*AIConfig, error) {
	if err := requireRole(ctx, string(authz.RoleSiteAdmin)); err != nil {
		return nil, err
	}
	resp, err := client.SetProviderConfig(ctx, &aiv1.SetProviderConfigRequest{
		Provider:   aiProviderToProto(input.Provider),
		Model:      derefOrEmpty(input.Model),
		BaseUrl:    derefOrEmpty(input.BaseURL),
		Region:     derefOrEmpty(input.Region),
		Deployment: derefOrEmpty(input.Deployment),
	})
	if err != nil {
		return nil, err
	}
	return aiConfigFromProto(resp.GetConfig()), nil
}

// SetAIProviderCredentialResolver stores (or, empty, clears) the provider
// credential (site admin). Write-only.
func SetAIProviderCredentialResolver(ctx context.Context, client aiv1.AiServiceClient, credential string) (*AICredentialStatus, error) {
	if err := requireRole(ctx, string(authz.RoleSiteAdmin)); err != nil {
		return nil, err
	}
	resp, err := client.SetProviderCredential(ctx, &aiv1.SetProviderCredentialRequest{Credential: credential})
	if err != nil {
		return nil, err
	}
	return &AICredentialStatus{CredentialSet: resp.GetCredentialSet(), CredentialLast4: resp.GetCredentialLast4()}, nil
}

// TestAIProviderResolver makes one small provider call through ai (site admin).
func TestAIProviderResolver(ctx context.Context, client aiv1.AiServiceClient) (*AIProviderTestResult, error) {
	if err := requireRole(ctx, string(authz.RoleSiteAdmin)); err != nil {
		return nil, err
	}
	resp, err := client.TestProvider(ctx, &aiv1.TestProviderRequest{})
	if err != nil {
		return nil, err
	}
	return &AIProviderTestResult{Ok: resp.GetOk(), Reason: nilIfEmpty(resp.GetReason()), LatencyMs: int(resp.GetLatencyMs())}, nil
}

// AcceptAIDataNoticeResolver records the caller's acceptance of the data
// notice version (site admin).
func AcceptAIDataNoticeResolver(ctx context.Context, client aiv1.AiServiceClient, noticeVersion string) (*AIDataNotice, error) {
	if err := requireRole(ctx, string(authz.RoleSiteAdmin)); err != nil {
		return nil, err
	}
	resp, err := client.AcceptDataNotice(ctx, &aiv1.AcceptDataNoticeRequest{NoticeVersion: noticeVersion})
	if err != nil {
		return nil, err
	}
	return aiDataNoticeFromProto(resp.GetDataNotice()), nil
}

// AIRetrievalConfigResolver reads the effective retrieval candidate count.
func AIRetrievalConfigResolver(ctx context.Context, client aiv1.AiServiceClient) (*AIRetrievalConfig, error) {
	resp, err := client.GetAIConfig(ctx, &aiv1.GetAIConfigRequest{})
	if err != nil {
		return nil, err
	}
	return &AIRetrievalConfig{TopK: int(resp.GetConfig().GetTopK())}, nil
}

// SetAIRetrievalConfigResolver sets the retrieval candidate count (site
// admin) and returns the value ai applied after clamping.
func SetAIRetrievalConfigResolver(ctx context.Context, client aiv1.AiServiceClient, topK int) (*AIRetrievalConfig, error) {
	if err := requireRole(ctx, string(authz.RoleSiteAdmin)); err != nil {
		return nil, err
	}
	resp, err := client.SetAIRetrievalConfig(ctx, &aiv1.SetAIRetrievalConfigRequest{TopK: toInt32(topK)})
	if err != nil {
		return nil, err
	}
	return &AIRetrievalConfig{TopK: int(resp.GetTopK())}, nil
}

// SetUserAiQueryLimitResolver sets or clears one user's per-day AI query
// limit (site admin).
func SetUserAiQueryLimitResolver(ctx context.Context, client aiv1.AiServiceClient, userID string, limit int) (*AIUserQueryLimit, error) {
	if err := requireRole(ctx, string(authz.RoleSiteAdmin)); err != nil {
		return nil, err
	}
	resp, err := client.SetUserAiQueryLimit(ctx, &aiv1.SetUserAiQueryLimitRequest{
		TargetUserId: userID,
		Limit:        aiQueryLimitToInt32(limit),
	})
	if err != nil {
		return nil, err
	}
	return &AIUserQueryLimit{
		EffectiveLimit: int(resp.GetEffectiveLimit()),
		Unlimited:      resp.GetUnlimited(),
		IsDefault:      resp.GetIsDefault(),
	}, nil
}
