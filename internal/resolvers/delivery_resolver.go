// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	deliveryv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/delivery/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// errObfuscatedContent refuses rendered output to a reader who may only see the
// obfuscated text: delivery renders the real content.
var errObfuscatedContent = status.Error(codes.NotFound, "policy version not found")

// GetRenderedContent fetches server-rendered HTML for a policy version via the Delivery service,
// under the version's read decision. An obfuscated reader gets nothing.
func GetRenderedContent(ctx context.Context, client deliveryv1.DeliveryServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, policyVersionID string) (*RenderedContent, error) {
	if _, effect, err := authorizeVersionReads(ctx, policyClient, categoryClient, adminClient, policyVersionID); err != nil {
		return nil, err
	} else if effect != authz.EffectAllow {
		return nil, errObfuscatedContent
	}
	resp, err := client.GetRenderedContent(ctx, &deliveryv1.GetRenderedContentRequest{PolicyVersionId: policyVersionID})
	if err != nil {
		return nil, fmt.Errorf("delivery get rendered content: %w", err)
	}
	return &RenderedContent{HTML: resp.GetHtml()}, nil
}

// GetPolicyDiff returns the section-aware diff between two policy versions as surfaced by the
// Delivery service, under the read decision on both. An obfuscated read drops the word diffs.
func GetPolicyDiff(ctx context.Context, client deliveryv1.DeliveryServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, fromVersionID, toVersionID string) (*PolicyDiff, error) {
	_, effect, err := authorizeVersionReads(ctx, policyClient, categoryClient, adminClient, fromVersionID, toVersionID)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetDiff(ctx, &deliveryv1.GetDiffRequest{
		PolicyVersionIdFrom: fromVersionID,
		PolicyVersionIdTo:   toVersionID,
	})
	if err != nil {
		return nil, fmt.Errorf("delivery get diff: %w", err)
	}
	sections := make([]*SectionDiff, 0, len(resp.GetSections()))
	for _, s := range resp.GetSections() {
		sections = append(sections, &SectionDiff{
			SectionKey:    s.GetSectionKey(),
			ChangeType:    s.GetChangeType(),
			WordDiffHTML:  nilIfEmpty(s.GetDiffHtml()),
			IsBoilerplate: s.GetBoilerplate(),
		})
	}
	return &PolicyDiff{Sections: obfuscateSectionDiffs(sections, effect)}, nil
}

// GetPDFDownloadLink resolves the pdfDownloadLink query by asking the Delivery service for the
// signed URL of a previously completed PDF job.
func GetPDFDownloadLink(ctx context.Context, client deliveryv1.DeliveryServiceClient, jobID string) (*PDFDownloadLink, error) {
	resp, err := client.GetPDFDownloadLink(ctx, &deliveryv1.GetPDFDownloadLinkRequest{JobId: jobID})
	if err != nil {
		return nil, fmt.Errorf("delivery get pdf download link: %w", err)
	}
	expires := ""
	if t := resp.GetExpiresAt(); t != nil {
		expires = t.AsTime().UTC().Format(time.RFC3339)
	}
	return &PDFDownloadLink{SignedURL: resp.GetSignedUrl(), ExpiresAt: expires}, nil
}

// RequestPDFExport enqueues an async PDF rendering job under the version's read decision. The PDF
// holds the real content, so an obfuscated reader gets nothing.
func RequestPDFExport(ctx context.Context, client deliveryv1.DeliveryServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, policyVersionID string) (*PDFExportJob, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	if _, effect, err := authorizeVersionReads(ctx, policyClient, categoryClient, adminClient, policyVersionID); err != nil {
		return nil, err
	} else if effect != authz.EffectAllow {
		return nil, errObfuscatedContent
	}
	resp, err := client.RequestPDFExport(ctx, &deliveryv1.RequestPDFExportRequest{
		PolicyVersionId: policyVersionID,
		RequesterUserId: claims.UserID(),
	})
	if err != nil {
		return nil, fmt.Errorf("delivery request pdf export: %w", err)
	}
	return &PDFExportJob{JobID: resp.GetJobId()}, nil
}

// CreateMagicLinkResolver mints a magic-link token for a published policy version.
func CreateMagicLinkResolver(ctx context.Context, client deliveryv1.DeliveryServiceClient, policyVersionID string, sensitive bool) (*MagicLink, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.CreateMagicLink(ctx, &deliveryv1.CreateMagicLinkRequest{
		PolicyVersionId: policyVersionID,
		CreatedByUserId: claims.UserID(),
		Sensitive:       sensitive,
	})
	if err != nil {
		return nil, fmt.Errorf("delivery create magic link: %w", err)
	}
	expires := ""
	if t := resp.GetExpiresAt(); t != nil {
		expires = t.AsTime().UTC().Format(time.RFC3339)
	}
	return &MagicLink{Token: resp.GetToken(), ExpiresAt: expires}, nil
}

// RevokeMagicLinkResolver invalidates a magic-link token.
func RevokeMagicLinkResolver(ctx context.Context, client deliveryv1.DeliveryServiceClient, token string) (bool, error) {
	if err := authorizeOp(ctx, authz.DeliveryManage); err != nil {
		return false, err
	}
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return false, fmt.Errorf("unauthenticated")
	}
	resp, err := client.RevokeMagicLink(ctx, &deliveryv1.RevokeMagicLinkRequest{
		Token:           token,
		RevokedByUserId: claims.UserID(),
	})
	if err != nil {
		return false, fmt.Errorf("delivery revoke magic link: %w", err)
	}
	return resp.GetRevoked(), nil
}
