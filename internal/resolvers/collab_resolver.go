// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"time"

	collabv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/collab/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// IssueCollabToken mints a collaboration token for the caller on one draft,
// gated on the effective-author model like saveDraft. Collab mints for the
// go-grpc-actor actor and resolves the presence name itself.
func IssueCollabToken(ctx context.Context, client collabv1.CollabTokenServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, input IssueCollabTokenInput) (*IssueCollabTokenPayload, error) {
	if _, err := authorizeEffectiveAuthor(ctx, policyClient, categoryClient, input.PolicyID); err != nil {
		return nil, err
	}
	resp, err := client.IssueToken(ctx, &collabv1.IssueTokenRequest{
		PolicyId:          input.PolicyID,
		DraftId:           input.DraftID,
		TemplateVersionId: derefOrEmpty(input.TemplateVersionID),
	})
	if err != nil {
		return nil, fmt.Errorf("collab issue token: %w", err)
	}
	expires := ""
	if resp.ExpiresAt != nil {
		expires = resp.ExpiresAt.AsTime().UTC().Format(time.RFC3339)
	}
	return &IssueCollabTokenPayload{
		Token:     resp.Token,
		WsURL:     resp.WsUrl,
		ExpiresAt: expires,
	}, nil
}
