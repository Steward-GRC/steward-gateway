// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-authz"
	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ResendWelcomeEmailResolver re-sends the welcome-account onboarding email to a user via
// compliance-notify's WelcomeService.
func ResendWelcomeEmailResolver(ctx context.Context, welcome obligationsv1.WelcomeServiceClient, userID string) (bool, error) {
	if err := authorizeOp(ctx, authz.UserManage); err != nil {
		return false, err
	}
	if welcome == nil {
		return false, status.Error(codes.Unavailable, "compliance-notify unavailable")
	}
	resp, err := welcome.ResendWelcome(ctx, &obligationsv1.ResendWelcomeRequest{UserId: userID})
	if err != nil {
		return false, err
	}
	return resp.GetSent(), nil
}
