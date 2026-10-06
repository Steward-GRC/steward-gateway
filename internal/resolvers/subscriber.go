// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// WithSubscriberClaims puts the claims verified in a subscription
// websocket's connection_init on the connection context, as the effective
// user (and so the go-grpc-actor actor of every backend call it makes).
func WithSubscriberClaims(ctx context.Context, claims principal.Claims) context.Context {
	return principal.WithClaims(ctx, claims)
}

// subscriberClaims returns the subscribing user's claims.
func subscriberClaims(ctx context.Context) (principal.Claims, bool) {
	c, ok := principal.FromContext(ctx)
	return c, ok && c != nil
}
