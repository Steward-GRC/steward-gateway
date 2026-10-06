// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

func ctxWithStubClaims(t *testing.T, c principal.Static) context.Context {
	t.Helper()
	return principal.WithClaims(context.Background(), c)
}

func ctxWithRoles(t *testing.T, uid string, roles []string) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: uid, RolesValue: roles})
}

func ctxWithClaims(t *testing.T, uid string, roles ...string) context.Context {
	t.Helper()
	return ctxWithRoles(t, uid, roles)
}
