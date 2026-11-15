// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The default return path must be a route the admin app has: steward-web's
// apps/admin/app/routes.ts registers "organisations" (British spelling).
func TestDefaultAdminReturnPath_IsAnAdminAppRoute(t *testing.T) {
	require.Equal(t, "/admin/organisations", defaultAdminReturnPath)
}
