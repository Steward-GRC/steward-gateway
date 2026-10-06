// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package maintenance_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-gateway/internal/maintenance"
	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {
	mux := http.NewServeMux()
	maintenance.NewGate(&fakeSettings{}, time.Minute).Register(mux)
	_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/maintenance", nil))
	require.Equal(t, "GET /maintenance", pattern)
}
