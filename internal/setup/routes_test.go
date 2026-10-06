// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package setup_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Steward-GRC/steward-gateway/internal/setup"
	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {
	mux := http.NewServeMux()
	setup.New(&fakeIdentity{}, "test-secret-not-real").Register(mux)
	for _, rt := range []string{"GET /setup/state", "POST /setup/bootstrap"} {
		m, p, _ := strings.Cut(rt, " ")
		_, pattern := mux.Handler(httptest.NewRequest(m, p, nil))
		require.Equal(t, rt, pattern)
	}
}
