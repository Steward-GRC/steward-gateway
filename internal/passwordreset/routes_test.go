// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package passwordreset_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Steward-GRC/steward-gateway/internal/passwordreset"
	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {
	mux := http.NewServeMux()
	passwordreset.New(&fakeIdentity{}).Register(mux)
	for _, rt := range []string{"GET /auth/config", "POST /auth/password-reset/request", "POST /auth/password-reset/confirm", "POST /auth/login-otp/request", "POST /auth/login-otp/verify"} {
		m, p, _ := strings.Cut(rt, " ")
		_, pattern := mux.Handler(httptest.NewRequest(m, p, nil))
		require.Equal(t, rt, pattern)
	}
}
