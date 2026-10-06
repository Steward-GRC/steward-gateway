// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package notifyunsub

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {
	v, err := NewVerifier(goldenSec)
	require.NoError(t, err)
	mux := http.NewServeMux()
	New(v, &fakeSetter{}, "/settings/notifications").Register(mux)
	NewVerifyEmail(v, &fakeEmailVerifier{}).Register(mux)
	for _, rt := range []string{"POST /notify/unsubscribe", "GET /notify/unsubscribe", "GET /notify/verify-email"} {
		m, p, _ := strings.Cut(rt, " ")
		_, pattern := mux.Handler(httptest.NewRequest(m, p, nil))
		require.Equal(t, rt, pattern)
	}
}
