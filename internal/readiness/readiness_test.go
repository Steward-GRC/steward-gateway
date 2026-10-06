// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	redis "github.com/Bugs5382/go-redis"
	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stack struct {
	mr     *miniredis.Miniredis
	kratos *httptest.Server
	h      http.Handler
	live   http.Handler
	rabbit *bool
}

func newStack(t *testing.T) *stack {
	t.Helper()
	mr := miniredis.RunT(t)
	vk, err := redis.Connect(context.Background(), redis.WithAddr(mr.Addr()), redis.WithRetry(0, time.Millisecond, time.Millisecond))
	require.NoError(t, err)
	t.Cleanup(func() { _ = vk.Close() })
	kratos := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(kratos.Close)
	up := true
	p, err := New(Deps{
		Valkey:      vk,
		KratosReady: kratos.URL + "/health/ready",
		RabbitMQ: func(context.Context) error {
			if !up {
				return errors.New("connection closed")
			}
			return nil
		},
		TTL:     50 * time.Millisecond,
		Timeout: 200 * time.Millisecond,
	})
	require.NoError(t, err)
	return &stack{mr: mr, kratos: kratos, h: p.Readyz(), live: p.Livez(), rabbit: &up}
}

func get(t *testing.T, h http.Handler) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	assert.NotEmpty(t, rec.Header().Get("Steward-Version"))
	assert.NotEmpty(t, rec.Header().Get("Steward-Commit"))
	return rec.Code, body
}

func TestReadyWhenEverythingIsUp(t *testing.T) {
	s := newStack(t)
	code, _ := get(t, s.h)
	assert.Equal(t, http.StatusOK, code)
}

func TestValkeyDownFailsReadinessNotLiveness(t *testing.T) {
	s := newStack(t)
	s.mr.Close()
	time.Sleep(60 * time.Millisecond)
	code, _ := get(t, s.h)
	assert.Equal(t, http.StatusServiceUnavailable, code)
	code, _ = get(t, s.live)
	assert.Equal(t, http.StatusOK, code)

	require.NoError(t, s.mr.Restart())
	assert.Eventually(t, func() bool { c, _ := get(t, s.h); return c == http.StatusOK }, 3*time.Second, 50*time.Millisecond)
}

func TestKratosDownFailsReadiness(t *testing.T) {
	s := newStack(t)
	s.kratos.Close()
	time.Sleep(60 * time.Millisecond)
	code, _ := get(t, s.h)
	assert.Equal(t, http.StatusServiceUnavailable, code)
	code, _ = get(t, s.live)
	assert.Equal(t, http.StatusOK, code)
}

func TestRabbitMQDownIsDegraded(t *testing.T) {
	s := newStack(t)
	*s.rabbit = false
	time.Sleep(60 * time.Millisecond)
	code, body := get(t, s.h)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "degraded", body["status"])
}
