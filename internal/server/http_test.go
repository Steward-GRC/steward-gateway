// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	log "github.com/Bugs5382/go-log"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapSetsARequestIDOnTheContextAndTheResponse(t *testing.T) {
	var seen string
	h := Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = RequestIDFromContext(r.Context()) }), log.Nop())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.NotEmpty(t, seen)
	assert.Equal(t, seen, rec.Header().Get(RequestIDHeader))
}

func TestAccessLogCarriesNoAddressQueryOrHeaderValues(t *testing.T) {
	var buf bytes.Buffer
	lg := log.NewLoggerWithOptions("gateway", log.WithOutput(&buf), log.WithDefaultFormat(log.FormatJSON))
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }), lg)
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=canary-code&state=canary-state", nil)
	req.RemoteAddr = "198.51.100.23:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("Cookie", "steward_sid=canary-cookie")
	h.ServeHTTP(httptest.NewRecorder(), req)
	out := buf.String()
	assert.Contains(t, out, `"status":418`)
	assert.Contains(t, out, "/auth/sso/callback")
	for _, canary := range []string{"198.51.100.23", "203.0.113.9", "canary-code", "canary-state", "canary-cookie"} {
		assert.NotContains(t, out, canary)
	}
}

func TestWrapRecoversAPanic(t *testing.T) {
	h := Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }), log.Nop())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "boom")
}

func TestWrapStaysTransparentToWebsocketUpgrades(t *testing.T) {
	up := websocket.Upgrader{}
	ts := httptest.NewServer(Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err == nil {
			_ = c.Close()
		}
	}), log.Nop()))
	defer ts.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http"), nil)
	require.NoError(t, err)
	_ = c.Close()
}

func TestSubscriptionWebsocketRefusesAForeignOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.org/query", nil)
	req.Header.Set("Origin", "https://evil.example.net")
	rec := httptest.NewRecorder()
	_, err := originChecked{}.Accept(rec, req, transport.WebsocketAcceptOptions{})
	require.Error(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
