// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testKratosSessionID = "8c1f2a4e-5b6d-4e7f-9a0b-1c2d3e4f5a6b"

func withKratosSession(f *fakeAuth) *fakeAuth {
	f.verify = func(string, string) (AuthResult, error) {
		return AuthResult{AccessToken: testSessionToken, SessionID: testKratosSessionID, ExpiresAt: time.Now().Add(time.Hour),
			Subject: "kratos-id-1", Email: "alice@example.org"}, nil
	}
	return f
}

func TestKratosClient_CarriesTheSessionID(t *testing.T) {
	sess := map[string]any{
		"id": testKratosSessionID, "active": true, "expires_at": time.Now().Add(time.Hour),
		"identity": map[string]any{"id": "kratos-id-1", "traits": map[string]any{"email": "alice@example.org"}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/self-service/login/api", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "flow-1"})
	})
	mux.HandleFunc("/self-service/login", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"session_token": testSessionToken, "session": sess})
	})
	mux.HandleFunc("/sessions/whoami", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(sess)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewKratosClient(srv.URL, srv.URL)

	res, err := c.VerifyPassword(context.Background(), "alice", "good")
	require.NoError(t, err)
	require.Equal(t, testKratosSessionID, res.SessionID)
	res, err = c.Refresh(context.Background(), testSessionToken)
	require.NoError(t, err)
	require.Equal(t, testKratosSessionID, res.SessionID)
}

func TestLogin_StoresTheKratosSessionID(t *testing.T) {
	h := newTestHandler(t, withKratosSession(okAuth()))
	rec := doLogin(t, h, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	sess, ok, _ := h.Store.Get(context.Background(), sessionCookie(rec).Value)
	require.True(t, ok)
	require.Equal(t, testKratosSessionID, sess.KratosSessionID)
}

func TestMfaPromotion_KeepsTheKratosSessionID(t *testing.T) {
	id := defaultIdentity()
	id.totpOK = true
	h := newMfaHandler(t, withKratosSession(okAuth()), id, edgeCfg())
	pid := mfaLogin(t, h)

	rec := verifyReq(t, h, map[string]string{"pendingId": pid, "kind": "totp", "code": "123456"})
	require.Equal(t, http.StatusOK, rec.Code)
	sess, ok, _ := h.Store.Get(context.Background(), sessionCookie(rec).Value)
	require.True(t, ok)
	require.Equal(t, testKratosSessionID, sess.KratosSessionID)
}

func TestAuthenticate_PassesTheKratosSessionToIdentity(t *testing.T) {
	h := newTestHandler(t, okAuth())
	_ = h.Store.Create(context.Background(), "sidK", Session{AccessToken: "AT", CSRFToken: "csrf", UserID: "u1",
		KratosSessionID: testKratosSessionID, ExpiresAt: time.Now().Add(5 * time.Minute)})

	h.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(httptest.NewRecorder(), authedRequest(http.MethodPost, "/query", "sidK", "csrf"))

	got := h.Identity.(*fakeMfaIdentity).lastGetUser
	require.Equal(t, "u1", got.GetUserId())
	require.Equal(t, testKratosSessionID, got.GetSessionId())
}

func TestAuthenticate_RefreshFillsTheKratosSessionID(t *testing.T) {
	auth := &fakeAuth{refresh: func(token string) (AuthResult, error) {
		return AuthResult{AccessToken: token, SessionID: testKratosSessionID, ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
	}}
	h := newTestHandler(t, auth)
	_ = h.Store.Create(context.Background(), "sidF",
		Session{AccessToken: "AT", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(2 * time.Second)})

	h.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(httptest.NewRecorder(), authedRequest(http.MethodPost, "/query", "sidF", "csrf"))

	got, _, _ := h.Store.Get(context.Background(), "sidF")
	require.Equal(t, testKratosSessionID, got.KratosSessionID)
	require.Equal(t, testKratosSessionID, h.Identity.(*fakeMfaIdentity).lastGetUser.GetSessionId())
}

func TestClaimsForUserFromIdentity_RecordsNoSession(t *testing.T) {
	id := &fakeMfaIdentity{getUser: testUser()}
	_, err := ClaimsForUserFromIdentity(id)(context.Background(), "u2")
	require.NoError(t, err)
	require.Empty(t, id.lastGetUser.GetSessionId(), "an act-as target lookup must not mark a session as used")
}
