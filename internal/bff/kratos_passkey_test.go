// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apperr "github.com/Bugs5382/go-apperr"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/stretchr/testify/require"
)

// optionsJSON is a representative WebAuthn assertion options blob (go-webauthn's
// {publicKey:{...}} shape) the browser feeds navigator.credentials.get.
const passkeyOptionsJSON = `{"publicKey":{"challenge":"Y2hhbGxlbmdl","rpId":"steward.example.org","allowCredentials":[],"userVerification":"preferred"}}`

// passkeyBrowserServerConfig tunes the stateful fake Kratos used by the passkey
// LOGIN tests. It models the PROVEN-LIVE browser-flow shape (mirroring the
// recovery redemption): the login/browser open sets the anti-CSRF cookie and
// returns a flow whose ui.nodes carry passkey_challenge + csrf_token; the login
// submit requires the anti-CSRF cookie AND the matching csrf_token, sets the
// ory_kratos_session cookie, and answers 200 with continue_with
// set_ory_session_token; whoami requires the session cookie.
type passkeyBrowserServerConfig struct {
	withChallenge bool   // login flow carries a passkey_challenge node
	omitCSRFNode  bool   // login flow carries no csrf_token node
	goodCred      string // login submit succeeds only for this passkey_login value
	csrfToken     string // csrf_token node value (and the value the submit must echo)
	sessionToken  string // ory_session_token handed back in continue_with
	sessionCookie string // value of the ory_kratos_session cookie the submit sets
	identityID    string
	email         string
	expiresAt     time.Time
	secureCookies bool // Set-Cookie marked Secure (relayed over the plaintext hop)
	omitToken     bool // 200 submit carries NO session token anywhere (fail-closed)
}

// newKratosPasskeyBrowserServer fakes Kratos's browser passkey login endpoints.
func newKratosPasskeyBrowserServer(t *testing.T, cfg passkeyBrowserServerConfig) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/self-service/login/browser", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "csrf_token_login", Value: "csrf-cookie-val", Path: "/", Secure: cfg.secureCookies})
		nodes := []map[string]any{}
		if !cfg.omitCSRFNode {
			nodes = append(nodes, map[string]any{"attributes": map[string]any{"name": "csrf_token", "value": cfg.csrfToken}})
		}
		if cfg.withChallenge {
			blob, _ := json.Marshal(passkeyOptionsJSON)
			nodes = append(nodes, map[string]any{
				"attributes": map[string]any{"name": "passkey_challenge", "value": json.RawMessage(blob)},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "flow-pk-1",
			"ui": map[string]any{"nodes": nodes},
		})
	})

	mux.HandleFunc("/self-service/login", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("flow") != "flow-pk-1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, err := r.Cookie("csrf_token_login"); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body struct {
			Method       string `json:"method"`
			PasskeyLogin string `json:"passkey_login"`
			CSRFToken    string `json:"csrf_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Method != "passkey" || body.PasskeyLogin != cfg.goodCred || body.CSRFToken != cfg.csrfToken {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ui": map[string]any{"messages": []map[string]any{
					{"id": 4000006, "text": "The provided credentials are invalid", "type": "error"},
				}},
			})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "ory_kratos_session", Value: cfg.sessionCookie, Path: "/", Secure: cfg.secureCookies})
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{"session": map[string]any{"active": true}}
		if !cfg.omitToken {
			resp["continue_with"] = []any{
				map[string]any{"action": "set_ory_session_token", "ory_session_token": cfg.sessionToken},
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/sessions/whoami", func(w http.ResponseWriter, r *http.Request) {
		_, cookieErr := r.Cookie("ory_kratos_session")
		bearerOK := r.Header.Get("Authorization") == "Bearer "+cfg.sessionToken
		if cookieErr != nil && !bearerOK {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active":     true,
			"expires_at": cfg.expiresAt,
			"identity":   map[string]any{"id": cfg.identityID, "traits": map[string]any{"email": cfg.email}},
		})
	})

	mux.HandleFunc("/self-service/logout/api", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SessionToken string `json:"session_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.SessionToken != cfg.sessionToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func defaultPasskeyServerConfig(expiresAt time.Time) passkeyBrowserServerConfig {
	return passkeyBrowserServerConfig{
		withChallenge: true,
		goodCred:      "good-cred",
		csrfToken:     "csrf-body-tok",
		sessionToken:  "sess-9",
		sessionCookie: "ory-sess-cookie",
		identityID:    "id-9",
		email:         "bob@example.net",
		expiresAt:     expiresAt,
	}
}

// TestPasskeyLoginBegin_ReturnsChallenge proves Begin drives the BROWSER flow and
// surfaces the flow id, the WebAuthn options JSON, the csrf_token, and the flow
// cookies (captured for the finish anti-CSRF replay).
func TestPasskeyLoginBegin_ReturnsChallenge(t *testing.T) {
	srv := newKratosPasskeyBrowserServer(t, defaultPasskeyServerConfig(time.Now().Add(time.Hour)))
	c := NewKratosClient(srv.URL, srv.URL)

	res, err := c.PasskeyLoginBegin(context.Background())
	require.NoError(t, err)
	require.Equal(t, "flow-pk-1", res.FlowID)
	require.Equal(t, passkeyOptionsJSON, res.OptionsJSON)
	require.Equal(t, "csrf-body-tok", res.CSRFToken)
	require.NotEmpty(t, res.Cookies["csrf_token_login"], "the anti-CSRF flow cookie must be captured for finish")
}

// TestPasskeyLoginBegin_NoChallengeNode proves a browser flow with no
// passkey_challenge node (passkey method not enabled in Kratos) is a coded init
// fault (1227), not a client error — fail closed. This is exactly the signal the
// UI viability gate keys the button on (only options-present un-hides it).
func TestPasskeyLoginBegin_NoChallengeNode(t *testing.T) {
	cfg := defaultPasskeyServerConfig(time.Now().Add(time.Hour))
	cfg.withChallenge = false
	srv := newKratosPasskeyBrowserServer(t, cfg)
	c := NewKratosClient(srv.URL, srv.URL)

	_, err := c.PasskeyLoginBegin(context.Background())
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosPasskeyLoginInitFailed, code)
}

// TestPasskeyLoginBegin_NoCSRFNode proves a flow missing the csrf_token node is a
// coded init fault — the browser submit could not pass anti-CSRF, so begin must
// not offer a login that cannot complete.
func TestPasskeyLoginBegin_NoCSRFNode(t *testing.T) {
	cfg := defaultPasskeyServerConfig(time.Now().Add(time.Hour))
	cfg.omitCSRFNode = true
	srv := newKratosPasskeyBrowserServer(t, cfg)
	c := NewKratosClient(srv.URL, srv.URL)

	_, err := c.PasskeyLoginBegin(context.Background())
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosPasskeyLoginInitFailed, code)
}

// TestPasskeyLoginBegin_InitServerError proves a non-2xx flow open is coded 1227.
func TestPasskeyLoginBegin_InitServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := NewKratosClient(srv.URL, srv.URL)

	_, err := c.PasskeyLoginBegin(context.Background())
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosPasskeyLoginInitFailed, code)
}

// TestPasskeyLoginBegin_Unreachable proves a bare transport failure is coded 1212.
func TestPasskeyLoginBegin_Unreachable(t *testing.T) {
	c := NewKratosClient("http://127.0.0.1:1", "http://127.0.0.1:1")
	_, err := c.PasskeyLoginBegin(context.Background())
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosUnreachable, code)
}

// TestPasskeyLogin_BrowserFlow_EndToEnd is the core proof: begin opens the
// browser flow, and finish — replaying the begin csrf_token + anti-CSRF cookie —
// submits the assertion, reads the session token from continue_with, resolves the
// identity via whoami on the established (cookie) session, and returns an
// AuthResult carrying the opaque session_token (parity with local login).
func TestPasskeyLogin_BrowserFlow_EndToEnd(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second).UTC()
	cfg := defaultPasskeyServerConfig(expiresAt)
	cfg.secureCookies = true // exercise the Secure-cookie relay over the plaintext hop
	srv := newKratosPasskeyBrowserServer(t, cfg)
	c := NewKratosClient(srv.URL, srv.URL)

	begin, err := c.PasskeyLoginBegin(context.Background())
	require.NoError(t, err)

	res, err := c.PasskeyLoginFinish(context.Background(), begin.FlowID, "good-cred", begin.CSRFToken, begin.Cookies)
	require.NoError(t, err)
	require.Equal(t, "sess-9", res.AccessToken, "the opaque session_token from continue_with")
	require.Equal(t, "id-9", res.Subject)
	require.Equal(t, "bob@example.net", res.Email)
	require.True(t, res.ExpiresAt.Equal(expiresAt))
}

// TestPasskeyLogin_SessionRefreshAndLogoutParity proves a passkey-originated
// session behaves EXACTLY like a password session downstream: the opaque
// session_token it stores drives Refresh (whoami by bearer, re-validated with an
// unchanged token) and Logout (logout/api by session_token). This is what keeps
// SessionHTTP's refresh path and Handler.Logout working for a passkey session
// with no special-casing.
func TestPasskeyLogin_SessionRefreshAndLogoutParity(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second).UTC()
	srv := newKratosPasskeyBrowserServer(t, defaultPasskeyServerConfig(expiresAt))
	c := NewKratosClient(srv.URL, srv.URL)

	begin, err := c.PasskeyLoginBegin(context.Background())
	require.NoError(t, err)
	res, err := c.PasskeyLoginFinish(context.Background(), begin.FlowID, "good-cred", begin.CSRFToken, begin.Cookies)
	require.NoError(t, err)
	require.Equal(t, "sess-9", res.AccessToken)

	refreshed, err := c.Refresh(context.Background(), res.AccessToken)
	require.NoError(t, err)
	require.Equal(t, res.AccessToken, refreshed.AccessToken)
	require.Equal(t, "id-9", refreshed.Subject)

	require.NoError(t, c.Logout(context.Background(), res.AccessToken))
}

// TestPasskeyLoginFinish_RejectedAssertion proves a 400 (rejected assertion)
// FAILS CLOSED as ErrInvalidCredentials — a 401, never a coded internal error.
func TestPasskeyLoginFinish_RejectedAssertion(t *testing.T) {
	srv := newKratosPasskeyBrowserServer(t, defaultPasskeyServerConfig(time.Now().Add(time.Hour)))
	c := NewKratosClient(srv.URL, srv.URL)

	begin, err := c.PasskeyLoginBegin(context.Background())
	require.NoError(t, err)
	_, err = c.PasskeyLoginFinish(context.Background(), begin.FlowID, "forged-cred", begin.CSRFToken, begin.Cookies)
	require.ErrorIs(t, err, ErrInvalidCredentials)
	if _, ok := apperr.Code(err); ok {
		t.Fatal("a rejected assertion must NOT carry an apperr code — it is a 401, not an internal error")
	}
}

// TestPasskeyLoginFinish_MissingCSRFCookie proves the anti-CSRF cookie really is
// threaded: a finish that replays NO cookies is rejected by Kratos (403) and
// surfaces as a coded verify fault, not a false login.
func TestPasskeyLoginFinish_MissingCSRFCookie(t *testing.T) {
	srv := newKratosPasskeyBrowserServer(t, defaultPasskeyServerConfig(time.Now().Add(time.Hour)))
	c := NewKratosClient(srv.URL, srv.URL)

	begin, err := c.PasskeyLoginBegin(context.Background())
	require.NoError(t, err)
	_, err = c.PasskeyLoginFinish(context.Background(), begin.FlowID, "good-cred", begin.CSRFToken, nil)
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosPasskeyLoginVerifyFailed, code)
}

// TestPasskeyLoginFinish_NoSessionToken proves a 200 that carries NO session
// token anywhere fails closed (coded 1228) — the gateway will not mint a session
// it cannot later refresh/revoke.
func TestPasskeyLoginFinish_NoSessionToken(t *testing.T) {
	cfg := defaultPasskeyServerConfig(time.Now().Add(time.Hour))
	cfg.omitToken = true
	srv := newKratosPasskeyBrowserServer(t, cfg)
	c := NewKratosClient(srv.URL, srv.URL)

	begin, err := c.PasskeyLoginBegin(context.Background())
	require.NoError(t, err)
	_, err = c.PasskeyLoginFinish(context.Background(), begin.FlowID, "good-cred", begin.CSRFToken, begin.Cookies)
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosPasskeyLoginVerifyFailed, code)
}

// TestPasskeyLoginFinish_SubmitServerError proves a non-2xx/non-400 submit
// response is coded 1228, not ErrInvalidCredentials.
func TestPasskeyLoginFinish_SubmitServerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/self-service/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewKratosClient(srv.URL, srv.URL)

	_, err := c.PasskeyLoginFinish(context.Background(), "flow-pk-1", "good-cred", "csrf", map[string]string{"csrf_token_login": "x"})
	require.False(t, errors.Is(err, ErrInvalidCredentials))
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosPasskeyLoginVerifyFailed, code)
}

// TestPasskeyLoginFinish_Unreachable proves a bare transport failure is coded 1212.
func TestPasskeyLoginFinish_Unreachable(t *testing.T) {
	c := NewKratosClient("http://127.0.0.1:1", "http://127.0.0.1:1")
	_, err := c.PasskeyLoginFinish(context.Background(), "flow-pk-1", "good-cred", "csrf", nil)
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosUnreachable, code)
}

// A Kratos version may embed the challenge as a bare JSON object.
func TestChallengeOptions_ObjectForm(t *testing.T) {
	var f kratosFlowUI
	raw := `{"id":"f1","ui":{"nodes":[{"attributes":{"name":"passkey_challenge","value":{"publicKey":{"challenge":"x"}}}}]}}`
	require.NoError(t, json.Unmarshal([]byte(raw), &f))
	opts, ok := f.nodeValue(passkeyChallengeNodeName)
	require.True(t, ok)
	require.JSONEq(t, `{"publicKey":{"challenge":"x"}}`, opts)
}

func TestKratosClient_SatisfiesPasskeyAuthClient(t *testing.T) {
	var _ passkeyAuthClient = &KratosClient{}
	var _ passkeyRegisterAuthClient = &KratosClient{}
}
