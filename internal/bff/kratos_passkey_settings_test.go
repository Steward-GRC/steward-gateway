// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	apperr "github.com/Bugs5382/go-apperr"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/stretchr/testify/require"
)

// pkCreateOptionsJSON is a representative WebAuthn CREATION options blob
// (go-webauthn's {publicKey:{...}} shape) the browser feeds
// navigator.credentials.create.
const pkCreateOptionsJSON = `{"publicKey":{"challenge":"Y3JlYXRl","rp":{"id":"steward.example.org","name":"Steward"},"user":{"id":"dS0x","name":"grace@example.net","displayName":"grace@example.net"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}}`

// settingsFlowBody builds the JSON a browser settings flow returns, with a
// csrf_token node and (optionally) the passkey_create_data node whose value is
// the creation options serialized the way Kratos does — a JSON STRING.
func settingsFlowBody(id string, withCreateData bool) map[string]any {
	nodes := []map[string]any{
		{"attributes": map[string]any{"name": "csrf_token", "value": "csrf-tok-1"}},
	}
	if withCreateData {
		blob, _ := json.Marshal(pkCreateOptionsJSON)
		nodes = append(nodes, map[string]any{
			"attributes": map[string]any{"name": "passkey_create_data", "value": json.RawMessage(blob)},
		})
	}
	return map[string]any{"id": id, "ui": map[string]any{"nodes": nodes}}
}

// newKratosSettingsServer fakes Kratos's browser settings-flow endpoints for
// passkey registration. It requires the X-Session-Token header (401 without),
// sets a flow csrf cookie on the open, and accepts the goodCred attestation
// under method=passkey with a csrf_token (200) — otherwise finishStatus.
func newKratosSettingsServer(t *testing.T, withCreateData bool, goodCred string, finishStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/self-service/settings/browser", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Session-Token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "csrf_token_flow", Value: "csrf-cookie-1", Path: "/"})
		_ = json.NewEncoder(w).Encode(settingsFlowBody("set-flow-1", withCreateData))
	})
	mux.HandleFunc("/self-service/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Session-Token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("flow") != "set-flow-1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var body struct {
			Method   string `json:"method"`
			Register string `json:"passkey_settings_register"`
			CSRF     string `json:"csrf_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if finishStatus != http.StatusOK {
			w.WriteHeader(finishStatus)
			return
		}
		if body.Method != "passkey" || body.Register != goodCred || body.CSRF == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestPasskeyRegisterBegin_ReturnsOptionsAndCSRF(t *testing.T) {
	srv := newKratosSettingsServer(t, true, "goodcred", http.StatusOK)
	c := NewKratosClient(srv.URL, srv.URL)

	res, err := c.PasskeyRegisterBegin(context.Background(), "sess-token")
	require.NoError(t, err)
	require.Equal(t, "set-flow-1", res.FlowID)
	require.Equal(t, pkCreateOptionsJSON, res.OptionsJSON)
	require.Equal(t, "csrf-tok-1", res.CSRFToken)
	require.Equal(t, "csrf-cookie-1", res.Cookies["csrf_token_flow"], "flow csrf cookie must be captured for finish")
}

func TestPasskeyRegisterBegin_NoCreateDataNode_Coded(t *testing.T) {
	srv := newKratosSettingsServer(t, false, "goodcred", http.StatusOK)
	c := NewKratosClient(srv.URL, srv.URL)

	_, err := c.PasskeyRegisterBegin(context.Background(), "sess-token")
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosPasskeyRegisterInit, code)
}

func TestPasskeyRegisterBegin_NoSession_ReauthRequired(t *testing.T) {
	srv := newKratosSettingsServer(t, true, "goodcred", http.StatusOK)
	c := NewKratosClient(srv.URL, srv.URL)

	_, err := c.PasskeyRegisterBegin(context.Background(), "") // no session token → mock 401
	require.ErrorIs(t, err, ErrPasskeyReauthRequired)
}

func TestPasskeyRegisterBegin_Unreachable_Coded(t *testing.T) {
	c := NewKratosClient("http://127.0.0.1:1", "http://127.0.0.1:1")
	_, err := c.PasskeyRegisterBegin(context.Background(), "sess-token")
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosUnreachable, code)
}

func TestPasskeyRegisterFinish_Success(t *testing.T) {
	srv := newKratosSettingsServer(t, true, "goodcred", http.StatusOK)
	c := NewKratosClient(srv.URL, srv.URL)

	err := c.PasskeyRegisterFinish(context.Background(), "sess-token", "set-flow-1", "goodcred", "csrf-tok-1", map[string]string{"csrf_token_flow": "csrf-cookie-1"})
	require.NoError(t, err)
}

func TestPasskeyRegisterFinish_Rejected400_FailsClosed(t *testing.T) {
	srv := newKratosSettingsServer(t, true, "goodcred", http.StatusOK)
	c := NewKratosClient(srv.URL, srv.URL)

	err := c.PasskeyRegisterFinish(context.Background(), "sess-token", "set-flow-1", "WRONGCRED", "csrf-tok-1", nil)
	require.ErrorIs(t, err, ErrPasskeyRegistrationRejected)
}

func TestPasskeyRegisterFinish_Privileged403_ReauthRequired(t *testing.T) {
	srv := newKratosSettingsServer(t, true, "goodcred", http.StatusForbidden)
	c := NewKratosClient(srv.URL, srv.URL)

	err := c.PasskeyRegisterFinish(context.Background(), "sess-token", "set-flow-1", "goodcred", "csrf-tok-1", nil)
	require.ErrorIs(t, err, ErrPasskeyReauthRequired)
}

func TestPasskeyRegisterFinish_ServerError_Coded(t *testing.T) {
	srv := newKratosSettingsServer(t, true, "goodcred", http.StatusInternalServerError)
	c := NewKratosClient(srv.URL, srv.URL)

	err := c.PasskeyRegisterFinish(context.Background(), "sess-token", "set-flow-1", "goodcred", "csrf-tok-1", nil)
	code, ok := apperr.Code(err)
	require.True(t, ok, "expected a coded error, got %v", err)
	require.Equal(t, errcodes.CodeKratosPasskeyRegisterVerify, code)
}

func TestPasskeyRegisterFinish_EmptyInputs_FailsClosed(t *testing.T) {
	c := NewKratosClient("http://127.0.0.1:1", "http://127.0.0.1:1")
	require.ErrorIs(t, c.PasskeyRegisterFinish(context.Background(), "sess", "", "cred", "csrf", nil), ErrPasskeyRegistrationRejected)
	require.ErrorIs(t, c.PasskeyRegisterFinish(context.Background(), "sess", "flow", "", "csrf", nil), ErrPasskeyRegistrationRejected)
}

func TestPasskeyLoginAvailable(t *testing.T) {
	viable := newKratosPasskeyBrowserServer(t, defaultPasskeyServerConfig(time.Now().Add(time.Hour)))
	require.True(t, NewKratosClient(viable.URL, viable.URL).PasskeyLoginAvailable(context.Background()))

	noChallenge := defaultPasskeyServerConfig(time.Now().Add(time.Hour))
	noChallenge.withChallenge = false
	notViable := newKratosPasskeyBrowserServer(t, noChallenge)
	require.False(t, NewKratosClient(notViable.URL, notViable.URL).PasskeyLoginAvailable(context.Background()),
		"passkey method not exposed → login not viable → button hidden")
}

// TestRegisterThenLogin_EndToEnd is the integration proof: a
// credential a passkey REGISTER flow persists in Kratos is exactly what a passkey
// LOGIN flow then accepts. One stateful mock plays Kratos across both ceremonies —
// registration stores the credential, and login only succeeds once it exists.
func TestRegisterThenLogin_EndToEnd(t *testing.T) {
	var (
		mu         sync.Mutex
		registered string // the credential Kratos "persisted" during registration
	)
	const cred = "attestation-cred-xyz"

	mux := http.NewServeMux()
	mux.HandleFunc("/self-service/settings/browser", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Session-Token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "csrf_token_flow", Value: "cc", Path: "/"})
		_ = json.NewEncoder(w).Encode(settingsFlowBody("set-flow-1", true))
	})
	mux.HandleFunc("/self-service/settings", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Method, Register, CSRFToken string
		}
		raw := map[string]string{}
		_ = json.NewDecoder(r.Body).Decode(&raw)
		body.Method, body.Register, body.CSRFToken = raw["method"], raw["passkey_settings_register"], raw["csrf_token"]
		if body.Method != "passkey" || body.Register == "" || body.CSRFToken == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		registered = body.Register
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success"})
	})
	mux.HandleFunc("/self-service/login/browser", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		have := registered != ""
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "csrf_token_login", Value: "login-cc", Path: "/"})
		nodes := []map[string]any{{"attributes": map[string]any{"name": "csrf_token", "value": "login-csrf"}}}
		if have {
			blob, _ := json.Marshal(pkCreateOptionsJSON)
			nodes = append(nodes, map[string]any{"attributes": map[string]any{"name": "passkey_challenge", "value": json.RawMessage(blob)}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "login-flow-1", "ui": map[string]any{"nodes": nodes}})
	})
	mux.HandleFunc("/self-service/login", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("csrf_token_login"); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var raw map[string]string
		_ = json.NewDecoder(r.Body).Decode(&raw)
		mu.Lock()
		ok := raw["method"] == "passkey" && raw["passkey_login"] == registered && registered != "" && raw["csrf_token"] == "login-csrf"
		mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "ory_kratos_session", Value: "login-sess-cookie", Path: "/"})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"session": map[string]any{"active": true},
			"continue_with": []any{
				map[string]any{"action": "set_ory_session_token", "ory_session_token": "logged-in-token"},
			},
		})
	})
	mux.HandleFunc("/sessions/whoami", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("ory_kratos_session"); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true, "expires_at": time.Now().Add(time.Hour),
			"identity": map[string]any{"id": "id-1", "traits": map[string]any{"email": "grace@example.net"}},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewKratosClient(srv.URL, srv.URL)
	ctx := context.Background()

	require.False(t, c.PasskeyLoginAvailable(ctx), "no credential yet → login not viable")
	_, loginErr := c.PasskeyLoginBegin(ctx)
	require.Error(t, loginErr, "login begin must fail before any passkey is registered")

	beginRes, err := c.PasskeyRegisterBegin(ctx, "sess-token")
	require.NoError(t, err)
	require.Equal(t, pkCreateOptionsJSON, beginRes.OptionsJSON)
	require.NoError(t, c.PasskeyRegisterFinish(ctx, "sess-token", beginRes.FlowID, cred, beginRes.CSRFToken, beginRes.Cookies))

	require.True(t, c.PasskeyLoginAvailable(ctx), "after registration → login viable")
	loginBegin, err := c.PasskeyLoginBegin(ctx)
	require.NoError(t, err)
	require.Equal(t, pkCreateOptionsJSON, loginBegin.OptionsJSON)
	authRes, err := c.PasskeyLoginFinish(ctx, loginBegin.FlowID, cred, loginBegin.CSRFToken, loginBegin.Cookies)
	require.NoError(t, err)
	require.Equal(t, "grace@example.net", authRes.Email)
	require.Equal(t, "logged-in-token", authRes.AccessToken)
}
