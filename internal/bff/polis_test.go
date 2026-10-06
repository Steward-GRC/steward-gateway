// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	apperr "github.com/Bugs5382/go-apperr"
	"github.com/stretchr/testify/require"
)

// polisCapture records what the fake Jackson server received so tests can
// assert the server-to-server token/userinfo calls carried the expected shape.
type polisCapture struct {
	tokenForm    url.Values
	userInfoAuth string
	tokenStatus  int // override token endpoint status (0 → 200)
	userInfoBody string
	userInfoStat int // override userinfo status (0 → 200)
	accessToken  string
	refreshToken string
}

// newPolisServer stands up a fake Jackson exposing /api/oauth/token and
// /api/oauth/userinfo (the two server-to-server endpoints PolisClient calls).
func newPolisServer(t *testing.T, cap *polisCapture) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cap.tokenForm = r.PostForm
		if cap.tokenStatus != 0 {
			w.WriteHeader(cap.tokenStatus)
			return
		}
		at := cap.accessToken
		if at == "" {
			at = "polis-at"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": at, "refresh_token": cap.refreshToken, "expires_in": 300,
		})
	})
	mux.HandleFunc("/api/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		cap.userInfoAuth = r.Header.Get("Authorization")
		if cap.userInfoStat != 0 {
			w.WriteHeader(cap.userInfoStat)
			return
		}
		if cap.userInfoBody != "" {
			_, _ = w.Write([]byte(cap.userInfoBody))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "polis-id-1", "email": "alice@example.org", "firstName": "Alice", "lastName": "Anderson",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestPolisAuthorizeURL_HasTenantProductAndDummyClient(t *testing.T) {
	c := NewPolisClient("https://edge/sso", "http://polis:5225", "steward")
	raw := c.AuthorizeURL("https://app/auth/sso/callback", "st-123", "example.org", "steward")
	u, err := url.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, "https", u.Scheme)
	require.Equal(t, "edge", u.Host)
	require.Equal(t, "/sso/api/oauth/authorize", u.Path)
	q := u.Query()
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "dummy", q.Get("client_id"))
	require.Equal(t, "https://app/auth/sso/callback", q.Get("redirect_uri"))
	require.Equal(t, "st-123", q.Get("state"))
	require.Equal(t, "openid", q.Get("scope"))
	require.Equal(t, "example.org", q.Get("tenant"))
	require.Equal(t, "steward", q.Get("product"))
}

// IdP-initiated has no pre-known tenant: an empty tenant must be OMITTED, not
// sent as tenant="" (which Jackson would treat as a real, empty tenant).
func TestPolisAuthorizeURL_OmitsEmptyTenant(t *testing.T) {
	c := NewPolisClient("https://edge/sso", "http://polis:5225", "steward")
	raw := c.AuthorizeURL("https://app/auth/sso/callback", "st", "", "steward")
	u, _ := url.Parse(raw)
	_, present := u.Query()["tenant"]
	require.False(t, present, "empty tenant must be omitted")
}

func TestPolisCodeExchange_HitsTokenEndpointWithDummySecret(t *testing.T) {
	cap := &polisCapture{accessToken: "at-xyz", refreshToken: "rt-xyz"}
	srv := newPolisServer(t, cap)
	c := NewPolisClient("https://edge/sso", srv.URL, "steward")

	tok, err := c.CodeExchange(context.Background(), "the-code", "https://app/auth/sso/callback")
	require.NoError(t, err)
	require.Equal(t, "at-xyz", tok.AccessToken)

	require.Equal(t, "authorization_code", cap.tokenForm.Get("grant_type"))
	require.Equal(t, "the-code", cap.tokenForm.Get("code"))
	require.Equal(t, "https://app/auth/sso/callback", cap.tokenForm.Get("redirect_uri"))
	require.Equal(t, "dummy", cap.tokenForm.Get("client_id"))
	require.Equal(t, "dummy", cap.tokenForm.Get("client_secret"))
	require.Empty(t, cap.tokenForm.Get("code_verifier"))
}

func TestPolisCodeExchange_ErrorStatusIsCoded1218(t *testing.T) {
	cap := &polisCapture{tokenStatus: http.StatusBadRequest}
	srv := newPolisServer(t, cap)
	c := NewPolisClient("https://edge/sso", srv.URL, "steward")

	_, err := c.CodeExchange(context.Background(), "bad", "https://app/auth/sso/callback")
	require.Error(t, err)
	code, ok := apperr.Code(err)
	require.True(t, ok)
	require.Equal(t, 1218, code)
}

func TestPolisUserInfo_ParsesProfileAndSendsBearer(t *testing.T) {
	cap := &polisCapture{}
	srv := newPolisServer(t, cap)
	c := NewPolisClient("https://edge/sso", srv.URL, "steward")

	p, err := c.UserInfo(context.Background(), "the-access-token")
	require.NoError(t, err)
	require.Equal(t, "polis-id-1", p.ID)
	require.Equal(t, "alice@example.org", p.Email)
	require.Equal(t, "Alice", p.FirstName)
	require.Equal(t, "Anderson", p.LastName)
	require.Equal(t, "Bearer the-access-token", cap.userInfoAuth)
}

func TestPolisUserInfo_ErrorStatusIsCoded1219(t *testing.T) {
	cap := &polisCapture{userInfoStat: http.StatusUnauthorized}
	srv := newPolisServer(t, cap)
	c := NewPolisClient("https://edge/sso", srv.URL, "steward")

	_, err := c.UserInfo(context.Background(), "tok")
	require.Error(t, err)
	code, ok := apperr.Code(err)
	require.True(t, ok)
	require.Equal(t, 1219, code)
}
