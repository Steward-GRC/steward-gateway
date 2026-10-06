// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

func testLinkRecord() SSOTestLinkRecord {
	return SSOTestLinkRecord{
		ConnectionID: "conn-9",
		Alias:        "example-sso",
		Tenant:       "acme.example",
		ReturnPath:   "/admin/organizations/acme.example",
		AdminUserID:  testAdminUserID,
	}
}

func TestSSOTestLinkStore_RoundTripAllFields(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	want := testLinkRecord()
	require.NoError(t, store.PutSSOTestLink(ctx, "tok1", want, time.Minute))
	got, ok, err := store.GetSSOTestLink(ctx, "tok1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, want, got)
}

// Unlike SSOState (single-use), a test link must survive repeated Gets within
// its TTL so a remote user can retry a failed IdP login on the SAME link.
func TestSSOTestLinkStore_NotSingleUse(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, store.PutSSOTestLink(ctx, "tok1", testLinkRecord(), time.Minute))
	for i := range 3 {
		_, ok, err := store.GetSSOTestLink(ctx, "tok1")
		require.NoError(t, err)
		require.True(t, ok, "link must stay usable across retries (attempt %d)", i)
	}
}

func TestSSOTestLinkStore_GetMiss(t *testing.T) {
	store := newTestStore(t)
	_, ok, err := store.GetSSOTestLink(context.Background(), "nope")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestSSOTestLinkStore_TTLExpiry(t *testing.T) {
	store, mr := newTestStoreClock(t)
	ctx := context.Background()
	require.NoError(t, store.PutSSOTestLink(ctx, "tok1", testLinkRecord(), time.Minute))
	mr.FastForward(2 * time.Minute)
	_, ok, err := store.GetSSOTestLink(ctx, "tok1")
	require.NoError(t, err)
	require.False(t, ok, "link must expire after its ttl")
}

// serveMintTestLink serves body to MintSSOTestLink with claims on the
// context, as Authenticate leaves them.
func serveMintTestLink(t *testing.T, h *Handler, claims principal.Claims, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/sso/test-link", strings.NewReader(body))
	if claims != nil {
		req = req.WithContext(principal.WithClaims(req.Context(), claims))
	}
	rec := httptest.NewRecorder()
	h.MintSSOTestLink(rec, req)
	return rec
}

func TestMintSSOTestLink_HappyPathStashesAdminAndReturnsURL(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{SSOTestLink: store, SSORedirectBase: "https://app", TestLinkTTL: 30 * time.Minute}
	body := `{"connectionId":"conn-9","alias":"example-sso","tenant":"ACME.example","returnPath":"/admin/organizations/acme.example"}`
	rec := serveMintTestLink(t, h, siteAdminClaims(), body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp struct{ URL, ExpiresAt string }
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.ExpiresAt)

	u, err := url.Parse(resp.URL)
	require.NoError(t, err)
	require.Equal(t, "https://app", u.Scheme+"://"+u.Host)
	require.Equal(t, "/auth/sso/start", u.Path)
	q := u.Query()
	require.Equal(t, "example-sso", q.Get("connection"))
	require.Equal(t, "test", q.Get("mode"))
	token := q.Get("testToken")
	require.NotEmpty(t, token)

	got, ok, err := store.GetSSOTestLink(context.Background(), token)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "conn-9", got.ConnectionID)
	require.Equal(t, "example-sso", got.Alias)
	require.Equal(t, "acme.example", got.Tenant, "tenant is lowercased")
	require.Equal(t, "/admin/organizations/acme.example", got.ReturnPath)
	require.Equal(t, "admin-1", got.AdminUserID)
}

func TestMintSSOTestLink_ForbiddenNonSiteAdmin(t *testing.T) {
	h := &Handler{SSOTestLink: newTestStore(t), SSORedirectBase: "https://app"}
	rec := serveMintTestLink(t, h, nonAdminClaims(), `{"connectionId":"conn-9","alias":"example-sso"}`)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestMintSSOTestLink_BadRequestMissingFields(t *testing.T) {
	h := &Handler{SSOTestLink: newTestStore(t), SSORedirectBase: "https://app"}
	rec := serveMintTestLink(t, h, siteAdminClaims(), `{"alias":"example-sso"}`) // no connectionId
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// An off-origin / non-/admin returnPath is coerced to the safe default by the
// open-redirect guard, so a minted link can never redirect the browser off-site.
func TestMintSSOTestLink_CoercesUnsafeReturnPath(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{SSOTestLink: store, SSORedirectBase: "https://app"}
	body := `{"connectionId":"conn-9","alias":"example-sso","returnPath":"https://evil.example.net/steal"}`
	rec := serveMintTestLink(t, h, siteAdminClaims(), body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp struct{ URL string }
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	u, _ := url.Parse(resp.URL)
	got, ok, err := store.GetSSOTestLink(context.Background(), u.Query().Get("testToken"))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, defaultAdminReturnPath, got.ReturnPath)
}

// A shareable-link start (testToken) parks a mode=test state sourced ENTIRELY
// from the minted record — connection alias, connection UUID, return path, and
// the minting admin's UserID — WITHOUT any live admin session on the request
// (the remote user has none).
func TestSSOStart_TestTokenStashesStateWithoutSession(t *testing.T) {
	linkStore := newTestStore(t)
	ssoState := newTestStore(t)
	require.NoError(t, linkStore.PutSSOTestLink(context.Background(), "tok1", testLinkRecord(), time.Minute))

	h := &Handler{
		Polis:           testPolis(),
		SSOState:        ssoState,
		SSOTestLink:     linkStore,
		SSORedirectBase: "https://app",
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/start?testToken=tok1", nil)
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "acme.example", loc.Query().Get("tenant"), "the link's tenant selects the Jackson connection")
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)

	got, ok, err := ssoState.TakeSSOState(req.Context(), state)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "test", got.Mode)
	require.Equal(t, "conn-9", got.ConnectionID)
	require.Equal(t, "example-sso", got.Connection)
	require.Equal(t, "/admin/organizations/acme.example", got.ReturnPath)
	require.Equal(t, testAdminUserID, got.AdminUserID, "the minting admin's UserID rides the state to the callback")
}

func TestSSOStart_TestTokenExpiredFailsClosed(t *testing.T) {
	h := &Handler{
		Polis:           testPolis(),
		SSOState:        newTestStore(t),
		SSOTestLink:     newTestStore(t), // empty: token misses
		SSORedirectBase: "https://app",
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/start?testToken=gone", nil)
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusGone, rec.Code)
	require.Contains(t, rec.Body.String(), "expired")
	require.Empty(t, rec.Header().Get("Location"), "an invalid link must not start any IdP round trip")
}

// End-to-end: a remote user opens the minted link (SSOStart via testToken) and
// completes the IdP round trip; the callback records the result via
// RecordIdPTestResult under the MINTING admin's forwarded site-admin claims,
// with NO admin cookie anywhere in the flow.
func TestSSOTestLink_EndToEnd_RecordsWithoutAdminCookie(t *testing.T) {
	id := defaultIdentity()
	id.getUser = adminUser() // callback re-resolves the stashed admin UserID → site-admin
	h, ssoState := newSSOCallbackHandler(t, "grace@example.net", id, MFAConfig{Mode: MFAModeNever})
	h.SSOTestLink = newTestStore(t)
	require.NoError(t, h.SSOTestLink.PutSSOTestLink(context.Background(), "tok1", testLinkRecord(), time.Minute))

	var recordedConn string
	var recordedOK, recorded, ctxHadSiteAdmin bool
	h.IdPTestRecorder = func(ctx context.Context, connectionID string, success bool, _ string) error {
		recorded, recordedConn, recordedOK = true, connectionID, success
		if c, ok := principal.FromContext(ctx); ok {
			ctxHadSiteAdmin = principal.HasRole(c, siteAdminRole)
		}
		return nil
	}

	startRec := httptest.NewRecorder()
	h.SSOStart(startRec, httptest.NewRequest(http.MethodGet, "/auth/sso/start?testToken=tok1", nil))
	require.Equal(t, http.StatusFound, startRec.Code, startRec.Body.String())
	loc, err := url.Parse(startRec.Header().Get("Location"))
	require.NoError(t, err)
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)

	cbRec := httptest.NewRecorder()
	h.SSOCallback(cbRec, ssoCallbackReq(state))

	require.Nil(t, sessionCookie(cbRec), "a test round trip must never issue a session")
	require.True(t, recorded, "the outcome must be recorded")
	require.Equal(t, "conn-9", recordedConn)
	require.True(t, recordedOK, "a usable email claim is a pass")
	require.True(t, ctxHadSiteAdmin, "record ctx must forward the minting admin's site-admin claims")
	_ = ssoState // state store shared via the handler
}
