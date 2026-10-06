// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/stretchr/testify/require"
)

func testPolis() *PolisClient {
	return NewPolisClient("https://edge/sso", "http://unused", "steward")
}

// The state parked in Redis must carry the connection alias
// and default to Mode=login when the caller omits ?mode, so the callback
// can look it up by the `state` query param on the redirect.
func TestSSOStart_StoresStateWithConnectionAndDefaultMode(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{Polis: testPolis(), SSOState: store, SSORedirectBase: "https://app"}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso&identifier=frank@example.org", nil)
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)

	got, ok, err := store.TakeSSOState(req.Context(), state)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "example-sso", got.Connection)
	require.Equal(t, "login", got.Mode)
	require.Equal(t, "example.org", got.Tenant)
}

// A "test" mode probe (admin connection-test) must be recorded as such so the
// callback can route the result to the admin flow instead of
// completing a login. Bug 1: a mode=test start now requires an
// authenticated site-admin SESSION (same-origin, cookie present; resolved
// kratos-natively cookie→Store→UserID→GetUser→site-admin) and STASHES that
// admin's platform UserID into SSOState.AdminUserID so the cross-site callback
// can re-resolve + record without the cookie.
func TestSSOStart_ModeTestIsStored(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{Polis: testPolis(), SSOState: store, SSORedirectBase: "https://app", Store: newTestStore(t), Identity: &fakeMfaIdentity{getUser: adminUser()}}
	req := siteAdminStartReq(t, h, "/auth/sso/start?connection=example-sso&mode=test&tenant=example.org")
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	state := loc.Query().Get("state")

	got, ok, err := store.TakeSSOState(req.Context(), state)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "test", got.Mode)
	require.Equal(t, testAdminUserID, got.AdminUserID, "the initiating admin's platform UserID must be stashed")
}

// Final whole-branch review: the test-mode probe carries the connection UUID
// via ?connectionId (the admin wizard already holds it), and SSOStart must
// persist it into SSOState.ConnectionID so the callback can hand a REAL UUID
// to identity's RecordIdPTestResult (an empty string parses to InvalidArgument
// and silently skips MarkIdPTestPassed, leaving the IdP-test gate un-flippable).
func TestSSOStart_StoresConnectionID(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{Polis: testPolis(), SSOState: store, SSORedirectBase: "https://app", Store: newTestStore(t), Identity: &fakeMfaIdentity{getUser: adminUser()}}
	const connID = "11111111-2222-3333-4444-555555555555"
	req := siteAdminStartReq(t, h, "/auth/sso/start?connection=example-sso&mode=test&tenant=example.org&connectionId="+connID)
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)

	got, ok, err := store.TakeSSOState(req.Context(), state)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "test", got.Mode)
	require.Equal(t, connID, got.ConnectionID)
}

// A test-mode probe may carry a returnPath so the callback returns the admin to
// the wizard step they launched from. SSOStart must store a VALID (relative,
// same-origin, /admin/-prefixed) path verbatim.
func TestSSOStart_StoresValidReturnPath(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{Polis: testPolis(), SSOState: store, SSORedirectBase: "https://app", Store: newTestStore(t), Identity: &fakeMfaIdentity{getUser: adminUser()}}
	const rp = "/admin/organizations/example.org"
	req := siteAdminStartReq(t, h, "/auth/sso/start?connection=example-sso&mode=test&tenant=example.org&returnPath="+url.QueryEscape(rp))
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	got, ok, err := store.TakeSSOState(req.Context(), loc.Query().Get("state"))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, rp, got.ReturnPath)
}

// The open-redirect guard: a returnPath with a scheme, an authority, a
// backslash, one not under /admin/, or an absent one all fall back to the
// default org list — never an attacker-controlled destination.
func TestSSOStart_ReturnPathOpenRedirectGuard(t *testing.T) {
	cases := map[string]string{
		"absent":            "",
		"absolute-https":    "https://evil.example.net/admin/x",
		"protocol-relative": "//evil.example/admin/x",
		"backslash":         "/admin/\\evil.example",
		"not-admin":         "/home",
		"root":              "/",
		"scheme-only":       "javascript:alert(1)",
	}
	for name, rp := range cases {
		t.Run(name, func(t *testing.T) {
			store := newTestStore(t)
			h := &Handler{Polis: testPolis(), SSOState: store, SSORedirectBase: "https://app", Store: newTestStore(t), Identity: &fakeMfaIdentity{getUser: adminUser()}}
			u := "/auth/sso/start?connection=example-sso&mode=test&tenant=example.org"
			if rp != "" {
				u += "&returnPath=" + url.QueryEscape(rp)
			}
			req := siteAdminStartReq(t, h, u)
			rec := httptest.NewRecorder()
			h.SSOStart(rec, req)
			require.Equal(t, http.StatusFound, rec.Code)

			loc, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			got, ok, err := store.TakeSSOState(req.Context(), loc.Query().Get("state"))
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, "/admin/organizations", got.ReturnPath)
		})
	}
}

func TestSSOStart_EmptyConnectionRejected(t *testing.T) {
	h := &Handler{Polis: testPolis(), SSOState: newTestStore(t), SSORedirectBase: "https://app"}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/start", nil)
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// Bug 1: a mode=test start WITHOUT a session fails closed 401 and
// parks NO state (nothing to record against, and no admin proof to stash).
func TestSSOStart_TestMode_NoSessionUnauthorized(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{Polis: testPolis(), SSOState: store, SSORedirectBase: "https://app", Store: newTestStore(t), Identity: &fakeMfaIdentity{getUser: adminUser()}}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso&mode=test", nil) // no cookie
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Empty(t, rec.Header().Get("Location"), "must not initiate the SSO redirect")
}

// Bug 1: a mode=test start by a logged-in but NON-site-admin caller (their
// session UserID resolves to a non-admin via GetUser) fails closed 403, no state.
func TestSSOStart_TestMode_NonAdminForbidden(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{Polis: testPolis(), SSOState: store, SSORedirectBase: "https://app", Store: newTestStore(t), Identity: &fakeMfaIdentity{getUser: nonAdminUser()}}
	req := siteAdminStartReq(t, h, "/auth/sso/start?connection=example-sso&mode=test&tenant=example.org")
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Empty(t, rec.Header().Get("Location"))
}

// Bug 2: a login-mode start for a connection that is NOT active
// (Discover does not return method=sso for the identifier) fails closed to
// /login?error=sso_not_active and never parks state / initiates SSO — even
// though a direct GET bypassed the widget's pre-login Discover.
func TestSSOStart_Login_InactiveConnectionBlocked(t *testing.T) {
	cases := map[string]*identityv1.DiscoverResponse{
		"not sso":        {Method: "local"},
		"alias mismatch": {Method: "sso", ConnectionAlias: "other"},
	}
	for name, disc := range cases {
		t.Run(name, func(t *testing.T) {
			store := newTestStore(t)
			h := &Handler{
				Polis:           testPolis(),
				SSOState:        store,
				SSORedirectBase: "https://app",
				Identity:        fakeIdentity{discover: disc},
			}
			req := httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso&identifier=frank@example.org", nil)
			rec := httptest.NewRecorder()
			h.SSOStart(rec, req)
			require.Equal(t, http.StatusFound, rec.Code)
			require.Equal(t, "/login?error=sso_not_active", rec.Header().Get("Location"))
		})
	}
}

// Bug 2: with NO identifier the active connection cannot be re-verified via
// Discover, so a login start fails closed rather than initiate SSO for an
// unverifiable connection.
func TestSSOStart_Login_MissingIdentifierBlocked(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{
		Polis:           testPolis(),
		SSOState:        store,
		SSORedirectBase: "https://app",
		Identity:        fakeIdentity{discover: &identityv1.DiscoverResponse{Method: "sso", ConnectionAlias: "example-sso"}},
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso", nil) // no identifier
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/login?error=sso_not_active", rec.Header().Get("Location"))
}

// Bug 2: a login-mode start for an ACTIVE connection (Discover returns method=sso
// for the matching alias) proceeds to the Polis authorize redirect and parks
// state as before.
func TestSSOStart_Login_ActiveConnectionProceeds(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{
		Polis:           testPolis(),
		SSOState:        store,
		SSORedirectBase: "https://app",
		Identity:        fakeIdentity{discover: &identityv1.DiscoverResponse{Method: "sso", ConnectionAlias: "example-sso"}},
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso&identifier=frank@example.org", nil)
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "example.org", loc.Query().Get("tenant"))
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)
	got, ok, err := store.TakeSSOState(context.Background(), state)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "example-sso", got.Connection)
}
