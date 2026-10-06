// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/stretchr/testify/require"
)

// newSSOCallbackHandler wires a polis-backed Handler for GET /auth/sso/callback
// tests whose fake Jackson userinfo answers with email ("" for none).
func newSSOCallbackHandler(t *testing.T, email string, id *fakeMfaIdentity, cfg MFAConfig) (*Handler, SSOStateStore) {
	t.Helper()
	h, ssoState, cap := newPolisSSOHandler(t, id, cfg)
	body, err := json.Marshal(map[string]string{"id": "polis-id-1", "email": email})
	require.NoError(t, err)
	cap.userInfoBody = string(body)
	return h, ssoState
}

func ssoCallbackReq(state string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=c&state="+state, nil)
}

// ssoCallbackReqPublicEdge is ssoCallbackReq with the trusted public-edge header
// Traefik stamps on external requests, so mfaRequired evaluates to true under
// MFAModeEdge (the production posture) — the SSO callback owes a second factor.
func ssoCallbackReqPublicEdge(state string) *http.Request {
	req := ssoCallbackReq(state)
	req.Header.Set("X-Steward-Edge", "public")
	return req
}

// mfaRedirect asserts an SSO MFA step-up redirect into the SPA's MFA resume
// route and returns the carried pending id + offered factor kinds. It proves the
// callback answered a full-page 302 into the SPA (never JSON) and never minted a
// session on the way.
func mfaRedirect(t *testing.T, rec *httptest.ResponseRecorder) (pendingID string, factors []string) {
	t.Helper()
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.Nil(t, sessionCookie(rec), "no session cookie may be issued before MFA verifies")
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/login", loc.Path, "MFA step-up must land on the SPA login/MFA route")
	pendingID = loc.Query().Get("pendingMfa")
	require.NotEmpty(t, pendingID, "the resume URL must carry the pending id")
	if f := loc.Query().Get("mfaFactors"); f != "" {
		factors = strings.Split(f, ",")
	}
	return pendingID, factors
}

// activeSSODiscover is the Discover verdict for an ACTIVE example-sso sso connection —
// the login-callback active gate refuses to mint a session unless
// identity Discover (keyed on the token/userinfo email) returns method=sso for
// the recovered connection, so a callback login test must model an active one.
func activeSSODiscover() *identityv1.DiscoverResponse {
	return &identityv1.DiscoverResponse{Method: "sso", ConnectionAlias: "example-sso"}
}

func TestSSOCallback_UnknownStateRejected(t *testing.T) {
	h := &Handler{SSOState: newTestStore(t)}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=c&state=missing", nil)
	rec := httptest.NewRecorder()
	h.SSOCallback(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// A login-mode callback with a valid state but no code is the broker reporting
// an OAuth front-channel error (e.g. login_required). Since this is a full-page
// browser navigation, it redirects to /login?error=sso rather than answering JSON.
func TestSSOCallback_EmptyCodeLoginRedirects(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Mode: "login"}, ssoStateTTL))
	h := &Handler{SSOState: store}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?state=st1&error=login_required", nil) // no code
	rec := httptest.NewRecorder()
	h.SSOCallback(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/login?error=sso", rec.Header().Get("Location"))
	require.Nil(t, sessionCookie(rec))
}

// A test-mode probe with no code keeps its JSON invalid_state (a missing code
// there is a genuinely bad callback).
func TestSSOCallback_EmptyCodeTestModeRejected(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Mode: "test", ConnectionID: "conn-9"}, ssoStateTTL))
	h := &Handler{SSOState: store}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?state=st1", nil) // no code
	rec := httptest.NewRecorder()
	h.SSOCallback(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// testAdminUserID is the initiating site-admin's PLATFORM UserID used across the
// test-mode SSO tests. Bug 1: the kratos-native auth resolves it
// from the steward_sid session (cookie → Store → UserID) at SSOStart and STASHES
// it in SSOState.AdminUserID; the test-mode callback re-resolves it via identity
// GetUser → site-admin, so the callback request carries NO cookie — proving the
// cross-site fix — and never runs an opaque bearer through the kratos verifier.
const testAdminUserID = "admin-1"

// adminUser is a site-admin identity.User for GetUser stubs (the projection
// claimsFromIdentityUser turns into site-admin claims).
func adminUser() *identityv1.User {
	return &identityv1.User{Id: testAdminUserID, Enabled: true, Roles: []string{"admin", "site-admin"}}
}

// nonAdminUser is an enabled but NON-site-admin identity.User for GetUser stubs.
func nonAdminUser() *identityv1.User {
	return &identityv1.User{Id: testAdminUserID, Enabled: true, Roles: []string{"reader"}}
}

// putTestStateWithAdmin stashes a mode=test state whose AdminUserID the callback
// re-resolves kratos-natively via identity GetUser. Configure the
// identity fake's getUser (e.g. adminUser()) so that lookup yields a site-admin.
func putTestStateWithAdmin(t *testing.T, ssoState SSOStateStore, connID string) {
	t.Helper()
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{
		Connection: "example-sso", Mode: "test", ConnectionID: connID,
		AdminUserID: testAdminUserID,
	}, ssoStateTTL))
}

func putTestState(t *testing.T, ssoState SSOStateStore, connID string) {
	t.Helper()
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{
		Connection: "example-sso", Mode: "test", ConnectionID: connID,
	}, ssoStateTTL))
}

// siteAdminStartReq wires an initiating-admin SESSION onto a mode=test SSOStart
// request: a Redis session carrying the admin's platform UserID (as
// a kratos local login mints) plus the steward_sid cookie (present same-origin at
// start). The identity fake must resolve that UserID to a site-admin via GetUser.
func siteAdminStartReq(t *testing.T, h *Handler, rawurl string) *http.Request {
	t.Helper()
	const sid = "admin-sid"
	require.NoError(t, h.Store.Create(context.Background(), sid, Session{
		AccessToken: "opaque-kratos-session-token", UserID: testAdminUserID, ExpiresAt: time.Now().Add(time.Hour),
	}))
	req := httptest.NewRequest(http.MethodGet, rawurl, nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sid})
	return req
}

// requireTestResultHTML asserts the response is the postMessage result page: a
// 200 HTML doc that posts an idp-test-result of the given success to the app
// origin (never "*") and carries the ?test= fallback.
func requireTestResultHTML(t *testing.T, rec *httptest.ResponseRecorder, wantSuccess bool, wantOrigin, wantFallback string) {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	body := rec.Body.String()
	require.Contains(t, body, "window.opener.postMessage")
	require.Contains(t, body, "idp-test-result")
	if wantSuccess {
		require.Contains(t, body, `"success":true`)
	} else {
		require.Contains(t, body, `"success":false`)
	}
	require.Contains(t, body, wantOrigin, "must postMessage to the app origin")
	require.NotContains(t, body, "*", "must never postMessage to the wildcard origin")
	require.Contains(t, body, wantFallback, "opener-less fallback must carry the ?test= result")
}

// A test-mode callback records the probe outcome via the STASHED admin proof
// — carrying the admin's forwarded site-admin claims — EVEN when the
// callback request carries NO cookie, and delivers the pass via the postMessage
// result page. Never issues a session.
func TestSSOCallback_TestMode_AuthorizedRecordsPassed(t *testing.T) {
	id := defaultIdentity()
	id.getUser = adminUser() // cookie-less callback re-resolves the admin by stashed UserID
	h, ssoState := newSSOCallbackHandler(t, "alice@example.org", id, MFAConfig{Mode: MFAModeNever})
	putTestStateWithAdmin(t, ssoState, "conn-9")

	var recordedConn string
	var recordedOK, recorded, ctxHadSiteAdmin bool
	h.IdPTestRecorder = func(ctx context.Context, connectionID string, success bool, _ string) error {
		recorded, recordedConn, recordedOK = true, connectionID, success
		if c, ok := principal.FromContext(ctx); ok {
			ctxHadSiteAdmin = principal.HasRole(c, "site-admin")
		}
		return nil
	}

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1")) // NO cookie: proof comes from the stash

	requireTestResultHTML(t, rec, true, "https://app", "/admin/organizations?test=passed")
	require.Nil(t, sessionCookie(rec), "test mode must never issue a session")
	require.True(t, recorded, "IdPTestRecorder must be invoked")
	require.Equal(t, "conn-9", recordedConn)
	require.True(t, recordedOK)
	require.True(t, ctxHadSiteAdmin, "record ctx must forward the admin's site-admin claims")
	require.Nil(t, id.lastGetUserByEmail, "test mode must not JIT-provision a user")
}

// When the probe carried a validated returnPath, the test-mode callback returns
// the admin THERE (not the org list) with the ?test= result appended — so the
// result surfaces in the wizard step they launched from.
func TestSSOCallback_TestMode_ReturnsToStoredReturnPath(t *testing.T) {
	id := defaultIdentity()
	id.getUser = adminUser()
	h, ssoState := newSSOCallbackHandler(t, "alice@example.org", id, MFAConfig{Mode: MFAModeNever})
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{
		Connection: "example-sso", Mode: "test", ConnectionID: "conn-9",
		ReturnPath: "/admin/organizations/example.org", AdminUserID: testAdminUserID,
	}, ssoStateTTL))
	h.IdPTestRecorder = func(context.Context, string, bool, string) error { return nil }

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	requireTestResultHTML(t, rec, true, "https://app", "/admin/organizations/example.org?test=passed")
}

// A returnPath that already carries a query gets the ?test= result appended with
// "&" (not a second "?"), preserving the existing query.
func TestSSOCallback_TestMode_ReturnPathWithExistingQuery(t *testing.T) {
	id := defaultIdentity()
	id.getUser = adminUser()
	h, ssoState := newSSOCallbackHandler(t, "alice@example.org", id, MFAConfig{Mode: MFAModeNever})
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{
		Connection: "example-sso", Mode: "test", ConnectionID: "conn-9",
		ReturnPath: "/admin/organizations/example.org?step=test", AdminUserID: testAdminUserID,
	}, ssoStateTTL))
	h.IdPTestRecorder = func(context.Context, string, bool, string) error { return nil }

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := rec.Body.String()
	require.Contains(t, body, `/admin/organizations/example.org?step=test&amp;test=passed`)
	require.Contains(t, body, `"success":true`)
}

// No stashed admin proof (state carries no AdminUserID) → fail closed: never
// record, redirect ?test=failed.
func TestSSOCallback_TestMode_NoAdminSessionFailsClosed(t *testing.T) {
	id := defaultIdentity()
	h, ssoState := newSSOCallbackHandler(t, "alice@example.org", id, MFAConfig{Mode: MFAModeNever})
	putTestState(t, ssoState, "conn-9") // no AdminUserID stashed

	recorded := false
	h.IdPTestRecorder = func(context.Context, string, bool, string) error { recorded = true; return nil }

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1")) // no cookie, no stashed proof

	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "failed", loc.Query().Get("test"))
	require.Equal(t, "not_authorized", loc.Query().Get("reason"))
	require.False(t, recorded, "must never record without a site-admin session")
	require.Nil(t, sessionCookie(rec))
}

// A logged-in but non-site-admin caller → fail closed, never record.
func TestSSOCallback_TestMode_NonAdminFailsClosed(t *testing.T) {
	id := defaultIdentity()
	id.getUser = nonAdminUser() // stashed UserID re-resolves to a NON-site-admin
	h, ssoState := newSSOCallbackHandler(t, "alice@example.org", id, MFAConfig{Mode: MFAModeNever})
	putTestStateWithAdmin(t, ssoState, "conn-9")

	recorded := false
	h.IdPTestRecorder = func(context.Context, string, bool, string) error { recorded = true; return nil }

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "failed", loc.Query().Get("test"))
	require.False(t, recorded, "a non-site-admin caller must never record")
}

// A record RPC failure must surface as ?test=failed — never a false pass.
func TestSSOCallback_TestMode_RecordFailureReflectsFailed(t *testing.T) {
	id := defaultIdentity()
	id.getUser = adminUser()
	h, ssoState := newSSOCallbackHandler(t, "alice@example.org", id, MFAConfig{Mode: MFAModeNever})
	putTestStateWithAdmin(t, ssoState, "conn-9")

	h.IdPTestRecorder = func(context.Context, string, bool, string) error {
		return errors.New("permission denied")
	}

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "failed", loc.Query().Get("test"))
	require.Equal(t, "record_failed", loc.Query().Get("reason"))
	require.Nil(t, sessionCookie(rec))
}

// A successful exchange with NO usable email claim is a genuine test failure:
// it is recorded with success=false and reflected as ?test=failed.
func TestSSOCallback_TestMode_NoEmailRecordsFailure(t *testing.T) {
	id := defaultIdentity()
	id.getUser = adminUser()
	h, ssoState := newSSOCallbackHandler(t, "", id, MFAConfig{Mode: MFAModeNever})
	putTestStateWithAdmin(t, ssoState, "conn-9")

	var recordedOK, recorded bool
	h.IdPTestRecorder = func(_ context.Context, _ string, success bool, _ string) error {
		recorded, recordedOK = true, success
		return nil
	}

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	requireTestResultHTML(t, rec, false, "https://app", "test=failed")
	require.True(t, recorded, "a failed probe must still be recorded")
	require.False(t, recordedOK, "must record success=false")
}

// An unwired recorder cannot persist the activation gate, so even an authorized
// admin probe fails closed rather than claim a pass it never recorded.
func TestSSOCallback_TestMode_NoRecorderFailsClosed(t *testing.T) {
	id := defaultIdentity()
	id.getUser = adminUser()
	h, ssoState := newSSOCallbackHandler(t, "alice@example.org", id, MFAConfig{Mode: MFAModeNever})
	putTestStateWithAdmin(t, ssoState, "conn-9")

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "failed", loc.Query().Get("test"))
	require.Equal(t, "recorder_unavailable", loc.Query().Get("reason"))
	require.Nil(t, sessionCookie(rec))
}

// Regression guard: the FULL kratos-native admin path end to end under
// AUTH_BACKEND=kratos with NO JWT bearer anywhere. SSOStart(mode=test)
// authenticates the site-admin from the steward_sid SESSION (cookie → Store →
// UserID → identity GetUser → site-admin) and stashes the UserID; the CROSS-SITE
// callback (NO cookie) re-resolves it and records the result under the admin's
// forwarded site-admin claims. This is the exact flow that regressed when the
// admin was authenticated by running the opaque session bearer through the kratos
// per-request verifier (which needs a SessionHTTP-stashed principal).
func TestSSO_Kratos_TestModeStartThenCallbackRecords(t *testing.T) {
	id := polisIdentity()    // polis is the Ory-only SSO front channel (dev)
	id.getUser = adminUser() // cookie→Store→UserID→GetUser resolves to a site-admin
	h, ssoState, cap := newPolisSSOHandler(t, id, MFAConfig{Mode: MFAModeNever})
	cap.accessToken = "polis-at"

	var recorded, ctxHadSiteAdmin bool
	h.IdPTestRecorder = func(ctx context.Context, _ string, success bool, _ string) error {
		recorded = true
		if c, ok := principal.FromContext(ctx); ok {
			ctxHadSiteAdmin = principal.HasRole(c, siteAdminRole)
		}
		return nil
	}

	startReq := siteAdminStartReq(t, h, "/auth/sso/start?connection=example-sso&mode=test&connectionId=conn-9&identifier=dave@example.org&tenant=example.org")
	startRec := httptest.NewRecorder()
	h.SSOStart(startRec, startReq)
	require.Equal(t, http.StatusFound, startRec.Code, startRec.Body.String())
	loc, err := url.Parse(startRec.Header().Get("Location"))
	require.NoError(t, err)
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)
	st, ok, err := ssoState.TakeSSOState(context.Background(), state)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, testAdminUserID, st.AdminUserID, "SSOStart must stash the admin's platform UserID")

	require.NoError(t, ssoState.PutSSOState(context.Background(), state, st, ssoStateTTL))

	cbReq := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=c&state="+state, nil)
	cbRec := httptest.NewRecorder()
	h.SSOCallback(cbRec, cbReq)

	requireTestResultHTML(t, cbRec, true, "https://app", "/admin/organizations?test=passed")
	require.True(t, recorded, "RecordIdPTestResult must be called on the kratos-native path")
	require.True(t, ctxHadSiteAdmin, "record ctx must carry the admin's forwarded site-admin claims")
	require.Nil(t, sessionCookie(cbRec), "test mode never issues a session")
}

// A missing/unusable email claim can never provision or link a user, so the
// callback must fail closed to /login?error=sso_no_email without a session,
// even in login mode.
func TestSSOCallback_NoEmailClaimRejected(t *testing.T) {
	id := defaultIdentity()
	h, ssoState := newSSOCallbackHandler(t, "", id, MFAConfig{Mode: MFAModeNever})
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{
		Connection: "example-sso", Mode: "login",
	}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "/login?error=sso_no_email")
	require.Nil(t, sessionCookie(rec))
	require.Nil(t, id.lastGetUserByEmail)
}

// A resolve-by-email failure must redirect to /login?error=sso_provision
// without ever issuing a session.
func TestSSOCallback_ProvisionFailureRedirects(t *testing.T) {
	id := defaultIdentity()
	id.discover = activeSSODiscover() // active connection so the flow reaches provisioning
	id.emailErr = context.DeadlineExceeded
	h, ssoState := newSSOCallbackHandler(t, "alice@example.org", id, MFAConfig{Mode: MFAModeNever})
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{
		Connection: "example-sso", Mode: "login",
	}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "/login?error=sso_provision")
	require.Nil(t, sessionCookie(rec))
}
