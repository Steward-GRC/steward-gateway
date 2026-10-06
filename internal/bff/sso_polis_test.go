// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// polisIdentity is defaultIdentity plus an email-resolvable user, since the
// polis SSO path resolves the platform user by email (GetUserByEmail), never
// by decoding a token sub. Discover is stubbed to an ACTIVE sso verdict for the
// example-sso connection so the login-mode active gate (SSOStart) and the callback's
// defense-in-depth active check (ssoCallbackPolis) — both reuse identity Discover
// — resolve to active on the happy path.
func polisIdentity() *fakeMfaIdentity {
	id := defaultIdentity()
	id.user = &identityv1.User{Id: "u1", Enabled: true}
	id.discover = &identityv1.DiscoverResponse{Method: "sso", ConnectionAlias: "example-sso"}
	return id
}

// newPolisSSOHandler wires a polis-backed SSO Handler: session/pending stores,
// a fresh SSOStateStore, the identity fake, and a PolisClient whose
// token/userinfo point at a fake Jackson.
func newPolisSSOHandler(t *testing.T, id *fakeMfaIdentity, cfg MFAConfig) (*Handler, SSOStateStore, *polisCapture) {
	t.Helper()
	st := newTestStore(t)
	ssoState := newTestStore(t)
	cap := &polisCapture{}
	srv := newPolisServer(t, cap)
	h := &Handler{
		Store:           st,
		Pending:         st,
		Polis:           NewPolisClient("https://edge/sso", srv.URL, "steward"),
		TTL:             time.Hour,
		Identity:        id,
		MFA:             cfg,
		SSOState:        ssoState,
		SSORedirectBase: "https://app",
	}
	return h, ssoState, cap
}

// SP-initiated start under polis derives the tenant from the identifier's email
// domain and 302s to Jackson's public authorize endpoint with tenant+product;
// the parked state carries the tenant.
func TestSSOStart_Polis_AuthorizeURLHasTenantAndProduct(t *testing.T) {
	h := &Handler{
		Polis:           NewPolisClient("https://edge/sso", "http://unused", "steward"),
		SSOState:        newTestStore(t),
		SSORedirectBase: "https://app",
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso&identifier=alice@example.org", nil)
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "edge", loc.Host)
	require.Equal(t, "/sso/api/oauth/authorize", loc.Path)
	q := loc.Query()
	require.Equal(t, "example.org", q.Get("tenant"))
	require.Equal(t, "steward", q.Get("product"))
	require.NotEmpty(t, q.Get("state"))
	require.NotContains(t, rec.Header().Get("Location"), "kc_idp_hint")

	got, ok, err := h.SSOState.TakeSSOState(req.Context(), q.Get("state"))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "example.org", got.Tenant)
	require.Equal(t, "example-sso", got.Connection)
}

// An explicit ?tenant= param wins over the identifier's email domain.
func TestSSOStart_Polis_ExplicitTenantWins(t *testing.T) {
	h := &Handler{
		Polis:           NewPolisClient("https://edge/sso", "http://unused", "steward"),
		SSOState:        newTestStore(t),
		SSORedirectBase: "https://app",
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso&identifier=alice@example.net&tenant=Chosen.Example", nil)
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	require.Equal(t, "chosen.example", loc.Query().Get("tenant"))
}

// Login-mode start under polis with no derivable tenant fails closed to /login
// (Jackson cannot select a connection without a tenant).
func TestSSOStart_Polis_MissingTenantLoginRedirects(t *testing.T) {
	h := &Handler{
		Polis:           NewPolisClient("https://edge/sso", "http://unused", "steward"),
		SSOState:        newTestStore(t),
		SSORedirectBase: "https://app",
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso", nil) // no identifier/tenant
	rec := httptest.NewRecorder()
	h.SSOStart(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/login?error=sso", rec.Header().Get("Location"))
}

// Happy path (no MFA): exchange → userinfo → resolve by email → issue session,
// redirect /home, and stamp the resolved UserID onto the session.
func TestSSOCallback_Polis_HappyPathIssuesSession(t *testing.T) {
	id := polisIdentity()
	h, ssoState, cap := newPolisSSOHandler(t, id, edgeCfg())
	cap.accessToken, cap.refreshToken = "polis-at", "polis-rt"
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{
		Connection: "example-sso", Tenant: "example.org", Mode: "login",
	}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.Equal(t, "/home", rec.Header().Get("Location"))
	c := sessionCookie(rec)
	require.NotNil(t, c)
	sess, ok, err := h.Store.Get(context.Background(), c.Value)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "polis-at", sess.AccessToken)
	require.Equal(t, "u1", sess.UserID)
}

// Resolution is BY EMAIL (userinfo), never by a token sub: GetUserByEmail is
// called with the userinfo email and ResolveClaims is never touched.
func TestSSOCallback_Polis_ResolvesByEmailNotSub(t *testing.T) {
	id := polisIdentity()
	h, ssoState, _ := newPolisSSOHandler(t, id, edgeCfg())
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Tenant: "example.org", Mode: "login"}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	require.NotNil(t, id.lastGetUserByEmail)
	require.Equal(t, "alice@example.org", id.lastGetUserByEmail.GetEmail())
}

// A first-seen email (GetUserByEmail NotFound) is JIT-PROVISIONED by email —
// the userinfo email/first/last + the stored connection alias are forwarded to
// JitProvisionByEmail — and the login proceeds to a session (SSO JIT closes the
// last SP-init blocker; JIT-by-email is no longer deferred).
func TestSSOCallback_Polis_UnknownEmailJITProvisionsAndIssuesSession(t *testing.T) {
	id := polisIdentity()
	id.user = nil // GetUserByEmail → NotFound, forcing the JIT path
	id.jitUser = &identityv1.User{Id: "u-jit", Enabled: true}
	h, ssoState, cap := newPolisSSOHandler(t, id, edgeCfg())
	cap.accessToken, cap.refreshToken = "polis-at", "polis-rt"
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{
		Connection: "example-sso", Tenant: "example.org", Mode: "login",
	}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.NotNil(t, id.lastJitProvisionByEmail, "a first-seen email must trigger JIT-by-email")
	require.Equal(t, "alice@example.org", id.lastJitProvisionByEmail.GetEmail())
	require.Equal(t, "Alice", id.lastJitProvisionByEmail.GetFirstName())
	require.Equal(t, "Anderson", id.lastJitProvisionByEmail.GetLastName())
	require.Equal(t, "example-sso", id.lastJitProvisionByEmail.GetConnectionAlias())
	require.Empty(t, id.lastJitProvisionByEmail.GetIdpGroups(), "polis userinfo carries no groups")

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.Equal(t, "/home", rec.Header().Get("Location"))
	c := sessionCookie(rec)
	require.NotNil(t, c)
	sess, ok, err := h.Store.Get(context.Background(), c.Value)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "u-jit", sess.UserID)
}

// A JIT RPC failure (identity errored while provisioning) is a GENUINE error:
// fail closed to /login?error=sso_error with no session.
func TestSSOCallback_Polis_JITErrorFailsClosed(t *testing.T) {
	id := polisIdentity()
	id.user = nil // NotFound → JIT path
	id.jitErr = status.Error(codes.Unavailable, "identity down")
	h, ssoState, _ := newPolisSSOHandler(t, id, edgeCfg())
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Tenant: "example.org", Mode: "login"}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/login?error=sso_error", rec.Header().Get("Location"))
	require.Nil(t, sessionCookie(rec))
}

// An EXISTING platform user is returned unchanged — JIT is never invoked.
func TestSSOCallback_Polis_ExistingUserNoJIT(t *testing.T) {
	id := polisIdentity() // user set → GetUserByEmail resolves
	h, ssoState, _ := newPolisSSOHandler(t, id, edgeCfg())
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Tenant: "example.org", Mode: "login"}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	require.Nil(t, id.lastJitProvisionByEmail, "an existing user must never trigger JIT-by-email")
	require.NotNil(t, sessionCookie(rec))
}

// MFA step-up (strong factor present): the callback is a full-page browser
// navigation, so it REDIRECTS the browser into the SPA's MFA route carrying the
// pending id — never JSON, never a session. A user WITH a strong
// factor does a normal step-up: NO email OTP is sent.
func TestSSOCallback_Polis_MFAStepUp(t *testing.T) {
	id := polisIdentity() // factors totp+email → strong factor present
	h, ssoState, _ := newPolisSSOHandler(t, id, MFAConfig{Mode: MFAModeAlways})
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Tenant: "example.org", Mode: "login"}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	pendingID, factors := mfaRedirect(t, rec)
	require.ElementsMatch(t, []string{"totp", "email"}, factors)
	require.Nil(t, id.lastSend, "a strong-factor step-up must not send an email OTP")
	require.Equal(t, "alice@example.org", id.lastGetUserByEmail.GetEmail())
	p, ok, err := h.Pending.GetPending(context.Background(), pendingID)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "u1", p.UserID, "polis pending must be keyed to the email-resolved user")
	require.False(t, p.Enroll)
}

// gateway#59, the PROD path: a public-edge Polis SSO login for a user with NO
// strong factor (email-only — exactly the pyaraki/krobertson state) must send a
// login-purpose email OTP to the SSO-verified account email AND redirect the
// browser into the SPA MFA route with the pending id — NO session yet. Only
// completing the email OTP mints the session. This is the whole regression: the
// old code answered JSON on a browser navigation and the user progressed with no
// verified factor.
func TestSSOCallback_Polis_PublicEdge_NoStrongFactor_EmailOtpThenVerify(t *testing.T) {
	id := polisIdentity()
	id.factors = []string{"email"} // implicit email only, no TOTP/passkey
	id.emailOK = true
	h, ssoState, _ := newPolisSSOHandler(t, id, edgeCfg()) // edge mode: the public header decides
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Tenant: "example.org", Mode: "login"}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReqPublicEdge("st1"))

	pendingID, factors := mfaRedirect(t, rec)
	require.Equal(t, []string{"email"}, factors)
	require.NotNil(t, id.lastSend, "a no-strong-factor SSO login must send an email OTP")
	require.Equal(t, "u1", id.lastSend.GetUserId())
	require.Equal(t, "login", id.lastSend.GetPurpose())

	vrec := verifyReq(t, h, map[string]string{"pendingId": pendingID, "kind": "email", "code": "654321"})
	require.Equal(t, http.StatusOK, vrec.Code, vrec.Body.String())
	c := sessionCookie(vrec)
	require.NotNil(t, c)
	sess, ok, err := h.Store.Get(context.Background(), c.Value)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, sess.MFAVerified)
	require.Equal(t, "u1", sess.UserID)
	require.Equal(t, "login", id.lastVerifyEmail.GetPurpose())
}

// Internal-edge Polis SSO (no public-edge header, MFAModeEdge) is UNCHANGED: no
// MFA, a session is minted directly and the browser lands on /home. This guards
// the "internal edge unchanged" invariant alongside the public-edge fix above.
func TestSSOCallback_Polis_InternalEdge_NoMFAIssuesSession(t *testing.T) {
	id := polisIdentity()
	h, ssoState, cap := newPolisSSOHandler(t, id, edgeCfg()) // edge mode, no public header below
	cap.accessToken, cap.refreshToken = "polis-at", "polis-rt"
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Tenant: "example.org", Mode: "login"}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1")) // no X-Steward-Edge header → internal

	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/home", rec.Header().Get("Location"))
	require.Nil(t, id.lastSend, "internal edge must not send an email OTP")
	c := sessionCookie(rec)
	require.NotNil(t, c, "internal edge mints a session directly, no MFA")
	sess, ok, err := h.Store.Get(context.Background(), c.Value)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "u1", sess.UserID)
}

// A CodeExchange failure (Jackson unreachable) redirects /login?error=sso_exchange.
func TestSSOCallback_Polis_ExchangeFailureRedirects(t *testing.T) {
	id := polisIdentity()
	ssoState := newTestStore(t)
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Tenant: "example.org", Mode: "login"}, ssoStateTTL))
	h := &Handler{
		Polis:           NewPolisClient("https://edge/sso", "http://127.0.0.1:1", "steward"), // nothing listens
		Identity:        id,
		SSOState:        ssoState,
		SSORedirectBase: "https://app",
	}
	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/login?error=sso_exchange", rec.Header().Get("Location"))
	require.Nil(t, sessionCookie(rec))
}

// Test-connection probe under polis: exchange+userinfo succeed, the outcome is
// recorded via RecordIdPTestResult against the initiating admin's context, and
// NO session is issued.
func TestSSOCallback_Polis_TestModeRecordsAndNoSession(t *testing.T) {
	id := polisIdentity()
	id.getUser = adminUser() // callback re-resolves the admin by the stashed UserID
	h, ssoState, _ := newPolisSSOHandler(t, id, MFAConfig{Mode: MFAModeNever})
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{
		Connection: "example-sso", Tenant: "example.org", Mode: "test", ConnectionID: "conn-9",
		AdminUserID: testAdminUserID,
	}, ssoStateTTL))

	var recordedOK, recorded bool
	h.IdPTestRecorder = func(_ context.Context, _ string, success bool, _ string) error {
		recorded, recordedOK = true, success
		return nil
	}

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	requireTestResultHTML(t, rec, true, "https://app", "/admin/organizations?test=passed")
	require.True(t, recorded)
	require.True(t, recordedOK)
	require.Nil(t, sessionCookie(rec), "test mode must never issue a session")
}

// IdP-initiated under polis: SSOIdpInitiated 302s to Jackson's authorize with
// an empty-Connection login state; the callback then resolves purely by the
// userinfo email (it needs no stored Connection).
func TestSSOIdpInitiated_Polis_RedirectsAndCallbackResolvesByEmail(t *testing.T) {
	id := polisIdentity()
	h, ssoState, _ := newPolisSSOHandler(t, id, edgeCfg())

	initReq := httptest.NewRequest(http.MethodPost, "/auth/sso/idp-initiated", nil)
	initRec := httptest.NewRecorder()
	h.SSOIdpInitiated(initRec, initReq)
	require.Equal(t, http.StatusFound, initRec.Code)
	loc, err := url.Parse(initRec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/sso/api/oauth/authorize", loc.Path)
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)
	got, ok, err := ssoState.TakeSSOState(context.Background(), state)
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, got.Connection, "idp-initiated state carries no connection")

	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Mode: "login"}, ssoStateTTL))
	cbRec := httptest.NewRecorder()
	h.SSOCallback(cbRec, ssoCallbackReq("st1"))
	require.Equal(t, http.StatusFound, cbRec.Code)
	require.Equal(t, "/home", cbRec.Header().Get("Location"))
	require.NotNil(t, sessionCookie(cbRec))
}

// gateway#47 (SECURITY): a polis IdP-initiated login for an INACTIVE connection
// (Discover does not return method=sso for the userinfo email) is rejected at the
// callback — no session — the same defense-in-depth as the KC path.
func TestSSOCallback_Polis_IdpInit_InactiveRejected(t *testing.T) {
	id := polisIdentity()
	id.discover = &identityv1.DiscoverResponse{Method: "local"} // NOT an active sso verdict
	h, ssoState, _ := newPolisSSOHandler(t, id, edgeCfg())
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Mode: "login"}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/login?error=sso_not_active", rec.Header().Get("Location"))
	require.Nil(t, sessionCookie(rec), "an inactive connection must never mint a session")
}
