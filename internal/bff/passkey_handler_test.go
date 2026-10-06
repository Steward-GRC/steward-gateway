// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// fakePasskeyClient satisfies BOTH authClient (via the embedded fakeAuthClient)
// and passkeyAuthClient, so it can stand in for a *KratosClient behind
// Handler.Auth and be type-asserted by Handler.passkeyClient.
type fakePasskeyClient struct {
	fakeAuthClient
	beginResult  PasskeyLoginResult
	beginErr     error
	finishResult AuthResult
	finishErr    error

	lastFinishFlow    string
	lastFinishCred    string
	lastFinishCSRF    string
	lastFinishCookies map[string]string
}

func (f *fakePasskeyClient) PasskeyLoginBegin(context.Context) (PasskeyLoginResult, error) {
	return f.beginResult, f.beginErr
}

func (f *fakePasskeyClient) PasskeyLoginFinish(_ context.Context, flowID, cred, csrf string, cookies map[string]string) (AuthResult, error) {
	f.lastFinishFlow, f.lastFinishCred, f.lastFinishCSRF, f.lastFinishCookies = flowID, cred, csrf, cookies
	return f.finishResult, f.finishErr
}

// defaultBeginResult is a viable begin outcome: a Kratos browser flow with a
// challenge, csrf token, and flow cookie.
func defaultBeginResult() PasskeyLoginResult {
	return PasskeyLoginResult{
		FlowID:      "flow-kratos",
		OptionsJSON: passkeyOptionsJSON,
		CSRFToken:   "csrf-body-tok",
		Cookies:     map[string]string{"csrf_token_login": "csrf-cookie-val"},
	}
}

// newPasskeyHandler builds a kratos-backend Handler wired with the given passkey
// client and identity fake, plus the one-shot passkey-login ceremony store.
func newPasskeyHandler(t *testing.T, pk *fakePasskeyClient, id *fakeMfaIdentity) *Handler {
	t.Helper()
	st := newTestStore(t)
	return &Handler{
		Store:        st,
		Pending:      st,
		PasskeyLogin: st,
		Auth:         pk,
		TTL:          time.Hour,
		Identity:     id,
		MFA:          edgeCfg(),
	}
}

func postJSONReq(path string, body any, hdr map[string]string) *http.Request {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

// beginTicket runs the begin endpoint and returns the opaque one-shot ticket the
// browser would echo on finish.
func beginTicket(t *testing.T, h *Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.PasskeyLoginBegin(rec, postJSONReq("/auth/passkey/login/begin", map[string]any{}, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("begin: want 200, got %d %s", rec.Code, rec.Body)
	}
	var raw map[string]string
	decodeInto(t, rec, &raw)
	if raw["flowId"] == "" {
		t.Fatalf("begin returned no flowId ticket: %+v", raw)
	}
	return raw["flowId"]
}

// TestPasskeyBegin_ReturnsChallenge proves the begin endpoint returns the options
// and an OPAQUE ticket (not the raw Kratos flow id), and parks the Kratos flow
// id + csrf + cookies server-side for finish.
func TestPasskeyBegin_ReturnsChallenge(t *testing.T) {
	pk := &fakePasskeyClient{beginResult: defaultBeginResult()}
	h := newPasskeyHandler(t, pk, &fakeMfaIdentity{})

	rec := httptest.NewRecorder()
	h.PasskeyLoginBegin(rec, postJSONReq("/auth/passkey/login/begin", map[string]any{}, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body)
	}
	var raw map[string]string
	decodeInto(t, rec, &raw)
	if raw["optionsJson"] != passkeyOptionsJSON {
		t.Fatalf("bad options: %+v", raw)
	}
	ticket := raw["flowId"]
	if ticket == "" || ticket == "flow-kratos" {
		t.Fatalf("flowId must be an opaque ticket, not the raw kratos flow id: %q", ticket)
	}
	flow, ok, err := h.PasskeyLogin.ConsumePasskeyLogin(context.Background(), ticket)
	if err != nil || !ok {
		t.Fatalf("ticket not parked: ok=%v err=%v", ok, err)
	}
	if flow.KratosFlowID != "flow-kratos" || flow.CSRFToken != "csrf-body-tok" || flow.Cookies["csrf_token_login"] != "csrf-cookie-val" {
		t.Fatalf("parked flow state wrong: %+v", flow)
	}
}

// An auth client without passkey support fails closed with 404.
func TestPasskeyBegin_NoPasskeySupport_404(t *testing.T) {
	st := newTestStore(t)
	h := &Handler{Store: st, Pending: st, PasskeyLogin: st, Auth: okAuth(), TTL: time.Hour}

	rec := httptest.NewRecorder()
	h.PasskeyLoginBegin(rec, postJSONReq("/auth/passkey/login/begin", map[string]any{}, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 without passkey support, got %d %s", rec.Code, rec.Body)
	}
}

// TestPasskeyBegin_KratosUnreachable_502 proves a client error surfaces as a
// 502, no ticket parked.
func TestPasskeyBegin_KratosUnreachable_502(t *testing.T) {
	pk := &fakePasskeyClient{beginErr: context.DeadlineExceeded}
	h := newPasskeyHandler(t, pk, &fakeMfaIdentity{})

	rec := httptest.NewRecorder()
	h.PasskeyLoginBegin(rec, postJSONReq("/auth/passkey/login/begin", map[string]any{}, nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d %s", rec.Code, rec.Body)
	}
}

// TestPasskeyFinish_Valid_IssuesSessionNoMFA is the core proof: a Kratos-
// verified passkey assertion issues the steward_sid session directly — WITH a
// cookie + csrf, marked MFAVerified — even at the PUBLIC edge, with NO
// mfaRequired/loginWithMFA step. The strong factor stands alone. It also proves
// the ticket is resolved to the Kratos flow and its csrf/cookies are replayed.
func TestPasskeyFinish_Valid_IssuesSessionNoMFA(t *testing.T) {
	id := &fakeMfaIdentity{user: &identityv1.User{Id: "u-pk-1", Enabled: true}}
	pk := &fakePasskeyClient{
		beginResult: defaultBeginResult(),
		finishResult: AuthResult{
			AccessToken: "kratos-sess", ExpiresAt: time.Now().Add(time.Hour), Email: "alice@example.net",
		},
	}
	h := newPasskeyHandler(t, pk, id)
	ticket := beginTicket(t, h)

	rec := httptest.NewRecorder()
	h.PasskeyLoginFinish(rec, postJSONReq("/auth/passkey/login/finish",
		map[string]string{"flowId": ticket, "credentialJson": "{assertion}"}, publicEdge()))

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body)
	}
	out := decodeLogin(t, rec)
	if out.CSRFToken == "" {
		t.Fatal("expected a csrf token (session issued)")
	}
	if out.MFARequired || out.PendingID != "" {
		t.Fatalf("passkey login must NOT enter the MFA step: %+v", out)
	}
	c := sessionCookie(rec)
	if c == nil || c.Value == "" {
		t.Fatal("expected a steward_sid session cookie")
	}
	if pk.lastFinishFlow != "flow-kratos" || pk.lastFinishCred != "{assertion}" {
		t.Fatalf("finish not called with the resolved flow/credential: %q %q", pk.lastFinishFlow, pk.lastFinishCred)
	}
	if pk.lastFinishCSRF != "csrf-body-tok" || pk.lastFinishCookies["csrf_token_login"] != "csrf-cookie-val" {
		t.Fatalf("finish did not replay the begin csrf/cookies: %q %+v", pk.lastFinishCSRF, pk.lastFinishCookies)
	}
	sess, ok, err := h.Store.Get(context.Background(), c.Value)
	if err != nil || !ok {
		t.Fatalf("session missing: ok=%v err=%v", ok, err)
	}
	if sess.UserID != "u-pk-1" {
		t.Fatalf("session UserID = %q, want u-pk-1", sess.UserID)
	}
	if !sess.MFAVerified {
		t.Fatal("passkey session must be marked MFAVerified")
	}
	if sess.AccessToken != "kratos-sess" {
		t.Fatalf("session AccessToken = %q, want the kratos session_token", sess.AccessToken)
	}
}

// TestPasskeyFinish_TicketSingleUse proves the ticket is single-use: a second
// finish with the same ticket is a 400 invalid_request (never a replayed login).
func TestPasskeyFinish_TicketSingleUse(t *testing.T) {
	id := &fakeMfaIdentity{user: &identityv1.User{Id: "u-pk-1", Enabled: true}}
	pk := &fakePasskeyClient{
		beginResult:  defaultBeginResult(),
		finishResult: AuthResult{AccessToken: "s", ExpiresAt: time.Now().Add(time.Hour), Email: "alice@example.net"},
	}
	h := newPasskeyHandler(t, pk, id)
	ticket := beginTicket(t, h)

	rec := httptest.NewRecorder()
	h.PasskeyLoginFinish(rec, postJSONReq("/auth/passkey/login/finish",
		map[string]string{"flowId": ticket, "credentialJson": "{a}"}, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("first finish: want 200, got %d %s", rec.Code, rec.Body)
	}
	rec2 := httptest.NewRecorder()
	h.PasskeyLoginFinish(rec2, postJSONReq("/auth/passkey/login/finish",
		map[string]string{"flowId": ticket, "credentialJson": "{a}"}, nil))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("replayed ticket: want 400, got %d %s", rec2.Code, rec2.Body)
	}
}

// TestPasskeyFinish_UnknownTicket_400 proves a finish with a ticket that was
// never begun (or expired) is a 400, no cookie.
func TestPasskeyFinish_UnknownTicket_400(t *testing.T) {
	pk := &fakePasskeyClient{beginResult: defaultBeginResult()}
	h := newPasskeyHandler(t, pk, &fakeMfaIdentity{user: &identityv1.User{Id: "u", Enabled: true}})

	rec := httptest.NewRecorder()
	h.PasskeyLoginFinish(rec, postJSONReq("/auth/passkey/login/finish",
		map[string]string{"flowId": "never-begun", "credentialJson": "{a}"}, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for an unknown ticket, got %d %s", rec.Code, rec.Body)
	}
	if sessionCookie(rec) != nil {
		t.Fatal("no cookie for an unknown ticket")
	}
}

// TestPasskeyFinish_RejectedAssertion_401 proves a rejected assertion fails
// closed: 401 invalid_credentials, no cookie.
func TestPasskeyFinish_RejectedAssertion_401(t *testing.T) {
	pk := &fakePasskeyClient{beginResult: defaultBeginResult(), finishErr: ErrInvalidCredentials}
	h := newPasskeyHandler(t, pk, &fakeMfaIdentity{user: &identityv1.User{Id: "u", Enabled: true}})
	ticket := beginTicket(t, h)

	rec := httptest.NewRecorder()
	h.PasskeyLoginFinish(rec, postJSONReq("/auth/passkey/login/finish",
		map[string]string{"flowId": ticket, "credentialJson": "{forged}"}, publicEdge()))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d %s", rec.Code, rec.Body)
	}
	if decodeLogin(t, rec).Error != "invalid_credentials" {
		t.Fatalf("want invalid_credentials, got %s", rec.Body)
	}
	if sessionCookie(rec) != nil {
		t.Fatal("no cookie on a rejected assertion")
	}
}

// TestPasskeyFinish_NoPlatformUser_401 proves a Kratos-verified email with no
// matching platform user is the SAME generic 401, not a 500/502 — and no cookie.
func TestPasskeyFinish_NoPlatformUser_401(t *testing.T) {
	id := &fakeMfaIdentity{} // GetUserByEmail answers NotFound
	pk := &fakePasskeyClient{
		beginResult:  defaultBeginResult(),
		finishResult: AuthResult{AccessToken: "s", ExpiresAt: time.Now().Add(time.Hour), Email: "nobody@example.net"},
	}
	h := newPasskeyHandler(t, pk, id)
	ticket := beginTicket(t, h)

	rec := httptest.NewRecorder()
	h.PasskeyLoginFinish(rec, postJSONReq("/auth/passkey/login/finish",
		map[string]string{"flowId": ticket, "credentialJson": "{a}"}, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d %s", rec.Code, rec.Body)
	}
	if sessionCookie(rec) != nil {
		t.Fatal("no cookie when there is no platform user")
	}
}

// TestPasskeyFinish_DisabledUser_401 proves a disabled platform user fails
// closed with the generic 401.
func TestPasskeyFinish_DisabledUser_401(t *testing.T) {
	id := &fakeMfaIdentity{user: &identityv1.User{Id: "u", Enabled: false}}
	pk := &fakePasskeyClient{
		beginResult:  defaultBeginResult(),
		finishResult: AuthResult{AccessToken: "s", ExpiresAt: time.Now().Add(time.Hour), Email: "alice@example.net"},
	}
	h := newPasskeyHandler(t, pk, id)
	ticket := beginTicket(t, h)

	rec := httptest.NewRecorder()
	h.PasskeyLoginFinish(rec, postJSONReq("/auth/passkey/login/finish",
		map[string]string{"flowId": ticket, "credentialJson": "{a}"}, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for disabled user, got %d %s", rec.Code, rec.Body)
	}
	if sessionCookie(rec) != nil {
		t.Fatal("no cookie for a disabled user")
	}
}

// TestPasskeyFinish_IdentityUnreachable_502 distinguishes a genuine identity
// blip (502) from the clean 401 no-user verdict.
func TestPasskeyFinish_IdentityUnreachable_502(t *testing.T) {
	id := &fakeMfaIdentity{emailErr: context.DeadlineExceeded}
	pk := &fakePasskeyClient{
		beginResult:  defaultBeginResult(),
		finishResult: AuthResult{AccessToken: "s", ExpiresAt: time.Now().Add(time.Hour), Email: "alice@example.net"},
	}
	h := newPasskeyHandler(t, pk, id)
	ticket := beginTicket(t, h)

	rec := httptest.NewRecorder()
	h.PasskeyLoginFinish(rec, postJSONReq("/auth/passkey/login/finish",
		map[string]string{"flowId": ticket, "credentialJson": "{a}"}, nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d %s", rec.Code, rec.Body)
	}
}

// TestPasskeyFinish_MalformedRequest_400 proves a missing flowId/credentialJson
// is a 400 (never a credential guess), no cookie.
func TestPasskeyFinish_MalformedRequest_400(t *testing.T) {
	pk := &fakePasskeyClient{beginResult: defaultBeginResult()}
	h := newPasskeyHandler(t, pk, &fakeMfaIdentity{})

	for _, body := range []map[string]string{
		{"credentialJson": "{a}"}, // missing flowId
		{"flowId": "flow-1"},      // missing credentialJson
		{},                        // both missing
	} {
		rec := httptest.NewRecorder()
		h.PasskeyLoginFinish(rec, postJSONReq("/auth/passkey/login/finish", body, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for %+v, got %d %s", body, rec.Code, rec.Body)
		}
	}
}

func TestPasskeyFinish_NoPasskeySupport_404(t *testing.T) {
	st := newTestStore(t)
	h := &Handler{Store: st, Pending: st, PasskeyLogin: st, Auth: okAuth(), TTL: time.Hour}

	rec := httptest.NewRecorder()
	h.PasskeyLoginFinish(rec, postJSONReq("/auth/passkey/login/finish",
		map[string]string{"flowId": "flow-1", "credentialJson": "{a}"}, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 without passkey support, got %d %s", rec.Code, rec.Body)
	}
}
