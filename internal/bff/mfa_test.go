// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("bad json %q: %v", rec.Body, err)
	}
}

func newMfaHandler(t *testing.T, auth authClient, id *fakeMfaIdentity, cfg MFAConfig) *Handler {
	t.Helper()
	st := newTestStore(t)
	return &Handler{
		Store:    st,
		Pending:  st,
		Auth:     auth,
		TTL:      time.Hour,
		Identity: id,
		MFA:      cfg,
	}
}

func edgeCfg() MFAConfig { return MFAConfig{Mode: MFAModeEdge} }

func doLogin(t *testing.T, h *Handler, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "good"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	return rec
}

type loginOut struct {
	CSRFToken          string   `json:"csrfToken"`
	MFARequired        bool     `json:"mfaRequired"`
	EnrollmentRequired bool     `json:"enrollmentRequired"`
	PendingID          string   `json:"pendingId"`
	Factors            []string `json:"factors"`
	Error              string   `json:"error"`
}

func decodeLogin(t *testing.T, rec *httptest.ResponseRecorder) loginOut {
	t.Helper()
	var out loginOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json %q: %v", rec.Body, err)
	}
	return out
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			return c
		}
	}
	return nil
}

func defaultIdentity() *fakeMfaIdentity {
	return &fakeMfaIdentity{
		user:    &identityv1.User{Id: "u1", Enabled: true},
		factors: []string{"totp", "email"},
	}
}

func publicEdge() map[string]string { return map[string]string{"X-Steward-Edge": "public"} }

// mfaLogin performs a public-edge login expected to yield a pending id.
func mfaLogin(t *testing.T, h *Handler) string {
	t.Helper()
	rec := doLogin(t, h, publicEdge())
	out := decodeLogin(t, rec)
	if rec.Code != 200 || !out.MFARequired || out.PendingID == "" {
		t.Fatalf("expected mfa-pending login, got code=%d %+v", rec.Code, out)
	}
	return out.PendingID
}

func postJSON(t *testing.T, fn http.HandlerFunc, path string, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	fn(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b)))
	return rec
}

func verifyReq(t *testing.T, h *Handler, body map[string]string) *httptest.ResponseRecorder {
	return postJSON(t, h.MfaVerify, "/auth/mfa/verify", body)
}

func TestLogin_EdgeMode_PublicEdge_PendingNoCookie(t *testing.T) {
	id := defaultIdentity()
	h := newMfaHandler(t, okAuth(), id, edgeCfg())

	rec := doLogin(t, h, publicEdge())
	out := decodeLogin(t, rec)

	if rec.Code != 200 || !out.MFARequired || out.PendingID == "" {
		t.Fatalf("want 200 mfaRequired+pendingId, got code=%d %+v", rec.Code, out)
	}
	if out.EnrollmentRequired {
		t.Fatal("enrollmentRequired must be false when factors exist")
	}
	if len(out.Factors) != 2 || out.Factors[0] != "totp" || out.Factors[1] != "email" {
		t.Fatalf("factors passthrough wrong: %v", out.Factors)
	}
	if out.CSRFToken != "" {
		t.Fatal("no csrf token before the factor is verified")
	}
	if c := sessionCookie(rec); c != nil {
		t.Fatalf("no session cookie may be issued pre-factor, got %+v", c)
	}
	p, ok, err := h.Pending.GetPending(context.Background(), out.PendingID)
	if err != nil || !ok {
		t.Fatalf("pending record missing: ok=%v err=%v", ok, err)
	}
	if p.AccessToken != testSessionToken || p.UserID != "u1" || p.Attempts != 0 {
		t.Fatalf("bad pending record: %+v", p)
	}
	if id.lastGetUserByEmail.GetEmail() != "alice@example.org" {
		t.Fatalf("bad GetUserByEmail request: %+v", id.lastGetUserByEmail)
	}
	if id.lastFactors.GetUserId() != "u1" {
		t.Fatalf("ListUserFactors keyed wrong: %+v", id.lastFactors)
	}
}

func TestLogin_EdgeMode_InternalEdge_CookieImmediately(t *testing.T) {
	for _, hdr := range []map[string]string{nil, {"X-Steward-Edge": "internal"}} {
		id := defaultIdentity()
		h := newMfaHandler(t, okAuth(), id, edgeCfg())

		rec := doLogin(t, h, hdr)
		out := decodeLogin(t, rec)
		if rec.Code != 200 || out.CSRFToken == "" || out.MFARequired {
			t.Fatalf("hdr=%v want legacy cookie login, got code=%d %+v", hdr, rec.Code, out)
		}
		c := sessionCookie(rec)
		if c == nil || c.Value == "" {
			t.Fatalf("hdr=%v want session cookie, got %+v", hdr, c)
		}
		sess, ok, _ := h.Store.Get(context.Background(), c.Value)
		if !ok || sess.MFAVerified {
			t.Fatalf("hdr=%v session should exist without mfa marker: ok=%v %+v", hdr, ok, sess)
		}
		if id.lastFactors != nil {
			t.Fatalf("hdr=%v factors must not be consulted on the internal edge", hdr)
		}
	}
}

func TestLogin_AlwaysMode_ForcesFactorWithoutHeader(t *testing.T) {
	id := defaultIdentity()
	h := newMfaHandler(t, okAuth(), id, MFAConfig{Mode: MFAModeAlways})

	rec := doLogin(t, h, nil) // no edge header at all
	out := decodeLogin(t, rec)
	if rec.Code != 200 || !out.MFARequired || out.PendingID == "" {
		t.Fatalf("always mode must force the factor, got code=%d %+v", rec.Code, out)
	}
	if sessionCookie(rec) != nil {
		t.Fatal("no cookie in always mode before the factor")
	}
}

func TestLogin_NeverMode_LegacyEvenOnPublicEdge(t *testing.T) {
	id := defaultIdentity()
	h := newMfaHandler(t, okAuth(), id, MFAConfig{Mode: MFAModeNever})

	rec := doLogin(t, h, publicEdge())
	out := decodeLogin(t, rec)
	if rec.Code != 200 || out.CSRFToken == "" || out.MFARequired {
		t.Fatalf("never mode must keep legacy behavior, got code=%d %+v", rec.Code, out)
	}
	if sessionCookie(rec) == nil {
		t.Fatal("never mode must issue the cookie immediately")
	}
}

func TestLogin_EnrollmentRequired_WhenNoFactors(t *testing.T) {
	id := defaultIdentity()
	id.factors = nil
	h := newMfaHandler(t, okAuth(), id, edgeCfg())

	rec := doLogin(t, h, publicEdge())
	out := decodeLogin(t, rec)
	if rec.Code != 200 || !out.MFARequired || !out.EnrollmentRequired {
		t.Fatalf("want mfaRequired+enrollmentRequired, got code=%d %+v", rec.Code, out)
	}
	if out.PendingID == "" {
		t.Fatalf("enrollment must return a pending id: %+v", out)
	}
	if out.CSRFToken != "" || sessionCookie(rec) != nil {
		t.Fatalf("no cookie/csrf until a factor is enrolled: %+v", out)
	}
	p, ok, _ := h.Pending.GetPending(context.Background(), out.PendingID)
	if !ok || !p.Enroll {
		t.Fatalf("expected an Enroll pending, ok=%v enroll=%v", ok, p.Enroll)
	}
}

// RequireStrong: an email-only user on an enforcing edge is forced to enroll a
// STRONG factor (email is implicit and does not satisfy the policy).
func TestLogin_RequireStrong_EmailOnly_ForcesEnrollment(t *testing.T) {
	id := defaultIdentity()
	id.factors = []string{"email"} // implicit-only
	h := newMfaHandler(t, okAuth(), id, MFAConfig{Mode: MFAModeEdge, RequireStrong: true})

	out := decodeLogin(t, doLogin(t, h, publicEdge()))
	if !out.MFARequired || !out.EnrollmentRequired || out.PendingID == "" {
		t.Fatalf("email-only + require-strong must force enrollment, got %+v", out)
	}
}

// RequireStrong: a user WITH a strong factor gets a normal challenge, not enroll.
func TestLogin_RequireStrong_WithStrongFactor_Challenges(t *testing.T) {
	id := defaultIdentity()
	id.factors = []string{"totp", "email"}
	h := newMfaHandler(t, okAuth(), id, MFAConfig{Mode: MFAModeEdge, RequireStrong: true})

	out := decodeLogin(t, doLogin(t, h, publicEdge()))
	if !out.MFARequired || out.EnrollmentRequired {
		t.Fatalf("a strong factor must yield a challenge, not enrollment, got %+v", out)
	}
}

// Without RequireStrong (DEV default), email alone satisfies public access —
// the user gets an email-OTP challenge, never forced enrollment.
func TestLogin_NoRequireStrong_EmailOnly_Challenges(t *testing.T) {
	id := defaultIdentity()
	id.factors = []string{"email"}
	h := newMfaHandler(t, okAuth(), id, edgeCfg())

	out := decodeLogin(t, doLogin(t, h, publicEdge()))
	if !out.MFARequired || out.EnrollmentRequired {
		t.Fatalf("email-only without require-strong must challenge, got %+v", out)
	}
}

func TestLogin_MFA_IdentityUnreachable_FailsClosed(t *testing.T) {
	id := defaultIdentity()
	id.emailErr = errors.New("identity down")
	h := newMfaHandler(t, okAuth(), id, edgeCfg())

	rec := doLogin(t, h, publicEdge())
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502 fail-closed, got %d %s", rec.Code, rec.Body)
	}
	if sessionCookie(rec) != nil {
		t.Fatal("must not issue a session when the factor check cannot run")
	}
}

func TestLogin_MFA_DisabledUser401(t *testing.T) {
	id := defaultIdentity()
	id.user = &identityv1.User{Id: "u1", Enabled: false}
	h := newMfaHandler(t, okAuth(), id, edgeCfg())

	rec := doLogin(t, h, publicEdge())
	if rec.Code != http.StatusUnauthorized || sessionCookie(rec) != nil {
		t.Fatalf("disabled user must get 401 and no cookie, got %d", rec.Code)
	}
}

func TestMfaOtpSend_LoginPurpose(t *testing.T) {
	id := defaultIdentity()
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := mfaLogin(t, h)

	rec := postJSON(t, h.MfaOtpSend, "/auth/mfa/otp/send", map[string]string{"pendingId": pid})
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body)
	}
	if id.lastSend.GetUserId() != "u1" || id.lastSend.GetPurpose() != "login" {
		t.Fatalf("SendEmailOtp contract wrong: %+v", id.lastSend)
	}
}

func TestMfaOtpSend_UnknownPending401(t *testing.T) {
	id := defaultIdentity()
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	rec := postJSON(t, h.MfaOtpSend, "/auth/mfa/otp/send", map[string]string{"pendingId": "nope"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if id.lastSend != nil {
		t.Fatal("identity must not be called for an unknown pending id")
	}
}

func TestMfaWebauthn_BeginStoresSessionAndFinishUsesIt(t *testing.T) {
	id := defaultIdentity()
	id.factors = []string{"passkey"}
	id.assertOptions = `{"publicKey":{"challenge":"abc"}}`
	id.assertSession = "wa-sess-9"
	id.assertOK = true
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := mfaLogin(t, h)

	rec := postJSON(t, h.MfaWebauthnBegin, "/auth/mfa/webauthn/begin", map[string]string{"pendingId": pid})
	if rec.Code != 200 {
		t.Fatalf("begin: want 200, got %d %s", rec.Code, rec.Body)
	}
	var beginOut struct {
		OptionsJSON string `json:"optionsJson"`
		SessionID   string `json:"sessionId"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &beginOut)
	if beginOut.OptionsJSON != id.assertOptions {
		t.Fatalf("options passthrough wrong: %q", beginOut.OptionsJSON)
	}
	if beginOut.SessionID != "" {
		t.Fatal("the identity session_id must stay server-side")
	}
	if id.lastAssertBegin.GetUserId() != "u1" {
		t.Fatalf("AssertBegin keyed wrong: %+v", id.lastAssertBegin)
	}

	rec = verifyReq(t, h, map[string]string{"pendingId": pid, "kind": "passkey", "credentialJson": `{"id":"cred"}`})
	if rec.Code != 200 {
		t.Fatalf("verify: want 200, got %d %s", rec.Code, rec.Body)
	}
	if id.lastAssertFinish.GetUserId() != "u1" ||
		id.lastAssertFinish.GetSessionId() != "wa-sess-9" ||
		id.lastAssertFinish.GetCredentialJson() != `{"id":"cred"}` {
		t.Fatalf("AssertFinish contract wrong: %+v", id.lastAssertFinish)
	}
	if sessionCookie(rec) == nil {
		t.Fatal("passkey success must issue the session cookie")
	}
}

func TestMfaVerify_PasskeyWithoutBegin_GenericFailure(t *testing.T) {
	id := defaultIdentity()
	id.factors = []string{"passkey"}
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := mfaLogin(t, h)

	rec := verifyReq(t, h, map[string]string{"pendingId": pid, "kind": "passkey", "credentialJson": `{}`})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 generic failure, got %d %s", rec.Code, rec.Body)
	}
	if id.lastAssertFinish != nil {
		t.Fatal("finish must not be called without a stored begin session")
	}
}

func TestMfaVerify_TotpOK_PromotesAndConsumesPending(t *testing.T) {
	id := defaultIdentity()
	id.totpOK = true
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := mfaLogin(t, h)

	rec := verifyReq(t, h, map[string]string{"pendingId": pid, "kind": "totp", "code": "123456"})
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body)
	}
	out := decodeLogin(t, rec)
	c := sessionCookie(rec)
	if out.CSRFToken == "" || c == nil || !c.HttpOnly || c.Value == "" {
		t.Fatalf("promotion must mirror login: csrf=%q cookie=%+v", out.CSRFToken, c)
	}
	if id.lastVerifyTotp.GetUserId() != "u1" || id.lastVerifyTotp.GetCode() != "123456" {
		t.Fatalf("VerifyTotp contract wrong: %+v", id.lastVerifyTotp)
	}
	sess, ok, _ := h.Store.Get(context.Background(), c.Value)
	if !ok || sess.CSRFToken != out.CSRFToken || sess.AccessToken != testSessionToken || !sess.MFAVerified || sess.UserID != "u1" {
		t.Fatalf("bad promoted session: ok=%v %+v", ok, sess)
	}
	if _, ok, _ := h.Pending.GetPending(context.Background(), pid); ok {
		t.Fatal("pending record must be deleted on promotion")
	}
	rec = verifyReq(t, h, map[string]string{"pendingId": pid, "kind": "totp", "code": "123456"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("second verify must fail, got %d", rec.Code)
	}
}

func TestMfaVerify_EmailUsesLoginPurpose(t *testing.T) {
	id := defaultIdentity()
	id.emailOK = true
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := mfaLogin(t, h)

	rec := verifyReq(t, h, map[string]string{"pendingId": pid, "kind": "email", "code": "654321"})
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body)
	}
	if id.lastVerifyEmail.GetUserId() != "u1" || id.lastVerifyEmail.GetCode() != "654321" || id.lastVerifyEmail.GetPurpose() != "login" {
		t.Fatalf("VerifyEmailOtp contract wrong: %+v", id.lastVerifyEmail)
	}
}

func TestMfaVerify_WrongCode_AttemptsThenLockout(t *testing.T) {
	id := defaultIdentity()
	id.totpOK = false
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := mfaLogin(t, h)

	for i := 1; i <= 4; i++ {
		rec := verifyReq(t, h, map[string]string{"pendingId": pid, "kind": "totp", "code": "000000"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, rec.Code)
		}
		out := decodeLogin(t, rec)
		if out.Error != "invalid_code" {
			t.Fatalf("attempt %d: generic invalid_code only, got %+v", i, out)
		}
		p, ok, _ := h.Pending.GetPending(context.Background(), pid)
		if !ok || p.Attempts != i {
			t.Fatalf("attempt %d: counter not persisted: ok=%v %+v", i, ok, p)
		}
	}
	rec := verifyReq(t, h, map[string]string{"pendingId": pid, "kind": "totp", "code": "000000"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 on 5th failure, got %d", rec.Code)
	}
	if _, ok, _ := h.Pending.GetPending(context.Background(), pid); ok {
		t.Fatal("pending must be deleted after 5 failures")
	}
	id.totpOK = true
	rec = verifyReq(t, h, map[string]string{"pendingId": pid, "kind": "totp", "code": "123456"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("dead pending must stay dead, got %d", rec.Code)
	}
}

func TestMfaVerify_ExpiredPendingRejected(t *testing.T) {
	id := defaultIdentity()
	id.totpOK = true
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	_ = h.Pending.CreatePending(context.Background(), "pexp", PendingAuth{
		UserID: "u1", AccessToken: "AT",
		Factors:   []string{"totp"},
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	rec := verifyReq(t, h, map[string]string{"pendingId": "pexp", "kind": "totp", "code": "123456"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired pending must 401, got %d %s", rec.Code, rec.Body)
	}
	if sessionCookie(rec) != nil {
		t.Fatal("expired pending must never mint a session")
	}
	if id.lastVerifyTotp != nil {
		t.Fatal("identity must not be consulted for an expired pending")
	}
}

func TestMfaVerify_KindNotOffered_GenericFailure(t *testing.T) {
	id := defaultIdentity()
	id.factors = []string{"totp"}
	id.emailOK = true // even a would-pass factor is rejected if not offered
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := mfaLogin(t, h)

	rec := verifyReq(t, h, map[string]string{"pendingId": pid, "kind": "email", "code": "111111"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-offered kind must fail generically, got %d %s", rec.Code, rec.Body)
	}
	if id.lastVerifyEmail != nil {
		t.Fatal("identity must not be called for a kind the pending login does not offer")
	}
	p, ok, _ := h.Pending.GetPending(context.Background(), pid)
	if !ok || p.Attempts != 1 {
		t.Fatalf("non-offered kind must consume an attempt: ok=%v %+v", ok, p)
	}
}

func TestMfaVerify_MalformedRequest400(t *testing.T) {
	h := newMfaHandler(t, okAuth(), defaultIdentity(), edgeCfg())
	for _, body := range []map[string]string{
		{},                                 // no pendingId
		{"pendingId": "p"},                 // no kind
		{"pendingId": "p", "kind": "totp"}, // totp without code
	} {
		rec := verifyReq(t, h, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%v want 400, got %d", body, rec.Code)
		}
	}
}

// fakeAuthClient answers every Kratos call with one fixed result.
type fakeAuthClient struct {
	result AuthResult
	err    error
}

func (f fakeAuthClient) VerifyPassword(context.Context, string, string) (AuthResult, error) {
	return f.result, f.err
}
func (f fakeAuthClient) Refresh(context.Context, string) (AuthResult, error) {
	return f.result, f.err
}
func (f fakeAuthClient) Logout(context.Context, string) error { return nil }

func TestLoginWithMFA_ResolvesUserByEmail(t *testing.T) {
	id := &fakeMfaIdentity{
		user:    &identityv1.User{Id: "u-kratos-1", Enabled: true},
		factors: []string{"totp"},
	}
	h := newMfaHandler(t, fakeAuthClient{result: AuthResult{
		AccessToken: "kratos-session-token", ExpiresAt: time.Now().Add(time.Hour),
		Subject: "kratos-identity-1", Email: "alice@example.net",
	}}, id, edgeCfg())

	rec := doLogin(t, h, publicEdge())
	out := decodeLogin(t, rec)
	if rec.Code != http.StatusOK || !out.MFARequired || out.PendingID == "" {
		t.Fatalf("want 200 mfaRequired+pendingId, got code=%d %+v", rec.Code, out)
	}
	if id.lastGetUserByEmail == nil || id.lastGetUserByEmail.GetEmail() != "alice@example.net" {
		t.Fatalf("GetUserByEmail not called with the AuthResult email: %+v", id.lastGetUserByEmail)
	}
	p, ok, err := h.Pending.GetPending(context.Background(), out.PendingID)
	if err != nil || !ok {
		t.Fatalf("pending record missing: ok=%v err=%v", ok, err)
	}
	if p.UserID != "u-kratos-1" {
		t.Fatalf("pending UserID = %q, want u-kratos-1", p.UserID)
	}
	if p.AccessToken != "kratos-session-token" {
		t.Fatalf("pending AccessToken = %q, want the kratos session_token", p.AccessToken)
	}
}

// An email with no platform user is a clean sign-in failure, never a 5xx.
func TestLoginWithMFA_EmailNotFound(t *testing.T) {
	id := &fakeMfaIdentity{}
	h := newMfaHandler(t, fakeAuthClient{result: AuthResult{
		AccessToken: "kratos-session-token", ExpiresAt: time.Now().Add(time.Hour),
		Subject: "kratos-identity-2", Email: "nobody@example.net",
	}}, id, edgeCfg())

	rec := doLogin(t, h, publicEdge())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 clean login failure, got %d %s", rec.Code, rec.Body)
	}
	out := decodeLogin(t, rec)
	if out.Error != "invalid_credentials" {
		t.Fatalf("want invalid_credentials, got %+v", out)
	}
	if out.MFARequired || out.PendingID != "" {
		t.Fatalf("no pending state may be created when resolution fails: %+v", out)
	}
	if sessionCookie(rec) != nil {
		t.Fatal("no session cookie when resolution fails")
	}
}

func TestLoginWithMFA_IdentityUnreachable_502(t *testing.T) {
	id := &fakeMfaIdentity{emailErr: context.DeadlineExceeded}
	h := newMfaHandler(t, fakeAuthClient{result: AuthResult{
		AccessToken: "kratos-session-token", ExpiresAt: time.Now().Add(time.Hour),
		Email: "alice@example.net",
	}}, id, edgeCfg())

	rec := doLogin(t, h, publicEdge())
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502 fail-closed, got %d %s", rec.Code, rec.Body)
	}
}
