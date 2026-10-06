// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// enrollIdentity is a zero-factor user: a public-edge sign-in must enrol.
func enrollIdentity() *fakeMfaIdentity {
	return &fakeMfaIdentity{
		user:    &identityv1.User{Id: "u1", Enabled: true},
		factors: nil,
	}
}

// enrollLogin performs a public-edge login for a zero-factor user and returns
// the enrollment pending id.
func enrollLogin(t *testing.T, h *Handler) string {
	t.Helper()
	rec := doLogin(t, h, publicEdge())
	out := decodeLogin(t, rec)
	if rec.Code != 200 || !out.MFARequired || !out.EnrollmentRequired || out.PendingID == "" {
		t.Fatalf("expected enrollment-pending login, got code=%d %+v", rec.Code, out)
	}
	return out.PendingID
}

func TestLoginZeroFactorPublicEdgeCreatesEnrollPending(t *testing.T) {
	id := enrollIdentity()
	h := newMfaHandler(t, okAuth(), id, edgeCfg())

	pid := enrollLogin(t, h)

	p, ok, err := h.Pending.GetPending(context.Background(), pid)
	if err != nil || !ok {
		t.Fatalf("pending not stored: ok=%v err=%v", ok, err)
	}
	if !p.Enroll {
		t.Fatal("pending must be marked Enroll")
	}
	if len(p.Factors) != 0 {
		t.Fatalf("enroll pending must have no factors, got %v", p.Factors)
	}
}

// A returning user WITH factors gets a challenge pending, not an enroll one —
// so the enroll endpoints must refuse it.
func TestEnrollEndpointsRejectChallengePending(t *testing.T) {
	id := defaultIdentity() // has totp+email
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := mfaLogin(t, h)

	rec := postJSON(t, h.EnrollTotpBegin, "/auth/mfa/enroll/totp/begin", map[string]string{"pendingId": pid})
	if rec.Code != 400 {
		t.Fatalf("challenge pending must not enroll: got %d %s", rec.Code, rec.Body)
	}
}

func TestEnrollTotpBeginReturnsProvisioning(t *testing.T) {
	id := enrollIdentity()
	id.enrollTotpURI = "otpauth://totp/Steward:alice?secret=ABC"
	id.enrollTotpSecret = "ABC***"
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := enrollLogin(t, h)

	rec := postJSON(t, h.EnrollTotpBegin, "/auth/mfa/enroll/totp/begin", map[string]string{"pendingId": pid})
	if rec.Code != 200 {
		t.Fatalf("begin code=%d %s", rec.Code, rec.Body)
	}
	var out struct {
		OtpauthURI string `json:"otpauthUri"`
		Secret     string `json:"secret"`
	}
	decodeInto(t, rec, &out)
	if out.OtpauthURI != id.enrollTotpURI || out.Secret != id.enrollTotpSecret {
		t.Fatalf("bad provisioning payload: %+v", out)
	}
	if id.lastEnrollTotpBegin.GetUserId() != "u1" {
		t.Fatalf("wrong user id: %q", id.lastEnrollTotpBegin.GetUserId())
	}
	if sessionCookie(rec) != nil {
		t.Fatal("begin must not promote to a session")
	}
}

func TestEnrollTotpConfirmPromotesSession(t *testing.T) {
	id := enrollIdentity()
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := enrollLogin(t, h)

	rec := postJSON(t, h.EnrollTotpConfirm, "/auth/mfa/enroll/totp/confirm",
		map[string]string{"pendingId": pid, "code": "123456"})
	if rec.Code != 200 {
		t.Fatalf("confirm code=%d %s", rec.Code, rec.Body)
	}
	if sessionCookie(rec) == nil {
		t.Fatal("confirm must promote to a session")
	}
	if id.lastEnrollTotpConfirm.GetCode() != "123456" {
		t.Fatalf("code not forwarded: %q", id.lastEnrollTotpConfirm.GetCode())
	}
	if _, ok, _ := h.Pending.GetPending(context.Background(), pid); ok {
		t.Fatal("pending must be consumed after promotion")
	}
}

func TestEnrollTotpConfirmBadCodeBurnsAttempt(t *testing.T) {
	id := enrollIdentity()
	id.enrollTotpConfirmErr = status.Error(codes.InvalidArgument, "bad code")
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := enrollLogin(t, h)

	rec := postJSON(t, h.EnrollTotpConfirm, "/auth/mfa/enroll/totp/confirm",
		map[string]string{"pendingId": pid, "code": "000000"})
	if rec.Code != 401 {
		t.Fatalf("bad code want 401 got %d %s", rec.Code, rec.Body)
	}
	if sessionCookie(rec) != nil {
		t.Fatal("bad code must not promote")
	}
	p, ok, _ := h.Pending.GetPending(context.Background(), pid)
	if !ok || p.Attempts != 1 {
		t.Fatalf("attempt not burned: ok=%v attempts=%d", ok, p.Attempts)
	}
}

func TestEnrollTotpConfirmInfraErrorFailsClosed(t *testing.T) {
	id := enrollIdentity()
	id.enrollTotpConfirmErr = status.Error(codes.Unavailable, "identity down")
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := enrollLogin(t, h)

	rec := postJSON(t, h.EnrollTotpConfirm, "/auth/mfa/enroll/totp/confirm",
		map[string]string{"pendingId": pid, "code": "123456"})
	if rec.Code != 502 {
		t.Fatalf("infra want 502 got %d %s", rec.Code, rec.Body)
	}
	p, ok, _ := h.Pending.GetPending(context.Background(), pid)
	if !ok || p.Attempts != 0 {
		t.Fatalf("infra fault must not burn attempt: ok=%v attempts=%d", ok, p.Attempts)
	}
}

func TestEnrollEmailSendUsesEnrollPurpose(t *testing.T) {
	id := enrollIdentity()
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := enrollLogin(t, h)

	rec := postJSON(t, h.EnrollEmailSend, "/auth/mfa/enroll/email/send", map[string]string{"pendingId": pid})
	if rec.Code != 200 {
		t.Fatalf("send code=%d %s", rec.Code, rec.Body)
	}
	if id.lastSend.GetPurpose() != mfaEnrollPurpose {
		t.Fatalf("want enroll purpose, got %q", id.lastSend.GetPurpose())
	}
}

func TestEnrollEmailVerifyPromotesOnOk(t *testing.T) {
	id := enrollIdentity()
	id.emailOK = true
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := enrollLogin(t, h)

	rec := postJSON(t, h.EnrollEmailVerify, "/auth/mfa/enroll/email/verify",
		map[string]string{"pendingId": pid, "code": "654321"})
	if rec.Code != 200 || sessionCookie(rec) == nil {
		t.Fatalf("verify-ok must promote: code=%d cookie=%v", rec.Code, sessionCookie(rec) != nil)
	}
	if id.lastVerifyEmail.GetPurpose() != mfaEnrollPurpose {
		t.Fatalf("verify must use enroll purpose, got %q", id.lastVerifyEmail.GetPurpose())
	}
}

func TestEnrollEmailVerifyBadCodeNoSession(t *testing.T) {
	id := enrollIdentity()
	id.emailOK = false
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := enrollLogin(t, h)

	rec := postJSON(t, h.EnrollEmailVerify, "/auth/mfa/enroll/email/verify",
		map[string]string{"pendingId": pid, "code": "000000"})
	if rec.Code != 401 || sessionCookie(rec) != nil {
		t.Fatalf("bad email code must 401 no-session: code=%d", rec.Code)
	}
}

func TestEnrollWebauthnBeginStoresSession(t *testing.T) {
	id := enrollIdentity()
	id.regBeginOptions = `{"challenge":"x"}`
	id.regBeginSession = "reg-sess-1"
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := enrollLogin(t, h)

	rec := postJSON(t, h.EnrollWebauthnBegin, "/auth/mfa/enroll/webauthn/begin", map[string]string{"pendingId": pid})
	if rec.Code != 200 {
		t.Fatalf("begin code=%d %s", rec.Code, rec.Body)
	}
	var out struct {
		OptionsJSON string `json:"optionsJson"`
	}
	decodeInto(t, rec, &out)
	if out.OptionsJSON != id.regBeginOptions {
		t.Fatalf("options not passed through: %q", out.OptionsJSON)
	}
	p, ok, _ := h.Pending.GetPending(context.Background(), pid)
	if !ok || p.WebauthnSessionID != "reg-sess-1" {
		t.Fatalf("reg session not stored: ok=%v sid=%q", ok, p.WebauthnSessionID)
	}
}

func TestEnrollWebauthnFinishPromotesSession(t *testing.T) {
	id := enrollIdentity()
	id.regBeginSession = "reg-sess-1"
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := enrollLogin(t, h)
	_ = postJSON(t, h.EnrollWebauthnBegin, "/auth/mfa/enroll/webauthn/begin", map[string]string{"pendingId": pid})

	rec := postJSON(t, h.EnrollWebauthnFinish, "/auth/mfa/enroll/webauthn/finish",
		map[string]string{"pendingId": pid, "credentialJson": `{"id":"c1"}`, "label": "Face ID"})
	if rec.Code != 200 || sessionCookie(rec) == nil {
		t.Fatalf("finish must promote: code=%d %s", rec.Code, rec.Body)
	}
	if id.lastRegFinish.GetSessionId() != "reg-sess-1" || id.lastRegFinish.GetLabel() != "Face ID" {
		t.Fatalf("finish did not forward session/label: %+v", id.lastRegFinish)
	}
}

func TestEnrollWebauthnFinishWithoutBegin(t *testing.T) {
	id := enrollIdentity()
	h := newMfaHandler(t, okAuth(), id, edgeCfg())
	pid := enrollLogin(t, h)

	rec := postJSON(t, h.EnrollWebauthnFinish, "/auth/mfa/enroll/webauthn/finish",
		map[string]string{"pendingId": pid, "credentialJson": `{"id":"c1"}`})
	if rec.Code != 400 {
		t.Fatalf("finish without begin want 400 got %d %s", rec.Code, rec.Body)
	}
}
