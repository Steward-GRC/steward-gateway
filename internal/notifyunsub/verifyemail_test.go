// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package notifyunsub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// goldenEmailVerify is a PurposeEmailVerify token minted by obligations'
// notifytoken.Signer.MintEmailVerify (secret goldenSec, user "u1",
// email "frank@example.org", expiry year ~2126). Its presence here proves the
// gateway verifier stays byte-compatible with the obligations signer for the email-verify
// purpose — exactly as goldenUnsub does for
// the unsubscribe purpose.
const goldenEmailVerify = "eyJ2IjoxLCJwIjoiZW1haWwtdmVyaWZ5IiwidSI6InUxIiwiZW0iOiJmcmFua0BleGFtcGxlLm9yZyIsImUiOjQ5NDEzMDQ1NTR9.ZHlEGXhHOm07K3x7FUJqHRhv94kL-1TW4ykvFo9QIXg"

// TestVerifyGoldenEmailVerifyTokenFromCN proves the gateway verifier decodes a
// obligations-minted PurposeEmailVerify token and rejects it under any other purpose.
func TestVerifyGoldenEmailVerifyTokenFromObligations(t *testing.T) {
	v, err := NewVerifier(goldenSec)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	c, err := v.Verify(goldenEmailVerify, PurposeEmailVerify)
	if err != nil {
		t.Fatalf("verify obligations-minted email-verify token: %v", err)
	}
	if c.UserID != "u1" || c.Email != "frank@example.org" {
		t.Fatalf("unexpected claims: %+v", c)
	}
	if _, err := v.Verify(goldenEmailVerify, PurposeUnsubscribe); err != ErrPurpose {
		t.Fatalf("want ErrPurpose for email-verify-as-unsub, got %v", err)
	}
	if _, err := v.Verify(goldenUnsub, PurposeEmailVerify); err != ErrPurpose {
		t.Fatalf("want ErrPurpose for unsub-as-email-verify, got %v", err)
	}
}

// fakeEmailVerifier records the MarkEmailVerified call and returns a
// configurable response/error.
type fakeEmailVerifier struct {
	gotUser  string
	gotEmail string
	calls    int
	resp     *identityv1.MarkEmailVerifiedResponse
	err      error
}

func (f *fakeEmailVerifier) MarkEmailVerified(_ context.Context, in *identityv1.MarkEmailVerifiedRequest, _ ...grpc.CallOption) (*identityv1.MarkEmailVerifiedResponse, error) {
	f.calls++
	f.gotUser = in.GetUserId()
	f.gotEmail = in.GetEmail()
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &identityv1.MarkEmailVerifiedResponse{}, nil
}

func newVerifyEmail(t *testing.T, id EmailVerifier) *VerifyEmailHandlers {
	t.Helper()
	v, err := NewVerifier(goldenSec)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return NewVerifyEmail(v, id)
}

func doVerify(h *VerifyEmailHandlers, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/notify/verify-email?token="+token, nil)
	rec := httptest.NewRecorder()
	h.Handler()(rec, req)
	return rec
}

// TestVerifyEmail_ValidMarksVerified: a valid token persists verification for
// the exact (user_id, email) in the token and renders the success page.
func TestVerifyEmail_ValidMarksVerified(t *testing.T) {
	fv := &fakeEmailVerifier{resp: &identityv1.MarkEmailVerifiedResponse{AlreadyVerified: false}}
	h := newVerifyEmail(t, fv)

	rec := doVerify(h, goldenEmailVerify)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if fv.calls != 1 || fv.gotUser != "u1" || fv.gotEmail != "frank@example.org" {
		t.Fatalf("MarkEmailVerified not called with token claims: %+v", fv)
	}
	if !strings.Contains(rec.Body.String(), "Email verified") {
		t.Fatalf("expected success page, got: %s", rec.Body.String())
	}
}

// TestVerifyEmail_AlreadyVerifiedIdempotent: already_verified renders the
// "already verified" page (still 200), the idempotent outcome.
func TestVerifyEmail_AlreadyVerifiedIdempotent(t *testing.T) {
	fv := &fakeEmailVerifier{resp: &identityv1.MarkEmailVerifiedResponse{AlreadyVerified: true}}
	h := newVerifyEmail(t, fv)

	rec := doVerify(h, goldenEmailVerify)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Already verified") {
		t.Fatalf("expected already-verified page, got: %s", rec.Body.String())
	}
}

// TestVerifyEmail_EmailMismatchIsInvalidLink: identity FailedPrecondition (the
// account's address changed since the link was minted) renders the invalid-link
// page (400), NOT a server error.
func TestVerifyEmail_EmailMismatchIsInvalidLink(t *testing.T) {
	fv := &fakeEmailVerifier{err: status.Error(codes.FailedPrecondition, "email does not match")}
	h := newVerifyEmail(t, fv)

	rec := doVerify(h, goldenEmailVerify)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for mismatch, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no longer valid") {
		t.Fatalf("expected invalid-link page, got: %s", rec.Body.String())
	}
}

// TestVerifyEmail_UnknownUserIsInvalidLink: identity NotFound also renders the
// invalid-link page.
func TestVerifyEmail_UnknownUserIsInvalidLink(t *testing.T) {
	fv := &fakeEmailVerifier{err: status.Error(codes.NotFound, "no such user")}
	h := newVerifyEmail(t, fv)

	rec := doVerify(h, goldenEmailVerify)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown user, got %d", rec.Code)
	}
}

// TestVerifyEmail_TransientErrorRendersRetry: a non-user identity failure
// (Unavailable) renders the retry page (502) and does NOT masquerade as an
// invalid link.
func TestVerifyEmail_TransientErrorRendersRetry(t *testing.T) {
	fv := &fakeEmailVerifier{err: status.Error(codes.Unavailable, "identity down")}
	h := newVerifyEmail(t, fv)

	rec := doVerify(h, goldenEmailVerify)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502 for transient failure, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Something went wrong") {
		t.Fatalf("expected retry page, got: %s", rec.Body.String())
	}
}

// TestVerifyEmail_TamperedTokenRejected: a tampered signature never reaches
// identity and renders the invalid-link page.
func TestVerifyEmail_TamperedTokenRejected(t *testing.T) {
	fv := &fakeEmailVerifier{}
	h := newVerifyEmail(t, fv)

	tampered := goldenEmailVerify[:len(goldenEmailVerify)-3] + "AAA"
	rec := doVerify(h, tampered)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for tampered token, got %d", rec.Code)
	}
	if fv.calls != 0 {
		t.Fatalf("identity must not be called for a bad token, calls=%d", fv.calls)
	}
}

// TestVerifyEmail_WrongPurposeRejected: an unsubscribe token presented to the
// verify-email endpoint is rejected (wrong purpose) without hitting identity.
func TestVerifyEmail_WrongPurposeRejected(t *testing.T) {
	fv := &fakeEmailVerifier{}
	h := newVerifyEmail(t, fv)

	rec := doVerify(h, goldenUnsub)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for wrong-purpose token, got %d", rec.Code)
	}
	if fv.calls != 0 {
		t.Fatalf("identity must not be called for a wrong-purpose token, calls=%d", fv.calls)
	}
}

// TestVerifyEmail_ExpiredTokenRejected: a well-signed token past expiry is
// rejected without hitting identity. The verifier's clock is advanced past the
// golden token's far-future expiry.
func TestVerifyEmail_ExpiredTokenRejected(t *testing.T) {
	fv := &fakeEmailVerifier{}
	v, err := NewVerifier(goldenSec)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	v.now = func() time.Time { return time.Unix(4941304554+1, 0) } // one second past exp
	h := NewVerifyEmail(v, fv)

	rec := doVerify(h, goldenEmailVerify)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for expired token, got %d", rec.Code)
	}
	if fv.calls != 0 {
		t.Fatalf("identity must not be called for an expired token, calls=%d", fv.calls)
	}
}
