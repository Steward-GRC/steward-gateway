// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"net/http"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// loadEnrollPending loads a pending record and requires it to be an enrollment
// pending. A challenge pending (user already has factors) is rejected with a
// uniform 400 — enrollment mid-login is only for the zero-factor case.
func (h *Handler) loadEnrollPending(w http.ResponseWriter, r *http.Request, id string) (PendingAuth, bool) {
	p, ok := h.loadPending(w, r, id)
	if !ok {
		return PendingAuth{}, false
	}
	if !p.Enroll {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return PendingAuth{}, false
	}
	return p, true
}

// decodePendingID reads {pendingId} and rejects an empty/malformed body.
func decodePendingID(w http.ResponseWriter, r *http.Request) (string, bool) {
	var in struct {
		PendingID string `json:"pendingId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PendingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return "", false
	}
	return in.PendingID, true
}

// enrollBeginError maps an identity begin/send error: a precondition/argument
// fault is a bad request (400); anything else is an upstream fault (502). No
// attempt is burned — a begin is not a factor guess.
func enrollBeginError(w http.ResponseWriter, err error) {
	switch status.Code(err) {
	case codes.FailedPrecondition, codes.NotFound, codes.InvalidArgument:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
	default:
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
	}
}

// isEnrollGuessError reports whether a confirm/finish error is a rejected
// proof (wrong code / bad assertion) rather than an infrastructure fault. Only
// a guess burns an attempt; an infra fault fails closed with no attempt spent.
func isEnrollGuessError(err error) bool {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.Unauthenticated, codes.PermissionDenied:
		return true
	default:
		return false
	}
}

// EnrollTotpBegin serves POST /auth/mfa/enroll/totp/begin {pendingId}: starts
// TOTP enrollment for the pending user and returns the otpauth:// provisioning
// URI (for the widget's QR) plus a masked secret. No session yet.
func (h *Handler) EnrollTotpBegin(w http.ResponseWriter, r *http.Request) {
	id, ok := decodePendingID(w, r)
	if !ok {
		return
	}
	p, ok := h.loadEnrollPending(w, r, id)
	if !ok {
		return
	}
	resp, err := h.Identity.EnrollTotpBegin(r.Context(), &identityv1.EnrollTotpBeginRequest{UserId: p.UserID})
	if err != nil {
		enrollBeginError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"otpauthUri": resp.GetOtpauthUri(),
		"secret":     resp.GetSecretMasked(),
	})
}

// EnrollTotpConfirm serves POST /auth/mfa/enroll/totp/confirm {pendingId, code}:
// activates the pending TOTP enrollment by proving possession with a current
// code, then promotes to a session. A rejected code burns one attempt.
func (h *Handler) EnrollTotpConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PendingID string `json:"pendingId"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PendingID == "" || in.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	p, ok := h.loadEnrollPending(w, r, in.PendingID)
	if !ok {
		return
	}
	_, err := h.Identity.EnrollTotpConfirm(r.Context(), &identityv1.EnrollTotpConfirmRequest{UserId: p.UserID, Code: in.Code})
	if err != nil {
		if isEnrollGuessError(err) {
			h.burnAttempt(r.Context(), in.PendingID, p)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	h.promotePending(w, r, in.PendingID)
}

// EnrollEmailSend serves POST /auth/mfa/enroll/email/send {pendingId}: emails
// the pending user a single-use enrollment-purpose OTP. No session yet.
func (h *Handler) EnrollEmailSend(w http.ResponseWriter, r *http.Request) {
	id, ok := decodePendingID(w, r)
	if !ok {
		return
	}
	p, ok := h.loadEnrollPending(w, r, id)
	if !ok {
		return
	}
	_, err := h.Identity.SendEmailOtp(r.Context(), &identityv1.SendEmailOtpRequest{UserId: p.UserID, Purpose: mfaEnrollPurpose})
	if err != nil {
		if status.Code(err) == codes.ResourceExhausted {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// EnrollEmailVerify serves POST /auth/mfa/enroll/email/verify {pendingId, code}:
// verifies the enrollment-purpose OTP (which enrolls email as a factor) and
// promotes to a session. A wrong code burns one attempt.
func (h *Handler) EnrollEmailVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PendingID string `json:"pendingId"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PendingID == "" || in.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	p, ok := h.loadEnrollPending(w, r, in.PendingID)
	if !ok {
		return
	}
	resp, err := h.Identity.VerifyEmailOtp(r.Context(), &identityv1.VerifyEmailOtpRequest{
		UserId: p.UserID, Code: in.Code, Purpose: mfaEnrollPurpose,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	if !resp.GetOk() {
		h.burnAttempt(r.Context(), in.PendingID, p)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}
	h.promotePending(w, r, in.PendingID)
}

// EnrollWebauthnBegin serves POST /auth/mfa/enroll/webauthn/begin {pendingId}:
// starts a passkey/biometric REGISTRATION ceremony and passes the creation
// options through to the widget. The registration session id is stored on the
// pending record (never sent to the client); the finish step reads it back.
func (h *Handler) EnrollWebauthnBegin(w http.ResponseWriter, r *http.Request) {
	id, ok := decodePendingID(w, r)
	if !ok {
		return
	}
	p, ok := h.loadEnrollPending(w, r, id)
	if !ok {
		return
	}
	resp, err := h.Identity.WebauthnRegisterBegin(r.Context(), &identityv1.WebauthnRegisterBeginRequest{UserId: p.UserID})
	if err != nil {
		enrollBeginError(w, err)
		return
	}
	p.WebauthnSessionID = resp.GetSessionId()
	if err := h.Pending.SavePending(r.Context(), id, p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"optionsJson": resp.GetOptionsJson()})
}

// EnrollWebauthnFinish serves POST /auth/mfa/enroll/webauthn/finish
// {pendingId, credentialJson, label?}: completes the registration ceremony
// against the session captured at begin, enrolling the passkey, then promotes
// to a session. Missing begin state or a rejected credential fails closed.
func (h *Handler) EnrollWebauthnFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PendingID      string `json:"pendingId"`
		CredentialJSON string `json:"credentialJson"`
		Label          string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PendingID == "" || in.CredentialJSON == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	p, ok := h.loadEnrollPending(w, r, in.PendingID)
	if !ok {
		return
	}
	if p.WebauthnSessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	_, err := h.Identity.WebauthnRegisterFinish(r.Context(), &identityv1.WebauthnRegisterFinishRequest{
		UserId:         p.UserID,
		SessionId:      p.WebauthnSessionID,
		CredentialJson: in.CredentialJSON,
		Label:          in.Label,
	})
	if err != nil {
		if isEnrollGuessError(err) {
			h.burnAttempt(r.Context(), in.PendingID, p)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	h.promotePending(w, r, in.PendingID)
}
