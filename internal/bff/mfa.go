// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MFA enforcement modes (MFA_ENFORCE).
const (
	// MFAModeEdge asks for a second factor when the sign-in arrives through
	// the public edge, as marked by the edge header.
	MFAModeEdge = "edge"
	// MFAModeAlways asks for a second factor on every sign-in.
	MFAModeAlways = "always"
	// MFAModeNever never asks.
	MFAModeNever = "never"
)

const (
	defaultEdgeHeader      = "X-Steward-Edge"
	defaultEdgePublicValue = "public"

	mfaLoginPurpose  = "login"
	mfaEnrollPurpose = "enroll"

	factorTotp    = "totp"
	factorEmail   = "email"
	factorPasskey = "passkey"
)

// MFAConfig controls second-factor enforcement, decided at sign-in from the
// request's headers.
type MFAConfig struct {
	// Mode is edge (the default), always or never.
	Mode string
	// EdgeHeader names the header the public edge sets; default X-Steward-Edge.
	EdgeHeader string
	// EdgePublicValue is the header value that marks the public edge; default
	// "public".
	EdgePublicValue string
	// RequireStrong makes a user with only the implicit email factor enrol a
	// TOTP or passkey first.
	RequireStrong bool
}

// strongFactors excludes email: every user has it, so it can't prove an
// enrolled possession.
var strongFactors = map[string]bool{factorTotp: true, factorPasskey: true}

func hasStrongFactor(kinds []string) bool {
	for _, k := range kinds {
		if strongFactors[k] {
			return true
		}
	}
	return false
}

func (c MFAConfig) edgeHeader() string {
	if c.EdgeHeader == "" {
		return defaultEdgeHeader
	}
	return c.EdgeHeader
}

func (c MFAConfig) edgePublicValue() string {
	if c.EdgePublicValue == "" {
		return defaultEdgePublicValue
	}
	return c.EdgePublicValue
}

// mfaRequired decides whether this sign-in owes a second factor. An unknown
// mode falls back to edge, so a typo never turns enforcement off.
func (h *Handler) mfaRequired(r *http.Request) bool {
	switch h.MFA.Mode {
	case MFAModeNever:
		return false
	case MFAModeAlways:
		return true
	default:
		return r.Header.Get(h.MFA.edgeHeader()) == h.MFA.edgePublicValue()
	}
}

// IdentityClient is the identity surface the sign-in flows use; the
// generated IdentityReadServiceClient satisfies it.
type IdentityClient interface {
	GetUserByEmail(ctx context.Context, in *identityv1.GetUserByEmailRequest, opts ...grpc.CallOption) (*identityv1.GetUserByEmailResponse, error)
	JitProvisionByEmail(ctx context.Context, in *identityv1.JitProvisionByEmailRequest, opts ...grpc.CallOption) (*identityv1.JitProvisionByEmailResponse, error)
	GetUser(ctx context.Context, in *identityv1.GetUserRequest, opts ...grpc.CallOption) (*identityv1.GetUserResponse, error)
	ListUserFactors(ctx context.Context, in *identityv1.ListUserFactorsRequest, opts ...grpc.CallOption) (*identityv1.ListUserFactorsResponse, error)
	SendEmailOtp(ctx context.Context, in *identityv1.SendEmailOtpRequest, opts ...grpc.CallOption) (*identityv1.SendEmailOtpResponse, error)
	VerifyTotp(ctx context.Context, in *identityv1.VerifyTotpRequest, opts ...grpc.CallOption) (*identityv1.VerifyTotpResponse, error)
	VerifyEmailOtp(ctx context.Context, in *identityv1.VerifyEmailOtpRequest, opts ...grpc.CallOption) (*identityv1.VerifyEmailOtpResponse, error)
	WebauthnAssertBegin(ctx context.Context, in *identityv1.WebauthnAssertBeginRequest, opts ...grpc.CallOption) (*identityv1.WebauthnAssertBeginResponse, error)
	WebauthnAssertFinish(ctx context.Context, in *identityv1.WebauthnAssertFinishRequest, opts ...grpc.CallOption) (*identityv1.WebauthnAssertFinishResponse, error)
	EnrollTotpBegin(ctx context.Context, in *identityv1.EnrollTotpBeginRequest, opts ...grpc.CallOption) (*identityv1.EnrollTotpBeginResponse, error)
	EnrollTotpConfirm(ctx context.Context, in *identityv1.EnrollTotpConfirmRequest, opts ...grpc.CallOption) (*identityv1.EnrollTotpConfirmResponse, error)
	WebauthnRegisterBegin(ctx context.Context, in *identityv1.WebauthnRegisterBeginRequest, opts ...grpc.CallOption) (*identityv1.WebauthnRegisterBeginResponse, error)
	WebauthnRegisterFinish(ctx context.Context, in *identityv1.WebauthnRegisterFinishRequest, opts ...grpc.CallOption) (*identityv1.WebauthnRegisterFinishResponse, error)
	Discover(ctx context.Context, in *identityv1.DiscoverRequest, opts ...grpc.CallOption) (*identityv1.DiscoverResponse, error)
	CheckBreakGlassEligibility(ctx context.Context, in *identityv1.CheckBreakGlassEligibilityRequest, opts ...grpc.CallOption) (*identityv1.CheckBreakGlassEligibilityResponse, error)
}

// resolveUserByEmail maps a Kratos identity's email to the platform user. No
// such user is coded CodeKratosEmailNoPlatformUser, which the sign-in paths
// answer like a wrong password.
func (h *Handler) resolveUserByEmail(ctx context.Context, email string) (*identityv1.User, error) {
	if email == "" {
		return nil, errors.New("kratos: sign-in carries no email")
	}
	resp, err := h.Identity.GetUserByEmail(ctx, &identityv1.GetUserByEmailRequest{Email: email})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, errcodes.Wrap(errcodes.CodeKratosEmailNoPlatformUser, fmt.Errorf("kratos: no platform user for email: %w", err))
		}
		return nil, err
	}
	if resp.GetUser() == nil {
		return nil, errcodes.Wrap(errcodes.CodeKratosEmailNoPlatformUser, errors.New("kratos: GetUserByEmail returned no user"))
	}
	return resp.GetUser(), nil
}

func factorKinds(factors []*identityv1.UserFactor) []string {
	kinds := make([]string, 0, len(factors))
	for _, f := range factors {
		kinds = append(kinds, f.GetKind())
	}
	return kinds
}

// loginWithMFA parks a verified sign-in under a pending id and tells the
// client which factors can finish it. If the factors can't be read, nothing
// is parked and no session is issued.
func (h *Handler) loginWithMFA(w http.ResponseWriter, r *http.Request, res AuthResult, user *identityv1.User) {
	factorsResp, err := h.Identity.ListUserFactors(r.Context(), &identityv1.ListUserFactorsRequest{UserId: user.GetId()})
	if err != nil {
		h.logger(r.Context()).Warn("mfa step-up: ListUserFactors failed", log.F("user_id", user.GetId()), errField(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	kinds := factorKinds(factorsResp.GetFactors())
	enroll := len(kinds) == 0 || (h.MFA.RequireStrong && !hasStrongFactor(kinds))

	pendingID, err := h.createPending(r.Context(), res.AccessToken, res.SessionID, res.ExpiresAt, user.GetId(), kinds, enroll)
	if err != nil {
		h.logger(r.Context()).Error(err, "mfa step-up: could not park the pending sign-in", log.F("user_id", user.GetId()))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	log.Trace(h.logger(r.Context()), "mfa step-up: pending parked", log.F("user_id", user.GetId()),
		log.F("factors", kinds), log.F("enrollment_required", enroll))
	out := map[string]any{"mfaRequired": true, "pendingId": pendingID}
	if enroll {
		out["enrollmentRequired"] = true
	} else {
		out["factors"] = kinds
	}
	writeJSON(w, http.StatusOK, out)
}

// createPending parks a sign-in for its second factor. sessionToken is the
// Kratos session token (and kratosSessionID its session's id) for a password
// or passkey sign-in, both empty for SSO.
func (h *Handler) createPending(ctx context.Context, sessionToken, kratosSessionID string, tokenExpiresAt time.Time, userID string, kinds []string, enroll bool) (string, error) {
	pendingID, err := newSessionID()
	if err != nil {
		return "", err
	}
	if err := h.Pending.CreatePending(ctx, pendingID, PendingAuth{
		AccessToken:     sessionToken,
		KratosSessionID: kratosSessionID,
		TokenExpiresAt:  tokenExpiresAt,
		UserID:          userID,
		Factors:         kinds,
		Enroll:          enroll,
		ExpiresAt:       time.Now().Add(pendingTTL),
	}); err != nil {
		return "", err
	}
	return pendingID, nil
}

// loadPending fetches and validates a pending record; a miss or an expired
// record answers 401 {"error":"invalid_pending"} (restart login) and returns
// ok=false. The distinction from invalid_code is deliberate: it tells the
// widget to restart the login, not that any secret was wrong.
func (h *Handler) loadPending(w http.ResponseWriter, r *http.Request, id string) (PendingAuth, bool) {
	p, ok, err := h.Pending.GetPending(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return PendingAuth{}, false
	}
	if !ok || time.Now().After(p.ExpiresAt) {
		if ok {
			_ = h.Pending.DeletePending(r.Context(), id)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_pending"})
		return PendingAuth{}, false
	}
	return p, true
}

// MfaOtpSend serves POST /auth/mfa/otp/send {pendingId}: asks identity to
// email a login-purpose OTP to the pending user. Identity enforces its own
// re-issue cooldown (ResourceExhausted → 429).
func (h *Handler) MfaOtpSend(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PendingID string `json:"pendingId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PendingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	p, ok := h.loadPending(w, r, in.PendingID)
	if !ok {
		return
	}
	_, err := h.Identity.SendEmailOtp(r.Context(), &identityv1.SendEmailOtpRequest{
		UserId: p.UserID, Purpose: mfaLoginPurpose,
	})
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

// MfaWebauthnBegin serves POST /auth/mfa/webauthn/begin {pendingId}: starts an
// assertion ceremony at identity and passes the request options through to the
// widget. The identity session_id is stored ON THE PENDING RECORD, never sent
// to the client — the finish step (MfaVerify kind=passkey) reads it back.
func (h *Handler) MfaWebauthnBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PendingID string `json:"pendingId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PendingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	p, ok := h.loadPending(w, r, in.PendingID)
	if !ok {
		return
	}
	resp, err := h.Identity.WebauthnAssertBegin(r.Context(), &identityv1.WebauthnAssertBeginRequest{UserId: p.UserID})
	if err != nil {
		switch status.Code(err) {
		case codes.FailedPrecondition, codes.NotFound, codes.InvalidArgument:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		}
		return
	}
	p.WebauthnSessionID = resp.GetSessionId()
	if err := h.Pending.SavePending(r.Context(), in.PendingID, p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"optionsJson": resp.GetOptionsJson()})
}

// MfaVerify serves POST /auth/mfa/verify {pendingId, kind, code?|credentialJson?}.
// On a verified factor the pending record is atomically consumed and the real
// session is issued exactly as a direct login would (cookie + CSRF). Failures
// are deliberately uniform — 401 {"error":"invalid_code"} — never revealing
// which part failed; each failure burns one of maxPendingAttempts attempts.
func (h *Handler) MfaVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PendingID      string `json:"pendingId"`
		Kind           string `json:"kind"`
		Code           string `json:"code"`
		CredentialJSON string `json:"credentialJson"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PendingID == "" || in.Kind == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	switch in.Kind {
	case factorTotp, factorEmail:
		if in.Code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
	case factorPasskey:
		if in.CredentialJSON == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	p, ok := h.loadPending(w, r, in.PendingID)
	if !ok {
		return
	}

	verified := false
	if factorOffered(p.Factors, in.Kind) {
		var rpcErr error
		switch in.Kind {
		case factorTotp:
			var resp *identityv1.VerifyTotpResponse
			resp, rpcErr = h.Identity.VerifyTotp(r.Context(), &identityv1.VerifyTotpRequest{UserId: p.UserID, Code: in.Code})
			verified = resp.GetOk()
		case factorEmail:
			var resp *identityv1.VerifyEmailOtpResponse
			resp, rpcErr = h.Identity.VerifyEmailOtp(r.Context(), &identityv1.VerifyEmailOtpRequest{
				UserId: p.UserID, Code: in.Code, Purpose: mfaLoginPurpose,
			})
			verified = resp.GetOk()
		case factorPasskey:
			if p.WebauthnSessionID == "" {
				break
			}
			var resp *identityv1.WebauthnAssertFinishResponse
			resp, rpcErr = h.Identity.WebauthnAssertFinish(r.Context(), &identityv1.WebauthnAssertFinishRequest{
				UserId: p.UserID, SessionId: p.WebauthnSessionID, CredentialJson: in.CredentialJSON,
			})
			verified = resp.GetOk()
		}
		if rpcErr != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
			return
		}
	}

	if !verified {
		h.burnAttempt(r.Context(), in.PendingID, p)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}

	h.promotePending(w, r, in.PendingID)
}

// burnAttempt records one failed factor guess against the pending record. At
// the attempt budget the record (and the held tokens) is discarded so the user
// must restart login; below it the incremented counter is saved in place,
// preserving the record's remaining TTL.
func (h *Handler) burnAttempt(ctx context.Context, id string, p PendingAuth) {
	p.Attempts++
	if p.Attempts >= maxPendingAttempts {
		_ = h.Pending.DeletePending(ctx, id)
		return
	}
	_ = h.Pending.SavePending(ctx, id, p)
}

// promotePending atomically consumes the pending record (single-use even under
// concurrent calls) and issues the real session exactly like a direct login,
// marked MFAVerified. A miss means the record was already consumed or expired
// and the caller restarts login. Shared by the verify (challenge) and enroll
// (first-login) promotion paths.
func (h *Handler) promotePending(w http.ResponseWriter, r *http.Request, id string) {
	final, ok, err := h.Pending.ConsumePending(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_pending"})
		return
	}
	log.Trace(h.logger(r.Context()), "mfa step-up: factor verified, session issued", log.F("user_id", final.UserID))
	h.issueSession(w, r, Session{
		AccessToken:     final.AccessToken,
		KratosSessionID: final.KratosSessionID,
		ExpiresAt:       final.TokenExpiresAt,
		UserID:          final.UserID,
		MFAVerified:     true,
	})
}

func factorOffered(factors []string, kind string) bool {
	return slices.Contains(factors, kind)
}
