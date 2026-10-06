// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"net/http"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc"
)

// Register mounts the /auth routes and the admin SSO helpers on mux. The
// sign-in steps are public; passkey registration and the /admin routes run
// inside Authenticate.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/login", h.Login)
	mux.HandleFunc("POST /auth/logout", h.Logout)
	mux.HandleFunc("GET /auth/session", h.Session)
	mux.HandleFunc("POST /auth/discover", h.Discover)
	mux.HandleFunc("POST /auth/breakglass", h.BreakGlassLogin)

	mux.HandleFunc("GET /auth/sso/start", h.SSOStart)
	mux.HandleFunc("GET /auth/sso/callback", h.SSOCallback)
	mux.HandleFunc("POST /auth/sso/idp-initiated", h.SSOIdpInitiated)

	mux.HandleFunc("POST /auth/mfa/otp/send", h.MfaOtpSend)
	mux.HandleFunc("POST /auth/mfa/webauthn/begin", h.MfaWebauthnBegin)
	mux.HandleFunc("POST /auth/mfa/verify", h.MfaVerify)
	mux.HandleFunc("POST /auth/mfa/enroll/totp/begin", h.EnrollTotpBegin)
	mux.HandleFunc("POST /auth/mfa/enroll/totp/confirm", h.EnrollTotpConfirm)
	mux.HandleFunc("POST /auth/mfa/enroll/email/send", h.EnrollEmailSend)
	mux.HandleFunc("POST /auth/mfa/enroll/email/verify", h.EnrollEmailVerify)
	mux.HandleFunc("POST /auth/mfa/enroll/webauthn/begin", h.EnrollWebauthnBegin)
	mux.HandleFunc("POST /auth/mfa/enroll/webauthn/finish", h.EnrollWebauthnFinish)

	mux.HandleFunc("POST /auth/passkey/login/begin", h.PasskeyLoginBegin)
	mux.HandleFunc("POST /auth/passkey/login/finish", h.PasskeyLoginFinish)
	mux.Handle("POST /auth/passkey/register/begin", h.Authenticate(http.HandlerFunc(h.PasskeyRegisterBegin)))
	mux.Handle("POST /auth/passkey/register/finish", h.Authenticate(http.HandlerFunc(h.PasskeyRegisterFinish)))

	mux.Handle("POST /admin/idp/import-metadata", h.Authenticate(http.HandlerFunc(ImportMetadataHandler)))
	mux.Handle("POST /admin/idp/parse-metadata", h.Authenticate(http.HandlerFunc(ParseMetadataHandler)))
	mux.Handle("POST /admin/idp/fetch-cert", h.Authenticate(http.HandlerFunc(FetchCertHandler)))
	mux.Handle("POST /admin/sso/test-link", h.Authenticate(http.HandlerFunc(h.MintSSOTestLink)))
}

// ssoAdminRecorder is the part of identity's SSO admin service the sign-in
// records use.
type ssoAdminRecorder interface {
	RecordIdPTestResult(ctx context.Context, in *identityv1.RecordIdPTestResultRequest, opts ...grpc.CallOption) (*identityv1.RecordIdPTestResultResponse, error)
	RecordBreakGlassLogin(ctx context.Context, in *identityv1.RecordBreakGlassLoginRequest, opts ...grpc.CallOption) (*identityv1.RecordBreakGlassLoginResponse, error)
}

// RecordIdPTestWith is the Handler.IdPTestRecorder backed by identity. The
// admin on ctx is the actor identity checks.
func RecordIdPTestWith(c ssoAdminRecorder) func(ctx context.Context, connectionID string, success bool, detail string) error {
	return func(ctx context.Context, connectionID string, success bool, detail string) error {
		_, err := c.RecordIdPTestResult(ctx, &identityv1.RecordIdPTestResultRequest{
			ConnectionId: connectionID, Success: success, Detail: detail,
		})
		return err
	}
}

// RecordBreakGlassWith is the Handler.BreakGlassPublish backed by identity,
// which keeps the record and alerts the site admins. A failure is logged and
// never blocks the sign-in.
func RecordBreakGlassWith(c ssoAdminRecorder, l log.Logger) func(ctx context.Context, email string) {
	if l == nil {
		l = log.Nop()
	}
	return func(ctx context.Context, email string) {
		if _, err := c.RecordBreakGlassLogin(ctx, &identityv1.RecordBreakGlassLoginRequest{Email: email}); err != nil {
			l.Ctx(ctx).Warn("break-glass: identity record failed", errField(err))
		}
	}
}
