// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package passwordreset serves the unauthenticated sign-in helpers: the
// sign-in settings the page loads first, the password reset by emailed code
// and the emailed sign-in code. Identity does the work, including setting the
// new password in Kratos; these handlers only shape the answers.
package passwordreset

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IdentityClient is the identity surface these routes call; the generated
// IdentityReadServiceClient satisfies it.
type IdentityClient interface {
	GetAuthConfig(ctx context.Context, in *identityv1.GetAuthConfigRequest, opts ...grpc.CallOption) (*identityv1.GetAuthConfigResponse, error)
	RequestPasswordReset(ctx context.Context, in *identityv1.RequestPasswordResetRequest, opts ...grpc.CallOption) (*identityv1.RequestPasswordResetResponse, error)
	ResetPasswordWithCode(ctx context.Context, in *identityv1.ResetPasswordWithCodeRequest, opts ...grpc.CallOption) (*identityv1.ResetPasswordWithCodeResponse, error)
	RequestLoginOtp(ctx context.Context, in *identityv1.RequestLoginOtpRequest, opts ...grpc.CallOption) (*identityv1.RequestLoginOtpResponse, error)
	VerifyLoginOtp(ctx context.Context, in *identityv1.VerifyLoginOtpRequest, opts ...grpc.CallOption) (*identityv1.VerifyLoginOtpResponse, error)
}

// The sign-in method the page shows first.
const (
	LoginMethodLocal = "local"
	LoginMethodSSO   = "sso"
)

func normalizeLoginMethod(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), LoginMethodSSO) {
		return LoginMethodSSO
	}
	return LoginMethodLocal
}

// Handlers serves the routes.
type Handlers struct {
	identity           IdentityClient
	log                log.Logger
	defaultLoginMethod string
	passkeyLogin       bool
	passkeyViable      func(ctx context.Context) bool
	reportProblemURL   string
}

// Option configures Handlers.
type Option func(*Handlers)

// WithLogger sets the logger.
func WithLogger(l log.Logger) Option { return func(h *Handlers) { h.log = l } }

// WithDefaultLoginMethod sets the method the page shows first; anything but
// "sso" means local.
func WithDefaultLoginMethod(method string) Option {
	return func(h *Handlers) { h.defaultLoginMethod = normalizeLoginMethod(method) }
}

// WithPasskeyLogin offers the passkey button.
func WithPasskeyLogin(enabled bool) Option {
	return func(h *Handlers) { h.passkeyLogin = enabled }
}

// WithPasskeyViabilityProbe hides the passkey button while the probe says
// passkey sign-in can't complete.
func WithPasskeyViabilityProbe(probe func(ctx context.Context) bool) Option {
	return func(h *Handlers) { h.passkeyViable = probe }
}

// WithReportProblemURL sets the adopter's "report a problem" target the web
// links to; empty hides the link.
func WithReportProblemURL(url string) Option {
	return func(h *Handlers) { h.reportProblemURL = url }
}

// New builds the handlers.
func New(identity IdentityClient, opts ...Option) *Handlers {
	h := &Handlers{identity: identity, defaultLoginMethod: LoginMethodLocal}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func (h *Handlers) logger(ctx context.Context) log.Logger {
	if h.log == nil {
		return log.Nop()
	}
	return h.log.Ctx(ctx)
}

// ConfigHandler is GET /auth/config. With identity down it still answers,
// with the identity-backed flags off.
func (h *Handlers) ConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{
			"login2faEnabled":    false,
			"ssoAvailable":       false,
			"defaultLoginMethod": h.defaultLoginMethod,
			"passkeyEnabled":     h.passkeyEnabled(r.Context()),
			"reportProblemUrl":   h.reportProblemURL,
		}
		resp, err := h.identity.GetAuthConfig(r.Context(), &identityv1.GetAuthConfigRequest{})
		if err != nil {
			h.logger(r.Context()).Warn("auth config: identity call failed; flags off", log.F("error", err.Error()))
		} else {
			out["login2faEnabled"] = resp.GetLogin_2FaEnabled()
			out["ssoAvailable"] = resp.GetSsoAvailable()
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}

func (h *Handlers) passkeyEnabled(ctx context.Context) bool {
	if !h.passkeyLogin {
		return false
	}
	return h.passkeyViable == nil || h.passkeyViable(ctx)
}

// RequestResetHandler is POST /auth/password-reset/request {email}. The
// answer is the same whether or not the account exists.
func (h *Handlers) RequestResetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, msgUnreadable)
			return
		}
		if body.Email == "" {
			writeErr(w, http.StatusBadRequest, "Enter your email address.")
			return
		}
		if _, err := h.identity.RequestPasswordReset(r.Context(), &identityv1.RequestPasswordResetRequest{Email: body.Email}); err != nil {
			h.identityErr(w, r, "reset request", err)
			return
		}
		log.Trace(h.logger(r.Context()), "reset request: accepted", log.F("flow", "reset_request"))
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

// ConfirmResetHandler is POST /auth/password-reset/confirm {email, code,
// newPassword}.
func (h *Handlers) ConfirmResetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			Email       string `json:"email"`
			Code        string `json:"code"`
			NewPassword string `json:"newPassword"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, msgUnreadable)
			return
		}
		if body.Email == "" || body.Code == "" || body.NewPassword == "" {
			writeErr(w, http.StatusBadRequest, "Code and new password are required.")
			return
		}
		if _, err := h.identity.ResetPasswordWithCode(r.Context(), &identityv1.ResetPasswordWithCodeRequest{
			Email: body.Email, Code: body.Code, NewPassword: body.NewPassword,
		}); err != nil {
			h.identityErr(w, r, "reset confirm", err)
			return
		}
		log.Trace(h.logger(r.Context()), "reset confirm: password set", log.F("flow", "reset_confirm"))
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

// RequestLoginOtpHandler is POST /auth/login-otp/request {username}.
func (h *Handlers) RequestLoginOtpHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, msgUnreadable)
			return
		}
		if body.Username == "" {
			writeErr(w, http.StatusBadRequest, "Enter your username.")
			return
		}
		if _, err := h.identity.RequestLoginOtp(r.Context(), &identityv1.RequestLoginOtpRequest{Username: body.Username}); err != nil {
			h.identityErr(w, r, "login code request", err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

// VerifyLoginOtpHandler is POST /auth/login-otp/verify {username, code}. A
// wrong code is 200 {"verified": false}.
func (h *Handlers) VerifyLoginOtpHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			Username string `json:"username"`
			Code     string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, msgUnreadable)
			return
		}
		if body.Code == "" {
			writeErr(w, http.StatusBadRequest, "Enter the code we emailed you.")
			return
		}
		if body.Username == "" {
			writeErr(w, http.StatusBadRequest, "Enter your username.")
			return
		}
		resp, err := h.identity.VerifyLoginOtp(r.Context(), &identityv1.VerifyLoginOtpRequest{Username: body.Username, Code: body.Code})
		if err != nil {
			h.identityErr(w, r, "login code verify", err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"verified": resp.GetVerified()})
	}
}

const (
	msgUnreadable  = "That request could not be read. Reload the page and try again."
	msgInvalidCode = "That code is invalid or has expired. Request a new code, then try again."
	msgUnreachable = "We couldn't reach the sign-in service. Try again in a moment."
	msgServerFault = "Something went wrong on our end. Try again in a moment — if it keeps happening, contact support."
)

// identityErr maps an identity refusal to user-safe copy; the cause is only
// logged.
func (h *Handlers) identityErr(w http.ResponseWriter, r *http.Request, step string, err error) {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition:
		log.Trace(h.logger(r.Context()), step+": refused", log.F("code", status.Code(err).String()))
		writeErr(w, http.StatusBadRequest, msgInvalidCode)
	case codes.Unavailable:
		h.logger(r.Context()).Warn(step+": identity unavailable", log.F("error", err.Error()))
		writeErr(w, http.StatusServiceUnavailable, msgUnreachable)
	default:
		h.logger(r.Context()).Warn(step+": identity call failed", log.F("error", err.Error()))
		writeErr(w, http.StatusBadGateway, msgServerFault)
	}
}

// writeErr answers {"error", "kind"}: a 5xx is our failure (reach), the rest
// the caller's (business).
func writeErr(w http.ResponseWriter, code int, msg string) {
	kind := errcodes.KindBusiness
	if code >= http.StatusInternalServerError {
		kind = errcodes.KindReach
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg, "kind": string(kind)})
}

// Register mounts the routes on mux.
func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/config", h.ConfigHandler())
	mux.HandleFunc("POST /auth/password-reset/request", h.RequestResetHandler())
	mux.HandleFunc("POST /auth/password-reset/confirm", h.ConfirmResetHandler())
	mux.HandleFunc("POST /auth/login-otp/request", h.RequestLoginOtpHandler())
	mux.HandleFunc("POST /auth/login-otp/verify", h.VerifyLoginOtpHandler())
}
