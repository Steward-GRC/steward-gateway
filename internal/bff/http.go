// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	apperr "github.com/Bugs5382/go-apperr"
	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// CookieName is the browser session cookie. Its value is the session's store
// id and never leaves the gateway.
const CookieName = "steward_sid"

const (
	refreshThreshold = 30 * time.Second
	// refreshLockTTL outlives the Kratos client's 10 s timeout, so a live
	// winner always releases before the lock lapses.
	refreshLockTTL = 15 * time.Second
	// refreshWaitBudget is longer than the lock TTL, so a waiter can take over
	// from a winner that crashed.
	refreshWaitBudget   = 20 * time.Second
	refreshPollInterval = 20 * time.Millisecond
)

var (
	// ErrSessionRevoked reports the session vanished while waiting for a peer
	// to refresh it.
	ErrSessionRevoked = errors.New("session revoked during refresh")
	// ErrRefreshTimeout reports the single-flight wait ran out before the
	// winner published the refreshed session.
	ErrRefreshTimeout = errors.New("refresh single-flight timed out")
)

// Handler serves the /auth routes and builds the per-request principal. The
// zero value of every optional field is safe: an unwired dependency turns its
// route off (404 or 503) instead of failing open.
type Handler struct {
	Store  SessionStore
	TTL    time.Duration
	Secure bool

	// Auth is the Kratos client local sign-in, session refresh and logout go
	// through.
	Auth authClient
	// Identity resolves users, factors and SSO discovery.
	Identity IdentityClient

	Pending PendingStore
	MFA     MFAConfig

	// PasskeyLogin parks a passkey sign-in between begin and finish; nil
	// turns passkey sign-in off.
	PasskeyLogin PasskeyLoginStore

	Log        log.Logger
	AuthMetric metric.Int64Counter

	// Now is the clock for act-as expiry; nil means time.Now.
	Now func() time.Time
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) logger(ctx context.Context) log.Logger {
	if h.Log == nil {
		return log.Nop()
	}
	return h.Log.Ctx(ctx)
}

func errField(err error) log.Field {
	if err == nil {
		return log.F("error", "")
	}
	return log.F("error", err.Error())
}

// authOutcome records one auth decision as a log line and a metric tagged
// with the reason, so a 401 or 403 is never silent.
func (h *Handler) authOutcome(ctx context.Context, path, reason string, err error) {
	l := h.logger(ctx)
	switch reason {
	case "ok":
		log.Trace(l, "bff auth decision", log.F("path", path), log.F("reason", reason))
	case "store_error", "user_lookup_failed":
		l.Warn("bff auth decision", log.F("path", path), log.F("reason", reason), errField(err))
	default:
		l.Debug("bff auth decision", log.F("path", path), log.F("reason", reason))
	}
	if h.AuthMetric != nil {
		h.AuthMetric.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
	}
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) setCookie(w http.ResponseWriter, id string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: id, Path: "/", HttpOnly: true, Secure: h.Secure,
		// Lax, not Strict: the SSO callback lands through a cross-site
		// redirect, and Strict would drop the cookie on that first navigation.
		// Writes are guarded by the CSRF double-submit, not by SameSite.
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

// Login is POST /auth/login: a Kratos password sign-in, then either a session
// or, when a second factor is required, a pending id.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	l := h.logger(r.Context())
	var in struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Username == "" {
		l.Debug("local login: bad request", log.F("flow", "local_login"), log.F("reason", "invalid_request"))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	res, err := h.Auth.VerifyPassword(r.Context(), in.Username, in.Password)
	if errors.Is(err, ErrInvalidCredentials) {
		log.Trace(l, "local login: password rejected", log.F("flow", "local_login"), log.F("reason", "invalid_credentials"))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	if err != nil {
		l.Warn("local login: kratos unreachable", log.F("flow", "local_login"), errField(err), log.F("reason", "backend_unreachable"))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "auth_backend_unreachable"})
		return
	}
	h.finishPasswordLogin(w, r, res, "local_login")
}

// finishPasswordLogin maps a verified Kratos credential to the platform user
// and issues the session, or parks it for the second factor.
func (h *Handler) finishPasswordLogin(w http.ResponseWriter, r *http.Request, res AuthResult, flow string) {
	l := h.logger(r.Context())
	user, err := h.resolveUserByEmail(r.Context(), res.Email)
	if err != nil {
		if code, ok := apperr.Code(err); ok && code == errcodes.CodeKratosEmailNoPlatformUser {
			log.Trace(l, "sign-in: credential ok but no platform user", log.F("flow", flow), log.F("reason", "no_platform_user_for_email"))
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
			return
		}
		l.Warn("sign-in: identity lookup by email failed", log.F("flow", flow), errField(err), log.F("reason", "identity_unreachable"))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	if !user.GetEnabled() {
		log.Trace(l, "sign-in: platform user disabled", log.F("flow", flow), log.F("user_id", user.GetId()), log.F("reason", "user_disabled"))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	if h.mfaRequired(r) {
		log.Trace(l, "sign-in: password ok, second factor required", log.F("flow", flow), log.F("user_id", user.GetId()))
		h.loginWithMFA(w, r, res, user)
		return
	}
	log.Trace(l, "sign-in: session issued", log.F("flow", flow), log.F("user_id", user.GetId()), log.F("mfa_required", false))
	h.issueSession(w, r, Session{AccessToken: res.AccessToken, ExpiresAt: res.ExpiresAt, UserID: user.GetId()})
}

// newSession stores sess under a fresh id with a fresh CSRF token. Every
// session-issuing path goes through it, so the cookie and CSRF contract
// can't drift between them.
func (h *Handler) newSession(ctx context.Context, sess Session) (string, Session, error) {
	csrf, err := NewCSRFToken()
	if err != nil {
		return "", Session{}, err
	}
	id, err := newSessionID()
	if err != nil {
		return "", Session{}, err
	}
	sess.CSRFToken = csrf
	if err := h.Store.Create(ctx, id, sess); err != nil {
		return "", Session{}, err
	}
	return id, sess, nil
}

// issueSession is the JSON answer for the XHR sign-in flows: the cookie plus
// {"csrfToken"}.
func (h *Handler) issueSession(w http.ResponseWriter, r *http.Request, sess Session) {
	id, sess, err := h.newSession(r.Context(), sess)
	if err != nil {
		h.logger(r.Context()).Error(err, "sign-in: session store write failed", log.F("user_id", sess.UserID))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	h.setCookie(w, id, int(h.TTL.Seconds()))
	writeJSON(w, http.StatusOK, map[string]string{"csrfToken": sess.CSRFToken})
}

// Logout is POST /auth/logout. It revokes the Kratos session best-effort and
// always drops the local one, even when the store read fails.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		if sess, ok, err := h.Store.Get(r.Context(), c.Value); err == nil && ok && sess.AccessToken != "" && h.Auth != nil {
			if lerr := h.Auth.Logout(r.Context(), sess.AccessToken); lerr != nil {
				h.logger(r.Context()).Warn("logout: kratos revoke failed", log.F("user_id", sess.UserID), errField(lerr))
			}
		}
		_ = h.Store.Delete(r.Context(), c.Value)
	}
	h.setCookie(w, "", -1)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// Session is GET /auth/session, the web's boot probe: whether a session is
// live, its CSRF token and the user's email.
func (h *Handler) Session(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	sess, ok, _ := h.Store.Get(r.Context(), c.Value)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	resp := map[string]any{"authenticated": true, "csrfToken": sess.CSRFToken}
	if sess.UserID != "" && h.Identity != nil {
		if u, gerr := h.Identity.GetUser(r.Context(), &identityv1.GetUserRequest{UserId: sess.UserID}); gerr == nil {
			if email := u.GetUser().GetEmail(); email != "" {
				resp["email"] = email
			}
		} else {
			h.logger(r.Context()).Warn("session: identity GetUser failed; email omitted", log.F("user_id", sess.UserID), errField(gerr))
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// refreshSession single-flights the Kratos session extension for one session
// across every gateway replica: one caller extends, the rest wait and reuse
// the stored result.
func (h *Handler) refreshSession(ctx context.Context, sid string, sess Session) (Session, error) {
	deadline := time.Now().Add(refreshWaitBudget)
	for {
		token, won, err := h.Store.AcquireRefreshLock(ctx, sid, refreshLockTTL)
		if err != nil {
			return h.performRefresh(ctx, sid, sess)
		}
		if won {
			out, rerr := h.performRefresh(ctx, sid, sess)
			_ = h.Store.ReleaseRefreshLock(ctx, sid, token)
			return out, rerr
		}
		time.Sleep(refreshPollInterval)
		fresh, ok, gerr := h.Store.Get(ctx, sid)
		if gerr != nil {
			return sess, gerr
		}
		if !ok {
			return Session{}, ErrSessionRevoked
		}
		if time.Until(fresh.ExpiresAt) >= refreshThreshold {
			return fresh, nil
		}
		if time.Now().After(deadline) {
			return Session{}, ErrRefreshTimeout
		}
	}
}

// performRefresh re-reads the session (a peer may have refreshed it), then
// asks Kratos whoami for the new expiry and stores it.
func (h *Handler) performRefresh(ctx context.Context, sid string, sess Session) (Session, error) {
	if cur, ok, err := h.Store.Get(ctx, sid); err == nil && ok {
		sess = cur
		if time.Until(sess.ExpiresAt) >= refreshThreshold {
			return sess, nil
		}
	}
	res, err := h.Auth.Refresh(ctx, sess.AccessToken)
	if err != nil {
		return sess, err
	}
	sess.AccessToken = res.AccessToken
	sess.ExpiresAt = res.ExpiresAt
	_ = h.Store.Save(ctx, sid, sess)
	return sess, nil
}
