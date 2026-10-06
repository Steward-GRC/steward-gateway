// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"google.golang.org/grpc"
)

// UserByIDResolver is the identity lookup the per-request principal is built
// from.
type UserByIDResolver interface {
	GetUser(ctx context.Context, in *identityv1.GetUserRequest, opts ...grpc.CallOption) (*identityv1.GetUserResponse, error)
}

// ClaimsForUser resolves a platform user id to the Claims a request runs as.
type ClaimsForUser func(ctx context.Context, userID string) (principal.Claims, error)

// Authenticate gates a route on a live session: the session cookie, the
// X-CSRF-Token double-submit on every method, then identity's current record
// of the user, put on the context as the principal (and the go-grpc-actor
// Actor). Anything missing answers 401, a CSRF mismatch 403.
func (h *Handler) Authenticate(next http.Handler) http.Handler {
	return h.authenticate(next, false)
}

// AuthenticateSafeRead is Authenticate for a read-only route a browser loads
// as a subresource (an <img src>), which can't send a header: GET and HEAD
// skip the CSRF check, every other method keeps it. The route stays
// authenticated, and a handler mounted here must not change state on GET or
// HEAD. Cross-site subresource loads get no cookie (SameSite=Lax).
func (h *Handler) AuthenticateSafeRead(next http.Handler) http.Handler {
	return h.authenticate(next, true)
}

func (h *Handler) authenticate(next http.Handler, exemptSafeMethods bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil {
			h.authOutcome(r.Context(), r.URL.Path, "no_cookie", nil)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		sess, ok, err := h.Store.Get(r.Context(), c.Value)
		if err != nil {
			h.authOutcome(r.Context(), r.URL.Path, "store_error", err)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if !ok {
			h.authOutcome(r.Context(), r.URL.Path, "session_miss", nil)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		csrfRequired := !exemptSafeMethods || !SafeMethod(r.Method)
		if csrfRequired && !CSRFEqual(r.Header.Get("X-CSRF-Token"), sess.CSRFToken) {
			h.authOutcome(r.Context(), r.URL.Path, "csrf_mismatch", nil)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf"})
			return
		}
		if sess.AccessToken != "" && time.Until(sess.ExpiresAt) < refreshThreshold {
			refreshed, err := h.refreshSession(r.Context(), c.Value, sess)
			if err != nil {
				h.authOutcome(r.Context(), r.URL.Path, "refresh_failed", err)
				_ = h.Store.Delete(r.Context(), c.Value)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session_expired"})
				return
			}
			sess = refreshed
		}
		claims, err := h.claimsForSession(r.Context(), sess.UserID, SessionRef(c.Value))
		if err != nil {
			h.authOutcome(r.Context(), r.URL.Path, "user_lookup_failed", err)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		h.authOutcome(r.Context(), r.URL.Path, "ok", nil)
		ctx := WithSessionID(r.Context(), c.Value)
		ctx = principal.WithClaims(ctx, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SessionRef is the opaque session reference that rides on the Actor and in
// audit records. It is derived from the cookie value one way, so it can't be
// replayed as the cookie.
func SessionRef(sid string) string {
	sum := sha256.Sum256([]byte("steward-session-ref:" + sid))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func (h *Handler) claimsForSession(ctx context.Context, userID, ref string) (principal.Claims, error) {
	if userID == "" {
		return nil, errcodes.Wrap(errcodes.CodeKratosVerifyNoSessionPrincipal,
			errors.New("session carries no platform user"))
	}
	c, err := ClaimsForUserFromIdentity(h.Identity)(ctx, userID)
	if err != nil {
		return nil, err
	}
	s := c.(principal.Static)
	s.SessionIDValue = ref
	return s, nil
}

// ActAs applies a live act-as record on the caller's session: the target's
// Claims become the principal and the real admin is kept as the
// impersonator. It must run inside Authenticate.
func (h *Handler) ActAs(next http.Handler) http.Handler {
	return ImpersonationMiddleware(h.Store, ClaimsForUserFromIdentity(h.Identity), h.now)(next)
}

// ImpersonationMiddleware swaps the principal to the act-as target when the
// session holds a live record. An expired record is cleared and the request
// runs as the admin. A failed target lookup refuses the request rather than
// proceeding as the admin.
func ImpersonationMiddleware(store SessionStore, claimsForUser ClaimsForUser, now func() time.Time) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sid, sess, ok := impersonationSession(r, store)
			if !ok || sess.Impersonation == nil {
				next.ServeHTTP(w, r)
				return
			}
			if !sess.Impersonation.Active(now()) {
				sess.Impersonation = nil
				_ = store.Save(r.Context(), sid, sess)
				next.ServeHTTP(w, r)
				return
			}

			target, err := claimsForUser(r.Context(), sess.Impersonation.TargetUserID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "impersonation_target_lookup"})
				return
			}

			admin, ok := principal.FromContext(r.Context())
			if !ok {
				admin, err = claimsForUser(r.Context(), sess.Impersonation.AdminUserID)
				if err != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "impersonation_admin_lookup"})
					return
				}
			}
			if s, isStatic := target.(principal.Static); isStatic && s.SessionIDValue == "" {
				s.SessionIDValue = admin.SessionID()
				target = s
			}

			ctx := principal.WithImpersonator(r.Context(), admin)
			ctx = principal.WithClaims(ctx, target)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func impersonationSession(r *http.Request, store SessionStore) (string, Session, bool) {
	sid, ok := SessionIDFromContext(r.Context())
	if !ok {
		c, err := r.Cookie(CookieName)
		if err != nil {
			return "", Session{}, false
		}
		sid = c.Value
	}
	sess, ok, err := store.Get(r.Context(), sid)
	if err != nil || !ok {
		return "", Session{}, false
	}
	return sid, sess, true
}

// ResolveCookieSession resolves the session cookie on r to its live session,
// without the CSRF check. It is for raw websocket upgrades, where the browser
// can't send a header; a caller must close the cross-site path another way.
func (h *Handler) ResolveCookieSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return Session{}, false
	}
	sess, ok, err := h.Store.Get(r.Context(), c.Value)
	if err != nil || !ok {
		return Session{}, false
	}
	return sess, true
}

// HasSession reports whether r carries a live session. The co-editing
// websocket proxy uses it to refuse an anonymous upgrade before dialling;
// which draft the user may open stays with the co-editing token.
func (h *Handler) HasSession(r *http.Request) bool {
	_, ok := h.ResolveCookieSession(r)
	return ok
}

// ErrWebsocketUnauthorized is returned by WebsocketInit when the upgrade
// carries no live session or the wrong CSRF token.
var ErrWebsocketUnauthorized = errors.New("ws: unauthorized")

// WebsocketInit authenticates a GraphQL websocket from its upgrade request:
// the session cookie, plus the CSRF token the client sends in the
// connection_init payload (the websocket's double-submit). It returns ctx
// carrying the principal. Act-as doesn't apply to subscriptions.
func (h *Handler) WebsocketInit(ctx context.Context, r *http.Request, csrf string) (context.Context, error) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ctx, ErrWebsocketUnauthorized
	}
	sess, ok := h.ResolveCookieSession(r)
	if !ok || !CSRFEqual(csrf, sess.CSRFToken) {
		return ctx, ErrWebsocketUnauthorized
	}
	claims, err := h.claimsForSession(ctx, sess.UserID, SessionRef(c.Value))
	if err != nil {
		return ctx, fmt.Errorf("%w: %v", ErrWebsocketUnauthorized, err)
	}
	return principal.WithClaims(ctx, claims), nil
}

// ClaimsForUserFromIdentity builds the ClaimsForUser lookup on identity's
// GetUser. A missing or disabled user fails closed.
func ClaimsForUserFromIdentity(users UserByIDResolver) ClaimsForUser {
	return func(ctx context.Context, userID string) (principal.Claims, error) {
		if userID == "" {
			return nil, errcodes.Wrap(errcodes.CodeKratosSessionUserLookupFailed,
				errors.New("resolve claims with an empty user id"))
		}
		resp, err := users.GetUser(ctx, &identityv1.GetUserRequest{UserId: userID})
		if err != nil {
			return nil, errcodes.Wrap(errcodes.CodeKratosSessionUserLookupFailed,
				fmt.Errorf("resolve user %q: %w", userID, err))
		}
		u := resp.GetUser()
		if u == nil {
			return nil, errcodes.Wrap(errcodes.CodeKratosSessionUserLookupFailed,
				fmt.Errorf("identity returned no user for %q", userID))
		}
		if !u.GetEnabled() {
			return nil, errcodes.Wrap(errcodes.CodeKratosSessionUserLookupFailed,
				fmt.Errorf("user %q is disabled", userID))
		}
		return claimsFromIdentityUser(u), nil
	}
}

func claimsFromIdentityUser(u *identityv1.User) principal.Claims {
	scoped := make([]principal.ScopedRole, 0, len(u.GetScopedRoles()))
	for _, sr := range u.GetScopedRoles() {
		scoped = append(scoped, principal.ScopedRole{Role: sr.GetRole(), Category: sr.GetCategory()})
	}
	overrides := make([]principal.Override, 0, len(u.GetPolicyOverrides()))
	for _, o := range u.GetPolicyOverrides() {
		overrides = append(overrides, principal.Override{
			PolicyNumber: o.GetPolicyNumber(),
			Effect:       overrideEffectString(o.GetEffect()),
		})
	}
	return principal.Static{
		UserIDValue:          u.GetId(),
		EmailValue:           u.GetEmail(),
		RolesValue:           append([]string{}, u.GetRoles()...),
		GroupsValue:          append([]string{}, u.GetGroups()...),
		IdpGroupsValue:       append([]string{}, u.GetIdpGroups()...),
		ScopedRolesValue:     scoped,
		PolicyOverridesValue: overrides,
		IsRootValue:          u.GetIsRoot(),
		ReadSensitiveValue:   u.GetReadSensitiveGrant(),
	}
}

func overrideEffectString(e identityv1.OverrideEffect) string {
	switch e {
	case identityv1.OverrideEffect_OVERRIDE_EFFECT_ALLOW:
		return "allow"
	case identityv1.OverrideEffect_OVERRIDE_EFFECT_DENY:
		return "deny"
	default:
		return ""
	}
}
