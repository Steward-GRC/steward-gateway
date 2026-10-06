// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	apperr "github.com/Bugs5382/go-apperr"
	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ssoStateTTL bounds the round trip through the IdP.
const ssoStateTTL = 10 * time.Minute

const (
	ssoCallbackPath        = "/auth/sso/callback"
	defaultAdminReturnPath = "/admin/organizations"
	// ssoMfaResumePath is the web route an SSO sign-in that owes a second
	// factor lands on, with the pending id in the query.
	ssoMfaResumePath = "/login"
)

func (h *Handler) ssoRedirectURI() string { return h.SSORedirectBase + ssoCallbackPath }

// SSOStart is GET /auth/sso/start?connection=&mode=login|test&connectionId=
// &identifier=&tenant=&returnPath=&testToken=. It parks the state and sends
// the browser to Polis. Test mode needs a site admin's session or a live test
// link.
func (h *Handler) SSOStart(w http.ResponseWriter, r *http.Request) {
	l := h.logger(r.Context())
	q := r.URL.Query()
	connection := q.Get("connection")
	mode := q.Get("mode")
	if mode == "" {
		mode = "login"
	}
	connectionID := q.Get("connectionId")
	returnPath := validateAdminReturnPath(q.Get("returnPath"))

	var (
		fromTestLink bool
		linkTenant   string
		adminUserID  string
	)
	if tok := q.Get("testToken"); tok != "" && h.SSOTestLink != nil {
		rec, ok, err := h.SSOTestLink.GetSSOTestLink(r.Context(), tok)
		if err != nil || !ok {
			l.Warn("sso start: test link expired or unknown", log.F("flow", "sso_start"), log.F("reason", "test_link_invalid"), errField(err))
			h.writeTestLinkExpired(w)
			return
		}
		fromTestLink = true
		mode = "test"
		connection = rec.Alias
		connectionID = rec.ConnectionID
		returnPath = rec.ReturnPath
		linkTenant = rec.Tenant
		adminUserID = rec.AdminUserID
	}

	if connection == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	log.Trace(l, "sso start", log.F("flow", "sso_start"), log.F("mode", mode), log.F("connection", connection), log.F("from_test_link", fromTestLink))

	if mode == "test" && !fromTestLink {
		uid, ok := h.ssoAdminSessionUserID(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not_authorized"})
			return
		}
		if _, ok := h.ssoAdminContext(r, uid); !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "not_authorized"})
			return
		}
		adminUserID = uid
	}

	if h.Polis == nil {
		l.Warn("sso start: no SSO broker configured", log.F("flow", "sso_start"), log.F("reason", "sso_unwired"))
		h.ssoFail(w, r, mode, http.StatusServiceUnavailable, "sso_unavailable", "/login?error=sso")
		return
	}

	if mode == "login" && h.Identity != nil && !h.ssoConnectionActive(r.Context(), connection, q.Get("identifier")) {
		http.Redirect(w, r, "/login?error=sso_not_active", http.StatusFound)
		return
	}

	tenant := polisTenant(r)
	if fromTestLink && linkTenant != "" {
		tenant = linkTenant
	}
	if tenant == "" {
		l.Warn("sso start: no tenant", log.F("flow", "sso_start"), log.F("mode", mode), log.F("reason", "no_derivable_tenant"))
		h.ssoFail(w, r, mode, http.StatusBadRequest, "invalid_request", "/login?error=sso")
		return
	}

	state, err := GenerateState()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	if err := h.SSOState.PutSSOState(r.Context(), state, SSOState{
		Connection:   connection,
		Mode:         mode,
		ConnectionID: connectionID,
		ReturnPath:   returnPath,
		Tenant:       tenant,
		AdminUserID:  adminUserID,
	}, ssoStateTTL); err != nil {
		l.Error(err, "sso start: could not park the state", log.F("flow", "sso_start"))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	log.Trace(l, "sso start: redirecting to the broker", log.F("flow", "sso_start"), log.F("mode", mode), log.F("connection", connection), log.F("tenant", tenant))
	http.Redirect(w, r, h.Polis.AuthorizeURL(h.ssoRedirectURI(), state, tenant, h.Polis.product), http.StatusFound)
}

// ssoFail answers a test-mode failure as JSON (the admin page fetched it) and
// a login-mode one as a redirect (the browser navigated).
func (h *Handler) ssoFail(w http.ResponseWriter, r *http.Request, mode string, code int, errName, loginRedirect string) {
	if mode == "test" {
		writeJSON(w, code, map[string]string{"error": errName})
		return
	}
	http.Redirect(w, r, loginRedirect, http.StatusFound)
}

// ssoConnectionActive asks identity's Discover whether the connection is live
// (verified, enabled and tested) for this identifier. Anything short of a
// clear yes is a no. An empty connection, as on an IdP-initiated sign-in,
// only needs an SSO verdict.
func (h *Handler) ssoConnectionActive(ctx context.Context, connection, identifier string) bool {
	l := h.logger(ctx)
	if h.Identity == nil || identifier == "" {
		l.Debug("sso active check: cannot run", log.F("flow", "sso_active_gate"), log.F("connection", connection), log.F("reason", "missing_identifier"))
		return false
	}
	res, err := h.Identity.Discover(ctx, &identityv1.DiscoverRequest{Identifier: identifier})
	if err != nil {
		l.Warn("sso active check: Discover failed", log.F("flow", "sso_active_gate"), log.F("connection", connection), errField(err))
		return false
	}
	active := res.GetMethod() == "sso" && (connection == "" || res.GetConnectionAlias() == connection)
	log.Trace(l, "sso active check", log.F("flow", "sso_active_gate"), log.F("connection", connection),
		log.F("discover_method", res.GetMethod()), log.F("discover_alias", res.GetConnectionAlias()), log.F("active", active))
	return active
}

// SSOIdpInitiated is POST /auth/sso/idp-initiated: an IdP-initiated sign-in
// with no known connection. The callback resolves the user by email and runs
// the active check then.
func (h *Handler) SSOIdpInitiated(w http.ResponseWriter, r *http.Request) {
	l := h.logger(r.Context())
	if h.Polis == nil {
		l.Warn("sso idp-initiated: no SSO broker configured", log.F("flow", "sso_idp_init"), log.F("reason", "sso_unwired"))
		http.Redirect(w, r, "/login?error=sso", http.StatusFound)
		return
	}
	state, err := GenerateState()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	if err := h.SSOState.PutSSOState(r.Context(), state, SSOState{Mode: "login"}, ssoStateTTL); err != nil {
		l.Error(err, "sso idp-initiated: could not park the state", log.F("flow", "sso_idp_init"))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	http.Redirect(w, r, h.Polis.AuthorizeURL(h.ssoRedirectURI(), state, "", h.Polis.product), http.StatusFound)
}

// SSOCallback is GET /auth/sso/callback?code=&state=, where Polis returns the
// browser. The state is single-use and every failure issues no session.
func (h *Handler) SSOCallback(w http.ResponseWriter, r *http.Request) {
	l := h.logger(r.Context())
	code, state := r.URL.Query().Get("code"), r.URL.Query().Get("state")
	st, ok, err := h.SSOState.TakeSSOState(r.Context(), state)
	if err != nil || !ok {
		l.Warn("sso callback: unknown or expired state", log.F("flow", "sso_callback"), log.F("has_code", code != ""), log.F("reason", "invalid_state"), errField(err))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_state"})
		return
	}
	if code == "" {
		l.Warn("sso callback: no code", log.F("flow", "sso_callback"), log.F("mode", st.Mode), log.F("reason", "no_code"))
		h.ssoFail(w, r, st.Mode, http.StatusBadRequest, "invalid_state", "/login?error=sso")
		return
	}
	if h.Polis == nil {
		l.Warn("sso callback: no SSO broker configured", log.F("flow", "sso_callback"), log.F("reason", "sso_unwired"))
		h.ssoFail(w, r, st.Mode, http.StatusServiceUnavailable, "sso_unavailable", "/login?error=sso")
		return
	}
	if st.Mode == "test" {
		h.ssoTestCallback(w, r, st, code)
		return
	}
	h.ssoLoginCallback(w, r, st, code)
}

// ssoTestCallback finishes a connection test. It records the real outcome at
// identity, as the admin who started it, and never issues a session.
func (h *Handler) ssoTestCallback(w http.ResponseWriter, r *http.Request, st SSOState, code string) {
	l := h.logger(r.Context())
	adminCtx, ok := h.ssoAdminContext(r, st.AdminUserID)
	if !ok {
		h.redirectSSOTestResult(w, r, st.ReturnPath, false, "not_authorized")
		return
	}

	success, detail := true, ""
	tok, err := h.Polis.CodeExchange(r.Context(), code, h.ssoRedirectURI())
	if err != nil {
		success, detail = false, "code_exchange_failed"
		l.Warn("sso test: code exchange failed", log.F("flow", "sso_test_callback"), log.F("connection_id", st.ConnectionID), errField(err))
	} else if profile, uerr := h.Polis.UserInfo(r.Context(), tok.AccessToken); uerr != nil || profile.Email == "" {
		success, detail = false, "no_email_claim"
		l.Warn("sso test: userinfo carried no email", log.F("flow", "sso_test_callback"), log.F("connection_id", st.ConnectionID), errField(uerr))
	}

	if h.IdPTestRecorder == nil {
		l.Warn("sso test: no recorder wired", log.F("flow", "sso_test_callback"), log.F("reason", "recorder_unavailable"))
		h.redirectSSOTestResult(w, r, st.ReturnPath, false, "recorder_unavailable")
		return
	}
	if err := h.IdPTestRecorder(adminCtx, st.ConnectionID, success, detail); err != nil {
		l.Warn("sso test: recording the result failed", log.F("flow", "sso_test_callback"), log.F("connection_id", st.ConnectionID), errField(err))
		h.redirectSSOTestResult(w, r, st.ReturnPath, false, "record_failed")
		return
	}
	log.Trace(l, "sso test: result recorded", log.F("flow", "sso_test_callback"), log.F("connection_id", st.ConnectionID), log.F("success", success), log.F("detail", detail))
	h.writeSSOTestResult(w, r, st.ReturnPath, success, detail)
}

// ssoAdminSessionUserID reads the platform user id off the caller's session
// cookie.
func (h *Handler) ssoAdminSessionUserID(r *http.Request) (string, bool) {
	_, sess, ok := h.sessionByCookie(r)
	if !ok || sess.UserID == "" {
		h.logger(r.Context()).Debug("sso admin check: no signed-in session", log.F("flow", "sso_admin_auth"), log.F("reason", "no_session"))
		return "", false
	}
	return sess.UserID, true
}

// ssoAdminContext checks that userID is an enabled site admin and returns a
// context carrying that admin as the principal, so the identity call that
// records the test runs as them.
func (h *Handler) ssoAdminContext(r *http.Request, userID string) (context.Context, bool) {
	l := h.logger(r.Context())
	if h.Identity == nil || userID == "" {
		return nil, false
	}
	resp, err := h.Identity.GetUser(r.Context(), &identityv1.GetUserRequest{UserId: userID})
	if err != nil {
		l.Warn("sso admin check: GetUser failed", log.F("flow", "sso_admin_auth"), log.F("user_id", userID), errField(err))
		return nil, false
	}
	u := resp.GetUser()
	if u == nil || !u.GetEnabled() {
		l.Debug("sso admin check: user missing or disabled", log.F("flow", "sso_admin_auth"), log.F("user_id", userID))
		return nil, false
	}
	claims := claimsFromIdentityUser(u)
	if !principal.HasRole(claims, siteAdminRole) {
		l.Debug("sso admin check: not a site admin", log.F("flow", "sso_admin_auth"), log.F("user_id", userID), log.F("reason", "not_site_admin"))
		return nil, false
	}
	return principal.WithClaims(r.Context(), claims), true
}

// validateAdminReturnPath accepts only a same-origin path under /admin/;
// anything else becomes the organisations page.
func validateAdminReturnPath(raw string) string {
	if raw == "" || strings.Contains(raw, `\`) || strings.HasPrefix(raw, "//") {
		return defaultAdminReturnPath
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || !strings.HasPrefix(u.Path, "/admin/") {
		return defaultAdminReturnPath
	}
	return raw
}

func ssoTestResultPath(returnPath string, passed bool, reason string) string {
	if returnPath == "" {
		returnPath = defaultAdminReturnPath
	}
	result := "test=passed"
	if !passed {
		result = "test=failed"
		if reason != "" {
			result += "&reason=" + url.QueryEscape(reason)
		}
	}
	sep := "?"
	if strings.Contains(returnPath, "?") {
		sep = "&"
	}
	return returnPath + sep + result
}

func (h *Handler) redirectSSOTestResult(w http.ResponseWriter, r *http.Request, returnPath string, passed bool, reason string) {
	http.Redirect(w, r, ssoTestResultPath(returnPath, passed, reason), http.StatusFound)
}

// ssoAppOrigin is the postMessage target origin, never "*".
func (h *Handler) ssoAppOrigin(r *http.Request) string {
	if u, err := url.Parse(h.SSORedirectBase); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	if r.Host != "" {
		scheme := "https"
		if r.TLS == nil && !h.Secure {
			scheme = "http"
		}
		return scheme + "://" + r.Host
	}
	return ""
}

// ssoTestResultHTMLTmpl hands the result to the admin page that opened the
// test in a popup, then closes it; without an opener or script it falls back
// to the redirect. The placeholders are the escaped fallback URL, then the
// message, the origin and the fallback as JSON literals.
const ssoTestResultHTMLTmpl = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex">
<title>Connection test</title>
<noscript><meta http-equiv="refresh" content="0; url=%s"></noscript>
<script>
(function () {
  var msg = %s;
  var origin = %s;
  var fallback = %s;
  try {
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(msg, origin);
      window.close();
      return;
    }
  } catch (e) {}
  window.location.replace(fallback);
})();
</script></head>
<body>You can close this window.</body></html>`

func (h *Handler) writeSSOTestResult(w http.ResponseWriter, r *http.Request, returnPath string, passed bool, reason string) {
	fallback := ssoTestResultPath(returnPath, passed, reason)
	origin := h.ssoAppOrigin(r)
	if origin == "" {
		http.Redirect(w, r, fallback, http.StatusFound)
		return
	}
	msg, _ := json.Marshal(map[string]any{"type": "idp-test-result", "success": passed, "detail": reason})
	originJSON, _ := json.Marshal(origin)
	fallbackJSON, _ := json.Marshal(fallback)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, ssoTestResultHTMLTmpl, html.EscapeString(fallback), msg, originJSON, fallbackJSON)
}

const testLinkExpiredHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Test link expired</title></head>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.5">
<h1 style="font-size:1.25rem">This IdP test link has expired</h1>
<p>The test link you followed is no longer valid. Ask the administrator
who sent it to generate a new one and share it with you.</p>
</body></html>`

func (h *Handler) writeTestLinkExpired(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusGone)
	_, _ = w.Write([]byte(testLinkExpiredHTML))
}

// ssoLoginCallback finishes a brokered sign-in: code to token, token to
// profile, email to platform user (provisioned on first sight), then a
// session or the second-factor step.
func (h *Handler) ssoLoginCallback(w http.ResponseWriter, r *http.Request, st SSOState, code string) {
	l := h.logger(r.Context())
	tok, err := h.Polis.CodeExchange(r.Context(), code, h.ssoRedirectURI())
	if err != nil {
		l.Warn("sso callback: code exchange failed", log.F("flow", "sso_callback"), errField(err), log.F("reason", "code_exchange_failed"))
		http.Redirect(w, r, "/login?error=sso_exchange", http.StatusFound)
		return
	}
	profile, err := h.Polis.UserInfo(r.Context(), tok.AccessToken)
	if err != nil {
		l.Warn("sso callback: userinfo failed", log.F("flow", "sso_callback"), errField(err), log.F("reason", "userinfo_failed"))
		http.Redirect(w, r, "/login?error=sso_exchange", http.StatusFound)
		return
	}
	if profile.Email == "" {
		l.Warn("sso callback: userinfo carried no email", log.F("flow", "sso_callback"), log.F("reason", "no_email"))
		http.Redirect(w, r, "/login?error=sso_no_email", http.StatusFound)
		return
	}

	user, provisioned, err := h.resolveSSOUser(r.Context(), profile, st.Connection)
	if err != nil {
		if c, ok := apperr.Code(err); ok && c == errcodes.CodePolisJitProvisionFailed {
			http.Redirect(w, r, "/login?error=sso_error", http.StatusFound)
			return
		}
		l.Warn("sso callback: user lookup by email failed", log.F("flow", "sso_callback"), errField(err), log.F("reason", "resolve_by_email_failed"))
		http.Redirect(w, r, "/login?error=sso_provision", http.StatusFound)
		return
	}
	if !user.GetEnabled() {
		l.Debug("sso callback: user disabled", log.F("flow", "sso_callback"), log.F("user_id", user.GetId()), log.F("reason", "user_disabled"))
		http.Redirect(w, r, "/login?error=sso_no_user", http.StatusFound)
		return
	}
	if !h.ssoConnectionActive(r.Context(), st.Connection, profile.Email) {
		l.Warn("sso callback: connection not active", log.F("flow", "sso_callback"), log.F("connection", st.Connection), log.F("reason", "connection_not_active"))
		http.Redirect(w, r, "/login?error=sso_not_active", http.StatusFound)
		return
	}
	if h.mfaRequired(r) {
		h.ssoLoginWithMFA(w, r, user)
		return
	}

	id, _, err := h.newSession(r.Context(), Session{UserID: user.GetId(), ExpiresAt: time.Now().Add(h.TTL)})
	if err != nil {
		l.Error(err, "sso callback: session store write failed", log.F("flow", "sso_callback"), log.F("user_id", user.GetId()))
		http.Redirect(w, r, "/login?error=sso_session", http.StatusFound)
		return
	}
	h.setCookie(w, id, int(h.TTL.Seconds()))
	log.Trace(l, "sso callback: session issued", log.F("flow", "sso_callback"), log.F("user_id", user.GetId()), log.F("jit_provisioned", provisioned))
	http.Redirect(w, r, "/home", http.StatusFound)
}

// resolveSSOUser finds the platform user by email and provisions one on the
// first sign-in, passing the connection alias so identity applies its group
// mappings.
func (h *Handler) resolveSSOUser(ctx context.Context, p PolisProfile, connectionAlias string) (*identityv1.User, bool, error) {
	resp, err := h.Identity.GetUserByEmail(ctx, &identityv1.GetUserByEmailRequest{Email: p.Email})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, false, err
	}
	if err == nil && resp.GetUser() != nil {
		return resp.GetUser(), false, nil
	}
	l := h.logger(ctx)
	log.Trace(l, "sso callback: first sign-in, provisioning", log.F("flow", "sso_callback"), log.F("connection", connectionAlias))
	jit, err := h.Identity.JitProvisionByEmail(ctx, &identityv1.JitProvisionByEmailRequest{
		Email:           p.Email,
		FirstName:       p.FirstName,
		LastName:        p.LastName,
		ConnectionAlias: connectionAlias,
	})
	if err != nil {
		l.Warn("sso callback: provisioning failed", log.F("flow", "sso_callback"), log.F("connection", connectionAlias), errField(err))
		return nil, false, errcodes.Wrap(errcodes.CodePolisJitProvisionFailed, fmt.Errorf("polis: JIT-by-email failed: %w", err))
	}
	if jit.GetUser() == nil {
		return nil, false, errcodes.Wrap(errcodes.CodePolisJitProvisionFailed, errors.New("polis: JitProvisionByEmail returned no user"))
	}
	return jit.GetUser(), true, nil
}

// ssoLoginWithMFA parks an SSO sign-in for the second factor and sends the
// browser to the web's challenge page. A user with only the email factor gets
// the code sent straight away.
func (h *Handler) ssoLoginWithMFA(w http.ResponseWriter, r *http.Request, user *identityv1.User) {
	l := h.logger(r.Context())
	factorsResp, err := h.Identity.ListUserFactors(r.Context(), &identityv1.ListUserFactorsRequest{UserId: user.GetId()})
	if err != nil {
		l.Warn("sso mfa: ListUserFactors failed", log.F("flow", "sso_mfa"), log.F("user_id", user.GetId()), errField(err))
		http.Redirect(w, r, "/login?error=sso_mfa", http.StatusFound)
		return
	}
	kinds := factorKinds(factorsResp.GetFactors())
	hasStrong := hasStrongFactor(kinds)
	if !hasStrong && !factorOffered(kinds, factorEmail) {
		l.Warn("sso mfa: no usable factor", log.F("flow", "sso_mfa"), log.F("user_id", user.GetId()), log.F("reason", "no_usable_factor"))
		http.Redirect(w, r, "/login?error=sso_mfa", http.StatusFound)
		return
	}
	pendingID, err := h.createPending(r.Context(), "", time.Now().Add(h.TTL), user.GetId(), kinds, false)
	if err != nil {
		l.Error(err, "sso mfa: could not park the pending sign-in", log.F("flow", "sso_mfa"), log.F("user_id", user.GetId()))
		http.Redirect(w, r, "/login?error=sso_mfa", http.StatusFound)
		return
	}
	if !hasStrong {
		if _, err := h.Identity.SendEmailOtp(r.Context(), &identityv1.SendEmailOtpRequest{UserId: user.GetId(), Purpose: mfaLoginPurpose}); err != nil {
			l.Warn("sso mfa: email code send failed", log.F("flow", "sso_mfa"), log.F("user_id", user.GetId()), errField(err))
			http.Redirect(w, r, "/login?error=sso_mfa", http.StatusFound)
			return
		}
	}
	log.Trace(l, "sso mfa: pending parked", log.F("flow", "sso_mfa"), log.F("user_id", user.GetId()), log.F("factors", kinds))
	http.Redirect(w, r, ssoMfaResumeURL(pendingID, kinds), http.StatusFound)
}

func ssoMfaResumeURL(pendingID string, kinds []string) string {
	q := url.Values{}
	q.Set("pendingMfa", pendingID)
	if len(kinds) > 0 {
		q.Set("mfaFactors", strings.Join(kinds, ","))
	}
	return ssoMfaResumePath + "?" + q.Encode()
}
