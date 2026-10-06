// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

// bodySnippet reads up to a bounded number of bytes from a response body for
// diagnostic logging of a non-2xx Kratos reply (the shape of the error, never a
// secret — recovery/settings error bodies are Kratos ui/messages JSON, not the
// code). Only ever called on a branch that does NOT also decode the body.
func bodySnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 512))
	return strings.TrimSpace(string(b))
}

// ErrRecoveryIdentityNotFound is returned by CreateRecoveryCode when no Kratos
// identity matches the supplied recovery email. The password-reset request
// endpoint swallows it and still answers 200 {"ok":true} (anti-enumeration):
// a caller must not be able to tell an unknown email apart from a known one.
var ErrRecoveryIdentityNotFound = errors.New("kratos: no identity for recovery email")

// ErrInvalidRecoveryCode is returned by SubmitRecoveryCodeAndReset when the
// recovery code is wrong/expired (or the flow otherwise fails to reach a
// privileged session) or the new password is rejected. The confirm endpoint
// maps it to a plain 400 {"error":…} — never a coded internal error — the same
// way ErrInvalidCredentials maps to a 401.
var ErrInvalidRecoveryCode = errors.New("kratos: invalid or expired recovery code")

// kratosLoginFlow is the subset of Ory Kratos's login Flow object
// (GET /self-service/login/api) this client needs: just the flow id the
// subsequent POST targets.
type kratosLoginFlow struct {
	ID string `json:"id"`
}

// kratosIdentity is the part of a Kratos identity the gateway reads. The
// identity schema must carry an "email" trait.
type kratosIdentity struct {
	ID     string `json:"id"`
	Traits struct {
		Email string `json:"email"`
	} `json:"traits"`
}

// kratosSession is the subset of Ory Kratos's Session object this client
// needs, shared by the login response's embedded session and the
// /sessions/whoami response (same shape in both places).
type kratosSession struct {
	Active    bool           `json:"active"`
	ExpiresAt time.Time      `json:"expires_at"`
	Identity  kratosIdentity `json:"identity"`
}

// kratosLoginResponse is Ory Kratos's SuccessfulNativeLogin response
// (POST /self-service/login?flow=... on a 200): the bearer session_token the
// headless caller must present on every subsequent authenticated request,
// plus the session it belongs to.
type kratosLoginResponse struct {
	SessionToken string        `json:"session_token"`
	Session      kratosSession `json:"session"`
}

// KratosClient implements authClient against Ory Kratos's API (not browser)
// login flow: GET the flow, POST the password method, and the whoami
// endpoint for Refresh. No cookies are ever set or read — session_token is a
// bearer the caller stores itself.
type KratosClient struct {
	publicURL, adminURL string
	http                *http.Client
	log                 log.Logger
}

// NewKratosClient constructs a KratosClient against Kratos's public API
// (login/whoami/logout) and admin API (reserved for future admin-only calls;
// not used by any method in this task).
func NewKratosClient(publicURL, adminURL string) *KratosClient {
	return &KratosClient{publicURL: publicURL, adminURL: adminURL, http: &http.Client{Timeout: 10 * time.Second}}
}

// WithLogger sets the logger the client's flows log through.
func (c *KratosClient) WithLogger(l log.Logger) *KratosClient {
	c.log = l
	return c
}

func (c *KratosClient) logger(ctx context.Context) log.Logger {
	if c.log == nil {
		return log.Nop()
	}
	return c.log.Ctx(ctx)
}

// get issues a GET against the Kratos public API, optionally with a bearer
// Authorization header (whoami requires it; the login-flow init does not).
func (c *KratosClient) get(ctx context.Context, endpoint, bearer string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) // #nosec G704 -- endpoint is built from c.publicURL/c.adminURL (NewKratosClient config) + fixed path segments, with any dynamic component (flow id, email) url.QueryEscape'd; not user-controlled. SSRF not reachable
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return c.http.Do(req) // #nosec G704 -- request targets a c.publicURL/c.adminURL endpoint from trusted config (dynamic parts QueryEscape'd); not user-controlled. SSRF not reachable
}

// postJSON issues a JSON POST against a Kratos API endpoint — the login method
// submission, the logout-by-token call, and the recovery-code submit all use
// this shape. Cookie-threaded POSTs (the settings submit) use postJSONCookies.
func (c *KratosClient) postJSON(ctx context.Context, endpoint string, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b)) // #nosec G704 -- endpoint is built from c.publicURL/c.adminURL (NewKratosClient config) + fixed path segments, with any dynamic component (flow id) url.QueryEscape'd; not user-controlled. SSRF not reachable
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return c.http.Do(req) // #nosec G704 -- request targets a c.publicURL/c.adminURL endpoint from trusted config (dynamic parts QueryEscape'd); not user-controlled. SSRF not reachable
}

func sessionToAuthResult(sessionToken string, sess kratosSession) AuthResult {
	return AuthResult{
		AccessToken: sessionToken,
		ExpiresAt:   sess.ExpiresAt,
		Subject:     sess.Identity.ID,
		Email:       sess.Identity.Traits.Email,
	}
}

// VerifyPassword runs Kratos's headless API login flow: initialize the flow,
// then submit the password method against it. On success the returned
// AuthResult carries the session_token as AccessToken (no RefreshToken — see
// AuthResult's doc) and the identity's id/email as Subject/Email.
func (c *KratosClient) VerifyPassword(ctx context.Context, username, password string) (AuthResult, error) {
	initRes, err := c.get(ctx, c.publicURL+"/self-service/login/api", "")
	if err != nil {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: init login flow: %w", err))
	}
	defer func() { _ = initRes.Body.Close() }()
	if initRes.StatusCode != http.StatusOK {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosLoginFlowInitFailed, fmt.Errorf("kratos: init login flow: unexpected status %d", initRes.StatusCode))
	}
	var flow kratosLoginFlow
	if err := json.NewDecoder(initRes.Body).Decode(&flow); err != nil || flow.ID == "" {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosLoginFlowInitFailed, fmt.Errorf("kratos: decode login flow: %w", err))
	}

	submitURL := c.publicURL + "/self-service/login?flow=" + url.QueryEscape(flow.ID)
	subRes, err := c.postJSON(ctx, submitURL, map[string]string{
		"method":     "password",
		"identifier": username,
		"password":   password,
	})
	if err != nil {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: submit login: %w", err))
	}
	defer func() { _ = subRes.Body.Close() }()

	if subRes.StatusCode == http.StatusBadRequest {
		return AuthResult{}, ErrInvalidCredentials
	}
	if subRes.StatusCode != http.StatusOK {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosPasswordVerifyFailed, fmt.Errorf("kratos: submit login: unexpected status %d", subRes.StatusCode))
	}
	var lr kratosLoginResponse
	if err := json.NewDecoder(subRes.Body).Decode(&lr); err != nil || lr.SessionToken == "" {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosPasswordVerifyFailed, fmt.Errorf("kratos: decode login response: %w", err))
	}
	return sessionToAuthResult(lr.SessionToken, lr.Session), nil
}

// Refresh satisfies authClient by validating/extending a Kratos session:
// Kratos has no OAuth refresh grant, so this calls /sessions/whoami with the
// session_token as bearer. An active session returns a fresh AuthResult
// carrying the SAME token (session_token is opaque and long-lived; whoami
// does not rotate it) with an updated ExpiresAt. An inactive/expired/unknown
// session — whoami answers 401 — returns ErrInvalidCredentials so the caller
// fails closed and forces re-login, exactly as KCClient.Refresh does on a
// rejected refresh_token.
func (c *KratosClient) Refresh(ctx context.Context, sessionToken string) (AuthResult, error) {
	res, err := c.get(ctx, c.publicURL+"/sessions/whoami", sessionToken)
	if err != nil {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: whoami: %w", err))
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return AuthResult{}, ErrInvalidCredentials
	}
	if res.StatusCode != http.StatusOK {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosSessionRefreshFailed, fmt.Errorf("kratos: whoami: unexpected status %d", res.StatusCode))
	}
	var sess kratosSession
	if err := json.NewDecoder(res.Body).Decode(&sess); err != nil {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosSessionRefreshFailed, fmt.Errorf("kratos: decode whoami: %w", err))
	}
	if !sess.Active {
		return AuthResult{}, ErrInvalidCredentials
	}
	return sessionToAuthResult(sessionToken, sess), nil
}

// Logout best-effort revokes the Kratos session identified by sessionToken
// via the API-flow logout endpoint (POST .../self-service/logout/api), the
// headless counterpart of KCClient.Logout. Every existing caller (Handler.Logout)
// already swallows this error (`_ = h.auth().Logout(...)`) and drops the local
// session regardless of the outcome, so a failure here is diagnostic only — it
// never blocks logout.
func (c *KratosClient) Logout(ctx context.Context, sessionToken string) error {
	if sessionToken == "" {
		return nil
	}
	res, err := c.postJSON(ctx, c.publicURL+"/self-service/logout/api", map[string]string{"session_token": sessionToken})
	if err != nil {
		return errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: logout: %w", err))
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode >= 300 {
		return errcodes.Wrap(errcodes.CodeKratosLogoutFailed, fmt.Errorf("kratos: logout: unexpected status %d", res.StatusCode))
	}
	return nil
}

// recoveryExpiresIn is the lifetime requested when minting a recovery code via
// the admin API; recoveryExpiresInMinutes is its minute form, forwarded to the
// email template as expiresInMinutes so the two never drift.
const (
	recoveryExpiresIn        = "1h"
	recoveryExpiresInMinutes = 60
)

// RecoveryCode is the result of CreateRecoveryCode: the freshly minted code,
// the recipient's display name (best-effort, from the identity's traits, for
// the email greeting), how long the code is valid, and the id of the
// self-service recovery FLOW the code is bound to.
type RecoveryCode struct {
	Code             string
	RecipientName    string
	ExpiresInMinutes int
	FlowID           string
}

// kratosRecoveryIdentity is the subset of a Kratos admin Identity this client
// needs to mint a recovery code: the id, and the name trait for the email
// greeting. name is left raw because Kratos schemas differ (a plain
// string, or an object like {first,last} / {given_name,family_name}); see
// recipientName.
type kratosRecoveryIdentity struct {
	ID     string `json:"id"`
	Traits struct {
		Email string          `json:"email"`
		Name  json.RawMessage `json:"name"`
	} `json:"traits"`
}

// recipientName decodes the identity's name trait defensively: a plain string,
// else an object with first/last or given_name/family_name, else "". An empty
// result is fine — the recoveryCode email template renders a generic greeting.
func (i kratosRecoveryIdentity) recipientName() string {
	if len(i.Traits.Name) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(i.Traits.Name, &s) == nil && s != "" {
		return s
	}
	var o struct {
		First  string `json:"first"`
		Last   string `json:"last"`
		Given  string `json:"given_name"`
		Family string `json:"family_name"`
	}
	if json.Unmarshal(i.Traits.Name, &o) == nil {
		first := o.First
		if first == "" {
			first = o.Given
		}
		last := o.Last
		if last == "" {
			last = o.Family
		}
		return strings.TrimSpace(first + " " + last)
	}
	return ""
}

// kratosRecoveryCodeResponse is the subset of Kratos's
// createRecoveryCodeForIdentity response (POST admin/recovery/code) this
// client needs: the code itself, and the recovery_link the code is bound to —
// its ?flow=<id> is the self-service recovery flow the confirm step must submit
// the code to.
type kratosRecoveryCodeResponse struct {
	RecoveryCode string `json:"recovery_code"`
	RecoveryLink string `json:"recovery_link"`
}

// flowIDFromURL extracts the ?flow=<id> query parameter from a Kratos URL —
// the admin response's recovery_link and the recovery-submit's
// redirect_browser_to both carry the target flow this way. Returns "" when the
// URL is empty/unparseable or carries no flow param.
func flowIDFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Query().Get("flow")
}

// kratosActionShowSettingsUI is the continue_with action (Kratos v1.x) whose
// flow.id is the settings flow the recovery redemption must continue into after
// a successful code submit, on the HTTP 200 success shape.
const kratosActionShowSettingsUI = "show_settings_ui"

// kratosRecoverySubmitResult is the subset of Kratos's response to the recovery
// CODE submit this client needs to continue into the settings flow. It covers
// BOTH success shapes Kratos returns, depending on how it classifies the
// request (proven live on QA, gateway#40 reset-502):
type kratosRecoverySubmitResult struct {
	RedirectBrowserTo string `json:"redirect_browser_to"`
	Error             struct {
		ID string `json:"id"`
	} `json:"error"`
	ContinueWith []struct {
		Action string `json:"action"`
		Flow   struct {
			ID string `json:"id"`
		} `json:"flow"`
	} `json:"continue_with"`
}

// settingsFlowID resolves the settings flow to continue into from whichever
// success shape Kratos returned: a continue_with show_settings_ui entry (HTTP
// 200) takes precedence, falling back to redirect_browser_to's ?flow= (HTTP
// 422). Returns "" when neither carries one.
func (r kratosRecoverySubmitResult) settingsFlowID() string {
	for _, cw := range r.ContinueWith {
		if cw.Action == kratosActionShowSettingsUI && cw.Flow.ID != "" {
			return cw.Flow.ID
		}
	}
	return flowIDFromURL(r.RedirectBrowserTo)
}

// initSettingsFlow opens a fresh browser settings flow and returns its id. It is
// used when an accepted recovery code named NO settings flow (the admin-minted
// recovery-code shape): redeeming such a code establishes a privileged recovery
// session (continue_with set_ory_session_token) and leaves OPENING the settings
// flow to the client. hc MUST be the jar-backed recovery client so that session
// cookie threads onto this call. Kratos answers /self-service/settings/browser
// in one of two shapes depending on how it classifies the request: an AJAX 200
// carrying the flow (id in the body) or a browser 3xx whose Location carries the
// flow in ?flow= — both are handled. Failures are coded (never a client 400).
func (c *KratosClient) initSettingsFlow(ctx context.Context, hc *http.Client) (string, error) {
	res, err := c.getJSON(ctx, hc, c.publicURL+"/self-service/settings/browser")
	if err != nil {
		return "", errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: init settings flow: %w", err))
	}
	defer func() { _ = res.Body.Close() }()
	switch res.StatusCode {
	case http.StatusOK:
		var sf kratosSettingsFlow
		if err := json.NewDecoder(res.Body).Decode(&sf); err != nil {
			return "", errcodes.Wrap(errcodes.CodeKratosSettingsPasswordFailed, fmt.Errorf("kratos: decode init settings flow: %w", err))
		}
		if sf.ID == "" {
			return "", errcodes.Wrap(errcodes.CodeKratosSettingsPasswordFailed, fmt.Errorf("kratos: init settings flow (200) carried no id"))
		}
		return sf.ID, nil
	case http.StatusSeeOther, http.StatusFound, http.StatusTemporaryRedirect:
		if id := flowIDFromURL(res.Header.Get("Location")); id != "" {
			return id, nil
		}
		return "", errcodes.Wrap(errcodes.CodeKratosSettingsPasswordFailed, fmt.Errorf("kratos: init settings flow (%d) carried no ?flow= in Location", res.StatusCode))
	default:
		return "", errcodes.Wrap(errcodes.CodeKratosSettingsPasswordFailed, fmt.Errorf("kratos: init settings flow: unexpected status %d", res.StatusCode))
	}
}

// kratosSettingsFlow is the subset of the settings Flow object
// (GET self-service/settings/flows?id=…) this client needs: its ui.nodes carry
// the anti-CSRF token the settings submit must echo back.
type kratosSettingsFlow struct {
	ID string `json:"id"`
	UI struct {
		Nodes []struct {
			Attributes struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"attributes"`
		} `json:"nodes"`
	} `json:"ui"`
}

// csrfToken returns the value of the ui node named "csrf_token", or "" if the
// flow carries none.
func (f kratosSettingsFlow) csrfToken() string {
	for _, n := range f.UI.Nodes {
		if n.Attributes.Name == "csrf_token" {
			return n.Attributes.Value
		}
	}
	return ""
}

// recoveryCookieJar is a minimal http.CookieJar that faithfully RELAYS Kratos's
// own browser-flow cookies (ory_kratos_session + the anti-CSRF csrf_token_*)
// back to Kratos across the recovery→settings-flow→settings-submit calls, the
// way a browser would. It is deliberately NOT net/http/cookiejar, in two ways
// that matter under QA's secure cookies (COOKIE_INSECURE=false) — where the
// previous name-keyed map broke while DEV kept working:
type recoveryCookieJar struct {
	mu      sync.Mutex
	cookies map[string]string // live cookies only, name→value
}

func newRecoveryCookieJar() *recoveryCookieJar {
	return &recoveryCookieJar{cookies: map[string]string{}}
}

// SetCookies applies each Set-Cookie, dropping the entry on a deletion/clear so
// no stale csrf value survives a rotation.
func (j *recoveryCookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	for _, ck := range cookies {
		cleared := ck.Value == "" || ck.MaxAge < 0 || (!ck.Expires.IsZero() && ck.Expires.Before(now))
		if cleared {
			delete(j.cookies, ck.Name)
			continue
		}
		j.cookies[ck.Name] = ck.Value
	}
}

// Cookies returns every live cookie regardless of the request URL's scheme —
// see the type doc for why Secure cookies are relayed over the plaintext hop.
func (j *recoveryCookieJar) Cookies(_ *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*http.Cookie, 0, len(j.cookies))
	for k, v := range j.cookies {
		out = append(out, &http.Cookie{Name: k, Value: v})
	}
	return out
}

// newRecoveryHTTPClient returns an http.Client dedicated to ONE recovery
// redemption: a recoveryCookieJar threads Kratos's flow cookies automatically
// across the three calls, and redirects are never followed so the caller
// observes Kratos's own status/body (200 continue_with, 422
// browser_location_change, 400/410 rejected code) directly. It reuses the shared
// client's Transport/Timeout; a jar is never attached to c.http itself —
// VerifyPassword/Refresh/Logout stay strictly cookieless.
func (c *KratosClient) newRecoveryHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   c.http.Timeout,
		Transport: c.http.Transport,
		Jar:       newRecoveryCookieJar(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ErrKratosEndpointNotAllowed is returned when an endpoint handed to one of the
// jar-backed helpers does not resolve to one of the Kratos base URLs this client
// was configured with. It signals a programming error, not a runtime condition.
var ErrKratosEndpointNotAllowed = errors.New("kratos: endpoint outside the configured Kratos base URLs")

// assertEndpoint PINS an outbound request to the Kratos deployment this client
// was constructed against — the publicURL/adminURL given to NewKratosClient,
// which come from config (KRATOS_PUBLIC_URL/KRATOS_ADMIN_URL), never from a
// request. Scheme and host must match one of those bases exactly, the base's
// path must be a prefix of the endpoint's, and userinfo is rejected outright.
func (c *KratosClient) assertEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("%w: unparseable endpoint: %v", ErrKratosEndpointNotAllowed, err)
	}
	if u.User != nil {
		return fmt.Errorf("%w: endpoint carries userinfo", ErrKratosEndpointNotAllowed)
	}
	for _, base := range []string{c.publicURL, c.adminURL} {
		if base == "" {
			continue
		}
		b, err := url.Parse(base)
		if err != nil || b.Scheme == "" || b.Host == "" {
			continue
		}
		if u.Scheme != b.Scheme || u.Host != b.Host {
			continue
		}
		basePath := strings.TrimSuffix(b.EscapedPath(), "/")
		if basePath == "" || strings.HasPrefix(u.EscapedPath(), basePath+"/") || u.EscapedPath() == basePath {
			return nil
		}
	}
	return fmt.Errorf("%w: %s://%s", ErrKratosEndpointNotAllowed, u.Scheme, u.Host)
}

// getJSON issues a GET (Accept: json) on the supplied client, so the recovery
// redemption's jar-backed client is used instead of the cookieless c.http. The
// endpoint is pinned to this client's configured Kratos bases first.
func (c *KratosClient) getJSON(ctx context.Context, hc *http.Client, endpoint string) (*http.Response, error) {
	if err := c.assertEndpoint(endpoint); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) // #nosec G704 -- endpoint is pinned to c.publicURL/c.adminURL (from config) by assertEndpoint immediately above; SSRF not reachable
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return hc.Do(req) // #nosec G704 -- see assertEndpoint above: scheme+host are pinned to the configured Kratos bases
}

// postJSONWith POSTs a JSON body on the supplied client (see getJSON), with the
// same endpoint pinning.
func (c *KratosClient) postJSONWith(ctx context.Context, hc *http.Client, endpoint string, body any) (*http.Response, error) {
	if err := c.assertEndpoint(endpoint); err != nil {
		return nil, err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b)) // #nosec G704 -- endpoint is pinned to c.publicURL/c.adminURL (from config) by assertEndpoint immediately above; SSRF not reachable
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return hc.Do(req) // #nosec G704 -- see assertEndpoint above: scheme+host are pinned to the configured Kratos bases
}

// CreateRecoveryCode mints a one-time password-recovery code for the identity
// whose credentials_identifier is email, using Kratos's admin API so Kratos
// itself sends no email (we deliver the code through our own platform). It
// resolves the identity first (GET admin/identities?credentials_identifier=…)
// then creates the code (POST admin/recovery/code). No identity for email
// returns ErrRecoveryIdentityNotFound so the caller can honor anti-enumeration;
// any other non-2xx/transport/parse failure is a coded internal error.
func (c *KratosClient) CreateRecoveryCode(ctx context.Context, email string) (RecoveryCode, error) {
	l := c.logger(ctx)
	idURL := c.adminURL + "/admin/identities?credentials_identifier=" + url.QueryEscape(email)
	idRes, err := c.get(ctx, idURL, "")
	if err != nil {
		l.Warn("reset request: kratos admin list-identities transport error", log.F("flow", "reset_request"), log.F("step", "kratos_list_identities"), errField(err), log.F("coded_err", errcodes.CodeKratosUnreachable))
		return RecoveryCode{}, errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: list identities: %w", err))
	}
	defer func() { _ = idRes.Body.Close() }()
	if idRes.StatusCode != http.StatusOK {
		l.Warn("reset request: kratos admin list-identities non-200", log.F("flow", "reset_request"), log.F("step", "kratos_list_identities"), log.F("status", idRes.StatusCode), log.F("body_snippet", bodySnippet(idRes.Body)))
		return RecoveryCode{}, errcodes.Wrap(errcodes.CodeKratosAdminIdentityLookup, fmt.Errorf("kratos: list identities: unexpected status %d", idRes.StatusCode))
	}
	var ids []kratosRecoveryIdentity
	if err := json.NewDecoder(idRes.Body).Decode(&ids); err != nil {
		return RecoveryCode{}, errcodes.Wrap(errcodes.CodeKratosAdminIdentityLookup, fmt.Errorf("kratos: decode identities: %w", err))
	}
	if len(ids) == 0 {
		log.Trace(l, "reset request: no kratos identity for email (anti-enumeration: caller still sees ok)", log.F("flow", "reset_request"), log.F("step", "kratos_list_identities"), log.F("status", idRes.StatusCode))
		return RecoveryCode{}, ErrRecoveryIdentityNotFound
	}
	id := ids[0]

	codeRes, err := c.postJSON(ctx, c.adminURL+"/admin/recovery/code", map[string]string{
		"identity_id": id.ID,
		"expires_in":  recoveryExpiresIn,
	})
	if err != nil {
		l.Warn("reset request: kratos admin recovery-code transport error", log.F("flow", "reset_request"), log.F("step", "kratos_create_code"), errField(err), log.F("coded_err", errcodes.CodeKratosUnreachable))
		return RecoveryCode{}, errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: create recovery code: %w", err))
	}
	defer func() { _ = codeRes.Body.Close() }()
	if codeRes.StatusCode != http.StatusOK && codeRes.StatusCode != http.StatusCreated {
		l.Warn("reset request: kratos admin recovery-code non-2xx", log.F("flow", "reset_request"), log.F("step", "kratos_create_code"), log.F("status", codeRes.StatusCode), log.F("body_snippet", bodySnippet(codeRes.Body)), log.F("coded_err", errcodes.CodeKratosAdminRecoveryCodeFailed))
		return RecoveryCode{}, errcodes.Wrap(errcodes.CodeKratosAdminRecoveryCodeFailed, fmt.Errorf("kratos: create recovery code: unexpected status %d", codeRes.StatusCode))
	}
	var cr kratosRecoveryCodeResponse
	if err := json.NewDecoder(codeRes.Body).Decode(&cr); err != nil || cr.RecoveryCode == "" {
		return RecoveryCode{}, errcodes.Wrap(errcodes.CodeKratosAdminRecoveryCodeFailed, fmt.Errorf("kratos: decode recovery code: %w", err))
	}
	flowID := flowIDFromURL(cr.RecoveryLink)
	if flowID == "" {
		return RecoveryCode{}, errcodes.Wrap(errcodes.CodeKratosAdminRecoveryCodeFailed, fmt.Errorf("kratos: recovery response carried no flow id (recovery_link=%q)", cr.RecoveryLink))
	}
	log.Trace(l, "reset request: kratos recovery code minted (bound to flow)", log.F("flow", "reset_request"), log.F("step", "kratos_create_code"), log.F("status", codeRes.StatusCode), log.F("recovery_flow_id", flowID), log.F("has_code", cr.RecoveryCode != ""))
	return RecoveryCode{
		Code:             cr.RecoveryCode,
		RecipientName:    id.recipientName(),
		ExpiresInMinutes: recoveryExpiresInMinutes,
		FlowID:           flowID,
	}, nil
}

// SubmitRecoveryCodeAndReset redeems code against the EXISTING self-service
// recovery flow the code is bound to (flowID, minted+persisted at request time
// — gateway#46) and sets newPassword. The admin-generated recovery code drives
// a BROWSER flow, so this threads cookies + CSRF across three calls exactly as
// a browser would, using a per-redemption cookie jar (see recoveryCookieJar):
func (c *KratosClient) SubmitRecoveryCodeAndReset(ctx context.Context, flowID, code, newPassword string) error {
	logger := c.logger(ctx)
	if flowID == "" {
		log.Trace(logger, "reset confirm: no stored recovery flow id — treating as invalid/expired code", log.F("flow", "reset_confirm"), log.F("step", "precheck"), log.F("reason", "empty_flow_id"))
		return ErrInvalidRecoveryCode
	}
	log.Trace(logger, "reset confirm: submitting recovery code to bound flow (browser flow)", log.F("flow", "reset_confirm"), log.F("step", "recovery_submit"), log.F("recovery_flow_id", flowID), log.F("has_code", code != ""))

	hc := c.newRecoveryHTTPClient()

	subURL := c.publicURL + "/self-service/recovery?flow=" + url.QueryEscape(flowID)
	subRes, err := c.postJSONWith(ctx, hc, subURL, map[string]string{
		"method": "code",
		"code":   code,
	})
	if err != nil {
		logger.Warn("reset confirm: recovery submit transport error", log.F("flow", "reset_confirm"), log.F("step", "recovery_submit"), errField(err), log.F("coded_err", errcodes.CodeKratosUnreachable))
		return errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: submit recovery code: %w", err))
	}
	defer func() { _ = subRes.Body.Close() }()

	switch subRes.StatusCode {
	case http.StatusOK, http.StatusUnprocessableEntity:
	case http.StatusBadRequest, http.StatusGone:
		log.Trace(logger, "reset confirm: recovery code rejected (400/410) — invalid/expired code", log.F("flow", "reset_confirm"), log.F("step", "recovery_submit"), log.F("status", subRes.StatusCode), log.F("body_snippet", bodySnippet(subRes.Body)), log.F("reason", "rejected_code"))
		return ErrInvalidRecoveryCode
	case http.StatusSeeOther:
		log.Trace(logger, "reset confirm: recovery flow already redeemed/expired (303) — invalid/expired code", log.F("flow", "reset_confirm"), log.F("step", "recovery_submit"), log.F("status", subRes.StatusCode), log.F("reason", "flow_consumed_or_expired"))
		return ErrInvalidRecoveryCode
	default:
		logger.Warn("reset confirm: recovery submit unexpected status — coded internal error (this is the reset 502)", log.F("flow", "reset_confirm"), log.F("step", "recovery_submit"), log.F("status", subRes.StatusCode), log.F("body_snippet", bodySnippet(subRes.Body)), log.F("coded_err", errcodes.CodeKratosRecoveryFlowFailed))
		return errcodes.Wrap(errcodes.CodeKratosRecoveryFlowFailed, fmt.Errorf("kratos: submit recovery code: unexpected status %d", subRes.StatusCode))
	}

	var result kratosRecoverySubmitResult
	if err := json.NewDecoder(subRes.Body).Decode(&result); err != nil {
		logger.Warn("reset confirm: decode recovery result failed", log.F("flow", "reset_confirm"), log.F("step", "recovery_submit"), errField(err), log.F("coded_err", errcodes.CodeKratosRecoveryFlowFailed))
		return errcodes.Wrap(errcodes.CodeKratosRecoveryFlowFailed, fmt.Errorf("kratos: decode recovery result: %w", err))
	}
	settingsFlowID := result.settingsFlowID()
	if settingsFlowID == "" {
		log.Trace(logger, "reset confirm: code accepted, no settings flow named — opening one on the recovery session", log.F("flow", "reset_confirm"), log.F("step", "recovery_submit"), log.F("status", subRes.StatusCode), log.F("reason", "no_settings_flow_named"))
		id, ierr := c.initSettingsFlow(ctx, hc)
		if ierr != nil {
			logger.Warn("reset confirm: could not open a settings flow on the recovery session — coded internal error", log.F("flow", "reset_confirm"), log.F("step", "settings_flow_init"), errField(ierr), log.F("reason", "settings_init_failed"))
			return ierr
		}
		settingsFlowID = id
	}
	log.Trace(logger, "reset confirm: code accepted, settings flow resolved", log.F("flow", "reset_confirm"), log.F("step", "recovery_submit"), log.F("status", subRes.StatusCode), log.F("settings_flow_id", settingsFlowID), log.F("reason", "accepted"))

	getURL := c.publicURL + "/self-service/settings/flows?id=" + url.QueryEscape(settingsFlowID)
	getRes, err := c.getJSON(ctx, hc, getURL)
	if err != nil {
		logger.Warn("reset confirm: settings-flow fetch transport error", log.F("flow", "reset_confirm"), log.F("step", "settings_flow_fetch"), errField(err), log.F("coded_err", errcodes.CodeKratosUnreachable))
		return errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: get settings flow: %w", err))
	}
	defer func() { _ = getRes.Body.Close() }()
	if getRes.StatusCode != http.StatusOK {
		logger.Warn("reset confirm: settings-flow fetch non-200 — coded internal error", log.F("flow", "reset_confirm"), log.F("step", "settings_flow_fetch"), log.F("status", getRes.StatusCode), log.F("settings_flow_id", settingsFlowID), log.F("body_snippet", bodySnippet(getRes.Body)), log.F("coded_err", errcodes.CodeKratosSettingsPasswordFailed))
		return errcodes.Wrap(errcodes.CodeKratosSettingsPasswordFailed, fmt.Errorf("kratos: get settings flow: unexpected status %d", getRes.StatusCode))
	}
	var sf kratosSettingsFlow
	if err := json.NewDecoder(getRes.Body).Decode(&sf); err != nil {
		logger.Warn("reset confirm: decode settings flow failed", log.F("flow", "reset_confirm"), log.F("step", "settings_flow_fetch"), errField(err), log.F("coded_err", errcodes.CodeKratosSettingsPasswordFailed))
		return errcodes.Wrap(errcodes.CodeKratosSettingsPasswordFailed, fmt.Errorf("kratos: decode settings flow: %w", err))
	}
	csrf := sf.csrfToken()
	log.Trace(logger, "reset confirm: fetched settings flow", log.F("flow", "reset_confirm"), log.F("step", "settings_flow_fetch"), log.F("status", getRes.StatusCode), log.F("settings_flow_id", settingsFlowID), log.F("csrf_present", csrf != ""))
	if csrf == "" {
		logger.Warn("reset confirm: settings flow carried no csrf_token node", log.F("flow", "reset_confirm"), log.F("step", "settings_flow_fetch"), log.F("reason", "no_csrf_node"), log.F("coded_err", errcodes.CodeKratosSettingsPasswordFailed))
		return errcodes.Wrap(errcodes.CodeKratosSettingsPasswordFailed, fmt.Errorf("kratos: settings flow carried no csrf_token node"))
	}

	log.Trace(logger, "reset confirm: submitting new password to settings flow (cookies + csrf)", log.F("flow", "reset_confirm"), log.F("step", "settings_submit"), log.F("settings_flow_id", settingsFlowID))
	setURL := c.publicURL + "/self-service/settings?flow=" + url.QueryEscape(settingsFlowID)
	setRes, err := c.postJSONWith(ctx, hc, setURL, map[string]string{
		"method":     "password",
		"password":   newPassword,
		"csrf_token": csrf,
	})
	if err != nil {
		logger.Warn("reset confirm: settings submit transport error", log.F("flow", "reset_confirm"), log.F("step", "settings_submit"), errField(err), log.F("coded_err", errcodes.CodeKratosUnreachable))
		return errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: submit settings: %w", err))
	}
	defer func() { _ = setRes.Body.Close() }()
	switch setRes.StatusCode {
	case http.StatusOK:
		log.Trace(logger, "reset confirm: new password set", log.F("flow", "reset_confirm"), log.F("step", "settings_submit"), log.F("status", setRes.StatusCode), log.F("reset_ok", true))
		return nil
	case http.StatusBadRequest:
		log.Trace(logger, "reset confirm: settings rejected new password (400) — client-facing 400", log.F("flow", "reset_confirm"), log.F("step", "settings_submit"), log.F("status", setRes.StatusCode), log.F("body_snippet", bodySnippet(setRes.Body)), log.F("reason", "password_rejected"))
		return ErrInvalidRecoveryCode
	default:
		logger.Warn("reset confirm: settings submit unexpected status — coded internal error (this is the reset 502)", log.F("flow", "reset_confirm"), log.F("step", "settings_submit"), log.F("status", setRes.StatusCode), log.F("body_snippet", bodySnippet(setRes.Body)), log.F("coded_err", errcodes.CodeKratosSettingsPasswordFailed))
		return errcodes.Wrap(errcodes.CodeKratosSettingsPasswordFailed, fmt.Errorf("kratos: submit settings: unexpected status %d", setRes.StatusCode))
	}
}
