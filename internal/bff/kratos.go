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

// flowIDFromURL reads the ?flow= id off a Kratos redirect URL, or "".
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

// flowCookieJar relays Kratos's browser-flow cookies (the session and the
// anti-CSRF cookie) across one ceremony's calls, as a browser would. Unlike
// net/http/cookiejar it drops a cleared cookie at once and sends Secure
// cookies over the plaintext in-cluster hop.
type flowCookieJar struct {
	mu      sync.Mutex
	cookies map[string]string // live cookies only, name→value
}

func newFlowCookieJar() *flowCookieJar {
	return &flowCookieJar{cookies: map[string]string{}}
}

// SetCookies applies each Set-Cookie, dropping the entry on a deletion/clear so
// no stale csrf value survives a rotation.
func (j *flowCookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
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
func (j *flowCookieJar) Cookies(_ *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*http.Cookie, 0, len(j.cookies))
	for k, v := range j.cookies {
		out = append(out, &http.Cookie{Name: k, Value: v}) // #nosec G124 -- relayed to Kratos on the server-side hop, never set on a browser
	}
	return out
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
