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
	"maps"
	"net/http"
	"net/url"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

// ErrPasskeyRegistrationRejected is Kratos refusing the attestation; the
// caller answers 400 and stores nothing.
var ErrPasskeyRegistrationRejected = errors.New("kratos: passkey registration rejected")

// ErrPasskeyReauthRequired is a session too old for a privileged settings
// change; the user signs in again first.
var ErrPasskeyReauthRequired = errors.New("kratos: re-authentication required to register a passkey")

const (
	// Kratos UI node and form field names for the passkey method.
	passkeyChallengeNodeName     = "passkey_challenge"
	passkeyLoginField            = "passkey_login"
	passkeyCreateDataNodeName    = "passkey_create_data"
	passkeySettingsRegisterField = "passkey_settings_register"

	kratosActionSetSessionToken = "set_ory_session_token"

	passkeyRegisterFlowTTL = 10 * time.Minute
)

// kratosFlowUI is a login or settings flow with the UI node values kept raw:
// Kratos sends the WebAuthn options either as a JSON string or as an object.
type kratosFlowUI struct {
	ID string `json:"id"`
	UI struct {
		Nodes []struct {
			Attributes struct {
				Name  string          `json:"name"`
				Value json.RawMessage `json:"value"`
			} `json:"attributes"`
		} `json:"nodes"`
	} `json:"ui"`
}

// nodeValue unwraps a string-valued node and passes an object through as is.
func (f kratosFlowUI) nodeValue(name string) (string, bool) {
	for _, n := range f.UI.Nodes {
		if n.Attributes.Name != name {
			continue
		}
		raw := n.Attributes.Value
		if len(raw) == 0 {
			return "", false
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s, s != ""
		}
		return string(raw), true
	}
	return "", false
}

func (f kratosFlowUI) csrf() string {
	v, _ := f.nodeValue("csrf_token")
	return v
}

// kratosBrowserLoginResult is a browser login submit's answer. Kratos puts the
// session token in continue_with; the top-level field is read as a fallback.
type kratosBrowserLoginResult struct {
	SessionToken string `json:"session_token"`
	ContinueWith []struct {
		Action          string `json:"action"`
		OrySessionToken string `json:"ory_session_token"`
	} `json:"continue_with"`
}

func (r kratosBrowserLoginResult) sessionToken() string {
	if r.SessionToken != "" {
		return r.SessionToken
	}
	for _, cw := range r.ContinueWith {
		if cw.Action == kratosActionSetSessionToken && cw.OrySessionToken != "" {
			return cw.OrySessionToken
		}
	}
	return ""
}

// PasskeyLoginResult is an opened browser login flow: its id, the WebAuthn
// assertion options, and the CSRF token and cookies finish must replay.
type PasskeyLoginResult struct {
	FlowID      string
	OptionsJSON string
	CSRFToken   string
	Cookies     map[string]string
}

// PasskeyRegisterResult is an opened settings flow for passkey registration.
type PasskeyRegisterResult struct {
	FlowID      string
	OptionsJSON string
	CSRFToken   string
	Cookies     map[string]string
}

// newFlowClient is a client for one browser-flow ceremony: its own cookie jar,
// seeded with the cookies a previous step captured, and no redirects followed.
// The shared c.http never gets a jar, so the password paths stay cookieless.
func (c *KratosClient) newFlowClient(seed map[string]string) (*http.Client, *recoveryCookieJar) {
	jar := newRecoveryCookieJar()
	maps.Copy(jar.cookies, seed)
	return &http.Client{
		Timeout:   c.http.Timeout,
		Transport: c.http.Transport,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, jar
}

func (j *recoveryCookieJar) snapshot() map[string]string {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make(map[string]string, len(j.cookies))
	maps.Copy(out, j.cookies)
	return out
}

// sessionRequest is a pinned Kratos request carrying the user's session token.
func (c *KratosClient) sessionRequest(ctx context.Context, hc *http.Client, method, endpoint, sessionToken string, body any) (*http.Response, error) {
	if err := c.assertEndpoint(endpoint); err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rd) // #nosec G704 -- endpoint pinned to the configured Kratos bases by assertEndpoint
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if sessionToken != "" {
		req.Header.Set("X-Session-Token", sessionToken)
	}
	return hc.Do(req) // #nosec G704 -- endpoint pinned to the configured Kratos bases by assertEndpoint
}

// openFlow starts a browser flow at initPath and returns it with its UI nodes,
// fetching the flow by id when the init answered with a redirect. For a
// settings flow, a 401 or 403 means the session must sign in again.
func (c *KratosClient) openFlow(ctx context.Context, hc *http.Client, initPath, flowsPath, sessionToken string, settings bool, initCode int, what string) (kratosFlowUI, error) {
	res, err := c.sessionRequest(ctx, hc, http.MethodGet, c.publicURL+initPath, sessionToken, nil)
	if err != nil {
		return kratosFlowUI{}, errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: open %s flow: %w", what, err))
	}
	var flow kratosFlowUI
	switch res.StatusCode {
	case http.StatusOK:
		derr := json.NewDecoder(res.Body).Decode(&flow)
		_ = res.Body.Close()
		if derr != nil || flow.ID == "" {
			return kratosFlowUI{}, errcodes.Wrap(initCode, fmt.Errorf("kratos: decode %s flow: %w", what, derr))
		}
	case http.StatusSeeOther, http.StatusFound, http.StatusTemporaryRedirect:
		id := flowIDFromURL(res.Header.Get("Location"))
		_ = res.Body.Close()
		if id == "" {
			return kratosFlowUI{}, errcodes.Wrap(initCode, fmt.Errorf("kratos: open %s flow (%d) carried no flow id", what, res.StatusCode))
		}
		flow.ID = id
	case http.StatusUnauthorized, http.StatusForbidden:
		_ = res.Body.Close()
		if settings {
			return kratosFlowUI{}, ErrPasskeyReauthRequired
		}
		return kratosFlowUI{}, errcodes.Wrap(initCode, fmt.Errorf("kratos: open %s flow: status %d", what, res.StatusCode))
	default:
		snippet := bodySnippet(res.Body)
		_ = res.Body.Close()
		return kratosFlowUI{}, errcodes.Wrap(initCode, fmt.Errorf("kratos: open %s flow: unexpected status %d (%s)", what, res.StatusCode, snippet))
	}
	if len(flow.UI.Nodes) > 0 {
		return flow, nil
	}

	fres, err := c.sessionRequest(ctx, hc, http.MethodGet, c.publicURL+flowsPath+"?id="+url.QueryEscape(flow.ID), sessionToken, nil)
	if err != nil {
		return kratosFlowUI{}, errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: fetch %s flow: %w", what, err))
	}
	defer func() { _ = fres.Body.Close() }()
	if settings && (fres.StatusCode == http.StatusUnauthorized || fres.StatusCode == http.StatusForbidden) {
		return kratosFlowUI{}, ErrPasskeyReauthRequired
	}
	if fres.StatusCode != http.StatusOK {
		return kratosFlowUI{}, errcodes.Wrap(initCode, fmt.Errorf("kratos: fetch %s flow: unexpected status %d (%s)", what, fres.StatusCode, bodySnippet(fres.Body)))
	}
	id := flow.ID
	flow = kratosFlowUI{}
	if err := json.NewDecoder(fres.Body).Decode(&flow); err != nil {
		return kratosFlowUI{}, errcodes.Wrap(initCode, fmt.Errorf("kratos: decode %s flow: %w", what, err))
	}
	if flow.ID == "" {
		flow.ID = id
	}
	return flow, nil
}

// PasskeyLoginBegin opens a browser login flow and returns its assertion
// options. A flow without the passkey challenge means the method is off in
// Kratos: a coded init fault. Nothing is authenticated yet.
func (c *KratosClient) PasskeyLoginBegin(ctx context.Context) (PasskeyLoginResult, error) {
	hc, jar := c.newFlowClient(nil)
	flow, err := c.openFlow(ctx, hc, "/self-service/login/browser", "/self-service/login/flows", "", false, errcodes.CodeKratosPasskeyLoginInitFailed, "passkey login")
	if err != nil {
		return PasskeyLoginResult{}, err
	}
	options, ok := flow.nodeValue(passkeyChallengeNodeName)
	if !ok {
		return PasskeyLoginResult{}, errcodes.Wrap(errcodes.CodeKratosPasskeyLoginInitFailed, fmt.Errorf("kratos: login flow %q carries no %s node", flow.ID, passkeyChallengeNodeName))
	}
	csrf := flow.csrf()
	if csrf == "" {
		return PasskeyLoginResult{}, errcodes.Wrap(errcodes.CodeKratosPasskeyLoginInitFailed, fmt.Errorf("kratos: login flow %q carries no csrf_token node", flow.ID))
	}
	log.Trace(c.logger(ctx), "passkey login: browser flow opened", log.F("flow", "passkey_login"), log.F("login_flow_id", flow.ID))
	return PasskeyLoginResult{FlowID: flow.ID, OptionsJSON: options, CSRFToken: csrf, Cookies: jar.snapshot()}, nil
}

// PasskeyLoginFinish submits the signed assertion to the flow begin opened and
// returns the new Kratos session, as VerifyPassword does. A rejected assertion
// is ErrInvalidCredentials.
func (c *KratosClient) PasskeyLoginFinish(ctx context.Context, flowID, credentialJSON, csrfToken string, cookies map[string]string) (AuthResult, error) {
	hc, _ := c.newFlowClient(cookies)
	res, err := c.postJSONWith(ctx, hc, c.publicURL+"/self-service/login?flow="+url.QueryEscape(flowID), map[string]string{
		"method":          "passkey",
		passkeyLoginField: credentialJSON,
		"csrf_token":      csrfToken,
	})
	if err != nil {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: submit passkey login: %w", err))
	}
	if res.StatusCode == http.StatusBadRequest {
		_ = res.Body.Close()
		return AuthResult{}, ErrInvalidCredentials
	}
	if res.StatusCode != http.StatusOK {
		snippet := bodySnippet(res.Body)
		_ = res.Body.Close()
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosPasskeyLoginVerifyFailed, fmt.Errorf("kratos: submit passkey login: unexpected status %d (%s)", res.StatusCode, snippet))
	}
	var lr kratosBrowserLoginResult
	derr := json.NewDecoder(res.Body).Decode(&lr)
	_ = res.Body.Close()
	if derr != nil {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosPasskeyLoginVerifyFailed, fmt.Errorf("kratos: decode passkey login response: %w", derr))
	}
	sessionToken := lr.sessionToken()
	if sessionToken == "" {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosPasskeyLoginVerifyFailed, errors.New("kratos: passkey login carried no session token"))
	}

	wres, err := c.getJSON(ctx, hc, c.publicURL+"/sessions/whoami")
	if err != nil {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: whoami after passkey login: %w", err))
	}
	defer func() { _ = wres.Body.Close() }()
	if wres.StatusCode != http.StatusOK {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosPasskeyLoginVerifyFailed, fmt.Errorf("kratos: whoami after passkey login: unexpected status %d", wres.StatusCode))
	}
	var sess kratosSession
	if err := json.NewDecoder(wres.Body).Decode(&sess); err != nil || !sess.Active {
		return AuthResult{}, errcodes.Wrap(errcodes.CodeKratosPasskeyLoginVerifyFailed, errors.New("kratos: whoami after passkey login: no active session"))
	}
	log.Trace(c.logger(ctx), "passkey login: session established", log.F("flow", "passkey_login"), log.F("login_flow_id", flowID), log.F("identity", sess.Identity.ID))
	return sessionToAuthResult(sessionToken, sess), nil
}

// PasskeyLoginAvailable reports whether Kratos offers passkey sign-in at all,
// by opening (and abandoning) a login flow.
func (c *KratosClient) PasskeyLoginAvailable(ctx context.Context) bool {
	res, err := c.PasskeyLoginBegin(ctx)
	return err == nil && res.OptionsJSON != ""
}

// PasskeyRegisterBegin opens a settings flow for the signed-in user and
// returns the WebAuthn creation options. Nothing is stored in Kratos yet.
func (c *KratosClient) PasskeyRegisterBegin(ctx context.Context, sessionToken string) (PasskeyRegisterResult, error) {
	hc, jar := c.newFlowClient(nil)
	flow, err := c.openFlow(ctx, hc, "/self-service/settings/browser", "/self-service/settings/flows", sessionToken, true, errcodes.CodeKratosPasskeyRegisterInit, "passkey settings")
	if err != nil {
		return PasskeyRegisterResult{}, err
	}
	options, ok := flow.nodeValue(passkeyCreateDataNodeName)
	if !ok {
		return PasskeyRegisterResult{}, errcodes.Wrap(errcodes.CodeKratosPasskeyRegisterInit, fmt.Errorf("kratos: settings flow %q carries no %s node", flow.ID, passkeyCreateDataNodeName))
	}
	csrf := flow.csrf()
	if csrf == "" {
		return PasskeyRegisterResult{}, errcodes.Wrap(errcodes.CodeKratosPasskeyRegisterInit, fmt.Errorf("kratos: settings flow %q carries no csrf_token node", flow.ID))
	}
	log.Trace(c.logger(ctx), "passkey register: settings flow opened", log.F("flow", "passkey_register"), log.F("settings_flow_id", flow.ID))
	return PasskeyRegisterResult{FlowID: flow.ID, OptionsJSON: options, CSRFToken: csrf, Cookies: jar.snapshot()}, nil
}

// PasskeyRegisterFinish submits the attestation to the settings flow begin
// opened. Kratos stores the credential only on a 200.
func (c *KratosClient) PasskeyRegisterFinish(ctx context.Context, sessionToken, flowID, credentialJSON, csrfToken string, cookies map[string]string) error {
	if flowID == "" || credentialJSON == "" {
		return ErrPasskeyRegistrationRejected
	}
	l := c.logger(ctx)
	hc, _ := c.newFlowClient(cookies)
	res, err := c.sessionRequest(ctx, hc, http.MethodPost, c.publicURL+"/self-service/settings?flow="+url.QueryEscape(flowID), sessionToken, map[string]string{
		"method":                     "passkey",
		passkeySettingsRegisterField: credentialJSON,
		"csrf_token":                 csrfToken,
	})
	if err != nil {
		return errcodes.Wrap(errcodes.CodeKratosUnreachable, fmt.Errorf("kratos: submit passkey settings: %w", err))
	}
	defer func() { _ = res.Body.Close() }()

	switch res.StatusCode {
	case http.StatusOK:
		log.Trace(l, "passkey register: credential stored", log.F("flow", "passkey_register"), log.F("settings_flow_id", flowID))
		return nil
	case http.StatusBadRequest:
		l.Debug("passkey register: attestation rejected", log.F("flow", "passkey_register"), log.F("settings_flow_id", flowID), log.F("reason", "rejected"))
		return ErrPasskeyRegistrationRejected
	case http.StatusUnauthorized, http.StatusForbidden:
		l.Debug("passkey register: privileged session required", log.F("flow", "passkey_register"), log.F("settings_flow_id", flowID), log.F("status", res.StatusCode), log.F("reason", "reauth_required"))
		return ErrPasskeyReauthRequired
	default:
		snippet := bodySnippet(res.Body)
		l.Warn("passkey register: unexpected status", log.F("flow", "passkey_register"), log.F("settings_flow_id", flowID), log.F("status", res.StatusCode))
		return errcodes.Wrap(errcodes.CodeKratosPasskeyRegisterVerify, fmt.Errorf("kratos: submit passkey settings: unexpected status %d (%s)", res.StatusCode, snippet))
	}
}
