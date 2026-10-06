// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

// polisDummy is Polis's default client id and secret verifier. Polis picks
// the connection by tenant and product, not by client credentials.
const polisDummy = "dummy"

// PolisProfile is Polis's userinfo for a brokered sign-in. Polis access tokens
// are opaque, so the email comes from here.
type PolisProfile struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

// polisTokens is Polis's token answer. The gateway keeps none of it past the
// userinfo call: SSO sessions live on the gateway's own session TTL.
type polisTokens struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// PolisClient talks to Polis's OAuth endpoints. The authorize redirect goes to
// the public URL the browser can reach; token and userinfo go to the issuer
// URL, server to server.
type PolisClient struct {
	publicURL string
	issuerURL string
	product   string
	http      *http.Client
}

// NewPolisClient builds a client. product selects the connection together
// with the tenant (the organisation's email domain).
func NewPolisClient(publicURL, issuerURL, product string) *PolisClient {
	return &PolisClient{
		publicURL: strings.TrimRight(publicURL, "/"),
		issuerURL: strings.TrimRight(issuerURL, "/"),
		product:   product,
		http:      &http.Client{Timeout: 10 * time.Second},
	}
}

// polisTenant is the connection tenant for a start request: an explicit
// ?tenant= wins, else the domain of ?identifier.
func polisTenant(r *http.Request) string {
	if t := strings.TrimSpace(r.URL.Query().Get("tenant")); t != "" {
		return strings.ToLower(t)
	}
	return emailDomain(r.URL.Query().Get("identifier"))
}

func emailDomain(identifier string) string {
	i := strings.LastIndex(identifier, "@")
	if i < 0 || i == len(identifier)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(identifier[i+1:]))
}

// AuthorizeURL is the browser redirect that starts a brokered sign-in. An
// empty tenant leaves the connection for Polis to pick.
func (c *PolisClient) AuthorizeURL(redirectURI, state, tenant, product string) string {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {polisDummy},
		"redirect_uri":  {redirectURI},
		"state":         {state},
		"scope":         {"openid"},
		"product":       {product},
	}
	if tenant != "" {
		q.Set("tenant", tenant)
	}
	return c.publicURL + "/api/oauth/authorize?" + q.Encode()
}

// CodeExchange trades the callback's code for an access token.
func (c *PolisClient) CodeExchange(ctx context.Context, code, redirectURI string) (polisTokens, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {polisDummy},
		"client_secret": {polisDummy},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.issuerURL+"/api/oauth/token", strings.NewReader(form.Encode())) // #nosec G704 -- issuerURL is configuration, not request input
	if err != nil {
		return polisTokens{}, errcodes.Wrap(errcodes.CodePolisCodeExchangeFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req) // #nosec G704 -- issuerURL is configuration, not request input
	if err != nil {
		return polisTokens{}, errcodes.Wrap(errcodes.CodePolisCodeExchangeFailed, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return polisTokens{}, errcodes.Wrap(errcodes.CodePolisCodeExchangeFailed, fmt.Errorf("polis: token endpoint status %d", res.StatusCode))
	}
	var t polisTokens
	if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
		return polisTokens{}, errcodes.Wrap(errcodes.CodePolisCodeExchangeFailed, err)
	}
	if t.AccessToken == "" {
		return polisTokens{}, errcodes.Wrap(errcodes.CodePolisCodeExchangeFailed, errors.New("polis: token response carried no access_token"))
	}
	return t, nil
}

// UserInfo reads the signed-in profile for an access token.
func (c *PolisClient) UserInfo(ctx context.Context, accessToken string) (PolisProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuerURL+"/api/oauth/userinfo", nil) // #nosec G704 -- issuerURL is configuration, not request input
	if err != nil {
		return PolisProfile{}, errcodes.Wrap(errcodes.CodePolisUserinfoFailed, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := c.http.Do(req) // #nosec G704 -- issuerURL is configuration, not request input
	if err != nil {
		return PolisProfile{}, errcodes.Wrap(errcodes.CodePolisUserinfoFailed, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return PolisProfile{}, errcodes.Wrap(errcodes.CodePolisUserinfoFailed, fmt.Errorf("polis: userinfo status %d", res.StatusCode))
	}
	var p PolisProfile
	if err := json.NewDecoder(res.Body).Decode(&p); err != nil {
		return PolisProfile{}, errcodes.Wrap(errcodes.CodePolisUserinfoFailed, err)
	}
	return p, nil
}
