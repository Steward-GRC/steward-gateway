// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

const defaultTestLinkTTL = 30 * time.Minute

func (h *Handler) testLinkTTL() time.Duration {
	if h.TestLinkTTL > 0 {
		return h.TestLinkTTL
	}
	return defaultTestLinkTTL
}

type mintTestLinkRequest struct {
	ConnectionID string `json:"connectionId"`
	Alias        string `json:"alias"`
	Tenant       string `json:"tenant"`
	ReturnPath   string `json:"returnPath"`
}

type mintTestLinkResponse struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expiresAt"`
}

// MintSSOTestLink is POST /admin/sso/test-link {connectionId, alias, tenant?,
// returnPath?}: a site admin mints a link someone else can open to test the
// connection. The result is recorded as the minting admin. It must run inside
// Authenticate.
func (h *Handler) MintSSOTestLink(w http.ResponseWriter, r *http.Request) {
	if !requireSiteAdminHTTP(w, r) {
		return
	}
	l := h.logger(r.Context())
	claims, _ := principal.FromContext(r.Context())
	if h.SSOTestLink == nil {
		idpWriteError(w, http.StatusServiceUnavailable, "test-link store not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxIDPRequestBodyBytes)
	var req mintTestLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		idpWriteError(w, http.StatusBadRequest, `Malformed request — expected JSON {"connectionId","alias"}`)
		return
	}
	if strings.TrimSpace(req.ConnectionID) == "" || strings.TrimSpace(req.Alias) == "" {
		idpWriteError(w, http.StatusBadRequest, "connectionId and alias are required")
		return
	}
	token, err := GenerateState()
	if err != nil {
		idpWriteError(w, http.StatusInternalServerError, "server")
		return
	}
	ttl := h.testLinkTTL()
	rec := SSOTestLinkRecord{
		ConnectionID: strings.TrimSpace(req.ConnectionID),
		Alias:        strings.TrimSpace(req.Alias),
		Tenant:       strings.ToLower(strings.TrimSpace(req.Tenant)),
		ReturnPath:   validateAdminReturnPath(req.ReturnPath),
		AdminUserID:  claims.UserID(),
	}
	if err := h.SSOTestLink.PutSSOTestLink(r.Context(), token, rec, ttl); err != nil {
		l.Warn("sso test link: store write failed", log.F("connection_id", rec.ConnectionID), errField(err))
		idpWriteError(w, http.StatusInternalServerError, "server")
		return
	}
	q := url.Values{}
	q.Set("connection", rec.Alias)
	q.Set("mode", "test")
	q.Set("testToken", token)
	log.Trace(l, "sso test link: minted", log.F("connection_id", rec.ConnectionID), log.F("user_id", rec.AdminUserID), log.F("ttl", ttl.String()))
	writeJSON(w, http.StatusOK, mintTestLinkResponse{
		URL:       h.SSORedirectBase + "/auth/sso/start?" + q.Encode(),
		ExpiresAt: time.Now().Add(ttl).UTC().Format(time.RFC3339),
	})
}
