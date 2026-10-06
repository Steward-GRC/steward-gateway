// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"net/http"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// Discover is POST /auth/discover {identifier}: which sign-in the identifier
// uses. idpInitiatedSsoUrl is set for a connection that only signs in from the
// IdP; allowLocal says the password form may still be offered.
func (h *Handler) Discover(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Identifier string `json:"identifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Identifier == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	res, err := h.Identity.Discover(r.Context(), &identityv1.DiscoverRequest{Identifier: in.Identifier})
	if err != nil {
		h.logger(r.Context()).Warn("discover: identity call failed", errField(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	log.Trace(h.logger(r.Context()), "discover", log.F("method", res.GetMethod()), log.F("connection", res.GetConnectionAlias()))
	writeJSON(w, http.StatusOK, map[string]any{
		"method":             res.GetMethod(),
		"connectionAlias":    res.GetConnectionAlias(),
		"idpInitiatedSsoUrl": res.GetIdpInitiatedSsoUrl(),
		"allowLocal":         res.GetAllowLocal(),
	})
}
