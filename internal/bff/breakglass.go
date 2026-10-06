// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"errors"
	"net/http"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

const breakGlassPath = "/auth/breakglass"

// BreakGlassLogin is POST /auth/breakglass {email, password}: the local
// password sign-in kept for when SSO is down. Identity decides who is
// eligible; the sign-in still owes the second factor like any other.
func (h *Handler) BreakGlassLogin(w http.ResponseWriter, r *http.Request) {
	l := h.logger(r.Context())
	var in struct{ Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Email == "" || in.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	elig, err := h.Identity.CheckBreakGlassEligibility(r.Context(), &identityv1.CheckBreakGlassEligibilityRequest{Email: in.Email})
	if err != nil {
		l.Warn("break-glass: eligibility check failed", log.F("flow", "breakglass"), errField(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	if !elig.GetEligible() {
		h.authOutcome(r.Context(), breakGlassPath, "breakglass_denied:"+elig.GetReason(), nil)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "not_eligible"})
		return
	}
	res, err := h.Auth.VerifyPassword(r.Context(), in.Email, in.Password)
	if errors.Is(err, ErrInvalidCredentials) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	if err != nil {
		l.Warn("break-glass: kratos unreachable", log.F("flow", "breakglass"), errField(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "auth_backend_unreachable"})
		return
	}
	h.authOutcome(r.Context(), breakGlassPath, "breakglass_login", nil)
	if h.BreakGlassPublish != nil {
		h.BreakGlassPublish(r.Context(), in.Email)
	}
	h.finishPasswordLogin(w, r, res, "breakglass")
}
