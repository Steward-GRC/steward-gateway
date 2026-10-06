// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	apperr "github.com/Bugs5382/go-apperr"
	log "github.com/Bugs5382/go-log"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

// passkeyLoginFlowTTL bounds the passkey sign-in ceremony between begin and
// finish.
const passkeyLoginFlowTTL = 5 * time.Minute

// passkeyAuthClient is passkey sign-in; *KratosClient implements it. When the
// wired Auth doesn't, the passkey routes answer 404.
type passkeyAuthClient interface {
	PasskeyLoginBegin(ctx context.Context) (PasskeyLoginResult, error)
	PasskeyLoginFinish(ctx context.Context, flowID, credentialJSON, csrfToken string, cookies map[string]string) (AuthResult, error)
}

// passkeyRegisterAuthClient is passkey registration for a signed-in user.
type passkeyRegisterAuthClient interface {
	PasskeyRegisterBegin(ctx context.Context, sessionToken string) (PasskeyRegisterResult, error)
	PasskeyRegisterFinish(ctx context.Context, sessionToken, flowID, credentialJSON, csrfToken string, cookies map[string]string) error
}

// PasskeyLoginFlow is a passkey sign-in parked between begin and finish. The
// browser holds only an opaque ticket; the Kratos flow id, its CSRF token and
// its cookies stay here.
type PasskeyLoginFlow struct {
	KratosFlowID string            `json:"kratos_flow_id"`
	CSRFToken    string            `json:"csrf_token"`
	Cookies      map[string]string `json:"cookies"`
	ExpiresAt    time.Time         `json:"expires_at"`
}

// PasskeyLoginStore keeps passkey sign-ins between begin and finish. *Store
// implements it on Valkey.
type PasskeyLoginStore interface {
	CreatePasskeyLogin(ctx context.Context, id string, f PasskeyLoginFlow) error
	// ConsumePasskeyLogin reads and deletes the ticket, so it works once.
	ConsumePasskeyLogin(ctx context.Context, id string) (PasskeyLoginFlow, bool, error)
}

func passkeyLoginKey(id string) string { return "pklogin:" + id }

func (s *Store) CreatePasskeyLogin(ctx context.Context, id string, f PasskeyLoginFlow) error {
	return kv{s.c}.put(ctx, passkeyLoginKey(id), f, passkeyLoginFlowTTL)
}

func (s *Store) ConsumePasskeyLogin(ctx context.Context, id string) (PasskeyLoginFlow, bool, error) {
	var f PasskeyLoginFlow
	ok, err := kv{s.c}.take(ctx, passkeyLoginKey(id), &f)
	return f, ok, err
}

func (h *Handler) passkeyClient() (passkeyAuthClient, bool) {
	pk, ok := h.Auth.(passkeyAuthClient)
	return pk, ok && h.PasskeyLogin != nil
}

func (h *Handler) passkeyRegisterClient() (passkeyRegisterAuthClient, bool) {
	pk, ok := h.Auth.(passkeyRegisterAuthClient)
	return pk, ok
}

// PasskeyLoginBegin is POST /auth/passkey/login/begin: it opens a Kratos login
// flow and answers {flowId, optionsJson}, flowId being an opaque one-shot
// ticket.
func (h *Handler) PasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	l := h.logger(r.Context())
	pk, ok := h.passkeyClient()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "passkey_unavailable"})
		return
	}
	res, err := pk.PasskeyLoginBegin(r.Context())
	if err != nil {
		l.Warn("passkey login: begin failed", log.F("flow", "passkey_login"), errField(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "kratos_unreachable"})
		return
	}
	ticket, err := newSessionID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	if err := h.PasskeyLogin.CreatePasskeyLogin(r.Context(), ticket, PasskeyLoginFlow{
		KratosFlowID: res.FlowID,
		CSRFToken:    res.CSRFToken,
		Cookies:      res.Cookies,
		ExpiresAt:    time.Now().Add(passkeyLoginFlowTTL),
	}); err != nil {
		l.Error(err, "passkey login: could not park the flow", log.F("flow", "passkey_login"))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"flowId": ticket, "optionsJson": res.OptionsJSON})
}

// PasskeyLoginFinish is POST /auth/passkey/login/finish {flowId,
// credentialJson}. A verified passkey is a strong factor on its own, so the
// session is issued without the MFA step. Every refusal answers like a wrong
// password.
func (h *Handler) PasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	l := h.logger(r.Context())
	var in struct {
		FlowID         string `json:"flowId"`
		CredentialJSON string `json:"credentialJson"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.FlowID == "" || in.CredentialJSON == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	pk, ok := h.passkeyClient()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "passkey_unavailable"})
		return
	}
	flow, ok, err := h.PasskeyLogin.ConsumePasskeyLogin(r.Context(), in.FlowID)
	if err != nil {
		l.Warn("passkey login: flow store read failed", log.F("flow", "passkey_login"), errField(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "kratos_unreachable"})
		return
	}
	if !ok || flow.KratosFlowID == "" || time.Now().After(flow.ExpiresAt) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	res, err := pk.PasskeyLoginFinish(r.Context(), flow.KratosFlowID, in.CredentialJSON, flow.CSRFToken, flow.Cookies)
	if errors.Is(err, ErrInvalidCredentials) {
		log.Trace(l, "passkey login: assertion rejected", log.F("flow", "passkey_login"), log.F("reason", "invalid_credentials"))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	if err != nil {
		l.Warn("passkey login: finish failed", log.F("flow", "passkey_login"), errField(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "kratos_unreachable"})
		return
	}

	user, err := h.resolveUserByEmail(r.Context(), res.Email)
	if err != nil {
		if code, ok := apperr.Code(err); ok && code == errcodes.CodeKratosEmailNoPlatformUser {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
			return
		}
		l.Warn("passkey login: identity lookup by email failed", log.F("flow", "passkey_login"), errField(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	if !user.GetEnabled() {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	log.Trace(l, "passkey login: session issued", log.F("flow", "passkey_login"), log.F("user_id", user.GetId()))
	h.issueSession(w, r, Session{
		AccessToken: res.AccessToken,
		ExpiresAt:   res.ExpiresAt,
		UserID:      user.GetId(),
		MFAVerified: true,
	})
}

// sessionByCookie loads the caller's session; the registration routes need a
// signed-in user and answer 401 without one.
func (h *Handler) sessionByCookie(r *http.Request) (string, Session, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return "", Session{}, false
	}
	sess, ok, err := h.Store.Get(r.Context(), c.Value)
	if err != nil || !ok {
		return "", Session{}, false
	}
	return c.Value, sess, true
}

// PasskeyRegisterBegin is POST /auth/passkey/register/begin: it opens a Kratos
// settings flow for the signed-in user and answers {flowId, optionsJson}. The
// flow's CSRF token and cookies wait on the session for finish.
func (h *Handler) PasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	l := h.logger(r.Context())
	pk, ok := h.passkeyRegisterClient()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "passkey_unavailable"})
		return
	}
	sid, sess, ok := h.sessionByCookie(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	res, err := pk.PasskeyRegisterBegin(r.Context(), sess.AccessToken)
	if errors.Is(err, ErrPasskeyReauthRequired) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "reauth_required"})
		return
	}
	if err != nil {
		l.Warn("passkey register: begin failed", log.F("flow", "passkey_register"), log.F("user_id", sess.UserID), errField(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "kratos_unreachable"})
		return
	}
	sess.PasskeyReg = &PasskeyRegState{
		FlowID:    res.FlowID,
		CSRFToken: res.CSRFToken,
		Cookies:   res.Cookies,
		ExpiresAt: time.Now().Add(passkeyRegisterFlowTTL),
	}
	if err := h.Store.Save(r.Context(), sid, sess); err != nil {
		l.Error(err, "passkey register: could not stash the flow", log.F("user_id", sess.UserID))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"flowId": res.FlowID, "optionsJson": res.OptionsJSON})
}

// PasskeyRegisterFinish is POST /auth/passkey/register/finish {flowId,
// credentialJson}: it submits the attestation to the flow begun for this
// session.
func (h *Handler) PasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	l := h.logger(r.Context())
	var in struct {
		FlowID         string `json:"flowId"`
		CredentialJSON string `json:"credentialJson"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.FlowID == "" || in.CredentialJSON == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	pk, ok := h.passkeyRegisterClient()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "passkey_unavailable"})
		return
	}
	sid, sess, ok := h.sessionByCookie(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	reg := sess.PasskeyReg
	if reg == nil || reg.FlowID != in.FlowID || time.Now().After(reg.ExpiresAt) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	err := pk.PasskeyRegisterFinish(r.Context(), sess.AccessToken, reg.FlowID, in.CredentialJSON, reg.CSRFToken, reg.Cookies)
	if errors.Is(err, ErrPasskeyRegistrationRejected) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "registration_rejected"})
		return
	}
	if errors.Is(err, ErrPasskeyReauthRequired) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "reauth_required"})
		return
	}
	if err != nil {
		l.Warn("passkey register: finish failed", log.F("flow", "passkey_register"), log.F("user_id", sess.UserID), errField(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "kratos_unreachable"})
		return
	}

	// The passkey is stored in Kratos by now; a failed cleanup only leaves a
	// stale stash that expires on its own.
	sess.PasskeyReg = nil
	if err := h.Store.Save(r.Context(), sid, sess); err != nil {
		l.Warn("passkey register: could not clear the stashed flow", log.F("user_id", sess.UserID), errField(err))
	}
	log.Trace(l, "passkey register: passkey added", log.F("user_id", sess.UserID))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
