// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"encoding/json"
	"net/http"

	log "github.com/Bugs5382/go-log"
	stewardauthz "github.com/Steward-GRC/steward-authz"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Handlers holds the unauthenticated /setup/* HTTP handlers.
type Handlers struct {
	identity   identityv1.IdentityReadServiceClient
	ssoAdmin   identityv1.IdentitySSOAdminServiceClient
	setupToken string
	log        log.Logger
}

// New returns a Handlers wired to identity and guarded by setupToken.
func New(identity identityv1.IdentityReadServiceClient, setupToken string) *Handlers {
	return &Handlers{identity: identity, setupToken: setupToken}
}

// WithLogger sets the logger. Returns the receiver for chaining.
func (h *Handlers) WithLogger(l log.Logger) *Handlers {
	h.log = l
	return h
}

func (h *Handlers) logger(ctx context.Context) log.Logger {
	if h.log == nil {
		return log.Nop()
	}
	return h.log.Ctx(ctx)
}

// WithSSOAdmin wires the IdentitySSOAdminService client used for the OPTIONAL
// first-run SSO bootstrap. Without it, /setup/bootstrap ignores any sso payload and
// behaves exactly as a plain root bootstrap. Returns the receiver for chaining.
func (h *Handlers) WithSSOAdmin(c identityv1.IdentitySSOAdminServiceClient) *Handlers {
	h.ssoAdmin = c
	return h
}

// StateHandler returns an http.HandlerFunc for GET /setup/state.
// Calls identity.GetSetupState and returns {"needsSetup": bool}.
func (h *Handlers) StateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := h.identity.GetSetupState(r.Context(), &identityv1.GetSetupStateRequest{})
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			h.logger(r.Context()).Error(err, "setup: GetSetupState failed")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "setup state unavailable"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"needsSetup": resp.GetNeedsSetup()})
	}
}

// BootstrapHandler returns an http.HandlerFunc for POST /setup/bootstrap.
// Expects JSON {setupToken, username, email, password}. Guards with SETUP_TOKEN
// (503 if unconfigured, 403 on mismatch) then delegates to identity.BootstrapRoot.
// Maps identity gRPC codes: FailedPrecondition→409, InvalidArgument→400,
// Unavailable→503, other→502. Success→200 {"userId": ...}.
func (h *Handlers) BootstrapHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if h.setupToken == "" {
			writeErr(w, http.StatusServiceUnavailable, "setup is not enabled (no SETUP_TOKEN configured)")
			return
		}
		var body struct {
			SetupToken string    `json:"setupToken"`
			Username   string    `json:"username"`
			Email      string    `json:"email"`
			Password   string    `json:"password"`
			Name       string    `json:"name"`
			SSO        *ssoInput `json:"sso"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if body.SetupToken != h.setupToken {
			writeErr(w, http.StatusForbidden, "invalid setup token")
			return
		}
		resp, err := h.identity.BootstrapRoot(r.Context(), &identityv1.BootstrapRootRequest{
			Username: body.Username,
			Email:    body.Email,
			Password: body.Password,
			Name:     body.Name,
		})
		if err != nil {
			h.logger(r.Context()).Error(err, "setup: BootstrapRoot failed", log.F("code", status.Code(err).String()))
			switch status.Code(err) {
			case codes.FailedPrecondition:
				writeErr(w, http.StatusConflict, "already set up")
			case codes.InvalidArgument:
				writeErr(w, http.StatusBadRequest, "username, email, and password are required")
			case codes.Unavailable:
				writeErr(w, http.StatusServiceUnavailable, "identity service unavailable")
			default:
				writeErr(w, http.StatusBadGateway, "bootstrap failed")
			}
			return
		}

		rootID := resp.GetUser().GetId()
		out := map[string]any{"userId": rootID}

		if body.SSO != nil {
			out["sso"] = h.provisionSSO(r.Context(), rootID, body.SSO)
		}

		_ = json.NewEncoder(w).Encode(out)
	}
}

// ssoInput is the optional first-run SSO block on /setup/bootstrap. It mirrors the
// admin org-onboarding "add organization" inputs (AddOrganizationInput) so the
// provisioning can reuse identity's AddOrganization verbatim.
type ssoInput struct {
	OrgName     string            `json:"orgName"`
	Domain      string            `json:"domain"`
	Protocol    string            `json:"protocol"` // "saml" | "oidc"
	DisplayName string            `json:"displayName"`
	Config      map[string]string `json:"config"`
	SecretRef   string            `json:"secretRef"`
}

// provisionSSO creates the organization SSO connection and starts DNS-TXT domain
// verification with identity's onboarding RPCs, as the new root: the root is put
// on the outbound context as the principal, so identity sees it as the actor and
// checks its own roles for it. It never fails setup: an error is folded into the
// returned map under "error".
func (h *Handlers) provisionSSO(ctx context.Context, rootID string, in *ssoInput) map[string]any {
	l := h.logger(ctx)
	if h.ssoAdmin == nil {
		l.Warn("setup: sso requested but no SSO admin client wired; skipping")
		return map[string]any{"error": "sso provisioning is not available on this deployment"}
	}

	authCtx := principal.WithClaims(ctx, principal.Static{
		UserIDValue: rootID,
		RolesValue:  []string{string(stewardauthz.RoleSiteAdmin)},
		IsRootValue: true,
	})

	org, err := h.ssoAdmin.AddOrganization(authCtx, &identityv1.AddOrganizationRequest{
		OrgName:     in.OrgName,
		Domain:      in.Domain,
		Protocol:    in.Protocol,
		DisplayName: in.DisplayName,
		Config:      in.Config,
		SecretRef:   in.SecretRef,
	})
	if err != nil {
		l.Error(err, "setup: SSO AddOrganization failed", log.F("code", status.Code(err).String()))
		return map[string]any{"error": ssoErrMessage(err)}
	}

	result := map[string]any{
		"organization":       orgSummary(org.GetOrganization()),
		"activationDeferred": true,
	}

	dv, err := h.ssoAdmin.StartDomainVerification(authCtx, &identityv1.StartDomainVerificationRequest{
		Domain: in.Domain,
	})
	if err != nil {
		l.Error(err, "setup: SSO StartDomainVerification failed", log.F("code", status.Code(err).String()))
		result["error"] = ssoErrMessage(err)
		return result
	}
	result["domainVerification"] = map[string]any{
		"token":          dv.GetToken(),
		"dnsRecordName":  dv.GetDnsRecordName(),
		"dnsRecordValue": dv.GetDnsRecordValue(),
		"instructions":   dv.GetInstructions(),
	}
	return result
}

// orgSummary projects the identity Organization onto the fields the setup wizard
// needs to confirm what was created and its (disabled, unverified) first-run state.
func orgSummary(o *identityv1.Organization) map[string]any {
	return map[string]any{
		"domain":      o.GetDomain(),
		"orgName":     o.GetOrgName(),
		"protocol":    o.GetProtocol(),
		"displayName": o.GetDisplayName(),
		"verified":    o.GetVerified(),
		"enabled":     o.GetEnabled(),
	}
}

// ssoErrMessage maps identity gRPC codes to a stable, non-leaky message for the
// setup wizard. Unlike the bootstrap error path this never changes the HTTP
// status: first-run SSO is best-effort on top of a completed root bootstrap.
func ssoErrMessage(err error) string {
	switch status.Code(err) {
	case codes.InvalidArgument:
		return "invalid SSO configuration (check org name, domain, protocol, and IdP metadata)"
	case codes.AlreadyExists:
		return "an SSO organization already exists for that domain"
	case codes.FailedPrecondition:
		return "SSO is not ready to provision (the service provider certificate may not be initialized yet)"
	case codes.Unavailable:
		return "SSO provisioning is temporarily unavailable; you can finish setup in Admin -> SSO"
	default:
		return "SSO provisioning failed; you can finish setup in Admin -> SSO"
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}
