// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	reportingv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/reporting/v1"
	authz "github.com/Steward-GRC/steward-gateway/internal/authz"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// The Compliance module's off switch and its four-eyes hard reset. Reporting
// owns the switch and the reset; identity owns the approval
// (see the hard reset resolvers in identity_resolver.go). The gateway gates
// every call by role first and relays reporting's refusals (MODULE_OFF 8113,
// HARD_RESET_* 8114 to 8118) unchanged, so the browser sees reporting's own
// code and message. Nothing here reads, logs or returns case or reporter data,
// and the confirmation phrase and the request reason are never logged.

// requireRoot gates a root-only resolver and returns the caller's claims.
func requireRoot(ctx context.Context) (principal.Claims, error) {
	c, err := signedIn(ctx)
	if err != nil {
		return nil, err
	}
	if !c.IsRoot() {
		return nil, status.Error(codes.PermissionDenied, "only the root admin can do this")
	}
	return c, nil
}

// requireSiteAdminOrRoot gates a resolver on the site-admin role. Root holds
// that role too; the explicit root check keeps the gate true if a claim set
// ever lists root without it.
func requireSiteAdminOrRoot(ctx context.Context) (principal.Claims, error) {
	c, err := signedIn(ctx)
	if err != nil {
		return nil, err
	}
	if c.IsRoot() || principal.HasRole(c, string(authz.RoleSiteAdmin)) {
		return c, nil
	}
	return nil, status.Error(codes.PermissionDenied, "only a site admin can do this")
}

// requireComplianceManager gates on compliance.manage (the site-admin role
// holds every permission) or root, the same rule reporting applies.
func requireComplianceManager(ctx context.Context) (principal.Claims, error) {
	c, err := signedIn(ctx)
	if err != nil {
		return nil, err
	}
	if c.IsRoot() {
		return c, nil
	}
	if err := authorizeOp(ctx, authz.ComplianceManage); err != nil {
		return nil, err
	}
	return c, nil
}

// ComplianceSettingsResolver reads the Compliance settings (the module
// switch for now) from reporting.
func (r *Resolver) ComplianceSettingsResolver(ctx context.Context) (*ComplianceSettings, error) {
	lg := r.logger().Ctx(ctx)
	if _, err := requireComplianceManager(ctx); err != nil {
		lg.Warn("compliance settings read refused", log.F("code", status.Code(err).String()))
		return nil, err
	}
	if r.ComplianceSettingsClient == nil {
		lg.Error(status.Error(codes.Unavailable, "no reporting settings client"), "compliance settings: reporting settings unavailable")
		return nil, status.Error(codes.Unavailable, "reporting settings unavailable")
	}
	start := time.Now()
	resp, err := r.ComplianceSettingsClient.GetSettings(ctx, &reportingv1.GetSettingsRequest{})
	if err != nil {
		lg.Warn("compliance settings read failed", log.F("code", status.Code(err).String()), log.F("ms", time.Since(start).Milliseconds()))
		return nil, err
	}
	enabled := resp.GetSettings().GetModuleEnabled()
	lg.Debug("compliance settings read", log.F("moduleEnabled", enabled), log.F("ms", time.Since(start).Milliseconds()))
	return &ComplianceSettings{ModuleEnabled: enabled}, nil
}

// SetComplianceModuleResolver switches the Compliance module off or on.
// Reporting audits the change and refuses act-as.
func (r *Resolver) SetComplianceModuleResolver(ctx context.Context, enabled bool) (*ComplianceSettings, error) {
	lg := r.logger().Ctx(ctx)
	c, err := requireComplianceManager(ctx)
	if err != nil {
		lg.Warn("compliance module switch refused", log.F("enabled", enabled), log.F("code", status.Code(err).String()))
		return nil, err
	}
	if r.ModuleClient == nil {
		lg.Error(status.Error(codes.Unavailable, "no reporting module client"), "compliance module switch: reporting module service unavailable")
		return nil, status.Error(codes.Unavailable, "reporting module service unavailable")
	}
	lg.Info("compliance module switch requested", log.F("enabled", enabled), log.F("userId", c.UserID()))
	start := time.Now()
	resp, err := r.ModuleClient.SetComplianceModule(ctx, &reportingv1.SetComplianceModuleRequest{Enabled: enabled})
	if err != nil {
		lg.Warn("compliance module switch refused by reporting", log.F("enabled", enabled), log.F("code", status.Code(err).String()), log.F("ms", time.Since(start).Milliseconds()))
		return nil, err
	}
	lg.Info("compliance module switched", log.F("moduleEnabled", resp.GetModuleEnabled()), log.F("userId", c.UserID()), log.F("ms", time.Since(start).Milliseconds()))
	return &ComplianceSettings{ModuleEnabled: resp.GetModuleEnabled()}, nil
}

// ExecuteHardResetResolver runs the Compliance hard reset once identity's
// four-eyes request is approved. Root only. The confirmation phrase goes to
// reporting untouched and is never logged.
func (r *Resolver) ExecuteHardResetResolver(ctx context.Context, requestID, confirmation string) (*HardResetResult, error) {
	lg := r.logger().Ctx(ctx)
	c, err := requireRoot(ctx)
	if err != nil {
		lg.Warn("compliance hard reset refused", log.F("requestId", requestID), log.F("code", status.Code(err).String()))
		return nil, err
	}
	if r.ModuleClient == nil {
		lg.Error(status.Error(codes.Unavailable, "no reporting module client"), "compliance hard reset: reporting module service unavailable")
		return nil, status.Error(codes.Unavailable, "reporting module service unavailable")
	}
	lg.Info("compliance hard reset requested", log.F("requestId", requestID), log.F("userId", c.UserID()))
	start := time.Now()
	resp, err := r.ModuleClient.ExecuteHardReset(ctx, &reportingv1.ExecuteHardResetRequest{RequestId: requestID, Confirmation: confirmation})
	if err != nil {
		lg.Warn("compliance hard reset refused by reporting", log.F("requestId", requestID), log.F("code", status.Code(err).String()), log.F("ms", time.Since(start).Milliseconds()))
		return nil, err
	}
	lg.Info("compliance hard reset done", log.F("requestId", requestID), log.F("casesDeleted", resp.GetCasesDeleted()), log.F("ms", time.Since(start).Milliseconds()))
	return &HardResetResult{
		CasesDeleted: int(resp.GetCasesDeleted()),
		RequestedBy:  resp.GetRequestedByUserId(),
		ApprovedBy:   resp.GetApprovedByUserId(),
	}, nil
}
