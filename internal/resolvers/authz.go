// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// The gateway is the enforcement boundary: every resolver gates here first,
// even when the callee checks again.

// requireRole returns nil when the caller holds any of roles, Unauthenticated
// without a signed-in user, and PermissionDenied otherwise.
func requireRole(ctx context.Context, roles ...string) error {
	c, err := signedIn(ctx)
	if err != nil {
		return err
	}
	for _, r := range roles {
		if principal.HasRole(c, r) {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "insufficient role for this operation")
}

// RequireRoleForTest exposes requireRole to the resolvers_test package.
func RequireRoleForTest(ctx context.Context, roles ...string) error {
	return requireRole(ctx, roles...)
}

// requireSiteAdmin gates a site-admin-only resolver and returns the caller's
// user id.
func requireSiteAdmin(ctx context.Context) (string, error) {
	if err := requireRole(ctx, string(authz.RoleSiteAdmin)); err != nil {
		return "", err
	}
	return claimsUserID(ctx)
}

func signedIn(ctx context.Context) (principal.Claims, error) {
	c, ok := principal.FromContext(ctx)
	if !ok || c.UserID() == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	return c, nil
}

// claimsUserID returns the signed-in user's id. Resolvers bind owner and actor
// ids from it, never from GraphQL input.
func claimsUserID(ctx context.Context) (string, error) {
	c, err := signedIn(ctx)
	if err != nil {
		return "", err
	}
	return c.UserID(), nil
}

// subjectFromCtx builds the steward-authz Subject for the signed-in user.
// BreakGlass is left unset; the read paths fill it per request.
func subjectFromCtx(ctx context.Context) (authz.Subject, error) {
	c, err := signedIn(ctx)
	if err != nil {
		return authz.Subject{}, err
	}
	roles := make([]authz.Role, 0, len(c.Roles()))
	for _, r := range c.Roles() {
		roles = append(roles, authz.Role(r))
	}
	sg := make([]authz.ScopedGrant, 0, len(c.ScopedRoles()))
	for _, s := range c.ScopedRoles() {
		sg = append(sg, authz.ScopedGrant{Role: authz.Role(s.Role), Category: s.Category})
	}
	ov := make([]authz.Override, 0, len(c.PolicyOverrides()))
	for _, o := range c.PolicyOverrides() {
		ov = append(ov, authz.Override{ResourceID: o.PolicyNumber, Grant: authz.Grant(o.Effect)})
	}
	return authz.Subject{
		UserID:        c.UserID(),
		Roles:         roles,
		Groups:        c.IdpGroups(),
		ScopedGrants:  sg,
		Overrides:     ov,
		ReadSensitive: c.ReadSensitive(),
		Root:          c.IsRoot(),
	}, nil
}

// evalSubjectFromCtx is subjectFromCtx plus the caller's user id.
func evalSubjectFromCtx(ctx context.Context) (string, authz.Subject, error) {
	subj, err := subjectFromCtx(ctx)
	if err != nil {
		return "", authz.Subject{}, err
	}
	return subj.UserID, subj, nil
}

// authorizeOp gates a resolver on a permission that isn't aimed at one
// resource.
func authorizeOp(ctx context.Context, p authz.Permission) error {
	s, err := subjectFromCtx(ctx)
	if err != nil {
		return err
	}
	if !authz.Authorize(s, p, nil).Allowed() {
		return status.Error(codes.PermissionDenied, "not authorized: "+string(p))
	}
	return nil
}

// AuthorizeOpForTest exposes authorizeOp to the resolvers_test package.
func AuthorizeOpForTest(ctx context.Context, p authz.Permission) error {
	return authorizeOp(ctx, p)
}

// authorizeCapability is the coarse check for work spanning categories the
// gateway can't resolve up front: the caller must hold p in some scope, and the
// callee makes the per-resource decision.
func authorizeCapability(ctx context.Context, p authz.Permission) error {
	s, err := subjectFromCtx(ctx)
	if err != nil {
		return err
	}
	if !authz.HasCapability(s, p) {
		return status.Error(codes.PermissionDenied, "not authorized: "+string(p))
	}
	return nil
}

// AuthorizeCapabilityForTest exposes authorizeCapability to the resolvers_test
// package.
func AuthorizeCapabilityForTest(ctx context.Context, p authz.Permission) error {
	return authorizeCapability(ctx, p)
}
