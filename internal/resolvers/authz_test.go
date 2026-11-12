// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	authz "github.com/Steward-GRC/steward-gateway/internal/authz"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthorizeOp(t *testing.T) {
	// template-admin holds template.manage -> allowed.
	ctx := ctxWithRoles(t, "u", []string{"template-admin"})
	if err := resolvers.AuthorizeOpForTest(ctx, authz.TemplateManage); err != nil {
		t.Fatalf("template-admin: %v", err)
	}
	// reader lacks template.manage -> PermissionDenied.
	ctx2 := ctxWithRoles(t, "u", []string{"reader"})
	if err := resolvers.AuthorizeOpForTest(ctx2, authz.TemplateManage); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("reader: %v", err)
	}
	// no claims -> Unauthenticated.
	if err := resolvers.AuthorizeOpForTest(t.Context(), authz.TemplateManage); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no claims: %v", err)
	}
}

func TestRequireRole(t *testing.T) {
	// holds one of the required roles -> allowed
	if err := resolvers.RequireRoleForTest(ctxWithRoles(t, "u1", []string{"template-admin"}), "site-admin", "template-admin"); err != nil {
		t.Fatalf("template-admin should pass: %v", err)
	}
	// holds none -> PermissionDenied
	err := resolvers.RequireRoleForTest(ctxWithRoles(t, "u2", []string{"author"}), "site-admin")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	// no claims -> Unauthenticated
	err = resolvers.RequireRoleForTest(t.Context(), "site-admin")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}

func TestAuthorizeCapability(t *testing.T) {
	// A site admin holds every capability except the sensitive read.
	ctx := ctxWithRoles(t, "u", []string{"site-admin"})
	if err := resolvers.AuthorizeCapabilityForTest(ctx, authz.PolicyApprove); err != nil {
		t.Fatalf("site-admin approve capability: %v", err)
	}
	if err := resolvers.AuthorizeCapabilityForTest(ctx, authz.PolicyReadSensitive); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("site-admin read_sensitive: %v", err)
	}
	// A reader holds neither admin nor approve capability.
	ctx2 := ctxWithRoles(t, "u", []string{"reader"})
	if err := resolvers.AuthorizeCapabilityForTest(ctx2, authz.PolicyApprove); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("reader approve: %v", err)
	}
	if err := resolvers.AuthorizeOpForTest(ctx2, authz.AuditRead); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("reader audit.read: %v", err)
	}
	// No claims -> Unauthenticated.
	if err := resolvers.AuthorizeCapabilityForTest(t.Context(), authz.PolicyApprove); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no claims: %v", err)
	}
}
