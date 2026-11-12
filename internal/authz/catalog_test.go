// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-authz/rbac"

	"github.com/Steward-GRC/steward-gateway/internal/authz"
)

func TestRolePermissions(t *testing.T) {
	cases := []struct {
		role authz.Role
		want []authz.Permission
	}{
		{authz.RoleReader, []authz.Permission{authz.PolicyRead}},
		{authz.RoleAuthor, []authz.Permission{authz.PolicyRead, authz.PolicyAuthor, authz.PolicySubmit}},
		{authz.RoleApprover, []authz.Permission{authz.PolicyRead, authz.PolicyApprove}},
		{authz.RoleTemplateAdmin, []authz.Permission{authz.PolicyRead, authz.TemplateManage, authz.WorkflowManage}},
		{authz.RoleComplianceAdmin, []authz.Permission{
			authz.PolicyRead, authz.ComplianceManage, authz.ComplianceReport, authz.AuditRead,
		}},
	}
	for _, c := range cases {
		t.Run(string(c.role), func(t *testing.T) {
			got := authz.RolePermissions(c.role)
			for _, p := range c.want {
				if !slices.Contains(got, p) {
					t.Errorf("role %q: missing permission %q (got %v)", c.role, p, got)
				}
			}
		})
	}
}

func TestRolePermissions_SiteAdminHoldsTheCatalogButReadSensitive(t *testing.T) {
	got := authz.RolePermissions(authz.RoleSiteAdmin)
	for _, p := range authz.Permissions() {
		if p == authz.PolicyReadSensitive {
			continue
		}
		if !slices.Contains(got, p) {
			t.Errorf("site-admin missing %q", p)
		}
	}
}

func TestRolePermissions_UnknownRoleGrantsOnlyTheReaderBaseline(t *testing.T) {
	got := authz.RolePermissions("admin")
	if len(got) != 1 || got[0] != authz.PolicyRead {
		t.Fatalf("an unknown role must grant only the implicit reader baseline, got %v", got)
	}
}

func TestRolePermissions_NoRolesStillReads(t *testing.T) {
	if got := authz.RolePermissions(); !slices.Contains(got, authz.PolicyRead) {
		t.Fatalf("no roles must still grant the implicit reader baseline, got %v", got)
	}
}

func TestRolePermissions_Snapshot(t *testing.T) {
	want := map[authz.Role]int{
		authz.RoleReader:          1,
		authz.RoleAuthor:          3,
		authz.RoleApprover:        2,
		authz.RoleTemplateAdmin:   3,
		authz.RoleComplianceAdmin: 4,
		authz.RoleSiteAdmin:       len(authz.Permissions()) - 1,
	}
	for role, n := range want {
		if got := len(authz.RolePermissions(role)); got != n {
			t.Errorf("role %q permission count = %d, want %d (update the snapshot only on purpose)", role, got, n)
		}
	}
}

func TestCatalogSnapshot(t *testing.T) {
	want := []authz.Permission{
		"policy.read", "policy.read_sensitive", "policy.author", "policy.submit", "policy.approve",
		"template.manage", "workflow.manage", "group.manage", "user.manage", "role.manage",
		"audit.read", "compliance.manage", "compliance.report", "settings.manage",
		"delivery.manage", "session.manage",
	}
	if got := authz.Permissions(); !slices.Equal(got, want) {
		t.Fatalf("catalog changed (update the snapshot only on purpose):\n got %v\nwant %v", got, want)
	}
	roles := []authz.Role{"reader", "author", "approver", "template-admin", "compliance-admin", "site-admin"}
	if got := authz.Roles(); !slices.Equal(got, roles) {
		t.Fatalf("roles changed: got %v want %v", got, roles)
	}
}

func TestPermission_Parts(t *testing.T) {
	p := authz.PolicyReadSensitive
	if p.Resource() != "policy" || p.Verb() != "read_sensitive" {
		t.Fatalf("parts of %q = %q, %q", p, p.Resource(), p.Verb())
	}
}

func TestPermission_Scoped(t *testing.T) {
	for _, p := range authz.Permissions() {
		want := p == authz.PolicyAuthor || p == authz.PolicySubmit || p == authz.PolicyApprove
		if got := authz.Catalog.IsScoped(p); got != want {
			t.Errorf("%q scoped = %v, want %v", p, got, want)
		}
	}
}

func TestHasCapability_SiteAdminWildcardCoversPermissionsAddedLater(t *testing.T) {
	if !authz.HasCapability(authz.Subject{Roles: []authz.Role{authz.RoleSiteAdmin}}, "report.export") {
		t.Fatal("site-admin holds every capability, including ones not yet in the catalog")
	}
	if authz.HasCapability(authz.Subject{Roles: []authz.Role{authz.RoleComplianceAdmin}}, "report.export") {
		t.Fatal("a non-wildcard role must not hold a permission outside its grants")
	}
}

func TestParsePermission(t *testing.T) {
	p, err := authz.ParsePermission("audit.read")
	if err != nil || p != authz.AuditRead {
		t.Fatalf("ParsePermission(audit.read) = %q, %v", p, err)
	}
	_, err = authz.ParsePermission("policy.delete")
	if !errors.Is(err, rbac.ErrUnknownPermission) {
		t.Fatalf("want ErrUnknownPermission, got %v", err)
	}
	if code, ok := apperr.Code(err); !ok || code != rbac.CodeUnknownPermission {
		t.Fatalf("want code %d, got %d (%v)", rbac.CodeUnknownPermission, code, ok)
	}
	if got := apperr.Metadata(err)["permission"]; got != "policy.delete" {
		t.Fatalf("want permission metadata, got %q", got)
	}
}

func TestParseRole(t *testing.T) {
	r, err := authz.ParseRole("template-admin")
	if err != nil || r != authz.RoleTemplateAdmin {
		t.Fatalf("ParseRole(template-admin) = %q, %v", r, err)
	}
	_, err = authz.ParseRole("admin")
	if !errors.Is(err, rbac.ErrUnknownRole) {
		t.Fatalf("the dropped admin role must not parse, got %v", err)
	}
	if code, ok := apperr.Code(err); !ok || code != rbac.CodeUnknownRole {
		t.Fatalf("want code %d, got %d (%v)", rbac.CodeUnknownRole, code, ok)
	}
}

func TestNoRoleGrantsReadSensitive(t *testing.T) {
	for _, r := range authz.Roles() {
		if slices.Contains(authz.RolePermissions(r), authz.PolicyReadSensitive) {
			t.Errorf("role %q grants policy.read_sensitive; it is an individual grant only", r)
		}
		if authz.HasCapability(authz.Subject{Roles: []authz.Role{r}}, authz.PolicyReadSensitive) {
			t.Errorf("role %q holds the read_sensitive capability", r)
		}
	}
}

func TestEmbeddedCatalogMatchesTheOldMatrix(t *testing.T) {
	want := map[authz.Role][]authz.Permission{
		authz.RoleReader:          {authz.PolicyRead},
		authz.RoleAuthor:          {authz.PolicyRead, authz.PolicyAuthor, authz.PolicySubmit},
		authz.RoleApprover:        {authz.PolicyRead, authz.PolicyApprove},
		authz.RoleTemplateAdmin:   {authz.PolicyRead, authz.TemplateManage, authz.WorkflowManage},
		authz.RoleComplianceAdmin: {authz.PolicyRead, authz.ComplianceManage, authz.ComplianceReport, authz.AuditRead},
	}
	for role, perms := range want {
		got := authz.RolePermissions(role)
		if len(got) != len(perms) {
			t.Errorf("role %q: got %v, want %v", role, got, perms)
			continue
		}
		for _, p := range perms {
			if !slices.Contains(got, p) {
				t.Errorf("role %q: missing %q", role, p)
			}
		}
	}
	if got := len(authz.RolePermissions(authz.RoleSiteAdmin)); got != 15 {
		t.Errorf("site-admin permission count = %d, want 15", got)
	}
}

// Every constant the gateway names must exist in the catalog, and every catalog
// permission and role must have a constant, so the two cannot drift apart.
func TestConstantsMatchTheCatalog(t *testing.T) {
	consts := []authz.Permission{
		authz.PolicyRead, authz.PolicyReadSensitive, authz.PolicyAuthor, authz.PolicySubmit, authz.PolicyApprove,
		authz.TemplateManage, authz.WorkflowManage, authz.GroupManage, authz.UserManage, authz.RoleManage,
		authz.AuditRead, authz.ComplianceManage, authz.ComplianceReport, authz.SettingsManage,
		authz.DeliveryManage, authz.SessionManage,
	}
	for _, p := range consts {
		if _, err := authz.Catalog.ParsePermission(string(p)); err != nil {
			t.Errorf("constant %q is not in the catalog: %v", p, err)
		}
	}
	for _, p := range authz.Catalog.PermissionNames() {
		if !slices.Contains(consts, p) {
			t.Errorf("catalog permission %q has no constant", p)
		}
	}
	roleConsts := []authz.Role{
		authz.RoleReader, authz.RoleAuthor, authz.RoleApprover,
		authz.RoleTemplateAdmin, authz.RoleComplianceAdmin, authz.RoleSiteAdmin,
	}
	for _, r := range roleConsts {
		if _, err := authz.Catalog.ParseRole(string(r)); err != nil {
			t.Errorf("constant %q is not in the catalog: %v", r, err)
		}
	}
	for _, r := range authz.Catalog.RoleNames() {
		if !slices.Contains(roleConsts, r) {
			t.Errorf("catalog role %q has no constant", r)
		}
	}
}

func TestCatalogReadSettings(t *testing.T) {
	c := authz.Catalog
	if c.BaselineRole != authz.RoleReader || c.Read.Permission != authz.PolicyRead || c.Read.SensitivePermission != authz.PolicyReadSensitive {
		t.Fatalf("read settings changed: %+v baseline %q", c.Read, c.BaselineRole)
	}
	if !slices.Equal(c.Read.ObfuscateRoles, []authz.Role{authz.RoleSiteAdmin}) {
		t.Fatalf("obfuscate roles: %v", c.Read.ObfuscateRoles)
	}
}

// The gateway reports a denial through gRPC status codes, not apperr; the rbac
// error codes are still the shared 9001/9003/9004 band.
func TestRBACErrorCodesAreStable(t *testing.T) {
	codes := map[int]string{}
	for _, e := range rbac.Entries() {
		codes[e.Code] = e.Symbol
	}
	for code, sym := range map[int]string{9001: "AUTHZ_DENIED", 9003: "AUTHZ_UNKNOWN_PERMISSION", 9004: "AUTHZ_UNKNOWN_ROLE"} {
		if codes[code] != sym {
			t.Errorf("code %d = %q, want %q", code, codes[code], sym)
		}
	}
}
