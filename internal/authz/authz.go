// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package authz is the gateway's permission catalog and per-document access
// decision. The catalog is the canonical Steward catalog (catalog.json, this
// repo is its home); the mechanism is go-authz's rbac package. The types are
// aliases of rbac's so a Subject built here goes straight to rbac, and the
// constants name the catalog's permissions and roles. Category rule decisions
// are not made here; they come from go-authz/ordered.
package authz

import (
	_ "embed"
	"slices"

	"github.com/Bugs5382/go-authz/rbac"
)

//go:embed catalog.json
var catalogJSON []byte

// Catalog is the parsed canonical catalog. It is read-only; a catalog that does
// not parse stops the process at start-up.
var Catalog = rbac.MustParse(catalogJSON)

type (
	Subject     = rbac.Subject
	Resource    = rbac.Resource
	Decision    = rbac.Decision
	Effect      = rbac.Effect
	Reason      = rbac.Reason
	Grant       = rbac.Grant
	Override    = rbac.Override
	ScopedGrant = rbac.ScopedGrant
	Permission  = rbac.Permission
	Role        = rbac.Role
)

const (
	EffectDeny      = rbac.EffectDeny
	EffectAllow     = rbac.EffectAllow
	EffectObfuscate = rbac.EffectObfuscate

	ReasonGranted           = rbac.ReasonGranted
	ReasonMissingCapability = rbac.ReasonMissingCapability
	ReasonOutOfScope        = rbac.ReasonOutOfScope
	ReasonOverrideAllow     = rbac.ReasonOverrideAllow
	ReasonBreakGlass        = rbac.ReasonBreakGlass
	ReasonExcluded          = rbac.ReasonExcluded
	ReasonSensitive         = rbac.ReasonSensitive
	ReasonAssigned          = rbac.ReasonAssigned

	GrantBlank = rbac.GrantBlank
	GrantAllow = rbac.GrantAllow
	GrantDeny  = rbac.GrantDeny
)

// The permissions of catalog.json.
const (
	PolicyRead          Permission = "policy.read"
	PolicyReadSensitive Permission = "policy.read_sensitive"
	PolicyAuthor        Permission = "policy.author"
	PolicySubmit        Permission = "policy.submit"
	PolicyApprove       Permission = "policy.approve"
	TemplateManage      Permission = "template.manage"
	WorkflowManage      Permission = "workflow.manage"
	GroupManage         Permission = "group.manage"
	UserManage          Permission = "user.manage"
	RoleManage          Permission = "role.manage"
	AuditRead           Permission = "audit.read"
	ComplianceManage    Permission = "compliance.manage"
	ComplianceReport    Permission = "compliance.report"
	SettingsManage      Permission = "settings.manage"
	DeliveryManage      Permission = "delivery.manage"
	SessionManage       Permission = "session.manage"
)

// The roles of catalog.json.
const (
	RoleReader          Role = "reader"
	RoleAuthor          Role = "author"
	RoleApprover        Role = "approver"
	RoleTemplateAdmin   Role = "template-admin"
	RoleComplianceAdmin Role = "compliance-admin"
	RoleSiteAdmin       Role = "site-admin"
)

// Authorize decides one permission for s on r (nil when the action is not aimed
// at one resource).
func Authorize(s Subject, p Permission, r *Resource) Decision {
	return Catalog.Authorize(s, p, r)
}

// HasCapability reports whether s could hold p in at least one scope.
func HasCapability(s Subject, p Permission) bool {
	return Catalog.HasCapability(s, p)
}

// RolePermissions lists the catalog permissions the roles hold, with the
// baseline role added, in catalog order.
func RolePermissions(rs ...Role) []Permission {
	return Catalog.PermissionsForRoles(rs...)
}

// Permissions lists every catalog permission in catalog order.
func Permissions() []Permission { return slices.Clone(Catalog.PermissionNames()) }

// Roles lists every catalog role in catalog order.
func Roles() []Role { return slices.Clone(Catalog.RoleNames()) }

// ParsePermission returns the catalog permission named s, or an error coded
// AUTHZ_UNKNOWN_PERMISSION.
func ParsePermission(s string) (Permission, error) { return Catalog.ParsePermission(s) }

// ParseRole returns the catalog role named s, or an error coded
// AUTHZ_UNKNOWN_ROLE.
func ParseRole(s string) (Role, error) { return Catalog.ParseRole(s) }

// IsSiteAdmin reports whether s holds the site-admin role.
func IsSiteAdmin(s Subject) bool { return slices.Contains(s.Roles, RoleSiteAdmin) }
