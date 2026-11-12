// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"errors"
	"testing"

	"github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-authz/rbac"

	"github.com/Steward-GRC/steward-gateway/internal/authz"
)

func withRoles(roles ...authz.Role) authz.Subject { return authz.Subject{Roles: roles} }

func TestAuthorize_Capability(t *testing.T) {
	if d := authz.Authorize(withRoles(authz.RoleReader), authz.PolicyAuthor, &authz.Resource{Category: "Finance"}); d.Effect != authz.EffectDeny {
		t.Fatalf("reader author: %+v", d)
	} else if d.Reason != authz.ReasonMissingCapability {
		t.Fatalf("reader author reason: %q", d.Reason)
	}
	bob := authz.Subject{UserID: "bob", Roles: []authz.Role{authz.RoleAuthor}, ScopedGrants: []authz.ScopedGrant{{Role: authz.RoleAuthor, Category: "Finance"}}}
	if d := authz.Authorize(bob, authz.PolicyAuthor, &authz.Resource{Category: "Finance"}); d.Effect != authz.EffectAllow {
		t.Fatalf("author in scope: %+v", d)
	}
	if d := authz.Authorize(bob, authz.PolicyAuthor, &authz.Resource{Category: "People"}); d.Effect != authz.EffectDeny || d.Reason != authz.ReasonOutOfScope {
		t.Fatalf("author out of scope: %+v", d)
	}
}

func TestAuthorize_ScopedActionWithoutResourceIsOutOfScope(t *testing.T) {
	bob := authz.Subject{ScopedGrants: []authz.ScopedGrant{{Role: authz.RoleAuthor, Category: "Finance"}}}
	if d := authz.Authorize(bob, authz.PolicyAuthor, nil); d.Effect != authz.EffectDeny || d.Reason != authz.ReasonOutOfScope {
		t.Fatalf("scoped action with no resource: %+v", d)
	}
}

func TestAuthorize_SiteAdminApprove(t *testing.T) {
	res := &authz.Resource{Category: "Finance", CategoryLineage: []string{"Finance"}}
	if d := authz.Authorize(withRoles(authz.RoleSiteAdmin), authz.PolicyApprove, res); d.Effect != authz.EffectDeny {
		t.Fatalf("site-admin approve without a grant must deny: %+v", d)
	}
	alice := authz.Subject{Roles: []authz.Role{authz.RoleSiteAdmin}, ScopedGrants: []authz.ScopedGrant{{Role: authz.RoleApprover, Category: "Finance"}}}
	if d := authz.Authorize(alice, authz.PolicyApprove, res); d.Effect != authz.EffectAllow {
		t.Fatalf("site-admin approve with a grant must allow: %+v", d)
	}
	if d := authz.Authorize(withRoles(authz.RoleSiteAdmin), authz.PolicyAuthor, res); d.Effect != authz.EffectAllow {
		t.Fatalf("site-admin author: %+v", d)
	}
	if d := authz.Authorize(withRoles(authz.RoleSiteAdmin), authz.PolicySubmit, res); d.Effect != authz.EffectAllow {
		t.Fatalf("site-admin submit: %+v", d)
	}
	carol := authz.Subject{ScopedGrants: []authz.ScopedGrant{{Role: authz.RoleApprover, Category: "Finance"}}}
	if d := authz.Authorize(carol, authz.PolicyApprove, res); d.Effect != authz.EffectAllow {
		t.Fatalf("scoped approver: %+v", d)
	}
}

func TestAuthorize_ScopedGrantInheritsDownTheTree(t *testing.T) {
	bob := authz.Subject{ScopedGrants: []authz.ScopedGrant{{Role: authz.RoleAuthor, Category: "Workplace"}}}
	child := &authz.Resource{Category: "Facilities", CategoryLineage: []string{"Facilities", "Workplace"}}
	if d := authz.Authorize(bob, authz.PolicyAuthor, child); d.Effect != authz.EffectAllow {
		t.Fatalf("an author of the parent covers the child: %+v", d)
	}
	self := &authz.Resource{Category: "Workplace", CategoryLineage: []string{"Workplace"}}
	if d := authz.Authorize(bob, authz.PolicyAuthor, self); d.Effect != authz.EffectAllow {
		t.Fatalf("an author of the parent covers the parent: %+v", d)
	}
	sibling := &authz.Resource{Category: "Expenses", CategoryLineage: []string{"Expenses", "Finance"}}
	if d := authz.Authorize(bob, authz.PolicyAuthor, sibling); d.Effect != authz.EffectDeny {
		t.Fatalf("an author of the parent must not cover a category outside its subtree: %+v", d)
	}
	if d := authz.Authorize(bob, authz.PolicyApprove, child); d.Effect != authz.EffectDeny {
		t.Fatalf("an author grant must not satisfy approve: %+v", d)
	}
}

func TestAuthorize_LineageFallsBackToTheCategory(t *testing.T) {
	bob := authz.Subject{ScopedGrants: []authz.ScopedGrant{{Role: authz.RoleAuthor, Category: "Travel"}}}
	if d := authz.Authorize(bob, authz.PolicySubmit, &authz.Resource{Category: "Travel"}); d.Effect != authz.EffectAllow {
		t.Fatalf("with no lineage the category itself is matched: %+v", d)
	}
}

func TestHasCapability(t *testing.T) {
	if !authz.HasCapability(withRoles(authz.RoleSiteAdmin), authz.PolicyApprove) {
		t.Fatal("site-admin approve")
	}
	if authz.HasCapability(withRoles(authz.RoleReader), authz.PolicyApprove) {
		t.Fatal("reader approve")
	}
	carol := authz.Subject{ScopedGrants: []authz.ScopedGrant{{Role: authz.RoleApprover, Category: "Finance"}}}
	if !authz.HasCapability(carol, authz.PolicyApprove) {
		t.Fatal("a scoped-only approver holds the approve capability")
	}
	if authz.HasCapability(carol, authz.TemplateManage) {
		t.Fatal("a scoped approver must not hold template.manage")
	}
	if !authz.HasCapability(authz.Subject{ReadSensitive: true}, authz.PolicyReadSensitive) {
		t.Fatal("the individual read_sensitive grant confers the capability without a role")
	}
}

func TestAuthorize_GlobalCapability(t *testing.T) {
	frank := withRoles(authz.RoleTemplateAdmin)
	if d := authz.Authorize(frank, authz.TemplateManage, nil); d.Effect != authz.EffectAllow {
		t.Fatalf("template admin template.manage: %+v", d)
	}
	if d := authz.Authorize(frank, authz.AuditRead, nil); d.Effect != authz.EffectDeny {
		t.Fatalf("template admin audit.read: %+v", d)
	}
}

func TestAuthorize_Visibility(t *testing.T) {
	pub := &authz.Resource{ID: "POL-FACILITIES-000001", Category: "Facilities"}
	if d := authz.Authorize(withRoles(authz.RoleReader), authz.PolicyRead, pub); d.Effect != authz.EffectAllow {
		t.Fatalf("reader read: %+v", d)
	}
	if d := authz.Authorize(authz.Subject{}, authz.PolicyRead, nil); d.Effect != authz.EffectAllow {
		t.Fatalf("a read with no resource is the capability check alone: %+v", d)
	}

	erin := withRoles(authz.RoleReader)
	erin.BreakGlass = map[string]bool{"POL-FACILITIES-000001": true}
	if d := authz.Authorize(erin, authz.PolicyRead, pub); d.Effect != authz.EffectAllow || d.Reason != authz.ReasonBreakGlass {
		t.Fatalf("break glass: %+v", d)
	}

	sens := &authz.Resource{ID: "POL-EXPENSES-000002", Category: "Expenses", Sensitive: true}
	if d := authz.Authorize(withRoles(authz.RoleReader), authz.PolicyRead, sens); d.Effect != authz.EffectDeny || d.Reason != authz.ReasonSensitive {
		t.Fatalf("sensitive without clearance: %+v", d)
	}
	if d := authz.Authorize(authz.Subject{Roles: []authz.Role{authz.RoleReader}, ReadSensitive: true}, authz.PolicyRead, sens); d.Effect != authz.EffectAllow {
		t.Fatalf("sensitive with the individual grant: %+v", d)
	}

	ov := authz.Subject{Roles: []authz.Role{authz.RoleReader}, Overrides: []authz.Override{{ResourceID: "POL-EXPENSES-000002", Grant: authz.GrantAllow}}}
	if d := authz.Authorize(ov, authz.PolicyRead, sens); d.Effect != authz.EffectAllow || d.Reason != authz.ReasonOverrideAllow {
		t.Fatalf("an override allow grants read whatever else would deny: %+v", d)
	}

	alice := authz.Subject{Roles: []authz.Role{authz.RoleSiteAdmin}, Overrides: []authz.Override{{ResourceID: "POL-FACILITIES-000001", Grant: authz.GrantDeny}}}
	if d := authz.Authorize(alice, authz.PolicyRead, pub); d.Effect != authz.EffectObfuscate {
		t.Fatalf("an override deny on a site admin obfuscates: %+v", d)
	}
	erinExcluded := authz.Subject{Overrides: []authz.Override{{ResourceID: "POL-FACILITIES-000001", Grant: authz.GrantDeny}}}
	if d := authz.Authorize(erinExcluded, authz.PolicyRead, pub); d.Effect != authz.EffectDeny || d.Reason != authz.ReasonExcluded {
		t.Fatalf("an override deny hides the resource from anyone else: %+v", d)
	}
}

func TestDecision_Err(t *testing.T) {
	if err := authz.Authorize(withRoles(authz.RoleReader), authz.PolicyRead, nil).Err(); err != nil {
		t.Fatalf("an allow has no error, got %v", err)
	}
	err := authz.Authorize(withRoles(authz.RoleReader), authz.AuditRead, nil).Err()
	if !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if code, ok := apperr.Code(err); !ok || code != rbac.CodeDenied {
		t.Fatalf("want code %d, got %d (%v)", rbac.CodeDenied, code, ok)
	}
	if md := apperr.Metadata(err); len(md) != 0 {
		t.Fatalf("a denial must not send its reason to the client, got %v", md)
	}
}

func TestAuthorize_SensitiveReadIsAssignmentOrExplicitGrantOnly(t *testing.T) {
	doc := &authz.Resource{
		ID: "POL-EXPENSES-000002", Category: "Expenses", CategoryLineage: []string{"Expenses", "Finance"},
		Sensitive: true, Authors: []string{"bob"}, Approvers: []string{"carol"},
	}
	scopedAuthor := func(id string) authz.Subject {
		return authz.Subject{UserID: id, Roles: []authz.Role{authz.RoleAuthor}, ScopedGrants: []authz.ScopedGrant{{Role: authz.RoleAuthor, Category: "Finance"}}}
	}
	scopedApprover := func(id string) authz.Subject {
		return authz.Subject{UserID: id, Roles: []authz.Role{authz.RoleApprover}, ScopedGrants: []authz.ScopedGrant{{Role: authz.RoleApprover, Category: "Finance"}}}
	}
	cases := []struct {
		name   string
		s      authz.Subject
		effect authz.Effect
		reason authz.Reason
	}{
		{"the assigned author", scopedAuthor("bob"), authz.EffectAllow, authz.ReasonAssigned},
		{"the assigned approver", scopedApprover("carol"), authz.EffectAllow, authz.ReasonAssigned},
		{"an assigned author with no role", authz.Subject{UserID: "bob"}, authz.EffectAllow, authz.ReasonAssigned},
		{"an unassigned author of the category", scopedAuthor("dave"), authz.EffectDeny, authz.ReasonSensitive},
		{"an unassigned approver of the category", scopedApprover("heidi"), authz.EffectDeny, authz.ReasonSensitive},
		{"the individual read_sensitive grant", authz.Subject{UserID: "frank", ReadSensitive: true}, authz.EffectAllow, authz.ReasonGranted},
		{"an override allow on this document", authz.Subject{UserID: "frank", Overrides: []authz.Override{{ResourceID: "POL-EXPENSES-000002", Grant: authz.GrantAllow}}}, authz.EffectAllow, authz.ReasonOverrideAllow},
		{"a break-glass grant on this document", authz.Subject{UserID: "frank", BreakGlass: map[string]bool{"POL-EXPENSES-000002": true}}, authz.EffectAllow, authz.ReasonBreakGlass},
		{"a compliance admin", authz.Subject{UserID: "grace", Roles: []authz.Role{authz.RoleComplianceAdmin}}, authz.EffectDeny, authz.ReasonSensitive},
		{"a site admin", authz.Subject{UserID: "alice", Roles: []authz.Role{authz.RoleSiteAdmin}}, authz.EffectDeny, authz.ReasonSensitive},
		{"a reader", authz.Subject{UserID: "erin"}, authz.EffectDeny, authz.ReasonSensitive},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := authz.Authorize(c.s, authz.PolicyRead, doc)
			if d.Effect != c.effect || d.Reason != c.reason {
				t.Fatalf("got %+v, want %s/%s", d, c.effect, c.reason)
			}
		})
	}
}
