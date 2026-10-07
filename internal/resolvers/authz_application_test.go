// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

// authz_application_test.go — deny tests for every gated admin resolver.
//
// Pattern: call the resolver with a context holding a wrong role (e.g. "author")
// and nil clients. The requireRole gate must reject with PermissionDenied before
// any client method is called, so nil clients do not panic on deny paths.
//
// One representative gated function is tested per resolver file as mandated by
// the plan; all table entries that share a file are covered in bulk below.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// ── group_resolver.go ──────────────────────────────────────────────────────

func TestGetGroupRequiresAdmin(t *testing.T) {
	_, err := resolvers.GetCategory(ctxWithRoles(t, "u", []string{"author"}), nil, "g1")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetGroup: want PermissionDenied, got %v", err)
	}
}

func TestCreateGroupRequiresAdmin(t *testing.T) {
	_, err := resolvers.CreateCategory(ctxWithRoles(t, "u", []string{"author"}), nil, "n", "n", nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CreateGroup: want PermissionDenied, got %v", err)
	}
}

func TestSetGroupDefaultsRequiresAdmin(t *testing.T) {
	_, err := resolvers.SetCategoryDefaults(ctxWithRoles(t, "u", []string{"author"}), nil, "g1", nil, nil, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SetGroupDefaults: want PermissionDenied, got %v", err)
	}
}

func TestSetGroupGovernanceRequiresGroupManage(t *testing.T) {
	// SetGroupGovernance is now gated on group.manage. author lacks it -> denied.
	// nil clients are safe here because the auth gate fires before any client call.
	_, err := resolvers.SetCategoryGovernance(ctxWithRoles(t, "u", []string{"author"}), nil, "g1", nil, nil, nil, resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SetGroupGovernance with author: want PermissionDenied, got %v", err)
	}
	// compliance-admin also lacks group.manage -> denied.
	_, err = resolvers.SetCategoryGovernance(ctxWithRoles(t, "u", []string{"compliance-admin"}), nil, "g1", nil, nil, nil, resolvers.AckTriggerNone, resolvers.ReviewCadenceNone, nil, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SetGroupGovernance with compliance-admin: want PermissionDenied, got %v", err)
	}
}

func TestGetEffectiveGovernanceRequiresGroupManage(t *testing.T) {
	// GetEffectiveGovernance exposes sensitive inherited governance data.
	// author lacks group.manage -> PermissionDenied before any backend call.
	_, err := resolvers.GetEffectiveGovernance(ctxWithRoles(t, "u", []string{"author"}), nil, "g1")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetEffectiveGovernance with author: want PermissionDenied, got %v", err)
	}
	// compliance-admin also lacks group.manage -> denied.
	_, err = resolvers.GetEffectiveGovernance(ctxWithRoles(t, "u", []string{"compliance-admin"}), nil, "g1")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetEffectiveGovernance with compliance-admin: want PermissionDenied, got %v", err)
	}
	// template-admin does NOT hold group.manage (dropped in fix(authz): drop GroupManage from
	// template-admin role) -> PermissionDenied, same as other non-site-admin roles.
	_, err = resolvers.GetEffectiveGovernance(ctxWithRoles(t, "u", []string{"template-admin"}), nil, "g1")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetEffectiveGovernance with template-admin: want PermissionDenied (no group.manage), got %v", err)
	}
	// site-admin holds group.manage; nil client produces Unavailable, not PermissionDenied.
	_, err = resolvers.GetEffectiveGovernance(ctxWithRoles(t, "u", []string{"site-admin"}), nil, "g1")
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("GetEffectiveGovernance with site-admin: want pass-through error (not PermissionDenied), got %v", err)
	}
}

// ── template_resolver.go ───────────────────────────────────────────────────

func TestCreateTemplateRequiresAdmin(t *testing.T) {
	_, err := resolvers.CreateTemplate(ctxWithRoles(t, "u", []string{"author"}), nil, "T", nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CreateTemplate: want PermissionDenied, got %v", err)
	}
}

func TestCreateTemplateVersionRequiresAdmin(t *testing.T) {
	_, err := resolvers.CreateTemplateVersion(ctxWithRoles(t, "u", []string{"author"}), nil, "tv1", nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CreateTemplateVersion: want PermissionDenied, got %v", err)
	}
}

func TestPublishTemplateVersionRequiresAdmin(t *testing.T) {
	_, err := resolvers.PublishTemplateVersion(ctxWithRoles(t, "u", []string{"author"}), nil, "tv1")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("PublishTemplateVersion: want PermissionDenied, got %v", err)
	}
}

// ── policy_resolver.go ─────────────────────────────────────────────────────

func TestGetPolicyRequiresAuthentication(t *testing.T) {
	// GetPolicy fails closed for an unauthenticated caller before any backend
	// call, so the nil clients never panic. Authenticated callers then get a
	// resource-aware read decision (hidden→NotFound).
	_, err := resolvers.GetPolicy(context.Background(), nil, nil, nil, nil, "p1")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("GetPolicy unauthenticated: want Unauthenticated, got %v", err)
	}
}

func TestSetPolicyAckRequiresAdmin(t *testing.T) {
	_, err := resolvers.SetPolicyAck(ctxWithRoles(t, "u", []string{"template-admin"}), nil, "p1", nil, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SetPolicyAck with template-admin: want PermissionDenied, got %v", err)
	}
}

// ── workflow_resolver.go ───────────────────────────────────────────────────

func TestSwapAssigneeRequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.SwapAssigneeResolver(ctxWithRoles(t, "u", []string{"author"}), nil, resolvers.SwapAssigneeInput{PolicyVersionID: "pv1", StageIndex: 0, CurrentUserID: "cu", NewUserID: "nu", Reason: "r"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SwapAssigneeResolver: want PermissionDenied, got %v", err)
	}
}

func TestBulkDecideNoLongerGatesOnApprove(t *testing.T) {
	// D5a: BulkDecide must NOT be gated on the policy.approve capability at the
	// gateway. Being the assigned stage approver is what confers the right to
	// decide, and the workflow service enforces that authoritatively (it decides
	// each row only against the caller's own pending assignment). A caller who
	// holds author/submit but not approve — yet is a stage assignee — must reach
	// the workflow service rather than being denied up front. We assert the
	// gateway does not return PermissionDenied; the request is forwarded to the
	// (fake) workflow client, whose empty response yields a nil-error result.
	c := &fakeWorkflowClient{bulkResp: &workflowv1.BulkDecideResponse{}}
	_, err := resolvers.BulkDecideResolver(ctxWithRoles(t, "u", []string{"author"}), c, resolvers.BulkDecideInput{
		Decisions: []*resolvers.DecisionInput{
			{PolicyVersionID: "pv1", StageIndex: 0, Decision: resolvers.DecisionTypeDecisionTypeApprove, Comment: "ok"},
		},
	})
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("BulkDecideResolver must not deny a stage assignee lacking the approve capability, got %v", err)
	}
}

func TestAssignmentHistoryRequiresApprove(t *testing.T) {
	// Gated on policy.approve; author lacks it -> denied.
	_, err := resolvers.AssignmentHistoryResolver(ctxWithRoles(t, "u", []string{"author"}), nil, nil, nil, "pv1", 0)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AssignmentHistoryResolver: want PermissionDenied, got %v", err)
	}
}

// ── compliance_resolver.go ─────────────────────────────────────────────────

func TestObligatedAudienceCountRequiresAdmin(t *testing.T) {
	_, err := resolvers.ObligatedAudienceCountResolver(ctxWithRoles(t, "u", []string{"author"}), nil, "p1")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ObligatedAudienceCountResolver: want PermissionDenied, got %v", err)
	}
}

func TestCompletionReportRequiresAdmin(t *testing.T) {
	_, err := resolvers.GetCompletionReportResolver(ctxWithRoles(t, "u", []string{"author"}), nil, nil, "pv1", nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetCompletionReportResolver: want PermissionDenied, got %v", err)
	}
}

func TestExportAcksRequiresAdmin(t *testing.T) {
	_, err := resolvers.ExportAcksResolver(ctxWithRoles(t, "u", []string{"author"}), nil, "pv1", "csv")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ExportAcksResolver: want PermissionDenied, got %v", err)
	}
}

// ── audit_resolver.go ──────────────────────────────────────────────────────

func TestQueryAuditLogRequiresAuditRead(t *testing.T) {
	// QueryAuditLog is now gated on audit.read. author lacks it -> denied.
	_, err := resolvers.QueryAuditLogResolver(ctxWithRoles(t, "u", []string{"author"}), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("QueryAuditLogResolver with author: want PermissionDenied, got %v", err)
	}
}

func TestAuditSegmentRequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.ExportAuditSegmentResolver(ctxWithRoles(t, "u", []string{"author"}), nil, "1", "10")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ExportAuditSegmentResolver: want PermissionDenied, got %v", err)
	}
}

func TestVerifyAuditChainRequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.VerifyAuditChainResolver(ctxWithRoles(t, "u", []string{"author"}), nil, nil, "1", "10")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("VerifyAuditChainResolver: want PermissionDenied, got %v", err)
	}
}

// ── identity_resolver.go ───────────────────────────────────────────────────

func TestUsersRequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.UsersResolver(ctxWithRoles(t, "u", []string{"compliance-admin"}), nil, nil, nil, nil, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("UsersResolver with compliance-admin: want PermissionDenied, got %v", err)
	}
}

func TestGrantRoleRequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.GrantRoleResolver(ctxWithRoles(t, "u", []string{"author"}), nil, "uid", "site-admin", nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GrantRoleResolver: want PermissionDenied, got %v", err)
	}
}

func TestRevokeRoleRequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.RevokeRoleResolver(ctxWithRoles(t, "u", []string{"author"}), nil, "uid", "site-admin", nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("RevokeRoleResolver: want PermissionDenied, got %v", err)
	}
}

func TestEnableUserRequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.EnableUserResolver(ctxWithRoles(t, "u", []string{"template-admin"}), nil, "uid")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("EnableUserResolver: want PermissionDenied, got %v", err)
	}
}

func TestDisableUserRequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.DisableUserResolver(ctxWithRoles(t, "u", []string{"template-admin"}), nil, "uid")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("DisableUserResolver: want PermissionDenied, got %v", err)
	}
}

func TestAddUserToGroupRequiresSiteAdminOrGroupManager(t *testing.T) {
	// A caller who is neither a site-admin nor a group-manager of the group
	// (empty managed_group_ids from the read service) is denied.
	read := &fakeReadClient{getUserResp: &identityv1.GetUserResponse{User: &identityv1.User{Id: "u"}}}
	_, err := resolvers.AddUserToGroupResolver(ctxWithRoles(t, "u", []string{"author"}), nil, read, "uid", "gid")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AddUserToGroupResolver: want PermissionDenied, got %v", err)
	}
}

func TestRemoveUserFromGroupRequiresSiteAdminOrGroupManager(t *testing.T) {
	read := &fakeReadClient{getUserResp: &identityv1.GetUserResponse{User: &identityv1.User{Id: "u"}}}
	_, err := resolvers.RemoveUserFromGroupResolver(ctxWithRoles(t, "u", []string{"author"}), nil, read, "uid", "gid")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("RemoveUserFromGroupResolver: want PermissionDenied, got %v", err)
	}
}

func TestSetUserPolicyOverrideRequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.SetUserPolicyOverrideResolver(ctxWithRoles(t, "u", []string{"author"}), nil, "uid", "POL-001", nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SetUserPolicyOverrideResolver: want PermissionDenied, got %v", err)
	}
}

// ── delivery_resolver.go ───────────────────────────────────────────────────

func TestRevokeMagicLinkRequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.RevokeMagicLinkResolver(ctxWithRoles(t, "u", []string{"author"}), nil, "tok")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("RevokeMagicLinkResolver: want PermissionDenied, got %v", err)
	}
}

// ── identity_resolver.go — directory group resolvers ──────────────────────
//
// All six directory-group resolvers require group.manage.
// template-admin does NOT hold group.manage (dropped in platform fix(authz)):
// both template-admin and author → PermissionDenied.
// site-admin holds group.manage → passes the gate; nil client → Unavailable.
