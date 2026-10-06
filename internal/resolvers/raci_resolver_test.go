// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	log "github.com/Bugs5382/go-log"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

// raciIdentityClient stubs IdentityReadServiceClient for RACI smoke tests.
// GetUser and ListUserIdpGroups are the primary methods; ListAllUsers returns
// all values from the users map (in map-iteration order) when allUsers is
// nil, matching what the real service does for pool-enumeration tests.
type raciIdentityClient struct {
	identityv1.IdentityReadServiceClient
	users     map[string]*identityv1.User
	idpGroups map[string][]string // user id → IdP group names
	allUsers  []*identityv1.User  // explicit list for ListAllUsers; nil = derive from users map
}

func (f *raciIdentityClient) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	u, ok := f.users[in.GetUserId()]
	if !ok {
		return nil, errors.New("user not found")
	}
	return &identityv1.GetUserResponse{User: u}, nil
}

func (f *raciIdentityClient) ListUserIdpGroups(_ context.Context, in *identityv1.ListUserIdpGroupsRequest, _ ...grpc.CallOption) (*identityv1.ListUserIdpGroupsResponse, error) {
	return &identityv1.ListUserIdpGroupsResponse{IdpGroups: f.idpGroups[in.GetUserId()]}, nil
}

func (f *raciIdentityClient) GetGroup(context.Context, *identityv1.GetGroupRequest, ...grpc.CallOption) (*identityv1.GetGroupResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ResolveClaims(context.Context, *identityv1.ResolveClaimsRequest, ...grpc.CallOption) (*identityv1.ResolveClaimsResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ListUsersInGroup(context.Context, *identityv1.ListUsersInGroupRequest, ...grpc.CallOption) (*identityv1.ListUsersInGroupResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ListGroupDescendants(context.Context, *identityv1.ListGroupDescendantsRequest, ...grpc.CallOption) (*identityv1.ListGroupDescendantsResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ListGroupAncestors(context.Context, *identityv1.ListGroupAncestorsRequest, ...grpc.CallOption) (*identityv1.ListGroupAncestorsResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ResolveEmail(context.Context, *identityv1.ResolveEmailRequest, ...grpc.CallOption) (*identityv1.ResolveEmailResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ResolveFCMToken(context.Context, *identityv1.ResolveFCMTokenRequest, ...grpc.CallOption) (*identityv1.ResolveFCMTokenResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ListUserGroups(context.Context, *identityv1.ListUserGroupsRequest, ...grpc.CallOption) (*identityv1.ListUserGroupsResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ListUsersByEmail(context.Context, *identityv1.ListUsersByEmailRequest, ...grpc.CallOption) (*identityv1.ListUsersByEmailResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ListGroups(context.Context, *identityv1.ListGroupsRequest, ...grpc.CallOption) (*identityv1.ListGroupsResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ListUsersByIdpGroups(context.Context, *identityv1.ListUsersByIdpGroupsRequest, ...grpc.CallOption) (*identityv1.ListUsersByIdpGroupsResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ListAllUsers(_ context.Context, _ *identityv1.ListAllUsersRequest, _ ...grpc.CallOption) (*identityv1.ListAllUsersResponse, error) {
	if f.allUsers != nil {
		return &identityv1.ListAllUsersResponse{Users: f.allUsers}, nil
	}
	// Derive from users map when no explicit list is set.
	out := make([]*identityv1.User, 0, len(f.users))
	for _, u := range f.users {
		out = append(out, u)
	}
	return &identityv1.ListAllUsersResponse{Users: out}, nil
}
func (f *raciIdentityClient) CountAllUsers(context.Context, *identityv1.CountAllUsersRequest, ...grpc.CallOption) (*identityv1.CountAllUsersResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) CountUsersByIdpGroups(context.Context, *identityv1.CountUsersByIdpGroupsRequest, ...grpc.CallOption) (*identityv1.CountUsersByIdpGroupsResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) RevokeMySessions(context.Context, *identityv1.RevokeMySessionsRequest, ...grpc.CallOption) (*identityv1.RevokeMySessionsResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) GetSetupState(context.Context, *identityv1.GetSetupStateRequest, ...grpc.CallOption) (*identityv1.GetSetupStateResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) BootstrapRoot(context.Context, *identityv1.BootstrapRootRequest, ...grpc.CallOption) (*identityv1.BootstrapRootResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) GetAuthConfig(context.Context, *identityv1.GetAuthConfigRequest, ...grpc.CallOption) (*identityv1.GetAuthConfigResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) RequestPasswordReset(context.Context, *identityv1.RequestPasswordResetRequest, ...grpc.CallOption) (*identityv1.RequestPasswordResetResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) ResetPasswordWithCode(context.Context, *identityv1.ResetPasswordWithCodeRequest, ...grpc.CallOption) (*identityv1.ResetPasswordWithCodeResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) RequestLoginOtp(context.Context, *identityv1.RequestLoginOtpRequest, ...grpc.CallOption) (*identityv1.RequestLoginOtpResponse, error) {
	return nil, nil
}
func (f *raciIdentityClient) VerifyLoginOtp(context.Context, *identityv1.VerifyLoginOtpRequest, ...grpc.CallOption) (*identityv1.VerifyLoginOtpResponse, error) {
	return nil, nil
}

// TestSimulateCategorySmoke exercises the full path:
// chain build → draft override → Resolve → decision mapping.
//
// Scenario: category "health-id" has an Everyone read=ALLOW rule.
// A draft ruleset adds: Contractors read=DENY first, Everyone read=ALLOW second.
// Simulate a Contractor → read must be denied.
// Simulate a non-Contractor → read must be allowed.
func TestSimulateCategorySmoke(t *testing.T) {
	gc := &raciCategoryClient{
		groups: map[string]*corev1.Category{
			"health-id": {
				Id:   "health-id",
				Name: "Health",
			},
		},
		rulesets: map[string][]*corev1.CategoryRule{
			"health-id": {
				{
					SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE,
					Read:        corev1.GrantEffect_GRANT_EFFECT_ALLOW,
					Ack:         corev1.GrantEffect_GRANT_EFFECT_ALLOW,
				},
			},
		},
	}

	ic := &raciIdentityClient{
		users: map[string]*identityv1.User{
			"contractor-1":   {Id: "contractor-1"},
			"regular-user-1": {Id: "regular-user-1"},
		},
		idpGroups: map[string][]string{
			"contractor-1":   {"Contractors"},
			"regular-user-1": {"IT-Staff"},
		},
	}

	r := &resolvers.Resolver{
		CategoryClient: gc,
		IdentityClient: ic,
	}

	// Draft: Deny Contractors read first, then allow Everyone read.
	draft := []*resolvers.RaciRuleInput{
		{
			SubjectKind: resolvers.RaciSubjectKindGroup,
			SubjectRef:  "Contractors",
			Read:        resolvers.RaciGrantDeny,
			Ack:         resolvers.RaciGrantBlank,
			Approve:     resolvers.RaciGrantBlank,
			Author:      resolvers.RaciGrantBlank,
		},
		{
			SubjectKind: resolvers.RaciSubjectKindEveryone,
			SubjectRef:  "",
			Read:        resolvers.RaciGrantAllow,
			Ack:         resolvers.RaciGrantAllow,
			Approve:     resolvers.RaciGrantBlank,
			Author:      resolvers.RaciGrantBlank,
		},
	}

	ctx := ctxWithRoles(t, "admin", []string{"site-admin"})

	// Contractor must be denied read.
	d, err := resolvers.SimulateCategoryResolver(ctx, r, "health-id", "contractor-1", draft)
	if err != nil {
		t.Fatalf("SimulateCategoryResolver (contractor): %v", err)
	}
	if d.Read {
		t.Errorf("Contractor: expected read=false, got true (reason: %v)", d.ReadReason)
	}

	// Non-Contractor must be allowed read (and ack).
	d2, err := resolvers.SimulateCategoryResolver(ctx, r, "health-id", "regular-user-1", draft)
	if err != nil {
		t.Fatalf("SimulateCategoryResolver (regular-user): %v", err)
	}
	if !d2.Read {
		t.Errorf("Non-Contractor: expected read=true, got false (reason: %v)", d2.ReadReason)
	}
	if !d2.Ack {
		t.Errorf("Non-Contractor: expected ack=true, got false (reason: %v)", d2.AckReason)
	}
}

// TestSimulateCategory_LegacyExclusionIgnored verifies that the RETIRED
// excluded_group_ids mechanism no longer influences the simulator: a user whose
// GetUser response still carries a stale exclusion for the target category is
// evaluated purely against the chart (rules + ownership). Denial is expressed
// ONLY as RACI deny rules now.
func TestSimulateCategory_LegacyExclusionIgnored(t *testing.T) {
	const (
		catID  = "cat-excl"
		userID = "excl-user"
	)

	gc := &raciCategoryClient{
		groups: map[string]*corev1.Category{
			catID: {
				Id:   catID,
				Name: "StaleExclCat",
			},
		},
		rulesets: map[string][]*corev1.CategoryRule{
			catID: {
				// Everyone read+ack=ALLOW — the chart grants read+ack.
				{
					SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE,
					Read:        corev1.GrantEffect_GRANT_EFFECT_ALLOW,
					Ack:         corev1.GrantEffect_GRANT_EFFECT_ALLOW,
				},
			},
		},
	}

	ic := &raciIdentityClient{
		users: map[string]*identityv1.User{
			userID: {
				Id: userID,
				// ExcludedGroupIds was retired (field reserved in proto) — no longer settable
			},
		},
		idpGroups: map[string][]string{
			userID: {"IT-Staff"},
		},
	}

	r := &resolvers.Resolver{
		CategoryClient: gc,
		IdentityClient: ic,
	}

	ctx := ctxWithRoles(t, "admin", []string{"site-admin"})

	d, err := resolvers.SimulateCategoryResolver(ctx, r, catID, userID, nil)
	if err != nil {
		t.Fatalf("SimulateCategoryResolver (stale exclusion): %v", err)
	}

	if !d.Read {
		t.Errorf("stale exclusion must be ignored: expected read=true via everyone rule, got false (reason: %v)", d.ReadReason)
	}
	if !d.Ack {
		t.Errorf("stale exclusion must be ignored: expected ack=true via everyone rule, got false (reason: %v)", d.AckReason)
	}
}

// TestSimulateCategory_AdminStripped verifies that a site-admin user who is NOT
// excluded but has no rule grant and is not an owner is still denied read in the
// simulator — proving the admin read-everything bypass is stripped.
func TestSimulateCategory_AdminStripped(t *testing.T) {
	const (
		catID   = "cat-admin"
		userID  = "admin-user"
		ownerID = "real-owner"
	)

	gc := &raciCategoryClient{
		groups: map[string]*corev1.Category{
			catID: {
				Id:     catID,
				Name:   "AdminTestCat",
				Owners: []string{ownerID}, // admin-user is NOT an owner
			},
		},
		rulesets: map[string][]*corev1.CategoryRule{
			catID: {
				// No rule for admin-user or Everyone — no grant at all.
			},
		},
	}

	ic := &raciIdentityClient{
		users: map[string]*identityv1.User{
			userID: {
				Id:    userID,
				Roles: []string{"site-admin"}, // real site-admin
				// ExcludedGroupIds: nil — not excluded
			},
		},
		idpGroups: map[string][]string{
			userID: {},
		},
	}

	r := &resolvers.Resolver{
		CategoryClient: gc,
		IdentityClient: ic,
	}

	ctx := ctxWithRoles(t, "admin", []string{"site-admin"})

	d, err := resolvers.SimulateCategoryResolver(ctx, r, catID, userID, nil)
	if err != nil {
		t.Fatalf("SimulateCategoryResolver (admin stripped): %v", err)
	}

	// Admin bypass is stripped; no rule/ownership match → read must be false.
	if d.Read {
		t.Errorf("Admin stripped: expected read=false (admin bypass removed), got true (reason: %v)", d.ReadReason)
	}
}

// TestSimulateCategory_EveryoneBaseline verifies that passing userId="" produces
// a bare EvalSubject (no identity RPC calls) and that only Everyone-kind rules
// apply: read=true (via Everyone ALLOW), approve=false and author=false (owner
// and user-specific rules do not match the empty subject).
func TestSimulateCategory_EveryoneBaseline(t *testing.T) {
	const ownerID = "owner-user"
	const specificUserID = "specific-user"

	gc := &raciCategoryClient{
		groups: map[string]*corev1.Category{
			"cat-id": {
				Id:     "cat-id",
				Name:   "TestCat",
				Owners: []string{ownerID},
			},
		},
		rulesets: map[string][]*corev1.CategoryRule{
			"cat-id": {
				// Owner-specific approve grant.
				{
					SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
					SubjectRef:  ownerID,
					Approve:     corev1.GrantEffect_GRANT_EFFECT_ALLOW,
					Author:      corev1.GrantEffect_GRANT_EFFECT_ALLOW,
				},
				// User-specific author grant.
				{
					SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
					SubjectRef:  specificUserID,
					Author:      corev1.GrantEffect_GRANT_EFFECT_ALLOW,
				},
				// Everyone read grant.
				{
					SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE,
					Read:        corev1.GrantEffect_GRANT_EFFECT_ALLOW,
				},
			},
		},
	}

	// Identity client is provided but must NOT be called for the empty-userId path.
	// raciIdentityClient will return "user not found" for unknown IDs; if it were
	// called with "" it would also error — which confirms the bypass is exercised.
	ic := &raciIdentityClient{
		users:     map[string]*identityv1.User{},
		idpGroups: map[string][]string{},
	}

	r := &resolvers.Resolver{
		CategoryClient: gc,
		IdentityClient: ic,
	}

	ctx := ctxWithRoles(t, "admin", []string{"site-admin"})

	d, err := resolvers.SimulateCategoryResolver(ctx, r, "cat-id", "", nil)
	if err != nil {
		t.Fatalf("SimulateCategoryResolver (everyone baseline): %v", err)
	}

	// Everyone rule grants read.
	if !d.Read {
		t.Errorf("Everyone baseline: expected read=true, got false (reason: %v)", d.ReadReason)
	}
	// No owner match and no user-subject match → approve must be false.
	if d.Approve {
		t.Errorf("Everyone baseline: expected approve=false, got true (reason: %v)", d.ApproveReason)
	}
	// No user-subject match → author must be false.
	if d.Author {
		t.Errorf("Everyone baseline: expected author=false, got true (reason: %v)", d.AuthorReason)
	}
}

// TestCategoryApprovers verifies the approve-eligible user pool for a 2-level
// chain (IT → Cyber).
//
// Setup:
//   - IT category: owned by "it-owner"; has an approve-allow rule for user "ceo".
//   - Cyber category: child of IT; no rules; no owners of its own.
//   - "it-owner"  → IT owner → approve via owner-inheritance.
//   - "ceo"       → explicit approve-allow rule on IT (inherited by Cyber).
//   - "nobody"    → no rule, no ownership → not in result.
//   - "stale-excl" → carries a RETIRED legacy exclusion for cyber-id AND an
//     approve-allow rule → the exclusion is ignored, the rule wins → in result.
//
// Expected result: {"it-owner", "ceo", "stale-excl"} — order may vary.
func TestCategoryApprovers(t *testing.T) {
	const (
		itCatID    = "it-id"
		cyberCatID = "cyber-id"
	)

	gc := &raciCategoryClient{
		groups: map[string]*corev1.Category{
			cyberCatID: {
				Id:       cyberCatID,
				Name:     "Cyber",
				ParentId: itCatID,
				// No owners on Cyber itself.
			},
			itCatID: {
				Id:     itCatID,
				Name:   "IT",
				Owners: []string{"it-owner"},
			},
		},
		rulesets: map[string][]*corev1.CategoryRule{
			cyberCatID: {
				// No rules on Cyber.
			},
			itCatID: {
				// Explicit approve-allow for "ceo" on IT (inherited by Cyber via chain).
				{
					SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
					SubjectRef:  "ceo",
					Approve:     corev1.GrantEffect_GRANT_EFFECT_ALLOW,
				},
				// Approve-allow for "stale-excl" — proves the retired legacy
				// exclusion no longer trumps a chart grant.
				{
					SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
					SubjectRef:  "stale-excl",
					Approve:     corev1.GrantEffect_GRANT_EFFECT_ALLOW,
				},
			},
		},
	}

	ic := &raciIdentityClient{
		users: map[string]*identityv1.User{
			"it-owner":   {Id: "it-owner"},
			"ceo":        {Id: "ceo"},
			"nobody":     {Id: "nobody"},
			"stale-excl": {Id: "stale-excl"}, // ExcludedGroupIds was retired (field reserved in proto)
		},
		idpGroups: map[string][]string{
			"it-owner":   {},
			"ceo":        {},
			"nobody":     {},
			"stale-excl": {},
		},
	}

	r := &resolvers.Resolver{
		CategoryClient: gc,
		IdentityClient: ic,
	}

	ctx := ctxWithRoles(t, "admin", []string{"site-admin"})

	pool, err := resolvers.CategoryApproversResolver(ctx, r, cyberCatID)
	if err != nil {
		t.Fatalf("CategoryApproversResolver: %v", err)
	}

	// Collect result user IDs into a set for order-independent assertion.
	got := make(map[string]bool, len(pool))
	for _, u := range pool {
		got[u.UserID] = true
	}

	if !got["it-owner"] {
		t.Errorf("expected it-owner in approver pool (owner-inherited approve), got pool: %v", got)
	}
	if !got["ceo"] {
		t.Errorf("expected ceo in approver pool (explicit rule on IT, inherited by Cyber), got pool: %v", got)
	}
	if got["nobody"] {
		t.Errorf("expected nobody NOT in approver pool, but got pool: %v", got)
	}
	if !got["stale-excl"] {
		t.Errorf("expected stale-excl IN approver pool (legacy exclusion retired; rule grant wins), got pool: %v", got)
	}
	if len(pool) != 3 {
		t.Errorf("expected exactly 3 approvers, got %d: %v", len(pool), got)
	}
}

// viewerCategoryClient extends raciCategoryClient with a children map so the BFS
// inside ViewerIsApproverResolver can walk the full category tree.
// children maps parentId → slice of child groups ("" = root children).
type viewerCategoryClient struct {
	raciCategoryClient
	children map[string][]*corev1.Category
}

func (f *viewerCategoryClient) ListCategoryChildren(_ context.Context, in *corev1.ListCategoryChildrenRequest, _ ...grpc.CallOption) (*corev1.ListCategoryChildrenResponse, error) {
	kids := f.children[in.GetParentId()]
	return &corev1.ListCategoryChildrenResponse{Categories: kids}, nil
}

// ctxWithStubClaimsForRaci builds an HTTP-middleware context carrying the given
// StubClaims, matching the pattern in policy_resolver_test.go. It is kept here
// so raci_resolver_test.go can be compiled independently without import-cycle
// concerns (ctxWithStubClaims is already defined in policy_resolver_test.go which
// is in the same package, so we reuse it directly below).

// TestViewerIsApprover covers the five cases required by the task brief.
func TestViewerIsApprover(t *testing.T) {
	const (
		catID    = "cat-1"
		userID   = "viewer"
		ownerID  = "owner-u"
		adminID  = "admin-u"
		groupUID = "group-u"
	)

	// Helpers to build a viewerCategoryClient with one root category.
	makeGC := func(rules []*corev1.CategoryRule, owners []string) *viewerCategoryClient {
		g := &corev1.Category{Id: catID, Name: "Root", ParentId: "", Owners: owners}
		return &viewerCategoryClient{
			raciCategoryClient: raciCategoryClient{
				groups:   map[string]*corev1.Category{catID: g},
				rulesets: map[string][]*corev1.CategoryRule{catID: rules},
			},
			children: map[string][]*corev1.Category{
				"": {g}, // root children
			},
		}
	}

	// (a) user-rule approve=ALLOW for the viewer → true.
	t.Run("user_rule_approve_allow", func(t *testing.T) {
		gc := makeGC([]*corev1.CategoryRule{
			{
				SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
				SubjectRef:  userID,
				Approve:     corev1.GrantEffect_GRANT_EFFECT_ALLOW,
			},
		}, nil)
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: userID})
		got, err := resolvers.ViewerIsApproverResolver(ctx, log.Nop(), gc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got {
			t.Error("expected true (user rule approve=allow), got false")
		}
	})

	// (b) viewer is category owner → approve via owner-inheritance → true.
	t.Run("owner_approve", func(t *testing.T) {
		gc := makeGC(nil, []string{userID})
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: userID})
		got, err := resolvers.ViewerIsApproverResolver(ctx, log.Nop(), gc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got {
			t.Error("expected true (owner inherits approve), got false")
		}
	})

	// (c) plain user, no rules, no ownership → false.
	t.Run("plain_user_no_grant", func(t *testing.T) {
		gc := makeGC([]*corev1.CategoryRule{
			{
				SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
				SubjectRef:  ownerID, // different user
				Approve:     corev1.GrantEffect_GRANT_EFFECT_ALLOW,
			},
		}, []string{ownerID})
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: userID})
		got, err := resolvers.ViewerIsApproverResolver(ctx, log.Nop(), gc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got {
			t.Error("expected false (no grant for viewer), got true")
		}
	})

	// (d) site-admin with NO chart approve rule → false (merit; IsSiteAdmin stripped).
	t.Run("site_admin_no_chart_approve", func(t *testing.T) {
		gc := makeGC([]*corev1.CategoryRule{
			{
				SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
				SubjectRef:  ownerID,
				Approve:     corev1.GrantEffect_GRANT_EFFECT_ALLOW,
			},
		}, nil)
		ctx := ctxWithStubClaims(t, principal.Static{
			UserIDValue: adminID,
			RolesValue:  []string{"site-admin"},
		})
		got, err := resolvers.ViewerIsApproverResolver(ctx, log.Nop(), gc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got {
			t.Error("expected false (site-admin alone must not grant approve), got true")
		}
	})

	// (e) group-rule approve matched via IdP groups → true.
	t.Run("group_rule_via_ad_groups", func(t *testing.T) {
		gc := makeGC([]*corev1.CategoryRule{
			{
				SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP,
				SubjectRef:  "ApproverTeam",
				Approve:     corev1.GrantEffect_GRANT_EFFECT_ALLOW,
			},
		}, nil)
		ctx := ctxWithStubClaims(t, principal.Static{
			UserIDValue:    groupUID,
			IdpGroupsValue: []string{"ApproverTeam"},
		})
		got, err := resolvers.ViewerIsApproverResolver(ctx, log.Nop(), gc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got {
			t.Error("expected true (group rule via IdP groups), got false")
		}
	})
}
