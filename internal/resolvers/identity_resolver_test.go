// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"slices"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeReadClient struct {
	identityv1.IdentityReadServiceClient
	getUserResp    *identityv1.GetUserResponse
	getUserErr     error
	lastGetUserReq *identityv1.GetUserRequest

	listResp    *identityv1.ListUsersByEmailResponse
	listErr     error
	lastListReq *identityv1.ListUsersByEmailRequest

	usersInGroupResp    *identityv1.ListUsersInGroupResponse
	usersInGroupErr     error
	lastUsersInGroupReq *identityv1.ListUsersInGroupRequest
}

func (f *fakeReadClient) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	f.lastGetUserReq = in
	if f.getUserErr != nil {
		return nil, f.getUserErr
	}
	return f.getUserResp, nil
}
func (f *fakeReadClient) ListUsersInGroup(_ context.Context, in *identityv1.ListUsersInGroupRequest, _ ...grpc.CallOption) (*identityv1.ListUsersInGroupResponse, error) {
	f.lastUsersInGroupReq = in
	if f.usersInGroupErr != nil {
		return nil, f.usersInGroupErr
	}
	if f.usersInGroupResp != nil {
		return f.usersInGroupResp, nil
	}
	return &identityv1.ListUsersInGroupResponse{}, nil
}
func (f *fakeReadClient) ListUsersByEmail(_ context.Context, in *identityv1.ListUsersByEmailRequest, _ ...grpc.CallOption) (*identityv1.ListUsersByEmailResponse, error) {
	f.lastListReq = in
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResp, nil
}

type fakeAdminClient struct {
	identityv1.IdentityAdminServiceClient
	grantResp    *identityv1.GrantRoleResponse
	grantErr     error
	lastGrantReq *identityv1.GrantRoleRequest

	revokeResp    *identityv1.RevokeRoleResponse
	revokeErr     error
	lastRevokeReq *identityv1.RevokeRoleRequest

	enableResp *identityv1.EnableUserResponse
	enableErr  error

	disableResp *identityv1.DisableUserResponse
	disableErr  error

	deleteUserResp *identityv1.DeleteUserResponse
	deleteUserErr  error
	lastDeleteUser *identityv1.DeleteUserRequest

	previewMergeResp *identityv1.PreviewAccountMergeResponse
	previewMergeErr  error
	lastPreviewMerge *identityv1.PreviewAccountMergeRequest

	mergeAccountsResp *identityv1.MergeAccountsResponse
	mergeAccountsErr  error
	lastMerge         *identityv1.MergeAccountsRequest
	lastMergeActor    string

	addGroupResp    *identityv1.AddUserToGroupResponse
	addGroupErr     error
	lastAddGroupReq *identityv1.AddUserToGroupRequest

	removeGroupResp *identityv1.RemoveUserFromGroupResponse
	removeGroupErr  error

	grantMgrResp    *identityv1.GrantGroupManagerResponse
	grantMgrErr     error
	lastGrantMgrReq *identityv1.GrantGroupManagerRequest

	revokeMgrResp    *identityv1.RevokeGroupManagerResponse
	revokeMgrErr     error
	lastRevokeMgrReq *identityv1.RevokeGroupManagerRequest

	setPolicyResp    *identityv1.SetUserPolicyOverrideResponse
	setPolicyErr     error
	lastSetPolicyReq *identityv1.SetUserPolicyOverrideRequest

	transferResp    *identityv1.TransferRootResponse
	transferErr     error
	lastTransferReq *identityv1.TransferRootRequest

	completeOnboardingResp *identityv1.CompleteOnboardingResponse
	completeOnboardingErr  error
	lastCompleteOnboarding *identityv1.CompleteOnboardingRequest

	updateMyProfileResp *identityv1.UpdateMyProfileResponse
	updateMyProfileErr  error
	lastUpdateMyProfile *identityv1.UpdateMyProfileRequest

	stepUpResp    *identityv1.RequestStepUpOtpResponse
	stepUpErr     error
	lastStepUpReq *identityv1.RequestStepUpOtpRequest
	stepUpCalls   int

	createLocalUserResp  *identityv1.CreateLocalUserResponse
	createLocalUserErr   error
	lastCreateLocalReq   *identityv1.CreateLocalUserRequest
	resetPasswordErr     error
	lastResetPasswordReq *identityv1.ResetUserPasswordRequest
	updateProfileResp    *identityv1.UpdateUserProfileResponse
	updateProfileErr     error
	lastUpdateProfileReq *identityv1.UpdateUserProfileRequest
}

func (f *fakeAdminClient) TransferRoot(_ context.Context, in *identityv1.TransferRootRequest, _ ...grpc.CallOption) (*identityv1.TransferRootResponse, error) {
	f.lastTransferReq = in
	if f.transferErr != nil {
		return nil, f.transferErr
	}
	return f.transferResp, nil
}

func (f *fakeAdminClient) RequestStepUpOtp(_ context.Context, in *identityv1.RequestStepUpOtpRequest, _ ...grpc.CallOption) (*identityv1.RequestStepUpOtpResponse, error) {
	f.lastStepUpReq = in
	f.stepUpCalls++
	if f.stepUpErr != nil {
		return nil, f.stepUpErr
	}
	if f.stepUpResp != nil {
		return f.stepUpResp, nil
	}
	return &identityv1.RequestStepUpOtpResponse{}, nil
}

func (f *fakeAdminClient) EnableUser(_ context.Context, _ *identityv1.EnableUserRequest, _ ...grpc.CallOption) (*identityv1.EnableUserResponse, error) {
	if f.enableErr != nil {
		return nil, f.enableErr
	}
	return f.enableResp, nil
}
func (f *fakeAdminClient) DisableUser(_ context.Context, _ *identityv1.DisableUserRequest, _ ...grpc.CallOption) (*identityv1.DisableUserResponse, error) {
	if f.disableErr != nil {
		return nil, f.disableErr
	}
	return f.disableResp, nil
}
func (f *fakeAdminClient) DeleteUser(_ context.Context, in *identityv1.DeleteUserRequest, _ ...grpc.CallOption) (*identityv1.DeleteUserResponse, error) {
	f.lastDeleteUser = in
	if f.deleteUserErr != nil {
		return nil, f.deleteUserErr
	}
	return f.deleteUserResp, nil
}
func (f *fakeAdminClient) GrantRole(_ context.Context, in *identityv1.GrantRoleRequest, _ ...grpc.CallOption) (*identityv1.GrantRoleResponse, error) {
	f.lastGrantReq = in
	if f.grantErr != nil {
		return nil, f.grantErr
	}
	return f.grantResp, nil
}
func (f *fakeAdminClient) RevokeRole(_ context.Context, in *identityv1.RevokeRoleRequest, _ ...grpc.CallOption) (*identityv1.RevokeRoleResponse, error) {
	f.lastRevokeReq = in
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	return f.revokeResp, nil
}
func (f *fakeAdminClient) AddUserToGroup(_ context.Context, in *identityv1.AddUserToGroupRequest, _ ...grpc.CallOption) (*identityv1.AddUserToGroupResponse, error) {
	f.lastAddGroupReq = in
	if f.addGroupErr != nil {
		return nil, f.addGroupErr
	}
	return f.addGroupResp, nil
}
func (f *fakeAdminClient) RemoveUserFromGroup(_ context.Context, _ *identityv1.RemoveUserFromGroupRequest, _ ...grpc.CallOption) (*identityv1.RemoveUserFromGroupResponse, error) {
	if f.removeGroupErr != nil {
		return nil, f.removeGroupErr
	}
	return f.removeGroupResp, nil
}
func (f *fakeAdminClient) GrantGroupManager(_ context.Context, in *identityv1.GrantGroupManagerRequest, _ ...grpc.CallOption) (*identityv1.GrantGroupManagerResponse, error) {
	f.lastGrantMgrReq = in
	if f.grantMgrErr != nil {
		return nil, f.grantMgrErr
	}
	return f.grantMgrResp, nil
}
func (f *fakeAdminClient) RevokeGroupManager(_ context.Context, in *identityv1.RevokeGroupManagerRequest, _ ...grpc.CallOption) (*identityv1.RevokeGroupManagerResponse, error) {
	f.lastRevokeMgrReq = in
	if f.revokeMgrErr != nil {
		return nil, f.revokeMgrErr
	}
	return f.revokeMgrResp, nil
}
func (f *fakeAdminClient) SetUserPolicyOverride(_ context.Context, in *identityv1.SetUserPolicyOverrideRequest, _ ...grpc.CallOption) (*identityv1.SetUserPolicyOverrideResponse, error) {
	f.lastSetPolicyReq = in
	if f.setPolicyErr != nil {
		return nil, f.setPolicyErr
	}
	return f.setPolicyResp, nil
}

func (f *fakeAdminClient) CreateLocalUser(_ context.Context, in *identityv1.CreateLocalUserRequest, _ ...grpc.CallOption) (*identityv1.CreateLocalUserResponse, error) {
	f.lastCreateLocalReq = in
	if f.createLocalUserErr != nil {
		return nil, f.createLocalUserErr
	}
	if f.createLocalUserResp != nil {
		return f.createLocalUserResp, nil
	}
	return &identityv1.CreateLocalUserResponse{}, nil
}
func (f *fakeAdminClient) ResetUserPassword(_ context.Context, in *identityv1.ResetUserPasswordRequest, _ ...grpc.CallOption) (*identityv1.ResetUserPasswordResponse, error) {
	f.lastResetPasswordReq = in
	if f.resetPasswordErr != nil {
		return nil, f.resetPasswordErr
	}
	return &identityv1.ResetUserPasswordResponse{}, nil
}
func (f *fakeAdminClient) UpdateUserProfile(_ context.Context, in *identityv1.UpdateUserProfileRequest, _ ...grpc.CallOption) (*identityv1.UpdateUserProfileResponse, error) {
	f.lastUpdateProfileReq = in
	if f.updateProfileErr != nil {
		return nil, f.updateProfileErr
	}
	if f.updateProfileResp != nil {
		return f.updateProfileResp, nil
	}
	return &identityv1.UpdateUserProfileResponse{}, nil
}
func (f *fakeAdminClient) CompleteOnboarding(_ context.Context, in *identityv1.CompleteOnboardingRequest, _ ...grpc.CallOption) (*identityv1.CompleteOnboardingResponse, error) {
	f.lastCompleteOnboarding = in
	if f.completeOnboardingErr != nil {
		return nil, f.completeOnboardingErr
	}
	if f.completeOnboardingResp != nil {
		return f.completeOnboardingResp, nil
	}
	return &identityv1.CompleteOnboardingResponse{}, nil
}
func (f *fakeAdminClient) UpdateMyProfile(_ context.Context, in *identityv1.UpdateMyProfileRequest, _ ...grpc.CallOption) (*identityv1.UpdateMyProfileResponse, error) {
	f.lastUpdateMyProfile = in
	if f.updateMyProfileErr != nil {
		return nil, f.updateMyProfileErr
	}
	if f.updateMyProfileResp != nil {
		return f.updateMyProfileResp, nil
	}
	return &identityv1.UpdateMyProfileResponse{}, nil
}
func (f *fakeAdminClient) PreviewAccountMerge(_ context.Context, in *identityv1.PreviewAccountMergeRequest, _ ...grpc.CallOption) (*identityv1.PreviewAccountMergeResponse, error) {
	f.lastPreviewMerge = in
	if f.previewMergeErr != nil {
		return nil, f.previewMergeErr
	}
	return f.previewMergeResp, nil
}
func (f *fakeAdminClient) MergeAccounts(ctx context.Context, in *identityv1.MergeAccountsRequest, _ ...grpc.CallOption) (*identityv1.MergeAccountsResponse, error) {
	f.lastMerge = in
	if a, ok := grpcactor.FromContext(ctx); ok {
		f.lastMergeActor = a.Subject
	}
	if f.mergeAccountsErr != nil {
		return nil, f.mergeAccountsErr
	}
	return f.mergeAccountsResp, nil
}

func TestMeResolverHappyPath(t *testing.T) {
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{
				Id:    "u-42",
				Email: "test@example.com",
				Name:  "Test User",
				ScopedRoles: []*identityv1.ScopedRole{
					{Role: "author", Category: "cat-a"},
					{Role: "approver", Category: "cat-b"},
				},
				IdpGroups: []string{"ad-group-1"},
			},
		},
	}

	out, err := resolvers.MeResolver(ctxWithUser(t, "u-42"), read, nil)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if out.UserID != "u-42" {
		t.Errorf("UserID: got %q want %q", out.UserID, "u-42")
	}
	if read.lastGetUserReq == nil || read.lastGetUserReq.UserId != "u-42" {
		t.Errorf("GetUser not called with correct user id: %+v", read.lastGetUserReq)
	}
	if len(out.Scopes.Author) != 1 || out.Scopes.Author[0] != "cat-a" {
		t.Errorf("Author scopes: got %v", out.Scopes.Author)
	}
	if len(out.Scopes.Approver) != 1 || out.Scopes.Approver[0] != "cat-b" {
		t.Errorf("Approver scopes: got %v", out.Scopes.Approver)
	}
	if len(out.IdpGroups) != 1 || out.IdpGroups[0] != "ad-group-1" {
		t.Errorf("IdpGroups: got %v", out.IdpGroups)
	}
}

// TestMeResolverReturnsStoredLocale pins the read half of: me().locale
// relays the account-level BCP-47 preference from the identity record so the UI
// can seed <I18nProvider> from the user's account rather than the browser.
//
// NOTE the deploy order this field implies: selecting a field the DEPLOYED
// gateway does not know fails the WHOLE me query (and with it the Policy UI,
// closed to NO_ACCESS), so this gateway must ship BEFORE any UI that selects
// locale. The estate's standing "UI wave deploys last" rule covers it.
func TestMeResolverReturnsStoredLocale(t *testing.T) {
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{Id: "u-42", Locale: "es-419"},
		},
	}
	out, err := resolvers.MeResolver(ctxWithUser(t, "u-42"), read, nil)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if out.Locale != "es-419" {
		t.Errorf("Locale: got %q want %q", out.Locale, "es-419")
	}
}

// TestMeResolverUnsetLocaleIsEmptyString pins the unset sentinel: a user who
// never chose a language yields "" (not a fabricated default), which is the
// signal for the client to fall back to its own detection.
func TestMeResolverUnsetLocaleIsEmptyString(t *testing.T) {
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{Id: "u-42"},
		},
	}
	out, err := resolvers.MeResolver(ctxWithUser(t, "u-42"), read, nil)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if out.Locale != "" {
		t.Errorf("unset Locale: got %q want %q", out.Locale, "")
	}
}

// TestMeResolverEmailIsCanonicalIdentityRecordNotTokenClaim pins:
// me.email (and me.name) must always come from the identity-service GetUser
// row, never from the caller's session claims, even when they diverge (a
// stale email from the identity provider). The
// claims context below deliberately carries a DIFFERENT email than the fake
// identity response so a future regression that reads claims.Email() instead
// of the identity row fails this test.
func TestMeResolverEmailIsCanonicalIdentityRecordNotTokenClaim(t *testing.T) {
	const (
		tokenClaimEmail   = "alice.old@example.org" // divergent session claim
		identityCanonical = "alice@example.org"     // system-of-record row
	)
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{
				Id:    "u-42",
				Email: identityCanonical,
				Name:  "Alice Example",
			},
		},
	}

	out, err := resolvers.MeResolver(ctxWithUserEmail(t, "u-42", tokenClaimEmail), read, nil)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if out.Email != identityCanonical {
		t.Errorf("Email: got %q, want the identity-service canonical %q (never the token claim %q)",
			out.Email, identityCanonical, tokenClaimEmail)
	}
}

func TestMeResolverEnrichesOwnerInheritedApprover(t *testing.T) {
	// u-owner owns the "Medical" group but has NO explicit approver/author grant.
	// me.scopes must still include "Medical" for BOTH approver (D5b — gates the
	// Approvals nav) AND author (D9 — gates the create/author affordance), since
	// the RACI model grants owners auto read+approve+author.
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{
				Id: "u-owner",
				ScopedRoles: []*identityv1.ScopedRole{
					{Role: "approver", Category: "IT"}, // explicit grant, must be preserved
				},
			},
		},
	}
	grp := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"g-med": {Id: "g-med", Name: "Medical", Owners: []string{"u-owner"}},
		"g-it":  {Id: "g-it", Name: "IT", Owners: []string{"u-someone-else"}},
		// A child of Medical, owned by someone else — the walk must still reach it,
		// but it does not confer ownership on u-owner.
		"g-med-sub": {Id: "g-med-sub", Name: "Medical/Sub", ParentId: "g-med", Owners: []string{"u-other"}},
	}}

	out, err := resolvers.MeResolver(ctxWithUser(t, "u-owner"), read, grp)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if !containsStr(out.Scopes.Approver, "Medical") {
		t.Errorf("expected owner-inherited 'Medical' in approver scopes; got %v", out.Scopes.Approver)
	}
	if !containsStr(out.Scopes.Approver, "IT") {
		t.Errorf("expected explicit 'IT' approver grant preserved; got %v", out.Scopes.Approver)
	}
	// Owner-inherited AUTHOR (D9): owning Medical must also confer author scope so
	// the owner can create/author policies in it — regression for the create-policy
	// block hit by group owners (lradziul/kyoung couldn't author their own group).
	if !containsStr(out.Scopes.Author, "Medical") {
		t.Errorf("expected owner-inherited 'Medical' in author scopes; got %v", out.Scopes.Author)
	}
}

func TestMeResolverNoOwnershipNoGrantEmptyApprover(t *testing.T) {
	// A user who owns nothing and has no explicit grant gets empty approver scopes.
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{User: &identityv1.User{Id: "u-nobody"}},
	}
	grp := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"g-med": {Id: "g-med", Name: "Medical", Owners: []string{"u-owner"}},
	}}
	out, err := resolvers.MeResolver(ctxWithUser(t, "u-nobody"), read, grp)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if len(out.Scopes.Approver) != 0 {
		t.Errorf("expected empty approver scopes; got %v", out.Scopes.Approver)
	}
}

func TestMeResolverDedupesOwnedAgainstExplicit(t *testing.T) {
	// User has an explicit approver grant for "Medical" AND owns the "Medical"
	// group — the category must appear exactly once (deduped).
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{
				Id:          "u-owner",
				ScopedRoles: []*identityv1.ScopedRole{{Role: "approver", Category: "Medical"}},
			},
		},
	}
	grp := &fakeCategoryClient{groups: map[string]*corev1.Category{
		"g-med": {Id: "g-med", Name: "Medical", Owners: []string{"u-owner"}},
	}}
	out, err := resolvers.MeResolver(ctxWithUser(t, "u-owner"), read, grp)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	count := 0
	for _, c := range out.Scopes.Approver {
		if c == "Medical" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 'Medical' exactly once (deduped); got %v", out.Scopes.Approver)
	}
}

func TestMeResolverNilCategoryClientSkipsEnrichment(t *testing.T) {
	// A nil group client skips enrichment entirely: only explicit grants remain.
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{
				Id:          "u-owner",
				ScopedRoles: []*identityv1.ScopedRole{{Role: "approver", Category: "IT"}},
			},
		},
	}
	out, err := resolvers.MeResolver(ctxWithUser(t, "u-owner"), read, nil)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if len(out.Scopes.Approver) != 1 || out.Scopes.Approver[0] != "IT" {
		t.Errorf("expected only explicit 'IT'; got %v", out.Scopes.Approver)
	}
}

func TestMeResolverNoClaims(t *testing.T) {
	read := &fakeReadClient{}
	_, err := resolvers.MeResolver(context.Background(), read, nil)
	if err == nil {
		t.Fatal("expected error when no claims in context")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got %v", status.Code(err))
	}
}

func TestMeResolverNilClient(t *testing.T) {
	_, err := resolvers.MeResolver(ctxWithUser(t, "u-1"), nil, nil)
	if err == nil {
		t.Fatal("expected error when read client is nil")
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestUserToGraphQLProjection(t *testing.T) {
	protoUser := &identityv1.User{
		Id:      "u-1",
		Email:   "user@example.com",
		Name:    "Example User",
		Enabled: true,
		Roles:   []string{"admin"},
		ScopedRoles: []*identityv1.ScopedRole{
			{Role: "author", Category: "cat-x"},
			{Role: "approver", Category: "cat-y"},
		},
		Groups:    []string{"grp-1"},
		IdpGroups: []string{"ad-1", "ad-2"},
		PolicyOverrides: []*identityv1.PolicyOverride{
			{PolicyNumber: "POL-001", Effect: identityv1.OverrideEffect_OVERRIDE_EFFECT_ALLOW},
			{PolicyNumber: "POL-002", Effect: identityv1.OverrideEffect_OVERRIDE_EFFECT_UNSPECIFIED}, // should be skipped
		},
	}

	// Expose userToGraphQL indirectly via MeResolver.
	read := &fakeReadClient{getUserResp: &identityv1.GetUserResponse{User: protoUser}}
	out, err := resolvers.MeResolver(ctxWithUser(t, "u-1"), read, nil)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}

	if out.UserID != "u-1" {
		t.Errorf("UserID: got %q", out.UserID)
	}
	if len(out.GroupIds) != 1 || out.GroupIds[0] != "grp-1" {
		t.Errorf("GroupIds: got %v", out.GroupIds)
	}
	if len(out.IdpGroups) != 2 {
		t.Errorf("AdGroups count: got %d", len(out.IdpGroups))
	}
	if len(out.Scopes.Author) != 1 || out.Scopes.Author[0] != "cat-x" {
		t.Errorf("Author: got %v", out.Scopes.Author)
	}
	if len(out.Scopes.Approver) != 1 || out.Scopes.Approver[0] != "cat-y" {
		t.Errorf("Approver: got %v", out.Scopes.Approver)
	}
	// Only the ALLOW override should survive; UNSPECIFIED is skipped.
	if len(out.PolicyOverrides) != 1 {
		t.Fatalf("PolicyOverrides count: got %d want 1", len(out.PolicyOverrides))
	}
	if out.PolicyOverrides[0].PolicyNumber != "POL-001" {
		t.Errorf("override policy number: got %q", out.PolicyOverrides[0].PolicyNumber)
	}
	if out.PolicyOverrides[0].Effect != resolvers.OverrideEffectAllow {
		t.Errorf("override effect: got %v", out.PolicyOverrides[0].Effect)
	}
}

func containsStr(s []string, v string) bool {
	return slices.Contains(s, v)
}

func TestUserToGraphQL_Permissions(t *testing.T) {
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{Id: "u-1", Roles: []string{"compliance-admin"}},
		},
	}
	out, err := resolvers.MeResolver(ctxWithUser(t, "u-1"), read, nil)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	// No role grants read-sensitive; only the individual grant does.
	if containsStr(out.Permissions, "policy.read_sensitive") || !containsStr(out.Permissions, "compliance.manage") {
		t.Fatalf("permissions: %v", out.Permissions)
	}

	read.getUserResp.User.ReadSensitiveGrant = true
	out, err = resolvers.MeResolver(ctxWithUser(t, "u-1"), read, nil)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if !containsStr(out.Permissions, "policy.read_sensitive") {
		t.Fatalf("the read-sensitive grant must list policy.read_sensitive: %v", out.Permissions)
	}
}

func TestUsersResolverArgMapping(t *testing.T) {
	search := "alice"
	pageSize := 10
	pageToken := "tok-1"

	read := &fakeReadClient{
		listResp: &identityv1.ListUsersByEmailResponse{
			Users:         []*identityv1.User{{Id: "u-1"}},
			NextPageToken: "tok-2",
		},
	}

	out, err := resolvers.UsersResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), read, &search, &pageSize, &pageToken, nil)
	if err != nil {
		t.Fatalf("UsersResolver: %v", err)
	}
	if read.lastListReq == nil {
		t.Fatal("ListUsersByEmail not called")
	}
	if read.lastListReq.EmailSubstring != "alice" {
		t.Errorf("EmailSubstring: got %q", read.lastListReq.EmailSubstring)
	}
	if read.lastListReq.Limit != 10 {
		t.Errorf("Limit: got %d want 10", read.lastListReq.Limit)
	}
	if read.lastListReq.PageToken != "tok-1" {
		t.Errorf("PageToken: got %q", read.lastListReq.PageToken)
	}
	if out.NextPageToken != "tok-2" {
		t.Errorf("NextPageToken: got %q", out.NextPageToken)
	}
	if len(out.Users) != 1 {
		t.Errorf("Users count: got %d", len(out.Users))
	}
}

func TestUsersResolverNilArgs(t *testing.T) {
	read := &fakeReadClient{listResp: &identityv1.ListUsersByEmailResponse{}}
	_, err := resolvers.UsersResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), read, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("UsersResolver with nil args: %v", err)
	}
	if read.lastListReq == nil {
		t.Fatal("ListUsersByEmail not called")
	}
	// Nil args should produce zero values.
	if read.lastListReq.EmailSubstring != "" || read.lastListReq.Limit != 0 || read.lastListReq.PageToken != "" {
		t.Errorf("expected zero-value request fields: %+v", read.lastListReq)
	}
}

func TestGrantRoleResolverCategoryPassthrough(t *testing.T) {
	admin := &fakeAdminClient{
		grantResp: &identityv1.GrantRoleResponse{
			User: &identityv1.User{Id: "u-1", Roles: []string{"author"}},
		},
	}
	cat := "cat-a"
	out, err := resolvers.GrantRoleResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), admin, "u-1", "author", &cat)
	if err != nil {
		t.Fatalf("GrantRoleResolver: %v", err)
	}
	if admin.lastGrantReq == nil {
		t.Fatal("GrantRole not called")
	}
	if admin.lastGrantReq.Category != "cat-a" {
		t.Errorf("Category passthrough: got %q want %q", admin.lastGrantReq.Category, "cat-a")
	}
	if out == nil || out.UserID != "u-1" {
		t.Errorf("unexpected output: %+v", out)
	}
}

func TestGrantRoleResolverErrorPropagates(t *testing.T) {
	admin := &fakeAdminClient{
		grantErr: status.Error(codes.PermissionDenied, "not allowed"),
	}
	_, err := resolvers.GrantRoleResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), admin, "u-1", "author", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", status.Code(err))
	}
}

func TestSetUserPolicyOverrideNilEffectSendsUnspecified(t *testing.T) {
	admin := &fakeAdminClient{
		setPolicyResp: &identityv1.SetUserPolicyOverrideResponse{
			User: &identityv1.User{Id: "u-1"},
		},
	}
	_, err := resolvers.SetUserPolicyOverrideResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), admin, "u-1", "POL-001", nil)
	if err != nil {
		t.Fatalf("SetUserPolicyOverrideResolver: %v", err)
	}
	if admin.lastSetPolicyReq == nil {
		t.Fatal("SetUserPolicyOverride not called")
	}
	if admin.lastSetPolicyReq.Effect != identityv1.OverrideEffect_OVERRIDE_EFFECT_UNSPECIFIED {
		t.Errorf("nil effect should map to UNSPECIFIED; got %v", admin.lastSetPolicyReq.Effect)
	}
}

func TestSetUserPolicyOverrideExplicitAllow(t *testing.T) {
	admin := &fakeAdminClient{
		setPolicyResp: &identityv1.SetUserPolicyOverrideResponse{
			User: &identityv1.User{Id: "u-1"},
		},
	}
	allow := resolvers.OverrideEffectAllow
	_, err := resolvers.SetUserPolicyOverrideResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), admin, "u-1", "POL-001", &allow)
	if err != nil {
		t.Fatalf("SetUserPolicyOverrideResolver: %v", err)
	}
	if admin.lastSetPolicyReq.Effect != identityv1.OverrideEffect_OVERRIDE_EFFECT_ALLOW {
		t.Errorf("ALLOW effect not mapped: got %v", admin.lastSetPolicyReq.Effect)
	}
}

func TestAddUserToGroupRefetchesViaGetUser(t *testing.T) {
	admin := &fakeAdminClient{
		addGroupResp: &identityv1.AddUserToGroupResponse{UserId: "u-1", GroupId: "g-1"},
	}
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{Id: "u-1", Groups: []string{"g-1"}},
		},
	}
	out, err := resolvers.AddUserToGroupResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), admin, read, "u-1", "g-1")
	if err != nil {
		t.Fatalf("AddUserToGroupResolver: %v", err)
	}
	// Must have called GetUser with the correct userID.
	if read.lastGetUserReq == nil || read.lastGetUserReq.UserId != "u-1" {
		t.Errorf("GetUser not called with u-1: %+v", read.lastGetUserReq)
	}
	if out.UserID != "u-1" {
		t.Errorf("UserID: got %q", out.UserID)
	}
	// The refetched user should have the group in GroupIds.
	if len(out.GroupIds) != 1 || out.GroupIds[0] != "g-1" {
		t.Errorf("GroupIds: got %v", out.GroupIds)
	}
}

func TestTransferRootResolverRequiresRootCaller(t *testing.T) {
	// Caller is not the root → PermissionDenied, and TransferRoot is never called.
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{Id: "u-caller", IsRoot: false},
		},
	}
	admin := &fakeAdminClient{}
	_, err := resolvers.TransferRootResolver(ctxWithUser(t, "u-caller"), admin, read, "u-target", "123456")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", status.Code(err))
	}
	if admin.lastTransferReq != nil {
		t.Errorf("TransferRoot should not be called by a non-root caller: %+v", admin.lastTransferReq)
	}
}

func TestTransferRootResolverHappyPath(t *testing.T) {
	// Caller IS the root → delegates to TransferRoot with the target id.
	read := &fakeReadClient{
		getUserResp: &identityv1.GetUserResponse{
			User: &identityv1.User{Id: "u-root", IsRoot: true},
		},
	}
	admin := &fakeAdminClient{
		transferResp: &identityv1.TransferRootResponse{
			User: &identityv1.User{Id: "u-target", IsRoot: true, Roles: []string{"site-admin", "admin"}},
		},
	}
	out, err := resolvers.TransferRootResolver(ctxWithUser(t, "u-root"), admin, read, "u-target", "654321")
	if err != nil {
		t.Fatalf("TransferRootResolver: %v", err)
	}
	if admin.lastTransferReq == nil || admin.lastTransferReq.ToUserId != "u-target" {
		t.Errorf("TransferRoot called with wrong target: %+v", admin.lastTransferReq)
	}
	if admin.lastTransferReq.GetOtp() != "654321" {
		t.Errorf("TransferRoot otp not forwarded: %q", admin.lastTransferReq.GetOtp())
	}
	if out.UserID != "u-target" || !out.IsRoot {
		t.Errorf("unexpected transferred user: %+v", out)
	}
}

func TestRequestStepUpOtpResolver(t *testing.T) {
	admin := &fakeAdminClient{}
	ok, err := resolvers.RequestStepUpOtpResolver(ctxWithUser(t, "u-actor"), admin)
	if err != nil {
		t.Fatalf("RequestStepUpOtpResolver: %v", err)
	}
	if !ok {
		t.Fatal("want true (anti-enumeration success)")
	}
	if admin.stepUpCalls != 1 || admin.lastStepUpReq == nil {
		t.Errorf("RequestStepUpOtp not forwarded to identity: calls=%d", admin.stepUpCalls)
	}
}

func TestRequestStepUpOtpResolverRequiresAuth(t *testing.T) {
	admin := &fakeAdminClient{}
	_, err := resolvers.RequestStepUpOtpResolver(context.Background(), admin)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", status.Code(err))
	}
	if admin.stepUpCalls != 0 {
		t.Errorf("RequestStepUpOtp must not be called without auth")
	}
}

func TestCreateLocalUserResolverHappyPath(t *testing.T) {
	admin := &fakeAdminClient{
		createLocalUserResp: &identityv1.CreateLocalUserResponse{
			User: &identityv1.User{Id: "u-new", Email: "new@example.com", Name: "New User", LocalAccount: true},
		},
	}
	out, err := resolvers.CreateLocalUserResolver(
		ctxWithRoles(t, "u-admin", []string{"site-admin"}),
		admin, "newuser", "new@example.com", "New User", "Passw0rd!")
	if err != nil {
		t.Fatalf("CreateLocalUserResolver: %v", err)
	}
	if out.UserID != "u-new" || out.Email != "new@example.com" {
		t.Errorf("unexpected user: %+v", out)
	}
	if !out.LocalAccount {
		t.Errorf("expected LocalAccount=true to be projected through userToGraphQL, got false")
	}
	if admin.lastCreateLocalReq == nil {
		t.Fatal("CreateLocalUser not called")
	}
	if admin.lastCreateLocalReq.Username != "newuser" || admin.lastCreateLocalReq.Password != "Passw0rd!" {
		t.Errorf("request fields: %+v", admin.lastCreateLocalReq)
	}
}

func TestCreateLocalUserResolverNilClient(t *testing.T) {
	_, err := resolvers.CreateLocalUserResolver(
		ctxWithRoles(t, "u-admin", []string{"site-admin"}),
		nil, "x", "x@example.org", "X", "pw")
	if status.Code(err) != codes.Unavailable {
		t.Errorf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestUpdateUserProfileResolverHappyPath(t *testing.T) {
	admin := &fakeAdminClient{
		updateProfileResp: &identityv1.UpdateUserProfileResponse{
			User: &identityv1.User{Id: "u-1", Name: "Updated Name", Email: "updated@example.com"},
		},
	}
	out, err := resolvers.UpdateUserProfileResolver(
		ctxWithRoles(t, "u-admin", []string{"site-admin"}),
		admin, "u-1", "Updated Name", "updated@example.com")
	if err != nil {
		t.Fatalf("UpdateUserProfileResolver: %v", err)
	}
	if out.Name != "Updated Name" || out.Email != "updated@example.com" {
		t.Errorf("unexpected user: %+v", out)
	}
	if admin.lastUpdateProfileReq == nil || admin.lastUpdateProfileReq.UserId != "u-1" {
		t.Errorf("UpdateUserProfile not called correctly: %+v", admin.lastUpdateProfileReq)
	}
}

// TestSearchUsersMatchingAndLimit verifies the resolver forwards the query as
// EmailSubstring and the limit arg, and maps results to UserLabel correctly.
func TestSearchUsersMatchingAndLimit(t *testing.T) {
	read := &fakeReadClient{
		listResp: &identityv1.ListUsersByEmailResponse{
			Users: []*identityv1.User{
				{Id: "u-1", Name: "Alice Smith", Email: "alice@example.com"},
				{Id: "u-2", Name: "Alice Jones", Email: "alice.jones@example.com"},
			},
		},
	}
	lim := 5
	out, err := resolvers.SearchUsersResolver(ctxWithUser(t, "u-caller"), read, "alice", &lim)
	if err != nil {
		t.Fatalf("SearchUsersResolver: %v", err)
	}
	// Verify the RPC was called with the correct args.
	if read.lastListReq == nil {
		t.Fatal("ListUsersByEmail not called")
	}
	if read.lastListReq.EmailSubstring != "alice" {
		t.Errorf("EmailSubstring: got %q want %q", read.lastListReq.EmailSubstring, "alice")
	}
	if read.lastListReq.Limit != 5 {
		t.Errorf("Limit: got %d want 5", read.lastListReq.Limit)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 results, got %d", len(out))
	}
	if out[0].ID != "u-1" || out[0].Name != "Alice Smith" {
		t.Errorf("result[0]: got %+v", out[0])
	}
	if out[1].ID != "u-2" || out[1].Name != "Alice Jones" {
		t.Errorf("result[1]: got %+v", out[1])
	}
}

// TestSearchUsersDefaultLimit verifies a nil limit sends 20 to the RPC.
func TestSearchUsersDefaultLimit(t *testing.T) {
	read := &fakeReadClient{listResp: &identityv1.ListUsersByEmailResponse{}}
	_, err := resolvers.SearchUsersResolver(ctxWithUser(t, "u-caller"), read, "bob", nil)
	if err != nil {
		t.Fatalf("SearchUsersResolver: %v", err)
	}
	if read.lastListReq == nil {
		t.Fatal("ListUsersByEmail not called")
	}
	if read.lastListReq.Limit != 20 {
		t.Errorf("default limit: got %d want 20", read.lastListReq.Limit)
	}
}

// TestSearchUsersNameFallsBackToEmail verifies that when Name is blank, the
// returned UserLabel.Name is the user's email address.
func TestSearchUsersNameFallsBackToEmail(t *testing.T) {
	read := &fakeReadClient{
		listResp: &identityv1.ListUsersByEmailResponse{
			Users: []*identityv1.User{
				{Id: "u-3", Name: "", Email: "no-name@example.com"},
			},
		},
	}
	out, err := resolvers.SearchUsersResolver(ctxWithUser(t, "u-caller"), read, "no-name", nil)
	if err != nil {
		t.Fatalf("SearchUsersResolver: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out))
	}
	if out[0].Name != "no-name@example.com" {
		t.Errorf("fallback name: got %q want %q", out[0].Name, "no-name@example.com")
	}
}

// TestSearchUsersRequiresAuth verifies an unauthenticated caller is rejected.
func TestSearchUsersRequiresAuth(t *testing.T) {
	read := &fakeReadClient{}
	_, err := resolvers.SearchUsersResolver(context.Background(), read, "alice", nil)
	if err == nil {
		t.Fatal("expected Unauthenticated error")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got %v", status.Code(err))
	}
}

// TestSearchUsersNilClientReturnsUnavailable verifies a nil identity client
// returns Unavailable (not a panic).
func TestSearchUsersNilClientReturnsUnavailable(t *testing.T) {
	_, err := resolvers.SearchUsersResolver(ctxWithUser(t, "u-caller"), nil, "alice", nil)
	if err == nil {
		t.Fatal("expected Unavailable error")
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestResetUserPasswordResolverForwardsToIdentity(t *testing.T) {
	admin := &fakeAdminClient{}
	ok, err := resolvers.ResetUserPasswordResolver(
		ctxWithRoles(t, "u-admin", []string{"site-admin"}),
		admin, "u-1", "NewPass1!")
	if err != nil {
		t.Fatalf("ResetUserPasswordResolver: %v", err)
	}
	if !ok {
		t.Errorf("expected true, got false")
	}
	if admin.lastResetPasswordReq == nil || admin.lastResetPasswordReq.UserId != "u-1" || admin.lastResetPasswordReq.NewPassword != "NewPass1!" {
		t.Errorf("ResetUserPassword not forwarded correctly")
	}
}

// Fail-closed: identity's refusal surfaces unchanged and the resolver reports
// false.
func TestResetUserPasswordResolverRelaysIdentityError(t *testing.T) {
	admin := &fakeAdminClient{resetPasswordErr: status.Error(codes.FailedPrecondition, "no credential")}
	ok, err := resolvers.ResetUserPasswordResolver(
		ctxWithRoles(t, "u-admin", []string{"site-admin"}),
		admin, "u-1", "NewPass1!")
	if ok || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected the identity refusal, got ok=%v err=%v", ok, err)
	}
}

func TestResetUserPasswordResolverDeniedWithoutUserManage(t *testing.T) {
	admin := &fakeAdminClient{}
	_, err := resolvers.ResetUserPasswordResolver(
		ctxWithRoles(t, "u-1", []string{"reader"}),
		admin, "u-2", "NewPass1!")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
	if admin.lastResetPasswordReq != nil {
		t.Fatal("identity must not be called when the gate refuses")
	}
}
