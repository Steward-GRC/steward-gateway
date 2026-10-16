// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"slices"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RequestStepUpOtpResolver arms the server-verified step-up confirmation for a high-risk action
// (grantRoot or revokeRoot).
func RequestStepUpOtpResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient) (bool, error) {
	if admin == nil {
		return false, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return false, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	if _, err := admin.RequestStepUpOtp(ctx, &identityv1.RequestStepUpOtpRequest{}); err != nil {
		return false, err
	}
	return true, nil
}

// GrantRootResolver makes userID a root admin as well. Identity itself is
// root-only, refuses act-as and verifies the step-up code; the gateway only
// passes the call through.
func GrantRootResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, otp string) (*User, error) {
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	if _, ok := principal.FromContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	resp, err := admin.GrantRoot(ctx, &identityv1.GrantRootRequest{UserId: userID, Otp: otp})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// RevokeRootResolver takes the root role from userID, who keeps site-admin.
// Same checks as GrantRootResolver, all enforced by identity.
func RevokeRootResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, otp string) (*User, error) {
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	if _, ok := principal.FromContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	resp, err := admin.RevokeRoot(ctx, &identityv1.RevokeRootRequest{UserId: userID, Otp: otp})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// RequestHardResetResolver starts a two-person hard reset of module. Root
// only and refused during act-as, both enforced by identity.
func RequestHardResetResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, module, reason string) (*HardResetRequest, error) {
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	if _, ok := principal.FromContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	resp, err := admin.RequestHardReset(ctx, &identityv1.RequestHardResetRequest{Module: module, Reason: reason})
	if err != nil {
		return nil, err
	}
	return hardResetRequestToGraphQL(resp.GetRequest()), nil
}

// ApproveHardResetResolver approves a pending request by a different root
// admin than its requester, both enforced by identity.
func ApproveHardResetResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, requestID string) (*HardResetRequest, error) {
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	if _, ok := principal.FromContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	resp, err := admin.ApproveHardReset(ctx, &identityv1.ApproveHardResetRequest{RequestId: requestID})
	if err != nil {
		return nil, err
	}
	return hardResetRequestToGraphQL(resp.GetRequest()), nil
}

// CancelHardResetResolver withdraws a pending or approved request; only its
// requester may, enforced by identity.
func CancelHardResetResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, requestID string) (*HardResetRequest, error) {
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	if _, ok := principal.FromContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	resp, err := admin.CancelHardReset(ctx, &identityv1.CancelHardResetRequest{RequestId: requestID})
	if err != nil {
		return nil, err
	}
	return hardResetRequestToGraphQL(resp.GetRequest()), nil
}

// HardResetRequestsResolver lists the hard reset requests, newest first,
// root only (enforced by identity).
func HardResetRequestsResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, module *string) ([]*HardResetRequest, error) {
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	if _, ok := principal.FromContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	mod := ""
	if module != nil {
		mod = *module
	}
	resp, err := admin.ListHardResetRequests(ctx, &identityv1.ListHardResetRequestsRequest{Module: mod})
	if err != nil {
		return nil, err
	}
	out := make([]*HardResetRequest, 0, len(resp.GetRequests()))
	for _, req := range resp.GetRequests() {
		out = append(out, hardResetRequestToGraphQL(req))
	}
	return out, nil
}

// hardResetRequestToGraphQL converts identity's HardResetRequest to the
// GraphQL shape. A nil req (should not happen) converts to a zero-valued
// request rather than panicking on the enum/string calls below.
func hardResetRequestToGraphQL(req *identityv1.HardResetRequest) *HardResetRequest {
	if req == nil {
		return &HardResetRequest{}
	}
	out := &HardResetRequest{
		ID:          req.GetId(),
		Module:      req.GetModule(),
		Reason:      req.GetReason(),
		State:       req.GetState().String(),
		RequestedBy: req.GetRequestedBy(),
		RequestedAt: req.GetRequestedAt(),
		ExpiresAt:   req.GetExpiresAt(),
	}
	if v := req.GetApprovedBy(); v != "" {
		out.ApprovedBy = &v
	}
	if v := req.GetApprovedAt(); v != "" {
		out.ApprovedAt = &v
	}
	if v := req.GetApprovalExpiresAt(); v != "" {
		out.ApprovalExpiresAt = &v
	}
	if v := req.GetCancelledAt(); v != "" {
		out.CancelledAt = &v
	}
	if v := req.GetConsumedAt(); v != "" {
		out.ConsumedAt = &v
	}
	if v := req.GetConsumedBy(); v != "" {
		out.ConsumedBy = &v
	}
	return out
}

// CompleteOnboardingResolver completes the CALLING user's first-run onboarding.
func CompleteOnboardingResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, acceptTerms bool, username *string, firstName *string, lastName *string, email *string) (*User, error) {
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	req := &identityv1.CompleteOnboardingRequest{AcceptTerms: acceptTerms}
	req.Username = username
	req.FirstName = firstName
	req.LastName = lastName
	req.Email = email
	resp, err := admin.CompleteOnboarding(ctx, req)
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// UpdateMyProfileResolver lets the CALLING user edit their OWN first/last name and language
// preference,.
func UpdateMyProfileResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, firstName *string, lastName *string, locale *string) (*User, error) {
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	var normalizedLocale *string
	if locale != nil {
		norm, err := normalizeLocale(*locale)
		if err != nil {
			return nil, err
		}
		normalizedLocale = &norm
	}
	resp, err := admin.UpdateMyProfile(ctx, &identityv1.UpdateMyProfileRequest{
		FirstName: firstName,
		LastName:  lastName,
		Locale:    normalizedLocale,
	})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

func overrideEffectFromGraphQL(e *OverrideEffect) identityv1.OverrideEffect {
	if e == nil {
		return identityv1.OverrideEffect_OVERRIDE_EFFECT_UNSPECIFIED
	}
	switch *e {
	case OverrideEffectAllow:
		return identityv1.OverrideEffect_OVERRIDE_EFFECT_ALLOW
	case OverrideEffectDeny:
		return identityv1.OverrideEffect_OVERRIDE_EFFECT_DENY
	default:
		return identityv1.OverrideEffect_OVERRIDE_EFFECT_UNSPECIFIED
	}
}

// MeResolver returns the signed-in user, never one named in the input.
func MeResolver(ctx context.Context, read identityv1.IdentityReadServiceClient, categoryClient corev1.CategoryServiceClient) (*User, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	if read == nil {
		return nil, status.Error(codes.Unavailable, "identity service unavailable")
	}
	resp, err := read.GetUser(ctx, &identityv1.GetUserRequest{UserId: claims.UserID()})
	if err != nil {
		return nil, err
	}
	me := userToGraphQL(resp.GetUser())
	if categoryClient == nil || me == nil {
		return me, nil
	}
	uid := claims.UserID()
	authorCats, approverCats := meritScopeCategories(ctx, categoryClient, uid, claims.IdpGroups())
	me.Scopes.Author = mergeUniqueCategories(me.Scopes.Author, authorCats)
	me.Scopes.Approver = mergeUniqueCategories(me.Scopes.Approver, approverCats)
	return me, nil
}

// mergeUniqueCategories appends every category name in add to existing that is not already present,
// preserving order and deduping against the explicit grants already projected onto the
// scope.
func mergeUniqueCategories(existing, add []string) []string {
	have := make(map[string]bool, len(existing))
	for _, cat := range existing {
		have[cat] = true
	}
	for _, name := range add {
		if have[name] {
			continue
		}
		have[name] = true
		existing = append(existing, name)
	}
	return existing
}

// meritScopeCategories walks the category tree from the roots and returns the
// names of every category where the caller authors or approves on merit (the
// category rules, without site admin or root).
func meritScopeCategories(ctx context.Context, gc corev1.CategoryServiceClient, uid string, idpGroups []string) (authorCats, approverCats []string) {
	merit := authz.Subject{UserID: uid, Groups: idpGroups}
	seen := make(map[string]bool)
	queue := []string{""}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		resp, err := gc.ListCategoryChildren(ctx, &corev1.ListCategoryChildrenRequest{ParentId: parent})
		if err != nil {
			continue
		}
		for _, g := range resp.GetCategories() {
			id := g.GetId()
			queue = append(queue, id)
			if seen[id] {
				continue
			}
			seen[id] = true
			chain, err := buildCategoryChain(ctx, gc, id)
			if err != nil {
				continue
			}
			res := authz.Resolve(ctx, merit, chain)
			if res.Author.Allowed {
				authorCats = append(authorCats, g.GetName())
			}
			if res.Approve.Allowed {
				approverCats = append(approverCats, g.GetName())
			}
		}
	}
	return authorCats, approverCats
}

// ownedGroupNames walks the category tree from the roots and returns the names
// of every category whose owners include uid.
func ownedGroupNames(ctx context.Context, categoryClient corev1.CategoryServiceClient, uid string) []string {
	var owned []string
	queue := []string{""}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		resp, err := categoryClient.ListCategoryChildren(ctx, &corev1.ListCategoryChildrenRequest{ParentId: parent})
		if err != nil {
			continue
		}
		for _, g := range resp.GetCategories() {
			queue = append(queue, g.GetId())
			if slices.Contains(g.GetOwners(), uid) {
				owned = append(owned, g.GetName())
			}
		}
	}
	return owned
}

// UsersResolver lists users (admin surface), mapping the GraphQL paging args onto ListUsersByEmail.
func UsersResolver(ctx context.Context, read identityv1.IdentityReadServiceClient, search *string, pageSize *int, pageToken *string, includeDeleted *bool) (*UserPage, error) {
	if err := authorizeOp(ctx, authz.UserManage); err != nil {
		return nil, err
	}
	if read == nil {
		return nil, status.Error(codes.Unavailable, "identity service unavailable")
	}
	req := &identityv1.ListUsersByEmailRequest{}
	if search != nil {
		req.EmailSubstring = *search
	}
	if pageSize != nil {
		req.Limit = toInt32(*pageSize)
	}
	if pageToken != nil {
		req.PageToken = *pageToken
	}
	req.IncludeDeleted = derefBool(includeDeleted)
	resp, err := read.ListUsersByEmail(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make([]*User, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		out = append(out, userToGraphQL(u))
	}
	return &UserPage{Users: out, NextPageToken: resp.GetNextPageToken()}, nil
}

// GrantRoleResolver adds a role to a user.
func GrantRoleResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, role string, category *string) (*User, error) {
	if err := authorizeOp(ctx, authz.RoleManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	cat := ""
	if category != nil {
		cat = *category
	}
	resp, err := admin.GrantRole(ctx, &identityv1.GrantRoleRequest{UserId: userID, Role: role, Category: cat})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// RevokeRoleResolver removes a role from a user.
func RevokeRoleResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, role string, category *string) (*User, error) {
	if err := authorizeOp(ctx, authz.RoleManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	cat := ""
	if category != nil {
		cat = *category
	}
	resp, err := admin.RevokeRole(ctx, &identityv1.RevokeRoleRequest{UserId: userID, Role: role, Category: cat})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// EnableUserResolver un-soft-disables a user.
func EnableUserResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID string) (*User, error) {
	if err := authorizeOp(ctx, authz.RoleManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := admin.EnableUser(ctx, &identityv1.EnableUserRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// DisableUserResolver soft-disables a user.
func DisableUserResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID string) (*User, error) {
	if err := authorizeOp(ctx, authz.RoleManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := admin.DisableUser(ctx, &identityv1.DisableUserRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// CanManageGroupMembership authorizes the caller to add/remove memberships of groupID and reports
// whether they hold FULL rights as a site-admin.
func CanManageGroupMembership(ctx context.Context, read identityv1.IdentityReadServiceClient, groupID string) (siteAdmin bool, err error) {
	subj, err := subjectFromCtx(ctx)
	if err != nil {
		return false, err
	}
	if authz.HasCapability(subj, authz.RoleManage) {
		return true, nil
	}
	if read == nil {
		return false, status.Error(codes.Unavailable, "identity service unavailable")
	}
	claims, _ := principal.FromContext(ctx)
	resp, gerr := read.GetUser(ctx, &identityv1.GetUserRequest{UserId: claims.UserID()})
	if gerr != nil {
		return false, gerr
	}
	if slices.Contains(resp.GetUser().GetManagedGroupIds(), groupID) {
		return false, nil
	}
	return false, status.Error(codes.PermissionDenied, "not authorized to manage this group's membership")
}

// AddUserToGroupResolver adds a group membership; because the proto response carries only {user_id,
// group_id} (not a User), it re-fetches via the read client to satisfy the GraphQL User!
func AddUserToGroupResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, read identityv1.IdentityReadServiceClient, userID, groupID string) (*User, error) {
	if _, err := CanManageGroupMembership(ctx, read, groupID); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	_, err := admin.AddUserToGroup(ctx, &identityv1.AddUserToGroupRequest{UserId: userID, GroupId: groupID})
	if err != nil {
		return nil, err
	}
	if read == nil {
		return nil, status.Error(codes.Unavailable, "identity service unavailable")
	}
	getResp, err := read.GetUser(ctx, &identityv1.GetUserRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(getResp.GetUser()), nil
}

// RemoveUserFromGroupResolver removes a group membership; re-fetches the user via the read client
// because the proto response carries only {user_id, group_id}.
func RemoveUserFromGroupResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, read identityv1.IdentityReadServiceClient, userID, groupID string) (*User, error) {
	siteAdmin, err := CanManageGroupMembership(ctx, read, groupID)
	if err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	if read == nil {
		return nil, status.Error(codes.Unavailable, "identity service unavailable")
	}
	if !siteAdmin {
		tgt, terr := read.GetUser(ctx, &identityv1.GetUserRequest{UserId: userID})
		if terr != nil {
			return nil, terr
		}
		for _, m := range tgt.GetUser().GetMemberships() {
			if m.GetGroupId() == groupID && m.GetSource() != "manual" {
				return nil, status.Error(codes.PermissionDenied, "membership is IdP-synced and read-only to group managers")
			}
		}
	}
	if _, err := admin.RemoveUserFromGroup(ctx, &identityv1.RemoveUserFromGroupRequest{UserId: userID, GroupId: groupID}); err != nil {
		return nil, err
	}
	getResp, err := read.GetUser(ctx, &identityv1.GetUserRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(getResp.GetUser()), nil
}

// GrantGroupManagerResolver makes userID a LOCAL group-manager of groupID.
func GrantGroupManagerResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, groupID string) (*User, error) {
	if err := authorizeOp(ctx, authz.RoleManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := admin.GrantGroupManager(ctx, &identityv1.GrantGroupManagerRequest{UserId: userID, GroupId: groupID})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// RevokeGroupManagerResolver removes userID's group-manager grant on groupID.
func RevokeGroupManagerResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, groupID string) (*User, error) {
	if err := authorizeOp(ctx, authz.RoleManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := admin.RevokeGroupManager(ctx, &identityv1.RevokeGroupManagerRequest{UserId: userID, GroupId: groupID})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// ManagedGroupMembersResolver lists the DIRECT members of a platform group for the group-manager
// "My Groups" editor.
func ManagedGroupMembersResolver(ctx context.Context, read identityv1.IdentityReadServiceClient, groupID string) ([]*User, error) {
	if _, err := CanManageGroupMembership(ctx, read, groupID); err != nil {
		return nil, err
	}
	if read == nil {
		return nil, status.Error(codes.Unavailable, "identity service unavailable")
	}
	resp, err := read.ListUsersInGroup(ctx, &identityv1.ListUsersInGroupRequest{GroupId: groupID})
	if err != nil {
		return nil, err
	}
	out := make([]*User, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		out = append(out, userToGraphQL(u))
	}
	return out, nil
}

// CreateLocalUserResolver creates a local (password) account in identity and
// returns it.
func CreateLocalUserResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, username, email, name, password string) (*User, error) {
	if err := authorizeOp(ctx, authz.UserManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := admin.CreateLocalUser(ctx, &identityv1.CreateLocalUserRequest{
		Username: username,
		Email:    email,
		Name:     name,
		Password: password,
	})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// ResetUserPasswordResolver sets a user's password (admin action). Identity
// writes it to the user's Kratos credential.
func ResetUserPasswordResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, newPassword string) (bool, error) {
	if err := authorizeOp(ctx, authz.UserManage); err != nil {
		return false, err
	}
	if admin == nil {
		return false, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	if _, err := admin.ResetUserPassword(ctx, &identityv1.ResetUserPasswordRequest{UserId: userID, NewPassword: newPassword}); err != nil {
		return false, err
	}
	return true, nil
}

// UpdateUserProfileResolver updates a user's name and email (admin action).
func UpdateUserProfileResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, name, email string) (*User, error) {
	if err := authorizeOp(ctx, authz.UserManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := admin.UpdateUserProfile(ctx, &identityv1.UpdateUserProfileRequest{
		UserId: userID,
		Name:   name,
		Email:  email,
	})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}

// SetUserPolicyOverrideResolver upserts a per-policy override.
func SetUserPolicyOverrideResolver(ctx context.Context, admin identityv1.IdentityAdminServiceClient, userID, policyNumber string, effect *OverrideEffect) (*User, error) {
	if err := authorizeOp(ctx, authz.RoleManage); err != nil {
		return nil, err
	}
	if admin == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := admin.SetUserPolicyOverride(ctx, &identityv1.SetUserPolicyOverrideRequest{
		UserId:       userID,
		PolicyNumber: policyNumber,
		Effect:       overrideEffectFromGraphQL(effect),
	})
	if err != nil {
		return nil, err
	}
	return userToGraphQL(resp.GetUser()), nil
}
