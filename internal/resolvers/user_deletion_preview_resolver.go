// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// deletionItemKindFromProto maps the proto DeletionItemKind onto the GraphQL enum.
func deletionItemKindFromProto(k identityv1.DeletionItemKind) DeletionItemKind {
	switch k {
	case identityv1.DeletionItemKind_DELETION_ITEM_KIND_PENDING_APPROVAL:
		return DeletionItemKindPendingApproval
	case identityv1.DeletionItemKind_DELETION_ITEM_KIND_OWNED_POLICY:
		return DeletionItemKindOwnedPolicy
	case identityv1.DeletionItemKind_DELETION_ITEM_KIND_RACI_GRANT:
		return DeletionItemKindRaciGrant
	case identityv1.DeletionItemKind_DELETION_ITEM_KIND_CREDENTIAL:
		return DeletionItemKindCredential
	default:
		return DeletionItemKindAccessRow
	}
}

func deletionCountsFromProto(c *identityv1.UserDeletionCounts) *UserDeletionCounts {
	return &UserDeletionCounts{
		PendingApprovals: int(c.GetPendingApprovals()),
		OwnedPolicies:    int(c.GetOwnedPolicies()),
		RaciGrants:       int(c.GetRaciGrants()),
		Roles:            int(c.GetRoles()),
		Permissions:      int(c.GetPermissions()),
		GroupMemberships: int(c.GetGroupMemberships()),
		IdpGroups:        int(c.GetIdpGroups()),
		PolicyOverrides:  int(c.GetPolicyOverrides()),
		BreakGlassGrants: int(c.GetBreakGlassGrants()),
		ManagedGroups:    int(c.GetManagedGroups()),
	}
}

// PreviewUserDeletionResolver relays IdentityAdminService.PreviewUserDeletion, the read-only dry
// run of deleteUser.
func PreviewUserDeletionResolver(ctx context.Context, adminClient identityv1.IdentityAdminServiceClient, userID string) (*UserDeletionPreview, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	if adminClient == nil {
		return nil, status.Error(codes.Unavailable, "identity admin unavailable")
	}
	resp, err := adminClient.PreviewUserDeletion(ctx, &identityv1.PreviewUserDeletionRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	p := resp.GetPreview()
	out := &UserDeletionPreview{
		UserID:               p.GetUserId(),
		Counts:               deletionCountsFromProto(p.GetCounts()),
		Items:                make([]*UserDeletionPreviewItem, 0, len(p.GetItems())),
		Warnings:             make([]*UserDeletionWarning, 0, len(p.GetWarnings())),
		BlocksDelete:         p.GetBlocksDelete(),
		LocallyAuthenticable: p.GetLocallyAuthenticable(),
	}
	for _, it := range p.GetItems() {
		out.Items = append(out.Items, &UserDeletionPreviewItem{
			Kind:         deletionItemKindFromProto(it.GetKind()),
			RefID:        it.GetRefId(),
			Label:        it.GetLabel(),
			Detail:       it.GetDetail(),
			BlocksDelete: it.GetBlocksDelete(),
		})
	}
	for _, w := range p.GetWarnings() {
		out.Warnings = append(out.Warnings, &UserDeletionWarning{Code: w.GetCode(), Message: w.GetMessage()})
	}
	return out, nil
}
