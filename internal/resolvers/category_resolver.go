// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// ackTriggerToProto maps a GQL AckTrigger to its proto counterpart.
func ackTriggerToProto(t AckTrigger) corev1.AckTrigger {
	switch t {
	case AckTriggerOnPublish:
		return corev1.AckTrigger_ACK_TRIGGER_ON_PUBLISH
	case AckTriggerOnChange:
		return corev1.AckTrigger_ACK_TRIGGER_ON_CHANGE
	default:
		return corev1.AckTrigger_ACK_TRIGGER_NONE
	}
}

// ackTriggerFromProto maps a proto AckTrigger to the GQL enum.
func ackTriggerFromProto(t corev1.AckTrigger) AckTrigger {
	switch t {
	case corev1.AckTrigger_ACK_TRIGGER_ON_PUBLISH:
		return AckTriggerOnPublish
	case corev1.AckTrigger_ACK_TRIGGER_ON_CHANGE:
		return AckTriggerOnChange
	default:
		return AckTriggerNone
	}
}

// reviewCadenceToProto maps a GQL ReviewCadence to its proto counterpart.
func reviewCadenceToProto(c ReviewCadence) corev1.ReviewCadence {
	switch c {
	case ReviewCadenceAnnual:
		return corev1.ReviewCadence_REVIEW_CADENCE_ANNUAL
	case ReviewCadenceBiennial:
		return corev1.ReviewCadence_REVIEW_CADENCE_BIENNIAL
	case ReviewCadenceOnDate:
		return corev1.ReviewCadence_REVIEW_CADENCE_ON_DATE
	default:
		return corev1.ReviewCadence_REVIEW_CADENCE_NONE
	}
}

// reviewCadenceFromProto maps a proto ReviewCadence to the GQL enum.
func reviewCadenceFromProto(c corev1.ReviewCadence) ReviewCadence {
	switch c {
	case corev1.ReviewCadence_REVIEW_CADENCE_ANNUAL:
		return ReviewCadenceAnnual
	case corev1.ReviewCadence_REVIEW_CADENCE_BIENNIAL:
		return ReviewCadenceBiennial
	case corev1.ReviewCadence_REVIEW_CADENCE_ON_DATE:
		return ReviewCadenceOnDate
	default:
		return ReviewCadenceNone
	}
}

// categoryFromProto maps a core Category. The audience and exclusion lists are
// nil when the category inherits them and non-nil (possibly empty) when it
// sets its own.
func categoryFromProto(g *corev1.Category) *Category {
	if g == nil {
		return nil
	}
	owners := orEmpty(g.Owners)
	var idpGroupIds []string
	if g.AudienceGroupIdsSet {
		idpGroupIds = orEmpty(g.AudienceGroupIds)
	}
	var exclusionGroupIds []string
	if g.ExclusionGroupIdsSet {
		exclusionGroupIds = orEmpty(g.ExclusionGroupIds)
	}
	return &Category{
		ID:                  g.Id,
		Name:                g.Name,
		Slug:                g.Slug,
		ParentID:            nilIfEmpty(g.ParentId),
		DefaultTemplateID:   nilIfEmpty(g.DefaultTemplateId),
		DefaultTemplateNone: g.DefaultTemplateNone,
		DefaultWorkflowID:   nilIfEmpty(g.DefaultWorkflowId),
		Owners:              owners,
		IdpGroupIds:         idpGroupIds,
		AckTriggers:         ackTriggerFromProto(g.AckTriggers),
		ReviewCadence:       reviewCadenceFromProto(g.ReviewCadence),
		ReviewDate:          nilIfEmpty(g.ReviewDate),
		ExclusionGroupIds:   exclusionGroupIds,
		AckEveryone:         g.GetAckEveryone(),
		AckEveryoneSet:      g.GetAckEveryoneSet(),
	}
}

// GetCategory fetches one category.
func GetCategory(ctx context.Context, client corev1.CategoryServiceClient, id string) (*Category, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}
	resp, err := client.GetCategory(ctx, &corev1.GetCategoryRequest{Id: id})
	if err != nil {
		return nil, err
	}
	return categoryFromProto(resp.Category), nil
}

// ListCategoryChildren returns the direct children of parentID; nil lists the
// roots.
func ListCategoryChildren(ctx context.Context, client corev1.CategoryServiceClient, parentID *string) ([]*Category, error) {
	resp, err := client.ListCategoryChildren(ctx, &corev1.ListCategoryChildrenRequest{ParentId: derefOrEmpty(parentID)})
	if err != nil {
		return nil, err
	}
	out := make([]*Category, 0, len(resp.GetCategories()))
	for _, g := range resp.GetCategories() {
		out = append(out, categoryFromProto(g))
	}
	return out, nil
}

// CategoryTree returns rootID's whole subtree, including rootID itself, or
// the whole category forest when rootID is nil/empty. Categories are at most
// three levels deep (category.proto), so the recursion is always shallow, and
// every call is the same open read as categoryChildren.
func CategoryTree(ctx context.Context, client corev1.CategoryServiceClient, rootID *string) ([]*Category, error) {
	var out []*Category
	var walk func(parentID *string) error
	walk = func(parentID *string) error {
		children, err := ListCategoryChildren(ctx, client, parentID)
		if err != nil {
			return err
		}
		for _, c := range children {
			out = append(out, c)
			id := c.ID
			if err := walk(&id); err != nil {
				return err
			}
		}
		return nil
	}
	if rootID == nil || *rootID == "" {
		if err := walk(nil); err != nil {
			return nil, err
		}
		return out, nil
	}
	root, err := GetCategory(ctx, client, *rootID)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, status.Error(codes.NotFound, "category not found")
	}
	out = append(out, root)
	if err := walk(rootID); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateCategory creates a category under the optional parentID.
func CreateCategory(ctx context.Context, client corev1.CategoryServiceClient, name, slug string, parentID *string) (*Category, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.CreateCategory(ctx, &corev1.CreateCategoryRequest{
		Name:        name,
		Slug:        slug,
		ParentId:    derefOrEmpty(parentID),
		ActorUserId: uid,
	})
	if err != nil {
		return nil, err
	}
	return categoryFromProto(resp.Category), nil
}

// SetCategoryDefaults sets the inheritable default template and workflow. A
// nil id unsets it; defaultTemplateNone=true is the explicit freeform default.
func SetCategoryDefaults(ctx context.Context, client corev1.CategoryServiceClient, id string, defaultTemplateID, defaultWorkflowID *string, defaultTemplateNone *bool) (*Category, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetCategoryDefaults(ctx, &corev1.SetCategoryDefaultsRequest{
		Id:                  id,
		DefaultTemplateId:   derefOrEmpty(defaultTemplateID),
		DefaultWorkflowId:   derefOrEmpty(defaultWorkflowID),
		DefaultTemplateNone: derefBool(defaultTemplateNone),
		ActorUserId:         uid,
	})
	if err != nil {
		return nil, err
	}
	return categoryFromProto(resp.Category), nil
}

// SetCategoryGovernance persists a category's governance. idpGroupIds and
// exclusionGroupIds are tri-state: nil leaves the stored (possibly inherited)
// value alone, a non-nil slice (even empty) overrides it.
func SetCategoryGovernance(
	ctx context.Context,
	client corev1.CategoryServiceClient,
	id string,
	owners []string,
	idpGroupIds []string,
	exclusionGroupIds []string,
	ackTriggers AckTrigger,
	reviewCadence ReviewCadence,
	reviewDate *string,
	ackEveryone *bool,
) (*Category, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetGovernance(ctx, &corev1.SetGovernanceRequest{
		Id:                        id,
		Owners:                    owners,
		AudienceGroupIds:          idpGroupIds,
		AudienceGroupIdsProvided:  idpGroupIds != nil,
		ExclusionGroupIds:         exclusionGroupIds,
		ExclusionGroupIdsProvided: exclusionGroupIds != nil,
		AckTriggers:               ackTriggerToProto(ackTriggers),
		ReviewCadence:             reviewCadenceToProto(reviewCadence),
		ReviewDate:                derefOrEmpty(reviewDate),
		AckEveryone:               derefBool(ackEveryone),
		AckEveryoneProvided:       ackEveryone != nil,
		ActorUserId:               uid,
	})
	if err != nil {
		return nil, err
	}
	return categoryFromProto(resp.Category), nil
}

// RenameCategory renames a category; existing policies keep their numbers.
func RenameCategory(ctx context.Context, client corev1.CategoryServiceClient, id, name, slug string) (*Category, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}
	resp, err := client.RenameCategory(ctx, &corev1.RenameCategoryRequest{
		Id:   id,
		Name: name,
		Slug: slug,
	})
	if err != nil {
		return nil, err
	}
	return categoryFromProto(resp.Category), nil
}

// DeleteCategory deletes a category and its policy-free descendants; core
// refuses when any of them owns policies.
func DeleteCategory(ctx context.Context, client corev1.CategoryServiceClient, id string) (bool, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return false, err
	}
	resp, err := client.DeleteCategory(ctx, &corev1.DeleteCategoryRequest{Id: id})
	if err != nil {
		return false, err
	}
	return resp.GetDeleted(), nil
}

// MoveCategory re-parents a category and its subtree; nil promotes it to a
// root. Core refuses a cycle or a tree deeper than three levels.
func MoveCategory(ctx context.Context, client corev1.CategoryServiceClient, categoryID string, newParentID *string) (*Category, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}
	resp, err := client.MoveCategory(ctx, &corev1.MoveCategoryRequest{
		CategoryId:  categoryID,
		NewParentId: derefOrEmpty(newParentID),
	})
	if err != nil {
		return nil, err
	}
	return categoryFromProto(resp.Category), nil
}

// GetEffectiveGovernance returns the inherited audience and exclusions core
// resolves leaf-wins up the chain. It is gated like the other governance
// reads: inherited audiences are not for every reader.
func GetEffectiveGovernance(ctx context.Context, client corev1.CategoryServiceClient, categoryID string) (*EffectiveGovernance, error) {
	if err := authorizeOp(ctx, authz.GroupManage); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, status.Error(codes.Unavailable, "category service unavailable")
	}
	resp, err := client.GetEffectiveGovernance(ctx, &corev1.GetEffectiveGovernanceRequest{CategoryId: categoryID})
	if err != nil {
		return nil, err
	}
	eg := &EffectiveGovernance{}
	if resp.AudienceSet {
		eg.AckAudienceGroups = orEmpty(resp.AckAudienceGroups)
	}
	if resp.ExclusionSet {
		eg.ExclusionGroups = orEmpty(resp.ExclusionGroups)
	}
	eg.AckEveryone = resp.GetAckEveryone()
	return eg, nil
}
