// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func contactBlockFromProto(b *corev1.ContactBlock) *ContactBlock {
	str := func(v string) *string {
		if v == "" {
			return nil
		}
		return &v
	}
	return &ContactBlock{
		ID:          b.GetId(),
		Label:       b.GetLabel(),
		Name:        str(b.GetName()),
		Role:        str(b.GetRole()),
		Department:  str(b.GetDepartment()),
		Email:       str(b.GetEmail()),
		Phone:       str(b.GetPhone()),
		Hours:       str(b.GetHours()),
		Notes:       str(b.GetNotes()),
		Archived:    b.GetArchived(),
		UsedByCount: int(b.GetUsedByCount()),
	}
}

// authorizeContactLibrary gates all contact-library CRUD (create/edit/archive/ restore) to the
// three admin types: site-admin OR template-admin OR compliance-admin (reusing the existing
// capabilities — no new permission).
func authorizeContactLibrary(ctx context.Context) error {
	s, err := subjectFromCtx(ctx)
	if err != nil {
		return err
	}
	if subjIsSiteAdmin(s) || authz.HasCapability(s, authz.TemplateManage) || authz.HasCapability(s, authz.ComplianceManage) {
		return nil
	}
	return status.Error(codes.PermissionDenied, "not authorized to manage the contact library")
}

func contactInputToProto(in *ContactBlockInput) *corev1.ContactBlockInput {
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return &corev1.ContactBlockInput{
		Label:      in.Label,
		Name:       deref(in.Name),
		Role:       deref(in.Role),
		Department: deref(in.Department),
		Email:      deref(in.Email),
		Phone:      deref(in.Phone),
		Hours:      deref(in.Hours),
		Notes:      deref(in.Notes),
	}
}

func contactBlocksFromProto(bs []*corev1.ContactBlock) []*ContactBlock {
	out := make([]*ContactBlock, 0, len(bs))
	for _, b := range bs {
		out = append(out, contactBlockFromProto(b))
	}
	return out
}

// ContactBlocksResolver lists the reusable contact-block library.
func ContactBlocksResolver(ctx context.Context, client corev1.ContactServiceClient, includeArchived bool) ([]*ContactBlock, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return nil, err
	}
	resp, err := client.ListContactBlocks(ctx, &corev1.ListContactBlocksRequest{IncludeArchived: includeArchived})
	if err != nil {
		return nil, fmt.Errorf("list contact blocks: %w", err)
	}
	return contactBlocksFromProto(resp.GetBlocks()), nil
}

// PolicyContactBlocksResolver lists the blocks attached to a policy (resolved live).
func PolicyContactBlocksResolver(ctx context.Context, client corev1.ContactServiceClient, policyID string) ([]*ContactBlock, error) {
	resp, err := client.ListPolicyContactBlocks(ctx, &corev1.ListPolicyContactBlocksRequest{PolicyId: policyID})
	if err != nil {
		return nil, fmt.Errorf("list policy contact blocks: %w", err)
	}
	return contactBlocksFromProto(resp.GetBlocks()), nil
}

// CreateContactBlockResolver adds a library block.
func CreateContactBlockResolver(ctx context.Context, client corev1.ContactServiceClient, in *ContactBlockInput) (*ContactBlock, error) {
	if err := authorizeContactLibrary(ctx); err != nil {
		return nil, err
	}
	resp, err := client.CreateContactBlock(ctx, &corev1.CreateContactBlockRequest{Block: contactInputToProto(in)})
	if err != nil {
		return nil, fmt.Errorf("create contact block: %w", err)
	}
	return contactBlockFromProto(resp.GetBlock()), nil
}

// UpdateContactBlockResolver edits a library block (propagates live).
func UpdateContactBlockResolver(ctx context.Context, client corev1.ContactServiceClient, id string, in *ContactBlockInput) (*ContactBlock, error) {
	if err := authorizeContactLibrary(ctx); err != nil {
		return nil, err
	}
	resp, err := client.UpdateContactBlock(ctx, &corev1.UpdateContactBlockRequest{Id: id, Block: contactInputToProto(in)})
	if err != nil {
		return nil, fmt.Errorf("update contact block: %w", err)
	}
	return contactBlockFromProto(resp.GetBlock()), nil
}

// DeleteContactBlockResolver removes a library block (cascade-detaches).
func DeleteContactBlockResolver(ctx context.Context, client corev1.ContactServiceClient, id string) (bool, error) {
	if err := authorizeContactLibrary(ctx); err != nil {
		return false, err
	}
	if _, err := client.DeleteContactBlock(ctx, &corev1.DeleteContactBlockRequest{Id: id}); err != nil {
		return false, fmt.Errorf("delete contact block: %w", err)
	}
	return true, nil
}

// SetContactBlockArchivedResolver archives (true) or restores (false) a library block.
func SetContactBlockArchivedResolver(ctx context.Context, client corev1.ContactServiceClient, id string, archived bool) (*ContactBlock, error) {
	if err := authorizeContactLibrary(ctx); err != nil {
		return nil, err
	}
	resp, err := client.SetContactBlockArchived(ctx, &corev1.SetContactBlockArchivedRequest{Id: id, Archived: archived})
	if err != nil {
		return nil, fmt.Errorf("set contact block archived: %w", err)
	}
	return contactBlockFromProto(resp.GetBlock()), nil
}

// SetPolicyContactBlocksResolver replaces a policy's attached blocks.
func SetPolicyContactBlocksResolver(ctx context.Context, client corev1.ContactServiceClient, policyID string, blockIDs []string) ([]*ContactBlock, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return nil, err
	}
	resp, err := client.SetPolicyContactBlocks(ctx, &corev1.SetPolicyContactBlocksRequest{PolicyId: policyID, ContactBlockIds: blockIDs})
	if err != nil {
		return nil, fmt.Errorf("set policy contact blocks: %w", err)
	}
	return contactBlocksFromProto(resp.GetBlocks()), nil
}
