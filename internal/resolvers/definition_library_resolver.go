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

func definitionEntryFromProto(d *corev1.DefinitionEntry) *DefinitionEntry {
	str := func(v string) *string {
		if v == "" {
			return nil
		}
		return &v
	}
	return &DefinitionEntry{
		ID:              d.GetId(),
		CategoryID:      d.GetCategoryId(),
		Term:            d.GetTerm(),
		Definition:      d.GetDefinition(),
		Archived:        d.GetArchived(),
		CreatedByUserID: str(d.GetCreatedByUserId()),
		UsedByCount:     int(d.GetUsedByCount()),
	}
}

func definitionEntriesFromProto(ds []*corev1.DefinitionEntry) []*DefinitionEntry {
	out := make([]*DefinitionEntry, 0, len(ds))
	for _, d := range ds {
		out = append(out, definitionEntryFromProto(d))
	}
	return out
}

func definitionEntryInputToProto(in *DefinitionEntryInput) *corev1.DefinitionEntryInput {
	return &corev1.DefinitionEntryInput{
		CategoryId: in.CategoryID,
		Term:       in.Term,
		Definition: in.Definition,
	}
}

// definitionEntryIsAdmin is the SAME tri-admin predicate the references + contact libraries use:
// site-admin OR template-admin OR compliance-admin (reusing the existing capabilities — no new
// permission).
func definitionEntryIsAdmin(s authz.Subject) bool {
	return subjIsSiteAdmin(s) || authz.HasCapability(s, authz.TemplateManage) || authz.HasCapability(s, authz.ComplianceManage)
}

// fetchDefinitionEntry loads a single library entry by id.
func fetchDefinitionEntry(ctx context.Context, client corev1.DefinitionLibraryServiceClient, id string) (*corev1.DefinitionEntry, error) {
	resp, err := client.ListDefinitionEntries(ctx, &corev1.ListDefinitionEntriesRequest{IncludeArchived: true})
	if err != nil {
		return nil, fmt.Errorf("list definitions: %w", err)
	}
	for _, d := range resp.GetDefinitions() {
		if d.GetId() == id {
			return d, nil
		}
	}
	return nil, status.Error(codes.NotFound, "definition not found")
}

// authorizeDefinitionMutation gates the destructive/edit library actions (update / delete /
// archive-restore) to the tri-admin set (site/template/ compliance admin) OR the entry's own
// creator.
func authorizeDefinitionMutation(ctx context.Context, client corev1.DefinitionLibraryServiceClient, id string) (string, error) {
	uid, subj, err := evalSubjectFromCtx(ctx)
	if err != nil {
		return "", err
	}
	if definitionEntryIsAdmin(subj) {
		return uid, nil
	}
	d, err := fetchDefinitionEntry(ctx, client, id)
	if err != nil {
		return "", err
	}
	if d.GetCreatedByUserId() != "" && d.GetCreatedByUserId() == uid {
		return uid, nil
	}
	return "", status.Error(codes.PermissionDenied, "not authorized to manage this definition")
}

// DefinitionLibraryResolver lists the reusable definitions library, optionally scoped to a single
// category.
func DefinitionLibraryResolver(ctx context.Context, client corev1.DefinitionLibraryServiceClient, categoryID *string, includeArchived bool) ([]*DefinitionEntry, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return nil, err
	}
	req := &corev1.ListDefinitionEntriesRequest{IncludeArchived: includeArchived}
	if categoryID != nil {
		req.CategoryId = *categoryID
	}
	resp, err := client.ListDefinitionEntries(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list definitions: %w", err)
	}
	return definitionEntriesFromProto(resp.GetDefinitions()), nil
}

// PolicyDefinitionCandidatesResolver lists the definitions attachable to a policy: those whose
// category is in the policy's ancestor chain (leaf->root).
func PolicyDefinitionCandidatesResolver(ctx context.Context, client corev1.DefinitionLibraryServiceClient, policyID string, includeArchived bool) ([]*DefinitionEntry, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return nil, err
	}
	resp, err := client.ListPolicyDefinitionCandidates(ctx, &corev1.ListPolicyDefinitionCandidatesRequest{PolicyId: policyID, IncludeArchived: includeArchived})
	if err != nil {
		return nil, fmt.Errorf("list definition candidates: %w", err)
	}
	return definitionEntriesFromProto(resp.GetDefinitions()), nil
}

// PolicyDefinitionEntriesResolver lists the definitions attached to a policy (resolved live, incl.
func PolicyDefinitionEntriesResolver(ctx context.Context, client corev1.DefinitionLibraryServiceClient, policyID string) ([]*DefinitionEntry, error) {
	resp, err := client.ListPolicyDefinitionEntries(ctx, &corev1.ListPolicyDefinitionEntriesRequest{PolicyId: policyID})
	if err != nil {
		return nil, fmt.Errorf("list policy definitions: %w", err)
	}
	return definitionEntriesFromProto(resp.GetDefinitions()), nil
}

// CreateDefinitionResolver adds a library entry.
func CreateDefinitionResolver(ctx context.Context, client corev1.DefinitionLibraryServiceClient, in *DefinitionEntryInput) (*DefinitionEntry, error) {
	actor, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.CreateDefinitionEntry(ctx, &corev1.CreateDefinitionEntryRequest{Input: definitionEntryInputToProto(in), ActorUserId: actor})
	if err != nil {
		return nil, fmt.Errorf("create definition: %w", err)
	}
	return definitionEntryFromProto(resp.GetDefinition()), nil
}

// UpdateDefinitionResolver edits a library entry (propagates live).
func UpdateDefinitionResolver(ctx context.Context, client corev1.DefinitionLibraryServiceClient, id string, in *DefinitionEntryInput) (*DefinitionEntry, error) {
	actor, err := authorizeDefinitionMutation(ctx, client, id)
	if err != nil {
		return nil, err
	}
	resp, err := client.UpdateDefinitionEntry(ctx, &corev1.UpdateDefinitionEntryRequest{Id: id, Input: definitionEntryInputToProto(in), ActorUserId: actor})
	if err != nil {
		return nil, fmt.Errorf("update definition: %w", err)
	}
	return definitionEntryFromProto(resp.GetDefinition()), nil
}

// DeleteDefinitionResolver removes a library entry (refused while attached).
func DeleteDefinitionResolver(ctx context.Context, client corev1.DefinitionLibraryServiceClient, id string) (bool, error) {
	actor, err := authorizeDefinitionMutation(ctx, client, id)
	if err != nil {
		return false, err
	}
	if _, err := client.DeleteDefinitionEntry(ctx, &corev1.DeleteDefinitionEntryRequest{Id: id, ActorUserId: actor}); err != nil {
		return false, fmt.Errorf("delete definition: %w", err)
	}
	return true, nil
}

// SetDefinitionArchivedResolver archives (true) or restores (false) a library entry.
func SetDefinitionArchivedResolver(ctx context.Context, client corev1.DefinitionLibraryServiceClient, id string, archived bool) (*DefinitionEntry, error) {
	actor, err := authorizeDefinitionMutation(ctx, client, id)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetDefinitionEntryArchived(ctx, &corev1.SetDefinitionEntryArchivedRequest{Id: id, Archived: archived, ActorUserId: actor})
	if err != nil {
		return nil, fmt.Errorf("set definition archived: %w", err)
	}
	return definitionEntryFromProto(resp.GetDefinition()), nil
}

// SetPolicyDefinitionEntriesResolver replaces a policy's attached definitions (full replace).
func SetPolicyDefinitionEntriesResolver(ctx context.Context, client corev1.DefinitionLibraryServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID string, definitionIDs []string) ([]*DefinitionEntry, error) {
	actor, err := authorizeEffectiveAuthor(ctx, policyClient, categoryClient, policyID)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetPolicyDefinitionEntries(ctx, &corev1.SetPolicyDefinitionEntriesRequest{PolicyId: policyID, DefinitionIds: definitionIDs, ActorUserId: actor})
	if err != nil {
		return nil, fmt.Errorf("set policy definitions: %w", err)
	}
	return definitionEntriesFromProto(resp.GetDefinitions()), nil
}
