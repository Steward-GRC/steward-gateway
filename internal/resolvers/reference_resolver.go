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

func referenceKindFromProto(k corev1.ReferenceKind) ReferenceKind {
	switch k {
	case corev1.ReferenceKind_REFERENCE_KIND_TEXT:
		return ReferenceKindText
	case corev1.ReferenceKind_REFERENCE_KIND_LINK:
		return ReferenceKindLink
	default:
		return ReferenceKindStandard
	}
}

func referenceKindToProto(k ReferenceKind) corev1.ReferenceKind {
	switch k {
	case ReferenceKindText:
		return corev1.ReferenceKind_REFERENCE_KIND_TEXT
	case ReferenceKindLink:
		return corev1.ReferenceKind_REFERENCE_KIND_LINK
	default:
		return corev1.ReferenceKind_REFERENCE_KIND_STANDARD
	}
}

func referenceFromProto(r *corev1.Reference) *Reference {
	str := func(v string) *string {
		if v == "" {
			return nil
		}
		return &v
	}
	return &Reference{
		ID:              r.GetId(),
		Label:           r.GetLabel(),
		Kind:            referenceKindFromProto(r.GetKind()),
		Clause:          str(r.GetClause()),
		Body:            str(r.GetBody()),
		URL:             str(r.GetUrl()),
		Archived:        r.GetArchived(),
		CreatedByUserID: str(r.GetCreatedByUserId()),
		UsedByCount:     int(r.GetUsedByCount()),
	}
}

func referencesFromProto(rs []*corev1.Reference) []*Reference {
	out := make([]*Reference, 0, len(rs))
	for _, r := range rs {
		out = append(out, referenceFromProto(r))
	}
	return out
}

func referenceInputToProto(in *ReferenceInput) *corev1.ReferenceInput {
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return &corev1.ReferenceInput{
		Label:  in.Label,
		Kind:   referenceKindToProto(in.Kind),
		Clause: deref(in.Clause),
		Body:   deref(in.Body),
		Url:    deref(in.URL),
	}
}

// referenceIsAdmin is the SAME tri-admin predicate the contact-block library uses in
// authorizeContactLibrary: site-admin OR template-admin OR compliance-admin (reusing the existing
// capabilities — no new permission).
func referenceIsAdmin(s authz.Subject) bool {
	return subjIsSiteAdmin(s) || authz.HasCapability(s, authz.TemplateManage) || authz.HasCapability(s, authz.ComplianceManage)
}

// fetchReference loads a single library entry by id.
func fetchReference(ctx context.Context, client corev1.ReferenceServiceClient, id string) (*corev1.Reference, error) {
	resp, err := client.ListReferences(ctx, &corev1.ListReferencesRequest{IncludeArchived: true})
	if err != nil {
		return nil, fmt.Errorf("list references: %w", err)
	}
	for _, r := range resp.GetReferences() {
		if r.GetId() == id {
			return r, nil
		}
	}
	return nil, status.Error(codes.NotFound, "reference not found")
}

// authorizeReferenceMutation gates the destructive/edit library actions (update / delete /
// archive-restore) to the tri-admin set (site/template/ compliance admin) OR the entry's own
// creator.
func authorizeReferenceMutation(ctx context.Context, client corev1.ReferenceServiceClient, id string) (string, error) {
	uid, subj, err := evalSubjectFromCtx(ctx)
	if err != nil {
		return "", err
	}
	if referenceIsAdmin(subj) {
		return uid, nil
	}
	ref, err := fetchReference(ctx, client, id)
	if err != nil {
		return "", err
	}
	if ref.GetCreatedByUserId() != "" && ref.GetCreatedByUserId() == uid {
		return uid, nil
	}
	return "", status.Error(codes.PermissionDenied, "not authorized to manage this reference")
}

// ReferencesResolver lists the reusable References/Standards library.
func ReferencesResolver(ctx context.Context, client corev1.ReferenceServiceClient, includeArchived bool) ([]*Reference, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return nil, err
	}
	resp, err := client.ListReferences(ctx, &corev1.ListReferencesRequest{IncludeArchived: includeArchived})
	if err != nil {
		return nil, fmt.Errorf("list references: %w", err)
	}
	return referencesFromProto(resp.GetReferences()), nil
}

// PolicyReferencesResolver lists the entries attached to a policy (resolved live, incl.
func PolicyReferencesResolver(ctx context.Context, client corev1.ReferenceServiceClient, policyID string) ([]*Reference, error) {
	resp, err := client.ListPolicyReferences(ctx, &corev1.ListPolicyReferencesRequest{PolicyId: policyID})
	if err != nil {
		return nil, fmt.Errorf("list policy references: %w", err)
	}
	return referencesFromProto(resp.GetReferences()), nil
}

// CreateReferenceResolver adds a library entry.
func CreateReferenceResolver(ctx context.Context, client corev1.ReferenceServiceClient, in *ReferenceInput) (*Reference, error) {
	actor, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.CreateReference(ctx, &corev1.CreateReferenceRequest{Input: referenceInputToProto(in), ActorUserId: actor})
	if err != nil {
		return nil, fmt.Errorf("create reference: %w", err)
	}
	return referenceFromProto(resp.GetReference()), nil
}

// UpdateReferenceResolver edits a library entry (propagates live).
func UpdateReferenceResolver(ctx context.Context, client corev1.ReferenceServiceClient, id string, in *ReferenceInput) (*Reference, error) {
	actor, err := authorizeReferenceMutation(ctx, client, id)
	if err != nil {
		return nil, err
	}
	resp, err := client.UpdateReference(ctx, &corev1.UpdateReferenceRequest{Id: id, Input: referenceInputToProto(in), ActorUserId: actor})
	if err != nil {
		return nil, fmt.Errorf("update reference: %w", err)
	}
	return referenceFromProto(resp.GetReference()), nil
}

// DeleteReferenceResolver removes a library entry (cascade-detaches).
func DeleteReferenceResolver(ctx context.Context, client corev1.ReferenceServiceClient, id string) (bool, error) {
	actor, err := authorizeReferenceMutation(ctx, client, id)
	if err != nil {
		return false, err
	}
	if _, err := client.DeleteReference(ctx, &corev1.DeleteReferenceRequest{Id: id, ActorUserId: actor}); err != nil {
		return false, fmt.Errorf("delete reference: %w", err)
	}
	return true, nil
}

// SetReferenceArchivedResolver archives (true) or restores (false) a library entry.
func SetReferenceArchivedResolver(ctx context.Context, client corev1.ReferenceServiceClient, id string, archived bool) (*Reference, error) {
	actor, err := authorizeReferenceMutation(ctx, client, id)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetReferenceArchived(ctx, &corev1.SetReferenceArchivedRequest{Id: id, Archived: archived, ActorUserId: actor})
	if err != nil {
		return nil, fmt.Errorf("set reference archived: %w", err)
	}
	return referenceFromProto(resp.GetReference()), nil
}

// SetPolicyReferencesResolver replaces a policy's attached entries (full replace).
func SetPolicyReferencesResolver(ctx context.Context, client corev1.ReferenceServiceClient, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID string, referenceIDs []string) ([]*Reference, error) {
	actor, err := authorizeEffectiveAuthor(ctx, policyClient, categoryClient, policyID)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetPolicyReferences(ctx, &corev1.SetPolicyReferencesRequest{PolicyId: policyID, ReferenceIds: referenceIDs, ActorUserId: actor})
	if err != nil {
		return nil, fmt.Errorf("set policy references: %w", err)
	}
	return referencesFromProto(resp.GetReferences()), nil
}
