// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// blockTypeFromString maps GraphQL block type strings to the proto enum.
func blockTypeFromString(s string) corev1.BlockType {
	switch s {
	case "boilerplate", "BOILERPLATE":
		return corev1.BlockType_BLOCK_TYPE_BOILERPLATE
	case "editable", "EDITABLE":
		return corev1.BlockType_BLOCK_TYPE_EDITABLE
	default:
		return corev1.BlockType_BLOCK_TYPE_EDITABLE
	}
}

// blockTypeToString is the inverse — proto enum to a lowercase GraphQL string.
func blockTypeToString(b corev1.BlockType) string {
	switch b {
	case corev1.BlockType_BLOCK_TYPE_BOILERPLATE:
		return "boilerplate"
	case corev1.BlockType_BLOCK_TYPE_EDITABLE:
		return "editable"
	default:
		return "unspecified"
	}
}

// sectionsFromProto maps proto Sections (with Blocks) onto the gqlgen Section/Block models for
// response shaping.
func sectionsFromProto(in []*corev1.Section) []*Section {
	out := make([]*Section, 0, len(in))
	for _, s := range in {
		blocks := make([]*Block, 0, len(s.Blocks))
		for _, b := range s.Blocks {
			cj := b.ContentJson
			blocks = append(blocks, &Block{
				Type:        blockTypeToString(b.Type),
				ContentJSON: &cj,
			})
		}
		level := max(int(s.Level), 1)
		out = append(out, &Section{
			Key:      s.Key,
			Title:    s.Title,
			Order:    int(s.Order),
			Level:    level,
			Required: s.Required,
			Blocks:   blocks,
		})
	}
	return out
}

// sectionsToProto converts the GraphQL SectionInput inputs into proto Sections for
// CreateTemplateVersion.
func sectionsToProto(in []*SectionInput) []*corev1.Section {
	out := make([]*corev1.Section, 0, len(in))
	for _, s := range in {
		blocks := make([]*corev1.Block, 0, len(s.Blocks))
		for _, b := range s.Blocks {
			cj := ""
			if b.ContentJSON != nil {
				cj = *b.ContentJSON
			}
			blocks = append(blocks, &corev1.Block{
				Type:        blockTypeFromString(b.Type),
				ContentJson: cj,
			})
		}
		level := int32(1)
		if s.Level != nil && *s.Level >= 1 {
			level = toInt32(*s.Level)
		}
		required := false
		if s.Required != nil {
			required = *s.Required
		}
		out = append(out, &corev1.Section{
			Key:      s.Key,
			Title:    s.Title,
			Order:    toInt32(s.Order),
			Level:    level,
			Required: required,
			Blocks:   blocks,
		})
	}
	return out
}

func templateFromProto(t *corev1.Template) *Template {
	if t == nil {
		return nil
	}
	return &Template{
		ID:              t.Id,
		Code:            t.Code,
		Name:            t.Name,
		OwnerCategoryID: nilIfEmpty(t.OwnerCategoryId),
		RetiredAt:       nilIfEmpty(t.RetiredAt),
	}
}

// RetireTemplate soft-deletes a template (hidden from listings; versions kept).
func RetireTemplate(ctx context.Context, client corev1.TemplateServiceClient, id string) (*Template, error) {
	if err := authorizeOp(ctx, authz.TemplateManage); err != nil {
		return nil, err
	}
	resp, err := client.RetireTemplate(ctx, &corev1.RetireTemplateRequest{Id: id})
	if err != nil {
		return nil, err
	}
	return templateFromProto(resp.Template), nil
}

// RenameTemplate renames a template's display name (template-level, NON-VERSIONED — does not create
// a new template version).
func RenameTemplate(ctx context.Context, client corev1.TemplateServiceClient, id, name string) (*Template, error) {
	if err := authorizeOp(ctx, authz.TemplateManage); err != nil {
		return nil, err
	}
	resp, err := client.RenameTemplate(ctx, &corev1.RenameTemplateRequest{Id: id, Name: name})
	if err != nil {
		return nil, err
	}
	return templateFromProto(resp.Template), nil
}

// UpdateTemplateVersionSections saves edits to a draft version's sections.
func UpdateTemplateVersionSections(ctx context.Context, client corev1.TemplateServiceClient, id string, sections []*SectionInput) (*TemplateVersion, error) {
	if err := authorizeOp(ctx, authz.TemplateManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.UpdateTemplateVersionSections(ctx, &corev1.UpdateTemplateVersionSectionsRequest{
		Id:          id,
		Sections:    sectionsToProto(sections),
		ActorUserId: uid,
	})
	if err != nil {
		return nil, err
	}
	return templateVersionFromProto(resp.Version), nil
}

// DiscardTemplateVersion deletes a draft version.
func DiscardTemplateVersion(ctx context.Context, client corev1.TemplateServiceClient, id string) error {
	if err := authorizeOp(ctx, authz.TemplateManage); err != nil {
		return err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return err
	}
	_, err = client.DeleteTemplateVersion(ctx, &corev1.DeleteTemplateVersionRequest{Id: id, ActorUserId: uid})
	return err
}

// ListTemplateVersions returns all versions of a template (newest first).
func ListTemplateVersions(ctx context.Context, client corev1.TemplateServiceClient, categoryClient corev1.CategoryServiceClient, templateID string) ([]*TemplateVersion, error) {
	if err := authorizeTemplateRead(ctx, client, categoryClient, templateID); err != nil {
		return nil, err
	}
	resp, err := client.ListTemplateVersions(ctx, &corev1.ListTemplateVersionsRequest{TemplateId: templateID})
	if err != nil {
		return nil, err
	}
	out := make([]*TemplateVersion, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		out = append(out, templateVersionFromProto(v))
	}
	return out, nil
}

// DeleteTemplate hard-deletes a template.
func DeleteTemplate(ctx context.Context, client corev1.TemplateServiceClient, id string) error {
	if err := authorizeOp(ctx, authz.TemplateManage); err != nil {
		return err
	}
	_, err := client.DeleteTemplate(ctx, &corev1.DeleteTemplateRequest{Id: id})
	return err
}

func templateVersionFromProto(v *corev1.TemplateVersion) *TemplateVersion {
	if v == nil {
		return nil
	}
	return &TemplateVersion{
		ID:         v.Id,
		TemplateID: v.TemplateId,
		VersionNo:  int(v.VersionNo),
		Status:     v.Status.String(),
		Sections:   sectionsFromProto(v.Sections),
	}
}

// LatestTemplateVersion fetches the latest version of a template — returns nil (mapped from gRPC
// NotFound by upstream handling) when no version exists.
func LatestTemplateVersion(ctx context.Context, client corev1.TemplateServiceClient, categoryClient corev1.CategoryServiceClient, templateID string) (*TemplateVersion, error) {
	if err := authorizeTemplateRead(ctx, client, categoryClient, templateID); err != nil {
		return nil, err
	}
	resp, err := client.GetLatestTemplateVersion(ctx, &corev1.GetLatestTemplateVersionRequest{TemplateId: templateID})
	if err != nil {
		return nil, err
	}
	return templateVersionFromProto(resp.Version), nil
}

// ListTemplates returns the templates the caller may AUTHOR with a template is a harmless "use this
// to CREATE a policy" link, so its visibility is gated on AUTHOR rights — it is returned only when
// its attached category (OwnerCategoryId) is one the caller can author in, per the same
// per-category decision as createPolicy (canAuthorCategory).
func ListTemplates(ctx context.Context, client corev1.TemplateServiceClient, categoryClient corev1.CategoryServiceClient, ownerCategoryID *string) ([]*Template, error) {
	uid, subj, err := evalSubjectFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.ListTemplates(ctx, &corev1.ListTemplatesRequest{OwnerCategoryId: derefOrEmpty(ownerCategoryID)})
	if err != nil {
		return nil, err
	}
	out := make([]*Template, 0, len(resp.Templates))
	for _, t := range resp.Templates {
		if !canAuthorCategory(ctx, categoryClient, uid, subj, t.GetOwnerCategoryId()) {
			continue
		}
		out = append(out, templateFromProto(t))
	}
	return out, nil
}

// authorizeTemplateRead gates a per-template read (latest version / all versions) on the caller's
// AUTHOR capability in the template's attached category, mirroring the ListTemplates filter for the
// single-template path.
func authorizeTemplateRead(ctx context.Context, client corev1.TemplateServiceClient, categoryClient corev1.CategoryServiceClient, templateID string) error {
	uid, subj, err := evalSubjectFromCtx(ctx)
	if err != nil {
		return err
	}
	resp, err := client.ListTemplates(ctx, &corev1.ListTemplatesRequest{})
	if err != nil {
		return err
	}
	for _, t := range resp.Templates {
		if t.GetId() == templateID {
			if canAuthorCategory(ctx, categoryClient, uid, subj, t.GetOwnerCategoryId()) {
				return nil
			}
			break
		}
	}
	return status.Error(codes.PermissionDenied, "not an author for this template's category")
}

// CreateTemplate creates a template owned by the optional ownerCategoryID.
func CreateTemplate(ctx context.Context, client corev1.TemplateServiceClient, name string, ownerCategoryID *string) (*Template, error) {
	if err := authorizeOp(ctx, authz.TemplateManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.CreateTemplate(ctx, &corev1.CreateTemplateRequest{
		Name:            name,
		OwnerCategoryId: derefOrEmpty(ownerCategoryID),
		ActorUserId:     uid,
	})
	if err != nil {
		return nil, err
	}
	return templateFromProto(resp.Template), nil
}

// CreateTemplateVersion creates a new draft version of a template with the supplied sections
// (boilerplate/editable blocks).
func CreateTemplateVersion(ctx context.Context, client corev1.TemplateServiceClient, templateID string, sections []*SectionInput) (*TemplateVersion, error) {
	if err := authorizeOp(ctx, authz.TemplateManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.CreateTemplateVersion(ctx, &corev1.CreateTemplateVersionRequest{
		TemplateId:  templateID,
		Sections:    sectionsToProto(sections),
		ActorUserId: uid,
	})
	if err != nil {
		return nil, err
	}
	return templateVersionFromProto(resp.Version), nil
}

// PublishTemplateVersion transitions a draft template version to published.
func PublishTemplateVersion(ctx context.Context, client corev1.TemplateServiceClient, id string) (*TemplateVersion, error) {
	if err := authorizeOp(ctx, authz.TemplateManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.PublishTemplateVersion(ctx, &corev1.PublishTemplateVersionRequest{Id: id, ActorUserId: uid})
	if err != nil {
		return nil, err
	}
	return templateVersionFromProto(resp.Version), nil
}
