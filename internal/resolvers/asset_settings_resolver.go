// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	authz "github.com/Steward-GRC/steward-gateway/internal/authz"
)

// assetSettingsFromProto maps core's asset settings onto the gqlgen model.
func assetSettingsFromProto(in *corev1.AssetSettings) *AssetSettings {
	out := &AssetSettings{Kinds: []*AssetKindSetting{}, RefusedExtensions: []string{}}
	if in == nil {
		return out
	}
	for _, k := range in.GetKinds() {
		ext := k.GetExtensions()
		if ext == nil {
			ext = []string{}
		}
		out.Kinds = append(out.Kinds, &AssetKindSetting{
			Kind:       k.GetKind(),
			Label:      k.GetLabel(),
			Extensions: ext,
			Enabled:    k.GetEnabled(),
			MaxBytes:   int(k.GetMaxBytes()),
		})
	}
	if refused := in.GetRefusedExtensions(); refused != nil {
		out.RefusedExtensions = refused
	}
	out.MaxFileBytes = int(in.GetMaxFileBytes())
	out.UpdatedBy = in.GetUpdatedBy()
	out.UpdatedAt = in.GetUpdatedAt()
	return out
}

// GetAssetSettings reads the editor file settings. Any signed-in user may, so
// the editor can follow the setting.
func GetAssetSettings(ctx context.Context, client corev1.AssetServiceClient) (*AssetSettings, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return nil, err
	}
	resp, err := client.GetAssetSettings(ctx, &corev1.GetAssetSettingsRequest{})
	if err != nil {
		return nil, err
	}
	return assetSettingsFromProto(resp.GetSettings()), nil
}

// SetAssetSettings replaces the set of allowed file kinds. Site-admin only;
// the actor is the signed-in admin, never the request.
func SetAssetSettings(ctx context.Context, client corev1.AssetServiceClient, allowedKinds []string) (*AssetSettings, error) {
	if err := authorizeOp(ctx, authz.SettingsManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetAssetSettings(ctx, &corev1.SetAssetSettingsRequest{
		AllowedKinds: allowedKinds,
		ActorUserId:  uid,
	})
	if err != nil {
		return nil, err
	}
	return assetSettingsFromProto(resp.GetSettings()), nil
}
