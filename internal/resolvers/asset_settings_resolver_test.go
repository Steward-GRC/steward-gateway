// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"reflect"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeAssetSettingsClient stubs only the two settings calls of core's AssetService.
type fakeAssetSettingsClient struct {
	corev1.AssetServiceClient
	settings *corev1.AssetSettings
	getErr   error
	setErr   error
	gets     int
	sets     int
	lastSet  *corev1.SetAssetSettingsRequest
}

func (f *fakeAssetSettingsClient) GetAssetSettings(_ context.Context, _ *corev1.GetAssetSettingsRequest, _ ...grpc.CallOption) (*corev1.GetAssetSettingsResponse, error) {
	f.gets++
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &corev1.GetAssetSettingsResponse{Settings: f.settings}, nil
}

func (f *fakeAssetSettingsClient) SetAssetSettings(_ context.Context, in *corev1.SetAssetSettingsRequest, _ ...grpc.CallOption) (*corev1.SetAssetSettingsResponse, error) {
	f.sets++
	f.lastSet = in
	if f.setErr != nil {
		return nil, f.setErr
	}
	return &corev1.SetAssetSettingsResponse{Settings: f.settings}, nil
}

func sampleAssetSettings() *corev1.AssetSettings {
	return &corev1.AssetSettings{
		Kinds: []*corev1.AssetKindSetting{
			{Kind: "pdf", Label: "PDF", Extensions: []string{"pdf"}, Enabled: true, MaxBytes: 25 << 20},
			{Kind: "image", Label: "Images", Extensions: []string{"png", "jpg", "jpeg", "gif", "webp"}, Enabled: false, MaxBytes: 10 << 20},
		},
		RefusedExtensions: []string{"exe", "html"},
		MaxFileBytes:      25 << 20,
		UpdatedBy:         "admin-1",
		UpdatedAt:         "2026-11-01T10:00:00Z",
	}
}

func TestAssetSettings_AnySignedInUserReadsThem(t *testing.T) {
	client := &fakeAssetSettingsClient{settings: sampleAssetSettings()}
	got, err := resolvers.GetAssetSettings(ctxWithUser(t, "user-1"), client)
	if err != nil {
		t.Fatalf("GetAssetSettings: %v", err)
	}
	if len(got.Kinds) != 2 || got.Kinds[0].Kind != "pdf" || !got.Kinds[0].Enabled || got.Kinds[1].Enabled {
		t.Errorf("kinds = %+v", got.Kinds)
	}
	if !reflect.DeepEqual(got.Kinds[1].Extensions, []string{"png", "jpg", "jpeg", "gif", "webp"}) {
		t.Errorf("extensions = %v", got.Kinds[1].Extensions)
	}
	if got.Kinds[1].MaxBytes != 10<<20 || got.MaxFileBytes != 25<<20 {
		t.Errorf("caps = %d / %d", got.Kinds[1].MaxBytes, got.MaxFileBytes)
	}
	if !reflect.DeepEqual(got.RefusedExtensions, []string{"exe", "html"}) {
		t.Errorf("refused = %v", got.RefusedExtensions)
	}
	if got.UpdatedBy != "admin-1" || got.UpdatedAt != "2026-11-01T10:00:00Z" {
		t.Errorf("updated = %q %q", got.UpdatedBy, got.UpdatedAt)
	}
}

func TestAssetSettings_ReadNeedsASession(t *testing.T) {
	client := &fakeAssetSettingsClient{settings: sampleAssetSettings()}
	if _, err := resolvers.GetAssetSettings(context.Background(), client); err == nil {
		t.Fatal("want an error without a signed-in user")
	}
	if client.gets != 0 {
		t.Errorf("core was called %d times without a session", client.gets)
	}
}

func TestAssetSettings_ReadPassesCoreErrorsOn(t *testing.T) {
	client := &fakeAssetSettingsClient{getErr: status.Error(codes.Unavailable, "down")}
	_, err := resolvers.GetAssetSettings(ctxWithUser(t, "user-1"), client)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}

func TestAssetSettings_SetIsAdminOnly(t *testing.T) {
	client := &fakeAssetSettingsClient{settings: sampleAssetSettings()}
	for name, ctx := range map[string]context.Context{
		"reader":  nonAdminCtx(t),
		"author":  ctxWithClaims(t, "author-1", "author"),
		"no user": context.Background(),
	} {
		_, err := resolvers.SetAssetSettings(ctx, client, []string{"pdf"})
		if err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
	if client.sets != 0 {
		t.Errorf("core was called %d times for a non-admin", client.sets)
	}
	if _, err := resolvers.SetAssetSettings(nonAdminCtx(t), client, []string{"pdf"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestAssetSettings_SetBindsTheActorAndReturnsTheSettings(t *testing.T) {
	client := &fakeAssetSettingsClient{settings: sampleAssetSettings()}
	got, err := resolvers.SetAssetSettings(adminCtx(t), client, []string{"pdf", "text"})
	if err != nil {
		t.Fatalf("SetAssetSettings: %v", err)
	}
	if client.lastSet.GetActorUserId() != "admin-1" {
		t.Errorf("actor = %q, want the signed-in admin", client.lastSet.GetActorUserId())
	}
	if !reflect.DeepEqual(client.lastSet.GetAllowedKinds(), []string{"pdf", "text"}) {
		t.Errorf("allowed = %v", client.lastSet.GetAllowedKinds())
	}
	if len(got.Kinds) != 2 {
		t.Errorf("returned kinds = %d", len(got.Kinds))
	}
}

func TestAssetSettings_AllOffIsAllowedAndUnknownKindIsCoresRefusal(t *testing.T) {
	client := &fakeAssetSettingsClient{settings: sampleAssetSettings()}
	if _, err := resolvers.SetAssetSettings(adminCtx(t), client, nil); err != nil {
		t.Fatalf("all off: %v", err)
	}
	if client.sets != 1 || len(client.lastSet.GetAllowedKinds()) != 0 {
		t.Errorf("sets = %d, allowed = %v", client.sets, client.lastSet.GetAllowedKinds())
	}
	client.setErr = status.Error(codes.InvalidArgument, `asset: unknown kind "exe"`)
	_, err := resolvers.SetAssetSettings(adminCtx(t), client, []string{"exe"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
}
