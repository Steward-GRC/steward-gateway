// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// globalSettingsFromProto maps the proto GlobalSettings onto the gqlgen model.
func globalSettingsFromProto(in *corev1.GlobalSettings) *GlobalSettings {
	ann := &Announcement{Level: "info"}
	maint := &Maintenance{}
	if in != nil {
		if a := in.GetAnnouncement(); a != nil {
			ann = &Announcement{
				Enabled: a.GetEnabled(),
				Level:   a.GetLevel(),
				Message: a.GetMessage(),
			}
		}
		if m := in.GetMaintenance(); m != nil {
			maint = &Maintenance{
				Enabled: m.GetEnabled(),
				Message: m.GetMessage(),
			}
		}
	}
	return &GlobalSettings{Announcement: ann, Maintenance: maint}
}

// globalSettingsToProto maps the GraphQL input onto the proto GlobalSettings.
func globalSettingsToProto(in GlobalSettingsInput) *corev1.GlobalSettings {
	out := &corev1.GlobalSettings{
		Announcement: &corev1.Announcement{Level: "info"},
		Maintenance:  &corev1.Maintenance{},
	}
	if in.Announcement != nil {
		out.Announcement = &corev1.Announcement{
			Enabled: in.Announcement.Enabled,
			Level:   in.Announcement.Level,
			Message: in.Announcement.Message,
		}
	}
	if in.Maintenance != nil {
		out.Maintenance = &corev1.Maintenance{
			Enabled: in.Maintenance.Enabled,
			Message: in.Maintenance.Message,
		}
	}
	return out
}

// GetGlobalSettings reads the cross-app settings singleton.
func GetGlobalSettings(ctx context.Context, client corev1.SettingsServiceClient) (*GlobalSettings, error) {
	resp, err := client.GetGlobalSettings(ctx, &corev1.GetGlobalSettingsRequest{})
	if err != nil {
		return nil, err
	}
	return globalSettingsFromProto(resp.GetSettings()), nil
}

// SetGlobalSettings writes the cross-app settings singleton.
func SetGlobalSettings(ctx context.Context, client corev1.SettingsServiceClient, input GlobalSettingsInput) (*GlobalSettings, error) {
	if err := authorizeOp(ctx, authz.SettingsManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetGlobalSettings(ctx, &corev1.SetGlobalSettingsRequest{
		Settings:    globalSettingsToProto(input),
		ActorUserId: uid,
	})
	if err != nil {
		return nil, err
	}
	return globalSettingsFromProto(resp.GetSettings()), nil
}

// emailServiceStatusFromProto maps core's keyless email-service status.
func emailServiceStatusFromProto(in *corev1.EmailServiceStatus) *EmailServiceConfigStatus {
	out := &EmailServiceConfigStatus{}
	if in != nil {
		out.APIKeySet = in.GetApiKeySet()
		out.Provider = in.GetProvider()
		out.Domain = in.GetDomain()
		out.Region = in.GetRegion()
		out.FromAddress = in.GetFromAddress()
		out.Enabled = in.GetEnabled()
	}
	return out
}

// GetEmailServiceConfig reads the keyless email-service status.
func GetEmailServiceConfig(ctx context.Context, client corev1.SettingsServiceClient) (*EmailServiceConfigStatus, error) {
	if err := authorizeOp(ctx, authz.SettingsManage); err != nil {
		return nil, err
	}
	resp, err := client.EmailServiceConfigStatus(ctx, &corev1.EmailServiceConfigStatusRequest{})
	if err != nil {
		return nil, err
	}
	return emailServiceStatusFromProto(resp.GetStatus()), nil
}

// SetEmailServiceConfig stores the email-service config and returns the
// keyless status. A nil apiKey keeps the stored key; "" clears it.
func SetEmailServiceConfig(ctx context.Context, client corev1.SettingsServiceClient, input EmailServiceConfigInput) (*EmailServiceConfigStatus, error) {
	if err := authorizeOp(ctx, authz.SettingsManage); err != nil {
		return nil, err
	}
	uid, err := claimsUserID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetEmailServiceConfig(ctx, &corev1.SetEmailServiceConfigRequest{
		ApiKey:      input.APIKey,
		Provider:    input.Provider,
		Domain:      input.Domain,
		Region:      input.Region,
		FromAddress: input.FromAddress,
		Enabled:     input.Enabled,
		ActorUserId: uid,
	})
	if err != nil {
		return nil, err
	}
	return emailServiceStatusFromProto(resp.GetStatus()), nil
}
