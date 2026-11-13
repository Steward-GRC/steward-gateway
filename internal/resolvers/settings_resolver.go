// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	authz "github.com/Steward-GRC/steward-gateway/internal/authz"
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
	var wc *corev1.WorkCalendar
	if in != nil {
		wc = in.GetWorkCalendar()
	}
	return &GlobalSettings{Announcement: ann, Maintenance: maint, WorkCalendar: workCalendarFromProto(wc)}
}

// defaultWorkCalendar is what a site that never set one has: Monday to
// Friday in UTC with no holidays. Core answers the same; this only covers a
// reply that carries no calendar, so the non-null field never goes null.
func defaultWorkCalendar() *WorkCalendar {
	return &WorkCalendar{Weekdays: []int{1, 2, 3, 4, 5}, Timezone: "UTC", Holidays: []*Holiday{}}
}

// workCalendarFromProto maps core's calendar onto the model. A missing one
// becomes the default; the holiday list is never nil so it marshals as [].
func workCalendarFromProto(in *corev1.WorkCalendar) *WorkCalendar {
	if in == nil {
		return defaultWorkCalendar()
	}
	out := &WorkCalendar{
		Weekdays: make([]int, 0, len(in.GetWeekdays())),
		Timezone: in.GetTimezone(),
		Holidays: make([]*Holiday, 0, len(in.GetHolidays())),
	}
	for _, d := range in.GetWeekdays() {
		out.Weekdays = append(out.Weekdays, int(d))
	}
	for _, h := range in.GetHolidays() {
		out.Holidays = append(out.Holidays, &Holiday{Date: h.GetDate(), Label: h.GetLabel()})
	}
	return out
}

// workCalendarToProto maps the input calendar onto core's. The caller only
// calls it for a present input; an absent one stays unset on the request.
func workCalendarToProto(in *WorkCalendarInput) *corev1.WorkCalendar {
	out := &corev1.WorkCalendar{
		Weekdays: make([]int32, 0, len(in.Weekdays)),
		Timezone: in.Timezone,
		Holidays: make([]*corev1.Holiday, 0, len(in.Holidays)),
	}
	for _, d := range in.Weekdays {
		out.Weekdays = append(out.Weekdays, int32(d)) //nolint:gosec // ISO weekdays are validated by core; an out-of-range value is refused there
	}
	for _, h := range in.Holidays {
		if h == nil {
			continue
		}
		out.Holidays = append(out.Holidays, &corev1.Holiday{Date: h.Date, Label: h.Label})
	}
	return out
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
	// An absent workCalendar stays unset: core reads that as "unchanged".
	// The banners above are always sent, because core replaces both on
	// every set.
	if in.WorkCalendar != nil {
		out.WorkCalendar = workCalendarToProto(in.WorkCalendar)
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
