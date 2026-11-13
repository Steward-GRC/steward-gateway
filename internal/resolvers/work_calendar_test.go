// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func banners() (*resolvers.AnnouncementInput, *resolvers.MaintenanceInput) {
	return &resolvers.AnnouncementInput{Enabled: true, Level: "warn", Message: "Heads up"},
		&resolvers.MaintenanceInput{Enabled: false, Message: "Later"}
}

func calendarInput() *resolvers.WorkCalendarInput {
	return &resolvers.WorkCalendarInput{
		Weekdays: []int{7, 1, 2, 3, 4},
		Timezone: "Europe/London",
		Holidays: []*resolvers.HolidayInput{
			{Date: "2026-12-25", Label: "Christmas Day"},
			{Date: "2026-12-28", Label: ""},
		},
	}
}

// A calendar core returns is mapped as is.
func TestGetGlobalSettings_mapsWorkCalendar(t *testing.T) {
	client := &fakeSettingsClient{getGlobalResp: &corev1.GetGlobalSettingsResponse{Settings: &corev1.GlobalSettings{
		WorkCalendar: &corev1.WorkCalendar{
			Weekdays: []int32{1, 2, 3},
			Timezone: "America/New_York",
			Holidays: []*corev1.Holiday{{Date: "2026-07-03", Label: "Observed"}, {Date: "2026-11-26"}},
		},
	}}}
	out, err := resolvers.GetGlobalSettings(adminCtx(t), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := &resolvers.WorkCalendar{
		Weekdays: []int{1, 2, 3},
		Timezone: "America/New_York",
		Holidays: []*resolvers.Holiday{{Date: "2026-07-03", Label: "Observed"}, {Date: "2026-11-26", Label: ""}},
	}
	if !reflect.DeepEqual(out.WorkCalendar, want) {
		t.Fatalf("workCalendar = %+v, want %+v", out.WorkCalendar, want)
	}
}

// The field is never null: when core sends none (an older core, or defaults it
// does not spell out), the gateway answers Mon-Fri, UTC, no holidays, with a
// non-nil holiday list so the non-null list marshals as [].
func TestGetGlobalSettings_workCalendarDefaults(t *testing.T) {
	for name, settings := range map[string]*corev1.GlobalSettings{
		"no settings":      nil,
		"no work calendar": {},
	} {
		t.Run(name, func(t *testing.T) {
			client := &fakeSettingsClient{getGlobalResp: &corev1.GetGlobalSettingsResponse{Settings: settings}}
			out, err := resolvers.GetGlobalSettings(adminCtx(t), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out.WorkCalendar == nil {
				t.Fatal("workCalendar must never be nil")
			}
			if !reflect.DeepEqual(out.WorkCalendar.Weekdays, []int{1, 2, 3, 4, 5}) || out.WorkCalendar.Timezone != "UTC" {
				t.Fatalf("defaults = %+v, want Mon-Fri UTC", out.WorkCalendar)
			}
			if out.WorkCalendar.Holidays == nil || len(out.WorkCalendar.Holidays) != 0 {
				t.Fatalf("holidays = %#v, want an empty non-nil list", out.WorkCalendar.Holidays)
			}
		})
	}
}

// Core's own defaults (empty holidays, Mon-Fri, UTC) pass straight through.
func TestGetGlobalSettings_coreDefaultsPassThrough(t *testing.T) {
	client := &fakeSettingsClient{getGlobalResp: &corev1.GetGlobalSettingsResponse{Settings: &corev1.GlobalSettings{
		WorkCalendar: &corev1.WorkCalendar{Weekdays: []int32{1, 2, 3, 4, 5}, Timezone: "UTC"},
	}}}
	out, err := resolvers.GetGlobalSettings(adminCtx(t), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(out.WorkCalendar.Weekdays, []int{1, 2, 3, 4, 5}) || out.WorkCalendar.Timezone != "UTC" ||
		out.WorkCalendar.Holidays == nil || len(out.WorkCalendar.Holidays) != 0 {
		t.Fatalf("got %+v", out.WorkCalendar)
	}
}

// A set that carries the calendar sends it, with both banners as today, and
// returns the calendar core answers with.
func TestSetGlobalSettings_calendarAndBanners(t *testing.T) {
	ann, maint := banners()
	client := &fakeSettingsClient{setGlobalResp: &corev1.SetGlobalSettingsResponse{Settings: &corev1.GlobalSettings{
		Announcement: &corev1.Announcement{Enabled: true, Level: "warn", Message: "Heads up"},
		Maintenance:  &corev1.Maintenance{Message: "Later"},
		WorkCalendar: &corev1.WorkCalendar{Weekdays: []int32{7, 1, 2, 3, 4}, Timezone: "Europe/London",
			Holidays: []*corev1.Holiday{{Date: "2026-12-25", Label: "Christmas Day"}, {Date: "2026-12-28"}}},
	}}}
	out, err := resolvers.SetGlobalSettings(adminCtx(t), client, resolvers.GlobalSettingsInput{
		Announcement: ann, Maintenance: maint, WorkCalendar: calendarInput(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := client.lastSetGlobalReq
	if req.GetActorUserId() != "admin-1" {
		t.Fatalf("actor = %q, want the signed-in admin", req.GetActorUserId())
	}
	s := req.GetSettings()
	if s.GetAnnouncement().GetMessage() != "Heads up" || s.GetAnnouncement().GetLevel() != "warn" || !s.GetAnnouncement().GetEnabled() ||
		s.GetMaintenance().GetMessage() != "Later" {
		t.Fatalf("banners not forwarded: %+v", s)
	}
	wc := s.GetWorkCalendar()
	if wc == nil {
		t.Fatal("work_calendar must be set on the core request")
	}
	if !reflect.DeepEqual(wc.GetWeekdays(), []int32{7, 1, 2, 3, 4}) || wc.GetTimezone() != "Europe/London" ||
		len(wc.GetHolidays()) != 2 || wc.GetHolidays()[0].GetDate() != "2026-12-25" || wc.GetHolidays()[0].GetLabel() != "Christmas Day" ||
		wc.GetHolidays()[1].GetDate() != "2026-12-28" || wc.GetHolidays()[1].GetLabel() != "" {
		t.Fatalf("calendar not forwarded: %+v", wc)
	}
	if out.WorkCalendar.Timezone != "Europe/London" || len(out.WorkCalendar.Holidays) != 2 {
		t.Fatalf("response calendar = %+v", out.WorkCalendar)
	}
}

// Calendar only: the banners still go out (core replaces both on every set),
// and the calendar is set.
func TestSetGlobalSettings_calendarOnlyKeepsSendingBanners(t *testing.T) {
	client := &fakeSettingsClient{}
	ann := &resolvers.AnnouncementInput{Level: "info"}
	maint := &resolvers.MaintenanceInput{}
	_, err := resolvers.SetGlobalSettings(adminCtx(t), client, resolvers.GlobalSettingsInput{
		Announcement: ann, Maintenance: maint, WorkCalendar: calendarInput(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := client.lastSetGlobalReq.GetSettings()
	if s.GetAnnouncement() == nil || s.GetMaintenance() == nil {
		t.Fatalf("both banners must always be sent, got %+v", s)
	}
	if s.GetWorkCalendar() == nil {
		t.Fatal("work_calendar must be set")
	}
}

// Banners only: the calendar is left UNSET on the core request, which core
// reads as "unchanged", and the response still carries the effective calendar.
func TestSetGlobalSettings_absentCalendarIsUnchanged(t *testing.T) {
	ann, maint := banners()
	client := &fakeSettingsClient{setGlobalResp: &corev1.SetGlobalSettingsResponse{Settings: &corev1.GlobalSettings{
		WorkCalendar: &corev1.WorkCalendar{Weekdays: []int32{1, 2, 3, 4, 5}, Timezone: "Asia/Tokyo"},
	}}}
	out, err := resolvers.SetGlobalSettings(adminCtx(t), client, resolvers.GlobalSettingsInput{Announcement: ann, Maintenance: maint})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := client.lastSetGlobalReq.GetSettings()
	if s.WorkCalendar != nil {
		t.Fatalf("work_calendar must be unset when the input omits it, got %+v", s.WorkCalendar)
	}
	if s.GetAnnouncement().GetMessage() != "Heads up" || s.GetMaintenance().GetMessage() != "Later" {
		t.Fatalf("banners must still be sent: %+v", s)
	}
	if out.WorkCalendar.Timezone != "Asia/Tokyo" {
		t.Fatalf("response must carry the stored calendar, got %+v", out.WorkCalendar)
	}
}

// An empty holiday label is allowed and reaches core as given.
func TestSetGlobalSettings_emptyHolidayLabelAccepted(t *testing.T) {
	ann, maint := banners()
	client := &fakeSettingsClient{}
	in := resolvers.GlobalSettingsInput{Announcement: ann, Maintenance: maint, WorkCalendar: &resolvers.WorkCalendarInput{
		Weekdays: []int{1}, Timezone: "UTC", Holidays: []*resolvers.HolidayInput{{Date: "2026-01-01", Label: ""}},
	}}
	if _, err := resolvers.SetGlobalSettings(adminCtx(t), client, in); err != nil {
		t.Fatalf("an empty label must be accepted, got %v", err)
	}
	h := client.lastSetGlobalReq.GetSettings().GetWorkCalendar().GetHolidays()
	if len(h) != 1 || h[0].GetLabel() != "" {
		t.Fatalf("holidays = %+v", h)
	}
}

// Core's InvalidArgument refusal reaches the caller untouched so the error
// presenter can relay its code and message.
func TestSetGlobalSettings_relaysInvalidWorkCalendar(t *testing.T) {
	reg, err := apperr.NewRegistry([]apperr.Entry{{
		Code: 4009, Symbol: "INVALID_WORK_CALENDAR", Category: apperr.CategoryInvalid,
		Title: "work calendar", Cause: "bad calendar", UserSafe: true, Message: "The work calendar is not valid: {reason}.",
	}}, apperr.WithService(4))
	if err != nil {
		t.Fatal(err)
	}
	coreErr := apperrgrpc.Error(context.Background(), reg, apperr.WithMeta(apperr.Coded(4009, nil), apperr.Meta("reason", "unknown time zone")), 4000, "core")
	ann, maint := banners()
	client := &fakeSettingsClient{setGlobalErr: coreErr}
	_, got := resolvers.SetGlobalSettings(adminCtx(t), client, resolvers.GlobalSettingsInput{Announcement: ann, Maintenance: maint, WorkCalendar: calendarInput()})
	if status.Code(got) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument relayed, got %v", got)
	}
	info, ok := apperrgrpc.FromError(got)
	if !ok || info.Symbol != "INVALID_WORK_CALENDAR" || info.Code != 4009 || !strings.Contains(status.Convert(got).Message(), "unknown time zone") {
		t.Fatalf("coded error not relayed: ok=%v info=%+v msg=%q", ok, info, status.Convert(got).Message())
	}
}

// Without settings.manage nothing is sent to core.
func TestSetGlobalSettings_calendarRefusedForNonAdmin(t *testing.T) {
	ann, maint := banners()
	client := &fakeSettingsClient{}
	_, err := resolvers.SetGlobalSettings(nonAdminCtx(t), client, resolvers.GlobalSettingsInput{Announcement: ann, Maintenance: maint, WorkCalendar: calendarInput()})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.setGlobalCallsCount != 0 {
		t.Fatal("core must not be called for an unauthorized caller")
	}
}

// The schema declares exactly what the mock does.
func TestSchema_workCalendarShape(t *testing.T) {
	schema := resolvers.NewExecutableSchema(resolvers.Config{}).Schema()
	wc := schema.Types["WorkCalendar"]
	if wc == nil || schema.Types["Holiday"] == nil || schema.Types["HolidayInput"] == nil || schema.Types["WorkCalendarInput"] == nil {
		t.Fatal("WorkCalendar, Holiday, WorkCalendarInput and HolidayInput must exist")
	}
	if f := schema.Types["GlobalSettings"].Fields.ForName("workCalendar"); f == nil || f.Type.String() != "WorkCalendar!" {
		t.Fatalf("GlobalSettings.workCalendar = %v, want WorkCalendar!", f)
	}
	if f := schema.Types["GlobalSettingsInput"].Fields.ForName("workCalendar"); f == nil || f.Type.String() != "WorkCalendarInput" {
		t.Fatalf("GlobalSettingsInput.workCalendar = %v, want optional WorkCalendarInput", f)
	}
}
