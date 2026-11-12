// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// These tests map the mock server's quiet-hours cases
// (steward-mock-server src/product/notification-inbox.test.ts, "quiet hours")
// onto the gateway. Steward-obligations stores the window, validates it and
// applies it at send time (steward-obligations#54), so the gateway's job is:
// read it for the caller, forward the set or clear with the caller bound from
// the session, answer the full settings after a set, and relay the coded
// NOTIFY_PREF_INVALID refusal untouched.

// quietClient is a notification-preference service that stores one window the
// way obligations does: unset until saved, cleared by neither start nor end,
// refused with NOTIFY_PREF_INVALID when the window is not valid.
type quietClient struct {
	*fakeNotifPrefClient
	stored   *obligationsv1.QuietHours
	getErr   error
	setErr   error
	getCalls int
	lastGet  *obligationsv1.GetQuietHoursRequest
	lastSet  *obligationsv1.SetQuietHoursRequest
}

func newQuietClient() *quietClient {
	return &quietClient{fakeNotifPrefClient: &fakeNotifPrefClient{
		settingsResp: &obligationsv1.GetNotificationSettingsResponse{
			Settings: &obligationsv1.NotificationSettings{
				Channels: &obligationsv1.NotificationPref{UserId: "u-1", Email: true, InApp: true},
				Digest:   &obligationsv1.DigestWindow{DailyHour: 8, WeeklyDow: 1},
			},
		},
	}}
}

func (q *quietClient) GetQuietHours(_ context.Context, in *obligationsv1.GetQuietHoursRequest, _ ...grpc.CallOption) (*obligationsv1.GetQuietHoursResponse, error) {
	q.getCalls++
	q.lastGet = in
	if q.getErr != nil {
		return nil, q.getErr
	}
	return &obligationsv1.GetQuietHoursResponse{QuietHours: q.stored}, nil
}

func (q *quietClient) SetQuietHours(_ context.Context, in *obligationsv1.SetQuietHoursRequest, _ ...grpc.CallOption) (*obligationsv1.SetQuietHoursResponse, error) {
	q.lastSet = in
	if q.setErr != nil {
		return nil, q.setErr
	}
	if in.Start == nil && in.End == nil {
		q.stored = nil
		return &obligationsv1.SetQuietHoursResponse{}, nil
	}
	tz := in.GetTimezone()
	if tz == "" {
		tz = "UTC"
	}
	q.stored = &obligationsv1.QuietHours{Start: in.GetStart(), End: in.GetEnd(), Timezone: tz}
	return &obligationsv1.SetQuietHoursResponse{QuietHours: q.stored}, nil
}

func errPrefInvalid(t *testing.T) error {
	t.Helper()
	st := codedCoreError(t, codes.InvalidArgument, 7005, "NOTIFY_PREF_INVALID",
		"That notification preference isn't valid — check the value and try again.", nil)
	return st
}

func intp(n int) *int { return &n }

// Mock: "is off until saved". An unset window answers null.
func TestQuietHours_NullUntilSaved(t *testing.T) {
	q := newQuietClient()
	got, err := resolvers.QuietHoursResolver(ctxWithUser(t, "u-1"), q)
	if err != nil {
		t.Fatalf("QuietHoursResolver: %v", err)
	}
	if got != nil {
		t.Fatalf("no stored window must read null, got %+v", got)
	}
	if q.lastGet.GetUserId() != "u-1" {
		t.Fatalf("user must be bound from the session, got %q", q.lastGet.GetUserId())
	}
}

func TestQuietHours_ReadMapsTheStoredWindow(t *testing.T) {
	q := newQuietClient()
	q.stored = &obligationsv1.QuietHours{Start: 22, End: 7, Timezone: "America/New_York"}
	got, err := resolvers.QuietHoursResolver(ctxWithUser(t, "u-1"), q)
	if err != nil {
		t.Fatalf("QuietHoursResolver: %v", err)
	}
	if got == nil || got.Start != 22 || got.End != 7 || got.Timezone != "America/New_York" {
		t.Fatalf("window mismapped: %+v", got)
	}
}

func TestQuietHours_ReadNeedsASignedInUser(t *testing.T) {
	q := newQuietClient()
	if _, err := resolvers.QuietHoursResolver(context.Background(), q); err == nil {
		t.Fatal("expected an unauthenticated error")
	}
	if q.getCalls != 0 {
		t.Fatal("GetQuietHours must not be called without claims")
	}
}

func TestQuietHours_ReadPropagatesServiceError(t *testing.T) {
	q := newQuietClient()
	q.getErr = errPrefInvalid(t)
	if _, err := resolvers.QuietHoursResolver(ctxWithUser(t, "u-1"), q); err == nil {
		t.Fatal("expected the service error")
	}
}

// Mock: "stores a window in the person's timezone, beside the other settings".
func TestSetQuietHours_ForwardsTheWindowAndReturnsTheSettings(t *testing.T) {
	q := newQuietClient()
	out, err := resolvers.SetQuietHoursResolver(ctxWithUser(t, "u-1"), q, intp(22), intp(7), strp("America/New_York"))
	if err != nil {
		t.Fatalf("SetQuietHoursResolver: %v", err)
	}
	if q.lastSet.GetUserId() != "u-1" {
		t.Fatalf("user must be bound from the session, got %q", q.lastSet.GetUserId())
	}
	if q.lastSet.Start == nil || *q.lastSet.Start != 22 || q.lastSet.End == nil || *q.lastSet.End != 7 ||
		q.lastSet.GetTimezone() != "America/New_York" {
		t.Fatalf("window not forwarded: %+v", q.lastSet)
	}
	if out == nil || !out.Channels.Email || out.Digest.DailyHour != 8 {
		t.Fatalf("the full settings must come back beside the window: %+v", out)
	}
}

// Mock: "takes UTC when no timezone is given". The gateway leaves the default
// to obligations, which answers UTC for an empty timezone.
func TestSetQuietHours_NoTimezoneIsForwardedEmpty(t *testing.T) {
	q := newQuietClient()
	if _, err := resolvers.SetQuietHoursResolver(ctxWithUser(t, "u-1"), q, intp(23), intp(6), nil); err != nil {
		t.Fatalf("SetQuietHoursResolver: %v", err)
	}
	if q.lastSet.GetTimezone() != "" {
		t.Fatalf("no timezone must reach obligations empty, got %q", q.lastSet.GetTimezone())
	}
	if q.stored == nil || q.stored.Timezone != "UTC" {
		t.Fatalf("obligations stores UTC for an empty timezone, got %+v", q.stored)
	}
}

// Mock: "clears with no start and end". Neither set stays unset on the wire,
// never a zero hour.
func TestSetQuietHours_NoStartAndEndClears(t *testing.T) {
	q := newQuietClient()
	q.stored = &obligationsv1.QuietHours{Start: 22, End: 7, Timezone: "UTC"}
	if _, err := resolvers.SetQuietHoursResolver(ctxWithUser(t, "u-1"), q, nil, nil, nil); err != nil {
		t.Fatalf("SetQuietHoursResolver: %v", err)
	}
	if q.lastSet.Start != nil || q.lastSet.End != nil {
		t.Fatalf("clearing must send neither start nor end, got %+v", q.lastSet)
	}
	if q.stored != nil {
		t.Fatalf("window not cleared: %+v", q.stored)
	}
}

// A window across midnight and hour 0 are real values: a zero is sent as set,
// not dropped as if it were absent.
func TestSetQuietHours_HourZeroIsAValue(t *testing.T) {
	q := newQuietClient()
	if _, err := resolvers.SetQuietHoursResolver(ctxWithUser(t, "u-1"), q, intp(0), intp(6), nil); err != nil {
		t.Fatalf("SetQuietHoursResolver: %v", err)
	}
	if q.lastSet.Start == nil || *q.lastSet.Start != 0 {
		t.Fatalf("start 0 must be sent as set, got %+v", q.lastSet.Start)
	}
}

// A negative or huge hour must reach obligations as it is so it is refused
// there; narrowing it to 0 would store a window nobody asked for.
func TestSetQuietHours_OutOfRangeHoursAreNotClamped(t *testing.T) {
	q := newQuietClient()
	if _, err := resolvers.SetQuietHoursResolver(ctxWithUser(t, "u-1"), q, intp(-1), intp(7), nil); err != nil {
		t.Fatalf("SetQuietHoursResolver: %v", err)
	}
	if q.lastSet.Start == nil || *q.lastSet.Start != -1 {
		t.Fatalf("start -1 must reach obligations unchanged, got %+v", q.lastSet.Start)
	}
}

func TestSetQuietHours_NeedsASignedInUser(t *testing.T) {
	q := newQuietClient()
	if _, err := resolvers.SetQuietHoursResolver(context.Background(), q, intp(22), intp(7), nil); err == nil {
		t.Fatal("expected an unauthenticated error")
	}
	if q.lastSet != nil {
		t.Fatal("SetQuietHours must not be called without claims")
	}
}

// --- over GraphQL ---------------------------------------------------------------------------

// The schema exposes NotificationSettings.quietHours, null until saved.
func TestQuietHours_OverGraphQL_ReadNullThenSaved(t *testing.T) {
	q := newQuietClient()
	res := &resolvers.Resolver{NotifPrefClient: q}
	const read = `query { notificationSettings { digest { dailyHour } quietHours { start end timezone } } }`

	out := lockGraphQL(t, ctxWithUser(t, "u-1"), res, read, nil)
	if len(out.Errors) != 0 {
		t.Fatalf("errors: %+v", out.Errors)
	}
	var settings struct {
		QuietHours *struct {
			Start    int    `json:"start"`
			End      int    `json:"end"`
			Timezone string `json:"timezone"`
		} `json:"quietHours"`
	}
	if err := json.Unmarshal(out.Data["notificationSettings"], &settings); err != nil {
		t.Fatal(err)
	}
	if settings.QuietHours != nil {
		t.Fatalf("want null before a save, got %+v", settings.QuietHours)
	}

	q.stored = &obligationsv1.QuietHours{Start: 22, End: 7, Timezone: "Europe/Paris"}
	out = lockGraphQL(t, ctxWithUser(t, "u-1"), res, read, nil)
	if len(out.Errors) != 0 {
		t.Fatalf("errors: %+v", out.Errors)
	}
	if err := json.Unmarshal(out.Data["notificationSettings"], &settings); err != nil {
		t.Fatal(err)
	}
	if settings.QuietHours == nil || settings.QuietHours.Start != 22 || settings.QuietHours.End != 7 || settings.QuietHours.Timezone != "Europe/Paris" {
		t.Fatalf("saved window: %+v", settings.QuietHours)
	}
}

// The mutation's arguments are all optional: omitted start and end clear, a
// given pair is stored, and the answer is the settings with the new window.
func TestSetQuietHours_OverGraphQL_SetThenClear(t *testing.T) {
	q := newQuietClient()
	res := &resolvers.Resolver{NotifPrefClient: q}
	const set = `mutation ($start: Int, $end: Int, $timezone: String) {
		setQuietHours(start: $start, end: $end, timezone: $timezone) {
			channels { email inApp push }
			quietHours { start end timezone }
		}
	}`

	out := lockGraphQL(t, ctxWithUser(t, "u-1"), res, set, map[string]any{"start": 22, "end": 7, "timezone": "America/New_York"})
	if len(out.Errors) != 0 {
		t.Fatalf("errors: %+v", out.Errors)
	}
	var got struct {
		Channels   struct{ Email, InApp, Push bool }
		QuietHours *struct {
			Start    int
			End      int
			Timezone string
		}
	}
	if err := json.Unmarshal(out.Data["setQuietHours"], &got); err != nil {
		t.Fatal(err)
	}
	if got.QuietHours == nil || got.QuietHours.Start != 22 || got.QuietHours.End != 7 || got.QuietHours.Timezone != "America/New_York" {
		t.Fatalf("stored window: %+v", got.QuietHours)
	}
	if !got.Channels.Email || !got.Channels.InApp || got.Channels.Push {
		t.Fatalf("the other settings must ride along: %+v", got.Channels)
	}

	out = lockGraphQL(t, ctxWithUser(t, "u-1"), res, set, map[string]any{})
	if len(out.Errors) != 0 {
		t.Fatalf("errors: %+v", out.Errors)
	}
	got.QuietHours = &struct {
		Start    int
		End      int
		Timezone string
	}{}
	if err := json.Unmarshal(out.Data["setQuietHours"], &got); err != nil {
		t.Fatal(err)
	}
	if got.QuietHours != nil {
		t.Fatalf("no start and end must clear the window, got %+v", got.QuietHours)
	}
}

// Mock: "refuses an hour out of range, half a window, an empty window and an
// unknown timezone". Obligations decides; the client sees its coded refusal.
func TestSetQuietHours_OverGraphQL_RefusalReachesTheClientCoded(t *testing.T) {
	q := newQuietClient()
	q.setErr = errPrefInvalid(t)
	out := lockGraphQL(t, ctxWithUser(t, "u-1"), &resolvers.Resolver{NotifPrefClient: q},
		`mutation { setQuietHours(start: 22) { digest { dailyHour } } }`, nil)
	if len(out.Errors) != 1 {
		t.Fatalf("want one error, got %+v", out.Errors)
	}
	e := out.Errors[0]
	if e.Extensions["code"] != "NOTIFY_PREF_INVALID" {
		t.Errorf("code = %v, want NOTIFY_PREF_INVALID", e.Extensions["code"])
	}
	if n, _ := e.Extensions["codeNum"].(float64); int(n) != 7005 {
		t.Errorf("codeNum = %v, want 7005", e.Extensions["codeNum"])
	}
	if e.Extensions["kind"] != "business" {
		t.Errorf("kind = %v, want business", e.Extensions["kind"])
	}
	if q.lastSet.GetStart() != 22 || q.lastSet.End != nil {
		t.Errorf("the half window must reach obligations as given: %+v", q.lastSet)
	}
}
