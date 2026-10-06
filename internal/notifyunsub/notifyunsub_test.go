// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package notifyunsub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Golden tokens minted by obligations' notifytoken signer with secret
// "shared-secret", user "u1", category "informational", expiry in year ~2126.
// Their presence here proves the gateway verifier stays byte-compatible with the
// obligations signer.
const (
	goldenUnsub = "eyJ2IjoxLCJwIjoidW5zdWIiLCJ1IjoidTEiLCJjIjoiaW5mb3JtYXRpb25hbCIsImUiOjQ5NDEzMDQ1NTR9.DtlqmVeaN8A0DdxoIfRAxqsDxzFNgpsUyfWQMiwiazM"
	goldenPrefs = "eyJ2IjoxLCJwIjoicHJlZnMiLCJ1IjoidTEiLCJlIjo0OTQxMzA0NTU0fQ.DQ7Fo5M7mVnNdtGSeuNq44yhs_XqNRVVwxsaKDdWkKo"
	goldenSec   = "shared-secret"
)

func TestVerifyGoldenUnsubscribeTokenFromObligations(t *testing.T) {
	v, err := NewVerifier(goldenSec)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	c, err := v.Verify(goldenUnsub, PurposeUnsubscribe)
	if err != nil {
		t.Fatalf("verify obligations-minted token: %v", err)
	}
	if c.UserID != "u1" || c.Category != "informational" {
		t.Fatalf("unexpected claims: %+v", c)
	}
	if _, err := v.Verify(goldenUnsub, PurposePreferences); err != ErrPurpose {
		t.Fatalf("want ErrPurpose, got %v", err)
	}
	if _, err := v.Verify(goldenPrefs, PurposePreferences); err != nil {
		t.Fatalf("verify obligations-minted prefs token: %v", err)
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	v, _ := NewVerifier("some-other-secret")
	if _, err := v.Verify(goldenUnsub, PurposeUnsubscribe); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

// fakeSetter records SetCategoryCadence calls and returns a configurable error.
type fakeSetter struct {
	gotUser string
	gotCat  obligationsv1.NotifCategory
	gotCad  obligationsv1.NotifCadence
	err     error
	calls   int
}

func (f *fakeSetter) SetCategoryCadence(_ context.Context, in *obligationsv1.SetCategoryCadenceRequest, _ ...grpc.CallOption) (*obligationsv1.SetCategoryCadenceResponse, error) {
	f.calls++
	f.gotUser = in.GetUserId()
	f.gotCat = in.GetCategory()
	f.gotCad = in.GetCadence()
	if f.err != nil {
		return nil, f.err
	}
	return &obligationsv1.SetCategoryCadenceResponse{}, nil
}

func newHandlers(t *testing.T, setter CategorySetter) *Handlers {
	t.Helper()
	v, err := NewVerifier(goldenSec)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return New(v, setter, "https://steward.example.org/settings/notifications")
}

func TestOneClickSetsCategoryOff(t *testing.T) {
	fs := &fakeSetter{}
	h := newHandlers(t, fs)

	req := httptest.NewRequest(http.MethodPost, "/notify/unsubscribe?token="+goldenUnsub, nil)
	rec := httptest.NewRecorder()
	h.OneClickHandler()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if fs.calls != 1 || fs.gotUser != "u1" ||
		fs.gotCat != obligationsv1.NotifCategory_NOTIF_CATEGORY_INFORMATIONAL ||
		fs.gotCad != obligationsv1.NotifCadence_NOTIF_CADENCE_OFF {
		t.Fatalf("SetCategoryCadence not called with OFF for u1/informational: %+v", fs)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "unsubscribed" {
		t.Fatalf("unexpected body: %v", body)
	}
}

func TestOneClickMandatoryPointsToPreferences(t *testing.T) {
	fs := &fakeSetter{err: status.Error(codes.InvalidArgument, "mandatory category cannot be off")}
	h := newHandlers(t, fs)

	req := httptest.NewRequest(http.MethodPost, "/notify/unsubscribe?token="+goldenUnsub, nil)
	rec := httptest.NewRecorder()
	h.OneClickHandler()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 for mandatory floor, got %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "see_preferences" || body["preferencesUrl"] == "" {
		t.Fatalf("mandatory floor should point at preferences: %v", body)
	}
}

func TestOneClickRejectsBadToken(t *testing.T) {
	fs := &fakeSetter{}
	h := newHandlers(t, fs)
	req := httptest.NewRequest(http.MethodPost, "/notify/unsubscribe?token=garbage", nil)
	rec := httptest.NewRecorder()
	h.OneClickHandler()(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad token, got %d", rec.Code)
	}
	if fs.calls != 0 {
		t.Fatal("bad token must not reach the backend")
	}
}

func TestManageRedirectsToPreferences(t *testing.T) {
	fs := &fakeSetter{}
	h := newHandlers(t, fs)
	req := httptest.NewRequest(http.MethodGet, "/notify/unsubscribe?token="+goldenUnsub, nil)
	rec := httptest.NewRecorder()
	h.ManageHandler()(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://steward.example.org/settings/notifications" {
		t.Fatalf("unexpected redirect: %q", loc)
	}
	if fs.calls != 1 || fs.gotCad != obligationsv1.NotifCadence_NOTIF_CADENCE_OFF {
		t.Fatalf("browser unsubscribe should still apply OFF: %+v", fs)
	}
}

func TestManageRejectsBadToken(t *testing.T) {
	fs := &fakeSetter{}
	h := newHandlers(t, fs)
	req := httptest.NewRequest(http.MethodGet, "/notify/unsubscribe?token=nope", nil)
	rec := httptest.NewRecorder()
	h.ManageHandler()(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad token, got %d", rec.Code)
	}
}
