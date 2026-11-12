// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// prefsAdmin records UpdateUserPreferences calls (issue #84).
type prefsAdmin struct {
	identityv1.IdentityAdminServiceClient
	last *identityv1.UpdateUserPreferencesRequest
	resp *identityv1.UpdateUserPreferencesResponse
	err  error
}

func (f *prefsAdmin) UpdateUserPreferences(_ context.Context, in *identityv1.UpdateUserPreferencesRequest, _ ...grpc.CallOption) (*identityv1.UpdateUserPreferencesResponse, error) {
	f.last = in
	return f.resp, f.err
}

func TestUpdateUserPreferences_DeniedWithoutUserManage(t *testing.T) {
	admin := &prefsAdmin{}
	loc := "fr"
	_, err := resolvers.UpdateUserPreferencesResolver(ctxWithRoles(t, "u-1", []string{"reader"}), admin, "u-2", &loc)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
	if admin.last != nil {
		t.Fatal("identity must not be called when the gate refuses")
	}
}

func TestUpdateUserPreferences_UnavailableWithoutClient(t *testing.T) {
	_, err := resolvers.UpdateUserPreferencesResolver(ctxWithRoles(t, "u-1", []string{"site-admin"}), nil, "u-2", nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", err)
	}
}

func TestUpdateUserPreferences_ForwardsNormalizedLocale(t *testing.T) {
	admin := &prefsAdmin{resp: &identityv1.UpdateUserPreferencesResponse{
		User: &identityv1.User{Id: "u-2", Locale: "fr-CA"},
	}}
	loc := " fr-ca "
	got, err := resolvers.UpdateUserPreferencesResolver(ctxWithRoles(t, "u-1", []string{"site-admin"}), admin, "u-2", &loc)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if admin.last.GetUserId() != "u-2" || admin.last.Locale == nil || admin.last.GetLocale() != "fr-CA" {
		t.Fatalf("bad request: %+v", admin.last)
	}
	if got.Locale != "fr-CA" {
		t.Fatalf("bad result: %+v", got)
	}
}

func TestUpdateUserPreferences_OmittedLocaleStaysOmitted(t *testing.T) {
	admin := &prefsAdmin{resp: &identityv1.UpdateUserPreferencesResponse{User: &identityv1.User{Id: "u-2"}}}
	if _, err := resolvers.UpdateUserPreferencesResolver(ctxWithRoles(t, "u-1", []string{"site-admin"}), admin, "u-2", nil); err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if admin.last.Locale != nil {
		t.Fatalf("omitted locale must stay unset, got %q", admin.last.GetLocale())
	}
}

func TestUpdateUserPreferences_EmptyLocaleClears(t *testing.T) {
	admin := &prefsAdmin{resp: &identityv1.UpdateUserPreferencesResponse{User: &identityv1.User{Id: "u-2"}}}
	empty := "  "
	if _, err := resolvers.UpdateUserPreferencesResolver(ctxWithRoles(t, "u-1", []string{"site-admin"}), admin, "u-2", &empty); err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if admin.last.Locale == nil || admin.last.GetLocale() != "" {
		t.Fatalf("empty locale must be forwarded as set-and-empty, got %+v", admin.last)
	}
}

func TestUpdateUserPreferences_InvalidLocaleRefusedBeforeCall(t *testing.T) {
	admin := &prefsAdmin{}
	bad := "not a tag!"
	_, err := resolvers.UpdateUserPreferencesResolver(ctxWithRoles(t, "u-1", []string{"site-admin"}), admin, "u-2", &bad)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if admin.last != nil {
		t.Fatal("identity must not be called for a malformed locale")
	}
}

func TestUpdateUserPreferences_PassesIdentityErrorThrough(t *testing.T) {
	admin := &prefsAdmin{err: status.Error(codes.NotFound, "user not found")}
	loc := "en"
	_, err := resolvers.UpdateUserPreferencesResolver(ctxWithRoles(t, "u-1", []string{"site-admin"}), admin, "u-9", &loc)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}
