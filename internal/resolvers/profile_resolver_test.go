// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	"github.com/Bugs5382/go-apperr/apperrgrpc"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUpdateMyProfileResolver_RequiresAuth(t *testing.T) {
	admin := &fakeAdminClient{}
	_, err := resolvers.UpdateMyProfileResolver(context.Background(), admin, nil, nil, nil)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated without claims, got %v", err)
	}
}

func TestUpdateMyProfileResolver_UnavailableWhenNoClient(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
	_, err := resolvers.UpdateMyProfileResolver(ctx, nil, nil, nil, nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable with nil admin client, got %v", err)
	}
}

// TestUpdateMyProfileResolver_ForwardsAndMaps proves the resolver is
// caller-scoped (a plain authenticated user, no admin role), forwards the
// presence-tracked first/last name to the RPC (never a userId), and maps the
// returned user — whose display name is DERIVED server-side — onto the GraphQL
// User.
func TestUpdateMyProfileResolver_ForwardsAndMaps(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
	first := "Alice"
	last := "Example"
	// name is the derived display name returned by identity; never sent.
	name := "Alice Example"
	admin := &fakeAdminClient{
		updateMyProfileResp: &identityv1.UpdateMyProfileResponse{
			User: &identityv1.User{Id: "user-1", Name: name, FirstName: first, LastName: last, Email: "alice@example.org"},
		},
	}
	got, err := resolvers.UpdateMyProfileResolver(ctx, admin, &first, &last, nil)
	if err != nil {
		t.Fatalf("UpdateMyProfileResolver: %v", err)
	}
	if admin.lastUpdateMyProfile == nil {
		t.Fatal("expected request forwarded to RPC")
	}
	if admin.lastUpdateMyProfile.GetFirstName() != first || admin.lastUpdateMyProfile.GetLastName() != last {
		t.Fatalf("first/last not forwarded: %+v", admin.lastUpdateMyProfile)
	}
	// Response mapped onto the GraphQL User (display name derived server-side).
	if got.FirstName != first || got.LastName != last {
		t.Fatalf("first/last not mapped: %+v", got)
	}
	if got.Name != name {
		t.Fatalf("derived name not mapped: got %q want %q", got.Name, name)
	}
}

// TestUpdateMyProfileResolver_PresenceForwardedForOmitted verifies that omitting
// a field forwards a nil pointer (presence semantics preserved end to end), so
// the identity service leaves the omitted value unchanged.
func TestUpdateMyProfileResolver_PresenceForwardedForOmitted(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
	last := "Jones"
	admin := &fakeAdminClient{
		updateMyProfileResp: &identityv1.UpdateMyProfileResponse{
			User: &identityv1.User{Id: "user-1", Name: "Ann Jones", FirstName: "Ann", LastName: "Jones"},
		},
	}
	if _, err := resolvers.UpdateMyProfileResolver(ctx, admin, nil, &last, nil); err != nil {
		t.Fatalf("UpdateMyProfileResolver: %v", err)
	}
	if admin.lastUpdateMyProfile.FirstName != nil {
		t.Fatalf("omitted first_name must forward nil, got %+v", admin.lastUpdateMyProfile)
	}
	if admin.lastUpdateMyProfile.LastName == nil || admin.lastUpdateMyProfile.GetLastName() != last {
		t.Fatalf("present last_name must forward: %+v", admin.lastUpdateMyProfile)
	}
	// locale is on the SAME presence contract. An omitted locale must
	// forward nil so identity leaves the stored language preference untouched —
	// a name edit can never silently reset the user's language.
	if admin.lastUpdateMyProfile.Locale != nil {
		t.Fatalf("omitted locale must forward nil, got %+v", admin.lastUpdateMyProfile)
	}
}

// TestUpdateMyProfileResolver_ForwardsValidLocale proves a well-formed BCP-47
// tag reaches identity's UpdateMyProfile, canonically cased, and that the
// response's locale is projected back onto the GraphQL User.
func TestUpdateMyProfileResolver_ForwardsValidLocale(t *testing.T) {
	cases := []struct{ in, want string }{
		{"en", "en"},
		{"en-US", "en-US"},
		{"EN-us", "en-US"},     // canonicalized: lowercase language, UPPER region
		{"zh-hant", "zh-Hant"}, // script subtag Titlecased
		{"zh-Hant-TW", "zh-Hant-TW"},
		{"es-419", "es-419"}, // UN M.49 numeric region
		{"fil-PH", "fil-PH"}, // 3-letter language subtag
		{"  en-GB  ", "en-GB"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
			admin := &fakeAdminClient{
				updateMyProfileResp: &identityv1.UpdateMyProfileResponse{
					User: &identityv1.User{Id: "user-1", Locale: tc.want},
				},
			}
			got, err := resolvers.UpdateMyProfileResolver(ctx, admin, nil, nil, &tc.in)
			if err != nil {
				t.Fatalf("UpdateMyProfileResolver(%q): %v", tc.in, err)
			}
			if admin.lastUpdateMyProfile == nil {
				t.Fatal("expected request forwarded to RPC")
			}
			if admin.lastUpdateMyProfile.Locale == nil {
				t.Fatalf("present locale must forward non-nil: %+v", admin.lastUpdateMyProfile)
			}
			if fwd := admin.lastUpdateMyProfile.GetLocale(); fwd != tc.want {
				t.Fatalf("forwarded locale = %q, want %q", fwd, tc.want)
			}
			if got.Locale != tc.want {
				t.Fatalf("mapped locale = %q, want %q", got.Locale, tc.want)
			}
		})
	}
}

// TestUpdateMyProfileResolver_EmptyLocaleClears pins the documented clear:
// identity's unset sentinel is "", so a present-but-blank locale is forwarded
// as "" (reset to the client default) rather than rejected as invalid.
func TestUpdateMyProfileResolver_EmptyLocaleClears(t *testing.T) {
	for _, in := range []string{"", "   "} {
		ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
		admin := &fakeAdminClient{
			updateMyProfileResp: &identityv1.UpdateMyProfileResponse{
				User: &identityv1.User{Id: "user-1", Locale: ""},
			},
		}
		if _, err := resolvers.UpdateMyProfileResolver(ctx, admin, nil, nil, &in); err != nil {
			t.Fatalf("UpdateMyProfileResolver(%q): %v", in, err)
		}
		if admin.lastUpdateMyProfile.Locale == nil {
			t.Fatalf("blank locale %q must forward a PRESENT empty string (the clear), not nil", in)
		}
		if fwd := admin.lastUpdateMyProfile.GetLocale(); fwd != "" {
			t.Fatalf("blank locale %q forwarded %q, want %q", in, fwd, "")
		}
	}
}

// TestUpdateMyProfileResolver_InvalidLocaleRejectedAndNotForwarded is the
// security-relevant half of: identity stores locale verbatim with no
// shape check, so the gateway must refuse a malformed tag with the coded
// business error PROFILE_LOCALE_INVALID (1241) and make NO RPC at all — the
// names sent alongside an invalid locale must not be written either.
func TestUpdateMyProfileResolver_InvalidLocaleRejectedAndNotForwarded(t *testing.T) {
	invalid := []string{
		"e",                       // too short
		"english",                 // 7 letters; not a language subtag
		"en_US",                   // underscore, not a hyphen
		"en-USA",                  // 3-letter region
		"en-U",                    // 1-letter region
		"en-Latn-US-u-co-phonebk", // extension subtag: outside the accepted subset
		"en-x-private",            // private-use subtag
		"en-US-",                  // trailing separator
		"-en",                     // leading separator
		"en US",                   // embedded space
		"en-US; DROP TABLE users", // arbitrary payload
		"<script>alert(1)</script>",
		"../../etc/passwd",
		"en\nen-US", // newline / header-injection shaped
	}
	for _, in := range invalid {
		t.Run(in, func(t *testing.T) {
			ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
			admin := &fakeAdminClient{
				updateMyProfileResp: &identityv1.UpdateMyProfileResponse{
					User: &identityv1.User{Id: "user-1"},
				},
			}
			first := "Alice"
			_, err := resolvers.UpdateMyProfileResolver(ctx, admin, &first, nil, &in)
			info := infoOf(t, err)
			want := gatewayEntry(errcodes.CodeProfileLocaleInvalid)
			if info.Code != want.Code || info.Symbol != want.Symbol {
				t.Fatalf("coded error = {%d %q}, want {%d %q}", info.Code, info.Symbol, want.Code, want.Symbol)
			}
			if got := wireStatus(err).Code(); got != apperrgrpc.Code(want.Category) {
				t.Fatalf("grpc code = %v, want %v", got, apperrgrpc.Code(want.Category))
			}
			// A bad INPUT is a business outcome (inline, no retry), never a
			// reach fault (retryable banner).
			if k := errcodes.KindOf(want.Category); k != errcodes.KindBusiness {
				t.Fatalf("kind = %q, want %q", k, errcodes.KindBusiness)
			}
			// Nothing forwarded: identity is never asked to store the bad tag,
			// and the firstName sent with it is not written either.
			if admin.lastUpdateMyProfile != nil {
				t.Fatalf("invalid locale %q must NOT reach identity, got %+v", in, admin.lastUpdateMyProfile)
			}
		})
	}
}
