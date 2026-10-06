// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeSettingsClient is an in-package stub of corev1.SettingsServiceClient.
// It captures the last request for each EmailService method so tests can assert the
// key + actor binding, and it deliberately implements ONLY the gateway-facing
// SettingsService — it has no method for the key-bearing EmailServiceSecretService,
// which the gateway must never reference.
type fakeSettingsClient struct {
	corev1.SettingsServiceClient
	setEmailServiceResp    *corev1.SetEmailServiceConfigResponse
	setEmailServiceErr     error
	lastSetEmailServiceReq *corev1.SetEmailServiceConfigRequest

	statusResp *corev1.EmailServiceConfigStatusResponse
	statusErr  error
	statusCall bool
}

func (f *fakeSettingsClient) GetGlobalSettings(_ context.Context, _ *corev1.GetGlobalSettingsRequest, _ ...grpc.CallOption) (*corev1.GetGlobalSettingsResponse, error) {
	return &corev1.GetGlobalSettingsResponse{}, nil
}

func (f *fakeSettingsClient) SetGlobalSettings(_ context.Context, _ *corev1.SetGlobalSettingsRequest, _ ...grpc.CallOption) (*corev1.SetGlobalSettingsResponse, error) {
	return &corev1.SetGlobalSettingsResponse{}, nil
}

func (f *fakeSettingsClient) SetEmailServiceConfig(_ context.Context, in *corev1.SetEmailServiceConfigRequest, _ ...grpc.CallOption) (*corev1.SetEmailServiceConfigResponse, error) {
	f.lastSetEmailServiceReq = in
	if f.setEmailServiceErr != nil {
		return nil, f.setEmailServiceErr
	}
	return f.setEmailServiceResp, nil
}

func (f *fakeSettingsClient) EmailServiceConfigStatus(_ context.Context, _ *corev1.EmailServiceConfigStatusRequest, _ ...grpc.CallOption) (*corev1.EmailServiceConfigStatusResponse, error) {
	f.statusCall = true
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return f.statusResp, nil
}

func adminCtx(t *testing.T) context.Context {
	return ctxWithStubClaims(t, principal.Static{UserIDValue: "admin-1", RolesValue: []string{"site-admin"}})
}

func nonAdminCtx(t *testing.T) context.Context {
	return ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"}) // reader-only, no settings.manage
}

// TestSetEmailServiceConfigResolver_siteAdminPersistsAndReturnsKeylessStatus proves
// the write path: a site-admin's input reaches core with the api key + the
// actor bound server-side, and the resolver returns the KEYLESS status (the
// api key is never echoed back — the response type carries no field for it).
func TestSetEmailServiceConfigResolver_siteAdminPersistsAndReturnsKeylessStatus(t *testing.T) {
	client := &fakeSettingsClient{
		setEmailServiceResp: &corev1.SetEmailServiceConfigResponse{
			Status: &corev1.EmailServiceStatus{
				ApiKeySet:   true,
				Domain:      "mail.example.org",
				Region:      "us",
				FromAddress: "no-reply@example.org",
				Enabled:     true,
			},
		},
	}
	input := resolvers.EmailServiceConfigInput{
		APIKey:      new("key-super-secret"),
		Domain:      "mail.example.org",
		Region:      "us",
		FromAddress: "no-reply@example.org",
		Enabled:     true,
	}

	out, err := resolvers.SetEmailServiceConfig(adminCtx(t), client, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The request reaching core carries the key + the non-secret fields, and
	// the actor is bound from claims (not trusted from GraphQL input).
	req := client.lastSetEmailServiceReq
	if req == nil {
		t.Fatal("expected core SetEmailServiceConfig to be called")
	}
	if req.ApiKey == nil || *req.ApiKey != "key-super-secret" {
		t.Fatalf("expected the api key forwarded to core, got %v", req.ApiKey)
	}
	if req.GetActorUserId() != "admin-1" {
		t.Fatalf("expected actor bound server-side from claims, got %q", req.GetActorUserId())
	}
	if req.GetDomain() != "mail.example.org" || req.GetRegion() != "us" ||
		req.GetFromAddress() != "no-reply@example.org" || !req.GetEnabled() {
		t.Fatalf("expected non-secret fields forwarded, got %+v", req)
	}

	// The returned status reflects presence WITHOUT the key.
	if !out.APIKeySet {
		t.Fatal("expected apiKeySet=true in the returned status")
	}
	if out.Domain != "mail.example.org" || out.Region != "us" ||
		out.FromAddress != "no-reply@example.org" || !out.Enabled {
		t.Fatalf("unexpected status mapping: %+v", out)
	}
}

// TestSetEmailServiceConfigResolver_forwardsThreeStateKey proves the presence-tracked
// apiKey forwards its three states to the core client unchanged: a nil (omitted/
// null) input leaves the proto api_key UNSET (nil) so core keeps the stored key;
// an empty string clears it; a value sets it. In every case the resolver returns
// the keyless status (no api-key field on EmailServiceConfigStatus).
func TestSetEmailServiceConfigResolver_forwardsThreeStateKey(t *testing.T) {
	cases := []struct {
		name     string
		inputKey *string
		wantNil  bool
		wantVal  string
	}{
		{name: "absent leaves key unchanged", inputKey: nil, wantNil: true},
		{name: "empty clears key", inputKey: new(""), wantNil: false, wantVal: ""},
		{name: "value sets key", inputKey: new("key-new"), wantNil: false, wantVal: "key-new"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeSettingsClient{
				setEmailServiceResp: &corev1.SetEmailServiceConfigResponse{
					Status: &corev1.EmailServiceStatus{
						ApiKeySet:   true,
						Domain:      "mail.example.org",
						Region:      "us",
						FromAddress: "no-reply@example.org",
						Enabled:     true,
					},
				},
			}
			input := resolvers.EmailServiceConfigInput{
				APIKey:      tc.inputKey,
				Domain:      "mail.example.org",
				Region:      "us",
				FromAddress: "no-reply@example.org",
				Enabled:     true,
			}

			out, err := resolvers.SetEmailServiceConfig(adminCtx(t), client, input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			req := client.lastSetEmailServiceReq
			if req == nil {
				t.Fatal("expected core SetEmailServiceConfig to be called")
			}
			if tc.wantNil {
				if req.ApiKey != nil {
					t.Fatalf("expected proto api_key UNSET (nil), got %q", *req.ApiKey)
				}
			} else {
				if req.ApiKey == nil {
					t.Fatal("expected proto api_key set, got nil")
				}
				if *req.ApiKey != tc.wantVal {
					t.Fatalf("forwarded api_key = %q, want %q", *req.ApiKey, tc.wantVal)
				}
			}

			// The non-secret fields and the server-bound actor always forward.
			if req.GetActorUserId() != "admin-1" {
				t.Fatalf("expected actor bound from claims, got %q", req.GetActorUserId())
			}
			if req.GetDomain() != "mail.example.org" || req.GetRegion() != "us" ||
				req.GetFromAddress() != "no-reply@example.org" || !req.GetEnabled() {
				t.Fatalf("expected non-secret fields forwarded, got %+v", req)
			}

			// The returned status is keyless.
			if out == nil || !out.APIKeySet {
				t.Fatalf("expected keyless status with presence, got %+v", out)
			}
			rt := reflect.TypeFor[resolvers.EmailServiceConfigStatus]()
			for field := range rt.Fields() {
				name := strings.ToLower(field.Name)
				if name == "apikeyset" {
					continue
				}
				if strings.Contains(name, "key") || strings.Contains(name, "secret") {
					t.Fatalf("status must not carry a key/secret field, found %q", field.Name)
				}
			}
		})
	}
}

// TestGetEmailServiceConfigResolver_siteAdminReturnsKeylessStatus proves the
// presence query maps the keyless EmailServiceStatus and never surfaces the key.
func TestGetEmailServiceConfigResolver_siteAdminReturnsKeylessStatus(t *testing.T) {
	client := &fakeSettingsClient{
		statusResp: &corev1.EmailServiceConfigStatusResponse{
			Status: &corev1.EmailServiceStatus{
				ApiKeySet:   true,
				Domain:      "mail.example.org",
				Region:      "eu",
				FromAddress: "no-reply@example.org",
				Enabled:     false,
			},
		},
	}

	out, err := resolvers.GetEmailServiceConfig(adminCtx(t), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !client.statusCall {
		t.Fatal("expected core EmailServiceConfigStatus to be called")
	}
	if !out.APIKeySet || out.Domain != "mail.example.org" || out.Region != "eu" ||
		out.FromAddress != "no-reply@example.org" || out.Enabled {
		t.Fatalf("unexpected status mapping: %+v", out)
	}
}

// TestGetEmailServiceConfigResolver_nilStatusCollapsesToKeyless verifies a nil
// sub-message maps to a safe zero-value status (no panic, presence=false).
func TestGetEmailServiceConfigResolver_nilStatusCollapsesToKeyless(t *testing.T) {
	client := &fakeSettingsClient{statusResp: &corev1.EmailServiceConfigStatusResponse{}}
	out, err := resolvers.GetEmailServiceConfig(adminCtx(t), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.APIKeySet {
		t.Fatal("expected apiKeySet=false for an empty status")
	}
}

// TestSetEmailServiceConfigResolver_requiresSiteAdmin verifies a non-site-admin is
// rejected with PermissionDenied and core is never called (no write attempt).
func TestSetEmailServiceConfigResolver_requiresSiteAdmin(t *testing.T) {
	client := &fakeSettingsClient{}
	_, err := resolvers.SetEmailServiceConfig(nonAdminCtx(t), client, resolvers.EmailServiceConfigInput{APIKey: new("key-x")})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.lastSetEmailServiceReq != nil {
		t.Fatal("expected core never called for an unauthorized caller")
	}
}

// TestGetEmailServiceConfigResolver_requiresSiteAdmin verifies the presence query is
// also site-admin gated.
func TestGetEmailServiceConfigResolver_requiresSiteAdmin(t *testing.T) {
	client := &fakeSettingsClient{}
	_, err := resolvers.GetEmailServiceConfig(nonAdminCtx(t), client)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.statusCall {
		t.Fatal("expected core never called for an unauthorized caller")
	}
}

// TestEmailServiceConfigStatusModelHasNoKeyField is a reflection assertion that the
// gateway-facing status model exposes only a presence flag (apiKeySet) and no
// field that could carry the api key itself.
func TestEmailServiceConfigStatusModelHasNoKeyField(t *testing.T) {
	rt := reflect.TypeFor[resolvers.EmailServiceConfigStatus]()
	for field := range rt.Fields() {
		name := strings.ToLower(field.Name)
		tag := strings.ToLower(field.Tag.Get("json"))
		// apiKeySet (presence flag) is allowed; a bare key/secret field is not.
		if name == "apikeyset" || tag == `apikeyset` {
			continue
		}
		if strings.Contains(name, "key") || strings.Contains(name, "secret") ||
			strings.Contains(tag, "key") || strings.Contains(tag, "secret") {
			t.Fatalf("EmailServiceConfigStatus must not carry a key/secret field, found %q", field.Name)
		}
	}
}

// TestEmailServiceConfigStatusSchemaHasNoKeyField asserts against the compiled
// GraphQL schema (the source of truth) that the EmailServiceConfigStatus type has
// apiKeySet but exposes NO field returning the api key — the secret cannot be
// read back through the GraphQL surface.
func TestEmailServiceConfigStatusSchemaHasNoKeyField(t *testing.T) {
	schema := resolvers.NewExecutableSchema(resolvers.Config{}).Schema()
	def := schema.Types["EmailServiceConfigStatus"]
	if def == nil {
		t.Fatal("EmailServiceConfigStatus type missing from schema")
	}
	var hasPresence bool
	for _, f := range def.Fields {
		if f.Name == "apiKeySet" {
			hasPresence = true
			continue
		}
		lower := strings.ToLower(f.Name)
		if strings.Contains(lower, "key") || strings.Contains(lower, "secret") {
			t.Fatalf("EmailServiceConfigStatus must not expose a key/secret field, found %q", f.Name)
		}
	}
	if !hasPresence {
		t.Fatal("expected EmailServiceConfigStatus to expose the apiKeySet presence flag")
	}
}
