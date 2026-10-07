// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"encoding/json"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// anonCtx is an unauthenticated request context (no forwarded claims), so the
// requireSiteAdmin gate must reject with Unauthenticated.
func anonCtx() context.Context { return context.Background() }

// siteAdminCtx builds a request context carrying site-admin claims, mirroring
// the setup used by the other site-admin-gated resolver tests (ctxWithRoles).
func siteAdminCtx(t *testing.T) context.Context {
	t.Helper()
	return ctxWithRoles(t, "admin-1", []string{"site-admin"})
}

// fakeSSOAdmin is an in-memory IdentitySSOAdminServiceClient for resolver unit
// tests: it records the last request it received and returns canned responses.
type fakeSSOAdmin struct {
	lastActor string
	identityv1.IdentitySSOAdminServiceClient
	orgs []*identityv1.Organization

	lastAddOrg *identityv1.AddOrganizationRequest
	addOrgResp *identityv1.Organization

	lastDeleteOrg *identityv1.DeleteOrganizationRequest
	deleteErr     error // when set, DeleteOrganization returns it (e.g. disable-first)

	lastUpdateIdP *identityv1.UpdateIdPConnectionRequest

	lastStartDV *identityv1.StartDomainVerificationRequest

	lastChangeProto *identityv1.ChangeOrgProtocolRequest
	changeProtoResp *identityv1.Organization
}

func (f *fakeSSOAdmin) AddOrganization(ctx context.Context, in *identityv1.AddOrganizationRequest, _ ...grpc.CallOption) (*identityv1.AddOrganizationResponse, error) {
	if a, ok := grpcactor.FromContext(ctx); ok {
		f.lastActor = a.Subject
	}
	f.lastAddOrg = in
	org := f.addOrgResp
	if org == nil {
		org = &identityv1.Organization{Domain: in.GetDomain(), OrgName: in.GetOrgName(), Protocol: in.GetProtocol()}
	}
	return &identityv1.AddOrganizationResponse{Organization: org}, nil
}

func (f *fakeSSOAdmin) ListOrganizations(_ context.Context, _ *identityv1.ListOrganizationsRequest, _ ...grpc.CallOption) (*identityv1.ListOrganizationsResponse, error) {
	return &identityv1.ListOrganizationsResponse{Organizations: f.orgs}, nil
}

func (f *fakeSSOAdmin) GetOrganization(_ context.Context, in *identityv1.GetOrganizationRequest, _ ...grpc.CallOption) (*identityv1.GetOrganizationResponse, error) {
	return &identityv1.GetOrganizationResponse{Organization: &identityv1.Organization{Domain: in.GetDomain()}}, nil
}

func (f *fakeSSOAdmin) UpdateIdPConnection(ctx context.Context, in *identityv1.UpdateIdPConnectionRequest, _ ...grpc.CallOption) (*identityv1.UpdateIdPConnectionResponse, error) {
	if a, ok := grpcactor.FromContext(ctx); ok {
		f.lastActor = a.Subject
	}
	f.lastUpdateIdP = in
	// Echo the requested toggles back so the resolver's proto->GraphQL mapping
	// is exercised (unset toggles default to false on the echoed org).
	return &identityv1.UpdateIdPConnectionResponse{Organization: &identityv1.Organization{
		Domain:     in.GetDomain(),
		JitEnabled: in.GetJitEnabled(),
		AllowLocal: in.GetAllowLocal(),
	}}, nil
}

func (f *fakeSSOAdmin) DeleteOrganization(ctx context.Context, in *identityv1.DeleteOrganizationRequest, _ ...grpc.CallOption) (*identityv1.DeleteOrganizationResponse, error) {
	if a, ok := grpcactor.FromContext(ctx); ok {
		f.lastActor = a.Subject
	}
	f.lastDeleteOrg = in
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return &identityv1.DeleteOrganizationResponse{Domain: in.GetDomain()}, nil
}

func (f *fakeSSOAdmin) StartDomainVerification(_ context.Context, in *identityv1.StartDomainVerificationRequest, _ ...grpc.CallOption) (*identityv1.StartDomainVerificationResponse, error) {
	f.lastStartDV = in
	return &identityv1.StartDomainVerificationResponse{Token: "tok", DnsRecordName: "_pol.partner.example.net", Instructions: "add TXT"}, nil
}

func (f *fakeSSOAdmin) ChangeOrgProtocol(ctx context.Context, in *identityv1.ChangeOrgProtocolRequest, _ ...grpc.CallOption) (*identityv1.ChangeOrgProtocolResponse, error) {
	if a, ok := grpcactor.FromContext(ctx); ok {
		f.lastActor = a.Subject
	}
	f.lastChangeProto = in
	org := f.changeProtoResp
	if org == nil {
		// Mirror the identity handler: a protocol change returns the org reset to
		// the start (unverified, untested, disabled) with the new protocol.
		org = &identityv1.Organization{Domain: in.GetDomain(), Protocol: in.GetProtocol()}
	}
	return &identityv1.ChangeOrgProtocolResponse{Organization: org}, nil
}

func (f *fakeSSOAdmin) VerifyDomain(_ context.Context, _ *identityv1.VerifyDomainRequest, _ ...grpc.CallOption) (*identityv1.VerifyDomainResponse, error) {
	return &identityv1.VerifyDomainResponse{Verified: true}, nil
}

func (f *fakeSSOAdmin) RecordIdPTestResult(_ context.Context, _ *identityv1.RecordIdPTestResultRequest, _ ...grpc.CallOption) (*identityv1.RecordIdPTestResultResponse, error) {
	return &identityv1.RecordIdPTestResultResponse{}, nil
}

func (f *fakeSSOAdmin) ActivateOrganization(_ context.Context, in *identityv1.ActivateOrganizationRequest, _ ...grpc.CallOption) (*identityv1.ActivateOrganizationResponse, error) {
	return &identityv1.ActivateOrganizationResponse{Organization: &identityv1.Organization{Domain: in.GetDomain(), Enabled: true}}, nil
}

func (f *fakeSSOAdmin) DisableOrganization(_ context.Context, in *identityv1.DisableOrganizationRequest, _ ...grpc.CallOption) (*identityv1.DisableOrganizationResponse, error) {
	return &identityv1.DisableOrganizationResponse{Organization: &identityv1.Organization{Domain: in.GetDomain(), Enabled: false}}, nil
}

func (f *fakeSSOAdmin) AddGroupMapping(_ context.Context, in *identityv1.AddGroupMappingRequest, _ ...grpc.CallOption) (*identityv1.AddGroupMappingResponse, error) {
	return &identityv1.AddGroupMappingResponse{Mapping: &identityv1.GroupMapping{Id: "gm-1", ConnectionId: in.GetConnectionId(), IdpGroupClaimValue: in.GetIdpGroupClaimValue(), TargetGroupId: in.GetTargetGroupId()}}, nil
}

func (f *fakeSSOAdmin) ListGroupMappings(_ context.Context, in *identityv1.ListGroupMappingsRequest, _ ...grpc.CallOption) (*identityv1.ListGroupMappingsResponse, error) {
	return &identityv1.ListGroupMappingsResponse{Mappings: []*identityv1.GroupMapping{{Id: "gm-1", ConnectionId: in.GetConnectionId()}}}, nil
}

func (f *fakeSSOAdmin) DeleteGroupMapping(_ context.Context, in *identityv1.DeleteGroupMappingRequest, _ ...grpc.CallOption) (*identityv1.DeleteGroupMappingResponse, error) {
	return &identityv1.DeleteGroupMappingResponse{MappingId: in.GetMappingId()}, nil
}

func (f *fakeSSOAdmin) GetSPCertificate(_ context.Context, _ *identityv1.GetSPCertificateRequest, _ ...grpc.CallOption) (*identityv1.GetSPCertificateResponse, error) {
	return &identityv1.GetSPCertificateResponse{Certificate: &identityv1.SPCertificate{Serial: "01", CertPem: "PEM", Active: true}}, nil
}

func (f *fakeSSOAdmin) ListSPCertificates(_ context.Context, _ *identityv1.ListSPCertificatesRequest, _ ...grpc.CallOption) (*identityv1.ListSPCertificatesResponse, error) {
	return &identityv1.ListSPCertificatesResponse{Certificates: []*identityv1.SPCertificate{{Serial: "01", Active: true}}}, nil
}

func (f *fakeSSOAdmin) ForceRotateSPCertificate(_ context.Context, _ *identityv1.ForceRotateSPCertificateRequest, _ ...grpc.CallOption) (*identityv1.ForceRotateSPCertificateResponse, error) {
	return &identityv1.ForceRotateSPCertificateResponse{Certificate: &identityv1.SPCertificate{Serial: "02", Active: true}}, nil
}

func (f *fakeSSOAdmin) RecordBreakGlassLogin(_ context.Context, _ *identityv1.RecordBreakGlassLoginRequest, _ ...grpc.CallOption) (*identityv1.RecordBreakGlassLoginResponse, error) {
	return &identityv1.RecordBreakGlassLoginResponse{}, nil
}

// TestOrganizationsResolver_RequiresSiteAdmin verifies the organizations query
// enforces site-admin and maps the proto list to GraphQL Organizations.
func TestOrganizationsResolver_RequiresSiteAdmin(t *testing.T) {
	_, err := resolvers.OrganizationsResolver(anonCtx(), &fakeSSOAdmin{})
	require.Error(t, err) // Unauthenticated/PermissionDenied

	orgs, err := resolvers.OrganizationsResolver(siteAdminCtx(t), &fakeSSOAdmin{orgs: []*identityv1.Organization{{Domain: "partner.example.net", Enabled: true}}})
	require.NoError(t, err)
	require.Len(t, orgs, 1)
	require.Equal(t, "partner.example.net", orgs[0].Domain)
	require.True(t, orgs[0].Enabled)
}

func TestOrganizationsResolver_CarriesConnectionAlias(t *testing.T) {
	orgs, err := resolvers.OrganizationsResolver(siteAdminCtx(t), &fakeSSOAdmin{orgs: []*identityv1.Organization{{Domain: "partner.example.net", ConnectionAlias: "ds-saml"}}})
	require.NoError(t, err)
	require.Len(t, orgs, 1)
	require.Equal(t, "ds-saml", orgs[0].ConnectionAlias)
}

// TestAddOrganizationResolver maps the GraphQL input to the proto request
// (binding the actor from claims, never from input) and back to a model, and
// rejects a non-site-admin caller before reaching the gRPC client.
func TestAddOrganizationResolver(t *testing.T) {
	// Non-site-admin is rejected and never reaches the client.
	fake := &fakeSSOAdmin{}
	_, err := resolvers.AddOrganizationResolver(ctxWithRoles(t, "u-9", []string{"policy-author"}), fake, resolvers.AddOrganizationInput{Domain: "partner.example.net", OrgName: "DS", Protocol: "saml"})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Nil(t, fake.lastAddOrg, "must not call identity when unauthorized")

	// Site-admin: input maps to proto (config list -> map), actor bound from claims.
	display := "Partner Organisation"
	secret := "vault://sso/ds"
	org, err := resolvers.AddOrganizationResolver(siteAdminCtx(t), fake, resolvers.AddOrganizationInput{
		Domain:      "partner.example.net",
		OrgName:     "DS",
		Protocol:    "saml",
		DisplayName: &display,
		SecretRef:   &secret,
		Config:      []*resolvers.KeyValueInput{{Key: "entityId", Value: "urn:ds"}},
	})
	require.NoError(t, err)
	require.Equal(t, "partner.example.net", org.Domain)
	require.NotNil(t, fake.lastAddOrg)
	require.Equal(t, "partner.example.net", fake.lastAddOrg.GetDomain())
	require.Equal(t, "DS", fake.lastAddOrg.GetOrgName())
	require.Equal(t, "saml", fake.lastAddOrg.GetProtocol())
	require.Equal(t, "Partner Organisation", fake.lastAddOrg.GetDisplayName())
	require.Equal(t, "vault://sso/ds", fake.lastAddOrg.GetSecretRef())
	require.Equal(t, "urn:ds", fake.lastAddOrg.GetConfig()["entityId"])
	require.Equal(t, "admin-1", fake.lastActor, "actor must be bound from claims")
}

// TestSSOResolvers_AllRejectNonSiteAdmin confirms every SSO resolver refuses an
// unauthenticated caller (defense in depth: the gate is the first statement).
func TestSSOResolvers_AllRejectNonSiteAdmin(t *testing.T) {
	f := &fakeSSOAdmin{}
	ctx := anonCtx()

	checks := []func() error{
		func() error { _, e := resolvers.OrganizationsResolver(ctx, f); return e },
		func() error { _, e := resolvers.OrganizationResolver(ctx, f, "partner.example.net"); return e },
		func() error { _, e := resolvers.SpCertificateResolver(ctx, f); return e },
		func() error { _, e := resolvers.SpCertificatesResolver(ctx, f); return e },
		func() error { _, e := resolvers.GroupMappingsResolver(ctx, f, "conn-1"); return e },
		func() error {
			_, e := resolvers.AddOrganizationResolver(ctx, f, resolvers.AddOrganizationInput{})
			return e
		},
		func() error {
			_, e := resolvers.StartDomainVerificationResolver(ctx, f, "partner.example.net", nil)
			return e
		},
		func() error {
			_, e := resolvers.ChangeOrgProtocolResolver(ctx, f, "partner.example.net", "saml", nil, nil, nil)
			return e
		},
		func() error { _, e := resolvers.VerifyDomainResolver(ctx, f, "partner.example.net"); return e },
		func() error { _, e := resolvers.ActivateOrganizationResolver(ctx, f, "partner.example.net"); return e },
		func() error { _, e := resolvers.DisableOrganizationResolver(ctx, f, "partner.example.net"); return e },
		func() error { _, e := resolvers.DeleteOrganizationResolver(ctx, f, "partner.example.net"); return e },
		func() error { _, e := resolvers.AddGroupMappingResolver(ctx, f, "conn-1", "grp", "Target"); return e },
		func() error { _, e := resolvers.DeleteGroupMappingResolver(ctx, f, "gm-1"); return e },
		func() error { _, e := resolvers.ForceRotateSpCertificateResolver(ctx, f); return e },
	}
	for i, c := range checks {
		if err := c(); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("resolver #%d: want Unauthenticated for anon caller, got %v", i, err)
		}
	}
	require.Nil(t, f.lastAddOrg, "no resolver may reach the client for an anon caller")
}

// TestDeleteOrganizationResolver covers the destructive org-delete surface:
//   - a non-site-admin is refused before the client is ever called;
//   - a site-admin deletes, binding the actor from claims (never input) and
//     forwarding the domain, and the resolver reports success as `true`;
//   - the identity "disable first" guard (FailedPrecondition) is propagated
//     unchanged so the gateway's error presenter can surface its clean,
//     client-facing message (and the "delete a live org" is refused);
//   - NotFound is propagated the same way for a domain with no connection.
//
// FailedPrecondition and NotFound are both in the gateway's clientFacingCodes
// set, so the presenter passes their messages through with a machine-readable
// extensions["code"] rather than genericizing to a 500 — that is what lets the
// admin UI show "disable the organization before deleting it".
func TestDeleteOrganizationResolver(t *testing.T) {
	// Non-site-admin is rejected and never reaches the client.
	fake := &fakeSSOAdmin{}
	ok, err := resolvers.DeleteOrganizationResolver(ctxWithRoles(t, "u-9", []string{"policy-author"}), fake, "partner.example.net")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.False(t, ok)
	require.Nil(t, fake.lastDeleteOrg, "must not call identity when unauthorized")

	// Site-admin happy path: domain forwarded, actor bound from claims, true.
	fake = &fakeSSOAdmin{}
	ok, err = resolvers.DeleteOrganizationResolver(siteAdminCtx(t), fake, "partner.example.net")
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, fake.lastDeleteOrg)
	require.Equal(t, "partner.example.net", fake.lastDeleteOrg.GetDomain())
	require.Equal(t, "admin-1", fake.lastActor, "actor must be bound from claims")

	// Disable-first guard: identity returns FailedPrecondition, which the
	// resolver forwards unchanged (code + clean message preserved for the UI).
	fake = &fakeSSOAdmin{deleteErr: status.Error(codes.FailedPrecondition, "disable the organization before deleting it")}
	ok, err = resolvers.DeleteOrganizationResolver(siteAdminCtx(t), fake, "live.example.net")
	require.False(t, ok)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, "disable the organization before deleting it", status.Convert(err).Message())

	// NotFound: an unregistered domain propagates NotFound (not a 500).
	fake = &fakeSSOAdmin{deleteErr: status.Error(codes.NotFound, "domain has no sso connection registered")}
	ok, err = resolvers.DeleteOrganizationResolver(siteAdminCtx(t), fake, "unknown.example.net")
	require.False(t, ok)
	require.Equal(t, codes.NotFound, status.Code(err))
}

// TestUpdateIdPConnectionResolver covers the per-org login toggles (
// jitEnabled / allowLocal): a non-site-admin is rejected before the
// client is touched; a site-admin's toggles + domain + actor are forwarded, and
// only the supplied toggle is sent (nil leaves the other unset for the identity
// "leave unchanged" semantics).
func TestUpdateIdPConnectionResolver(t *testing.T) {
	// Non-site-admin is rejected and never reaches the client.
	fake := &fakeSSOAdmin{}
	jitOff := false
	_, err := resolvers.UpdateIdPConnectionResolver(ctxWithRoles(t, "u-9", []string{"policy-author"}), fake, "partner.example.net", &jitOff, nil, nil, nil)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Nil(t, fake.lastUpdateIdP, "must not call identity when unauthorized")

	// Site-admin: both toggles forwarded, actor bound, response mapped.
	fake = &fakeSSOAdmin{}
	jitOff, allowOn := false, true
	org, err := resolvers.UpdateIdPConnectionResolver(siteAdminCtx(t), fake, "partner.example.net", &jitOff, &allowOn, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, fake.lastUpdateIdP)
	require.Equal(t, "partner.example.net", fake.lastUpdateIdP.GetDomain())
	require.Equal(t, "admin-1", fake.lastActor, "actor must be bound from claims")
	require.NotNil(t, fake.lastUpdateIdP.JitEnabled)
	require.False(t, fake.lastUpdateIdP.GetJitEnabled())
	require.NotNil(t, fake.lastUpdateIdP.AllowLocal)
	require.True(t, fake.lastUpdateIdP.GetAllowLocal())
	require.False(t, org.JitEnabled)
	require.True(t, org.AllowLocal)

	// Only one toggle supplied: the other is forwarded as nil (unset).
	fake = &fakeSSOAdmin{}
	allowOff := false
	_, err = resolvers.UpdateIdPConnectionResolver(siteAdminCtx(t), fake, "partner.example.net", nil, &allowOff, nil, nil)
	require.NoError(t, err)
	require.Nil(t, fake.lastUpdateIdP.JitEnabled, "unset jitEnabled must forward as nil")
	require.NotNil(t, fake.lastUpdateIdP.AllowLocal)
}

// TestStartDomainVerificationResolver_Rotate verifies rotate is site-admin
// gated and that the optional rotate arg is forwarded to the identity RPC: nil
// or false stays stable (Rotate=false), true forwards Rotate=true.
func TestStartDomainVerificationResolver_Rotate(t *testing.T) {
	_, err := resolvers.StartDomainVerificationResolver(anonCtx(), &fakeSSOAdmin{}, "partner.example.net", nil)
	require.Error(t, err) // site-admin gate

	fake := &fakeSSOAdmin{}
	dv, err := resolvers.StartDomainVerificationResolver(siteAdminCtx(t), fake, "partner.example.net", nil)
	require.NoError(t, err)
	require.Equal(t, "tok", dv.Token)
	require.False(t, fake.lastStartDV.GetRotate(), "nil rotate must forward as stable (Rotate=false)")

	no := false
	_, err = resolvers.StartDomainVerificationResolver(siteAdminCtx(t), fake, "partner.example.net", &no)
	require.NoError(t, err)
	require.False(t, fake.lastStartDV.GetRotate())

	yes := true
	_, err = resolvers.StartDomainVerificationResolver(siteAdminCtx(t), fake, "partner.example.net", &yes)
	require.NoError(t, err)
	require.True(t, fake.lastStartDV.GetRotate(), "rotate:true must forward Rotate=true")
}

// TestChangeOrgProtocolResolver maps the GraphQL args to the proto request
// (actor bound from claims, config folded into the map), returns the reset org,
// and rejects a non-site-admin caller before reaching the gRPC client.
func TestChangeOrgProtocolResolver(t *testing.T) {
	_, err := resolvers.ChangeOrgProtocolResolver(anonCtx(), &fakeSSOAdmin{}, "partner.example.net", "saml", nil, nil, nil)
	require.Error(t, err) // site-admin gate

	fake := &fakeSSOAdmin{changeProtoResp: &identityv1.Organization{
		Domain: "partner.example.net", Protocol: "saml", Verified: false, TestPassed: false, Enabled: false,
	}}
	secret := "vault://ds/saml"
	org, err := resolvers.ChangeOrgProtocolResolver(siteAdminCtx(t), fake, "partner.example.net", "saml",
		[]*resolvers.KeyValueInput{{Key: "entityId", Value: "https://partner.example.net/saml"}}, &secret, nil)
	require.NoError(t, err)

	// The resolver returns the org reset to the start with the new protocol.
	require.Equal(t, "saml", org.Protocol)
	require.False(t, org.Verified)
	require.False(t, org.TestPassed)
	require.False(t, org.Enabled)

	// The request was mapped correctly: actor bound from claims, config folded.
	require.Equal(t, "partner.example.net", fake.lastChangeProto.GetDomain())
	require.Equal(t, "saml", fake.lastChangeProto.GetProtocol())
	require.Equal(t, "admin-1", fake.lastActor)
	require.Equal(t, "vault://ds/saml", fake.lastChangeProto.GetSecretRef())
	require.Equal(t, "https://partner.example.net/saml", fake.lastChangeProto.GetConfig()["entityId"])
}

// The OIDC client secret is write-only: every mutation that takes it passes it
// to identity unchanged, and no GraphQL field can carry it back.
func TestSSOResolvers_ClientSecretIsPassedThroughAndNeverReturned(t *testing.T) {
	const plain = "aaaa-bbbb-test-only" // #nosec G101 -- test value
	secret := plain
	fake := &fakeSSOAdmin{changeProtoResp: &identityv1.Organization{Domain: "partner.example.net", Protocol: "oidc"}}

	org, err := resolvers.AddOrganizationResolver(siteAdminCtx(t), fake, resolvers.AddOrganizationInput{
		Domain: "partner.example.net", OrgName: "DS", Protocol: "oidc", ClientSecret: &secret,
	})
	require.NoError(t, err)
	require.Equal(t, plain, fake.lastAddOrg.GetClientSecret())
	require.Empty(t, fake.lastAddOrg.GetSecretRef())
	requireNoSecretInJSON(t, org, plain)

	org, err = resolvers.ChangeOrgProtocolResolver(siteAdminCtx(t), fake, "partner.example.net", "oidc", nil, nil, &secret)
	require.NoError(t, err)
	require.Equal(t, plain, fake.lastChangeProto.GetClientSecret())
	requireNoSecretInJSON(t, org, plain)

	ref := "operator-key"
	_, err = resolvers.UpdateIdPConnectionResolver(siteAdminCtx(t), fake, "partner.example.net", nil, nil, &ref, nil)
	require.NoError(t, err)
	require.Equal(t, "operator-key", fake.lastUpdateIdP.GetSecretRef())
	require.Empty(t, fake.lastUpdateIdP.GetClientSecret())

	org, err = resolvers.UpdateIdPConnectionResolver(siteAdminCtx(t), fake, "partner.example.net", nil, nil, nil, &secret)
	require.NoError(t, err)
	require.Equal(t, plain, fake.lastUpdateIdP.GetClientSecret())
	requireNoSecretInJSON(t, org, plain)
}

func TestSSOResolvers_SecretReentryRequiredIsShown(t *testing.T) {
	fake := &fakeSSOAdmin{changeProtoResp: &identityv1.Organization{Domain: "partner.example.net", SecretReentryRequired: true}}
	org, err := resolvers.ChangeOrgProtocolResolver(siteAdminCtx(t), fake, "partner.example.net", "saml", nil, nil, nil)
	require.NoError(t, err)
	require.True(t, org.SecretReentryRequired)
}

func requireNoSecretInJSON(t *testing.T, v any, secret string) {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	require.NotContains(t, string(b), secret)
}
