// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package setup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/setup"
)

// fakeIdentity is a minimal fake for IdentityReadServiceClient. Only
// GetSetupState and BootstrapRoot are exercised by these tests; every other
// method satisfies the interface by returning an Unimplemented error.
type fakeIdentity struct {
	identityv1.IdentityReadServiceClient

	needsSetup    bool
	stateErr      error
	bootstrapUser *identityv1.User
	bootstrapErr  error

	gotBootstrap *identityv1.BootstrapRootRequest
}

func (f *fakeIdentity) GetSetupState(_ context.Context, _ *identityv1.GetSetupStateRequest, _ ...grpc.CallOption) (*identityv1.GetSetupStateResponse, error) {
	if f.stateErr != nil {
		return nil, f.stateErr
	}
	return &identityv1.GetSetupStateResponse{NeedsSetup: f.needsSetup}, nil
}

func (f *fakeIdentity) BootstrapRoot(_ context.Context, req *identityv1.BootstrapRootRequest, _ ...grpc.CallOption) (*identityv1.BootstrapRootResponse, error) {
	f.gotBootstrap = req
	if f.bootstrapErr != nil {
		return nil, f.bootstrapErr
	}
	return &identityv1.BootstrapRootResponse{User: f.bootstrapUser}, nil
}

// bootstrapBody encodes a JSON bootstrap request body.
func bootstrapBody(t *testing.T, token, username, email, password string) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"setupToken": token,
		"username":   username,
		"email":      email,
		"password":   password,
	})
	require.NoError(t, err)
	return bytes.NewBuffer(b)
}

func TestStateHandler_NeedsSetupTrue(t *testing.T) {
	h := setup.New(&fakeIdentity{needsSetup: true}, "tok")
	rec := httptest.NewRecorder()
	h.StateHandler()(rec, httptest.NewRequest(http.MethodGet, "/setup/state", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var body struct {
		NeedsSetup bool `json:"needsSetup"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body.NeedsSetup)
}

func TestStateHandler_NeedsSetupFalse(t *testing.T) {
	h := setup.New(&fakeIdentity{needsSetup: false}, "tok")
	rec := httptest.NewRecorder()
	h.StateHandler()(rec, httptest.NewRequest(http.MethodGet, "/setup/state", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		NeedsSetup bool `json:"needsSetup"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.False(t, body.NeedsSetup)
}

func TestStateHandler_IdentityError_Returns500(t *testing.T) {
	h := setup.New(&fakeIdentity{stateErr: status.Error(codes.Internal, "rpc down")}, "tok")
	rec := httptest.NewRecorder()
	h.StateHandler()(rec, httptest.NewRequest(http.MethodGet, "/setup/state", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestBootstrapHandler_NoToken_Returns503(t *testing.T) {
	h := setup.New(&fakeIdentity{}, "")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap",
		bootstrapBody(t, "anything", "admin", "dave@example.org", "hunter2"))
	h.BootstrapHandler()(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestBootstrapHandler_WrongToken_Returns403(t *testing.T) {
	h := setup.New(&fakeIdentity{}, "correct-token")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap",
		bootstrapBody(t, "wrong-token", "admin", "dave@example.org", "hunter2"))
	h.BootstrapHandler()(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestBootstrapHandler_IdentityFailedPrecondition_Returns409(t *testing.T) {
	fake := &fakeIdentity{
		bootstrapErr: status.Error(codes.FailedPrecondition, "root already exists"),
	}
	h := setup.New(fake, "tok")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap",
		bootstrapBody(t, "tok", "admin", "dave@example.org", "hunter2"))
	h.BootstrapHandler()(rec, req)
	require.Equal(t, http.StatusConflict, rec.Code)
}

func TestBootstrapHandler_IdentityInvalidArgument_Returns400(t *testing.T) {
	fake := &fakeIdentity{
		bootstrapErr: status.Error(codes.InvalidArgument, "username required"),
	}
	h := setup.New(fake, "tok")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap",
		bootstrapBody(t, "tok", "", "dave@example.org", "hunter2"))
	h.BootstrapHandler()(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBootstrapHandler_IdentityUnavailable_Returns503(t *testing.T) {
	fake := &fakeIdentity{
		bootstrapErr: status.Error(codes.Unavailable, "lldap not configured"),
	}
	h := setup.New(fake, "tok")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap",
		bootstrapBody(t, "tok", "admin", "dave@example.org", "hunter2"))
	h.BootstrapHandler()(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestBootstrapHandler_IdentityOtherError_Returns502(t *testing.T) {
	fake := &fakeIdentity{
		bootstrapErr: status.Error(codes.Internal, "unexpected failure"),
	}
	h := setup.New(fake, "tok")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap",
		bootstrapBody(t, "tok", "admin", "dave@example.org", "hunter2"))
	h.BootstrapHandler()(rec, req)
	require.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestBootstrapHandler_HappyPath_Returns200WithUserId(t *testing.T) {
	fake := &fakeIdentity{
		bootstrapUser: &identityv1.User{Id: "00000000-0000-0000-0000-000000000001"},
	}
	h := setup.New(fake, "tok")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap",
		bootstrapBody(t, "tok", "admin", "dave@example.org", "Passw0rd!"))
	h.BootstrapHandler()(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var body struct {
		UserID string `json:"userId"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, "00000000-0000-0000-0000-000000000001", body.UserID)
}

// TestBootstrapHandler_ForwardsName is the regression guard for Fix 1: the
// Display name in the POST body must survive the JSON decode and be forwarded
// verbatim in the BootstrapRootRequest (not dropped, leaving identity to fall
// back to the username).
func TestBootstrapHandler_ForwardsName(t *testing.T) {
	fake := &fakeIdentity{
		bootstrapUser: &identityv1.User{Id: "00000000-0000-0000-0000-000000000001"},
	}
	h := setup.New(fake, "tok")
	rec := httptest.NewRecorder()
	b, err := json.Marshal(map[string]string{
		"setupToken": "tok",
		"username":   "alice",
		"email":      "dave@example.org",
		"password":   "Passw0rd!",
		"name":       "Alice Anderson",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap", bytes.NewBuffer(b))
	h.BootstrapHandler()(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, fake.gotBootstrap)
	require.Equal(t, "Alice Anderson", fake.gotBootstrap.GetName())
	require.Equal(t, "alice", fake.gotBootstrap.GetUsername())
}

func TestBootstrapHandler_InvalidJSON_Returns400(t *testing.T) {
	h := setup.New(&fakeIdentity{}, "tok")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap",
		strings.NewReader("not-json"))
	h.BootstrapHandler()(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// fakeSSOAdmin is a minimal fake for IdentitySSOAdminServiceClient. Only the two
// RPCs the first-run setup path uses are exercised; the embedded interface satisfies
// the rest. It captures the outbound context so tests can assert that the
// freshly-created root principal (site-admin) was forwarded — proving the setup
// path reuses identity's admin onboarding under the correct authorization.
type fakeSSOAdmin struct {
	identityv1.IdentitySSOAdminServiceClient

	addResp *identityv1.AddOrganizationResponse
	addErr  error
	gotAdd  *identityv1.AddOrganizationRequest
	addCtx  context.Context

	verifyResp *identityv1.StartDomainVerificationResponse
	verifyErr  error
	gotVerify  *identityv1.StartDomainVerificationRequest
}

func (f *fakeSSOAdmin) AddOrganization(ctx context.Context, req *identityv1.AddOrganizationRequest, _ ...grpc.CallOption) (*identityv1.AddOrganizationResponse, error) {
	f.gotAdd = req
	f.addCtx = ctx
	if f.addErr != nil {
		return nil, f.addErr
	}
	return f.addResp, nil
}

func (f *fakeSSOAdmin) StartDomainVerification(_ context.Context, req *identityv1.StartDomainVerificationRequest, _ ...grpc.CallOption) (*identityv1.StartDomainVerificationResponse, error) {
	f.gotVerify = req
	if f.verifyErr != nil {
		return nil, f.verifyErr
	}
	return f.verifyResp, nil
}

// bootstrapWithSSOBody encodes a bootstrap request carrying an optional sso block.
func bootstrapWithSSOBody(t *testing.T, token string, sso map[string]any) *bytes.Buffer {
	t.Helper()
	payload := map[string]any{
		"setupToken": token,
		"username":   "admin",
		"email":      "dave@example.org",
		"password":   "Passw0rd!",
		"name":       "Root Admin",
	}
	if sso != nil {
		payload["sso"] = sso
	}
	b, err := json.Marshal(payload)
	require.NoError(t, err)
	return bytes.NewBuffer(b)
}

const testRootID = "00000000-0000-0000-0000-000000000001"

func TestBootstrapHandler_NoSSO_Unchanged(t *testing.T) {
	fake := &fakeIdentity{bootstrapUser: &identityv1.User{Id: testRootID}}
	sso := &fakeSSOAdmin{}
	h := setup.New(fake, "tok").WithSSOAdmin(sso)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap", bootstrapWithSSOBody(t, "tok", nil))
	h.BootstrapHandler()(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, testRootID, body["userId"])
	_, hasSSO := body["sso"]
	require.False(t, hasSSO, "no sso block requested => no sso key in response")
	require.Nil(t, sso.gotAdd, "SSO admin must not be called without an sso block")
}

func TestBootstrapHandler_SSO_HappyPath(t *testing.T) {
	fake := &fakeIdentity{bootstrapUser: &identityv1.User{Id: testRootID}}
	sso := &fakeSSOAdmin{
		addResp: &identityv1.AddOrganizationResponse{Organization: &identityv1.Organization{
			Domain: "example.org", OrgName: "Example Organisation", Protocol: "saml", Verified: false, Enabled: false,
		}},
		verifyResp: &identityv1.StartDomainVerificationResponse{
			Token:          "verif-tok",
			DnsRecordName:  "_steward-verify.example.net",
			DnsRecordValue: "steward-verify=verif-tok",
			Instructions:   "Add a DNS TXT record…",
		},
	}
	h := setup.New(fake, "tok").WithSSOAdmin(sso)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap", bootstrapWithSSOBody(t, "tok", map[string]any{
		"orgName":     "Example Organisation",
		"domain":      "example.org",
		"protocol":    "saml",
		"displayName": "Example Organisation SSO",
		"config":      map[string]string{"entityId": "https://idp.example.net"},
	}))
	h.BootstrapHandler()(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		UserID string `json:"userId"`
		SSO    struct {
			Organization       map[string]any `json:"organization"`
			DomainVerification struct {
				DNSRecordName  string `json:"dnsRecordName"`
				DNSRecordValue string `json:"dnsRecordValue"`
			} `json:"domainVerification"`
			ActivationDeferred bool   `json:"activationDeferred"`
			Error              string `json:"error"`
		} `json:"sso"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, testRootID, body.UserID)
	require.Empty(t, body.SSO.Error)
	require.True(t, body.SSO.ActivationDeferred)
	require.Equal(t, "example.org", body.SSO.Organization["domain"])
	require.Equal(t, "_steward-verify.example.net", body.SSO.DomainVerification.DNSRecordName)
	require.Equal(t, "steward-verify=verif-tok", body.SSO.DomainVerification.DNSRecordValue)

	require.NotNil(t, sso.gotAdd)
	require.Equal(t, "Example Organisation", sso.gotAdd.GetOrgName())
	require.Equal(t, "example.org", sso.gotAdd.GetDomain())
	require.Equal(t, "saml", sso.gotAdd.GetProtocol())
	require.Equal(t, "https://idp.example.net", sso.gotAdd.GetConfig()["entityId"])
	require.NotNil(t, sso.gotVerify)
	require.Equal(t, "example.org", sso.gotVerify.GetDomain())

	claims, ok := principal.FromContext(sso.addCtx)
	require.True(t, ok, "outbound SSO context must carry substituted claims")
	require.Equal(t, testRootID, claims.UserID())
	require.True(t, principal.HasRole(claims, "site-admin"))
}

func TestBootstrapHandler_SSO_AddOrgError_SetupStillSucceeds(t *testing.T) {
	fake := &fakeIdentity{bootstrapUser: &identityv1.User{Id: testRootID}}
	sso := &fakeSSOAdmin{addErr: status.Error(codes.InvalidArgument, "bad metadata")}
	h := setup.New(fake, "tok").WithSSOAdmin(sso)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap", bootstrapWithSSOBody(t, "tok", map[string]any{
		"orgName": "Example Organisation", "domain": "example.org", "protocol": "saml",
	}))
	h.BootstrapHandler()(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		UserID string `json:"userId"`
		SSO    struct {
			Error              string         `json:"error"`
			DomainVerification map[string]any `json:"domainVerification"`
		} `json:"sso"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, testRootID, body.UserID)
	require.NotEmpty(t, body.SSO.Error)
	require.Nil(t, body.SSO.DomainVerification)
	require.Nil(t, sso.gotVerify, "domain verification must not start when AddOrganization failed")
}

func TestBootstrapHandler_SSO_NoClientWired_ReportsError(t *testing.T) {
	fake := &fakeIdentity{bootstrapUser: &identityv1.User{Id: testRootID}}
	h := setup.New(fake, "tok") // no WithSSOAdmin
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap", bootstrapWithSSOBody(t, "tok", map[string]any{
		"orgName": "Example Organisation", "domain": "example.org", "protocol": "saml",
	}))
	h.BootstrapHandler()(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		UserID string `json:"userId"`
		SSO    struct {
			Error string `json:"error"`
		} `json:"sso"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, testRootID, body.UserID)
	require.NotEmpty(t, body.SSO.Error)
}

func TestBootstrapHandler_SSO_VerifyError_KeepsOrganization(t *testing.T) {
	fake := &fakeIdentity{bootstrapUser: &identityv1.User{Id: testRootID}}
	sso := &fakeSSOAdmin{
		addResp: &identityv1.AddOrganizationResponse{Organization: &identityv1.Organization{
			Domain: "example.org", OrgName: "Example Organisation", Protocol: "saml",
		}},
		verifyErr: status.Error(codes.Unavailable, "dns backend down"),
	}
	h := setup.New(fake, "tok").WithSSOAdmin(sso)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup/bootstrap", bootstrapWithSSOBody(t, "tok", map[string]any{
		"orgName": "Example Organisation", "domain": "example.org", "protocol": "saml",
	}))
	h.BootstrapHandler()(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		SSO struct {
			Organization       map[string]any `json:"organization"`
			Error              string         `json:"error"`
			DomainVerification map[string]any `json:"domainVerification"`
		} `json:"sso"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.NotEmpty(t, body.SSO.Error)
	require.Equal(t, "example.org", body.SSO.Organization["domain"])
	require.Nil(t, body.SSO.DomainVerification)
}
