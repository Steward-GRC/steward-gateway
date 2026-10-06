// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package passwordreset_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/passwordreset"
)

// fakeIdentity implements only the OTP RPCs exercised here; the embedded
// interface satisfies the rest with nil-method panics we never hit.
type fakeIdentity struct {
	identityv1.IdentityReadServiceClient

	authCfg2FA   bool
	authCfgSSO   bool
	authCfgErr   error
	requestErr   error
	confirmErr   error
	loginReqErr  error
	verifyResult bool
	verifyErr    error

	gotReset   *identityv1.RequestPasswordResetRequest
	gotConfirm *identityv1.ResetPasswordWithCodeRequest
	gotLoginRq *identityv1.RequestLoginOtpRequest
	gotVerify  *identityv1.VerifyLoginOtpRequest
}

func (f *fakeIdentity) GetAuthConfig(_ context.Context, _ *identityv1.GetAuthConfigRequest, _ ...grpc.CallOption) (*identityv1.GetAuthConfigResponse, error) {
	if f.authCfgErr != nil {
		return nil, f.authCfgErr
	}
	return &identityv1.GetAuthConfigResponse{Login_2FaEnabled: f.authCfg2FA, SsoAvailable: f.authCfgSSO}, nil
}

func (f *fakeIdentity) RequestPasswordReset(_ context.Context, req *identityv1.RequestPasswordResetRequest, _ ...grpc.CallOption) (*identityv1.RequestPasswordResetResponse, error) {
	f.gotReset = req
	if f.requestErr != nil {
		return nil, f.requestErr
	}
	return &identityv1.RequestPasswordResetResponse{}, nil
}

func (f *fakeIdentity) ResetPasswordWithCode(_ context.Context, req *identityv1.ResetPasswordWithCodeRequest, _ ...grpc.CallOption) (*identityv1.ResetPasswordWithCodeResponse, error) {
	f.gotConfirm = req
	if f.confirmErr != nil {
		return nil, f.confirmErr
	}
	return &identityv1.ResetPasswordWithCodeResponse{}, nil
}

func (f *fakeIdentity) RequestLoginOtp(_ context.Context, req *identityv1.RequestLoginOtpRequest, _ ...grpc.CallOption) (*identityv1.RequestLoginOtpResponse, error) {
	f.gotLoginRq = req
	if f.loginReqErr != nil {
		return nil, f.loginReqErr
	}
	return &identityv1.RequestLoginOtpResponse{}, nil
}

func (f *fakeIdentity) VerifyLoginOtp(_ context.Context, req *identityv1.VerifyLoginOtpRequest, _ ...grpc.CallOption) (*identityv1.VerifyLoginOtpResponse, error) {
	f.gotVerify = req
	if f.verifyErr != nil {
		return nil, f.verifyErr
	}
	return &identityv1.VerifyLoginOtpResponse{Verified: f.verifyResult}, nil
}

func post(t *testing.T, h http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewBuffer(b)))
	return rec
}

func TestConfigHandler_ReflectsFlag(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{authCfg2FA: true, authCfgSSO: false})
	rec := httptest.NewRecorder()
	h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Login2FAEnabled bool `json:"login2faEnabled"`
		SSOAvailable    bool `json:"ssoAvailable"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body.Login2FAEnabled)
	require.False(t, body.SSOAvailable)
}

func TestConfigHandler_ReflectsSSOAvailable(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{authCfgSSO: true})
	rec := httptest.NewRecorder()
	h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Login2FAEnabled bool `json:"login2faEnabled"`
		SSOAvailable    bool `json:"ssoAvailable"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.False(t, body.Login2FAEnabled)
	require.True(t, body.SSOAvailable)
}

func TestConfigHandler_IdentityDown_FailsSafeDisabled(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{authCfgErr: status.Error(codes.Unavailable, "down")})
	rec := httptest.NewRecorder()
	h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Login2FAEnabled bool `json:"login2faEnabled"`
		SSOAvailable    bool `json:"ssoAvailable"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.False(t, body.Login2FAEnabled)
	require.False(t, body.SSOAvailable, "identity down → SSO reported unavailable (fail safe)")
}

func TestConfigHandler_DefaultLoginMethod_DefaultsLocal(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{})
	rec := httptest.NewRecorder()
	h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		DefaultLoginMethod string `json:"defaultLoginMethod"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, "local", body.DefaultLoginMethod)
}

func TestConfigHandler_DefaultLoginMethod_SSO(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{authCfgSSO: true}, passwordreset.WithDefaultLoginMethod("sso"))
	rec := httptest.NewRecorder()
	h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		DefaultLoginMethod string `json:"defaultLoginMethod"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, "sso", body.DefaultLoginMethod)
}

func TestConfigHandler_DefaultLoginMethod_UnknownFallsBackLocal(t *testing.T) {
	for _, in := range []string{"", "  ", "garbage", "LOCAL", "Sso"} {
		h := passwordreset.New(&fakeIdentity{}, passwordreset.WithDefaultLoginMethod(in))
		rec := httptest.NewRecorder()
		h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
		var body struct {
			DefaultLoginMethod string `json:"defaultLoginMethod"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
		want := "local"
		if in == "Sso" {
			want = "sso"
		}
		require.Equalf(t, want, body.DefaultLoginMethod, "input %q", in)
	}
}

func TestConfigHandler_IdentityDown_StillReportsDefaultLoginMethod(t *testing.T) {
	h := passwordreset.New(
		&fakeIdentity{authCfgErr: status.Error(codes.Unavailable, "down")},
		passwordreset.WithDefaultLoginMethod("sso"),
	)
	rec := httptest.NewRecorder()
	h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		SSOAvailable       bool   `json:"ssoAvailable"`
		DefaultLoginMethod string `json:"defaultLoginMethod"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.False(t, body.SSOAvailable, "identity down → SSO unavailable (UI falls back to local)")
	require.Equal(t, "sso", body.DefaultLoginMethod)
}

// TestConfigHandler_PasskeyEnabled proves WithPasskeyLogin is reflected in the
// passkeyEnabled flag the UI gates the passkey button on. Default off; on when
// opted in.
func TestConfigHandler_PasskeyEnabled(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{})
	rec := httptest.NewRecorder()
	h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
	var off struct {
		PasskeyEnabled bool `json:"passkeyEnabled"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&off))
	require.False(t, off.PasskeyEnabled)

	h = passwordreset.New(&fakeIdentity{}, passwordreset.WithPasskeyLogin(true))
	rec = httptest.NewRecorder()
	h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
	var on struct {
		PasskeyEnabled bool `json:"passkeyEnabled"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&on))
	require.True(t, on.PasskeyEnabled)

	h = passwordreset.New(&fakeIdentity{authCfgErr: status.Error(codes.Unavailable, "down")}, passwordreset.WithPasskeyLogin(true))
	rec = httptest.NewRecorder()
	h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
	var down struct {
		PasskeyEnabled bool `json:"passkeyEnabled"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&down))
	require.True(t, down.PasskeyEnabled)
}

// TestConfigHandler_PasskeyViabilityGate proves the viability probe
// further gates passkeyEnabled: even with WithPasskeyLogin(true), a probe that
// reports passkey login is NOT completable hides the button — and the probe is
// never consulted (nor the button shown) when passkey login is not enabled.
func TestConfigHandler_PasskeyViabilityGate(t *testing.T) {
	readPasskey := func(h *passwordreset.Handlers) bool {
		rec := httptest.NewRecorder()
		h.ConfigHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
		var body struct {
			PasskeyEnabled bool `json:"passkeyEnabled"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
		return body.PasskeyEnabled
	}

	require.True(t, readPasskey(passwordreset.New(&fakeIdentity{},
		passwordreset.WithPasskeyLogin(true),
		passwordreset.WithPasskeyViabilityProbe(func(context.Context) bool { return true }))))

	require.False(t, readPasskey(passwordreset.New(&fakeIdentity{},
		passwordreset.WithPasskeyLogin(true),
		passwordreset.WithPasskeyViabilityProbe(func(context.Context) bool { return false }))))

	probed := false
	require.False(t, readPasskey(passwordreset.New(&fakeIdentity{},
		passwordreset.WithPasskeyViabilityProbe(func(context.Context) bool { probed = true; return true }))))
	require.False(t, probed, "probe must not run when passkey login is not enabled")
}

func TestRequestReset_AlwaysOK_NoEnumeration(t *testing.T) {
	fake := &fakeIdentity{}
	h := passwordreset.New(fake)
	rec := post(t, h.RequestResetHandler(), "/auth/password-reset/request", map[string]string{"email": "heidi@example.net"})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "heidi@example.net", fake.gotReset.GetEmail())
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, true, body["ok"])
}

func TestRequestReset_MissingEmail_400(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{})
	rec := post(t, h.RequestResetHandler(), "/auth/password-reset/request", map[string]string{})
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestConfirmReset_BadCode_400(t *testing.T) {
	fake := &fakeIdentity{confirmErr: status.Error(codes.InvalidArgument, "invalid or expired code")}
	h := passwordreset.New(fake)
	rec := post(t, h.ConfirmResetHandler(), "/auth/password-reset/confirm",
		map[string]string{"email": "heidi@example.net", "code": "000000", "newPassword": "Newpass1!"})
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestConfirmReset_HappyPath(t *testing.T) {
	fake := &fakeIdentity{}
	h := passwordreset.New(fake)
	rec := post(t, h.ConfirmResetHandler(), "/auth/password-reset/confirm",
		map[string]string{"email": "heidi@example.net", "code": "123456", "newPassword": "Newpass1!"})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "123456", fake.gotConfirm.GetCode())
	require.Equal(t, "Newpass1!", fake.gotConfirm.GetNewPassword())
}

func TestConfirmReset_MissingFields_400(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{})
	rec := post(t, h.ConfirmResetHandler(), "/auth/password-reset/confirm",
		map[string]string{"email": "heidi@example.net"})
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRequestLoginOtp_AlwaysOK(t *testing.T) {
	fake := &fakeIdentity{}
	h := passwordreset.New(fake)
	rec := post(t, h.RequestLoginOtpHandler(), "/auth/login-otp/request",
		map[string]string{"username": "alice", "email": "carol@example.net"})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "alice", fake.gotLoginRq.GetUsername())
	require.Empty(t, fake.gotLoginRq.GetEmail())
}

func TestRequestLoginOtp_MissingUsername_400(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{})
	rec := post(t, h.RequestLoginOtpHandler(), "/auth/login-otp/request",
		map[string]string{"email": "heidi@example.net"})
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestVerifyLoginOtp_WrongCodeIs200False(t *testing.T) {
	fake := &fakeIdentity{verifyResult: false}
	h := passwordreset.New(fake)
	rec := post(t, h.VerifyLoginOtpHandler(), "/auth/login-otp/verify",
		map[string]string{"username": "alice", "code": "000000"})
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Verified bool `json:"verified"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.False(t, body.Verified)
}

func TestVerifyLoginOtp_GoodCodeIs200True(t *testing.T) {
	fake := &fakeIdentity{verifyResult: true}
	h := passwordreset.New(fake)
	rec := post(t, h.VerifyLoginOtpHandler(), "/auth/login-otp/verify",
		map[string]string{"username": "alice", "code": "123456"})
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Verified bool `json:"verified"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body.Verified)
	require.Equal(t, "123456", fake.gotVerify.GetCode())
	require.Equal(t, "alice", fake.gotVerify.GetUsername())
	require.Empty(t, fake.gotVerify.GetEmail())
}

func TestVerifyLoginOtp_MissingCode_400(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{})
	rec := post(t, h.VerifyLoginOtpHandler(), "/auth/login-otp/verify", map[string]string{"username": "alice"})
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestInvalidJSON_400(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{})
	rec := httptest.NewRecorder()
	h.RequestResetHandler()(rec, httptest.NewRequest(http.MethodPost, "/auth/password-reset/request", strings.NewReader("nope")))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// decodeErrBody reads the {"error", "kind"} shape every non-2xx from these
// endpoints answers with.
func decodeErrBody(t *testing.T, rec *httptest.ResponseRecorder) (message, kind string) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
		Kind  string `json:"kind"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	return body.Error, body.Kind
}

// A wrong or expired code is the user's input: kind business, with copy that
// names the action that helps.
func TestConfirmReset_InvalidCode_IsBusinessWithActionableCopy(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{confirmErr: status.Error(codes.InvalidArgument, "invalid code")})

	res := post(t, h.ConfirmResetHandler(), "/auth/password-reset/confirm",
		map[string]string{"email": "erin@example.org", "code": "000000", "newPassword": "N3wpass!word"})
	require.Equal(t, http.StatusBadRequest, res.Code)

	message, kind := decodeErrBody(t, res)
	require.Equal(t, "business", kind, "a wrong/expired code is the user's input, not our failure")
	require.Contains(t, message, "invalid or has expired")
	require.Contains(t, message, "Request a new code", "the copy must name the action that resolves it")
}

// An account without a local password answers like a bad code, so the
// reset can't be used to probe accounts.
func TestConfirmReset_NoLocalPassword_IsBusiness(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{confirmErr: status.Error(codes.FailedPrecondition, "the account has no local password")})

	res := post(t, h.ConfirmResetHandler(), "/auth/password-reset/confirm",
		map[string]string{"email": "erin@example.org", "code": "483920", "newPassword": "N3wpass!word"})
	require.Equal(t, http.StatusBadRequest, res.Code)

	message, kind := decodeErrBody(t, res)
	require.Equal(t, "business", kind)
	require.Contains(t, message, "invalid or has expired", "must be indistinguishable from a bad code")
}

// Identity unreachable is our failure: kind reach, generic copy, no
// transport detail.
func TestConfirmReset_IdentityUnreachable_IsReachAndRetryable(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{confirmErr: errors.New("dial tcp: connect: connection refused")})

	res := post(t, h.ConfirmResetHandler(), "/auth/password-reset/confirm",
		map[string]string{"email": "erin@example.org", "code": "483920", "newPassword": "N3wpass!word"})
	require.Equal(t, http.StatusBadGateway, res.Code)

	message, kind := decodeErrBody(t, res)
	require.Equal(t, "reach", kind, "an unreachable dependency is our failure, and retrying may well work")
	require.Contains(t, message, "on our end")
	require.NotContains(t, message, "dial tcp", "the transport detail must never reach the client")
	require.NotContains(t, message, "connection refused")
	require.NotContains(t, message, "kratos", "no backend name in user-facing copy")
}

// An Unavailable from the identity RPC maps to 503 + kind "reach", with copy that
// says we could not reach the sign-in service.
func TestConfirmReset_IdentityUnavailable_IsReach(t *testing.T) {
	fake := &fakeIdentity{confirmErr: status.Error(codes.Unavailable, "identity: no healthy upstream")}
	h := passwordreset.New(fake)

	res := post(t, h.ConfirmResetHandler(), "/auth/password-reset/confirm",
		map[string]string{"email": "heidi@example.net", "code": "123456", "newPassword": "Newpass1!"})
	require.Equal(t, http.StatusServiceUnavailable, res.Code)

	message, kind := decodeErrBody(t, res)
	require.Equal(t, "reach", kind)
	require.Contains(t, message, "couldn't reach the sign-in service")
	require.NotContains(t, message, "upstream", "the backend detail must not leak")
}

// TestConfirmReset_MissingFields_IsBusiness proves a validation 400 is a business
// outcome too — inline, no retry — with copy that tells the user what to fill in.
func TestConfirmReset_MissingFields_IsBusiness(t *testing.T) {
	h := passwordreset.New(&fakeIdentity{})
	res := post(t, h.ConfirmResetHandler(), "/auth/password-reset/confirm",
		map[string]string{"email": "heidi@example.net"})
	require.Equal(t, http.StatusBadRequest, res.Code)

	message, kind := decodeErrBody(t, res)
	require.Equal(t, "business", kind)
	require.Equal(t, "Code and new password are required.", message)
}
