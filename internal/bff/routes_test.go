// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestRegister_MountsEveryAuthRoute(t *testing.T) {
	mux := http.NewServeMux()
	h := &Handler{Store: newTestStore(t), Auth: okAuth(), Identity: &fakeMfaIdentity{}}
	h.Register(mux)

	for _, rt := range []string{
		"POST /auth/login", "POST /auth/logout", "GET /auth/session", "POST /auth/discover",
		"GET /auth/sso/start", "GET /auth/sso/callback", "POST /auth/sso/idp-initiated",
		"POST /auth/breakglass",
		"POST /auth/mfa/otp/send", "POST /auth/mfa/webauthn/begin", "POST /auth/mfa/verify",
		"POST /auth/mfa/enroll/totp/begin", "POST /auth/mfa/enroll/totp/confirm",
		"POST /auth/mfa/enroll/email/send", "POST /auth/mfa/enroll/email/verify",
		"POST /auth/mfa/enroll/webauthn/begin", "POST /auth/mfa/enroll/webauthn/finish",
		"POST /auth/passkey/login/begin", "POST /auth/passkey/login/finish",
		"POST /auth/passkey/register/begin", "POST /auth/passkey/register/finish",
		"POST /admin/idp/import-metadata", "POST /admin/idp/parse-metadata",
		"POST /admin/idp/fetch-cert", "POST /admin/sso/test-link",
	} {
		method, path, _ := strings.Cut(rt, " ")
		_, pattern := mux.Handler(httptest.NewRequest(method, path, nil))
		require.Equal(t, rt, pattern, "route %s not mounted", rt)
	}
}

// The admin routes need a session; without one they answer 401 before the
// handler runs.
func TestRegister_AdminRoutesRequireASession(t *testing.T) {
	mux := http.NewServeMux()
	h := &Handler{Store: newTestStore(t), Auth: okAuth(), Identity: &fakeMfaIdentity{}}
	h.Register(mux)
	for _, path := range []string{"/admin/idp/import-metadata", "/admin/sso/test-link", "/auth/passkey/register/begin"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		require.Equal(t, http.StatusUnauthorized, rec.Code, path)
	}
}

type fakeSSOAdmin struct {
	identityv1.IdentitySSOAdminServiceClient
	gotTest       *identityv1.RecordIdPTestResultRequest
	gotBreakGlass *identityv1.RecordBreakGlassLoginRequest
	err           error
}

func (f *fakeSSOAdmin) RecordIdPTestResult(_ context.Context, in *identityv1.RecordIdPTestResultRequest, _ ...grpc.CallOption) (*identityv1.RecordIdPTestResultResponse, error) {
	f.gotTest = in
	return &identityv1.RecordIdPTestResultResponse{}, f.err
}

func (f *fakeSSOAdmin) RecordBreakGlassLogin(_ context.Context, in *identityv1.RecordBreakGlassLoginRequest, _ ...grpc.CallOption) (*identityv1.RecordBreakGlassLoginResponse, error) {
	f.gotBreakGlass = in
	return &identityv1.RecordBreakGlassLoginResponse{}, f.err
}

func TestIdentityRecorders(t *testing.T) {
	sa := &fakeSSOAdmin{}
	require.NoError(t, RecordIdPTestWith(sa)(context.Background(), "conn-1", false, "no_email_claim"))
	require.Equal(t, "conn-1", sa.gotTest.GetConnectionId())
	require.False(t, sa.gotTest.GetSuccess())
	require.Equal(t, "no_email_claim", sa.gotTest.GetDetail())

	RecordBreakGlassWith(sa, nil)(context.Background(), "carol@example.net")
	require.Equal(t, "carol@example.net", sa.gotBreakGlass.GetEmail())

	sa.err = errors.New("identity down")
	require.Error(t, RecordIdPTestWith(sa)(context.Background(), "conn-1", true, ""))
	RecordBreakGlassWith(sa, nil)(context.Background(), "carol@example.net")
}
