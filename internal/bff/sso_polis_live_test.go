// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type discoverSpy struct {
	*fakeMfaIdentity
	identifiers []string
}

func (d *discoverSpy) Discover(ctx context.Context, in *identityv1.DiscoverRequest, opts ...grpc.CallOption) (*identityv1.DiscoverResponse, error) {
	d.identifiers = append(d.identifiers, in.GetIdentifier())
	return d.fakeMfaIdentity.Discover(ctx, in, opts...)
}

func TestSSOStart_Polis_ActiveGateMatchesDiscoverAlias(t *testing.T) {
	spy := &discoverSpy{fakeMfaIdentity: polisIdentity()}
	h, ssoState, _ := newPolisSSOHandler(t, spy.fakeMfaIdentity, edgeCfg())
	h.Identity = spy

	rec := httptest.NewRecorder()
	h.SSOStart(rec, httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso&identifier=alice@example.org", nil))

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.Equal(t, []string{"alice@example.org"}, spy.identifiers, "the gate re-runs Discover on the typed identifier")
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/sso/api/oauth/authorize", loc.Path)
	require.Equal(t, "example.org", loc.Query().Get("tenant"))
	got, ok, err := ssoState.TakeSSOState(context.Background(), loc.Query().Get("state"))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "example-sso", got.Connection)
}

func TestSSOStart_Polis_InactiveConnectionNeverReachesPolis(t *testing.T) {
	cases := map[string]*identityv1.DiscoverResponse{
		"not sso":        {Method: "local"},
		"alias mismatch": {Method: "sso", ConnectionAlias: "other"},
	}
	for name, disc := range cases {
		t.Run(name, func(t *testing.T) {
			id := polisIdentity()
			id.discover = disc
			h, _, _ := newPolisSSOHandler(t, id, edgeCfg())

			rec := httptest.NewRecorder()
			h.SSOStart(rec, httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso&identifier=alice@example.org", nil))

			require.Equal(t, http.StatusFound, rec.Code)
			require.Equal(t, "/login?error=sso_not_active", rec.Header().Get("Location"))
		})
	}
}

func TestSSOCallback_Polis_AliasMismatchRefusesSession(t *testing.T) {
	id := polisIdentity()
	id.discover = &identityv1.DiscoverResponse{Method: "sso", ConnectionAlias: "other"}
	h, ssoState, _ := newPolisSSOHandler(t, id, edgeCfg())
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Tenant: "example.org", Mode: "login"}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/login?error=sso_not_active", rec.Header().Get("Location"))
	require.Nil(t, sessionCookie(rec))
}

func TestSSOCallback_Polis_MFAStepUpJITForwardsConnectionAlias(t *testing.T) {
	id := polisIdentity()
	id.user = nil
	id.jitUser = &identityv1.User{Id: "u-jit", Enabled: true}
	h, ssoState, _ := newPolisSSOHandler(t, id, MFAConfig{Mode: MFAModeAlways})
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Tenant: "example.org", Mode: "login"}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	pendingID, _ := mfaRedirect(t, rec)
	require.NotNil(t, id.lastJitProvisionByEmail)
	require.Equal(t, "example-sso", id.lastJitProvisionByEmail.GetConnectionAlias())
	p, ok, err := h.Pending.GetPending(context.Background(), pendingID)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "u-jit", p.UserID)
}

func noBrokerHandler(t *testing.T) (*Handler, SSOStateStore) {
	t.Helper()
	ssoState := newTestStore(t)
	id := polisIdentity()
	id.getUser = adminUser()
	return &Handler{
		Store:           newTestStore(t),
		Identity:        id,
		SSOState:        ssoState,
		SSORedirectBase: "https://app",
	}, ssoState
}

func TestSSOStart_WithoutBrokerFailsClosed(t *testing.T) {
	h, _ := noBrokerHandler(t)
	rec := httptest.NewRecorder()
	h.SSOStart(rec, httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection=example-sso&identifier=alice@example.org", nil))

	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/login?error=sso", rec.Header().Get("Location"))
}

func TestSSOStart_TestModeWithoutBrokerIsUnavailable(t *testing.T) {
	h, _ := noBrokerHandler(t)
	rec := httptest.NewRecorder()
	h.SSOStart(rec, siteAdminStartReq(t, h, "/auth/sso/start?connection=example-sso&mode=test&tenant=example.org"))

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Contains(t, rec.Body.String(), "sso_unavailable")
	require.Empty(t, rec.Header().Get("Location"))
}

func TestSSOIdpInitiated_WithoutBrokerFailsClosed(t *testing.T) {
	h, _ := noBrokerHandler(t)
	rec := httptest.NewRecorder()
	h.SSOIdpInitiated(rec, httptest.NewRequest(http.MethodPost, "/auth/sso/idp-initiated", nil))

	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/login?error=sso", rec.Header().Get("Location"))
}

func TestSSOCallback_WithoutBrokerFailsClosed(t *testing.T) {
	h, ssoState := noBrokerHandler(t)
	require.NoError(t, ssoState.PutSSOState(context.Background(), "st1", SSOState{Connection: "example-sso", Mode: "login"}, ssoStateTTL))

	rec := httptest.NewRecorder()
	h.SSOCallback(rec, ssoCallbackReq("st1"))

	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/login?error=sso", rec.Header().Get("Location"))
	require.Nil(t, sessionCookie(rec))
}
