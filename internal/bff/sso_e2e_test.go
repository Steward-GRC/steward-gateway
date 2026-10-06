// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/stretchr/testify/require"
)

// TestSSO_EndToEnd_DiscoverStartCallbackMFA drives identifier-first discovery
// → the Polis redirect → the simulated Polis callback → our MFA step-up,
// asserting at each hop exactly what the spec promises: discovery never does
// more than name the method+connection, the redirect carries the tenant and
// parks single-use state, the callback JIT-provisions the federated user by
// email (forwarding the connection alias) but — because MFAConfig=Always —
// issues NO session until the factor is verified, and only then does
// completing MFA (the same /auth/mfa/verify a password login uses) mint the
// real session.
func TestSSO_EndToEnd_DiscoverStartCallbackMFA(t *testing.T) {
	id := polisIdentity()
	id.user = nil
	id.jitUser = &identityv1.User{Id: "u1", Enabled: true}
	id.totpOK = true

	h, ssoState, cap := newPolisSSOHandler(t, id, MFAConfig{Mode: MFAModeAlways})
	cap.accessToken, cap.refreshToken = "polis-at", "RT"

	discoverBody, err := json.Marshal(map[string]string{"identifier": "alice@example.org"})
	require.NoError(t, err)
	drec := httptest.NewRecorder()
	h.Discover(drec, httptest.NewRequest(http.MethodPost, "/auth/discover", strings.NewReader(string(discoverBody))))
	require.Equal(t, http.StatusOK, drec.Code)
	var dout struct {
		Method          string `json:"method"`
		ConnectionAlias string `json:"connectionAlias"`
	}
	require.NoError(t, json.Unmarshal(drec.Body.Bytes(), &dout))
	require.Equal(t, "sso", dout.Method)
	require.Equal(t, "example-sso", dout.ConnectionAlias)

	srec := httptest.NewRecorder()
	h.SSOStart(srec, httptest.NewRequest(http.MethodGet, "/auth/sso/start?connection="+dout.ConnectionAlias+"&identifier=alice@example.org", nil))
	require.Equal(t, http.StatusFound, srec.Code)
	loc, err := url.Parse(srec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "example.org", loc.Query().Get("tenant"))
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)

	crec := httptest.NewRecorder()
	h.SSOCallback(crec, httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=c&state="+state, nil))
	pendingID, _ := mfaRedirect(t, crec)

	require.NotNil(t, id.lastJitProvisionByEmail, "the callback must run JIT-by-email")
	require.Equal(t, "alice@example.org", id.lastJitProvisionByEmail.GetEmail())
	require.Equal(t, "example-sso", id.lastJitProvisionByEmail.GetConnectionAlias())

	_, ok, err := ssoState.TakeSSOState(context.Background(), state)
	require.NoError(t, err)
	require.False(t, ok, "SSO state must be single-use")

	vrec := verifyReq(t, h, map[string]string{"pendingId": pendingID, "kind": "totp", "code": "123456"})
	require.Equal(t, http.StatusOK, vrec.Code, vrec.Body.String())
	vout := decodeLogin(t, vrec)
	require.NotEmpty(t, vout.CSRFToken)
	c := sessionCookie(vrec)
	require.NotNil(t, c)
	require.NotEmpty(t, c.Value)

	sess, ok, err := h.Store.Get(context.Background(), c.Value)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, sess.MFAVerified)
	require.Equal(t, "u1", sess.UserID)
	require.Empty(t, sess.AccessToken, "an SSO session holds no broker token")
}
