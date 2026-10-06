// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeRegisterClient satisfies authClient (via fakeAuthClient) AND
// passkeyRegisterAuthClient, so it stands in for a *KratosClient behind
// Handler.Auth and is type-asserted by Handler.passkeyRegisterClient.
type fakeRegisterClient struct {
	fakeAuthClient
	beginRes  PasskeyRegisterResult
	beginErr  error
	finishErr error

	lastSessionToken string
	lastFinishFlow   string
	lastFinishCred   string
}

func (f *fakeRegisterClient) PasskeyRegisterBegin(_ context.Context, sessionToken string) (PasskeyRegisterResult, error) {
	f.lastSessionToken = sessionToken
	return f.beginRes, f.beginErr
}

func (f *fakeRegisterClient) PasskeyRegisterFinish(_ context.Context, sessionToken, flowID, cred, _ string, _ map[string]string) error {
	f.lastSessionToken, f.lastFinishFlow, f.lastFinishCred = sessionToken, flowID, cred
	return f.finishErr
}

func newRegisterHandler(t *testing.T, auth authClient) (*Handler, *Store) {
	t.Helper()
	st := newTestStore(t)
	return &Handler{Store: st, Pending: st, Auth: auth, TTL: time.Hour}, st
}

// seedSession creates a signed-in session and returns a request carrying its
// cookie (SessionHTTP is bypassed in these unit tests — the handler reads the
// cookie + store directly).
func seedSession(t *testing.T, st *Store, sess Session) (sid string) {
	t.Helper()
	sid = "sid-reg-1"
	require.NoError(t, st.Create(context.Background(), sid, sess))
	return sid
}

func withCookie(req *http.Request, sid string) *http.Request {
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sid})
	return req
}

func TestPasskeyRegisterBegin_Success_StashesFlow(t *testing.T) {
	pk := &fakeRegisterClient{beginRes: PasskeyRegisterResult{
		FlowID: "set-flow-1", OptionsJSON: pkCreateOptionsJSON, CSRFToken: "csrf-1",
		Cookies: map[string]string{"csrf_token_flow": "cc"},
	}}
	h, st := newRegisterHandler(t, pk)
	sid := seedSession(t, st, Session{AccessToken: "kratos-sess-tok", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})

	rec := httptest.NewRecorder()
	h.PasskeyRegisterBegin(rec, withCookie(postJSONReq("/auth/passkey/register/begin", map[string]any{}, nil), sid))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var raw map[string]string
	decodeInto(t, rec, &raw)
	require.Equal(t, "set-flow-1", raw["flowId"])
	require.Equal(t, pkCreateOptionsJSON, raw["optionsJson"])
	require.Equal(t, "kratos-sess-tok", pk.lastSessionToken, "must drive Kratos with the caller's session token")

	sess, ok, _ := st.Get(context.Background(), sid)
	require.True(t, ok)
	require.NotNil(t, sess.PasskeyReg)
	require.Equal(t, "set-flow-1", sess.PasskeyReg.FlowID)
	require.Equal(t, "cc", sess.PasskeyReg.Cookies["csrf_token_flow"])
}

func TestPasskeyRegisterBegin_NoPasskeySupport_404(t *testing.T) {
	h, st := newRegisterHandler(t, okAuth())
	sid := seedSession(t, st, Session{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)})
	rec := httptest.NewRecorder()
	h.PasskeyRegisterBegin(rec, withCookie(postJSONReq("/x", map[string]any{}, nil), sid))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPasskeyRegisterBegin_NoSession_401(t *testing.T) {
	pk := &fakeRegisterClient{}
	h, _ := newRegisterHandler(t, pk)
	rec := httptest.NewRecorder()
	h.PasskeyRegisterBegin(rec, postJSONReq("/x", map[string]any{}, nil)) // no cookie
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPasskeyRegisterBegin_Reauth_401(t *testing.T) {
	pk := &fakeRegisterClient{beginErr: ErrPasskeyReauthRequired}
	h, st := newRegisterHandler(t, pk)
	sid := seedSession(t, st, Session{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)})
	rec := httptest.NewRecorder()
	h.PasskeyRegisterBegin(rec, withCookie(postJSONReq("/x", map[string]any{}, nil), sid))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	var raw map[string]string
	decodeInto(t, rec, &raw)
	require.Equal(t, "reauth_required", raw["error"])
}

func TestPasskeyRegisterBegin_KratosError_502(t *testing.T) {
	pk := &fakeRegisterClient{beginErr: context.DeadlineExceeded}
	h, st := newRegisterHandler(t, pk)
	sid := seedSession(t, st, Session{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)})
	rec := httptest.NewRecorder()
	h.PasskeyRegisterBegin(rec, withCookie(postJSONReq("/x", map[string]any{}, nil), sid))
	require.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestPasskeyRegisterFinish_Success_ClearsFlow(t *testing.T) {
	pk := &fakeRegisterClient{}
	h, st := newRegisterHandler(t, pk)
	sid := seedSession(t, st, Session{
		AccessToken: "kratos-sess-tok", ExpiresAt: time.Now().Add(time.Hour),
		PasskeyReg: &PasskeyRegState{FlowID: "set-flow-1", CSRFToken: "csrf-1", ExpiresAt: time.Now().Add(time.Minute)},
	})
	rec := httptest.NewRecorder()
	h.PasskeyRegisterFinish(rec, withCookie(postJSONReq("/x",
		map[string]string{"flowId": "set-flow-1", "credentialJson": "{att}"}, nil), sid))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "set-flow-1", pk.lastFinishFlow)
	require.Equal(t, "{att}", pk.lastFinishCred)
	sess, ok, _ := st.Get(context.Background(), sid)
	require.True(t, ok)
	require.Nil(t, sess.PasskeyReg, "flow state must be cleared after a successful registration")
}

func TestPasskeyRegisterFinish_Rejected_400(t *testing.T) {
	pk := &fakeRegisterClient{finishErr: ErrPasskeyRegistrationRejected}
	h, st := newRegisterHandler(t, pk)
	sid := seedSession(t, st, Session{
		AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour),
		PasskeyReg: &PasskeyRegState{FlowID: "set-flow-1", ExpiresAt: time.Now().Add(time.Minute)},
	})
	rec := httptest.NewRecorder()
	h.PasskeyRegisterFinish(rec, withCookie(postJSONReq("/x",
		map[string]string{"flowId": "set-flow-1", "credentialJson": "{att}"}, nil), sid))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var raw map[string]string
	decodeInto(t, rec, &raw)
	require.Equal(t, "registration_rejected", raw["error"])
}

func TestPasskeyRegisterFinish_Reauth_401(t *testing.T) {
	pk := &fakeRegisterClient{finishErr: ErrPasskeyReauthRequired}
	h, st := newRegisterHandler(t, pk)
	sid := seedSession(t, st, Session{
		AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour),
		PasskeyReg: &PasskeyRegState{FlowID: "set-flow-1", ExpiresAt: time.Now().Add(time.Minute)},
	})
	rec := httptest.NewRecorder()
	h.PasskeyRegisterFinish(rec, withCookie(postJSONReq("/x",
		map[string]string{"flowId": "set-flow-1", "credentialJson": "{att}"}, nil), sid))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPasskeyRegisterFinish_FlowMismatch_400(t *testing.T) {
	pk := &fakeRegisterClient{}
	h, st := newRegisterHandler(t, pk)
	sid := seedSession(t, st, Session{
		AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour),
		PasskeyReg: &PasskeyRegState{FlowID: "set-flow-1", ExpiresAt: time.Now().Add(time.Minute)},
	})
	rec := httptest.NewRecorder()
	h.PasskeyRegisterFinish(rec, withCookie(postJSONReq("/x",
		map[string]string{"flowId": "OTHER-FLOW", "credentialJson": "{att}"}, nil), sid))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Empty(t, pk.lastFinishFlow, "a mismatched flow must never reach Kratos")
}

func TestPasskeyRegisterFinish_Expired_400(t *testing.T) {
	pk := &fakeRegisterClient{}
	h, st := newRegisterHandler(t, pk)
	sid := seedSession(t, st, Session{
		AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour),
		PasskeyReg: &PasskeyRegState{FlowID: "set-flow-1", ExpiresAt: time.Now().Add(-time.Minute)}, // expired
	})
	rec := httptest.NewRecorder()
	h.PasskeyRegisterFinish(rec, withCookie(postJSONReq("/x",
		map[string]string{"flowId": "set-flow-1", "credentialJson": "{att}"}, nil), sid))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Empty(t, pk.lastFinishFlow, "an expired flow must never reach Kratos")
}

func TestPasskeyRegisterFinish_NoStash_400(t *testing.T) {
	pk := &fakeRegisterClient{}
	h, st := newRegisterHandler(t, pk)
	sid := seedSession(t, st, Session{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)}) // no PasskeyReg
	rec := httptest.NewRecorder()
	h.PasskeyRegisterFinish(rec, withCookie(postJSONReq("/x",
		map[string]string{"flowId": "set-flow-1", "credentialJson": "{att}"}, nil), sid))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPasskeyRegisterFinish_BadBody_400(t *testing.T) {
	pk := &fakeRegisterClient{}
	h, st := newRegisterHandler(t, pk)
	sid := seedSession(t, st, Session{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)})
	rec := httptest.NewRecorder()
	h.PasskeyRegisterFinish(rec, withCookie(postJSONReq("/x", map[string]string{"flowId": ""}, nil), sid))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
