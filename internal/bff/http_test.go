// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/stretchr/testify/require"
)

// failingReadStore errors on every read but records Delete calls.
type failingReadStore struct{ deleted []string }

func (f *failingReadStore) Create(ctx context.Context, id string, s Session) error { return nil }
func (f *failingReadStore) Save(ctx context.Context, id string, s Session) error   { return nil }
func (f *failingReadStore) Get(ctx context.Context, id string) (Session, bool, error) {
	return Session{}, false, errors.New("redis unavailable")
}
func (f *failingReadStore) Delete(ctx context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}
func (f *failingReadStore) AcquireRefreshLock(ctx context.Context, id string, ttl time.Duration) (string, bool, error) {
	return "", false, errors.New("redis unavailable")
}
func (f *failingReadStore) ReleaseRefreshLock(ctx context.Context, id, token string) error {
	return nil
}

func TestLogout_RevokesSessionEvenWhenReadFails(t *testing.T) {
	fs := &failingReadStore{}
	h := &Handler{Store: fs, Auth: okAuth(), TTL: time.Hour}
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sidZ"})
	rec := httptest.NewRecorder()
	h.Logout(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("logout should be idempotent 200, got %d", rec.Code)
	}
	if len(fs.deleted) != 1 || fs.deleted[0] != "sidZ" {
		t.Fatalf("session must be deleted despite read error, deleted=%v", fs.deleted)
	}
}

func testUser() *identityv1.User {
	return &identityv1.User{Id: "u1", Email: "alice@example.org", Enabled: true}
}

func newTestHandler(t *testing.T, auth authClient) *Handler {
	u := testUser()
	return &Handler{
		Store: newTestStore(t), Auth: auth, TTL: time.Hour, Secure: false,
		Identity: &fakeMfaIdentity{user: u, getUser: u},
		MFA:      MFAConfig{Mode: MFAModeNever},
	}
}

func TestLogin_SetsCookieAndCSRF(t *testing.T) {
	h := newTestHandler(t, okAuth())

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "good"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var out struct {
		CSRFToken string `json:"csrfToken"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.CSRFToken == "" {
		t.Fatal("missing csrfToken")
	}
	cs := rec.Result().Cookies()
	var sid *http.Cookie
	for _, c := range cs {
		if c.Name == CookieName {
			sid = c
		}
	}
	if sid == nil || !sid.HttpOnly || sid.Value == "" {
		t.Fatalf("bad cookie: %+v", sid)
	}

	sess, ok, _ := h.Store.Get(context.Background(), sid.Value)
	if !ok || sess.CSRFToken != out.CSRFToken || sess.AccessToken != testSessionToken || sess.UserID != "u1" {
		t.Fatalf("session not stored correctly: %+v ok=%v", sess, ok)
	}
}

func TestLogin_BadCreds401(t *testing.T) {
	h := newTestHandler(t, &fakeAuth{verify: func(string, string) (AuthResult, error) {
		return AuthResult{}, ErrInvalidCredentials
	}})
	body, _ := json.Marshal(map[string]string{"username": "x", "password": "y"})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))
	if rec.Code != 401 {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

// authedRequest builds a request carrying the session cookie and CSRF header.
func authedRequest(method, path, sid, csrf string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sid})
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return req
}

func TestAuthenticate_PutsPrincipalOnContext(t *testing.T) {
	h := newTestHandler(t, okAuth())
	_ = h.Store.Create(context.Background(), "sid1", Session{AccessToken: "AT", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(5 * time.Minute)})

	var seen principal.Claims
	var sidSeen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = principal.FromContext(r.Context())
		sidSeen, _ = SessionIDFromContext(r.Context())
	})
	h.Authenticate(next).ServeHTTP(httptest.NewRecorder(), authedRequest(http.MethodPost, "/query", "sid1", "csrf"))
	require.NotNil(t, seen)
	require.Equal(t, "u1", seen.UserID())
	require.Equal(t, "alice@example.org", seen.Email())
	require.Equal(t, SessionRef("sid1"), seen.SessionID(), "the actor carries the opaque ref, never the cookie value")
	require.NotEqual(t, "sid1", seen.SessionID())
	require.Equal(t, "sid1", sidSeen)
}

func TestAuthenticate_CSRFMismatch403(t *testing.T) {
	h := newTestHandler(t, okAuth())
	_ = h.Store.Create(context.Background(), "sid1", Session{AccessToken: "AT", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not reach next") })
	rec := httptest.NewRecorder()
	h.Authenticate(next).ServeHTTP(rec, authedRequest(http.MethodPost, "/query", "sid1", "WRONG"))
	if rec.Code != 403 {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

func TestSession_Authenticated(t *testing.T) {
	h := newTestHandler(t, okAuth())
	_ = h.Store.Create(context.Background(), "sidS", Session{AccessToken: "AT", CSRFToken: "csrfS", ExpiresAt: time.Now().Add(time.Hour)})
	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sidS"})
	rec := httptest.NewRecorder()
	h.Session(rec, req)

	var out struct {
		Authenticated bool   `json:"authenticated"`
		CSRFToken     string `json:"csrfToken"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || !out.Authenticated || out.CSRFToken != "csrfS" {
		t.Fatalf("want authenticated with csrf, got code=%d %+v", rec.Code, out)
	}
}

func TestSession_Unauthenticated(t *testing.T) {
	h := newTestHandler(t, okAuth())
	for _, tc := range []string{"", "unknown-sid"} {
		req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
		if tc != "" {
			req.AddCookie(&http.Cookie{Name: CookieName, Value: tc})
		}
		rec := httptest.NewRecorder()
		h.Session(rec, req)
		var out struct {
			Authenticated bool   `json:"authenticated"`
			CSRFToken     string `json:"csrfToken"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 200 || out.Authenticated || out.CSRFToken != "" {
			t.Fatalf("cookie=%q want unauthenticated no-csrf, got code=%d %+v", tc, rec.Code, out)
		}
	}
}

func TestAuthenticate_RefreshesNearExpiry(t *testing.T) {
	auth := &fakeAuth{refresh: func(string) (AuthResult, error) {
		return AuthResult{AccessToken: "AT2", ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
	}}
	h := newTestHandler(t, auth)
	_ = h.Store.Create(context.Background(), "sidR",
		Session{AccessToken: "AT", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(2 * time.Second)})

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	h.Authenticate(next).ServeHTTP(httptest.NewRecorder(), authedRequest(http.MethodPost, "/query", "sidR", "csrf"))

	require.True(t, reached)
	require.Equal(t, []string{"AT"}, auth.refreshTokens, "whoami gets the stored Kratos session token")
	got, _, _ := h.Store.Get(context.Background(), "sidR")
	if got.AccessToken != "AT2" || time.Until(got.ExpiresAt) < 4*time.Minute {
		t.Fatalf("session not updated after refresh: %+v", got)
	}
}

// Concurrent requests for the same session near expiry extend it once.
func TestAuthenticate_SingleFlightRefresh(t *testing.T) {
	auth := &fakeAuth{refresh: func(string) (AuthResult, error) {
		time.Sleep(60 * time.Millisecond)
		return AuthResult{AccessToken: "AT2", ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
	}}
	h := newTestHandler(t, auth)
	_ = h.Store.Create(context.Background(), "sidSF",
		Session{AccessToken: "AT", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(2 * time.Second)})

	const n = 8
	var wg sync.WaitGroup
	reached := make([]bool, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached[i] = true })
			h.Authenticate(next).ServeHTTP(httptest.NewRecorder(), authedRequest(http.MethodPost, "/query", "sidSF", "csrf"))
		}(i)
	}
	wg.Wait()

	if got := auth.calls(); got != 1 {
		t.Fatalf("single-flight: want exactly 1 refresh across %d concurrent callers, got %d", n, got)
	}
	for i, ok := range reached {
		if !ok {
			t.Fatalf("caller %d was not served", i)
		}
	}
	sess, _, _ := h.Store.Get(context.Background(), "sidSF")
	if sess.AccessToken != "AT2" {
		t.Fatalf("session not updated: %+v", sess)
	}
}

func TestWebsocketInit_EnforcesDoubleSubmit(t *testing.T) {
	h := newTestHandler(t, okAuth())
	_ = h.Store.Create(context.Background(), "sidW", Session{AccessToken: "ATW", CSRFToken: "goodcsrf", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})

	withCookie := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/query", nil)
		r.AddCookie(&http.Cookie{Name: CookieName, Value: "sidW"})
		return r
	}

	ctx, err := h.WebsocketInit(context.Background(), withCookie(), "goodcsrf")
	require.NoError(t, err)
	c, ok := principal.FromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "u1", c.UserID())

	_, err = h.WebsocketInit(context.Background(), withCookie(), "wrong")
	require.ErrorIs(t, err, ErrWebsocketUnauthorized)
	_, err = h.WebsocketInit(context.Background(), withCookie(), "")
	require.ErrorIs(t, err, ErrWebsocketUnauthorized)
	_, err = h.WebsocketInit(context.Background(), httptest.NewRequest(http.MethodGet, "/query", nil), "goodcsrf")
	require.ErrorIs(t, err, ErrWebsocketUnauthorized)
}

func TestAuthenticate_FailedRefreshRevokes401(t *testing.T) {
	h := newTestHandler(t, &fakeAuth{refresh: func(string) (AuthResult, error) {
		return AuthResult{}, ErrInvalidCredentials
	}})
	_ = h.Store.Create(context.Background(), "sidExp",
		Session{AccessToken: "STALE", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(2 * time.Second)})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not reach next with a dead session")
	})
	rec := httptest.NewRecorder()
	h.Authenticate(next).ServeHTTP(rec, authedRequest(http.MethodPost, "/query", "sidExp", "csrf"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 on failed refresh, got %d", rec.Code)
	}
	if _, ok, _ := h.Store.Get(context.Background(), "sidExp"); ok {
		t.Fatal("expected session deleted after failed refresh")
	}
}

// The safe-read exemption leans on SameSite=Lax: the browser withholds the
// cookie on cross-site subresource loads.
func TestSessionCookie_IsSameSiteLax(t *testing.T) {
	h := newTestHandler(t, okAuth())
	rec := httptest.NewRecorder()
	h.setCookie(rec, "sidLax", 3600)

	var got *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			got = c
		}
	}
	if got == nil {
		t.Fatalf("no %s cookie set", CookieName)
	}
	if got.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie must be SameSite=Lax, got %v", got.SameSite)
	}
	if !got.HttpOnly {
		t.Fatal("session cookie must stay HttpOnly")
	}
}

func TestSafeMethod(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if !SafeMethod(m) {
			t.Fatalf("%s must be safe", m)
		}
	}
	for _, m := range []string{
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		http.MethodOptions, http.MethodConnect, http.MethodTrace, "get", "",
	} {
		if SafeMethod(m) {
			t.Fatalf("%s must NOT be safe", m)
		}
	}
}

// A browser <img> or HEAD load carries the cookie but can't set the CSRF
// header; on a safe-read mount it must reach the handler, authenticated.
func TestAuthenticateSafeRead_SafeMethodNoCSRFHeader(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			h := newTestHandler(t, okAuth())
			_ = h.Store.Create(context.Background(), "sidRO",
				Session{AccessToken: "ATRO", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})

			var seen principal.Claims
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen, _ = principal.FromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})
			rec := httptest.NewRecorder()
			h.AuthenticateSafeRead(next).ServeHTTP(rec, authedRequest(method, "/api/assets/abc", "sidRO", ""))

			if rec.Code != http.StatusOK {
				t.Fatalf("want 200 with no CSRF header, got %d body=%s", rec.Code, rec.Body.String())
			}
			require.NotNil(t, seen, "the route stays authenticated")
			require.Equal(t, "u1", seen.UserID())
		})
	}
}

// The exemption keys off the method, never the mount.
func TestAuthenticateSafeRead_UnsafeMethodStill403(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			h := newTestHandler(t, okAuth())
			_ = h.Store.Create(context.Background(), "sidRW",
				Session{AccessToken: "AT", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("must not reach next without a CSRF token")
			})
			rec := httptest.NewRecorder()
			h.AuthenticateSafeRead(next).ServeHTTP(rec, authedRequest(method, "/api/assets/abc", "sidRW", ""))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("want 403, got %d", rec.Code)
			}
		})
	}
}

// No route becomes CSRF-exempt just by being a GET.
func TestAuthenticate_SafeMethodStill403(t *testing.T) {
	h := newTestHandler(t, okAuth())
	_ = h.Store.Create(context.Background(), "sidG",
		Session{AccessToken: "AT", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not reach next")
	})
	rec := httptest.NewRecorder()
	h.Authenticate(next).ServeHTTP(rec, authedRequest(http.MethodGet, "/some/read", "sidG", ""))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 on a non-opted-in GET, got %d", rec.Code)
	}
}

// The exemption is a skip, not a comparison: a stale header doesn't 403 a
// legitimate read.
func TestAuthenticateSafeRead_WrongCSRFOnSafeMethodStillAllowed(t *testing.T) {
	h := newTestHandler(t, okAuth())
	_ = h.Store.Create(context.Background(), "sidS2",
		Session{AccessToken: "AT", CSRFToken: "csrf", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rec := httptest.NewRecorder()
	h.AuthenticateSafeRead(next).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/assets/abc", "sidS2", "STALE"))

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

// The read path isn't public: no cookie or a dead one is a 401.
func TestAuthenticateSafeRead_NoSessionStillUnauthenticated(t *testing.T) {
	h := newTestHandler(t, okAuth())
	for name, cookie := range map[string]string{"no_cookie": "", "dead_session": "sidGone"} {
		t.Run(name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("must not reach next")
			})
			req := httptest.NewRequest(http.MethodGet, "/api/assets/abc", nil)
			if cookie != "" {
				req.AddCookie(&http.Cookie{Name: CookieName, Value: cookie})
			}
			rec := httptest.NewRecorder()
			h.AuthenticateSafeRead(next).ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("want 401, got %d", rec.Code)
			}
		})
	}
}

func TestSession_EmailFromUserID(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Create(context.Background(), "sid-sso", Session{
		CSRFToken: "csrf1", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour),
	}))
	id := &fakeMfaIdentity{getUser: &identityv1.User{Id: "u1", Enabled: true, Email: "alice@example.org"}}
	h := &Handler{Store: store, Identity: id}

	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid-sso"})
	rec := httptest.NewRecorder()
	h.Session(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, true, out["authenticated"])
	require.Equal(t, "alice@example.org", out["email"], "email must be resolved from the session UserID")
	require.NotNil(t, id.lastGetUser)
	require.Equal(t, "u1", id.lastGetUser.GetUserId())
}

// A GetUser failure omits the email but keeps authenticated=true.
func TestSession_EmailOmittedWhenGetUserErrors(t *testing.T) {
	store := newTestStore(t)
	require.NoError(t, store.Create(context.Background(), "sid-e", Session{
		AccessToken: "opaque", CSRFToken: "c", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour),
	}))
	id := &fakeMfaIdentity{getUserErr: context.DeadlineExceeded}
	h := &Handler{Store: store, Identity: id}

	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid-e"})
	rec := httptest.NewRecorder()
	h.Session(rec, req)

	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, true, out["authenticated"], "auth stays true even if the email lookup fails")
	_, hasEmail := out["email"]
	require.False(t, hasEmail, "email omitted on GetUser error")
}

// The act-as record round-trips through the stored JSON, and Active is true
// only before ExpiresAt.
func TestSession_ImpersonationRoundTripAndExpiry(t *testing.T) {
	now := time.Now()
	st := &ImpersonationState{
		TargetUserID: "t",
		AdminUserID:  "a",
		Reason:       "debug",
		StartedAt:    now,
		ExpiresAt:    now.Add(30 * time.Minute),
	}
	require.True(t, st.Active(now), "active before ExpiresAt")
	require.False(t, st.Active(now.Add(31*time.Minute)), "inactive after ExpiresAt")

	var nilState *ImpersonationState
	require.False(t, nilState.Active(now), "nil state is never active")

	sess := Session{UserID: "a", Impersonation: st}
	b, err := json.Marshal(sess)
	require.NoError(t, err)
	var got Session
	require.NoError(t, json.Unmarshal(b, &got))
	require.NotNil(t, got.Impersonation)
	require.Equal(t, "t", got.Impersonation.TargetUserID)
	require.Equal(t, "a", got.Impersonation.AdminUserID)
	require.Equal(t, "debug", got.Impersonation.Reason)
	require.True(t, got.Impersonation.StartedAt.Equal(st.StartedAt))
	require.True(t, got.Impersonation.ExpiresAt.Equal(st.ExpiresAt))
}
