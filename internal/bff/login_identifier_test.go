// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const rootEmail = "root@example.org"

// kratosEmailOnly mimics Kratos: only the identity's email verifies, and only
// with the right password. It records every identifier it was asked about.
type kratosEmailOnly struct {
	mu   sync.Mutex
	seen []string
}

func (k *kratosEmailOnly) fake() *fakeAuth {
	return &fakeAuth{verify: func(identifier, password string) (AuthResult, error) {
		k.mu.Lock()
		k.seen = append(k.seen, identifier)
		k.mu.Unlock()
		if identifier == rootEmail && password == "ok" {
			return AuthResult{AccessToken: testSessionToken, ExpiresAt: time.Now().Add(time.Hour), Subject: "kratos-id-1", Email: rootEmail}, nil
		}
		return AuthResult{}, ErrInvalidCredentials
	}}
}

func loginHandler(t *testing.T, k *kratosEmailOnly, id *fakeMfaIdentity) *Handler {
	t.Helper()
	h := newTestHandler(t, k.fake())
	h.Identity = id
	return h
}

func postLogin(h *Handler, username, password string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))
	return rec
}

func rootIdentity() *fakeMfaIdentity {
	u := testUser()
	return &fakeMfaIdentity{user: u, getUser: u, loginEmails: map[string]string{"root": rootEmail}}
}

func TestLogin_UsernameSignsInThroughMappedEmail(t *testing.T) {
	for _, typed := range []string{"root", "ROOT", "Root", "  root  "} {
		k := &kratosEmailOnly{}
		id := rootIdentity()
		rec := postLogin(loginHandler(t, k, id), typed, "ok")
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: status=%d body=%s", typed, rec.Code, rec.Body)
		}
		if len(k.seen) != 1 || k.seen[0] != rootEmail {
			t.Fatalf("%q: kratos saw %v, want [%s]", typed, k.seen, rootEmail)
		}
	}
}

func TestLogin_UnknownUsernameLooksLikeWrongPassword(t *testing.T) {
	kWrong, kUnknown := &kratosEmailOnly{}, &kratosEmailOnly{}
	wrong := postLogin(loginHandler(t, kWrong, rootIdentity()), "root", "nope")
	unknown := postLogin(loginHandler(t, kUnknown, rootIdentity()), "nobody", "nope")

	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status=%d", wrong.Code)
	}
	if unknown.Code != wrong.Code || unknown.Body.String() != wrong.Body.String() {
		t.Fatalf("unknown differs: %d %q vs %d %q", unknown.Code, unknown.Body, wrong.Code, wrong.Body)
	}
	if strings.TrimSpace(unknown.Body.String()) != `{"error":"invalid_credentials"}` {
		t.Fatalf("body=%q", unknown.Body)
	}
	if unknown.Header().Get("Content-Type") != wrong.Header().Get("Content-Type") || len(unknown.Result().Cookies()) != len(wrong.Result().Cookies()) {
		t.Fatal("headers or cookies differ")
	}
	if len(kWrong.seen) != 1 || len(kUnknown.seen) != 1 {
		t.Fatalf("VerifyPassword calls: wrong=%d unknown=%d, want 1 each", len(kWrong.seen), len(kUnknown.seen))
	}
	if kUnknown.seen[0] != "nobody" {
		t.Fatalf("fallback must submit the typed value, got %q", kUnknown.seen[0])
	}
}

func TestLogin_DisabledOrSSOUsernameBehavesLikeUnknown(t *testing.T) {
	// Identity answers an empty email for a disabled, deleted or SSO account,
	// which the fake models as the username being absent from the map.
	k := &kratosEmailOnly{}
	id := rootIdentity()
	delete(id.loginEmails, "root")
	rec := postLogin(loginHandler(t, k, id), "root", "ok")
	if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"error":"invalid_credentials"}` {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if len(k.seen) != 1 || k.seen[0] != "root" {
		t.Fatalf("kratos saw %v, want the typed value once", k.seen)
	}
}

func TestLogin_LookupErrorFallsBackToTypedValue(t *testing.T) {
	k := &kratosEmailOnly{}
	id := rootIdentity()
	id.loginEmailErr = status.Error(codes.Unavailable, "identity down")
	rec := postLogin(loginHandler(t, k, id), "root", "ok")
	if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"error":"invalid_credentials"}` {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if len(k.seen) != 1 || k.seen[0] != "root" {
		t.Fatalf("kratos saw %v, want the typed value once", k.seen)
	}
}

func TestLogin_EmailIdentifierSkipsLookup(t *testing.T) {
	k := &kratosEmailOnly{}
	id := rootIdentity()
	rec := postLogin(loginHandler(t, k, id), rootEmail, "ok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if len(id.loginEmailReq) != 0 {
		t.Fatalf("an email identifier must not call ResolveLoginEmail, got %v", id.loginEmailReq)
	}
	if len(k.seen) != 1 || k.seen[0] != rootEmail {
		t.Fatalf("kratos saw %v", k.seen)
	}
}

func TestLogin_LookupSendsTrimmedUsername(t *testing.T) {
	id := rootIdentity()
	postLogin(loginHandler(t, &kratosEmailOnly{}, id), "  Root ", "ok")
	if len(id.loginEmailReq) != 1 || id.loginEmailReq[0] != "Root" {
		t.Fatalf("lookup requests=%v, want [Root]", id.loginEmailReq)
	}
}
