// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/stretchr/testify/require"
)

func TestBreakGlass_RejectsIneligible(t *testing.T) {
	h := &Handler{
		Identity: fakeIdentity{btg: &identityv1.CheckBreakGlassEligibilityResponse{Eligible: false, Reason: "not_privileged"}},
		Auth:     okAuth(),
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"email":"bob@example.net","password":"x"}`))
	rec := httptest.NewRecorder()
	h.BreakGlassLogin(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "not_eligible")
}

func TestBreakGlass_InvalidRequest(t *testing.T) {
	h := &Handler{Identity: fakeIdentity{}}
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"email":"bob@example.net"}`))
	rec := httptest.NewRecorder()
	h.BreakGlassLogin(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBreakGlass_IdentityUnreachable(t *testing.T) {
	h := &Handler{Identity: fakeIdentity{btgErr: context.DeadlineExceeded}}
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"email":"carol@example.net","password":"x"}`))
	rec := httptest.NewRecorder()
	h.BreakGlassLogin(rec, req)
	require.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestBreakGlass_InvalidCredentials(t *testing.T) {
	var published int
	h := &Handler{
		Identity: fakeIdentity{btg: &identityv1.CheckBreakGlassEligibilityResponse{Eligible: true, Reason: "ok"}},
		Auth: &fakeAuth{verify: func(string, string) (AuthResult, error) {
			return AuthResult{}, ErrInvalidCredentials
		}},
		BreakGlassPublish: func(_ context.Context, _ string) { published++ },
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"email":"carol@example.net","password":"wrong"}`))
	rec := httptest.NewRecorder()
	h.BreakGlassLogin(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, 0, published, "the break-glass alert must never fire on a failed credential check")
}

// An eligible caller with the right password gets the Login answer, and the
// break-glass record fires once with the caller's email.
func TestBreakGlass_EligibleSucceeds(t *testing.T) {
	var mu sync.Mutex
	var publishedEmails []string
	h := &Handler{
		Identity: &fakeMfaIdentity{
			btg:  &identityv1.CheckBreakGlassEligibilityResponse{Eligible: true, Reason: "ok"},
			user: &identityv1.User{Id: "u-carol", Enabled: true},
		},
		Auth:  okAuth(),
		MFA:   MFAConfig{Mode: MFAModeNever},
		Store: newTestStore(t),
		TTL:   time.Hour,
		BreakGlassPublish: func(_ context.Context, email string) {
			mu.Lock()
			defer mu.Unlock()
			publishedEmails = append(publishedEmails, email)
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"email":"carol@example.net","password":"good"}`))
	rec := httptest.NewRecorder()
	h.BreakGlassLogin(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var out struct {
		CSRFToken string `json:"csrfToken"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.NotEmpty(t, out.CSRFToken)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"carol@example.net"}, publishedEmails)
}

// Break-glass owes the same second factor as a normal sign-in.
func TestBreakGlass_StillSubjectToMFA(t *testing.T) {
	id := &fakeMfaIdentity{
		btg:     &identityv1.CheckBreakGlassEligibilityResponse{Eligible: true, Reason: "ok"},
		user:    &identityv1.User{Id: "u-carol", Enabled: true},
		factors: []string{"totp"},
	}
	h := newMfaHandler(t, okAuth(), id, MFAConfig{Mode: MFAModeAlways})
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"email":"carol@example.net","password":"good"}`))
	rec := httptest.NewRecorder()
	h.BreakGlassLogin(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	out := decodeLogin(t, rec)
	require.True(t, out.MFARequired)
	require.NotEmpty(t, out.PendingID)
	require.Nil(t, sessionCookie(rec), "no session before the second factor")
}
