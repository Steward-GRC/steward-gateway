// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// fakeIdentity is a minimal IdentityClient stub scoped to the discover tests.
// It embeds the interface (left nil) so it satisfies IdentityClient without
// implementing every method — only Discover is exercised here.
type fakeIdentity struct {
	IdentityClient
	discover    *identityv1.DiscoverResponse
	discoverErr error
	btg         *identityv1.CheckBreakGlassEligibilityResponse
	btgErr      error
}

func (f fakeIdentity) Discover(_ context.Context, _ *identityv1.DiscoverRequest, _ ...grpc.CallOption) (*identityv1.DiscoverResponse, error) {
	if f.discoverErr != nil {
		return nil, f.discoverErr
	}
	return f.discover, nil
}

// CheckBreakGlassEligibility supports the break-glass login tests
// (breakglass_test.go), which construct fakeIdentity{btg: ...}.
func (f fakeIdentity) CheckBreakGlassEligibility(_ context.Context, _ *identityv1.CheckBreakGlassEligibilityRequest, _ ...grpc.CallOption) (*identityv1.CheckBreakGlassEligibilityResponse, error) {
	if f.btgErr != nil {
		return nil, f.btgErr
	}
	return f.btg, nil
}

func TestDiscoverHandler(t *testing.T) {
	h := &Handler{Identity: fakeIdentity{discover: &identityv1.DiscoverResponse{Method: "sso", ConnectionAlias: "example-sso"}}}
	req := httptest.NewRequest(http.MethodPost, "/auth/discover", strings.NewReader(`{"identifier":"frank@example.org"}`))
	rec := httptest.NewRecorder()
	h.Discover(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct{ Method, ConnectionAlias string }
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "sso", body.Method)
	require.Equal(t, "example-sso", body.ConnectionAlias)
}

func TestDiscoverHandler_InvalidRequest(t *testing.T) {
	h := &Handler{Identity: fakeIdentity{}}
	req := httptest.NewRequest(http.MethodPost, "/auth/discover", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.Discover(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDiscoverHandler_IdentityUnreachable(t *testing.T) {
	h := &Handler{Identity: fakeIdentity{discoverErr: context.DeadlineExceeded}}
	req := httptest.NewRequest(http.MethodPost, "/auth/discover", strings.NewReader(`{"identifier":"frank@example.org"}`))
	rec := httptest.NewRecorder()
	h.Discover(rec, req)
	require.Equal(t, http.StatusBadGateway, rec.Code)
}
