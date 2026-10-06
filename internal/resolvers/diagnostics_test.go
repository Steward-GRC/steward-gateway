// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/diagnostics"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

type diagIdentity struct {
	identityv1.IdentityReadServiceClient
	names map[string]string
}

func (d diagIdentity) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	return &identityv1.GetUserResponse{User: &identityv1.User{Id: in.GetUserId(), Username: d.names[in.GetUserId()]}}, nil
}

const (
	canarySession = "canary-session-cookie-7f3a"
	canaryCSRF    = "canary-csrf-9b21"
	canaryBearer  = "canary-bearer-44c0"
	canaryAPI     = "canary-api-token-e12d"
	canaryIP      = "203.0.113.77"
	canaryAIKey   = "sk-canary-ai-provider-key-5501"
)

const diagQuery = `{"query":"{ diagnostics { generatedAt traceId actor { id username roles actingAs { id username roles } } gateway { name version commit status } release appliance services { name version commit status } thirdParty { name version commit status } } }"}`

func diagServer(t *testing.T, claims, admin principal.Claims) *httptest.Server {
	t.Helper()
	r := &Resolver{
		IdentityClient: diagIdentity{names: map[string]string{"u-alice": "alice", "u-bob": "bob"}},
		Diagnostics: diagnostics.New(diagnostics.Config{ThirdParty: map[string]diagnostics.VersionFunc{
			"kratos": func(context.Context) (string, error) { return "v1.3.0", nil },
			"ai":     func(context.Context) (string, error) { return "provider_key=" + canaryAIKey, nil },
		}}),
	}
	srv := handler.New(NewExecutableSchema(Config{Resolvers: r}))
	srv.AddTransport(transport.POST{})
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		if admin != nil {
			ctx = principal.WithImpersonator(ctx, admin)
		}
		if claims != nil {
			ctx = principal.WithClaims(ctx, claims)
		}
		srv.ServeHTTP(w, req.WithContext(ctx))
	})
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func readDiagnostics(t *testing.T, ts *httptest.Server, body string) (string, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+canaryBearer)
	req.Header.Set("X-CSRF-Token", canaryCSRF)
	req.Header.Set("X-Api-Token", canaryAPI)
	req.Header.Set("X-Forwarded-For", canaryIP)
	req.AddCookie(&http.Cookie{Name: "steward_sid", Value: canarySession})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	raw, _ := json.Marshal(out)
	return string(raw), out
}

func TestDiagnosticsNeverCarriesTokensCookiesSecretsOrIPs(t *testing.T) {
	ts := diagServer(t, principal.Static{UserIDValue: "u-alice", RolesValue: []string{"admin"}, SessionIDValue: canarySession}, nil)
	raw, out := readDiagnostics(t, ts, diagQuery)
	require.Nil(t, out["errors"], raw)
	for _, canary := range []string{canarySession, canaryCSRF, canaryBearer, canaryAPI, canaryIP, canaryAIKey, "sk-canary"} {
		assert.NotContains(t, raw, canary)
	}
}

func TestDiagnosticsActorIsTheCallersOwn(t *testing.T) {
	ts := diagServer(t, principal.Static{UserIDValue: "u-alice", RolesValue: []string{"admin"}}, nil)
	raw, out := readDiagnostics(t, ts, diagQuery)
	require.Nil(t, out["errors"], raw)
	actor := out["data"].(map[string]any)["diagnostics"].(map[string]any)["actor"].(map[string]any)
	assert.Equal(t, "u-alice", actor["id"])
	assert.Equal(t, "alice", actor["username"])
	assert.Equal(t, []any{"admin"}, actor["roles"])
	assert.Nil(t, actor["actingAs"])
}

func TestDiagnosticsDuringActAsShowsTheAdminAndTheTarget(t *testing.T) {
	ts := diagServer(t, principal.Static{UserIDValue: "u-bob", RolesValue: []string{}},
		principal.Static{UserIDValue: "u-alice", RolesValue: []string{"site-admin"}})
	raw, out := readDiagnostics(t, ts, diagQuery)
	require.Nil(t, out["errors"], raw)
	actor := out["data"].(map[string]any)["diagnostics"].(map[string]any)["actor"].(map[string]any)
	assert.Equal(t, "u-alice", actor["id"], "the actor is the real admin")
	as := actor["actingAs"].(map[string]any)
	assert.Equal(t, "u-bob", as["id"])
	assert.Equal(t, "bob", as["username"])
}

func TestDiagnosticsTakesNoArguments(t *testing.T) {
	ts := diagServer(t, principal.Static{UserIDValue: "u-alice"}, nil)
	raw, out := readDiagnostics(t, ts, `{"query":"{ diagnostics(userId: \"u-bob\") { actor { id } } }"}`)
	require.NotNil(t, out["errors"], raw)
	assert.NotContains(t, raw, "u-bob\",\"username")
}

func TestDiagnosticsSignedOutIsRefused(t *testing.T) {
	ts := diagServer(t, nil, nil)
	raw, out := readDiagnostics(t, ts, diagQuery)
	errs, ok := out["errors"].([]any)
	require.True(t, ok, raw)
	assert.Contains(t, raw, "UNAUTHENTICATED")
	assert.Len(t, errs, 1)
	assert.Nil(t, out["data"])
}

func TestDiagnosticsVersionsAreTypedFieldsOnly(t *testing.T) {
	ts := diagServer(t, principal.Static{UserIDValue: "u-alice"}, nil)
	raw, out := readDiagnostics(t, ts, diagQuery)
	require.Nil(t, out["errors"], raw)
	d := out["data"].(map[string]any)["diagnostics"].(map[string]any)
	third := d["thirdParty"].([]any)
	byName := map[string]map[string]any{}
	for _, c := range third {
		m := c.(map[string]any)
		byName[m["name"].(string)] = m
		assert.ElementsMatch(t, []string{"name", "version", "commit", "status"}, keys(m))
	}
	assert.Equal(t, "v1.3.0", byName["kratos"]["version"])
	assert.Equal(t, "UNAVAILABLE", byName["ai"]["status"], "a value that isn't a version shape is never passed on")
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
