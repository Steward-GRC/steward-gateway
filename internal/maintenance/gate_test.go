// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package maintenance_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/stretchr/testify/require"
	"github.com/vektah/gqlparser/v2/ast"
	"google.golang.org/grpc"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/maintenance"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// fakeSettings returns a fixed maintenance state and counts calls so the cache
// can be asserted.
type fakeSettings struct {
	corev1.SettingsServiceClient
	enabled bool
	message string
	calls   int
	err     error
}

func (f *fakeSettings) GetGlobalSettings(_ context.Context, _ *corev1.GetGlobalSettingsRequest, _ ...grpc.CallOption) (*corev1.GetGlobalSettingsResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &corev1.GetGlobalSettingsResponse{Settings: &corev1.GlobalSettings{
		Maintenance: &corev1.Maintenance{Enabled: f.enabled, Message: f.message},
	}}, nil
}

// ctxWithRoles is a context carrying a principal with roles, as
// Authenticate leaves it.
func ctxWithRoles(t *testing.T, roles ...string) context.Context {
	t.Helper()
	return principal.WithClaims(context.Background(), principal.Static{UserIDValue: "u1", RolesValue: roles})
}

// withOp attaches a gqlgen operation context whose top-level selections are the
// named root fields, so the gate can inspect them.
func withOp(ctx context.Context, fields ...string) context.Context {
	sel := ast.SelectionSet{}
	for _, f := range fields {
		sel = append(sel, &ast.Field{Name: f})
	}
	return graphql.WithOperationContext(ctx, &graphql.OperationContext{
		Operation: &ast.OperationDefinition{Operation: ast.Query, SelectionSet: sel},
	})
}

// run invokes the middleware with a next() that records whether it was called,
// and returns the response plus that flag.
func run(g *maintenance.Gate, ctx context.Context) (*graphql.Response, bool) {
	called := false
	next := func(c context.Context) graphql.ResponseHandler {
		called = true
		return graphql.OneShot(&graphql.Response{})
	}
	resp := g.Middleware()(ctx, next)(ctx)
	return resp, called
}

func TestGate_MaintenanceOff_PassesThrough(t *testing.T) {
	g := maintenance.NewGate(&fakeSettings{enabled: false}, time.Minute)
	_, called := run(g, withOp(ctxWithRoles(t, "reader"), "policies"))
	require.True(t, called, "next must run when maintenance is off")
}

func TestGate_SiteAdmin_PassesThrough(t *testing.T) {
	g := maintenance.NewGate(&fakeSettings{enabled: true, message: "down"}, time.Minute)
	_, called := run(g, withOp(ctxWithRoles(t, "site-admin"), "setGlobalSettings"))
	require.True(t, called, "site-admin must pass during maintenance")
}

func TestGate_NonAdminBlocked_WithMaintenanceCode(t *testing.T) {
	g := maintenance.NewGate(&fakeSettings{enabled: true, message: "down for repairs"}, time.Minute)
	resp, called := run(g, withOp(ctxWithRoles(t, "admin"), "policies"))
	require.False(t, called, "non-site-admin must be blocked")
	require.Len(t, resp.Errors, 1)
	require.Equal(t, "MAINTENANCE", resp.Errors[0].Extensions["code"])
	require.Equal(t, "down for repairs", resp.Errors[0].Extensions["message"])
}

func TestGate_WhitelistedFields_PassForNonAdmin(t *testing.T) {
	g := maintenance.NewGate(&fakeSettings{enabled: true}, time.Minute)
	for _, f := range []string{"globalSettings", "me", "__schema"} {
		_, called := run(g, withOp(ctxWithRoles(t, "reader"), f))
		require.True(t, called, "%s must be whitelisted during maintenance", f)
	}
	_, called := run(g, withOp(ctxWithRoles(t, "reader"), "me", "policies"))
	require.False(t, called, "mixed selection must be blocked")
}

func TestGate_ReadError_FailsOpen(t *testing.T) {
	g := maintenance.NewGate(&fakeSettings{err: errors.New("core down")}, time.Minute)
	_, called := run(g, withOp(ctxWithRoles(t, "reader"), "policies"))
	require.True(t, called, "a settings read error must fail open (do not block)")
}

func TestGate_CachesWithinTTL(t *testing.T) {
	fs := &fakeSettings{enabled: true}
	g := maintenance.NewGate(fs, time.Minute)
	for range 5 {
		run(g, withOp(ctxWithRoles(t, "reader"), "globalSettings"))
	}
	require.Equal(t, 1, fs.calls, "settings must be read at most once per TTL")
}

func TestGate_Status_ReflectsState(t *testing.T) {
	g := maintenance.NewGate(&fakeSettings{enabled: true, message: "soon"}, time.Minute)
	enabled, msg := g.Status(context.Background())
	require.True(t, enabled)
	require.Equal(t, "soon", msg)
}

func TestGate_StatusHandler_JSON(t *testing.T) {
	g := maintenance.NewGate(&fakeSettings{enabled: true, message: "soon"}, time.Minute)
	rec := httptest.NewRecorder()
	g.StatusHandler()(rec, httptest.NewRequest(http.MethodGet, "/maintenance", nil))
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var body struct {
		Enabled bool   `json:"enabled"`
		Message string `json:"message"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body.Enabled)
	require.Equal(t, "soon", body.Message)
}

// A staged message must not leak through the UNAUTHENTICATED endpoint while
// maintenance is off — an operator can configure the notice ahead of a window.
func TestGate_StatusHandler_OmitsMessageWhenDisabled(t *testing.T) {
	g := maintenance.NewGate(&fakeSettings{enabled: false, message: "down at 9pm"}, time.Minute)
	rec := httptest.NewRecorder()
	g.StatusHandler()(rec, httptest.NewRequest(http.MethodGet, "/maintenance", nil))
	var body struct {
		Enabled bool   `json:"enabled"`
		Message string `json:"message"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.False(t, body.Enabled)
	require.Equal(t, "", body.Message)
}
