// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package maintenance holds the gateway side of maintenance mode: a cached
// read of core's setting, a public status route and a GraphQL gate that lets
// only site admins through.
package maintenance

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"

	stewardauthz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// whitelist names the root fields a locked-out (non-site-admin) caller may still
// run during maintenance so the lockdown screen can render and learn its role.
var whitelist = map[string]bool{
	"globalSettings": true,
	"me":             true,
	"__schema":       true,
	"__type":         true,
	"__typename":     true,
}

// Gate reads maintenance state (cached) and decides whether an operation may run.
type Gate struct {
	client corev1.SettingsServiceClient
	ttl    time.Duration
	now    func() time.Time

	mu        sync.Mutex
	cached    state
	fetchedAt time.Time
	hasCache  bool
}

type state struct {
	enabled bool
	message string
}

// NewGate builds a Gate that reads from client and caches the result for ttl.
func NewGate(client corev1.SettingsServiceClient, ttl time.Duration) *Gate {
	return &Gate{client: client, ttl: ttl, now: time.Now}
}

// read returns the current maintenance state, cached for ttl. On a read error it
// returns enabled=false (fail-open): maintenance is an explicit operator action,
// so the safe default on uncertainty is to keep serving.
func (g *Gate) read(ctx context.Context) state {
	g.mu.Lock()
	if g.hasCache && g.now().Sub(g.fetchedAt) < g.ttl {
		st := g.cached
		g.mu.Unlock()
		return st
	}
	g.mu.Unlock()

	resp, err := g.client.GetGlobalSettings(ctx, &corev1.GetGlobalSettingsRequest{})
	if err != nil {
		return state{}
	}
	m := resp.GetSettings().GetMaintenance()
	st := state{enabled: m.GetEnabled(), message: m.GetMessage()}

	g.mu.Lock()
	g.cached = st
	g.fetchedAt = g.now()
	g.hasCache = true
	g.mu.Unlock()
	return st
}

// Status returns the current maintenance state (cached). Fail-open: (false,"")
// on read error, same as the middleware.
func (g *Gate) Status(ctx context.Context) (bool, string) {
	st := g.read(ctx)
	return st.enabled, st.message
}

// StatusHandler serves maintenance state as JSON for UNAUTHENTICATED clients, so
// the web can lock down before sign-in. Mounted outside Authenticate.
func (g *Gate) StatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enabled, message := g.Status(r.Context())
		if !enabled {
			message = ""
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"enabled": enabled, "message": message})
	}
}

// Middleware returns a gqlgen operation middleware that blocks non-site-admin
// operations while maintenance is enabled.
func (g *Gate) Middleware() graphql.OperationMiddleware {
	return func(ctx context.Context, next graphql.OperationHandler) graphql.ResponseHandler {
		st := g.read(ctx)
		if !st.enabled || g.allowed(ctx) {
			return next(ctx)
		}
		err := gqlerror.Errorf("the system is in maintenance mode")
		err.Extensions = map[string]any{"code": "MAINTENANCE", "message": st.message}
		return graphql.OneShot(&graphql.Response{Errors: gqlerror.List{err}})
	}
}

// allowed reports whether the operation may run during maintenance: site-admins
// always may; everyone else only when every top-level selection is whitelisted.
func (g *Gate) allowed(ctx context.Context) bool {
	if c, ok := principal.FromContext(ctx); ok && c != nil && principal.HasRole(c, string(stewardauthz.RoleSiteAdmin)) {
		return true
	}
	oc := graphql.GetOperationContext(ctx)
	if oc == nil || oc.Operation == nil {
		return false
	}
	for _, sel := range oc.Operation.SelectionSet {
		f, ok := sel.(*ast.Field)
		if !ok || !whitelist[f.Name] {
			return false
		}
	}
	return true
}

// Register mounts the public status route on mux. The GraphQL gate is added
// with Middleware.
func (g *Gate) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /maintenance", g.StatusHandler())
}
