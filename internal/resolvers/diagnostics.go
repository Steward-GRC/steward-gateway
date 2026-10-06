// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/diagnostics"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// diagnosticsRead builds the diagnostics payload. It takes no input: the actor
// is always the caller's own, and during act-as the real admin is the actor
// and the target is actingAs. Only typed, allow-listed fields are copied in.
func (r *Resolver) diagnosticsRead(ctx context.Context) (*Diagnostics, error) {
	eff, ok := principal.FromContext(ctx)
	if !ok || eff.UserID() == "" {
		return nil, errcodes.New(errcodes.CodeUnauthenticated)
	}
	real := eff
	admin, acting := principal.ImpersonatorFromContext(ctx)
	if acting {
		real = admin
	}
	out := &Diagnostics{
		GeneratedAt: time.Now().UTC(),
		Actor:       &DiagnosticsActor{ID: real.UserID(), Username: r.diagnosticsUsername(ctx, real), Roles: real.Roles()},
		Gateway:     &ComponentVersion{Name: "gateway", Version: "unknown", Status: ComponentStatusOk},
		Services:    []*ComponentVersion{},
		ThirdParty:  []*ComponentVersion{},
	}
	if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
		out.TraceID = sc.TraceID().String()
	}
	if acting {
		out.Actor.ActingAs = &DiagnosticsActingAs{ID: eff.UserID(), Username: r.diagnosticsUsername(ctx, eff), Roles: eff.Roles()}
	}
	if r.Diagnostics == nil {
		return out, nil
	}
	snap := r.Diagnostics.Snapshot(ctx)
	out.Gateway = componentVersion(snap.Gateway)
	if snap.Release != "" {
		out.Release = &snap.Release
	}
	if snap.Appliance != "" {
		out.Appliance = &snap.Appliance
	}
	for _, c := range snap.Services {
		out.Services = append(out.Services, componentVersion(c))
	}
	for _, c := range snap.ThirdParty {
		out.ThirdParty = append(out.ThirdParty, componentVersion(c))
	}
	return out, nil
}

// diagnosticsUsername is the user's sign-in name from identity, or the id
// when identity can't be read: the read never fails on it.
func (r *Resolver) diagnosticsUsername(ctx context.Context, c principal.Claims) string {
	if r.IdentityClient != nil {
		if res, err := r.IdentityClient.GetUser(ctx, &identityv1.GetUserRequest{UserId: c.UserID()}); err == nil {
			if u := res.GetUser().GetUsername(); u != "" {
				return u
			}
		}
	}
	return c.UserID()
}

func componentVersion(c diagnostics.Component) *ComponentVersion {
	out := &ComponentVersion{Name: c.Name, Version: c.Version, Status: ComponentStatusOk}
	if c.Status == diagnostics.StatusUnavailable {
		out.Status = ComponentStatusUnavailable
	}
	if c.Commit != "" && c.Commit != diagnostics.Unknown {
		commit := c.Commit
		out.Commit = &commit
	}
	return out
}
