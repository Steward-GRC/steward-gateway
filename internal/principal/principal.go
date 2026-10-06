// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package principal holds who a request is for. The session layer resolves
// the signed-in user from identity on every request and puts their Claims on
// the context; resolvers read them from there and never from client input.
//
// Putting Claims on the context also puts the go-grpc-actor Actor on it, so
// every backend call carries the effective user (and, during act-as, the real
// admin) without each resolver doing it.
package principal

import (
	"context"
	"slices"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
)

// ScopedRole binds a category-scoped role (author or approver) to a category
// name.
type ScopedRole struct {
	Role     string
	Category string
}

// Override is a per-policy access override. Effect is "allow" or "deny".
type Override struct {
	PolicyNumber string
	Effect       string
}

// Claims is the signed-in user's identity surface. Every slice accessor returns
// a non-nil slice.
type Claims interface {
	UserID() string
	Email() string
	// Roles are the global roles; reader is implicit and never listed.
	Roles() []string
	// Groups are the ids of the groups the user is a direct member of.
	Groups() []string
	// IdpGroups are the group names the identity provider asserted.
	IdpGroups() []string
	ScopedRoles() []ScopedRole
	// SessionID is the gateway's opaque session id; empty outside a session.
	SessionID() string
	PolicyOverrides() []Override
	// IsRoot reports the protected root site-admin.
	IsRoot() bool
	// ReadSensitive reports the individual policy.read_sensitive grant.
	ReadSensitive() bool
}

// Static is a Claims with every value set up front. The session layer builds
// one from identity's user record; tests build them directly.
type Static struct {
	UserIDValue          string
	EmailValue           string
	RolesValue           []string
	GroupsValue          []string
	IdpGroupsValue       []string
	ScopedRolesValue     []ScopedRole
	SessionIDValue       string
	PolicyOverridesValue []Override
	IsRootValue          bool
	ReadSensitiveValue   bool
}

func (s Static) UserID() string              { return s.UserIDValue }
func (s Static) Email() string               { return s.EmailValue }
func (s Static) SessionID() string           { return s.SessionIDValue }
func (s Static) IsRoot() bool                { return s.IsRootValue }
func (s Static) ReadSensitive() bool         { return s.ReadSensitiveValue }
func (s Static) Roles() []string             { return orEmpty(s.RolesValue) }
func (s Static) Groups() []string            { return orEmpty(s.GroupsValue) }
func (s Static) IdpGroups() []string         { return orEmpty(s.IdpGroupsValue) }
func (s Static) ScopedRoles() []ScopedRole   { return orEmpty(s.ScopedRolesValue) }
func (s Static) PolicyOverrides() []Override { return orEmpty(s.PolicyOverridesValue) }

func orEmpty[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// HasRole reports whether c holds the global role. A nil c holds none.
func HasRole(c Claims, role string) bool {
	return c != nil && slices.Contains(c.Roles(), role)
}

// HasScopedRole reports whether c holds role scoped to category. An empty
// category asks for the global role.
func HasScopedRole(c Claims, role, category string) bool {
	if c == nil {
		return false
	}
	if category == "" {
		return HasRole(c, role)
	}
	return slices.Contains(c.ScopedRoles(), ScopedRole{Role: role, Category: category})
}

// IsInGroup reports whether c is a direct member of the group id.
func IsInGroup(c Claims, groupID string) bool {
	return c != nil && slices.Contains(c.Groups(), groupID)
}

type claimsKey struct{}

type impersonatorKey struct{}

// FromContext returns the effective user's Claims. During act-as they are the
// target's.
func FromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(Claims)
	return c, ok && c != nil
}

// ImpersonatorFromContext returns the real admin during act-as.
func ImpersonatorFromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(impersonatorKey{}).(Claims)
	return c, ok && c != nil
}

// WithClaims returns ctx carrying c as the effective user, and the matching
// go-grpc-actor Actor for every backend call made with it. An impersonator
// already on ctx stays on the Actor.
func WithClaims(ctx context.Context, c Claims) context.Context {
	ctx = context.WithValue(ctx, claimsKey{}, c)
	return withActor(ctx)
}

// WithImpersonator returns ctx recording admin as the real user acting as the
// effective one. Call it with the target's Claims already on ctx (or set them
// after); the Actor carries both.
func WithImpersonator(ctx context.Context, admin Claims) context.Context {
	ctx = context.WithValue(ctx, impersonatorKey{}, admin)
	return withActor(ctx)
}

func withActor(ctx context.Context) context.Context {
	c, ok := FromContext(ctx)
	if !ok || c.UserID() == "" {
		return ctx
	}
	a := grpcactor.Actor{Subject: c.UserID(), Session: c.SessionID()}
	if admin, ok := ImpersonatorFromContext(ctx); ok && admin.UserID() != c.UserID() {
		a.Impersonator = admin.UserID()
		if a.Session == "" {
			a.Session = admin.SessionID()
		}
	}
	if a.Validate() != nil {
		return ctx
	}
	return grpcactor.WithActor(ctx, a)
}
