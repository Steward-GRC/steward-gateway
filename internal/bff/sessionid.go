// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import "context"

// sessionIDKey is the private context key carrying the CSRF-checked BFF
// session's store id (the policy_sid cookie value, i.e. the Redis key) from
// SessionHTTP to the resolvers. Private type so it can never collide with
// another package's context keys.
type sessionIDKey struct{}

// WithSessionID returns a context carrying the validated BFF session's store
// id. SessionHTTP calls this AFTER it has validated the cookie, CSRF token and
// session liveness, so a session id in context is proof a valid session backed
// the request. The impersonation resolvers read it back (via
// SessionIDFromContext) to Save/Get the caller's server-side session — the
// single source of truth for an active "act as" record — without re-parsing
// the cookie.
func WithSessionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sessionIDKey{}, id)
}

// SessionIDFromContext returns the BFF session store id stashed by
// WithSessionID; ok=false when absent (the request never went through the
// session gate, e.g. a raw-bearer or public-op path).
func SessionIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(sessionIDKey{}).(string)
	return v, ok && v != ""
}
