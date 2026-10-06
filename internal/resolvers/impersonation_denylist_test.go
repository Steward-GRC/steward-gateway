// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	"github.com/Bugs5382/go-apperr"
	"github.com/stretchr/testify/require"
	"github.com/vektah/gqlparser/v2/ast"

	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// impersonatingCtx returns a context that is "acting as another user": the
// effective claims are the target, and the real admin is stashed as the
// impersonator (the signal denyIfImpersonating keys off).
func impersonatingCtx() context.Context {
	return principal.WithImpersonator(context.Background(), principal.Static{UserIDValue: "admin"})
}

// impWithOp attaches a gqlgen operation context whose top-level selections are
// the named root fields, mirroring how the guard middleware inspects a request.
func impWithOp(ctx context.Context, fields ...string) context.Context {
	sel := ast.SelectionSet{}
	for _, f := range fields {
		sel = append(sel, &ast.Field{Name: f})
	}
	return graphql.WithOperationContext(ctx, &graphql.OperationContext{
		Operation: &ast.OperationDefinition{Operation: ast.Mutation, SelectionSet: sel},
	})
}

// runImpGuard invokes the guard middleware with a next() that records whether it
// ran, returning the response and that flag.
func runImpGuard(ctx context.Context) (*graphql.Response, bool) {
	called := false
	next := func(c context.Context) graphql.ResponseHandler {
		called = true
		return graphql.OneShot(&graphql.Response{})
	}
	resp := ImpersonationDenylistMiddleware()(ctx, next)(ctx)
	return resp, called
}

func TestDenyIfImpersonating_DenylistedFieldsBlocked(t *testing.T) {
	ctx := impersonatingCtx()
	require.NotEmpty(t, impersonationDenylist, "denylist must not be empty")
	for name := range impersonationDenylist {
		require.Error(t, denyIfImpersonating(ctx, name), "%q must be blocked while impersonating", name)
	}
}

func TestDenyIfImpersonating_NonDenylistedAllowed(t *testing.T) {
	ctx := impersonatingCtx()
	// NB: these must be real, non-denylisted root fields. "acknowledgePolicy"
	// used to stand in here and exists nowhere in schema.graphqls — a phantom
	// name that read as "acknowledgment mutations are deliberately allowed
	// while impersonating". The real field is `recordAck`, which is now denied
	//, so the placeholder is replaced with `recordView`.
	for _, name := range []string{"recordView", "me", "createPolicy", "updateUserProfile"} {
		require.NoError(t, denyIfImpersonating(ctx, name), "%q is not high-risk and must be allowed", name)
	}
}

func TestDenyIfImpersonating_StopAllowedStartDenied(t *testing.T) {
	ctx := impersonatingCtx()
	// Regression: Stop must always be able to end the session,
	// otherwise the Stop button is a no-op and identity never reverts.
	require.NoError(t, denyIfImpersonating(ctx, "stopImpersonation"),
		"stopImpersonation must be allowed while impersonating")
	require.Error(t, denyIfImpersonating(ctx, "startImpersonation"),
		"startImpersonation must stay denied (no nested impersonation)")
}

func TestDenyIfImpersonating_NotImpersonating(t *testing.T) {
	for name := range impersonationDenylist {
		require.NoError(t, denyIfImpersonating(context.Background(), name),
			"%q must be allowed when NOT impersonating", name)
	}
}

func TestImpersonationDenylistMiddleware_BlocksDenylistedWhileImpersonating(t *testing.T) {
	resp, called := runImpGuard(impWithOp(impersonatingCtx(), "resetUserPassword"))
	require.False(t, called, "denylisted mutation must be rejected before the resolver runs")
	require.NotEmpty(t, resp.Errors)
	require.Contains(t, resp.Errors[0].Message, "acting as another user")

	// The refusal carries the coded extensions (IMPERSONATION_DENIED,
	// 1234) so the client branches on the code, not the message.
	ext := resp.Errors[0].Extensions
	require.Equal(t, deniedEntry().Symbol, ext["code"])
	require.Equal(t, deniedEntry().Code, ext["codeNum"])
	require.Equal(t, errcodes.Domain, ext["domain"])
	require.Equal(t, "resetUserPassword", ext["field"])
}

func TestImpersonationDenylistMiddleware_AllowsNormalWhileImpersonating(t *testing.T) {
	_, called := runImpGuard(impWithOp(impersonatingCtx(), "setDigestWindow"))
	require.True(t, called, "a normal mutation must pass through while impersonating")
}

func TestImpersonationDenylistMiddleware_AllowsDenylistedWhenNotImpersonating(t *testing.T) {
	_, called := runImpGuard(impWithOp(context.Background(), "resetUserPassword"))
	require.True(t, called, "denylist only applies while impersonating")
}

// TestDenyIfImpersonating_RecordAckDenied is the security half of
// . `acknowledgments.user_id` is a legal attestation and
// stays the target's row by design, so attribution alone cannot fix an
// impersonated acknowledgment — it only records the forgery. The mutation has
// to be refused outright: a site admin must not be able to create an
// attestation in a user's name.
//
// The field name is the GraphQL root field `recordAck`
// (graphql/schema.graphqls, `extend type Mutation`), not the gRPC method
// `RecordAck` — the denylist is keyed by GraphQL field name.
func TestDenyIfImpersonating_RecordAckDenied(t *testing.T) {
	ctx := impersonatingCtx()

	err := denyIfImpersonating(ctx, "recordAck")
	require.Error(t, err, "recordAck must be refused while impersonating: an acknowledgment is a legal attestation and may not be created on another user's behalf")
	require.Contains(t, err.Error(), "acting as another user")

	// And it must still be permitted for a normal, non-impersonated session —
	// the guard blocks impersonation, it does not disable acknowledgment.
	require.NoError(t, denyIfImpersonating(context.Background(), "recordAck"),
		"recordAck must remain allowed when NOT impersonating")
}

// TestImpersonationDenylistMiddleware_BlocksRecordAck proves the refusal lands
// at the operation layer, before the resolver runs, and carries the coded
// extensions.
func TestImpersonationDenylistMiddleware_BlocksRecordAck(t *testing.T) {
	resp, called := runImpGuard(impWithOp(impersonatingCtx(), "recordAck"))
	require.False(t, called, "impersonated recordAck must be rejected before the resolver runs — no acknowledgment row may be written")
	require.NotEmpty(t, resp.Errors)
	require.Contains(t, resp.Errors[0].Message, "acting as another user")

	ext := resp.Errors[0].Extensions
	require.Equal(t, deniedEntry().Symbol, ext["code"])
	require.Equal(t, deniedEntry().Code, ext["codeNum"])
	require.Equal(t, errcodes.Domain, ext["domain"])
	require.Equal(t, "recordAck", ext["field"])
}

// TestImpersonationDenylistMiddleware_AllowsRecordViewWhileImpersonating pins
// the boundary: `recordView` writes `policy_views`, which is read telemetry
// rather than an attestation. Denying it would corrupt the read-coverage
// metric, so it stays allowed.
func TestImpersonationDenylistMiddleware_AllowsRecordViewWhileImpersonating(t *testing.T) {
	_, called := runImpGuard(impWithOp(impersonatingCtx(), "recordView"))
	require.True(t, called, "recordView is read telemetry and must stay allowed while impersonating")
}

func deniedEntry() apperr.Entry {
	e, _ := errcodes.Registry().Describe(errcodes.CodeImpersonationDenied)
	return e
}
