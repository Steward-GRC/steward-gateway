// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	"github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"google.golang.org/grpc/status"
)

func ctxWithStubClaims(t *testing.T, c principal.Static) context.Context {
	t.Helper()
	return principal.WithClaims(context.Background(), c)
}

func ctxWithRoles(t *testing.T, uid string, roles []string) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: uid, RolesValue: roles})
}

func ctxWithClaims(t *testing.T, uid string, roles ...string) context.Context {
	t.Helper()
	return ctxWithRoles(t, uid, roles)
}

func ctxWithUser(t *testing.T, uid string) context.Context {
	t.Helper()
	return ctxWithUserEmail(t, uid, "")
}

func ctxWithUserEmail(t *testing.T, uid, email string) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: uid, EmailValue: email, RolesValue: []string{"dev"}, GroupsValue: []string{"g1"}})
}

// gatewayStatus is the status the gateway's error presenter sends for err.
func gatewayStatus(err error) *status.Status {
	return apperrgrpc.Status(context.Background(), errcodes.Registry(), err, errcodes.CodeInternal, errcodes.Domain)
}

// wireStatus is the status a client sees for err: a gateway-coded error goes
// through the presenter, a relayed backend status passes unchanged.
func wireStatus(err error) *status.Status {
	if _, ok := apperr.Code(err); ok {
		return gatewayStatus(err)
	}
	return status.Convert(err)
}

func gatewayEntry(code int) apperr.Entry {
	e, _ := errcodes.Registry().Describe(code)
	return e
}
