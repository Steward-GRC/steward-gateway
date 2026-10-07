// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// impersonationBlockedMsg is the client-facing reason a high-risk mutation is refused while a
// site-admin is acting as another user.
const impersonationBlockedMsg = "not allowed while acting as another user"

// impersonationDenylist is the set of high-risk GraphQL mutation *field names* that are refused
// while a request is impersonating — even though writes are generally allowed during impersonation.
var impersonationDenylist = map[string]struct{}{
	"resetUserPassword": {},

	"enrollTotpBegin":          {},
	"enrollTotpConfirm":        {},
	"sendEnrollEmailOtp":       {},
	"verifyEnrollEmailOtp":     {},
	"webauthnRegisterBegin":    {},
	"webauthnRegisterFinish":   {},
	"removeFactor":             {},
	"removeWebauthnCredential": {},
	"renameMfaMethod":          {},

	"removeUserMfaFactor": {},
	"renameUserMfaFactor": {},

	"disableUser": {},
	"enableUser":  {},

	"deleteOrganization": {},
	"deleteGroupMapping": {},

	"grantRole":             {},
	"revokeRole":            {},
	"setUserPolicyOverride": {},

	"addUserToGroup":      {},
	"removeUserFromGroup": {},

	"revokeUserSessions": {},
	"revokeMagicLink":    {},

	"createLocalUser": {},

	"recordAck": {},

	"shredAuditSubject":     {},
	"createAuditLegalHold":  {},
	"releaseAuditLegalHold": {},

	"startImpersonation": {},
}

// denyIfImpersonating returns a clear error when the request is currently impersonating
// (principal.ImpersonatorFromContext is ok) AND fieldName is a high-risk mutation in the denylist.
func denyIfImpersonating(ctx context.Context, fieldName string) error {
	if _, ok := principal.ImpersonatorFromContext(ctx); !ok {
		return nil
	}
	if _, denied := impersonationDenylist[fieldName]; !denied {
		return nil
	}
	e, _ := errcodes.Registry().Describe(errcodes.CodeImpersonationDenied)
	err := gqlerror.Errorf("%s: %q is a high-risk operation", impersonationBlockedMsg, fieldName)
	err.Extensions = map[string]any{
		"code":    e.Symbol,
		"codeNum": e.Code,
		"domain":  errcodes.Domain,
		"field":   fieldName,
	}
	return err
}

// ImpersonationDenylistMiddleware returns a gqlgen operation middleware that rejects any denylisted
// top-level mutation BEFORE its resolver runs when the request is impersonating.
func ImpersonationDenylistMiddleware() graphql.OperationMiddleware {
	return func(ctx context.Context, next graphql.OperationHandler) graphql.ResponseHandler {
		if _, ok := principal.ImpersonatorFromContext(ctx); ok {
			if oc := graphql.GetOperationContext(ctx); oc != nil && oc.Operation != nil {
				for _, sel := range oc.Operation.SelectionSet {
					f, ok := sel.(*ast.Field)
					if !ok {
						continue
					}
					if err := denyIfImpersonating(ctx, f.Name); err != nil {
						gErr, ok := err.(*gqlerror.Error)
						if !ok {
							gErr = gqlerror.Errorf("%s", err.Error())
						}
						return graphql.OneShot(&graphql.Response{Errors: gqlerror.List{gErr}})
					}
				}
			}
		}
		return next(ctx)
	}
}
