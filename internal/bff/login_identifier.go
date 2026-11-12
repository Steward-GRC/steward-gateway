// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"strings"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// resolveLoginIdentifier turns what the user typed on the sign-in page into the
// identifier Kratos verifies. Kratos knows only the email, so a username is
// mapped through identity first. Anything with an "@" is an email already and
// never calls identity.
//
// It always returns something Kratos can be asked about. An unknown, disabled,
// deleted or SSO username (identity answers an empty email) and a failed lookup
// both return the typed value unchanged, so the caller still runs the Kratos
// login flow and the failure is the one a wrong password gives: same status,
// same body, same work. A lookup failure is logged without the username.
func (h *Handler) resolveLoginIdentifier(ctx context.Context, typed string) string {
	name := strings.TrimSpace(typed)
	if name == "" || strings.Contains(name, "@") || h.Identity == nil {
		return typed
	}
	resp, err := h.Identity.ResolveLoginEmail(ctx, &identityv1.ResolveLoginEmailRequest{Username: name})
	if err != nil {
		h.logger(ctx).Warn("sign-in: username lookup failed, using the typed value", log.F("flow", "local_login"), errField(err), log.F("reason", "identity_unreachable"))
		return typed
	}
	if email := resp.GetEmail(); email != "" {
		return email
	}
	return typed
}
