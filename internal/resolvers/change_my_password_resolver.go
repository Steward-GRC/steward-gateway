// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// ChangeMyPasswordResolver changes the signed-in person's own password through
// identity. Identity binds the user to the forwarded actor, checks the current
// password first and applies its password policy; its coded refusals
// (CURRENT_PASSWORD_WRONG, PASSWORD_TOO_WEAK, NO_LOCAL_PASSWORD,
// PASSWORD_CHANGE_UNAVAILABLE) are relayed untouched. Neither password is ever
// logged. Self-service: no site-admin gate, and refused while acting as
// someone (impersonation denylist).
func ChangeMyPasswordResolver(ctx context.Context, logger log.Logger, read identityv1.IdentityReadServiceClient, currentPassword, newPassword string) (bool, error) {
	lg := logger.Ctx(ctx)
	if read == nil {
		return false, status.Error(codes.Unavailable, "identity service unavailable")
	}
	if currentPassword == "" || newPassword == "" {
		lg.Debug("changeMyPassword refused: empty password")
		return false, status.Error(codes.InvalidArgument, "current_password and new_password required")
	}
	lg.Debug("changeMyPassword: calling identity")
	if _, err := read.ChangeMyPassword(ctx, &identityv1.ChangeMyPasswordRequest{CurrentPassword: currentPassword, NewPassword: newPassword}); err != nil {
		lg.Debug("changeMyPassword: identity refused", log.F("grpc_code", status.Code(err).String()))
		return false, err
	}
	lg.Info("changeMyPassword: password changed")
	return true, nil
}
