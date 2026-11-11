// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"time"

	log "github.com/Bugs5382/go-log"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// QueryAuditActionsResolver returns the distinct action codes the audit log holds, sorted, for the
// auditLog action filter. It has the same access as auditLog: audit.read, or a group manager. Audit
// itself lets any signed-in requester call ListAuditActions, so this check is the gate; a caller
// the scope check refuses, or one it cannot decide on, never reaches audit. Only codes come back:
// readable labels belong to the client.
func QueryAuditActionsResolver(
	ctx context.Context,
	logger log.Logger,
	client auditv1.AuditServiceClient,
	identity identityv1.IdentityReadServiceClient,
) ([]string, error) {
	lg := logger.Ctx(ctx)
	req, err := auditReader(ctx, identity)
	if err != nil {
		lg.Debug("audit actions refused", log.F("reason", "scope_check_failed"))
		return nil, err
	}
	start := time.Now()
	resp, err := client.ListAuditActions(ctx, &auditv1.ListAuditActionsRequest{Requester: req})
	if err != nil {
		lg.Error(err, "audit actions lookup failed", log.F("duration", time.Since(start)))
		return nil, fmt.Errorf("audit actions: %w", err)
	}
	actions := append([]string{}, resp.GetActions()...)
	lg.Debug("audit actions listed", log.F("count", len(actions)), log.F("duration", time.Since(start)))
	return actions, nil
}
