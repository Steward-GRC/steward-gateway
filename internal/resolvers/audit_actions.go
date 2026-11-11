// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	log "github.com/Bugs5382/go-log"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// QueryAuditActionsResolver returns the distinct action codes the audit log holds, sorted, for the
// auditLog action filter. It has the same access as auditLog: audit.read, or a group manager. Audit
// itself lets any signed-in requester call ListAuditActions, so this check is the gate; a caller
// the scope check refuses, or one it cannot decide on, never reaches audit. Each code comes with a label made
// from it by AuditActionLabel, sorted by code.
func QueryAuditActionsResolver(
	ctx context.Context,
	logger log.Logger,
	client auditv1.AuditServiceClient,
	identity identityv1.IdentityReadServiceClient,
) ([]*AuditActionInfo, error) {
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
	codes := slices.DeleteFunc(slices.Clone(resp.GetActions()), func(c string) bool { return c == "" })
	slices.Sort(codes)
	actions := make([]*AuditActionInfo, 0, len(codes))
	for _, c := range codes {
		actions = append(actions, &AuditActionInfo{Code: c, Label: AuditActionLabel(c)})
	}
	lg.Debug("audit actions listed", log.F("count", len(actions)), log.F("duration", time.Since(start)))
	return actions, nil
}

// AuditActionLabel makes a readable label from an action code: the code is split on dots and
// underscores, the words are lowercased and the first is capitalised, so "policy.break_glass_read"
// becomes "Policy break glass read". Audit holds codes only, so the label is made here.
func AuditActionLabel(code string) string {
	words := strings.FieldsFunc(strings.ToLower(code), func(r rune) bool { return r == '.' || r == '_' })
	if len(words) == 0 {
		return ""
	}
	first, size := utf8.DecodeRuneInString(words[0])
	words[0] = string(unicode.ToUpper(first)) + words[0][size:]
	return strings.Join(words, " ")
}
