// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"strconv"
	"time"

	authz "github.com/Steward-GRC/steward-authz"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// retentionRequester gates the shred and legal-hold resolvers on
// compliance.manage and returns the caller as the audit requester. audit
// checks the same permission again and records every call.
func retentionRequester(ctx context.Context) (*auditv1.RequesterIdentity, error) {
	if err := authorizeOp(ctx, authz.ComplianceManage); err != nil {
		return nil, err
	}
	req, ok := requesterFromClaims(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	return req, nil
}

func legalHoldFromProto(h *auditv1.LegalHold) *AuditLegalHold {
	if h == nil {
		return nil
	}
	out := &AuditLegalHold{
		HoldUUID:      h.GetHoldUuid(),
		SubjectFilter: h.GetSubjectFilter(),
		GroupFilter:   h.GetGroupFilter(),
		Reason:        h.GetReason(),
		HeldBy:        h.GetHeldBy(),
	}
	if t := h.GetCreatedAt(); t != nil {
		out.CreatedAt = t.AsTime().UTC().Format(time.RFC3339)
	}
	if t := h.GetReleasedAt(); t != nil {
		released := t.AsTime().UTC().Format(time.RFC3339)
		out.ReleasedAt = &released
	}
	return out
}

// ShredAuditSubjectResolver crypto-shreds a subject: audit erases its key and
// clears its personal data from activity records.
func ShredAuditSubjectResolver(ctx context.Context, client auditv1.AuditServiceClient, subjectKey, reason string) (*AuditShredResult, error) {
	req, err := retentionRequester(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.ShredSubject(ctx, &auditv1.ShredSubjectRequest{SubjectKey: subjectKey, Reason: reason, Requester: req})
	if err != nil {
		return nil, err
	}
	return &AuditShredResult{
		RecordsTombstoned: int(resp.GetRecordsTombstoned()),
		RecordID:          strconv.FormatInt(resp.GetRecordId(), 10),
	}, nil
}

// CreateAuditLegalHoldResolver places a hold that stops the retention purge
// for the records it matches. An unset filter matches everything.
func CreateAuditLegalHoldResolver(ctx context.Context, client auditv1.AuditServiceClient, subjectFilter, groupFilter *string, reason string) (*AuditLegalHold, error) {
	req, err := retentionRequester(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.CreateLegalHold(ctx, &auditv1.CreateLegalHoldRequest{
		SubjectFilter: derefOrEmpty(subjectFilter),
		GroupFilter:   derefOrEmpty(groupFilter),
		Reason:        reason,
		Requester:     req,
	})
	if err != nil {
		return nil, err
	}
	return legalHoldFromProto(resp.GetHold()), nil
}

// AuditLegalHoldsResolver lists the holds, oldest first; released holds only
// when includeReleased is set.
func AuditLegalHoldsResolver(ctx context.Context, client auditv1.AuditServiceClient, includeReleased *bool) ([]*AuditLegalHold, error) {
	req, err := retentionRequester(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.ListLegalHolds(ctx, &auditv1.ListLegalHoldsRequest{
		IncludeReleased: includeReleased != nil && *includeReleased,
		Requester:       req,
	})
	if err != nil {
		return nil, err
	}
	out := make([]*AuditLegalHold, 0, len(resp.GetHolds()))
	for _, h := range resp.GetHolds() {
		out = append(out, legalHoldFromProto(h))
	}
	return out, nil
}

// ReleaseAuditLegalHoldResolver lifts a hold.
func ReleaseAuditLegalHoldResolver(ctx context.Context, client auditv1.AuditServiceClient, holdUUID string) (*AuditLegalHold, error) {
	req, err := retentionRequester(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.ReleaseLegalHold(ctx, &auditv1.ReleaseLegalHoldRequest{HoldUuid: holdUUID, Requester: req})
	if err != nil {
		return nil, err
	}
	return legalHoldFromProto(resp.GetHold()), nil
}
