// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	authz "github.com/Steward-GRC/steward-authz"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// requesterFromClaims projects principal.Claims onto the audit RequesterIdentity wire message.
func requesterFromClaims(ctx context.Context) (*auditv1.RequesterIdentity, bool) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, false
	}
	return &auditv1.RequesterIdentity{
		UserId: claims.UserID(),
		Roles:  append([]string(nil), claims.Roles()...),
		Groups: append([]string(nil), claims.Groups()...),
	}, true
}

// parseRecordID converts a string-typed record id (as the GraphQL surface exposes int64 ids) into
// the proto int64.
func parseRecordID(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid record id %q: %w", s, err)
	}
	return n, nil
}

func auditRecordFromProto(r *auditv1.AuditRecord) *AuditRecord {
	if r == nil {
		return nil
	}
	out := &AuditRecord{
		ID:               strconv.FormatInt(r.GetId(), 10),
		RecordUUID:       r.GetRecordUuid(),
		Tier:             r.GetTier(),
		Action:           r.GetAction(),
		ActorUserID:      r.GetActorUserId(),
		Subject:          r.GetSubject(),
		GroupID:          r.GetGroupId(),
		PrevHash:         r.GetPrevHash(),
		RecordHash:       r.GetRecordHash(),
		LegalBasisExempt: r.GetLegalBasisExempt(),
	}
	if t := r.GetOccurredAt(); t != nil {
		out.OccurredAt = t.AsTime().UTC().Format(time.RFC3339)
	}
	return out
}

func auditCheckpointFromProto(c *auditv1.Checkpoint) *AuditCheckpoint {
	if c == nil {
		return nil
	}
	out := &AuditCheckpoint{
		CheckpointUUID: c.GetCheckpointUuid(),
		MerkleRoot:     c.GetMerkleRoot(),
		AnchorType:     c.GetAnchorType(),
		AnchorURL:      c.GetAnchorUrl(),
		TsaToken:       base64.StdEncoding.EncodeToString(c.GetTsaToken()),
	}
	if t := c.GetAnchoredAt(); t != nil {
		out.AnchoredAt = t.AsTime().UTC().Format(time.RFC3339)
	}
	return out
}

// QueryAuditLogResolver returns a paged window over the audit log, filtered by optional tier /
// groupId / actorUserId / subject.
func QueryAuditLogResolver(
	ctx context.Context,
	client auditv1.AuditServiceClient,
	identity identityv1.IdentityReadServiceClient,
	groups corev1.CategoryServiceClient,
	policies corev1.PolicyServiceClient,
	tmpls corev1.TemplateServiceClient,
	tier, groupID, actorUserID, subject *string, pageSize *int, pageToken *string,
) (*AuditQueryPage, error) {
	if err := authorizeOp(ctx, authz.AuditRead); err != nil {
		return nil, err
	}
	req, ok := requesterFromClaims(ctx)
	if !ok {
		return nil, fmt.Errorf("unauthenticated")
	}
	var size int32
	if pageSize != nil {
		size = toInt32(*pageSize)
	}
	resp, err := client.QueryAuditLog(ctx, &auditv1.QueryAuditLogRequest{
		Tier:        derefOrEmpty(tier),
		GroupId:     derefOrEmpty(groupID),
		ActorUserId: derefOrEmpty(actorUserID),
		Subject:     derefOrEmpty(subject),
		PageSize:    size,
		PageToken:   derefOrEmpty(pageToken),
		Requester:   req,
	})
	if err != nil {
		return nil, fmt.Errorf("audit query: %w", err)
	}
	labels := newLabelResolver(identity, groups, policies, tmpls)
	records := make([]*AuditRecord, 0, len(resp.GetRecords()))
	for _, r := range resp.GetRecords() {
		rec := auditRecordFromProto(r)
		enrichAuditRecord(ctx, labels, rec)
		records = append(records, rec)
	}
	return &AuditQueryPage{
		Records:       records,
		NextPageToken: resp.GetNextPageToken(),
	}, nil
}

// enrichAuditRecord fills the nullable label fields on rec in place.
func enrichAuditRecord(ctx context.Context, labels *labelResolver, rec *AuditRecord) {
	if rec == nil {
		return
	}
	rec.ActorName = nilIfEmpty(labels.userName(ctx, rec.ActorUserID))
	rec.GroupName = nilIfEmpty(labels.categoryNameByID(ctx, rec.GroupID))
	rec.SubjectLabel = nilIfEmpty(labels.subjectLabel(ctx, rec.Subject))
}

// ExportAuditSegmentResolver returns a contiguous slice of records plus the checkpoints covering
// that range — the input format consumed by the offline chain verifier.
func ExportAuditSegmentResolver(ctx context.Context, client auditv1.AuditServiceClient, fromRecordID, toRecordID string) (*AuditSegment, error) {
	if err := authorizeOp(ctx, authz.AuditRead); err != nil {
		return nil, err
	}
	req, ok := requesterFromClaims(ctx)
	if !ok {
		return nil, fmt.Errorf("unauthenticated")
	}
	from, err := parseRecordID(fromRecordID)
	if err != nil {
		return nil, err
	}
	to, err := parseRecordID(toRecordID)
	if err != nil {
		return nil, err
	}
	resp, err := client.ExportAuditSegment(ctx, &auditv1.ExportAuditSegmentRequest{
		FromRecordId: from,
		ToRecordId:   to,
		Requester:    req,
	})
	if err != nil {
		return nil, fmt.Errorf("audit export: %w", err)
	}
	records := make([]*AuditRecord, 0, len(resp.GetRecords()))
	for _, r := range resp.GetRecords() {
		records = append(records, auditRecordFromProto(r))
	}
	checkpoints := make([]*AuditCheckpoint, 0, len(resp.GetCheckpoints()))
	for _, c := range resp.GetCheckpoints() {
		checkpoints = append(checkpoints, auditCheckpointFromProto(c))
	}
	return &AuditSegment{Records: records, Checkpoints: checkpoints}, nil
}

// VerifyAuditChainResolver re-walks the per-record hash chain in the supplied id range and returns
// a verdict plus any tampering errors.
func VerifyAuditChainResolver(ctx context.Context, client auditv1.AuditServiceClient, fromRecordID, toRecordID string) (*AuditChainVerification, error) {
	if err := authorizeOp(ctx, authz.AuditRead); err != nil {
		return nil, err
	}
	req, ok := requesterFromClaims(ctx)
	if !ok {
		return nil, fmt.Errorf("unauthenticated")
	}
	from, err := parseRecordID(fromRecordID)
	if err != nil {
		return nil, err
	}
	to, err := parseRecordID(toRecordID)
	if err != nil {
		return nil, err
	}
	resp, err := client.VerifyAuditChain(ctx, &auditv1.VerifyAuditChainRequest{
		FromRecordId: from,
		ToRecordId:   to,
		Requester:    req,
	})
	if err != nil {
		return nil, fmt.Errorf("audit verify chain: %w", err)
	}
	errs := append([]string(nil), resp.GetErrors()...)
	return &AuditChainVerification{
		Valid:          resp.GetValid(),
		RecordsChecked: int(resp.GetRecordsChecked()),
		Errors:         errs,
	}, nil
}
