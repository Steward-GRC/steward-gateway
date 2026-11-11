// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authz "github.com/Steward-GRC/steward-authz"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
)

const (
	// historyDefaultPage is the page size when the caller sends none or one out
	// of range, the same rule audit applies.
	historyDefaultPage = 50
	// historyMaxPage is the largest page a caller may ask for.
	historyMaxPage = 200
	// historyFetchCap bounds the records read from audit for one policy, so a
	// history with no end cannot hold a request open. Reaching it is logged.
	historyFetchCap = 5000
)

// PolicyHistoryResolver answers a policy's whole history in one list
// (steward-gateway#48). Core files a policy's creation and a discarded draft
// under policy:<id>; its draft saves, publishes and status changes, and every
// event workflow writes for an approval run, under policy_version:<id>. Audit
// matches one exact subject a query, so the gateway asks once for the policy
// and once for each version it may show, and merges the answers newest first.
//
// Access is the policy's read decision, the one policy applies: a caller who
// cannot read it gets NotFound before audit is asked. A draft, a version in
// review or a rejected one is shown to an editor or the holder of a pending
// approval seat on it, as the version reads are (#44, #104); for anyone else
// its records are left out and audit is not asked for them.
//
// Audit only serves a caller with audit.read, which an ordinary reader lacks.
// Once the policy read has passed, the gateway therefore asks audit as the
// caller with a role that holds audit.read; the audit record carries no
// attributes or personal data on the wire, and the subjects asked for are
// fixed here, so the caller cannot widen the read. Record text is never logged.
func PolicyHistoryResolver(
	ctx context.Context,
	logger log.Logger,
	client auditv1.AuditServiceClient,
	identity identityv1.IdentityReadServiceClient,
	categories corev1.CategoryServiceClient,
	policies corev1.PolicyServiceClient,
	tmpls corev1.TemplateServiceClient,
	admin identityv1.IdentityAdminServiceClient,
	workflow workflowv1.WorkflowServiceClient,
	policyID string,
	pageSize *int,
	pageToken *string,
) (*AuditQueryPage, error) {
	start := time.Now()
	req, ok := requesterFromClaims(ctx)
	if !ok {
		logger.Debug("policy history refused: no signed-in user", log.F("policy_id", policyID))
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	size := historyDefaultPage
	if pageSize != nil && *pageSize >= 1 && *pageSize <= historyMaxPage {
		size = *pageSize
	}
	var before int64
	if tok := derefOrEmpty(pageToken); tok != "" {
		n, err := strconv.ParseInt(tok, 10, 64)
		if err != nil || n <= 0 {
			logger.Debug("policy history refused: bad page token", log.F("policy_id", policyID))
			return nil, status.Error(codes.InvalidArgument, "invalid page token")
		}
		before = n
	}
	logger.Debug("policy history", log.F("policy_id", policyID), log.F("page_size", size), log.F("after_cursor", before > 0))

	p, err := GetPolicy(ctx, policies, categories, admin, identity, workflow, policyID)
	if err != nil {
		logger.Debug("policy history: policy not readable", log.F("policy_id", policyID), log.F("code", status.Code(err).String()))
		return nil, err
	}

	versionIDs, err := historyVersionIDs(ctx, logger, policies, workflow, p)
	if err != nil {
		return nil, err
	}
	subjects := make([]string, 0, len(versionIDs)+1)
	subjects = append(subjects, "policy:"+policyID)
	for _, id := range versionIDs {
		subjects = append(subjects, "policy_version:"+id)
	}

	// Audit's role check reads the roles the gateway names; the caller's own
	// are replaced for this read only, after the policy read decision above.
	req.Roles = []string{string(authz.RoleComplianceAdmin)}

	merged, err := historyRecords(ctx, logger, client, req, subjects)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(merged, func(a, b *auditv1.AuditRecord) int {
		switch {
		case a.GetId() > b.GetId():
			return -1
		case a.GetId() < b.GetId():
			return 1
		}
		return 0
	})
	if before > 0 {
		merged = slices.DeleteFunc(merged, func(r *auditv1.AuditRecord) bool { return r.GetId() >= before })
	}
	next := ""
	if len(merged) > size {
		merged = merged[:size]
		next = strconv.FormatInt(merged[size-1].GetId(), 10)
	}

	labels := newLabelResolver(identity, categories, policies, tmpls)
	records := make([]*AuditRecord, 0, len(merged))
	for _, r := range merged {
		rec := auditRecordFromProto(r)
		enrichAuditRecord(ctx, labels, rec)
		records = append(records, rec)
	}
	logger.Debug("policy history served",
		log.F("policy_id", policyID), log.F("subjects", len(subjects)), log.F("returned", len(records)),
		log.F("more", next != ""), log.F("duration_ms", time.Since(start).Milliseconds()))
	return &AuditQueryPage{Records: records, NextPageToken: next}, nil
}

// historyVersionIDs lists the versions of p whose records the caller may see:
// every version core lists as published or superseded, the unpublished ones
// (in review, rejected) only for an editor or a pending approver, and the
// working draft the read model left on the policy, which core's list omits.
func historyVersionIDs(ctx context.Context, logger log.Logger, policies corev1.PolicyServiceClient, workflow workflowv1.WorkflowServiceClient, p *Policy) ([]string, error) {
	resp, err := policies.ListPolicyVersions(ctx, &corev1.ListPolicyVersionsRequest{PolicyId: p.ID})
	if err != nil {
		logger.Error(err, "policy history: core version list failed", log.F("policy_id", p.ID), log.F("code", status.Code(err).String()))
		return nil, fmt.Errorf("core list policy versions: %w", err)
	}
	editor := p.ViewerCan != nil && p.ViewerCan.Edit
	seats := newPendingSeats(workflow)
	ids := make([]string, 0, len(resp.GetVersions())+1)
	for _, v := range resp.GetVersions() {
		id := v.GetId()
		if id == "" || slices.Contains(ids, id) {
			continue
		}
		if unpublishedVersionStatuses[versionStatusName(v.GetStatus())] && !editor && !seats.holds(ctx, id) {
			log.Trace(logger, "policy history: unpublished version left out",
				log.F("policy_id", p.ID), log.F("policy_version_id", id))
			continue
		}
		ids = append(ids, id)
	}
	// GetPolicy already cleared the draft pointer for a caller who may not see
	// the draft, so what is left is theirs to read.
	if d := derefOrEmpty(p.CurrentDraftVersionID); d != "" && !slices.Contains(ids, d) {
		ids = append(ids, d)
	}
	logger.Debug("policy history: versions in scope", log.F("policy_id", p.ID), log.F("versions", len(ids)))
	return ids, nil
}

// historyRecords reads every record of each subject from audit, following the
// page tokens, and returns them unsorted with no id twice. A failed read fails
// the whole query: a timeline with a subject missing would look complete.
func historyRecords(ctx context.Context, logger log.Logger, client auditv1.AuditServiceClient, req *auditv1.RequesterIdentity, subjects []string) ([]*auditv1.AuditRecord, error) {
	seen := map[int64]bool{}
	var out []*auditv1.AuditRecord
	for _, subject := range subjects {
		token := ""
		for {
			started := time.Now()
			resp, err := client.QueryAuditLog(ctx, &auditv1.QueryAuditLogRequest{
				Subject:   subject,
				PageSize:  historyMaxPage,
				PageToken: token,
				Requester: req,
			})
			if err != nil {
				logger.Error(err, "policy history: audit query failed",
					log.F("subject", subject), log.F("code", status.Code(err).String()),
					log.F("duration_ms", time.Since(started).Milliseconds()))
				return nil, fmt.Errorf("audit query: %w", err)
			}
			log.Trace(logger, "policy history: audit page",
				log.F("subject", subject), log.F("records", len(resp.GetRecords())),
				log.F("duration_ms", time.Since(started).Milliseconds()))
			for _, r := range resp.GetRecords() {
				if !seen[r.GetId()] {
					seen[r.GetId()] = true
					out = append(out, r)
				}
			}
			token = resp.GetNextPageToken()
			if token == "" {
				break
			}
			if len(out) >= historyFetchCap {
				logger.Warn("policy history: record cap reached, older records not read",
					log.F("subject", subject), log.F("cap", historyFetchCap))
				return out, nil
			}
		}
	}
	return out, nil
}
