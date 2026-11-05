// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// pendingSeats answers whether the caller holds a pending approval seat on a
// version: a seat lets its holder read the draft it sits on until they decide
// (#44). It lifts only the editors-only rule on drafts; the policy's read
// decision (sensitivity, overrides, category rules) still applies.
//
// Workflow is asked once, on the first question, so a caller the ordinary
// rules already serve costs nothing. It fails closed: no workflow client, no
// caller or a failed lookup is no seat.
type pendingSeats struct {
	client   workflowv1.WorkflowServiceClient
	asked    bool
	versions map[string]bool
}

// newPendingSeats returns the seat lookup for one request, or nil without a
// workflow client; a nil lookup holds no seats.
func newPendingSeats(client workflowv1.WorkflowServiceClient) *pendingSeats {
	if client == nil {
		return nil
	}
	return &pendingSeats{client: client}
}

// holds reports whether the caller holds a pending seat on versionID.
func (s *pendingSeats) holds(ctx context.Context, versionID string) bool {
	if s == nil || versionID == "" {
		return false
	}
	if !s.asked {
		s.asked = true
		s.versions = s.load(ctx)
	}
	return s.versions[versionID]
}

// load lists the versions the caller holds a pending seat on. Workflow's
// pending tasks are already narrowed to the approver's undecided seats.
func (s *pendingSeats) load(ctx context.Context) map[string]bool {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil
	}
	resp, err := s.client.ListPendingTasks(ctx, &workflowv1.ListPendingTasksRequest{ApproverUserId: claims.UserID()})
	if err != nil {
		return nil
	}
	out := make(map[string]bool, len(resp.GetTasks()))
	for _, t := range resp.GetTasks() {
		if id := t.GetPolicyVersionId(); id != "" {
			out[id] = true
		}
	}
	return out
}
