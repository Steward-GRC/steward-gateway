// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	"github.com/Steward-GRC/steward-gateway/internal/aijobs"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// AIJobResultResolver streams the terminal result of one async AI job to its
// submitter. A job that already finished is answered from GetAIJob at once.
func AIJobResultResolver(ctx context.Context, client aiv1.AiServiceClient, broker *aijobs.Broker, jobID string) (<-chan *AIJobResult, error) {
	claims, ok := subscriberClaims(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	if broker == nil {
		return nil, fmt.Errorf("ai job result stream unavailable")
	}
	actorUserID := claims.UserID()

	in, cancel := broker.Subscribe(jobID, actorUserID)

	initial, _ := client.GetAIJob(ctx, &aiv1.GetAIJobRequest{JobId: jobID})

	out := make(chan *AIJobResult, 1)
	go func() {
		defer cancel()
		defer close(out)

		if initial != nil && isTerminalJobPhase(initial.GetPhase()) {
			res := &AIJobResult{
				JobID:      jobID,
				Phase:      jobPhaseFromProto(initial.GetPhase()),
				ResultRef:  nilIfEmpty(initial.GetResultRef()),
				Error:      nilIfEmpty(initial.GetError()),
				FinishedAt: nilIfEmpty(initial.GetFinishedAt()),
			}
			select {
			case out <- res:
			case <-ctx.Done():
			}
			return
		}

		select {
		case <-ctx.Done():
			return
		case ev, ok := <-in:
			if !ok {
				return
			}
			select {
			case out <- completionToResult(ev):
			case <-ctx.Done():
			}
		}
	}()
	return out, nil
}

// isTerminalJobPhase reports whether a job has reached a phase from which no further events will
// follow.
func isTerminalJobPhase(p aiv1.JobPhase) bool {
	return p == aiv1.JobPhase_JOB_PHASE_SUCCEEDED || p == aiv1.JobPhase_JOB_PHASE_FAILED
}

// completionToResult maps a broker CompletionEvent to the GraphQL payload.
func completionToResult(ev aijobs.CompletionEvent) *AIJobResult {
	return &AIJobResult{
		JobID:      ev.JobID,
		Phase:      phaseFromCompletion(ev.Phase),
		ResultRef:  nilIfEmpty(ev.ResultRef),
		Error:      nilIfEmpty(ev.Error),
		FinishedAt: nilIfEmpty(ev.FinishedAt),
	}
}

// phaseFromCompletion maps the CompletionEvent's phase string ("Succeeded" / "Failed", mirroring
// PolicyAIJob.status.phase) to the GraphQL enum.
func phaseFromCompletion(phase string) AIJobPhase {
	switch phase {
	case "Succeeded":
		return AIJobPhaseAiJobPhaseSucceeded
	case "Failed":
		return AIJobPhaseAiJobPhaseFailed
	default:
		return AIJobPhaseAiJobPhasePending
	}
}

// AIJobResultContentResolver fetches a completed async AI job's generated content by resultRef
// content-fetch — the fetch-by-resultRef path the AIJobStatus/AIJobResult doc comments describe;
// that tag collides with the unrelated two-tier semantic-cache, not renumbered).
func AIJobResultContentResolver(ctx context.Context, reader *aijobs.ContentReader, resultRef string) (*AIJobResultContent, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	if reader == nil {
		return nil, fmt.Errorf("ai job result content fetch unavailable")
	}
	content, err := reader.Fetch(ctx, resultRef)
	if err != nil {
		return nil, fmt.Errorf("ai job result content: %w", err)
	}
	return &AIJobResultContent{
		Operation:  content.Operation,
		ResultJSON: content.ResultJSON,
	}, nil
}
