// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"errors"
	"fmt"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

	// ai answers NotFound for a job the caller did not submit. Return that (and any other
	// failure) to the caller, like the mock, instead of holding a stream that never delivers.
	// The error layer maps the status; the job id is an opaque key, no job content is involved.
	initial, err := client.GetAIJob(ctx, &aiv1.GetAIJobRequest{JobId: jobID})
	if err != nil {
		cancel()
		return nil, err
	}

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

// errJobResultNotFound is the one refusal for a result ref that does not resolve and one that
// belongs to someone else, so a ref reveals nothing about another user's job.
var errJobResultNotFound = status.Error(codes.NotFound, "job result not found")

// AIJobResultContentResolver fetches a completed async AI job's generated content by resultRef
// (the fetch-by-resultRef path the AIJobStatus/AIJobResult doc comments describe), and only for the
// user who submitted the job. The ref is an opaque key: ownership comes from the owner_user_id the
// ai service stores in the result envelope, compared with the caller's user id. A missing result, a
// different owner, an envelope with no owner and a caller with no id are all refused the same way.
func AIJobResultContentResolver(ctx context.Context, logger log.Logger, reader *aijobs.ContentReader, client aiv1.AiServiceClient, resultRef string, jobID *string) (*AIJobResultContent, error) {
	lg := logger.Ctx(ctx)
	claims, ok := principal.FromContext(ctx)
	if !ok || claims == nil {
		lg.Debug("ai job result content refused", log.F("reason", "unauthenticated"))
		return nil, fmt.Errorf("unauthenticated")
	}
	if reader == nil {
		return nil, fmt.Errorf("ai job result content fetch unavailable")
	}
	callerID := claims.UserID()
	if callerID == "" {
		lg.Debug("ai job result content refused", log.F("reason", "caller_has_no_user"))
		return nil, errJobResultNotFound
	}
	lg.Debug("ai job result content fetch")
	content, err := reader.Fetch(ctx, resultRef)
	if err != nil {
		if errors.Is(err, aijobs.ErrResultNotFound) {
			if jobID != nil && *jobID != "" && client != nil {
				return storedJobResult(ctx, lg, client, *jobID)
			}
			lg.Debug("ai job result content refused", log.F("reason", "no_such_result"))
			return nil, errJobResultNotFound
		}
		lg.Error(err, "ai job result content read failed")
		return nil, fmt.Errorf("ai job result content: %w", err)
	}
	if !content.OwnedBy(callerID) {
		reason := "owner_mismatch"
		if content.OwnerUserID == "" {
			reason = "result_has_no_owner"
		}
		lg.Debug("ai job result content refused", log.F("reason", reason))
		return nil, errJobResultNotFound
	}
	lg.Debug("ai job result content served", log.F("operation", content.Operation))
	return &AIJobResultContent{
		Operation:  content.Operation,
		ResultJSON: content.ResultJSON,
	}, nil
}

// storedJobResult is the fallback for a result whose cached copy has expired: ai answers from the
// result it stored for the job, and only for the job's submitter (the caller identity travels on
// the context like every other ai call). A foreign or unknown job comes back as ai's not-found
// error and is relayed untouched. Only ids are logged, never content.
func storedJobResult(ctx context.Context, lg log.Logger, client aiv1.AiServiceClient, jobID string) (*AIJobResultContent, error) {
	lg.Debug("ai job result content cache miss, reading the stored result", log.F("job_id", jobID))
	resp, err := client.GetAIJobResult(ctx, &aiv1.GetAIJobResultRequest{JobId: jobID})
	if err != nil {
		lg.Debug("ai job stored result refused", log.F("job_id", jobID), log.F("code", status.Code(err).String()))
		return nil, err
	}
	lg.Debug("ai job stored result served", log.F("job_id", jobID), log.F("operation", resp.GetOperation()))
	return &AIJobResultContent{
		Operation:  resp.GetOperation(),
		ResultJSON: resp.GetResultJson(),
	}, nil
}
