// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// storedResultClient stubs only GetAIJobResult, recording each call.
type storedResultClient struct {
	aiv1.AiServiceClient
	resp  *aiv1.GetAIJobResultResponse
	err   error
	calls []string
}

func (c *storedResultClient) GetAIJobResult(_ context.Context, in *aiv1.GetAIJobResultRequest, _ ...grpc.CallOption) (*aiv1.GetAIJobResultResponse, error) {
	c.calls = append(c.calls, in.GetJobId())
	return c.resp, c.err
}

const expiredRef = "ai:job-result:pol-1:ver-1:REWRITE"

func TestAIJobResultContentResolver_ExpiredFallsBackToStoredResult(t *testing.T) {
	reader, _ := newTestContentReader(t)
	client := &storedResultClient{resp: &aiv1.GetAIJobResultResponse{Operation: "REWRITE", ResultJson: `{"sections":[]}`}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})

	got, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, client, expiredRef, strp("job-1"))
	if err != nil {
		t.Fatalf("fallback failed: %v", err)
	}
	if got.Operation != "REWRITE" || got.ResultJSON != `{"sections":[]}` {
		t.Fatalf("unexpected content: %+v", got)
	}
	if len(client.calls) != 1 || client.calls[0] != "job-1" {
		t.Fatalf("expected one GetAIJobResult(job-1), got %v", client.calls)
	}
}

func TestAIJobResultContentResolver_ExpiredWithoutJobIDUnchanged(t *testing.T) {
	reader, _ := newTestContentReader(t)
	client := &storedResultClient{resp: &aiv1.GetAIJobResultResponse{Operation: "REWRITE", ResultJson: `{}`}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})

	for _, id := range []*string{nil, strp("")} {
		_, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, client, expiredRef, id)
		requireNotFound(t, err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("ai must not be called without a jobId, got %v", client.calls)
	}
}

func TestAIJobResultContentResolver_FallbackRelaysJobNotFound(t *testing.T) {
	reader, _ := newTestContentReader(t)
	client := &storedResultClient{err: status.Error(codes.NotFound, "AI_JOB_NOT_FOUND")}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-2"})

	got, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, client, expiredRef, strp("job-1"))
	if got != nil {
		t.Fatalf("content returned with an error: %+v", got)
	}
	if err != client.err {
		t.Fatalf("error not relayed untouched: %v", err)
	}
}

func TestAIJobResultContentResolver_CacheHitIgnoresJobID(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	putResult(t, rdb, expiredRef, ownedEnvelope)
	client := &storedResultClient{err: status.Error(codes.Internal, "must not be called")}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})

	got, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, client, expiredRef, strp("job-1"))
	if err != nil || got.Operation != "REWRITE" {
		t.Fatalf("cache hit failed: %v %+v", err, got)
	}
	if len(client.calls) != 0 {
		t.Fatalf("ai called on a cache hit: %v", client.calls)
	}
}

// A cached result of another user is refused and the jobId does not reopen it.
func TestAIJobResultContentResolver_NonOwnerStillRefusedWithJobID(t *testing.T) {
	reader, rdb := newTestContentReader(t)
	putResult(t, rdb, expiredRef, ownedEnvelope)
	client := &storedResultClient{resp: &aiv1.GetAIJobResultResponse{Operation: "REWRITE", ResultJson: `{}`}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-2"})

	got, err := resolvers.AIJobResultContentResolver(ctx, log.Nop(), reader, client, expiredRef, strp("job-1"))
	requireNotFound(t, err)
	if got != nil || len(client.calls) != 0 {
		t.Fatalf("non-owner not refused cleanly: %+v calls=%v", got, client.calls)
	}
}
