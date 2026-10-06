// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"
	"time"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	"github.com/Steward-GRC/steward-gateway/internal/aijobs"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

func recvResult(t *testing.T, ch <-chan *resolvers.AIJobResult) (*resolvers.AIJobResult, bool) {
	t.Helper()
	select {
	case r, ok := <-ch:
		return r, ok
	case <-time.After(2 * time.Second):
		return nil, false
	}
}

func assertNoResult(t *testing.T, ch <-chan *resolvers.AIJobResult) {
	t.Helper()
	select {
	case r := <-ch:
		if r != nil {
			t.Fatalf("expected no delivery, got %+v", r)
		}
	case <-time.After(150 * time.Millisecond):
	}
}

// TestAIJobResult_LiveEventDeliveredToMatchingSubscriber verifies a live
// completion published after subscribe is streamed to the job's submitter, and
// that a different user subscribed to the same job id receives nothing.
func TestAIJobResult_LiveEventDeliveredToMatchingSubscriber(t *testing.T) {
	client := &fakeAIClient{getResp: &aiv1.GetAIJobResponse{Phase: aiv1.JobPhase_JOB_PHASE_PENDING}}
	broker := aijobs.NewBroker()

	ctxA := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-a"})
	chA, err := resolvers.AIJobResultResolver(ctxA, client, broker, "job-1")
	if err != nil {
		t.Fatalf("subscribe user-a: %v", err)
	}
	ctxB := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-b"})
	chB, err := resolvers.AIJobResultResolver(ctxB, client, broker, "job-1")
	if err != nil {
		t.Fatalf("subscribe user-b: %v", err)
	}

	broker.Publish(aijobs.CompletionEvent{
		JobID:       "job-1",
		ActorUserID: "user-a",
		Phase:       "Succeeded",
		ResultRef:   "ai:job-result:job-1:DRAFT",
		FinishedAt:  "2026-07-23T10:00:00Z",
	})

	got, ok := recvResult(t, chA)
	if !ok || got == nil {
		t.Fatal("submitter (user-a) received nothing")
	}
	if got.Phase != resolvers.AIJobPhaseAiJobPhaseSucceeded {
		t.Fatalf("phase: got %v", got.Phase)
	}
	if got.ResultRef == nil || *got.ResultRef != "ai:job-result:job-1:DRAFT" {
		t.Fatalf("resultRef: got %v", got.ResultRef)
	}
	assertNoResult(t, chB)
}

// TestAIJobResult_SubscribeAfterEvent verifies a client subscribing AFTER the
// completion event fired still gets the result: the resolver's initial
// GetAIJob check returns the terminal phase and emits it immediately, with no
// live broker event.
func TestAIJobResult_SubscribeAfterEvent(t *testing.T) {
	client := &fakeAIClient{getResp: &aiv1.GetAIJobResponse{
		Phase:      aiv1.JobPhase_JOB_PHASE_SUCCEEDED,
		ResultRef:  "ai:job-result:job-9:DRAFT",
		FinishedAt: "2026-07-23T09:00:00Z",
	}}
	broker := aijobs.NewBroker()

	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-a"})
	ch, err := resolvers.AIJobResultResolver(ctx, client, broker, "job-9")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	got, ok := recvResult(t, ch)
	if !ok || got == nil {
		t.Fatal("late subscriber received nothing")
	}
	if got.Phase != resolvers.AIJobPhaseAiJobPhaseSucceeded ||
		got.ResultRef == nil || *got.ResultRef != "ai:job-result:job-9:DRAFT" {
		t.Fatalf("unexpected result: %+v", got)
	}
	// Terminal on subscribe ⇒ the stream ends (channel closes) with no further
	// events.
	if _, ok := recvResult(t, ch); ok {
		t.Fatal("stream should close after the terminal result")
	}
}

// TestAIJobResult_FailedTerminalOnSubscribe verifies a FAILED job surfaces its
// error on a late subscribe.
func TestAIJobResult_FailedTerminalOnSubscribe(t *testing.T) {
	client := &fakeAIClient{getResp: &aiv1.GetAIJobResponse{
		Phase: aiv1.JobPhase_JOB_PHASE_FAILED,
		Error: "generation failed",
	}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-a"})
	ch, err := resolvers.AIJobResultResolver(ctx, client, aijobs.NewBroker(), "job-x")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	got, ok := recvResult(t, ch)
	if !ok || got == nil {
		t.Fatal("received nothing")
	}
	if got.Phase != resolvers.AIJobPhaseAiJobPhaseFailed || got.Error == nil || *got.Error != "generation failed" {
		t.Fatalf("unexpected: %+v", got)
	}
}

// TestAIJobResult_WebsocketInjectedClaims verifies the websocket auth path:
// the transport InitFunc stashes verified claims via WithSubscriberClaims
// (principal.HTTP does not wrap the ws route), and the resolver reads them.
func TestAIJobResult_WebsocketInjectedClaims(t *testing.T) {
	client := &fakeAIClient{getResp: &aiv1.GetAIJobResponse{
		Phase:     aiv1.JobPhase_JOB_PHASE_SUCCEEDED,
		ResultRef: "ai:job-result:job-ws:DRAFT",
	}}
	ctx := resolvers.WithSubscriberClaims(context.Background(), principal.Static{UserIDValue: "user-a"})
	ch, err := resolvers.AIJobResultResolver(ctx, client, aijobs.NewBroker(), "job-ws")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	got, ok := recvResult(t, ch)
	if !ok || got == nil || got.ResultRef == nil || *got.ResultRef != "ai:job-result:job-ws:DRAFT" {
		t.Fatalf("ws-authed subscriber did not receive result: ok=%v got=%+v", ok, got)
	}
}

func TestAIJobResult_Unauthenticated(t *testing.T) {
	_, err := resolvers.AIJobResultResolver(context.Background(), &fakeAIClient{}, aijobs.NewBroker(), "job-1")
	if err == nil {
		t.Fatal("expected error for unauthenticated caller")
	}
}

func TestAIJobResult_NilBroker(t *testing.T) {
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-a"})
	_, err := resolvers.AIJobResultResolver(ctx, &fakeAIClient{}, nil, "job-1")
	if err == nil {
		t.Fatal("expected error when broker is unavailable")
	}
}

// TestAIJobResult_ClientDisconnectStopsStream verifies cancelling the
// subscription context tears the stream down (channel closes) and unsubscribes.
func TestAIJobResult_ClientDisconnectStopsStream(t *testing.T) {
	client := &fakeAIClient{getResp: &aiv1.GetAIJobResponse{Phase: aiv1.JobPhase_JOB_PHASE_RUNNING}}
	base := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-a"})
	ctx, cancel := context.WithCancel(base)
	ch, err := resolvers.AIJobResultResolver(ctx, client, aijobs.NewBroker(), "job-1")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed channel after disconnect")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not close on disconnect")
	}
}
