// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// Moving an approver's snapshot when they act (#115). The gateway asks core to
// mark the version reviewed for the person who acted, after the act succeeded;
// a failed mark is a warning and never fails the act. These tests mirror
// steward-mock-server review-snapshots.test.ts ("sending comments" and "the
// changes since an approver last reviewed").

// warnLog records the warnings it is given and drops everything else.
type warnLog struct {
	log.Logger
	warns []string
}

func newWarnLog() *warnLog { return &warnLog{Logger: log.Nop()} }

func (w *warnLog) Warn(msg string, fields ...log.Field) {
	parts := []string{msg}
	for _, f := range fields {
		parts = append(parts, f.Key+"="+toText(f.Val))
	}
	w.warns = append(w.warns, strings.Join(parts, " "))
}

func toText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	default:
		return "?"
	}
}

// seatedWorkflow is a workflow stub that keeps one run with seats the way
// workflow does: sending comments records them and changes nothing, an approval
// closes the seat, and a person with no open seat is refused.
type seatedWorkflow struct {
	*fakeWorkflowClient
	seats    map[string]string // user -> pending | approved | rejected
	comments map[string]string // user -> last comment sent back
}

func newSeatedWorkflow() *seatedWorkflow {
	return &seatedWorkflow{
		fakeWorkflowClient: &fakeWorkflowClient{},
		seats:              map[string]string{snapCharlie: "pending", snapAlice: "pending"},
		comments:           map[string]string{},
	}
}

func (w *seatedWorkflow) Signal(_ context.Context, in *workflowv1.SignalRequest, _ ...grpc.CallOption) (*workflowv1.SignalResponse, error) {
	w.lastSignal = in
	who := in.GetActorUserId()
	if w.seats[who] != "pending" {
		return nil, status.Error(codes.PermissionDenied, "no open seat on the run")
	}
	switch in.GetSignal() {
	case workflowv1.SignalType_SIGNAL_TYPE_REQUEST_CHANGES:
		w.comments[who] = in.GetComment()
	case workflowv1.SignalType_SIGNAL_TYPE_APPROVE:
		w.seats[who] = "approved"
	case workflowv1.SignalType_SIGNAL_TYPE_REJECT:
		w.seats[who] = "rejected"
	}
	return &workflowv1.SignalResponse{}, nil
}

func (w *seatedWorkflow) status() string {
	for _, s := range w.seats {
		if s == "rejected" {
			return "rejected"
		}
	}
	return "in_review"
}

func signalAs(t *testing.T, w workflowv1.WorkflowServiceClient, core *snapshotCore, logger log.Logger, user string, sig resolvers.SignalType, comment string) (bool, error) {
	t.Helper()
	return resolvers.SignalWorkflowResolver(snapCtx(t, user), logger, w, core, snapVersion, "run-1", "task-1", sig, comment)
}

// moves when the approver votes, sends comments, or marks it reviewed

func TestSignalMarksReviewed_ApproveRejectAndRequestChangesMoveTheActorsSnapshot(t *testing.T) {
	for _, sig := range []resolvers.SignalType{
		resolvers.SignalTypeSignalTypeApprove,
		resolvers.SignalTypeSignalTypeReject,
		resolvers.SignalTypeSignalTypeRequestChanges,
	} {
		t.Run(string(sig), func(t *testing.T) {
			core := newSnapshotCore()
			w := newSeatedWorkflow()
			// Both approvers read the version, then the author edits it.
			core.snapshot[snapCharlie] = cloneText(core.current)
			core.snapshot[snapAlice] = cloneText(core.current)
			core.edit("steps", "Book through the portal 21 days ahead.")

			ok, err := signalAs(t, w, core, log.Nop(), snapCharlie, sig, "See my comments.")
			if err != nil || !ok {
				t.Fatalf("signal = %v, %v; want it to succeed", ok, err)
			}
			if len(core.marks) != 1 || core.marks[0] != snapCharlie {
				t.Fatalf("core was asked to mark %v, want only charlie", core.marks)
			}
			if got := cloneText(core.snapshot[snapCharlie]); got["steps"] != core.current["steps"] {
				t.Fatalf("charlie's snapshot did not move: %v", got)
			}
			if core.snapshot[snapAlice]["steps"] == core.current["steps"] {
				t.Fatalf("alice's snapshot moved with charlie's act")
			}
		})
	}
}

func TestSignalMarksReviewed_OtherSignalsAndRefusedSignalsMarkNothing(t *testing.T) {
	core := newSnapshotCore()
	w := newSeatedWorkflow()
	if _, err := signalAs(t, w, core, log.Nop(), snapCharlie, resolvers.SignalTypeSignalTypeWithdraw, "x"); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if len(core.marks) != 0 {
		t.Fatalf("a withdraw marked %v, want nothing", core.marks)
	}
	if _, err := signalAs(t, w, core, log.Nop(), snapOutside, resolvers.SignalTypeSignalTypeApprove, "x"); err == nil {
		t.Fatal("a signal from someone with no seat succeeded")
	}
	if len(core.marks) != 0 {
		t.Fatalf("a refused signal marked %v, want nothing", core.marks)
	}
}

func TestSignalMarksReviewed_AFailedMarkWarnsAndDoesNotFailTheAct(t *testing.T) {
	core := newSnapshotCore()
	core.markErr = errors.New("core is down secret-token")
	w := newSeatedWorkflow()
	logger := newWarnLog()

	ok, err := signalAs(t, w, core, logger, snapCharlie, resolvers.SignalTypeSignalTypeApprove, "fine")
	if err != nil || !ok {
		t.Fatalf("signal = %v, %v; want the vote to stand", ok, err)
	}
	if w.seats[snapCharlie] != "approved" {
		t.Fatalf("seat = %q, want approved", w.seats[snapCharlie])
	}
	if len(logger.warns) != 1 || !strings.Contains(logger.warns[0], snapVersion) {
		t.Fatalf("warnings = %v, want one naming the version", logger.warns)
	}
	if strings.Contains(logger.warns[0], "fine") {
		t.Fatalf("warning carries the comment text: %q", logger.warns[0])
	}
}

func TestSignalMarksReviewed_WithNoSnapshotClientTheActStillSucceeds(t *testing.T) {
	w := newSeatedWorkflow()
	ok, err := resolvers.SignalWorkflowResolver(snapCtx(t, snapCharlie), log.Nop(), w, nil, snapVersion, "run-1", "task-1", resolvers.SignalTypeSignalTypeApprove, "fine")
	if err != nil || !ok {
		t.Fatalf("signal = %v, %v; want success without a snapshot client", ok, err)
	}
}

func TestBulkDecideMarksReviewed_ForEachDecidedItemOnly(t *testing.T) {
	core := newSnapshotCore()
	w := &fakeWorkflowClient{bulkResp: &workflowv1.BulkDecideResponse{
		BulkBatchId: "b-1",
		Results: []*workflowv1.DecisionResult{
			{PolicyVersionId: "pv-1", Ok: true},
			{PolicyVersionId: "pv-2", Ok: false, Error: "not your turn"},
			{PolicyVersionId: "pv-3", Ok: true},
		},
	}}
	out, err := resolvers.BulkDecideResolver(snapCtx(t, snapCharlie), log.Nop(), w, core, resolvers.BulkDecideInput{})
	if err != nil || len(out.Results) != 3 {
		t.Fatalf("bulkDecide = %+v, %v", out, err)
	}
	if len(core.marks) != 2 || core.marks[0] != snapCharlie || core.marks[1] != snapCharlie {
		t.Fatalf("core was asked to mark %v, want charlie twice (pv-1 and pv-3)", core.marks)
	}
}

func TestBulkDecideMarksReviewed_AFailedMarkWarnsAndKeepsTheResults(t *testing.T) {
	core := newSnapshotCore()
	core.markErr = errors.New("core is down")
	w := &fakeWorkflowClient{bulkResp: &workflowv1.BulkDecideResponse{
		BulkBatchId: "b-1",
		Results:     []*workflowv1.DecisionResult{{PolicyVersionId: "pv-1", Ok: true}, {PolicyVersionId: "pv-3", Ok: true}},
	}}
	logger := newWarnLog()
	out, err := resolvers.BulkDecideResolver(snapCtx(t, snapCharlie), logger, w, core, resolvers.BulkDecideInput{})
	if err != nil || len(out.Results) != 2 || !out.Results[0].Ok || !out.Results[1].Ok {
		t.Fatalf("bulkDecide = %+v, %v; want both results kept", out, err)
	}
	if len(logger.warns) != 2 {
		t.Fatalf("warnings = %v, want one per failed mark", logger.warns)
	}
}

// sending comments

func TestSendingComments_ChangesNoStatusAndKeepsTheSeatOpen(t *testing.T) {
	core := newSnapshotCore()
	w := newSeatedWorkflow()
	ok, err := signalAs(t, w, core, log.Nop(), snapCharlie, resolvers.SignalTypeSignalTypeRequestChanges, "See my comments.")
	if err != nil || !ok {
		t.Fatalf("signal = %v, %v", ok, err)
	}
	if w.lastSignal.GetSignal() != workflowv1.SignalType_SIGNAL_TYPE_REQUEST_CHANGES || w.lastSignal.GetComment() != "See my comments." {
		t.Fatalf("workflow was sent %v, want the request_changes signal with its comment", w.lastSignal)
	}
	if w.status() != "in_review" || w.seats[snapCharlie] != "pending" {
		t.Fatalf("status %q, charlie's seat %q; want in review and still pending", w.status(), w.seats[snapCharlie])
	}
	if w.comments[snapCharlie] != "See my comments." {
		t.Fatalf("workflow kept comment %q", w.comments[snapCharlie])
	}
}

func TestSendingComments_IsRefusedForSomeoneWithNoSeat(t *testing.T) {
	core := newSnapshotCore()
	w := newSeatedWorkflow()
	ok, err := signalAs(t, w, core, log.Nop(), snapOutside, resolvers.SignalTypeSignalTypeRequestChanges, "x")
	if err == nil || ok {
		t.Fatalf("signal = %v, %v; want a refusal", ok, err)
	}
	if status.Code(errors.Unwrap(err)) != codes.PermissionDenied {
		t.Fatalf("err = %v, want workflow's PermissionDenied relayed", err)
	}
	if len(w.comments) != 0 || len(core.marks) != 0 {
		t.Fatalf("comments %v, marks %v; want nothing recorded", w.comments, core.marks)
	}
}

func TestSendingComments_LetsTheApproverApproveAfterwards(t *testing.T) {
	core := newSnapshotCore()
	w := newSeatedWorkflow()
	if _, err := signalAs(t, w, core, log.Nop(), snapCharlie, resolvers.SignalTypeSignalTypeRequestChanges, "See my comments."); err != nil {
		t.Fatalf("request changes: %v", err)
	}
	ok, err := signalAs(t, w, core, log.Nop(), snapCharlie, resolvers.SignalTypeSignalTypeApprove, "Fine now.")
	if err != nil || !ok {
		t.Fatalf("approve after comments = %v, %v", ok, err)
	}
	if w.seats[snapCharlie] != "approved" {
		t.Fatalf("seat = %q, want approved", w.seats[snapCharlie])
	}
	if len(core.marks) != 2 {
		t.Fatalf("marks = %v, want one for the comments and one for the vote", core.marks)
	}
}
