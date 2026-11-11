// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// The per-approver "changes since I last reviewed" view (#114). Core keeps the
// snapshot; the gateway decides who may ask: only a person who holds a seat on
// the version's run, never the author and never someone outside the run. These
// tests run the two resolvers against a fake core that keeps snapshots the way
// core does: the first read takes one at the current text, a mark moves it, and
// every section is listed.

const (
	snapVersion = "pol-1-v1"
	snapAuthor  = "user-bob"
	snapCharlie = "user-charlie"
	snapAlice   = "user-alice"
	snapOutside = "user-erin"
)

// snapshotCore is core's ReviewSnapshotService with in-memory snapshots, one per
// user and version, and a call log so a test can tell who core was asked for.
type snapshotCore struct {
	corev1.ReviewSnapshotServiceClient
	current  map[string]string            // section key -> current text
	snapshot map[string]map[string]string // user -> section key -> text last reviewed
	gets     []string                     // user ids core was asked a diff for
	marks    []string                     // user ids core was asked to mark
	getErr   error
	markErr  error
}

func newSnapshotCore() *snapshotCore {
	return &snapshotCore{
		current:  map[string]string{"scope": "Book through the portal.", "steps": "Ask."},
		snapshot: map[string]map[string]string{},
	}
}

func (s *snapshotCore) edit(section, text string) { s.current[section] = text }

func (s *snapshotCore) keys() []string {
	out := make([]string, 0, len(s.current))
	for k := range s.current {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *snapshotCore) GetChangesSinceReview(_ context.Context, in *corev1.GetChangesSinceReviewRequest, _ ...grpc.CallOption) (*corev1.GetChangesSinceReviewResponse, error) {
	s.gets = append(s.gets, in.GetUserId())
	if s.getErr != nil {
		return nil, s.getErr
	}
	if _, ok := s.snapshot[in.GetUserId()]; !ok {
		s.snapshot[in.GetUserId()] = cloneText(s.current)
	}
	before := s.snapshot[in.GetUserId()]
	diffs := make([]*corev1.SectionDiff, 0, len(s.current))
	for _, k := range s.keys() {
		d := &corev1.SectionDiff{SectionKey: k, SectionTitle: strings.ToUpper(k[:1]) + k[1:], ChangeType: "unchanged"}
		if before[k] != s.current[k] {
			d.ChangeType, d.WordDiffHtml = "modified", "<ins>"+s.current[k]+"</ins>"
		}
		diffs = append(diffs, d)
	}
	return &corev1.GetChangesSinceReviewResponse{Diffs: diffs}, nil
}

func (s *snapshotCore) MarkVersionReviewed(_ context.Context, in *corev1.MarkVersionReviewedRequest, _ ...grpc.CallOption) (*corev1.MarkVersionReviewedResponse, error) {
	s.marks = append(s.marks, in.GetUserId())
	if s.markErr != nil {
		return nil, s.markErr
	}
	s.snapshot[in.GetUserId()] = cloneText(s.current)
	return &corev1.MarkVersionReviewedResponse{}, nil
}

func cloneText(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// snapRun is workflow with one run on the version whose first stage seats
// Charlie (pending) and Alice (already approved): a seat in any state counts.
func snapRun() *fakeWorkflowClient {
	return &fakeWorkflowClient{statusResp: &workflowv1.GetStatusResponse{
		RunId:      "run-1",
		Status:     workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW,
		StageNames: []string{"Legal"},
		StageAssignees: []*workflowv1.StageAssignees{{Assignees: []*workflowv1.StageAssignee{
			{UserId: snapCharlie, State: "pending"},
			{UserId: snapAlice, State: "approved"},
		}}},
	}}
}

func snapCtx(t *testing.T, user string) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: user, RolesValue: []string{"reader"}})
}

type snapEnv struct {
	core  *snapshotCore
	wf    *fakeWorkflowClient
	pc    *recordingPolicyClient
	gc    corev1.CategoryServiceClient
	admin *fakeBreakGlassAdmin
}

func newSnapEnv(t *testing.T) *snapEnv {
	t.Helper()
	pc, gc, _ := breakGlassReadSetup(t, false)
	return &snapEnv{core: newSnapshotCore(), wf: snapRun(), pc: pc, gc: gc, admin: noGrant()}
}

func (e *snapEnv) since(ctx context.Context) ([]*resolvers.SectionDiff, error) {
	return resolvers.VersionChangesSinceReview(ctx, log.Nop(), e.core, e.pc, e.gc, e.admin, e.wf, snapVersion)
}

func (e *snapEnv) mark(ctx context.Context) (bool, error) {
	return resolvers.MarkVersionReviewed(ctx, log.Nop(), e.core, e.pc, e.gc, e.admin, e.wf, snapVersion)
}

func (e *snapEnv) sinceAs(t *testing.T, user string) []*resolvers.SectionDiff {
	t.Helper()
	out, err := e.since(snapCtx(t, user))
	if err != nil {
		t.Fatalf("versionChangesSinceReview as %s: %v", user, err)
	}
	if out == nil {
		t.Fatalf("versionChangesSinceReview as %s = nil, want an empty list: the field is non-null", user)
	}
	for _, d := range out {
		if d.ChangeType == "unchanged" {
			t.Fatalf("versionChangesSinceReview as %s lists unchanged section %q, want only changed ones", user, d.SectionKey)
		}
	}
	return out
}

func (e *snapEnv) markAs(t *testing.T, user string) {
	t.Helper()
	ok, err := e.mark(snapCtx(t, user))
	if err != nil || !ok {
		t.Fatalf("markVersionReviewed as %s = %v, %v; want true", user, ok, err)
	}
}

func TestVersionChangesSinceReview_ShowsNothingBeforeTheAuthorEdits(t *testing.T) {
	e := newSnapEnv(t)
	for _, user := range []string{snapCharlie, snapAlice} {
		if got := e.sinceAs(t, user); len(got) != 0 {
			t.Fatalf("%s sees %+v before any edit, want nothing", user, got)
		}
	}
	// The caller, not the request, names whose snapshot core reads.
	if len(e.core.gets) != 2 || e.core.gets[0] != snapCharlie || e.core.gets[1] != snapAlice {
		t.Fatalf("core asked for %v, want the signed-in users in turn", e.core.gets)
	}
}

func TestVersionChangesSinceReview_ShowsEachApproverTheEditMadeInReview(t *testing.T) {
	e := newSnapEnv(t)
	e.sinceAs(t, snapCharlie)
	e.sinceAs(t, snapAlice)
	e.core.edit("steps", "Book through the portal 21 days ahead.")
	for _, user := range []string{snapCharlie, snapAlice} {
		got := e.sinceAs(t, user)
		if len(got) != 1 || got[0].SectionKey != "steps" || got[0].ChangeType != "modified" {
			t.Fatalf("%s sees %+v, want the one edited section", user, got)
		}
		if got[0].WordDiffHTML == nil || !strings.Contains(*got[0].WordDiffHTML, "21 days") {
			t.Fatalf("%s word diff = %v, want the edit", user, got[0].WordDiffHTML)
		}
	}
}

func TestMarkVersionReviewed_MovesOnlyForTheApproverWhoActed(t *testing.T) {
	e := newSnapEnv(t)
	e.sinceAs(t, snapCharlie)
	e.sinceAs(t, snapAlice)
	e.core.edit("steps", "Book through the portal 21 days ahead.")

	e.markAs(t, snapCharlie)
	if len(e.core.marks) != 1 || e.core.marks[0] != snapCharlie {
		t.Fatalf("core marked %v, want only the caller", e.core.marks)
	}
	if got := e.sinceAs(t, snapCharlie); len(got) != 0 {
		t.Fatalf("charlie still sees %+v after marking it reviewed", got)
	}
	if got := e.sinceAs(t, snapAlice); len(got) == 0 {
		t.Fatal("alice sees nothing: charlie's mark moved her snapshot")
	}
}

func TestMarkVersionReviewed_AnApproverWhoAlreadyDecidedMayMark(t *testing.T) {
	e := newSnapEnv(t)
	e.sinceAs(t, snapAlice)
	e.core.edit("steps", "Book through the portal 21 days ahead.")
	e.markAs(t, snapAlice) // her seat is "approved", still a seat on the run
	if got := e.sinceAs(t, snapAlice); len(got) != 0 {
		t.Fatalf("alice sees %+v after marking it reviewed", got)
	}
}

func TestVersionChangesSinceReview_ShowsALaterEditAgainAfterTheApproverMovedOn(t *testing.T) {
	e := newSnapEnv(t)
	e.sinceAs(t, snapCharlie)
	e.core.edit("steps", "Book through the portal 21 days ahead.")
	e.markAs(t, snapCharlie)
	if got := e.sinceAs(t, snapCharlie); len(got) != 0 {
		t.Fatalf("charlie sees %+v right after marking it reviewed", got)
	}
	e.core.edit("steps", "Book through the portal 30 days ahead.")
	got := e.sinceAs(t, snapCharlie)
	if len(got) != 1 || got[0].WordDiffHTML == nil || !strings.Contains(*got[0].WordDiffHTML, "30 days") {
		t.Fatalf("charlie sees %+v, want the later edit", got)
	}
}

func TestReviewSnapshot_RefusedForTheAuthorAndForSomeoneWithNoSeat(t *testing.T) {
	for _, user := range []string{snapAuthor, snapOutside} {
		t.Run(user, func(t *testing.T) {
			e := newSnapEnv(t)
			out, err := e.since(snapCtx(t, user))
			if status.Code(err) != codes.PermissionDenied || out != nil {
				t.Fatalf("versionChangesSinceReview = %+v, %v; want PermissionDenied", out, err)
			}
			ok, err := e.mark(snapCtx(t, user))
			if status.Code(err) != codes.PermissionDenied || ok {
				t.Fatalf("markVersionReviewed = %v, %v; want PermissionDenied", ok, err)
			}
			// A refused caller must not make core take a snapshot.
			if len(e.core.gets) != 0 || len(e.core.marks) != 0 || len(e.core.snapshot) != 0 {
				t.Fatalf("core was asked (gets %v, marks %v) for a refused caller", e.core.gets, e.core.marks)
			}
			if e.wf.lastStatus.GetPolicyVersionId() != snapVersion {
				t.Fatalf("workflow GetStatus asked for %q, want the version's run", e.wf.lastStatus.GetPolicyVersionId())
			}
		})
	}
}

func TestReviewSnapshot_AVersionWithNoRunSeatsNobody(t *testing.T) {
	for _, err := range []error{status.Error(codes.NotFound, "approval run not found"), status.Error(codes.Unknown, "no approval run")} {
		e := newSnapEnv(t)
		e.wf.statusResp, e.wf.statusErr = nil, err
		if out, got := e.since(snapCtx(t, snapCharlie)); status.Code(got) != codes.PermissionDenied || out != nil {
			t.Fatalf("versionChangesSinceReview = %+v, %v; want PermissionDenied", out, got)
		}
		if ok, got := e.mark(snapCtx(t, snapCharlie)); status.Code(got) != codes.PermissionDenied || ok {
			t.Fatalf("markVersionReviewed = %v, %v; want PermissionDenied", ok, got)
		}
		if len(e.core.gets)+len(e.core.marks) != 0 {
			t.Fatal("core was asked for a version with no run")
		}
	}
}

func TestReviewSnapshot_AWorkflowFailureServesNothing(t *testing.T) {
	e := newSnapEnv(t)
	e.wf.statusResp, e.wf.statusErr = nil, status.Error(codes.Unavailable, "workflow down")
	if out, err := e.since(snapCtx(t, snapCharlie)); status.Code(err) != codes.Unavailable || out != nil {
		t.Fatalf("versionChangesSinceReview = %+v, %v; want the workflow error", out, err)
	}
	if ok, err := e.mark(snapCtx(t, snapCharlie)); status.Code(err) != codes.Unavailable || ok {
		t.Fatalf("markVersionReviewed = %v, %v; want the workflow error", ok, err)
	}
	if len(e.core.gets)+len(e.core.marks) != 0 {
		t.Fatal("core was asked although the seat could not be checked")
	}
}

func TestReviewSnapshot_NeedsASignedInCaller(t *testing.T) {
	e := newSnapEnv(t)
	if out, err := e.since(context.Background()); status.Code(err) != codes.Unauthenticated || out != nil {
		t.Fatalf("versionChangesSinceReview = %+v, %v; want Unauthenticated", out, err)
	}
	if ok, err := e.mark(context.Background()); status.Code(err) != codes.Unauthenticated || ok {
		t.Fatalf("markVersionReviewed = %v, %v; want Unauthenticated", ok, err)
	}
	if len(e.core.gets)+len(e.core.marks) != 0 {
		t.Fatal("core was asked without a caller")
	}
}

func TestReviewSnapshot_AReaderWhoCannotReadThePolicyGetsNotFound(t *testing.T) {
	pc, gc, _ := breakGlassReadSetup(t, true) // the Admins group is denied the read
	e := &snapEnv{core: newSnapshotCore(), wf: snapRun(), pc: pc, gc: gc, admin: noGrant()}
	e.wf.statusResp.StageAssignees[0].Assignees[0].UserId = "u-1" // a seat does not lift a denied read
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", IdpGroupsValue: []string{"Admins"}})

	if out, err := e.since(ctx); status.Code(err) != codes.NotFound || out != nil {
		t.Fatalf("versionChangesSinceReview = %+v, %v; want NotFound", out, err)
	}
	if ok, err := e.mark(ctx); status.Code(err) != codes.NotFound || ok {
		t.Fatalf("markVersionReviewed = %v, %v; want NotFound", ok, err)
	}
	if len(e.core.gets)+len(e.core.marks) != 0 {
		t.Fatal("core was asked for a policy the caller cannot read")
	}
}

func TestVersionChangesSinceReview_AnObfuscatedReaderGetsNoWordDiffs(t *testing.T) {
	pc, gc, ctx := breakGlassReadSetup(t, true) // the site admin sees this policy obfuscated
	e := &snapEnv{core: newSnapshotCore(), wf: snapRun(), pc: pc, gc: gc, admin: noGrant()}
	e.wf.statusResp.StageAssignees[0].Assignees[0].UserId = "sa"
	e.since(ctx) //nolint:errcheck // the first read takes the snapshot
	e.core.edit("steps", "Book through the portal 21 days ahead.")

	got, err := e.since(ctx)
	if err != nil {
		t.Fatalf("versionChangesSinceReview: %v", err)
	}
	if len(got) != 1 || got[0].SectionKey != "steps" || got[0].WordDiffHTML != nil {
		t.Fatalf("got %+v, want the changed section without its word diff", got)
	}
	if len(pc.recorded) != 0 {
		t.Fatalf("recorded = %v, want no break-glass record without a grant", pc.recorded)
	}
}

func TestReviewSnapshot_RelaysCoreRefusals(t *testing.T) {
	for _, code := range []codes.Code{codes.InvalidArgument, codes.NotFound} {
		e := newSnapEnv(t)
		e.core.getErr = status.Error(code, "from core")
		e.core.markErr = status.Error(code, "from core")
		if out, err := e.since(snapCtx(t, snapCharlie)); status.Code(err) != code || out != nil {
			t.Fatalf("versionChangesSinceReview = %+v, %v; want core's %s", out, err, code)
		}
		if ok, err := e.mark(snapCtx(t, snapCharlie)); status.Code(err) != code || ok {
			t.Fatalf("markVersionReviewed = %v, %v; want core's %s", ok, err, code)
		}
	}
}

func TestReviewSnapshot_AnUnknownVersionIsNotFound(t *testing.T) {
	e := newSnapEnv(t)
	_, err := resolvers.VersionChangesSinceReview(snapCtx(t, snapCharlie), log.Nop(), e.core, e.pc, e.gc, e.admin, e.wf, "missing")
	if err == nil || status.Code(err) == codes.Unimplemented {
		t.Fatalf("err = %v, want the version lookup error", err)
	}
	if len(e.core.gets) != 0 {
		t.Fatal("core was asked for an unknown version")
	}
}
