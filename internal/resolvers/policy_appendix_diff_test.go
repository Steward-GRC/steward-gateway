// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// The appendix draft diff (#125). Each test names the mock server test it ports
// (steward-mock-server src/product/appendices.test.ts and
// appendix-titles-contributors.test.ts).

// DiffPolicyAppendix behaves as core does for one section: the published row is
// the "from" side; the given content, else the open draft, else the published
// row, is the "to" side. It reads only; it never counts as a write. Content
// that is not JSON is InvalidArgument.
func (c *appendixCore) DiffPolicyAppendix(_ context.Context, in *corev1.DiffPolicyAppendixRequest, _ ...grpc.CallOption) (*corev1.DiffPolicyAppendixResponse, error) {
	c.diffs++
	c.lastDiff = in
	a, err := c.find(in.GetId())
	if err != nil {
		return nil, err
	}
	var from, to string
	for _, r := range a.rows {
		if r.state == corev1.AppendixVersionState_APPENDIX_VERSION_STATE_PUBLISHED {
			from = r.content
		}
	}
	to = from
	if d := c.draftOf(a); d != nil {
		to = d.content
	}
	if in.ContentJson != nil {
		to = in.GetContentJson()
		if !json.Valid([]byte(to)) {
			return nil, status.Error(codes.InvalidArgument, "content is not valid JSON")
		}
	}
	d := &corev1.SectionDiff{SectionKey: "body", SectionTitle: "Body", ChangeType: "unchanged", WordDiffHtml: from}
	if from != to {
		d.ChangeType, d.WordDiffHtml = "modified", "<del>"+from+"</del><ins>"+to+"</ins>"
	}
	return &corev1.DiffPolicyAppendixResponse{Diffs: []*corev1.SectionDiff{d}}, nil
}

func apxBodyOf(text string) string {
	return `{"root":{"children":[{"type":"text","text":"` + text + `"}]}}`
}

// mock: "the version diff: is shown to an author, a site admin and compliance"
// (author and site admin here; compliance waits on the access model).
func TestAppendixDiff_ShownToAuthorAndRoot(t *testing.T) {
	for _, user := range []string{"bob", "alice"} {
		e := newApxEnv(t)
		e.save(t, "bob", apxSeeded, "Per-diem rates", apxBodyOf("Changed terms."))
		got, err := e.r.Query().AppendixDiff(apxCtx(t, user), apxSeeded, nil)
		if err != nil {
			t.Fatalf("appendixDiff as %s: %v", user, err)
		}
		if len(got) != 1 || got[0].ChangeType != "modified" || got[0].SectionKey != "body" {
			t.Fatalf("%s: diff = %+v, want one modified section", user, got)
		}
		if e.core.lastDiff.GetId() != apxSeeded || e.core.lastDiff.ContentJson != nil {
			t.Fatalf("%s: core was sent %+v, want the id and no content", user, e.core.lastDiff)
		}
	}
}

// mock: "the version diff: is refused to everyone else"
func TestAppendixDiff_RefusedToEveryoneElse(t *testing.T) {
	e := newApxEnv(t)
	e.save(t, "bob", apxSeeded, "Per-diem rates", apxBodyOf("Changed terms."))
	_, err := e.r.Query().AppendixDiff(apxCtx(t, "erin"), apxSeeded, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if e.core.diffs != 0 {
		t.Fatal("core was asked to diff for a caller who may not see it")
	}
}

// mock: "the live diff: diffs text that is not saved against what is published"
func TestAppendixDiff_UnsavedTextAgainstPublished(t *testing.T) {
	e := newApxEnv(t)
	typed := apxBodyOf("Per-diem rates, now reviewed every quarter.")
	got, err := e.r.Query().AppendixDiff(apxCtx(t, "bob"), apxSeeded, &typed)
	if err != nil {
		t.Fatalf("appendixDiff: %v", err)
	}
	if len(got) == 0 || got[0].ChangeType == "unchanged" {
		t.Fatalf("diff = %+v, want a change", got)
	}
	if e.core.lastDiff.GetContentJson() != typed {
		t.Fatalf("core was sent %q, want the typed text as is", e.core.lastDiff.GetContentJson())
	}
	if got[0].WordDiffHTML == nil || !strings.Contains(*got[0].WordDiffHTML, "quarter") {
		t.Fatalf("wordDiffHtml = %v, want the word diff", got[0].WordDiffHTML)
	}
}

// mock: "the live diff: saves nothing: no draft appears and the stored draft is left alone"
func TestAppendixDiff_SavesNothing(t *testing.T) {
	e := newApxEnv(t)
	before := e.core.writes
	typed := apxBodyOf("Typed, not saved.")
	if _, err := e.r.Query().AppendixDiff(apxCtx(t, "bob"), apxSeeded, &typed); err != nil {
		t.Fatal(err)
	}
	if e.core.writes != before {
		t.Fatalf("core saw %d writes from a diff", e.core.writes-before)
	}
	if a := e.list(t, "bob", false); a[0].Draft != nil {
		t.Fatal("a draft appeared after a diff")
	}
	// the stored draft is left alone too
	e.save(t, "bob", apxSeeded, "Per-diem rates", apxBodyOf("Stored draft."))
	before = e.core.writes
	if _, err := e.r.Query().AppendixDiff(apxCtx(t, "bob"), apxSeeded, &typed); err != nil {
		t.Fatal(err)
	}
	if e.core.writes != before {
		t.Fatal("core saw a write from a diff over an open draft")
	}
	if d := e.list(t, "bob", false)[0].Draft; d == nil || !strings.Contains(d.ContentJSON, "Stored draft.") {
		t.Fatalf("draft = %+v, want the stored draft untouched", d)
	}
}

// mock: "the live diff: is unchanged against itself"
func TestAppendixDiff_UnchangedAgainstItself(t *testing.T) {
	e := newApxEnv(t)
	same := apxBody
	got, err := e.r.Query().AppendixDiff(apxCtx(t, "bob"), apxSeeded, &same)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range got {
		if d.ChangeType != "unchanged" {
			t.Fatalf("diff = %+v, want every section unchanged", d)
		}
	}
}

// mock: "the live diff: is refused to those who may not see the diff"
func TestAppendixDiff_LiveRefusedToReader(t *testing.T) {
	e := newApxEnv(t)
	typed := apxBodyOf("Typed.")
	_, err := e.r.Query().AppendixDiff(apxCtx(t, "erin"), apxSeeded, &typed)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if e.core.diffs != 0 || e.core.writes != 0 {
		t.Fatal("core was called for a refused reader")
	}
}

// gateway: signing in is required.
func TestAppendixDiff_NeedsSignIn(t *testing.T) {
	e := newApxEnv(t)
	_, err := e.r.Query().AppendixDiff(t.Context(), apxSeeded, nil)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
	if e.core.diffs != 0 {
		t.Fatal("core was asked to diff for an unauthenticated caller")
	}
}

// gateway: an unknown appendix is NotFound and core is never asked to diff.
func TestAppendixDiff_UnknownAppendix(t *testing.T) {
	e := newApxEnv(t)
	_, err := e.r.Query().AppendixDiff(apxCtx(t, "bob"), "nope", nil)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
	if e.core.diffs != 0 {
		t.Fatal("core was asked to diff an unknown appendix")
	}
}

// gateway: core's InvalidArgument for text it cannot read reaches the caller.
func TestAppendixDiff_BadContentPassesThrough(t *testing.T) {
	e := newApxEnv(t)
	bad := "not json"
	_, err := e.r.Query().AppendixDiff(apxCtx(t, "bob"), apxSeeded, &bad)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
	if e.core.writes != 0 {
		t.Fatal("core saw a write")
	}
}

// gateway: an obfuscated reader keeps the section shape; the word diff is
// dropped and the title scrambled, as for the policy version diff.
func TestAppendixDiff_ObfuscatedReaderGetsNoText(t *testing.T) {
	e := newApxEnv(t)
	pc, gc, ctx := breakGlassReadSetup(t, true) // a site admin whose group is denied on merit
	// The site admin follows the rules, so what lets them edit is owning the
	// policy; the Read deny still applies to them.
	pc.policies[apxPolicy].OwnerUserId = "sa"
	e.r.PolicyClient, e.r.CategoryClient = pc, gc
	typed := apxBodyOf("Secret new text.")
	got, err := e.r.Query().AppendixDiff(ctx, apxSeeded, &typed)
	if err != nil {
		t.Fatalf("appendixDiff: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("diff = %+v", got)
	}
	if got[0].SectionTitle == "Body" {
		t.Fatal("the section title was not scrambled")
	}
	if got[0].WordDiffHTML != nil {
		t.Fatalf("wordDiffHtml = %q, want none for an obfuscated reader", *got[0].WordDiffHTML)
	}
}
