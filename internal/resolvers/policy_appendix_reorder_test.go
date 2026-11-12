// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"fmt"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// Reordering a policy's appendices (#124). Each test names the mock server
// test it ports (steward-mock-server src/product/appendices.test.ts).

// threeApx is the seeded appendix plus two more, all published, in order.
func threeApx(t *testing.T, e *apxEnv) []string {
	t.Helper()
	ids := []string{apxSeeded}
	for _, title := range []string{"Supplier terms", "Quote checklist"} {
		a := e.create(t, "bob", strp(title))
		e.publish(t, "bob", a.ID)
		ids = append(ids, a.ID)
	}
	return ids
}

func apxLetters(as []*resolvers.PolicyAppendix) []string {
	out := []string{}
	for _, a := range as {
		out = append(out, fmt.Sprintf("%s=%s", a.ID, deref(a.Letter)))
	}
	return out
}

// mock: "order: reorders the appendices and re-letters them"
func TestReorderPolicyAppendices_ReordersAndReLetters(t *testing.T) {
	e := newApxEnv(t)
	ids := threeApx(t, e)
	want := slices.Clone(ids)
	slices.Reverse(want)

	got, err := e.r.Mutation().ReorderPolicyAppendices(apxCtx(t, "bob"), apxPolicy, want)
	if err != nil {
		t.Fatalf("reorderPolicyAppendices: %v", err)
	}
	if !slices.Equal(apxIDs(got), want) {
		t.Fatalf("returned order = %v, want %v", apxIDs(got), want)
	}
	for i, a := range got {
		if letter := string(rune('A' + i)); deref(a.Letter) != letter || a.OrderIndex != i {
			t.Errorf("appendix %s: letter %s index %d, want %s and %d", a.ID, deref(a.Letter), a.OrderIndex, letter, i)
		}
	}
	// shaped for the editor as the other mutations shape them
	if got[2].Published == nil || len(got[2].Versions) == 0 || len(got[2].Contributors) == 0 || got[2].Contributors[0].Name != "Bob Author" {
		t.Fatalf("the reordered appendix lacks the editor shape: %+v", got[2])
	}
	if c := e.core.lastReorder; c.GetPolicyId() != apxPolicy || c.GetActorUserId() != "bob" || !slices.Equal(c.GetOrderedIds(), want) {
		t.Fatalf("core was sent %+v, want the policy, the list and the actor bob", c)
	}
	// the list query now follows the new order
	if !slices.Equal(apxIDs(e.list(t, "bob", false)), want) {
		t.Fatalf("listing after the reorder = %v, want %v", apxIDs(e.list(t, "bob", false)), want)
	}
}

// mock: "an unchanged appendix makes no draft: makes no draft on a reorder, a
// retire or a restore" (the reorder part; retire and restore are covered by
// TestRetireAndRestore_MakeNoDraft)
func TestReorderPolicyAppendices_MakesNoDraft(t *testing.T) {
	e := newApxEnv(t)
	ids := threeApx(t, e)
	slices.Reverse(ids)
	if _, err := e.r.Mutation().ReorderPolicyAppendices(apxCtx(t, "bob"), apxPolicy, ids); err != nil {
		t.Fatalf("reorderPolicyAppendices: %v", err)
	}
	for _, a := range e.list(t, "bob", true) {
		if a.Draft != nil {
			t.Fatalf("%s has a draft after a reorder", a.ID)
		}
	}
}

// gateway: a site admin may edit any policy, so may reorder it.
func TestReorderPolicyAppendices_RootMay(t *testing.T) {
	e := newApxEnv(t)
	ids := threeApx(t, e)
	slices.Reverse(ids)
	if _, err := e.r.Mutation().ReorderPolicyAppendices(apxCtx(t, "alice"), apxPolicy, ids); err != nil {
		t.Fatalf("reorderPolicyAppendices as a site admin: %v", err)
	}
	if e.core.lastReorder.GetActorUserId() != "alice" {
		t.Fatalf("actor = %q, want alice", e.core.lastReorder.GetActorUserId())
	}
}

// gateway: signing in is required.
func TestReorderPolicyAppendices_NeedsSignIn(t *testing.T) {
	e := newApxEnv(t)
	_, err := e.r.Mutation().ReorderPolicyAppendices(t.Context(), apxPolicy, []string{apxSeeded})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
	if e.core.writes != 0 {
		t.Fatalf("core saw %d writes from an unauthenticated caller", e.core.writes)
	}
}

// gateway (mock "who may"): a reader is refused and core sees no write.
func TestReorderPolicyAppendices_ReaderRefusedAndCoreNotWritten(t *testing.T) {
	e := newApxEnv(t)
	ids := threeApx(t, e)
	before := e.core.writes
	rev := slices.Clone(ids)
	slices.Reverse(rev)
	_, err := e.r.Mutation().ReorderPolicyAppendices(apxCtx(t, "erin"), apxPolicy, rev)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if e.core.writes != before || e.core.lastReorder != nil {
		t.Fatalf("core saw a write from a refused reader (writes %d -> %d)", before, e.core.writes)
	}
	if !slices.Equal(apxIDs(e.list(t, "bob", false)), ids) {
		t.Fatal("the order changed under a refused reader")
	}
}

// gateway (mock: "Name every appendix of this document exactly once"): core's
// InvalidArgument for a missing, repeated, foreign or retired id reaches the
// caller as it is, and the order stays as it was.
func TestReorderPolicyAppendices_BadListRefusedOrderUnchanged(t *testing.T) {
	e := newApxEnv(t)
	ids := threeApx(t, e)
	foreign := e.core.seed("other-1", "pol-other", "Elsewhere", apxBody, "bob")
	retired := e.create(t, "bob", strp("Old"))
	if _, err := e.r.Mutation().RetireAppendix(apxCtx(t, "bob"), retired.ID); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"missing":  ids[:2],
		"repeated": {ids[0], ids[0], ids[1]},
		"foreign":  {ids[0], ids[1], foreign.id},
		"retired":  {ids[0], ids[1], retired.ID},
		"unknown":  {ids[0], ids[1], "nope"},
		"empty":    {},
	}
	for name, list := range cases {
		_, err := e.r.Mutation().ReorderPolicyAppendices(apxCtx(t, "bob"), apxPolicy, list)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
		if got := e.list(t, "bob", false); !slices.Equal(apxIDs(got), ids) {
			t.Errorf("%s: order = %v, want unchanged %v", name, apxLetters(got), ids)
		}
	}
}

// gateway: a policy core does not know is NotFound, not a write.
func TestReorderPolicyAppendices_UnknownPolicy(t *testing.T) {
	e := newApxEnv(t)
	_, err := e.r.Mutation().ReorderPolicyAppendices(apxCtx(t, "bob"), "no-such-policy", []string{apxSeeded})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
	if e.core.lastReorder != nil {
		t.Fatal("core was sent a reorder for an unknown policy")
	}
}
