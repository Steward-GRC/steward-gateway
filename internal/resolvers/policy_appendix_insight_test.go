// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The appendix diff and the contributors are for an author, a site admin and
// compliance (steward-gateway#204); the mock's "who may" and "the version diff"
// tests. Compliance is the compliance-admin role of the permission catalog. A
// reader (and a role with no part in it, such as template-admin) gets neither,
// and the extra viewers still write nothing: their right to edit is the
// category rules', not their role's.

func TestAppendixDiff_SiteAdminAndComplianceSeeIt(t *testing.T) {
	for _, user := range []string{"sam", "carl"} {
		e := newApxEnv(t)
		e.save(t, "bob", apxSeeded, "Per-diem rates", apxBodyOf("Changed terms."))
		got, err := e.r.Query().AppendixDiff(apxCtx(t, user), apxSeeded, nil)
		if err != nil {
			t.Fatalf("appendixDiff as %s: %v", user, err)
		}
		if len(got) != 1 || got[0].ChangeType != "modified" {
			t.Fatalf("%s: diff = %+v, want one modified section", user, got)
		}
	}
}

func TestAppendixDiff_OthersRefused(t *testing.T) {
	for _, user := range []string{"erin", "tess"} {
		e := newApxEnv(t)
		_, err := e.r.Query().AppendixDiff(apxCtx(t, user), apxSeeded, nil)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: err = %v, want PermissionDenied", user, err)
		}
		if e.core.diffs != 0 {
			t.Fatalf("%s: core was asked to diff", user)
		}
	}
}

func TestAppendixContributors_SiteAdminAndComplianceSeeThem(t *testing.T) {
	for _, user := range []string{"sam", "carl"} {
		e := newApxEnv(t)
		got := e.contributors(t, user, apxSeeded)
		if len(got.Contributors) != 1 || got.Contributors[0].UserID != "bob" {
			t.Fatalf("%s: contributors = %+v, want bob", user, got.Contributors)
		}
		if got.Published == nil || len(got.Published.Contributors) != 1 {
			t.Fatalf("%s: published = %+v, want its contributors", user, got.Published)
		}
		if got.Draft != nil {
			t.Fatalf("%s: sees a draft, which is for an editor", user)
		}
	}
	e := newApxEnv(t)
	if n := len(e.contributors(t, "tess", apxSeeded).Contributors); n != 0 {
		t.Fatalf("template-admin sees %d contributors, want none", n)
	}
}

// mock: "refuses a reader every write and shows them no draft", and the extra
// viewers write nothing either.
func TestAppendixWrites_RefusedToReaderAndToViewOnlyRoles(t *testing.T) {
	for _, user := range []string{"erin", "carl", "sam", "tess"} {
		e := newApxEnv(t)
		writes := e.core.writes
		ctx := apxCtx(t, user)
		if _, err := e.r.Mutation().SaveAppendixDraft(ctx, apxSeeded, "T", apxBody); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s save: err = %v, want PermissionDenied", user, err)
		}
		if _, err := e.r.Mutation().PublishAppendix(ctx, apxSeeded); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s publish: err = %v, want PermissionDenied", user, err)
		}
		if _, err := e.r.Mutation().RetireAppendix(ctx, apxSeeded); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s retire: err = %v, want PermissionDenied", user, err)
		}
		if _, err := e.r.Mutation().ReorderPolicyAppendices(ctx, apxPolicy, []string{apxSeeded}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s reorder: err = %v, want PermissionDenied", user, err)
		}
		if e.core.writes != writes {
			t.Fatalf("%s: a refused write reached core", user)
		}
	}
}
