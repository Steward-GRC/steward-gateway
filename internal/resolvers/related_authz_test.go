// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	log "github.com/Bugs5382/go-log"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// read-superset fixtures. Two root categories:
//   - cat-open : Everyone read=ALLOW  → readers = {u-staff, u-contractor, u-cleared}
//   - cat-staff: group Staff read=ALLOW → readers = {u-staff, u-cleared}
//
// Policies:
//
//	A-open  (cat-open, standard)   readers = all three
//	A-staff (cat-staff, standard)  readers = {u-staff, u-cleared}
//	B-open  (cat-open, standard)   readers = all three
//	B-staff (cat-staff, standard)  readers = {u-staff, u-cleared}
//	B-sens  (cat-open, SENSITIVE)  readers = {u-cleared} (only read-sensitive clearance)
func core22Fixtures() (*raciCategoryClient, *raciIdentityClient, *fakePolicyClient) {
	gc := &raciCategoryClient{
		groups: map[string]*corev1.Category{
			"cat-open":  {Id: "cat-open", Name: "Open"},
			"cat-staff": {Id: "cat-staff", Name: "Staff"},
		},
		rulesets: map[string][]*corev1.CategoryRule{
			"cat-open": {
				{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_EVERYONE, Read: corev1.GrantEffect_GRANT_EFFECT_ALLOW},
			},
			"cat-staff": {
				{SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_GROUP, SubjectRef: "Staff", Read: corev1.GrantEffect_GRANT_EFFECT_ALLOW},
			},
		},
	}
	ic := &raciIdentityClient{
		users: map[string]*identityv1.User{
			"u-staff":      {Id: "u-staff"},
			"u-contractor": {Id: "u-contractor"},
			"u-cleared":    {Id: "u-cleared", ReadSensitiveGrant: true},
		},
		idpGroups: map[string][]string{
			"u-staff":      {"Staff"},
			"u-contractor": {"Contractors"},
			"u-cleared":    {"Staff"},
		},
	}
	// All five are PUBLISHED policies (each carries a current published version),
	// so they are legitimately linkable/readable references. D-draft is a
	// never-published draft used to exercise the draft-leak guards.
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"A-open":  {Id: "A-open", Number: "POL-OPEN-A", HomeCategoryId: "cat-open", CurrentPublishedVersionId: "A-open-v1"},
			"A-staff": {Id: "A-staff", Number: "POL-STAFF-A", HomeCategoryId: "cat-staff", CurrentPublishedVersionId: "A-staff-v1"},
			"B-open":  {Id: "B-open", Number: "POL-OPEN-B", HomeCategoryId: "cat-open", CurrentPublishedVersionId: "B-open-v1"},
			"B-staff": {Id: "B-staff", Number: "POL-STAFF-B", HomeCategoryId: "cat-staff", CurrentPublishedVersionId: "B-staff-v1"},
			"B-sens":  {Id: "B-sens", Number: "POL-OPEN-BS", HomeCategoryId: "cat-open", Sensitivity: corev1.Sensitivity_SENSITIVITY_SENSITIVE, CurrentPublishedVersionId: "B-sens-v1"},
			// Never published: draft only, cat-open, authored/owned by u-staff.
			// Readable in practice only by its overseers (here just its owner
			// u-staff, since cat-open defines no author rule) until it is published —
			// so its ACTUAL CURRENT reader set is {u-staff}, NOT the cat-open
			// read:everyone audience it would project once published.
			"D-draft": {Id: "D-draft", Number: "POL-OPEN-D", HomeCategoryId: "cat-open", OwnerUserId: "u-staff", CurrentDraftVersionId: "D-draft-d1"},
		},
		versions: map[string]*corev1.PolicyVersion{
			"A-open-v1":  {Id: "A-open-v1", PolicyId: "A-open"},
			"A-staff-v1": {Id: "A-staff-v1", PolicyId: "A-staff"},
			"B-open-v1":  {Id: "B-open-v1", PolicyId: "B-open"},
			"B-staff-v1": {Id: "B-staff-v1", PolicyId: "B-staff"},
			"B-sens-v1":  {Id: "B-sens-v1", PolicyId: "B-sens"},
			"D-draft-d1": {Id: "D-draft-d1", PolicyId: "D-draft"},
		},
	}
	return gc, ic, pc
}

// TestSetRelatedPolicies_ReadSupersetAllowed: readers(A-staff) ⊆ readers(B-open)
// (the two staff readers can also read the open policy) → the link is accepted
// and forwarded to core.
func TestSetRelatedPolicies_ReadSupersetAllowed(t *testing.T) {
	gc, ic, pc := core22Fixtures()
	rc := &fakeRelationClient{}
	ctx := ctxWithRoles(t, "u-staff", []string{"author"})

	out, err := resolvers.SetRelatedPoliciesResolver(ctx, log.Nop(), rc, pc, gc, ic, "A-staff", []string{"B-open"})
	if err != nil {
		t.Fatalf("expected link allowed, got error: %v", err)
	}
	if rc.lastSet == nil || len(rc.lastSet.RelatedPolicyIds) != 1 || rc.lastSet.RelatedPolicyIds[0] != "B-open" {
		t.Fatalf("expected forwarded set [B-open], got: %+v", rc.lastSet)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 related policy, got %d", len(out))
	}
}

// TestSetRelatedPolicies_ReadSupersetRejected: A-open is readable by u-contractor
// but B-staff is not → readers(A-open) ⊄ readers(B-staff) → FailedPrecondition,
// and core is never called.
func TestSetRelatedPolicies_ReadSupersetRejected(t *testing.T) {
	gc, ic, pc := core22Fixtures()
	rc := &fakeRelationClient{}
	ctx := ctxWithRoles(t, "u-staff", []string{"author"})

	_, err := resolvers.SetRelatedPoliciesResolver(ctx, log.Nop(), rc, pc, gc, ic, "A-open", []string{"B-staff"})
	if err == nil {
		t.Fatal("expected rejection linking a less-readable policy, got nil")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v (%v)", status.Code(err), err)
	}
	if rc.lastSet != nil {
		t.Fatalf("core must not be called on a rejected link, got: %+v", rc.lastSet)
	}
}

// TestSetRelatedPolicies_SensitivityRejected: B-sens is sensitive; u-staff reads
// A-open but lacks read-sensitive clearance so cannot read B-sens →
// readers(A-open) ⊄ readers(B-sens) → rejected.
func TestSetRelatedPolicies_SensitivityRejected(t *testing.T) {
	gc, ic, pc := core22Fixtures()
	rc := &fakeRelationClient{}
	ctx := ctxWithRoles(t, "u-cleared", []string{"author"})

	_, err := resolvers.SetRelatedPoliciesResolver(ctx, log.Nop(), rc, pc, gc, ic, "A-open", []string{"B-sens"})
	if err == nil {
		t.Fatal("expected rejection: a sensitive B unreadable by some A-readers must be blocked")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v (%v)", status.Code(err), err)
	}
	if rc.lastSet != nil {
		t.Fatalf("core must not be called on a rejected link, got: %+v", rc.lastSet)
	}
}

// TestSetRelatedPolicies_DraftRejected: D-draft has never been published, so it
// is readable only by its overseers and would dangle (and disclose a draft) for
// A-open's ordinary readers. Linking it is rejected up front and core is never
// called.
func TestSetRelatedPolicies_DraftRejected(t *testing.T) {
	gc, ic, pc := core22Fixtures()
	rc := &fakeRelationClient{}
	ctx := ctxWithRoles(t, "u-staff", []string{"author"})

	_, err := resolvers.SetRelatedPoliciesResolver(ctx, log.Nop(), rc, pc, gc, ic, "A-open", []string{"D-draft"})
	if err == nil {
		t.Fatal("expected rejection linking a never-published draft, got nil")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v (%v)", status.Code(err), err)
	}
	if rc.lastSet != nil {
		t.Fatalf("core must not be called on a rejected link, got: %+v", rc.lastSet)
	}
}

// TestSetRelatedPolicies_SameCategoryFastPath: A-open and B-open share a category
// and are both standard, so the same-category short-circuit admits the link
// without user enumeration.
func TestSetRelatedPolicies_SameCategoryFastPath(t *testing.T) {
	gc, ic, pc := core22Fixtures()
	rc := &fakeRelationClient{}
	ctx := ctxWithRoles(t, "u-staff", []string{"author"})

	if _, err := resolvers.SetRelatedPoliciesResolver(ctx, log.Nop(), rc, pc, gc, ic, "A-open", []string{"B-open"}); err != nil {
		t.Fatalf("same-category standard link must be allowed, got: %v", err)
	}
	if rc.lastSet == nil {
		t.Fatal("expected core call for an allowed same-category link")
	}
}

// TestSetRelatedPolicies_DraftSubjectActualReadersAllowed: the subject D-draft is
// a never-published draft in the broad cat-open (read:everyone) category, but its
// ACTUAL CURRENT readers are only its overseers — here just its owner u-staff
// (cat-open defines no author rule). readers(D-draft) = {u-staff} ⊆
// readers(B-staff) = {u-staff, u-cleared}, so linking the narrower B-staff is
// allowed. Under the old projected-published computation the draft
// would have been read-by-everyone and this link would have been rejected — this
// is exactly the draft-author picker/save case fixes.
func TestSetRelatedPolicies_DraftSubjectActualReadersAllowed(t *testing.T) {
	gc, ic, pc := core22Fixtures()
	rc := &fakeRelationClient{}
	ctx := ctxWithRoles(t, "u-staff", []string{"author"})

	out, err := resolvers.SetRelatedPoliciesResolver(ctx, log.Nop(), rc, pc, gc, ic, "D-draft", []string{"B-staff"})
	if err != nil {
		t.Fatalf("expected draft→narrower link allowed by actual-reader set, got error: %v", err)
	}
	if rc.lastSet == nil || len(rc.lastSet.RelatedPolicyIds) != 1 || rc.lastSet.RelatedPolicyIds[0] != "B-staff" {
		t.Fatalf("expected forwarded set [B-staff], got: %+v", rc.lastSet)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 related policy, got %d", len(out))
	}
}

// TestSetRelatedPolicies_DraftSubjectSensitiveStillRejected: the superset rule is
// still enforced against the draft's ACTUAL readers — its owner u-staff lacks
// read-sensitive clearance, so the sensitive B-sens is unreadable by a draft
// reader and the link is rejected. Confirms option 2 narrows readers(A) without
// weakening the check.
func TestSetRelatedPolicies_DraftSubjectSensitiveStillRejected(t *testing.T) {
	gc, ic, pc := core22Fixtures()
	rc := &fakeRelationClient{}
	ctx := ctxWithRoles(t, "u-staff", []string{"author"})

	_, err := resolvers.SetRelatedPoliciesResolver(ctx, log.Nop(), rc, pc, gc, ic, "D-draft", []string{"B-sens"})
	if err == nil {
		t.Fatal("expected rejection: a sensitive candidate unreadable by the draft's owner must be blocked")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v (%v)", status.Code(err), err)
	}
	if rc.lastSet != nil {
		t.Fatalf("core must not be called on a rejected link, got: %+v", rc.lastSet)
	}
}

// TestRelatedPolicyCandidates_DraftSubjectUsesActualReaders: the picker for the
// draft D-draft now offers every published policy readable by the draft's actual
// current readers ({u-staff}) — A-open, A-staff, B-open and B-staff all qualify.
// The sensitive B-sens (u-staff uncleared) is excluded, the draft itself and any
// never-published target are excluded. Previously the picker was EMPTY for this
// draft because it was treated as read-by-everyone; this is the fix.
func TestRelatedPolicyCandidates_DraftSubjectUsesActualReaders(t *testing.T) {
	baseGC, ic, pc := core22Fixtures()
	pc.listResult = []string{"A-open", "A-staff", "B-open", "B-staff", "B-sens", "D-draft"}

	gc := &viewerCategoryClient{
		raciCategoryClient: *baseGC,
		children: map[string][]*corev1.Category{
			"": {baseGC.groups["cat-open"], baseGC.groups["cat-staff"]},
		},
	}

	r := &resolvers.Resolver{
		PolicyClient:   pc,
		CategoryClient: gc,
		IdentityClient: ic,
	}

	// Site-admin caller sees every policy, so the candidate result is governed
	// purely by the read-superset filter over the draft's actual reader set.
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin", RolesValue: []string{"site-admin"}})

	cands, err := resolvers.RelatedPolicyCandidatesResolver(ctx, r, "D-draft")
	if err != nil {
		t.Fatalf("RelatedPolicyCandidatesResolver: %v", err)
	}

	got := make(map[string]bool, len(cands))
	for _, c := range cands {
		got[c.ID] = true
	}
	for _, want := range []string{"A-open", "A-staff", "B-open", "B-staff"} {
		if !got[want] {
			t.Errorf("expected %s to be an eligible candidate for the draft, got: %v", want, got)
		}
	}
	// B-sens unreadable by the draft's owner; D-draft is self + never-published.
	for _, bad := range []string{"B-sens", "D-draft"} {
		if got[bad] {
			t.Errorf("expected %s excluded from draft candidates, but present: %v", bad, got)
		}
	}
}

// TestRelatedPolicyCandidates_ExcludesIneligible: candidates for A-open (readers
// = everyone) are only policies readable by everyone who can read A-open. B-open
// qualifies; A-staff/B-staff (staff-only) and B-sens (sensitive) do not; A-open
// itself is excluded.
func TestRelatedPolicyCandidates_ExcludesIneligible(t *testing.T) {
	baseGC, ic, pc := core22Fixtures()
	pc.listResult = []string{"A-open", "A-staff", "B-open", "B-staff", "B-sens", "D-draft"}

	gc := &viewerCategoryClient{
		raciCategoryClient: *baseGC,
		children: map[string][]*corev1.Category{
			"": {baseGC.groups["cat-open"], baseGC.groups["cat-staff"]},
		},
	}

	r := &resolvers.Resolver{
		PolicyClient:   pc,
		CategoryClient: gc,
		IdentityClient: ic,
		// IdentityAdminClient nil → break-glass lookup is skipped.
	}

	// Site-admin caller sees every policy (obfuscated where merit-denied), so the
	// candidate result is governed purely by the read-superset filter.
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "admin", RolesValue: []string{"site-admin"}})

	cands, err := resolvers.RelatedPolicyCandidatesResolver(ctx, r, "A-open")
	if err != nil {
		t.Fatalf("RelatedPolicyCandidatesResolver: %v", err)
	}

	got := make(map[string]bool, len(cands))
	for _, c := range cands {
		got[c.ID] = true
	}
	if !got["B-open"] {
		t.Errorf("expected B-open to be an eligible candidate, got: %v", got)
	}
	// D-draft is never-published → not a citable reference; excluded.
	for _, bad := range []string{"A-open", "A-staff", "B-staff", "B-sens", "D-draft"} {
		if got[bad] {
			t.Errorf("expected %s excluded from candidates, but present: %v", bad, got)
		}
	}
}
