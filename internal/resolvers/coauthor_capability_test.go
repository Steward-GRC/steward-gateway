// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// a category co-author/co-approver whose grant comes ONLY from a
// category_rules row (System A), with NO global/scoped role (System B), must
// still receive the corresponding capabilities: draft visibility + edit,
// create, and — at the me()/nav layer — the author/approver scopes that gate
// the create affordance and the Approvals/Templates navs. These tests pin all
// of that, plus the "fail loud, never silently deny/hide" behaviour when the
// merit chain genuinely cannot be built.

const bobID = "bob-9766"

// userApproveRule returns a USER-kind RACI rule granting/denying APPROVE to a
// specific user id in a category (mirrors authorRule for the approve tag).
func userApproveRule(userID string, effect corev1.GrantEffect) *corev1.CategoryRule {
	return &corev1.CategoryRule{
		SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
		SubjectRef:  userID,
		Approve:     effect,
	}
}

// erroringCategoryClient simulates a LIVE GroupService whose category-chain build
// fails at runtime (an unhandled backend condition). GetGroup always errors, so
// buildCategoryChain returns an error — reproducing the
// degraded path in which the read/authoring gates used to silently fall back to
// the System-B-only decision and strip a legitimate co-author.
type erroringCategoryClient struct {
	*raciCategoryClient
}

func (e *erroringCategoryClient) GetCategory(_ context.Context, _ *corev1.GetCategoryRequest, _ ...grpc.CallOption) (*corev1.GetCategoryResponse, error) {
	return nil, status.Error(codes.Unavailable, "group service boom")
}

// draftOnlyCoAuthorEnv builds a NEVER-published (draft-only) policy "pol" in
// category "g-cat" owned by a DIFFERENT user (an admin), with an everyone-read
// rule plus the supplied extra rules. This is the exact prod shape: the only way
// a category-only co-author sees/edits the draft is via their System-A grant.
func draftOnlyCoAuthorEnv(extra []*corev1.CategoryRule) (*fakePolicyClient, *raciCategoryClient) {
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol": {
				Id:                    "pol",
				HomeCategoryId:        "g-cat",
				Number:                "POL-CAT-1",
				Title:                 "Draft only",
				OwnerUserId:           "admin-u", // owned by someone else
				CurrentDraftVersionId: "draft-1",
				// CurrentPublishedVersionId intentionally empty → never published.
			},
		},
		versions: map[string]*corev1.PolicyVersion{
			"draft-1": {Id: "draft-1", PolicyId: "pol", VersionNo: 1, Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT, ContentJson: `{"root":{}}`},
		},
	}
	rules := append([]*corev1.CategoryRule{allowEveryoneRule()}, extra...)
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT", ParentId: ""}},
		map[string][]*corev1.CategoryRule{"g-cat": rules},
	)
	return pc, gc
}

// TestCoAuthorDraftVisible_HappyPath is the primary reproduction: with a working
// chain, a category-only co-author (author=allow user rule, NO global role) sees
// the never-published draft policy AND gets ViewerCan.Edit=true + the draft
// pointer. This is the behaviour prod was missing.
func TestCoAuthorDraftVisible_HappyPath(t *testing.T) {
	pc, gc := draftOnlyCoAuthorEnv([]*corev1.CategoryRule{authorRule(bobID, corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: bobID}) // no roles

	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol")
	if err != nil {
		t.Fatalf("co-author must see their draft policy; got err %v", err)
	}
	if p.ViewerCan == nil || !p.ViewerCan.Edit {
		t.Fatalf("category co-author must have ViewerCan.Edit=true; got %+v", p.ViewerCan)
	}
	if p.CurrentDraftVersionID == nil || *p.CurrentDraftVersionID != "draft-1" {
		t.Fatalf("editor must keep the draft pointer; got %v", p.CurrentDraftVersionID)
	}
}

// TestCoAuthorDraftHidden_NonAuthor is the negative guard: a plain reader (only
// everyone-read, no author grant) must NOT see the never-published draft — its
// existence is not leaked (NotFound). Confirms the fix does not weaken hiding.
func TestCoAuthorDraftHidden_NonAuthor(t *testing.T) {
	pc, gc := draftOnlyCoAuthorEnv(nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}})

	_, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol")
	if status.Code(err) != codes.NotFound {
		t.Fatalf("non-author must NOT see a never-published draft (want NotFound); got %v", err)
	}
}

// TestCoAuthorDraft_ChainErrorFailsLoud pins the degraded path: when the merit
// chain genuinely cannot be built, the read model must FAIL LOUD (error) rather
// than silently falling back to the System-B gate and hiding the co-author's
// draft. Pre-fix this returned the policy stripped of Edit (draft vanished) with
// no error — the silent close that produced the prod symptom.
func TestCoAuthorDraft_ChainErrorFailsLoud(t *testing.T) {
	pc, gc := draftOnlyCoAuthorEnv([]*corev1.CategoryRule{authorRule(bobID, corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	egc := &erroringCategoryClient{raciCategoryClient: gc}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: bobID})

	_, err := resolvers.GetPolicy(ctx, pc, egc, nil, nil, "pol")
	if err == nil {
		t.Fatal("a genuine chain-build failure must fail loud, not silently hide the draft")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal on chain-build failure; got %v", err)
	}
}

// meScopeCategoryClient carries a single root category with rules, and a BFS tree,
// so MeResolver's merit walk can discover the caller's author/approver scopes.
func meScopeCategoryClient(catName string, rules []*corev1.CategoryRule) *viewerCategoryClient {
	g := &corev1.Category{Id: "g-cat", Name: catName, ParentId: ""}
	return &viewerCategoryClient{
		raciCategoryClient: raciCategoryClient{
			groups:   map[string]*corev1.Category{"g-cat": g},
			rulesets: map[string][]*corev1.CategoryRule{"g-cat": rules},
		},
		children: map[string][]*corev1.Category{"": {g}},
	}
}

// TestMeScopes_CategoryRuleAuthor pins the nav fix: a non-owner co-author whose
// authorship comes ONLY from a category_rules author rule appears in
// me().scopes.author (gates the create affordance + Templates nav) — and NOT in
// approver, since the rule grants author only.
func TestMeScopes_CategoryRuleAuthor(t *testing.T) {
	gc := meScopeCategoryClient("Facilities", []*corev1.CategoryRule{authorRule(bobID, corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	read := &fakeReadClient{getUserResp: &identityv1.GetUserResponse{User: &identityv1.User{Id: bobID}}}

	out, err := resolvers.MeResolver(ctxWithUser(t, bobID), read, gc)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if !containsStr(out.Scopes.Author, "Facilities") {
		t.Errorf("category_rules author grant must surface in me().scopes.author; got %v", out.Scopes.Author)
	}
	if containsStr(out.Scopes.Approver, "Facilities") {
		t.Errorf("author-only rule must NOT confer approver scope; got %v", out.Scopes.Approver)
	}
}

// TestMeScopes_CategoryRuleApprover pins the Approvals-nav fix: a non-owner
// co-approver whose approve grant comes ONLY from a category_rules approve rule
// appears in me().scopes.approver (gates the Approvals tab/nav).
func TestMeScopes_CategoryRuleApprover(t *testing.T) {
	gc := meScopeCategoryClient("Facilities", []*corev1.CategoryRule{userApproveRule(bobID, corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	read := &fakeReadClient{getUserResp: &identityv1.GetUserResponse{User: &identityv1.User{Id: bobID}}}

	out, err := resolvers.MeResolver(ctxWithUser(t, bobID), read, gc)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if !containsStr(out.Scopes.Approver, "Facilities") {
		t.Errorf("category_rules approve grant must surface in me().scopes.approver; got %v", out.Scopes.Approver)
	}
}

// TestMeScopes_NoGrantEmpty is the negative guard: a user with no global role,
// no ownership, and no category_rules grant gets empty scopes (no nav leak).
func TestMeScopes_NoGrantEmpty(t *testing.T) {
	gc := meScopeCategoryClient("Facilities", []*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	read := &fakeReadClient{getUserResp: &identityv1.GetUserResponse{User: &identityv1.User{Id: bobID}}}

	out, err := resolvers.MeResolver(ctxWithUser(t, bobID), read, gc)
	if err != nil {
		t.Fatalf("MeResolver: %v", err)
	}
	if len(out.Scopes.Author) != 0 || len(out.Scopes.Approver) != 0 {
		t.Errorf("a non-granted user must have empty scopes; got author=%v approver=%v", out.Scopes.Author, out.Scopes.Approver)
	}
}

// TestCreatePolicy_CategoryAuthorAllowed: a category-only co-author (author=allow
// user rule, no global role) may CREATE a policy in that category, and is bound
// as the owner/actor.
func TestCreatePolicy_CategoryAuthorAllowed(t *testing.T) {
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{}}
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT"}},
		map[string][]*corev1.CategoryRule{"g-cat": {authorRule(bobID, corev1.GrantEffect_GRANT_EFFECT_ALLOW)}},
	)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: bobID})

	_, err := resolvers.CreatePolicy(ctx, pc, gc, "g-cat", "New Policy", resolvers.SensitivityStandard, nil, nil)
	if err != nil {
		t.Fatalf("category co-author must be allowed to create; got %v", err)
	}
	if pc.lastCreate == nil || pc.lastCreate.OwnerUserId != bobID {
		t.Fatalf("owner must be bound to the co-author; got %+v", pc.lastCreate)
	}
}

// TestCreatePolicy_NonAuthorDenied: a user with no author grant for the target
// category is denied, and core CreatePolicy is never called.
func TestCreatePolicy_NonAuthorDenied(t *testing.T) {
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{}}
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT"}},
		map[string][]*corev1.CategoryRule{"g-cat": {authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)}},
	)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}})

	_, err := resolvers.CreatePolicy(ctx, pc, gc, "g-cat", "New Policy", resolvers.SensitivityStandard, nil, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-author create must be PermissionDenied; got %v", err)
	}
	if pc.lastCreate != nil {
		t.Fatal("core CreatePolicy must NOT be called when denied")
	}
}

// TestCreatePolicy_ChainErrorFailsLoud: a genuine chain-build failure on create
// must fail loud (Internal), never silently deny the co-author; core untouched.
func TestCreatePolicy_ChainErrorFailsLoud(t *testing.T) {
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{}}
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT"}},
		map[string][]*corev1.CategoryRule{"g-cat": {authorRule(bobID, corev1.GrantEffect_GRANT_EFFECT_ALLOW)}},
	)
	egc := &erroringCategoryClient{raciCategoryClient: gc}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: bobID})

	_, err := resolvers.CreatePolicy(ctx, pc, egc, "g-cat", "New Policy", resolvers.SensitivityStandard, nil, nil)
	if status.Code(err) != codes.Internal {
		t.Fatalf("chain-build failure on create must fail loud (Internal); got %v", err)
	}
	if pc.lastCreate != nil {
		t.Fatal("core CreatePolicy must NOT be called on chain-build failure")
	}
}

// TestSaveDraft_ChainErrorFailsLoud: a genuine chain-build failure while editing
// must fail loud rather than silently denying the co-author; core untouched.
func TestSaveDraft_ChainErrorFailsLoud(t *testing.T) {
	pc, gc := coAuthMatrixEnv("admin-u", nil, []*corev1.CategoryRule{authorRule(bobID, corev1.GrantEffect_GRANT_EFFECT_ALLOW)})
	egc := &erroringCategoryClient{raciCategoryClient: gc}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: bobID})

	_, err := resolvers.SaveDraft(ctx, pc, egc, "pol", `{"root":{}}`, "")
	if status.Code(err) != codes.Internal {
		t.Fatalf("chain-build failure on save must fail loud (Internal); got %v", err)
	}
	if pc.lastSave != nil {
		t.Fatal("core SaveDraft must NOT be called on chain-build failure")
	}
}

// TestPrimaryAuthorViewerCanEdit: a policy's PRIMARY author (owner_user_id ==
// caller) gets ViewerCan.Edit + Submit even with NO global role and NO RACI
// author rule — so the read-side projection matches authorizeEffectiveAuthor's
// primary-author grant. Otherwise a creator whose category-author grant was
// later removed can still edit via the mutation gate while the UI hides every
// author affordance (the AI toolbar gates on viewerCan.edit).
func TestPrimaryAuthorViewerCanEdit(t *testing.T) {
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			"pol": {
				Id:                    "pol",
				HomeCategoryId:        "g-cat",
				Number:                "POL-CAT-2",
				Title:                 "Owned",
				OwnerUserId:           bobID, // caller IS the primary author
				CurrentDraftVersionId: "draft-1",
			},
		},
		versions: map[string]*corev1.PolicyVersion{
			"draft-1": {Id: "draft-1", PolicyId: "pol", VersionNo: 1, Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT, ContentJson: `{"root":{}}`},
		},
	}
	// Category grants read to everyone but has NO author rule for Bob, and Bob
	// does NOT own the category — his only authoring path is being the policy owner.
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-cat": {Id: "g-cat", Name: "CAT"}},
		map[string][]*corev1.CategoryRule{"g-cat": {allowEveryoneRule()}},
	)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: bobID}) // no roles

	p, err := resolvers.GetPolicy(ctx, pc, gc, nil, nil, "pol")
	if err != nil {
		t.Fatalf("primary author must see their policy; got %v", err)
	}
	if p.ViewerCan == nil || !p.ViewerCan.Edit || !p.ViewerCan.Submit {
		t.Fatalf("primary author must have ViewerCan.Edit+Submit=true; got %+v", p.ViewerCan)
	}
	if p.CurrentDraftVersionID == nil || *p.CurrentDraftVersionID != "draft-1" {
		t.Fatalf("primary-author editor must keep the draft pointer; got %v", p.CurrentDraftVersionID)
	}
}

// TestDiscardDraft_PrimaryCoAuthorAllowed: a co-author who authored their OWN
// draft (they are the policy's primary author) may discard it — the realistic
// end-to-end path once create/edit work. A category owner and site-admin may
// also discard; a regular non-owner co-author may not (covered by the existing
// TestCoAuthoring_DestructiveMatrix).
func TestDiscardDraft_PrimaryCoAuthorAllowed(t *testing.T) {
	pc, gc := coAuthMatrixEnv(bobID, nil, nil) // Bob is the primary author
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: bobID})

	ok, err := resolvers.DiscardDraft(ctx, pc, gc, "pol")
	if err != nil || !ok {
		t.Fatalf("primary-author co-author must discard their own draft; ok=%v err=%v", ok, err)
	}
	if pc.lastDiscard == nil || pc.lastDiscard.ActorUserId != bobID {
		t.Fatalf("discard actor must be bound to the caller; got %+v", pc.lastDiscard)
	}
}
