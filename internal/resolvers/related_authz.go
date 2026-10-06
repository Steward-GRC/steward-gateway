// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	log "github.com/Bugs5382/go-log"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// audienceMember is a fully-hydrated evaluation record for one platform user, built once per
// request and reused across every reader-set computation.
type audienceMember struct {
	eval     authz.Subject
	readSens authz.Subject
}

// readerAudience answers "readers(A) ⊆ readers(B)" for the related-policy read-superset rule.
type readerAudience struct {
	ctx            context.Context
	logger         log.Logger
	categoryClient corev1.CategoryServiceClient
	identity       identityv1.IdentityReadServiceClient

	members []audienceMember
	loaded  bool
	loadErr error

	chainByCat  map[string][]authz.CategoryRuleset
	readByKey   map[string]bool
	authorByKey map[string]bool
}

func newReaderAudience(ctx context.Context, logger log.Logger, categoryClient corev1.CategoryServiceClient, identity identityv1.IdentityReadServiceClient) *readerAudience {
	return &readerAudience{
		ctx:            ctx,
		logger:         logger,
		categoryClient: categoryClient,
		identity:       identity,
		chainByCat:     map[string][]authz.CategoryRuleset{},
		readByKey:      map[string]bool{},
		authorByKey:    map[string]bool{},
	}
}

// load enumerates every platform user once and hydrates the merit subject plus sensitivity
// clearance for each.
func (a *readerAudience) load() error {
	if a.loaded {
		return a.loadErr
	}
	a.loaded = true

	resp, err := a.identity.ListAllUsers(a.ctx, &identityv1.ListAllUsersRequest{})
	if err != nil {
		a.loadErr = fmt.Errorf("list all users for reader audience: %w", err)
		return a.loadErr
	}

	seen := make(map[string]struct{})
	for _, u := range resp.GetUsers() {
		uid := u.GetId()
		if uid == "" {
			continue
		}
		if _, dup := seen[uid]; dup {
			continue
		}
		seen[uid] = struct{}{}

		subj, err := subjectForUser(a.ctx, a.identity, uid)
		if err != nil {
			a.logger.Warn("reader audience skipped a user", log.F("user_id", uid), log.F("error", err.Error()))
			continue
		}
		roles := make([]authz.Role, 0, len(u.GetRoles()))
		for _, r := range u.GetRoles() {
			roles = append(roles, authz.Role(r))
		}

		a.members = append(a.members, audienceMember{
			eval: meritSubject(subj),
			readSens: authz.Subject{
				UserID:        uid,
				Roles:         roles,
				ReadSensitive: u.GetReadSensitiveGrant(),
			},
		})
	}
	return nil
}

// chainFor returns (and memoizes) the RACI category chain for a policy's home category.
func (a *readerAudience) chainFor(homeCategoryID string) []authz.CategoryRuleset {
	if c, ok := a.chainByCat[homeCategoryID]; ok {
		return c
	}
	chain, err := buildCategoryChain(a.ctx, a.categoryClient, homeCategoryID)
	if err != nil {
		a.logger.Warn("reader audience could not build a category chain", log.F("category_id", homeCategoryID), log.F("error", err.Error()))
		chain = nil
	}
	a.chainByCat[homeCategoryID] = chain
	return chain
}

// memberReads reports whether user m can read policy p: merit RACI read allowed AND the policy's
// sensitivity gate satisfied.
func (a *readerAudience) memberReads(m audienceMember, p *Policy) bool {
	key := m.eval.UserID + "\x00" + p.HomeCategoryID
	meritRead, ok := a.readByKey[key]
	if !ok {
		meritRead = authz.Resolve(a.ctx, m.eval, a.chainFor(p.HomeCategoryID)).Read.Allowed
		a.readByKey[key] = meritRead
	}
	if !meritRead {
		return false
	}
	return sensitivityGate(m.readSens, p) == authz.EffectAllow
}

// isDraftPolicy reports whether p has no current published version.
func isDraftPolicy(p *Policy) bool {
	return p.CurrentPublishedVersionID == nil || *p.CurrentPublishedVersionID == ""
}

// memberAuthors reports whether user m is a merit OVERSEER (author) of policy p:
// authz.Resolve(...).Author.Allowed AND the policy's sensitivity gate satisfied.
func (a *readerAudience) memberAuthors(m audienceMember, p *Policy) bool {
	key := m.eval.UserID + "\x00" + p.HomeCategoryID
	author, ok := a.authorByKey[key]
	if !ok {
		author = authz.Resolve(a.ctx, m.eval, a.chainFor(p.HomeCategoryID)).Author.Allowed
		a.authorByKey[key] = author
	}
	if !author {
		return false
	}
	return sensitivityGate(m.readSens, p) == authz.EffectAllow
}

// subjectReads reports whether user m is an ACTUAL CURRENT reader of the subject policy A — the
// reader set the read-superset rule is applied against, option 2): - PUBLISHED subject (has a
// current published version): its published audience, exactly as before (memberReads).
func (a *readerAudience) subjectReads(m audienceMember, subject *Policy) bool {
	if !isDraftPolicy(subject) {
		return a.memberReads(m, subject)
	}
	if subject.OwnerUserID != "" && m.eval.UserID == subject.OwnerUserID {
		return true
	}
	return a.memberAuthors(m, subject)
}

// readerSubsetOK reports whether readers(subject) ⊆ readers(candidate): every user who can read
// subject can also read candidate.
func (a *readerAudience) readerSubsetOK(subject, candidate *Policy) (bool, error) {
	if err := a.load(); err != nil {
		return false, err
	}

	if !isDraftPolicy(subject) && subject.HomeCategoryID == candidate.HomeCategoryID {
		if candidate.Sensitivity != SensitivitySensitive || subject.Sensitivity == SensitivitySensitive {
			return true, nil
		}
	}

	for _, m := range a.members {
		if a.subjectReads(m, subject) && !a.memberReads(m, candidate) {
			return false, nil
		}
	}
	return true, nil
}

// loadPolicyByID fetches a policy and converts it to the gateway model, mapping a missing policy to
// NotFound.
func loadPolicyByID(ctx context.Context, client corev1.PolicyServiceClient, id string) (*Policy, error) {
	resp, err := client.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: id})
	if err != nil {
		return nil, err
	}
	p := policyFromProto(resp.GetPolicy())
	if p == nil {
		return nil, status.Errorf(codes.NotFound, "policy %s not found", id)
	}
	return p, nil
}

// enforceReadSuperset rejects a related-policy set that would create a leaky reference: every
// proposed link B must be readable by (at least) everyone who can read the subject policy A —
// readers(A) ⊆ readers(B).
func enforceReadSuperset(ctx context.Context, logger log.Logger, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, identity identityv1.IdentityReadServiceClient, policyID string, relatedPolicyIDs []string) error {
	if policyClient == nil || categoryClient == nil || identity == nil || len(relatedPolicyIDs) == 0 {
		return nil
	}

	subject, err := loadPolicyByID(ctx, policyClient, policyID)
	if err != nil {
		return err
	}

	aud := newReaderAudience(ctx, logger, categoryClient, identity)
	for _, bid := range relatedPolicyIDs {
		if bid == policyID || bid == "" {
			continue
		}
		cand, err := loadPolicyByID(ctx, policyClient, bid)
		if err != nil {
			return err
		}
		if cand.CurrentPublishedVersionID == nil || *cand.CurrentPublishedVersionID == "" {
			return status.Errorf(codes.FailedPrecondition,
				"cannot link %s to %s: %s has no published version yet, so it isn't readable and the link would dangle for its readers",
				cand.Number, subject.Number, cand.Number)
		}
		ok, err := aud.readerSubsetOK(subject, cand)
		if err != nil {
			return err
		}
		if !ok {
			return status.Errorf(codes.FailedPrecondition,
				"cannot link %s to %s: %s is not readable by everyone who can read %s, so the link would be a dangling reference for some readers",
				cand.Number, subject.Number, cand.Number, subject.Number)
		}
	}
	return nil
}

// listAllPolicies walks every root category (the root sentinel) and returns the
// deduped set of policies across the estate — the server-side equivalent of the UI's fetchAll.
func listAllPolicies(ctx context.Context, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient) ([]*Policy, error) {
	if categoryClient == nil {
		return nil, status.Error(codes.Unavailable, "category service unavailable")
	}
	rootsResp, err := categoryClient.ListCategoryChildren(ctx, &corev1.ListCategoryChildrenRequest{ParentId: ""})
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var out []*Policy
	for _, g := range rootsResp.GetCategories() {
		resp, err := policyClient.ListPolicies(ctx, &corev1.ListPoliciesRequest{CategoryId: g.GetId(), IncludeDescendants: true})
		if err != nil {
			return nil, err
		}
		for _, pp := range resp.GetPolicies() {
			if _, dup := seen[pp.GetId()]; dup {
				continue
			}
			seen[pp.GetId()] = struct{}{}
			out = append(out, policyFromProto(pp))
		}
	}
	return out, nil
}

// RelatedPolicyCandidatesResolver returns the policies eligible to be linked as related to
// policyID: the visible estate minus the policy itself, minus any B that violates readers(policyID)
// ⊆ readers(B).
func RelatedPolicyCandidatesResolver(ctx context.Context, r *Resolver, policyID string) ([]*Policy, error) {
	if _, err := subjectFromCtx(ctx); err != nil {
		return nil, err
	}
	subject, err := loadPolicyByID(ctx, r.PolicyClient, policyID)
	if err != nil {
		return nil, err
	}
	all, err := listAllPolicies(ctx, r.PolicyClient, r.CategoryClient)
	if err != nil {
		return nil, err
	}
	visible, err := resolvePolicyReadModel(ctx, all, r.PolicyClient, r.CategoryClient, r.IdentityAdminClient, r.IdentityClient)
	if err != nil {
		return nil, err
	}

	aud := newReaderAudience(ctx, r.logger(), r.CategoryClient, r.IdentityClient)
	out := make([]*Policy, 0, len(visible))
	for _, cand := range visible {
		if cand.ID == subject.ID || cand.Number == subject.Number {
			continue
		}
		if cand.CurrentPublishedVersionID == nil || *cand.CurrentPublishedVersionID == "" {
			continue
		}
		ok, err := aud.readerSubsetOK(subject, cand)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, cand)
		}
	}
	return out, nil
}
