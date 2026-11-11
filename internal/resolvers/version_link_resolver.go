// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authz "github.com/Steward-GRC/steward-authz"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// The library links of a policy version (#135). Core's VersionLinkService
// stores them per version and enforces what may be linked and that only a
// version holding the draft slot changes. It looks at no caller, so the
// gateway adds three things: who may read a version's links (the read gate
// every version read goes through), who may change them (a caller who may not
// edit the policy is refused before core is asked), and what each related
// policy shows (one the caller cannot read is left out). The mock server
// (src/product/resolvers/links.ts) is the reference for each rule.

// Fixed sentences for the refusals core relays. Core's own text carries ids and
// store detail, so the client gets these and the original goes to the log.
const (
	msgLinkNotFound     = "That version, policy or library item was not found."
	msgLinkNotEditable  = "Links can only change while the version is a draft or in review."
	msgLinkInvalid      = "Those links are not valid. Name each item once, use a known relationship type and do not relate a policy to itself."
	msgLinkForbidden    = "You don't have permission to do that."
	msgPolicyNotFound   = "policy not found"
	msgLinksUnavailable = "library links are not available"
)

// versionLinkClient is the core client, or Unavailable when none is wired.
func (r *Resolver) versionLinkClient() (corev1.VersionLinkServiceClient, error) {
	if r.VersionLinkClient == nil {
		return nil, status.Error(codes.Unavailable, msgLinksUnavailable)
	}
	return r.VersionLinkClient, nil
}

// linkError turns a core refusal into a status with a fixed sentence and the
// same code. A code the gateway does not map is returned as it is, for the
// error presenter to show as a fault.
func (r *Resolver) linkError(op string, err error, fields ...log.Field) error {
	logger := r.logger()
	code := status.Code(err)
	args := append([]log.Field{log.F("op", op), log.F("code", code.String())}, fields...)
	switch code {
	case codes.NotFound:
		logger.Debug("version links: core refused, not found", append(args, log.F("core_message", status.Convert(err).Message()))...)
		return status.Error(codes.NotFound, msgLinkNotFound)
	case codes.FailedPrecondition:
		logger.Debug("version links: core refused, not editable", append(args, log.F("core_message", status.Convert(err).Message()))...)
		return status.Error(codes.FailedPrecondition, msgLinkNotEditable)
	case codes.InvalidArgument:
		logger.Debug("version links: core refused, invalid", append(args, log.F("core_message", status.Convert(err).Message()))...)
		return status.Error(codes.InvalidArgument, msgLinkInvalid)
	}
	logger.Error(err, "version links: core call failed", args...)
	return err
}

// canEditPolicy reports whether the caller may edit the policy. A refusal is
// false; any other failure is an error, never a quiet false.
func (r *Resolver) canEditPolicy(ctx context.Context, op, policyID string) (bool, error) {
	_, err := authorizeEffectiveAuthor(ctx, r.PolicyClient, r.CategoryClient, policyID)
	switch {
	case err == nil:
		return true, nil
	case status.Code(err) == codes.PermissionDenied:
		return false, nil
	}
	r.logger().Error(err, "version links: could not decide the edit right", log.F("op", op), log.F("policy_id", policyID))
	return false, err
}

// readableVersion loads a version under the read gate every version read uses:
// an unknown version, a draft the caller may not see and a denied read are all
// NotFound, and a break-glass read is recorded before anything is served.
func (r *Resolver) readableVersion(ctx context.Context, op, versionID string) (*PolicyVersion, error) {
	reads, _, err := authorizeVersionReads(ctx, r.PolicyClient, r.CategoryClient, r.IdentityAdminClient, r.WorkflowClient, versionID)
	if err != nil {
		r.logger().Debug("version links: version not readable", log.F("op", op), log.F("policy_version_id", versionID), log.F("code", status.Code(err).String()))
		return nil, err
	}
	return reads[0].version, nil
}

// relatedReach decides, once per policy for a request, whether a related policy is in
// the caller's read model: the read decision allows it, and a policy that was never
// published is shown only to someone who may edit it or holds an approval seat on its
// draft. It is the rule the older relatedPolicies query always applied, so a link never
// gives away a policy, or a draft, the caller could not otherwise see.
type relatedReach struct {
	r    *Resolver
	ctx  context.Context
	seen map[string]bool
}

func (r *Resolver) newRelatedReach(ctx context.Context) *relatedReach {
	return &relatedReach{r: r, ctx: ctx, seen: map[string]bool{}}
}

// visible fails closed: a policy that cannot be loaded or evaluated is not shown.
func (rr *relatedReach) visible(policyID string) bool {
	if v, ok := rr.seen[policyID]; ok {
		return v
	}
	ok := false
	if p, err := loadPolicyByID(rr.ctx, rr.r.PolicyClient, policyID); err != nil {
		rr.r.logger().Debug("version links: related policy not loaded", log.F("policy_id", policyID), log.F("code", status.Code(err).String()))
	} else if shown, err := resolvePolicyReadModel(rr.ctx, []*Policy{p}, rr.r.PolicyClient, rr.r.CategoryClient, rr.r.IdentityAdminClient, nil, rr.r.WorkflowClient); err != nil {
		rr.r.logger().Error(err, "version links: could not evaluate a related policy", log.F("policy_id", policyID))
	} else {
		ok = len(shown) == 1
	}
	rr.seen[policyID] = ok
	return ok
}

// shapeLinks maps core's VersionLinks to the GraphQL shape for this caller. related keeps
// core's order (the version's own links, then the incoming ones); a policy that is not in
// the caller's read model is left out.
func (r *Resolver) shapeLinks(ctx context.Context, l *corev1.VersionLinks, editable bool) *PolicyVersionLinks {
	reach := r.newRelatedReach(ctx)
	related := make([]*RelatedLink, 0, len(l.GetRelated()))
	hidden := 0
	for _, rel := range l.GetRelated() {
		if !reach.visible(rel.GetPolicyId()) {
			hidden++
			continue
		}
		related = append(related, &RelatedLink{
			PolicyID: rel.GetPolicyId(), Number: rel.GetNumber(), Title: rel.GetTitle(),
			Type: rel.GetRelationType(), Label: rel.GetLabel(), Direction: relatedDirectionFromProto(rel.GetDirection()),
		})
	}
	if hidden > 0 {
		log.Trace(r.logger(), "version links: related policies left out for the caller", log.F("policy_version_id", l.GetPolicyVersionId()), log.F("hidden", hidden))
	}
	return &PolicyVersionLinks{
		PolicyVersionID: l.GetPolicyVersionId(),
		Editable:        editable,
		Definitions:     definitionEntriesFromProto(l.GetDefinitions()),
		Related:         related,
		References:      referencesFromProto(l.GetReferences()),
		Contacts:        contactBlocksFromProto(l.GetContacts()),
	}
}

func relatedDirectionFromProto(d corev1.RelatedDirection) RelatedDirection {
	if d == corev1.RelatedDirection_RELATED_DIRECTION_INCOMING {
		return RelatedDirectionIncoming
	}
	return RelatedDirectionOutgoing
}

// RelationshipTypesResolver lists the fixed relationship types, each with its inverse.
func (r *Resolver) RelationshipTypesResolver(ctx context.Context) ([]*RelationshipTypeInfo, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	client, err := r.versionLinkClient()
	if err != nil {
		return nil, err
	}
	started := time.Now()
	resp, err := client.ListRelationshipTypes(ctx, &corev1.ListRelationshipTypesRequest{})
	if err != nil {
		return nil, r.linkError("relationshipTypes", err, log.F("duration_ms", time.Since(started).Milliseconds()))
	}
	out := make([]*RelationshipTypeInfo, 0, len(resp.GetTypes()))
	for _, t := range resp.GetTypes() {
		out = append(out, &RelationshipTypeInfo{ID: t.GetId(), Label: t.GetLabel(), InverseID: t.GetInverseId(), InverseLabel: t.GetInverseLabel()})
	}
	log.Trace(r.logger(), "relationship types listed", log.F("count", len(out)), log.F("duration_ms", time.Since(started).Milliseconds()))
	return out, nil
}

// PolicyVersionLinksResolver reads what one version links to. The caller must be
// able to read the version; editable is core's status flag and the caller's own
// right to edit the policy.
func (r *Resolver) PolicyVersionLinksResolver(ctx context.Context, versionID string) (*PolicyVersionLinks, error) {
	logger := r.logger()
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	client, err := r.versionLinkClient()
	if err != nil {
		return nil, err
	}
	v, err := r.readableVersion(ctx, "policyVersionLinks", versionID)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	resp, err := client.GetVersionLinks(ctx, &corev1.GetVersionLinksRequest{PolicyVersionId: versionID})
	if err != nil {
		return nil, r.linkError("policyVersionLinks", err, log.F("policy_version_id", versionID), log.F("duration_ms", time.Since(started).Milliseconds()))
	}
	editable := false
	if resp.GetLinks().GetEditable() {
		if editable, err = r.canEditPolicy(ctx, "policyVersionLinks", v.PolicyID); err != nil {
			return nil, err
		}
	}
	out := r.shapeLinks(ctx, resp.GetLinks(), editable)
	logger.Debug("version links read", log.F("policy_version_id", versionID), log.F("policy_id", v.PolicyID),
		log.F("editable", editable), log.F("related", len(out.Related)), log.F("duration_ms", time.Since(started).Milliseconds()))
	return out, nil
}

// editableLinkTarget is the part every Set shares, in the order that matters:
// the read gate (an unknown or unseen version is NotFound), then the right to
// edit the policy (PermissionDenied). Core is asked only after both, so a
// caller who may not edit never reaches it.
func (r *Resolver) editableLinkTarget(ctx context.Context, op, versionID string) (corev1.VersionLinkServiceClient, *PolicyVersion, string, error) {
	logger := r.logger()
	claims, err := signedIn(ctx)
	if err != nil {
		logger.Debug("version links write refused: no signed-in user", log.F("op", op))
		return nil, nil, "", err
	}
	client, err := r.versionLinkClient()
	if err != nil {
		return nil, nil, "", err
	}
	v, err := r.readableVersion(ctx, op, versionID)
	if err != nil {
		return nil, nil, "", err
	}
	canEdit, err := r.canEditPolicy(ctx, op, v.PolicyID)
	if err != nil {
		return nil, nil, "", err
	}
	if !canEdit {
		logger.Info("version links write refused: the caller may not edit the policy",
			log.F("op", op), log.F("policy_version_id", versionID), log.F("policy_id", v.PolicyID))
		return nil, nil, "", status.Error(codes.PermissionDenied, msgLinkForbidden)
	}
	return client, v, claims.UserID(), nil
}

// finishSet shapes a Set response. The caller passed the edit check, so
// editable is core's status flag.
func (r *Resolver) finishSet(ctx context.Context, op string, v *PolicyVersion, links *corev1.VersionLinks, started time.Time) *PolicyVersionLinks {
	out := r.shapeLinks(ctx, links, links.GetEditable())
	r.logger().Info("version links changed", log.F("op", op), log.F("policy_version_id", v.ID), log.F("policy_id", v.PolicyID),
		log.F("duration_ms", time.Since(started).Milliseconds()))
	return out
}

// SetVersionReferencesResolver replaces the version's references, in the order given.
func (r *Resolver) SetVersionReferencesResolver(ctx context.Context, versionID string, referenceIDs []string) (*PolicyVersionLinks, error) {
	const op = "setVersionReferences"
	client, v, actor, err := r.editableLinkTarget(ctx, op, versionID)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	resp, err := client.SetVersionReferences(ctx, &corev1.SetVersionReferencesRequest{PolicyVersionId: versionID, ReferenceIds: referenceIDs, ActorUserId: actor})
	if err != nil {
		return nil, r.linkError(op, err, log.F("policy_version_id", versionID), log.F("count", len(referenceIDs)))
	}
	return r.finishSet(ctx, op, v, resp.GetLinks(), started), nil
}

// SetVersionContactsResolver replaces the version's contact blocks, in the order given.
func (r *Resolver) SetVersionContactsResolver(ctx context.Context, versionID string, contactBlockIDs []string) (*PolicyVersionLinks, error) {
	const op = "setVersionContacts"
	client, v, actor, err := r.editableLinkTarget(ctx, op, versionID)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	resp, err := client.SetVersionContactBlocks(ctx, &corev1.SetVersionContactBlocksRequest{PolicyVersionId: versionID, ContactBlockIds: contactBlockIDs, ActorUserId: actor})
	if err != nil {
		return nil, r.linkError(op, err, log.F("policy_version_id", versionID), log.F("count", len(contactBlockIDs)))
	}
	return r.finishSet(ctx, op, v, resp.GetLinks(), started), nil
}

// SetVersionDefinitionsResolver replaces the version's definitions. They carry no
// order: core lists them alphabetically.
func (r *Resolver) SetVersionDefinitionsResolver(ctx context.Context, versionID string, definitionIDs []string) (*PolicyVersionLinks, error) {
	const op = "setVersionDefinitions"
	client, v, actor, err := r.editableLinkTarget(ctx, op, versionID)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	resp, err := client.SetVersionDefinitions(ctx, &corev1.SetVersionDefinitionsRequest{PolicyVersionId: versionID, DefinitionIds: definitionIDs, ActorUserId: actor})
	if err != nil {
		return nil, r.linkError(op, err, log.F("policy_version_id", versionID), log.F("count", len(definitionIDs)))
	}
	return r.finishSet(ctx, op, v, resp.GetLinks(), started), nil
}

// SetVersionRelatedResolver replaces the version's own related policies, in the
// order given. A target the caller cannot read is NotFound before core is asked,
// the same as one that does not exist, so a link cannot confirm a hidden policy.
func (r *Resolver) SetVersionRelatedResolver(ctx context.Context, versionID string, links []*RelatedLinkInput) (*PolicyVersionLinks, error) {
	const op = "setVersionRelated"
	client, v, actor, err := r.editableLinkTarget(ctx, op, versionID)
	if err != nil {
		return nil, err
	}
	reach := r.newRelatedReach(ctx)
	in := make([]*corev1.RelatedLinkInput, 0, len(links))
	for _, l := range links {
		if l == nil {
			continue
		}
		// the version's own policy is for core to refuse as invalid; every other
		// target must be readable by the caller
		if l.PolicyID != v.PolicyID && !reach.visible(l.PolicyID) {
			r.logger().Debug("version links: related target not readable by the caller", log.F("op", op), log.F("policy_version_id", versionID), log.F("target_policy_id", l.PolicyID))
			return nil, status.Error(codes.NotFound, msgLinkNotFound)
		}
		in = append(in, &corev1.RelatedLinkInput{PolicyId: l.PolicyID, RelationType: l.Type})
	}
	started := time.Now()
	resp, err := client.SetVersionRelated(ctx, &corev1.SetVersionRelatedRequest{PolicyVersionId: versionID, Links: in, ActorUserId: actor})
	if err != nil {
		return nil, r.linkError(op, err, log.F("policy_version_id", versionID), log.F("count", len(in)))
	}
	return r.finishSet(ctx, op, v, resp.GetLinks(), started), nil
}

// policyLinks reads the links of the version a per-policy query stands for: the
// published version, else the draft. It is nil, with no error, when the policy
// has neither or the caller may not see the one it has (a draft is not
// confirmed to someone who may not see it). A policy the caller cannot read is
// NotFound.
func (r *Resolver) policyLinks(ctx context.Context, op, policyID string) (*PolicyVersionLinks, error) {
	logger := r.logger()
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	client, err := r.versionLinkClient()
	if err != nil {
		return nil, err
	}
	effect, _ := versionReadDecision(ctx, r.PolicyClient, r.CategoryClient, r.IdentityAdminClient, policyID)
	if effect == authz.EffectDeny {
		logger.Debug("policy links refused by the policy read decision", log.F("op", op), log.F("policy_id", policyID))
		return nil, status.Error(codes.NotFound, msgPolicyNotFound)
	}
	p, err := loadPolicyByID(ctx, r.PolicyClient, policyID)
	if err != nil {
		return nil, err
	}
	versionID := derefOrEmpty(p.CurrentPublishedVersionID)
	which := "published"
	if versionID == "" {
		versionID, which = derefOrEmpty(p.CurrentDraftVersionID), "draft"
	}
	if versionID == "" {
		log.Trace(logger, "policy links: the policy has no version", log.F("op", op), log.F("policy_id", policyID))
		return nil, nil
	}
	if _, err := r.readableVersion(ctx, op, versionID); err != nil {
		if status.Code(err) == codes.NotFound {
			logger.Debug("policy links: the version is not visible to the caller", log.F("op", op), log.F("policy_id", policyID), log.F("version", which))
			return nil, nil
		}
		return nil, err
	}
	started := time.Now()
	resp, err := client.GetVersionLinks(ctx, &corev1.GetVersionLinksRequest{PolicyVersionId: versionID})
	if err != nil {
		return nil, r.linkError(op, err, log.F("policy_id", policyID), log.F("policy_version_id", versionID), log.F("duration_ms", time.Since(started).Milliseconds()))
	}
	logger.Debug("policy links read from a version", log.F("op", op), log.F("policy_id", policyID), log.F("version", which),
		log.F("policy_version_id", versionID), log.F("duration_ms", time.Since(started).Milliseconds()))
	return r.shapeLinks(ctx, resp.GetLinks(), false), nil
}

// RelatedPoliciesResolver is the older relatedPolicies query, answered from the
// links of the policy's published version, else its draft. Only the policy's own
// links (OUTGOING) are listed; the incoming side is new and has no place here.
func (r *Resolver) RelatedPoliciesResolver(ctx context.Context, policyID string) ([]*RelatedPolicy, error) {
	links, err := r.policyLinks(ctx, "relatedPolicies", policyID)
	if err != nil {
		return nil, err
	}
	out := []*RelatedPolicy{}
	if links == nil {
		return out, nil
	}
	for _, l := range links.Related {
		if l.Direction == RelatedDirectionOutgoing {
			out = append(out, &RelatedPolicy{PolicyID: l.PolicyID, Number: l.Number, Title: l.Title})
		}
	}
	return out, nil
}

// PolicyReferencesResolver is the older policyReferences query, from the published version, else the draft.
func (r *Resolver) PolicyReferencesResolver(ctx context.Context, policyID string) ([]*Reference, error) {
	links, err := r.policyLinks(ctx, "policyReferences", policyID)
	if err != nil || links == nil {
		return []*Reference{}, err
	}
	return links.References, nil
}

// PolicyContactBlocksResolver is the older policyContactBlocks query, from the published version, else the draft.
func (r *Resolver) PolicyContactBlocksResolver(ctx context.Context, policyID string) ([]*ContactBlock, error) {
	links, err := r.policyLinks(ctx, "policyContactBlocks", policyID)
	if err != nil || links == nil {
		return []*ContactBlock{}, err
	}
	return links.Contacts, nil
}

// PolicyDefinitionEntriesResolver is the older policyDefinitionEntries query, from the published version, else the draft.
func (r *Resolver) PolicyDefinitionEntriesResolver(ctx context.Context, policyID string) ([]*DefinitionEntry, error) {
	links, err := r.policyLinks(ctx, "policyDefinitionEntries", policyID)
	if err != nil || links == nil {
		return []*DefinitionEntry{}, err
	}
	return links.Definitions, nil
}
