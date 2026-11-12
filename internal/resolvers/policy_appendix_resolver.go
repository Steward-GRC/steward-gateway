// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"slices"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	collabv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/collab/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	authz "github.com/Steward-GRC/steward-gateway/internal/authz"
)

// The appendix life cycle (#123). An appendix belongs to a policy, not to one
// of its versions. Core stores the version table and returns the published row
// and the draft side by side without looking at who asks; the gateway decides
// what the caller sees. Editors (whoever may edit the policy, a site admin
// included) see the drafts, every row, the retired appendices on request and
// the contributors. Anyone else who may read the policy sees the latest
// published row of the appendices that have one, and nothing more. The mock
// server (appendices.ts) is the reference for each rule.

var errAppendixForbidden = status.Error(codes.PermissionDenied, "You don't have permission to do that.")

// appendixAccess is what the gateway decided about one caller on one policy.
type appendixAccess struct {
	// editor is true when the caller may edit the policy.
	editor bool
	// insight is true when the caller sees the diff and the contributors: an
	// editor, a site admin, or compliance (the catalog's compliance.report).
	// It adds no right to write.
	insight bool
	// effect is the read effect on the policy: allow, or obfuscate to scramble the text.
	effect authz.Effect
}

// appendixAccessFor decides the caller's access to a policy's appendices. The
// order is fixed: the read decision first (a denied read is NotFound, as for a
// version), then the right to edit.
func (r *Resolver) appendixAccessFor(ctx context.Context, op, policyID string) (appendixAccess, error) {
	logger := r.logger()
	effect, breakGlass := versionReadDecision(ctx, r.PolicyClient, r.CategoryClient, r.IdentityAdminClient, policyID)
	if effect == authz.EffectDeny {
		logger.Debug("appendix refused by the policy read decision", log.F("op", op), log.F("policy_id", policyID))
		return appendixAccess{}, status.Error(codes.NotFound, "policy not found")
	}
	if breakGlass {
		if err := recordBreakGlassRead(ctx, r.PolicyClient, policyID, ""); err != nil {
			logger.Error(err, "appendix: could not record the break-glass read", log.F("op", op), log.F("policy_id", policyID))
			return appendixAccess{}, err
		}
	}
	access := appendixAccess{effect: effect}
	if _, aerr := authorizeEffectiveAuthor(ctx, r.PolicyClient, r.CategoryClient, policyID); aerr == nil {
		access.editor = true
	} else if status.Code(aerr) != codes.PermissionDenied {
		logger.Error(aerr, "appendix: could not decide the author right",
			log.F("op", op), log.F("policy_id", policyID), log.F("code", status.Code(aerr).String()))
		return appendixAccess{}, aerr
	}
	access.insight = access.editor
	if !access.insight {
		if subj, serr := subjectFromCtx(ctx); serr == nil {
			access.insight = authz.IsSiteAdmin(subj) || authz.HasCapability(subj, authz.ComplianceReport)
		}
	}
	log.Trace(logger, "appendix access decided", log.F("op", op), log.F("policy_id", policyID),
		log.F("editor", access.editor), log.F("insight", access.insight), log.F("effect", string(effect)))
	return access, nil
}

// appendixClient is the core client, or Unavailable when none is wired.
func (r *Resolver) appendixClient() (corev1.PolicyAppendixServiceClient, error) {
	if r.PolicyAppendixClient == nil {
		return nil, status.Error(codes.Unavailable, "appendices are not available")
	}
	return r.PolicyAppendixClient, nil
}

// editableAppendix finds an appendix by id and checks the caller may edit its
// policy, before any write. Core looks the appendix up (no actor check on a
// read); an unknown id is NotFound, a caller who cannot edit PermissionDenied.
func (r *Resolver) editableAppendix(ctx context.Context, op, id string) (corev1.PolicyAppendixServiceClient, appendixAccess, string, error) {
	client, access, actor, _, err := r.editableAppendixRow(ctx, op, id)
	return client, access, actor, err
}

// editableAppendixRow is editableAppendix that also returns the row core
// found, for the callers that need its policy or its retired state.
func (r *Resolver) editableAppendixRow(ctx context.Context, op, id string) (corev1.PolicyAppendixServiceClient, appendixAccess, string, *corev1.PolicyAppendix, error) {
	logger := r.logger()
	claims, err := signedIn(ctx)
	if err != nil {
		logger.Debug("appendix refused: no signed-in user", log.F("op", op))
		return nil, appendixAccess{}, "", nil, err
	}
	client, err := r.appendixClient()
	if err != nil {
		return nil, appendixAccess{}, "", nil, err
	}
	got, err := client.GetPolicyAppendix(ctx, &corev1.GetPolicyAppendixRequest{Id: id})
	if err != nil {
		logger.Debug("appendix: lookup failed", log.F("op", op), log.F("appendix_id", id), log.F("code", status.Code(err).String()))
		return nil, appendixAccess{}, "", nil, err
	}
	policyID := got.GetAppendix().GetPolicyId()
	access, err := r.appendixAccessFor(ctx, op, policyID)
	if err != nil {
		return nil, appendixAccess{}, "", nil, err
	}
	if !access.editor {
		logger.Info("appendix write refused: the caller may not edit the policy",
			log.F("op", op), log.F("appendix_id", id), log.F("policy_id", policyID))
		return nil, appendixAccess{}, "", nil, errAppendixForbidden
	}
	return client, access, claims.UserID(), got.GetAppendix(), nil
}

// appendixRoomKey is the collab room an appendix is co-edited in. Collab names
// it the same way in IssueAppendixToken (room_key); the publish calls pass it
// as the draft id.
func appendixRoomKey(appendixID string) string { return "appendix:" + appendixID }

// IssueAppendixCollabTokenResolver mints a collaboration token for the
// appendix's own room (#126). The checks run in a fixed order: signed in, the
// appendix exists (NotFound), the caller may edit its policy
// (PermissionDenied, so a reader never learns whether it is retired), then the
// appendix is not retired (FailedPrecondition). Only then is collab asked,
// which checks the edit right again and mints for the go-grpc-actor actor.
// Collab's refusals pass through with their code and message. The token is
// never logged.
func (r *Resolver) IssueAppendixCollabTokenResolver(ctx context.Context, appendixID string) (*AppendixCollabToken, error) {
	logger := r.logger()
	_, _, _, appendix, err := r.editableAppendixRow(ctx, "issueAppendixCollabToken", appendixID)
	if err != nil {
		return nil, err
	}
	if appendix.GetRetiredAt() != nil {
		logger.Info("appendix collab token refused: the appendix is retired", log.F("appendix_id", appendixID))
		return nil, status.Error(codes.FailedPrecondition, "A retired appendix can't be edited; restore it first.")
	}
	if r.CollabClient == nil {
		logger.Warn("appendix collab token: no collab client is wired", log.F("appendix_id", appendixID))
		return nil, status.Error(codes.Unavailable, "co-editing is not available")
	}
	started := time.Now()
	resp, err := r.CollabClient.IssueAppendixToken(ctx, &collabv1.IssueAppendixTokenRequest{AppendixId: appendixID})
	if err != nil {
		logger.Warn("appendix collab token: collab refused", log.F("appendix_id", appendixID),
			log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	expires := ""
	if resp.GetExpiresAt() != nil {
		expires = resp.GetExpiresAt().AsTime().UTC().Format(time.RFC3339)
	}
	logger.Info("appendix collab token issued", log.F("appendix_id", appendixID),
		log.F("room_key", resp.GetRoomKey()), log.F("duration_ms", time.Since(started).Milliseconds()))
	return &AppendixCollabToken{Token: resp.GetToken(), WsURL: resp.GetWsUrl(), ExpiresAt: expires}, nil
}

// PolicyAppendicesResolver lists a policy's appendices as the caller may see
// them: readers the live ones with a published row, editors also the drafts
// and, with includeRetired, the retired ones.
func (r *Resolver) PolicyAppendicesResolver(ctx context.Context, policyID string, includeRetired *bool) ([]*PolicyAppendix, error) {
	logger := r.logger()
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	client, err := r.appendixClient()
	if err != nil {
		return nil, err
	}
	access, err := r.appendixAccessFor(ctx, "policyAppendices", policyID)
	if err != nil {
		return nil, err
	}
	withRetired := access.editor && includeRetired != nil && *includeRetired
	started := time.Now()
	resp, err := client.ListPolicyAppendices(ctx, &corev1.ListPolicyAppendicesRequest{PolicyId: policyID, IncludeRetired: withRetired})
	if err != nil {
		logger.Error(err, "policy appendices: core list failed",
			log.F("policy_id", policyID), log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	people := newAppendixPeople(r.IdentityClient)
	out := make([]*PolicyAppendix, 0, len(resp.GetAppendices()))
	for _, a := range resp.GetAppendices() {
		if !access.editor && (a.GetRetiredAt() != nil || a.GetPublished() == nil) {
			continue
		}
		if !withRetired && a.GetRetiredAt() != nil {
			continue
		}
		out = append(out, shapePolicyAppendix(ctx, people, a, access))
	}
	logger.Debug("policy appendices listed", log.F("policy_id", policyID), log.F("editor", access.editor),
		log.F("include_retired", withRetired), log.F("from_core", len(resp.GetAppendices())), log.F("count", len(out)),
		log.F("duration_ms", time.Since(started).Milliseconds()))
	return out, nil
}

// PolicyAppendixResolver returns one appendix. A reader gets NotFound for one
// that is retired or has no published row, so a draft is never confirmed.
func (r *Resolver) PolicyAppendixResolver(ctx context.Context, id string) (*PolicyAppendix, error) {
	logger := r.logger()
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	client, err := r.appendixClient()
	if err != nil {
		return nil, err
	}
	got, err := client.GetPolicyAppendix(ctx, &corev1.GetPolicyAppendixRequest{Id: id})
	if err != nil {
		logger.Debug("policy appendix: lookup failed", log.F("appendix_id", id), log.F("code", status.Code(err).String()))
		return nil, err
	}
	a := got.GetAppendix()
	access, err := r.appendixAccessFor(ctx, "policyAppendix", a.GetPolicyId())
	if err != nil {
		return nil, err
	}
	if !access.editor && (a.GetRetiredAt() != nil || a.GetPublished() == nil) {
		logger.Debug("policy appendix hidden from a reader", log.F("appendix_id", id), log.F("retired", a.GetRetiredAt() != nil))
		return nil, status.Error(codes.NotFound, "appendix not found")
	}
	return shapePolicyAppendix(ctx, newAppendixPeople(r.IdentityClient), a, access), nil
}

// CreatePolicyAppendixResolver adds an appendix as a draft, last among the live
// ones. A missing or blank title is core's to name.
func (r *Resolver) CreatePolicyAppendixResolver(ctx context.Context, policyID string, title *string, contentJSON string) (*PolicyAppendix, error) {
	logger := r.logger()
	claims, err := signedIn(ctx)
	if err != nil {
		return nil, err
	}
	client, err := r.appendixClient()
	if err != nil {
		return nil, err
	}
	access, err := r.appendixAccessFor(ctx, "createPolicyAppendix", policyID)
	if err != nil {
		return nil, err
	}
	if !access.editor {
		logger.Info("create appendix refused: the caller may not edit the policy", log.F("policy_id", policyID))
		return nil, errAppendixForbidden
	}
	resp, err := client.CreatePolicyAppendix(ctx, &corev1.CreatePolicyAppendixRequest{
		PolicyId: policyID, Title: strings.TrimSpace(derefOrEmpty(title)), ContentJson: contentJSON, ActorUserId: claims.UserID(),
	})
	if err != nil {
		logger.Error(err, "create appendix: core failed", log.F("policy_id", policyID), log.F("code", status.Code(err).String()))
		return nil, err
	}
	logger.Info("appendix created", log.F("policy_id", policyID), log.F("appendix_id", resp.GetAppendix().GetId()))
	return shapePolicyAppendix(ctx, newAppendixPeople(r.IdentityClient), resp.GetAppendix(), access), nil
}

// SaveAppendixDraftResolver updates the open draft, or starts the next one
// beside the published row. A blank title is refused.
func (r *Resolver) SaveAppendixDraftResolver(ctx context.Context, id, title, contentJSON string) (*PolicyAppendix, error) {
	client, access, actor, err := r.editableAppendix(ctx, "saveAppendixDraft", id)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(title) == "" {
		return nil, status.Error(codes.InvalidArgument, "An appendix needs a title.")
	}
	resp, err := client.SaveAppendixDraft(ctx, &corev1.SaveAppendixDraftRequest{Id: id, Title: title, ContentJson: contentJSON, ActorUserId: actor})
	if err != nil {
		r.logger().Error(err, "save appendix draft: core failed", log.F("appendix_id", id), log.F("code", status.Code(err).String()))
		return nil, err
	}
	log.Trace(r.logger(), "appendix draft saved", log.F("appendix_id", id))
	return shapePolicyAppendix(ctx, newAppendixPeople(r.IdentityClient), resp.GetAppendix(), access), nil
}

// PublishAppendixResolver promotes the draft to the next published version.
// With a collab room client wired it also settles the appendix's room, as the
// policy publish does: flush the live room into core's draft, publish, then
// freeze the room on the version that went live. As for a policy, a failed
// flush fails closed (the same coded error as publishDraft; core is not called
// and no notify is sent), while a failed notify is only logged. Appendix text
// is never logged.
func (r *Resolver) PublishAppendixResolver(ctx context.Context, id string) (*PolicyAppendix, error) {
	client, access, actor, appendix, err := r.editableAppendixRow(ctx, "publishAppendix", id)
	if err != nil {
		return nil, err
	}
	policyID := appendix.GetPolicyId()
	// Fails closed, as publishDraft does: publishing after a failed flush would
	// cut the version from content older than the room holds.
	if err := flushCollabDraft(ctx, r.logger().Ctx(ctx), r.CollabRoomClient, policyID, appendixRoomKey(id)); err != nil {
		return nil, err
	}
	resp, err := client.PublishAppendix(ctx, &corev1.PublishAppendixRequest{Id: id, ActorUserId: actor})
	if err != nil {
		r.logger().Error(err, "publish appendix: core failed", log.F("appendix_id", id), log.F("code", status.Code(err).String()))
		return nil, err
	}
	r.logger().Info("appendix published", log.F("appendix_id", id), log.F("version_no", resp.GetAppendix().GetPublished().GetVersionNo()))
	r.notifyAppendixRoom(ctx, id, policyID, resp.GetAppendix().GetPublished().GetVersionNo())
	return shapePolicyAppendix(ctx, newAppendixPeople(r.IdentityClient), resp.GetAppendix(), access), nil
}

// notifyAppendixRoom drops the appendix's live room to read-only on the version
// that went live. Core has already committed the publish, so a failure is
// logged only. It runs on a context that outlives the request.
func (r *Resolver) notifyAppendixRoom(ctx context.Context, id, policyID string, versionNo int32) {
	if r.CollabRoomClient == nil {
		return
	}
	logger := r.logger()
	notifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), collabNotifyTimeout)
	defer cancel()
	resp, err := r.CollabRoomClient.NotifyDraftPublished(notifyCtx, &collabv1.NotifyDraftPublishedRequest{
		DraftId: appendixRoomKey(id), PolicyId: policyID, VersionNumber: versionNo,
	})
	if err != nil {
		logger.Warn("could not tell collab the appendix was published; a live editor keeps editing until it reconnects",
			log.F("appendix_id", id), log.F("version_no", versionNo), log.F("code", status.Code(err).String()), log.F("error", err.Error()))
		return
	}
	if !resp.GetRoomNotified() {
		logger.Debug("no live collab room for the published appendix", log.F("appendix_id", id))
	}
}

// RetireAppendixResolver hides an appendix and keeps it with its history.
func (r *Resolver) RetireAppendixResolver(ctx context.Context, id string) (*PolicyAppendix, error) {
	client, access, actor, err := r.editableAppendix(ctx, "retireAppendix", id)
	if err != nil {
		return nil, err
	}
	resp, err := client.RetireAppendix(ctx, &corev1.RetireAppendixRequest{Id: id, ActorUserId: actor})
	if err != nil {
		r.logger().Error(err, "retire appendix: core failed", log.F("appendix_id", id), log.F("code", status.Code(err).String()))
		return nil, err
	}
	r.logger().Info("appendix retired", log.F("appendix_id", id))
	return shapePolicyAppendix(ctx, newAppendixPeople(r.IdentityClient), resp.GetAppendix(), access), nil
}

// RestoreAppendixResolver brings a retired appendix back, last in the order.
func (r *Resolver) RestoreAppendixResolver(ctx context.Context, id string) (*PolicyAppendix, error) {
	client, access, actor, err := r.editableAppendix(ctx, "restoreAppendix", id)
	if err != nil {
		return nil, err
	}
	resp, err := client.RestoreAppendix(ctx, &corev1.RestoreAppendixRequest{Id: id, ActorUserId: actor})
	if err != nil {
		r.logger().Error(err, "restore appendix: core failed", log.F("appendix_id", id), log.F("code", status.Code(err).String()))
		return nil, err
	}
	r.logger().Info("appendix restored", log.F("appendix_id", id))
	return shapePolicyAppendix(ctx, newAppendixPeople(r.IdentityClient), resp.GetAppendix(), access), nil
}

// ReorderPolicyAppendicesResolver sets the order of a policy's live appendices
// (#124). The right to edit the policy is decided as for createPolicyAppendix,
// before core is called, so a reader's reorder never reaches core. Core refuses
// a list that is not every live appendix of the policy exactly once
// (InvalidArgument) and relays NotFound; both pass through for the usual
// GraphQL error codes. A reorder makes no draft.
func (r *Resolver) ReorderPolicyAppendicesResolver(ctx context.Context, policyID string, orderedIDs []string) ([]*PolicyAppendix, error) {
	logger := r.logger()
	claims, err := signedIn(ctx)
	if err != nil {
		logger.Debug("reorder appendices refused: no signed-in user", log.F("policy_id", policyID))
		return nil, err
	}
	client, err := r.appendixClient()
	if err != nil {
		return nil, err
	}
	access, err := r.appendixAccessFor(ctx, "reorderPolicyAppendices", policyID)
	if err != nil {
		return nil, err
	}
	if !access.editor {
		logger.Info("reorder appendices refused: the caller may not edit the policy", log.F("policy_id", policyID))
		return nil, errAppendixForbidden
	}
	log.Trace(logger, "reorder appendices: calling core", log.F("policy_id", policyID), log.F("count", len(orderedIDs)))
	started := time.Now()
	resp, err := client.ReorderPolicyAppendices(ctx, &corev1.ReorderPolicyAppendicesRequest{
		PolicyId: policyID, OrderedIds: orderedIDs, ActorUserId: claims.UserID(),
	})
	if err != nil {
		logger.Error(err, "reorder appendices: core failed", log.F("policy_id", policyID),
			log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	people := newAppendixPeople(r.IdentityClient)
	out := make([]*PolicyAppendix, 0, len(resp.GetAppendices()))
	for _, a := range resp.GetAppendices() {
		out = append(out, shapePolicyAppendix(ctx, people, a, access))
	}
	logger.Info("appendices reordered", log.F("policy_id", policyID), log.F("count", len(out)),
		log.F("duration_ms", time.Since(started).Milliseconds()))
	return out, nil
}

// AppendixDiffResolver is the appendixDiff query (#125): the appendix's text
// against its latest published row, from core's DiffPolicyAppendix. The text is
// the open draft, or contentJSON when the author passes what they are typing,
// which goes to core as it is (core validates it; InvalidArgument passes
// through). It writes nothing. Who may: whoever may edit the policy, decided as
// for the appendix drafts, a site admin, and compliance (the catalog's
// compliance.report, held by the compliance-admin role); the mock's rule. An
// obfuscated reader gets the section shape without the word diff, as for the
// policy version diff. The appendix text is never logged.
func (r *Resolver) AppendixDiffResolver(ctx context.Context, id string, contentJSON *string) ([]*SectionDiff, error) {
	logger := r.logger()
	if _, err := signedIn(ctx); err != nil {
		logger.Debug("appendix diff refused: no signed-in user", log.F("appendix_id", id))
		return nil, err
	}
	client, err := r.appendixClient()
	if err != nil {
		return nil, err
	}
	got, err := client.GetPolicyAppendix(ctx, &corev1.GetPolicyAppendixRequest{Id: id})
	if err != nil {
		logger.Debug("appendix diff: lookup failed", log.F("appendix_id", id), log.F("code", status.Code(err).String()))
		return nil, err
	}
	policyID := got.GetAppendix().GetPolicyId()
	access, err := r.appendixAccessFor(ctx, "appendixDiff", policyID)
	if err != nil {
		return nil, err
	}
	if !access.insight {
		logger.Info("appendix diff refused: the caller is not an author, site admin or compliance",
			log.F("appendix_id", id), log.F("policy_id", policyID))
		return nil, errAppendixForbidden
	}
	log.Trace(logger, "appendix diff: calling core", log.F("appendix_id", id), log.F("policy_id", policyID),
		log.F("unsaved_text", contentJSON != nil))
	started := time.Now()
	resp, err := client.DiffPolicyAppendix(ctx, &corev1.DiffPolicyAppendixRequest{Id: id, ContentJson: contentJSON})
	if err != nil {
		logger.Error(err, "appendix diff: core failed", log.F("appendix_id", id), log.F("policy_id", policyID),
			log.F("code", status.Code(err).String()), log.F("duration_ms", time.Since(started).Milliseconds()))
		return nil, err
	}
	out := make([]*SectionDiff, 0, len(resp.GetDiffs()))
	for _, d := range resp.GetDiffs() {
		out = append(out, sectionDiffFromProto(d))
	}
	logger.Debug("appendix diffed", log.F("appendix_id", id), log.F("policy_id", policyID), log.F("sections", len(out)),
		log.F("effect", string(access.effect)), log.F("duration_ms", time.Since(started).Milliseconds()))
	return obfuscateSectionDiffs(out, access.effect), nil
}

// AppendicesForVersionResolver is PolicyVersion.appendices: the older Appendix
// shape, filled from the latest published row of each live appendix of the
// policy, the same on every version (policyVersionId is the version asked).
// The version itself was already read under the policy's read decision; the
// text is scrambled here as it is there when that decision obfuscates.
func (r *Resolver) AppendicesForVersionResolver(ctx context.Context, v *PolicyVersion) ([]*Appendix, error) {
	logger := r.logger()
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	client, err := r.appendixClient()
	if err != nil {
		return nil, err
	}
	effect, _ := versionReadDecision(ctx, r.PolicyClient, r.CategoryClient, r.IdentityAdminClient, v.PolicyID)
	if effect == authz.EffectDeny {
		return nil, status.Error(codes.NotFound, "policy version not found")
	}
	resp, err := client.ListPolicyAppendices(ctx, &corev1.ListPolicyAppendicesRequest{PolicyId: v.PolicyID})
	if err != nil {
		logger.Error(err, "version appendices: core list failed",
			log.F("policy_version_id", v.ID), log.F("policy_id", v.PolicyID), log.F("code", status.Code(err).String()))
		return nil, err
	}
	out := make([]*Appendix, 0, len(resp.GetAppendices()))
	for _, a := range resp.GetAppendices() {
		p := a.GetPublished()
		if a.GetRetiredAt() != nil || p == nil {
			continue
		}
		content := p.GetContentJson()
		if effect == authz.EffectObfuscate {
			content = obfuscateContentJSON(content)
		}
		out = append(out, &Appendix{
			ID: a.GetId(), PolicyVersionID: v.ID, Title: p.GetTitle(), ContentJSON: content,
			OrderIndex: int(a.GetOrderIndex()), Letter: a.GetLetter(),
		})
	}
	logger.Debug("version appendices listed", log.F("policy_version_id", v.ID), log.F("policy_id", v.PolicyID),
		log.F("count", len(out)), log.F("effect", string(effect)))
	return out, nil
}

// appendixPeople resolves contributor ids to a name and whether they are still
// active, once per user for a request.
type appendixPeople struct {
	identity identityv1.IdentityReadServiceClient
	seen     map[string]*AppendixContributor
}

func newAppendixPeople(identity identityv1.IdentityReadServiceClient) *appendixPeople {
	return &appendixPeople{identity: identity, seen: map[string]*AppendixContributor{}}
}

// of lists the ids as contributors, in order. A user identity does not know,
// or cannot be reached for, stays listed with the id as the name and inactive.
func (p *appendixPeople) of(ctx context.Context, ids []string) []*AppendixContributor {
	out := make([]*AppendixContributor, 0, len(ids))
	for _, id := range ids {
		c, ok := p.seen[id]
		if !ok {
			c = &AppendixContributor{UserID: id, Name: id}
			if p.identity != nil {
				if resp, err := p.identity.GetUser(ctx, &identityv1.GetUserRequest{UserId: id}); err == nil && resp.GetUser() != nil {
					u := resp.GetUser()
					c.Active = u.GetEnabled() && u.GetDeletedAt() == ""
					if name := firstNonEmpty(u.GetName(), u.GetEmail()); name != "" {
						c.Name = name
					}
				}
			}
			p.seen[id] = c
		}
		out = append(out, &AppendixContributor{UserID: c.UserID, Name: c.Name, Active: c.Active})
	}
	return out
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func rfc3339(t *timestamppb.Timestamp) string {
	if t == nil {
		return ""
	}
	return t.AsTime().UTC().Format(time.RFC3339)
}

func rfc3339OrNil(t *timestamppb.Timestamp) *string { return nilIfEmpty(rfc3339(t)) }

// appendixVersionToModel is one row. Editors, site admins and compliance get the contributors; an
// obfuscating read decision scrambles the text.
func appendixVersionToModel(ctx context.Context, people *appendixPeople, v *corev1.AppendixVersion, access appendixAccess) *AppendixVersion {
	if v == nil {
		return nil
	}
	state := AppendixStateDraft
	if v.GetState() == corev1.AppendixVersionState_APPENDIX_VERSION_STATE_PUBLISHED {
		state = AppendixStatePublished
	}
	content := v.GetContentJson()
	if access.effect == authz.EffectObfuscate {
		content = obfuscateContentJSON(content)
	}
	contributors := []*AppendixContributor{}
	if access.insight {
		contributors = people.of(ctx, v.GetContributorIds())
	}
	return &AppendixVersion{
		Contributors: contributors, ID: v.GetId(), VersionNo: int(v.GetVersionNo()), State: state,
		Title: v.GetTitle(), ContentJSON: content,
		CreatedAt: rfc3339(v.GetCreatedAt()), CreatedBy: v.GetCreatedBy(),
		UpdatedAt: rfc3339(v.GetUpdatedAt()), UpdatedBy: v.GetUpdatedBy(),
		PublishedAt: rfc3339OrNil(v.GetPublishedAt()), PublishedBy: nilIfEmpty(v.GetPublishedBy()),
	}
}

// shapePolicyAppendix turns core's appendix into what the caller may see: an
// editor gets the draft, every row (the published rows newest first, and the
// table oldest first with the draft last) and the contributors; anyone else
// the latest published row alone.
func shapePolicyAppendix(ctx context.Context, people *appendixPeople, a *corev1.PolicyAppendix, access appendixAccess) *PolicyAppendix {
	out := &PolicyAppendix{
		ID: a.GetId(), PolicyID: a.GetPolicyId(), Letter: nilIfEmpty(a.GetLetter()), OrderIndex: int(a.GetOrderIndex()),
		RetiredAt: rfc3339OrNil(a.GetRetiredAt()),
		// Core keeps no record of who retired an appendix, so there is nothing to show.
		Published:         appendixVersionToModel(ctx, people, a.GetPublished(), access),
		Versions:          []*AppendixVersion{},
		PublishedVersions: []*AppendixVersion{},
		Contributors:      []*AppendixContributor{},
	}
	out.CreatedAt, out.CreatedBy = appendixCreated(a)
	if !access.editor {
		if out.Published != nil {
			out.Versions = append(out.Versions, out.Published)
			out.PublishedVersions = append(out.PublishedVersions, out.Published)
		}
		if access.insight {
			out.Contributors = people.of(ctx, a.GetContributorIds())
		}
		return out
	}
	out.Draft = appendixVersionToModel(ctx, people, a.GetDraft(), access)
	for _, v := range a.GetPublishedVersions() {
		out.PublishedVersions = append(out.PublishedVersions, appendixVersionToModel(ctx, people, v, access))
	}
	table := slices.Clone(out.PublishedVersions)
	slices.Reverse(table)
	out.Versions = table
	if out.Draft != nil {
		out.Versions = append(out.Versions, out.Draft)
	}
	out.Contributors = people.of(ctx, a.GetContributorIds())
	return out
}

// appendixCreated is when and by whom the first row was written. Core does not
// send it on the appendix, so it is read off the first version.
func appendixCreated(a *corev1.PolicyAppendix) (at, by string) {
	rows := append([]*corev1.AppendixVersion{a.GetDraft()}, a.GetPublishedVersions()...)
	var first *corev1.AppendixVersion
	for _, v := range rows {
		if v != nil && (first == nil || v.GetVersionNo() < first.GetVersionNo()) {
			first = v
		}
	}
	if first == nil {
		return "", ""
	}
	return rfc3339(first.GetCreatedAt()), first.GetCreatedBy()
}
