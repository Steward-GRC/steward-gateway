// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"slices"
	"time"

	"github.com/Bugs5382/go-apperr/apperrgrpc"
	log "github.com/Bugs5382/go-log"
	authz "github.com/Steward-GRC/steward-authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	collabv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/collab/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

// sensitivityToProto maps the GraphQL Sensitivity onto core's.
func sensitivityToProto(s Sensitivity) corev1.Sensitivity {
	switch s {
	case SensitivitySensitive:
		return corev1.Sensitivity_SENSITIVITY_SENSITIVE
	case SensitivityStandard:
		return corev1.Sensitivity_SENSITIVITY_STANDARD
	default:
		return corev1.Sensitivity_SENSITIVITY_STANDARD
	}
}

// sensitivityFromProto is the inverse of sensitivityToProto.
func sensitivityFromProto(s corev1.Sensitivity) Sensitivity {
	if s == corev1.Sensitivity_SENSITIVITY_SENSITIVE {
		return SensitivitySensitive
	}
	return SensitivityStandard
}

// documentTypeFromProto maps core's document type; unspecified is a policy.
func documentTypeFromProto(d corev1.DocumentType) DocumentType {
	if d == corev1.DocumentType_DOCUMENT_TYPE_PROCEDURE {
		return DocumentTypeProcedure
	}
	return DocumentTypePolicy
}

// documentTypeToProto maps an optional document type; nil is unspecified,
// which core reads as policies only (list) or a policy (create).
func documentTypeToProto(d *DocumentType) corev1.DocumentType {
	if d == nil {
		return corev1.DocumentType_DOCUMENT_TYPE_UNSPECIFIED
	}
	switch *d {
	case DocumentTypePolicy:
		return corev1.DocumentType_DOCUMENT_TYPE_POLICY
	case DocumentTypeProcedure:
		return corev1.DocumentType_DOCUMENT_TYPE_PROCEDURE
	default:
		return corev1.DocumentType_DOCUMENT_TYPE_UNSPECIFIED
	}
}

func policyFromProto(p *corev1.Policy) *Policy {
	if p == nil {
		return nil
	}
	gql := &Policy{
		ID:                        p.Id,
		HomeCategoryID:            p.HomeCategoryId,
		Number:                    p.Number,
		Title:                     p.Title,
		Sensitivity:               sensitivityFromProto(p.Sensitivity),
		DocumentType:              documentTypeFromProto(p.GetDocumentType()),
		OwnerUserID:               p.OwnerUserId,
		CurrentPublishedVersionID: nilIfEmpty(p.CurrentPublishedVersionId),
		CurrentDraftVersionID:     nilIfEmpty(p.CurrentDraftVersionId),
		TemplateID:                nilIfEmpty(p.TemplateId),
		TemplateNone:              p.TemplateNone,
		TemplateUpdateAvailable:   p.TemplateUpdateAvailable,
		AckAudienceOverride:       p.AckAudienceOverride,
		RetiredAt:                 nilIfEmpty(p.RetiredAt),
	}
	if p.AckTriggersSet {
		t := ackTriggerFromProto(p.AckTriggers)
		gql.AckTriggers = &t
	}
	if p.UpdatedAt != nil {
		ts := p.UpdatedAt.AsTime().UTC().Format("2006-01-02T15:04:05Z")
		gql.UpdatedAt = &ts
	}
	if p.CurrentVersionStatus != corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_UNSPECIFIED {
		no := int(p.CurrentVersionNo)
		status := p.CurrentVersionStatus.String()
		gql.CurrentVersionNo = &no
		gql.CurrentVersionStatus = &status
	}
	return gql
}

// policyResource builds the steward-authz Resource for p, keyed by policy
// number: its category lineage by name (scoped grants are keyed by name and
// inherit down) and the lineage ids. With no category client, or when the
// lineage can't be read, the lineage is the home category id alone.
func policyResource(ctx context.Context, p *Policy, categoryClient corev1.CategoryServiceClient) (authz.Resource, []string) {
	res := authz.Resource{
		ID:        p.Number,
		Sensitive: p.Sensitivity == SensitivitySensitive,
		Authors:   []string{p.OwnerUserID},
	}
	var home []string
	if p.HomeCategoryID != "" {
		home = []string{p.HomeCategoryID}
	}
	if categoryClient == nil {
		return res, home
	}
	ids, names, err := categoryLineageNamed(ctx, categoryClient, p.HomeCategoryID)
	if err != nil || len(ids) == 0 {
		return res, home
	}
	res.CategoryLineage = names
	res.Category = names[len(names)-1]
	return res, ids
}

// grantOwnerApprover adds a per-request approver grant on the policy's
// category when the caller owns any category in its lineage: owners approve
// their own categories' policies without an approver grant. Never persisted.
func grantOwnerApprover(ctx context.Context, subj authz.Subject, res authz.Resource, lineage []string, categoryClient corev1.CategoryServiceClient) authz.Subject {
	if categoryClient == nil || res.Category == "" || subj.UserID == "" {
		return subj
	}
	for _, id := range lineage {
		resp, err := categoryClient.GetCategory(ctx, &corev1.GetCategoryRequest{Id: id})
		if err != nil {
			continue
		}
		if slices.Contains(resp.GetCategory().GetOwners(), subj.UserID) {
			subj.ScopedGrants = append(slices.Clone(subj.ScopedGrants), authz.ScopedGrant{Role: authz.RoleApprover, Category: res.Category})
			return subj
		}
	}
	return subj
}

// viewerCanFor projects the viewer's capabilities on one policy. Edit, submit
// and approve are the union of the role-based decision and the category-rule
// decision; edit and submit also include the primary author, so the read side
// matches the write gate (authorizeEffectiveAuthor). Ack follows obligations:
// an override deny removes the viewer from the audience, an override allow
// uses the ungated acknowledge rule, otherwise the read-gated one.
func viewerCanFor(subj authz.Subject, res authz.Resource, readD authz.Effect, raci raciReadResult, isPrimaryAuthor bool) *PolicyViewerCan {
	allowed := func(p authz.Permission) bool { return authz.Authorize(subj, p, &res).Allowed() }
	var ack bool
	switch subjOverrideFor(subj, res.ID) {
	case authz.GrantDeny:
	case authz.GrantAllow:
		ack = raci.ackUngated
	default:
		ack = raci.action.Acknowledge.Allowed
	}
	return &PolicyViewerCan{
		Read:              readD != authz.EffectDeny,
		ContentObfuscated: readD == authz.EffectObfuscate,
		CanBreakGlass:     readD == authz.EffectObfuscate,
		Edit:              allowed(authz.PolicyAuthor) || raci.action.Author.Allowed || isPrimaryAuthor,
		Submit:            allowed(authz.PolicySubmit) || raci.action.Author.Allowed || isPrimaryAuthor,
		Approve:           allowed(authz.PolicyApprove) || raci.action.Approve.Allowed,
		Ack:               ack,
	}
}

// SetPolicyAck sets a policy's acknowledgement settings. A nil ackTriggers
// inherits the owning category's; a nil audience override uses the category's
// audience.
func SetPolicyAck(
	ctx context.Context,
	client corev1.PolicyServiceClient,
	policyID string,
	ackTriggers *AckTrigger,
	ackAudienceOverride []string,
) (*Policy, error) {
	if err := authorizeOp(ctx, authz.ComplianceManage); err != nil {
		return nil, err
	}
	req := &corev1.SetAckRequest{
		PolicyId:            policyID,
		AckAudienceOverride: ackAudienceOverride,
	}
	if ackTriggers != nil {
		req.AckTriggersSet = true
		req.AckTriggers = ackTriggerToProto(*ackTriggers)
	}
	resp, err := client.SetAck(ctx, req)
	if err != nil {
		return nil, err
	}
	return policyFromProto(resp.Policy), nil
}

// draftPolicyVersionStatus is PolicyVersion.status for a draft: only an editor
// may see a draft version.
var draftPolicyVersionStatus = corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT.String()

func policyVersionFromProto(v *corev1.PolicyVersion) *PolicyVersion {
	if v == nil {
		return nil
	}
	gql := &PolicyVersion{
		ID:                v.Id,
		PolicyID:          v.PolicyId,
		VersionNo:         int(v.VersionNo),
		Status:            v.Status.String(),
		TemplateVersionID: v.TemplateVersionId,
		ContentJSON:       v.ContentJson,
	}
	if v.CreatedAt != nil {
		ts := v.CreatedAt.AsTime().UTC().Format("2006-01-02T15:04:05Z")
		gql.CreatedAt = &ts
	}
	if v.PublishedAt != nil {
		ts := v.PublishedAt.AsTime().UTC().Format("2006-01-02T15:04:05Z")
		gql.PublishedAt = &ts
	}
	return gql
}

// resolvePolicyReadModel returns the policies the caller may see, each with
// viewerCan, ownerName and createdAt filled. Hidden (denied) policies are
// dropped. A viewer who can't edit never learns a draft exists: the draft
// pointer is cleared, and a never-published policy is dropped entirely. The
// owner-name and createdAt lookups are best effort.
func resolvePolicyReadModel(ctx context.Context, policies []*Policy, policyClient corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, identity identityv1.IdentityReadServiceClient) ([]*Policy, error) {
	if len(policies) == 0 {
		return policies, nil
	}
	subj, err := subjectFromCtx(ctx)
	if err != nil {
		return []*Policy{}, nil
	}
	subj.BreakGlass = activeBreakGlassFor(ctx, adminClient, subj.SiteAdmin())
	visible := make([]*Policy, 0, len(policies))
	for _, p := range policies {
		raci, raciOK, rerr := computeRACIResult(ctx, subj, p, categoryClient)
		if rerr != nil {
			return nil, status.Errorf(codes.Internal, "evaluate policy access: %v", rerr)
		}
		res, lineage := policyResource(ctx, p, categoryClient)
		readD := raci.effect
		if !raciOK {
			readD = authz.Authorize(subj, authz.PolicyRead, &res).Effect
		}
		if readD == authz.EffectDeny {
			continue
		}
		psubj := grantOwnerApprover(ctx, subj, res, lineage, categoryClient)
		p.ViewerCan = viewerCanFor(psubj, res, readD, raci, p.OwnerUserID == subj.UserID)
		if !p.ViewerCan.Edit {
			p.CurrentDraftVersionID = nil
			if derefOrEmpty(p.CurrentPublishedVersionID) == "" {
				continue
			}
		}
		visible = append(visible, p)
	}
	policies = visible
	if len(policies) == 0 {
		return policies, nil
	}

	if identity != nil {
		ownerNames := make(map[string]string)
		for _, p := range policies {
			if p.OwnerUserID != "" {
				ownerNames[p.OwnerUserID] = ""
			}
		}
		for uid := range ownerNames {
			resp, err := identity.GetUser(ctx, &identityv1.GetUserRequest{UserId: uid})
			if err != nil {
				continue
			}
			if u := resp.GetUser(); u != nil && u.Name != "" {
				ownerNames[uid] = u.Name
			}
		}
		for _, p := range policies {
			if name, ok := ownerNames[p.OwnerUserID]; ok && name != "" {
				p.OwnerName = &name
			}
		}
	}

	versionTimes := make(map[string]string)
	for _, p := range policies {
		vid := ""
		if p.CurrentDraftVersionID != nil && *p.CurrentDraftVersionID != "" {
			vid = *p.CurrentDraftVersionID
		} else if p.CurrentPublishedVersionID != nil && *p.CurrentPublishedVersionID != "" {
			vid = *p.CurrentPublishedVersionID
		}
		if vid == "" {
			continue
		}
		if _, seen := versionTimes[vid]; seen {
			continue
		}
		versionTimes[vid] = ""
		resp, err := policyClient.GetPolicyVersion(ctx, &corev1.GetPolicyVersionRequest{Id: vid})
		if err != nil {
			continue
		}
		if v := resp.GetVersion(); v != nil && v.CreatedAt != nil {
			versionTimes[vid] = v.CreatedAt.AsTime().UTC().Format("2006-01-02T15:04:05Z")
		}
	}
	for _, p := range policies {
		vid := ""
		if p.CurrentDraftVersionID != nil && *p.CurrentDraftVersionID != "" {
			vid = *p.CurrentDraftVersionID
		} else if p.CurrentPublishedVersionID != nil && *p.CurrentPublishedVersionID != "" {
			vid = *p.CurrentPublishedVersionID
		}
		if vid == "" {
			continue
		}
		if ts, ok := versionTimes[vid]; ok && ts != "" {
			tsCopy := ts
			p.CreatedAt = &tsCopy
		}
	}
	return policies, nil
}

// GetPolicy returns one policy. A policy the caller may not see is NotFound,
// so its existence doesn't leak; an obfuscated one is returned with
// viewerCan.contentObfuscated set.
func GetPolicy(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, identity identityv1.IdentityReadServiceClient, id string) (*Policy, error) {
	if _, err := subjectFromCtx(ctx); err != nil {
		return nil, err
	}
	resp, err := client.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: id})
	if err != nil {
		return nil, err
	}
	p := policyFromProto(resp.Policy)
	if p == nil {
		return nil, status.Error(codes.NotFound, "policy not found")
	}
	visible, err := resolvePolicyReadModel(ctx, []*Policy{p}, client, categoryClient, adminClient, identity)
	if err != nil {
		return nil, err
	}
	if len(visible) == 0 {
		return nil, status.Error(codes.NotFound, "policy not found")
	}
	return visible[0], nil
}

// PolicyByNumber returns one policy by its rendered number, the same read
// model and NotFound behavior as GetPolicy.
func PolicyByNumber(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, identity identityv1.IdentityReadServiceClient, number string) (*Policy, error) {
	if _, err := subjectFromCtx(ctx); err != nil {
		return nil, err
	}
	resp, err := client.GetPolicyByNumber(ctx, &corev1.GetPolicyByNumberRequest{Number: number})
	if err != nil {
		return nil, err
	}
	p := policyFromProto(resp.Policy)
	if p == nil {
		return nil, status.Error(codes.NotFound, "policy not found")
	}
	visible, err := resolvePolicyReadModel(ctx, []*Policy{p}, client, categoryClient, adminClient, identity)
	if err != nil {
		return nil, err
	}
	if len(visible) == 0 {
		return nil, status.Error(codes.NotFound, "policy not found")
	}
	return visible[0], nil
}

// ListPolicies returns the visible policies in categoryID, and its subtree
// when includeDescendants is set.
func ListPolicies(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, identity identityv1.IdentityReadServiceClient, categoryID string, includeDescendants *bool, documentType *DocumentType) ([]*Policy, error) {
	inc := false
	if includeDescendants != nil {
		inc = *includeDescendants
	}
	resp, err := client.ListPolicies(ctx, &corev1.ListPoliciesRequest{CategoryId: categoryID, IncludeDescendants: inc, DocumentType: documentTypeToProto(documentType)})
	if err != nil {
		return nil, err
	}
	out := make([]*Policy, 0, len(resp.Policies))
	for _, p := range resp.Policies {
		out = append(out, policyFromProto(p))
	}
	return resolvePolicyReadModel(ctx, out, client, categoryClient, adminClient, identity)
}

// versionReadDecision is the read effect on the policy that owns a version.
// It fails closed: no caller, no policy or any lookup error is deny, so a
// version body is never served on an unresolved decision. breakGlass reports
// that only the caller's active break-glass grant allows the read, so the read
// must be recorded before the content is served.
func versionReadDecision(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, policyID string) (effect authz.Effect, breakGlass bool) {
	subj, err := subjectFromCtx(ctx)
	if err != nil {
		return authz.EffectDeny, false
	}
	subj.BreakGlass = activeBreakGlassFor(ctx, adminClient, subj.SiteAdmin())
	resp, err := client.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: policyID})
	if err != nil {
		return authz.EffectDeny, false
	}
	p := policyFromProto(resp.GetPolicy())
	if p == nil {
		return authz.EffectDeny, false
	}
	effect, err = policyReadEffect(ctx, subj, p, categoryClient)
	if err != nil {
		return authz.EffectDeny, false
	}
	if effect != authz.EffectAllow || !subj.BreakGlass[p.Number] {
		return effect, false
	}
	subj.BreakGlass = nil
	without, err := policyReadEffect(ctx, subj, p, categoryClient)
	if err != nil {
		return authz.EffectDeny, false
	}
	return effect, without != authz.EffectAllow
}

// policyReadEffect is the read effect for subj on p: the category rules when
// they resolve, the role-based decision otherwise.
func policyReadEffect(ctx context.Context, subj authz.Subject, p *Policy, categoryClient corev1.CategoryServiceClient) (authz.Effect, error) {
	raci, raciOK, err := computeRACIResult(ctx, subj, p, categoryClient)
	if err != nil {
		return authz.EffectDeny, err
	}
	if raciOK {
		return raci.effect, nil
	}
	res, _ := policyResource(ctx, p, categoryClient)
	return authz.Authorize(subj, authz.PolicyRead, &res).Effect, nil
}

// recordBreakGlassRead has core audit a read that only a break-glass grant
// allows, and tell the owner and the compliance admins. Its error is returned
// as is, so the content is not served unrecorded.
func recordBreakGlassRead(ctx context.Context, client corev1.PolicyServiceClient, policyID, versionID string) error {
	_, err := client.RecordBreakGlassRead(ctx, &corev1.RecordBreakGlassReadRequest{PolicyId: policyID, PolicyVersionId: versionID})
	return err
}

// applyVersionReadDecision enforces the read effect on a version body: deny is
// NotFound, obfuscate replaces the content before it is ever serialized.
func applyVersionReadDecision(v *PolicyVersion, readD authz.Effect) (*PolicyVersion, error) {
	if v == nil {
		return nil, status.Error(codes.NotFound, "policy version not found")
	}
	switch readD {
	case authz.EffectDeny:
		return nil, status.Error(codes.NotFound, "policy version not found")
	case authz.EffectObfuscate:
		v.ContentJSON = obfuscateContentJSON(v.ContentJSON)
	}
	return v, nil
}

// GetPolicyVersion returns one version under its policy's read decision. A
// draft version is for editors only; anyone else gets NotFound.
func GetPolicyVersion(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, id string) (*PolicyVersion, error) {
	resp, err := client.GetPolicyVersion(ctx, &corev1.GetPolicyVersionRequest{Id: id})
	if err != nil {
		return nil, err
	}
	v := policyVersionFromProto(resp.Version)
	if v == nil {
		return nil, status.Error(codes.NotFound, "policy version not found")
	}
	if v.Status == draftPolicyVersionStatus {
		if _, aerr := authorizeEffectiveAuthor(ctx, client, categoryClient, v.PolicyID); aerr != nil {
			return nil, status.Error(codes.NotFound, "policy version not found")
		}
	}
	readD, breakGlass := versionReadDecision(ctx, client, categoryClient, adminClient, v.PolicyID)
	if breakGlass {
		if err := recordBreakGlassRead(ctx, client, v.PolicyID, v.ID); err != nil {
			return nil, err
		}
	}
	return applyVersionReadDecision(v, readD)
}

// ListPolicyVersions returns a policy's published versions, oldest first,
// under its read decision.
func ListPolicyVersions(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, policyID string) ([]*PolicyVersion, error) {
	readD, breakGlass := versionReadDecision(ctx, client, categoryClient, adminClient, policyID)
	if readD == authz.EffectDeny {
		return nil, status.Error(codes.NotFound, "policy not found")
	}
	if breakGlass {
		if err := recordBreakGlassRead(ctx, client, policyID, ""); err != nil {
			return nil, err
		}
	}
	resp, err := client.ListPolicyVersions(ctx, &corev1.ListPolicyVersionsRequest{PolicyId: policyID})
	if err != nil {
		return nil, err
	}
	out := make([]*PolicyVersion, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		pv := policyVersionFromProto(v)
		if readD == authz.EffectObfuscate {
			pv.ContentJSON = obfuscateContentJSON(pv.ContentJSON)
		}
		out = append(out, pv)
	}
	return out, nil
}

// DiffVersions returns core's section diff between two versions.
func DiffVersions(ctx context.Context, client corev1.PolicyServiceClient, fromID, toID string) ([]*SectionDiff, error) {
	resp, err := client.DiffVersions(ctx, &corev1.DiffVersionsRequest{FromVersionId: fromID, ToVersionId: toID})
	if err != nil {
		return nil, err
	}
	out := make([]*SectionDiff, 0, len(resp.Diffs))
	for _, d := range resp.Diffs {
		out = append(out, &SectionDiff{
			SectionKey:    d.SectionKey,
			SectionTitle:  d.SectionTitle,
			ChangeType:    d.ChangeType,
			WordDiffHTML:  nilIfEmpty(d.WordDiffHtml),
			IsBoilerplate: d.IsBoilerplate,
		})
	}
	return out, nil
}

// GetEffectiveTemplate returns the policy's pinned or inherited template.
func GetEffectiveTemplate(ctx context.Context, client corev1.PolicyServiceClient, policyID string) (*EffectiveTemplate, error) {
	resp, err := client.GetEffectiveTemplate(ctx, &corev1.GetEffectiveTemplateRequest{PolicyId: policyID})
	if err != nil {
		return nil, err
	}
	return &EffectiveTemplate{
		TemplateID:        resp.TemplateId,
		TemplateVersionID: resp.TemplateVersionId,
		None:              resp.None,
	}, nil
}

// SetPolicyTemplate sets the policy's template override: none=true is
// freeform, a template id pins it, neither inherits. Choosing the template is
// authoring, so it takes the effective-author gate.
func SetPolicyTemplate(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID string, templateID *string, none bool) (*Policy, error) {
	actor, err := authorizeEffectiveAuthor(ctx, client, categoryClient, policyID)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetPolicyTemplate(ctx, &corev1.SetPolicyTemplateRequest{
		PolicyId:    policyID,
		TemplateId:  derefOrEmpty(templateID),
		None:        none,
		ActorUserId: actor,
	})
	if err != nil {
		return nil, err
	}
	return policyFromProto(resp.GetPolicy()), nil
}

// SetPolicySensitivity flips a policy's classification in place: no new
// version and no approval. Anyone who can edit the policy may.
func SetPolicySensitivity(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID string, sensitivity Sensitivity) (*Policy, error) {
	actor, err := authorizeEffectiveAuthor(ctx, client, categoryClient, policyID)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetPolicySensitivity(ctx, &corev1.SetPolicySensitivityRequest{
		PolicyId:    policyID,
		Sensitivity: sensitivityToProto(sensitivity),
		ActorUserId: actor,
	})
	if err != nil {
		return nil, err
	}
	return policyFromProto(resp.GetPolicy()), nil
}

// CreatePolicy creates a policy in homeCategoryID, owned by the caller. A nil
// templateID inherits the category's default.
func CreatePolicy(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, homeCategoryID, title string, sensitivity Sensitivity, templateID *string, documentType *DocumentType) (*Policy, error) {
	uid, err := authorizeCategoryAuthor(ctx, categoryClient, homeCategoryID)
	if err != nil {
		return nil, err
	}
	resp, err := client.CreatePolicy(ctx, &corev1.CreatePolicyRequest{
		HomeCategoryId: homeCategoryID,
		Title:          title,
		Sensitivity:    sensitivityToProto(sensitivity),
		OwnerUserId:    uid,
		TemplateId:     derefOrEmpty(templateID),
		DocumentType:   documentTypeToProto(documentType),
	})
	if err != nil {
		return nil, err
	}
	return policyFromProto(resp.Policy), nil
}

// SaveDraft autosaves the policy's working draft.
func SaveDraft(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID, contentJSON, templateVersionID string) (*PolicyVersion, error) {
	uid, err := authorizeEffectiveAuthor(ctx, client, categoryClient, policyID)
	if err != nil {
		return nil, err
	}
	resp, err := client.SaveDraft(ctx, &corev1.SaveDraftRequest{
		PolicyId:          policyID,
		ContentJson:       contentJSON,
		TemplateVersionId: templateVersionID,
		ActorUserId:       uid,
	})
	if err != nil {
		return nil, err
	}
	return policyVersionFromProto(resp.Version), nil
}

// collabNotifyTimeout bounds the freeze after a publish, so a wedged collab
// can't stall the mutation.
const collabNotifyTimeout = 3 * time.Second

// collabFlushTimeout bounds the flush before a publish. Collab answers only
// once core has taken or refused the checkpoint, so it covers a core write too.
const collabFlushTimeout = 10 * time.Second

// PublishDraft publishes the policy's working draft: flush the live co-editing
// room to core, publish, then freeze the room. A nil collabRooms skips both.
func PublishDraft(ctx context.Context, logger log.Logger, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, collabRooms collabv1.CollabRoomServiceClient, policyID string) (*PolicyVersion, error) {
	author, err := authorizeEffectiveAuthorCtx(ctx, client, categoryClient, policyID)
	if err != nil {
		return nil, err
	}
	if err := flushCollabDraft(ctx, logger, collabRooms, policyID, author.draftID); err != nil {
		return nil, err
	}
	resp, err := client.PublishDraft(ctx, &corev1.PublishDraftRequest{PolicyId: policyID, ActorUserId: author.uid})
	if err != nil {
		return nil, err
	}
	version := policyVersionFromProto(resp.Version)
	logger.Info("policy published", log.F("policy_id", policyID), log.F("version_id", version.ID), log.F("version_no", version.VersionNo))
	// Synchronous, so no window exists where the publish has returned and an
	// editor is still typing into a now-immutable version.
	notifyCollabDraftPublished(ctx, logger, collabRooms, policyID, version)
	return version, nil
}

// flushCollabDraft has collab send the live room's newest checkpoint to core.
// It fails closed: publishing after a failed flush would cut the version from
// content older than the room holds, and the freeze would make that permanent.
// No live room is the everyday case and is success; no draft means no room.
func flushCollabDraft(ctx context.Context, logger log.Logger, rooms collabv1.CollabRoomServiceClient, policyID, draftID string) error {
	if rooms == nil || draftID == "" {
		return nil
	}
	flushCtx, cancel := context.WithTimeout(ctx, collabFlushTimeout)
	defer cancel()
	start := time.Now()
	resp, err := rooms.FlushDraft(flushCtx, &collabv1.FlushDraftRequest{DraftId: draftID, PolicyId: policyID})
	if err != nil {
		logger.Warn("collab flush failed; the policy was not published",
			log.F("policy_id", policyID), log.F("draft_id", draftID), log.F("duration_ms", time.Since(start).Milliseconds()), log.F("error", err.Error()))
		st := status.Convert(err)
		switch st.Code() {
		case codes.Unavailable, codes.DeadlineExceeded:
			return errcodes.New(errcodes.CodeCollabFlushUnavailable)
		case codes.FailedPrecondition:
			reason := st.Message()
			if info, ok := apperrgrpc.FromError(err); ok && info.Metadata["detail"] != "" {
				reason = info.Metadata["detail"]
			}
			return errcodes.New(errcodes.CodeCollabFlushRejected, "reason", reason)
		default:
			return errcodes.New(errcodes.CodeCollabFlushFailed)
		}
	}
	logger.Debug("collab room flushed",
		log.F("policy_id", policyID), log.F("draft_id", draftID), log.F("duration_ms", time.Since(start).Milliseconds()),
		log.F("room_found", resp.GetRoomFound()), log.F("content_flushed", resp.GetContentFlushed()))
	return nil
}

// notifyCollabDraftPublished drops the live room to read-only. It fails open:
// core has already committed the publish, so a failure is logged and the
// editor has to reload. It runs on a context that outlives the request, so a
// browser that has gone away still gets its room frozen, while keeping the
// request's values (the actor every backend call carries).
func notifyCollabDraftPublished(ctx context.Context, logger log.Logger, rooms collabv1.CollabRoomServiceClient, policyID string, version *PolicyVersion) {
	if rooms == nil || version == nil || version.ID == "" {
		return
	}
	notifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), collabNotifyTimeout)
	defer cancel()
	// Core publishes the draft row in place, so the version id is the draft id
	// the room is keyed by.
	resp, err := rooms.NotifyDraftPublished(notifyCtx, &collabv1.NotifyDraftPublishedRequest{
		DraftId:       version.ID,
		PolicyId:      policyID,
		VersionNumber: toInt32(version.VersionNo),
	})
	if err != nil {
		logger.Warn("could not tell collab the draft was published; a live editor keeps editing until it reconnects",
			log.F("policy_id", policyID), log.F("draft_id", version.ID), log.F("version_no", version.VersionNo), log.F("error", err.Error()))
		return
	}
	if !resp.GetRoomNotified() {
		logger.Debug("no live collab room for the published draft", log.F("policy_id", policyID), log.F("draft_id", version.ID))
	}
}

// renamePendingApprovalMsg is shown to the author when a rename is blocked by
// a change in review.
const renamePendingApprovalMsg = "A change is pending approval. Resolve or withdraw that draft before renaming."

// RenamePolicy renames a policy. Core renames a never-published policy in
// place and stages the rename on a draft otherwise. Core can't see a pending
// approval (workflow holds it), so the gateway refuses the rename while the
// current draft is in review.
func RenamePolicy(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, workflowClient workflowv1.WorkflowServiceClient, policyID, newTitle string) (*RenamePolicyResult, error) {
	uid, err := authorizeEffectiveAuthor(ctx, client, categoryClient, policyID)
	if err != nil {
		return nil, err
	}

	if workflowClient != nil {
		if draftID := currentDraftVersionID(ctx, client, policyID); draftID != "" {
			if approvalPending(ctx, workflowClient, draftID) {
				return nil, status.Error(codes.FailedPrecondition, renamePendingApprovalMsg)
			}
		}
	}

	resp, err := client.RenamePolicy(ctx, &corev1.RenamePolicyRequest{
		PolicyId:    policyID,
		NewTitle:    newTitle,
		ActorUserId: uid,
	})
	if err != nil {
		return nil, err
	}
	return &RenamePolicyResult{
		Policy:         policyFromProto(resp.GetPolicy()),
		Staged:         resp.GetStaged(),
		DraftVersionID: nilIfEmpty(resp.GetDraftVersionId()),
	}, nil
}

// currentDraftVersionID returns the policy's draft id, or "" when it has none
// or can't be read.
func currentDraftVersionID(ctx context.Context, client corev1.PolicyServiceClient, policyID string) string {
	resp, err := client.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: policyID})
	if err != nil {
		return ""
	}
	return resp.GetPolicy().GetCurrentDraftVersionId()
}

// approvalPending reports whether the version is in review. Any error is "not
// pending": rename must not hinge on workflow being reachable, and core's own
// guard remains.
func approvalPending(ctx context.Context, client workflowv1.WorkflowServiceClient, policyVersionID string) bool {
	resp, err := client.GetStatus(ctx, &workflowv1.GetStatusRequest{PolicyVersionId: policyVersionID})
	if err != nil {
		return false
	}
	return resp.GetStatus() == workflowv1.ApprovalStatus_APPROVAL_STATUS_IN_REVIEW
}

// DiscardDraft deletes the policy's working draft; published versions stay.
func DiscardDraft(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID string) (bool, error) {
	uid, err := authorizeEffectiveAuthor(ctx, client, categoryClient, policyID)
	if err != nil {
		return false, err
	}
	if _, err := client.DiscardDraft(ctx, &corev1.DiscardDraftRequest{PolicyId: policyID, ActorUserId: uid}); err != nil {
		return false, err
	}
	return true, nil
}

// DeletePolicy hard-deletes a never-published policy; core refuses once it has
// been published.
func DeletePolicy(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID string) (bool, error) {
	uid, err := authorizeEffectiveAuthor(ctx, client, categoryClient, policyID)
	if err != nil {
		return false, err
	}
	if _, err := client.DeletePolicy(ctx, &corev1.DeletePolicyRequest{PolicyId: policyID, ActorUserId: uid}); err != nil {
		return false, err
	}
	return true, nil
}

// RetirePolicy retires a policy: hidden from listings, history kept.
func RetirePolicy(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, policyID string) (*Policy, error) {
	uid, err := authorizeEffectiveAuthor(ctx, client, categoryClient, policyID)
	if err != nil {
		return nil, err
	}
	resp, err := client.RetirePolicy(ctx, &corev1.RetirePolicyRequest{PolicyId: policyID, ActorUserId: uid})
	if err != nil {
		return nil, err
	}
	return policyFromProto(resp.GetPolicy()), nil
}

// SetPolicyOwner reassigns a policy's owner. Site admin only.
func SetPolicyOwner(ctx context.Context, client corev1.PolicyServiceClient, policyID, ownerUserID string) (*Policy, error) {
	actor, err := requireSiteAdmin(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.SetPolicyOwner(ctx, &corev1.SetPolicyOwnerRequest{
		PolicyId: policyID, OwnerUserId: ownerUserID, ActorUserId: actor,
	})
	if err != nil {
		return nil, err
	}
	return policyFromProto(resp.GetPolicy()), nil
}

// MovePolicy moves a policy to another category and renumbers it there. Site
// admin only.
func MovePolicy(ctx context.Context, client corev1.PolicyServiceClient, policyID, homeCategoryID string) (*Policy, error) {
	actor, err := requireSiteAdmin(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.MovePolicy(ctx, &corev1.MovePolicyRequest{
		PolicyId: policyID, HomeCategoryId: homeCategoryID, ActorUserId: actor,
	})
	if err != nil {
		return nil, err
	}
	return policyFromProto(resp.GetPolicy()), nil
}

// ReindexPolicy re-sends the policy's published version to the AI indexer
// only (no review email). Site admin only.
func ReindexPolicy(ctx context.Context, client corev1.PolicyServiceClient, policyID string) (*ReindexResult, error) {
	actor, err := requireSiteAdmin(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.ReindexPolicy(ctx, &corev1.ReindexPolicyRequest{
		PolicyId: policyID, ActorUserId: actor,
	})
	if err != nil {
		return nil, err
	}
	return &ReindexResult{
		VersionID:    resp.GetVersionId(),
		Sections:     int(resp.GetSections()),
		RemovedPrior: int(resp.GetRemovedPrior()),
	}, nil
}

// ReindexPolicyVersion is ReindexPolicy for one published version.
func ReindexPolicyVersion(ctx context.Context, client corev1.PolicyServiceClient, policyVersionID string) (*ReindexResult, error) {
	actor, err := requireSiteAdmin(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.ReindexPolicyVersion(ctx, &corev1.ReindexPolicyVersionRequest{
		PolicyVersionId: policyVersionID, ActorUserId: actor,
	})
	if err != nil {
		return nil, err
	}
	return &ReindexResult{
		VersionID:    resp.GetVersionId(),
		Sections:     int(resp.GetSections()),
		RemovedPrior: int(resp.GetRemovedPrior()),
	}, nil
}
