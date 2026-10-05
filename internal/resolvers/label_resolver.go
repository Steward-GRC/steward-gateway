// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"strconv"
	"strings"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// labelResolver turns the raw user, category and subject ids on audit and
// assignment-history records into display labels. Build one per request: its
// caches resolve each distinct id once per response. Every lookup is best
// effort; a miss yields "" and the caller falls back to the raw id, because a
// label is decoration and must never fail the page.
//
// Subjects are the "type:id" strings the audit writers emit: user, policy,
// policy_version, category (core), group (identity), template and
// template_version. Anything else is returned unchanged.
type labelResolver struct {
	identity   identityv1.IdentityReadServiceClient
	categories corev1.CategoryServiceClient
	policies   corev1.PolicyServiceClient
	tmpls      corev1.TemplateServiceClient

	userNames    map[string]string
	userEmails   map[string]string
	categoryName map[string]string
	groupName    map[string]string
	subjects     map[string]string
	polByVer     map[string]string
	polLabel     map[string]string
	tmplLabel    map[string]string
	verNo        map[string]int32
	verTmpl      map[string]string
	verIndex     bool
}

func newLabelResolver(
	identity identityv1.IdentityReadServiceClient,
	categories corev1.CategoryServiceClient,
	policies corev1.PolicyServiceClient,
	tmpls corev1.TemplateServiceClient,
) *labelResolver {
	return &labelResolver{
		identity:     identity,
		categories:   categories,
		policies:     policies,
		tmpls:        tmpls,
		userNames:    map[string]string{},
		userEmails:   map[string]string{},
		categoryName: map[string]string{},
		groupName:    map[string]string{},
		subjects:     map[string]string{},
		polByVer:     map[string]string{},
		polLabel:     map[string]string{},
		tmplLabel:    map[string]string{},
		verNo:        map[string]int32{},
		verTmpl:      map[string]string{},
	}
}

// userName resolves a user id to its display name (falling back to email).
func (l *labelResolver) userName(ctx context.Context, id string) string {
	name, _ := l.userLabelFields(ctx, id)
	return name
}

// userLabelFields resolves a user id to its display name AND email from a SINGLE GetUser call — the
// response already carries both, so surfacing email costs no extra round-trip.
func (l *labelResolver) userLabelFields(ctx context.Context, id string) (name, email string) {
	if id == "" || l.identity == nil {
		return "", ""
	}
	if v, ok := l.userNames[id]; ok {
		return v, l.userEmails[id]
	}
	if resp, err := l.identity.GetUser(ctx, &identityv1.GetUserRequest{UserId: id}); err == nil {
		if u := resp.GetUser(); u != nil {
			email = u.GetEmail()
			name = u.GetName()
			if name == "" {
				name = email
			}
		}
	}
	l.userNames[id] = name
	l.userEmails[id] = email
	return name, email
}

// categoryNameByID resolves a core category id to its name; "" on a miss.
func (l *labelResolver) categoryNameByID(ctx context.Context, id string) string {
	if id == "" || l.categories == nil {
		return ""
	}
	if v, ok := l.categoryName[id]; ok {
		return v
	}
	name := ""
	if resp, err := l.categories.GetCategory(ctx, &corev1.GetCategoryRequest{Id: id}); err == nil {
		name = resp.GetCategory().GetName()
	}
	l.categoryName[id] = name
	return name
}

// groupNameByID resolves an identity group id to its name; "" on a miss.
func (l *labelResolver) groupNameByID(ctx context.Context, id string) string {
	if id == "" || l.identity == nil {
		return ""
	}
	if v, ok := l.groupName[id]; ok {
		return v
	}
	name := ""
	if resp, err := l.identity.GetGroup(ctx, &identityv1.GetGroupRequest{GroupId: id}); err == nil {
		name = resp.GetGroup().GetName()
	}
	l.groupName[id] = name
	return name
}

// policyLabelByID resolves a policy id to a document-type-aware label built from the human NUMBER:
// "Policy POL-0012" for a policy, "Procedure PRC-0003" for a procedure.
func (l *labelResolver) policyLabelByID(ctx context.Context, id string) string {
	if id == "" || l.policies == nil {
		return ""
	}
	if v, ok := l.polLabel[id]; ok {
		return v
	}
	label := ""
	if resp, err := l.policies.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: id}); err == nil {
		label = policyDisplayLabel(resp.GetPolicy())
	}
	l.polLabel[id] = label
	return label
}

// documentTypeLabel returns the human noun for a document type.
func documentTypeLabel(dt corev1.DocumentType) string {
	if dt == corev1.DocumentType_DOCUMENT_TYPE_PROCEDURE {
		return "Procedure"
	}
	return "Policy"
}

// policyDisplayLabel renders a Policy as its document-type-aware, number-first label: "Policy
// POL-0012" / "Procedure PRC-0003".
func policyDisplayLabel(p *corev1.Policy) string {
	if p == nil {
		return ""
	}
	typeLabel := documentTypeLabel(p.GetDocumentType())
	if num := strings.TrimSpace(p.GetNumber()); num != "" {
		return typeLabel + " " + num
	}
	if title := strings.TrimSpace(p.GetTitle()); title != "" {
		return typeLabel + ": " + title
	}
	return ""
}

// policyIDForVersion resolves a policy-version id to its parent policy id.
func (l *labelResolver) policyIDForVersion(ctx context.Context, versionID string) string {
	if versionID == "" || l.policies == nil {
		return ""
	}
	if v, ok := l.polByVer[versionID]; ok {
		return v
	}
	policyID := ""
	if resp, err := l.policies.GetPolicyVersion(ctx, &corev1.GetPolicyVersionRequest{Id: versionID}); err == nil {
		policyID = resp.GetVersion().GetPolicyId()
	}
	l.polByVer[versionID] = policyID
	return policyID
}

// templateVersionLabel resolves a template-version id to "<name> v<n>". Core
// has no lookup by version id, so the first one walks every template's
// versions once per request.
func (l *labelResolver) templateVersionLabel(ctx context.Context, versionID string) string {
	if versionID == "" || l.tmpls == nil {
		return ""
	}
	l.buildVersionIndex(ctx)
	tmplID, ok := l.verTmpl[versionID]
	if !ok || tmplID == "" {
		return ""
	}
	name := l.templateName(ctx, tmplID)
	if name == "" {
		return ""
	}
	if verNo := l.verNo[versionID]; verNo > 0 {
		return name + " v" + strconv.Itoa(int(verNo))
	}
	return name
}

// buildVersionIndex populates verTmpl/verNo for every template version, once per request.
func (l *labelResolver) buildVersionIndex(ctx context.Context) {
	if l.verIndex || l.tmpls == nil {
		return
	}
	l.verIndex = true
	resp, err := l.tmpls.ListTemplates(ctx, &corev1.ListTemplatesRequest{})
	if err != nil {
		return
	}
	for _, t := range resp.GetTemplates() {
		l.cacheTemplateName(t)
		vresp, verr := l.tmpls.ListTemplateVersions(ctx, &corev1.ListTemplateVersionsRequest{TemplateId: t.GetId()})
		if verr != nil {
			continue
		}
		for _, v := range vresp.GetVersions() {
			l.verTmpl[v.GetId()] = t.GetId()
			l.verNo[v.GetId()] = v.GetVersionNo()
		}
	}
}

// cacheTemplateName records a Template's display name in tmplLabel (idempotent).
func (l *labelResolver) cacheTemplateName(t *corev1.Template) {
	if t == nil {
		return
	}
	if _, seen := l.tmplLabel[t.GetId()]; seen {
		return
	}
	name := t.GetName()
	if c := t.GetCode(); c != "" {
		if name != "" {
			name = name + " (" + c + ")"
		} else {
			name = c
		}
	}
	l.tmplLabel[t.GetId()] = name
}

// templateName resolves a template id to its name.
func (l *labelResolver) templateName(ctx context.Context, id string) string {
	if id == "" || l.tmpls == nil {
		return ""
	}
	if v, ok := l.tmplLabel[id]; ok {
		return v
	}
	if resp, err := l.tmpls.ListTemplates(ctx, &corev1.ListTemplatesRequest{}); err == nil {
		for _, t := range resp.GetTemplates() {
			l.cacheTemplateName(t)
		}
	}
	if _, ok := l.tmplLabel[id]; !ok {
		l.tmplLabel[id] = ""
	}
	return l.tmplLabel[id]
}

// subjectLabel renders a `type:uuid` subject into a readable label.
func (l *labelResolver) subjectLabel(ctx context.Context, subject string) string {
	if subject == "" {
		return ""
	}
	if v, ok := l.subjects[subject]; ok {
		return v
	}
	label := l.resolveSubject(ctx, subject)
	l.subjects[subject] = label
	return label
}

func (l *labelResolver) resolveSubject(ctx context.Context, subject string) string {
	kind, id, ok := splitTypedID(subject)
	if !ok {
		return subject
	}
	switch kind {
	case "user":
		return l.userName(ctx, id)
	case "policy_version":
		policyID := l.policyIDForVersion(ctx, id)
		if policyID == "" {
			return ""
		}
		base := l.policyLabelByID(ctx, policyID)
		if base == "" {
			return ""
		}
		return base + " (version)"
	case "policy":
		return l.policyLabelByID(ctx, id)
	case "category":
		return l.categoryNameByID(ctx, id)
	case "group":
		return l.groupNameByID(ctx, id)
	case "template_version":
		return l.templateVersionLabel(ctx, id)
	case "template":
		return l.templateName(ctx, id)
	default:
		return subject
	}
}

// splitTypedID splits "type:uuid" into ("type","uuid",true).
func splitTypedID(s string) (kind, id string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}
