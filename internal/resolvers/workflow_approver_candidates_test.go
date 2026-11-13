// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"sort"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// workflowApproverCandidates answers who the workflow editor may offer as an approver: the Approve
// pools of the categories that use the workflow as their default, nothing for a workflow no
// category uses (Steward-GRC/steward-gateway#215).

const candidateWorkflowID = "wf-1"

func candidateWorkflow() *fakeWorkflowClient {
	return &fakeWorkflowClient{getDefResp: &workflowv1.GetWorkflowDefResponse{
		Def: &workflowv1.WorkflowDef{Id: candidateWorkflowID, Name: "Standard review"},
	}}
}

// candidateIdentity has an ordinary approver, a bystander and the root seat.
func candidateIdentity() *raciIdentityClient {
	return &raciIdentityClient{
		users: map[string]*identityv1.User{
			"ceo":     {Id: "ceo", Name: "Dana Example"},
			"nobody":  {Id: "nobody", Name: "Bob Example"},
			"root-id": {Id: "root-id", Name: "Root", IsRoot: true},
			"cfo":     {Id: "cfo", Name: "Grace Example"},
		},
		idpGroups: map[string][]string{},
	}
}

func approveRule(user string) *corev1.CategoryRule {
	return &corev1.CategoryRule{
		SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
		SubjectRef:  user,
		Approve:     corev1.GrantEffect_GRANT_EFFECT_ALLOW,
	}
}

func candidateIDs(c *resolvers.WorkflowApproverCandidates) []string {
	out := make([]string, 0, len(c.Users))
	for _, u := range c.Users {
		out = append(out, u.UserID)
	}
	sort.Strings(out)
	return out
}

func candidateResolver(workflow *fakeWorkflowClient, gc *viewerCategoryClient) *resolvers.Resolver {
	return &resolvers.Resolver{CategoryClient: gc, IdentityClient: candidateIdentity(), WorkflowClient: workflow}
}

func TestWorkflowApproverCandidates_AttachedOffersTheCategoryPoolWithoutRoot(t *testing.T) {
	gc := &viewerCategoryClient{
		raciCategoryClient: raciCategoryClient{
			groups: map[string]*corev1.Category{
				"it": {Id: "it", Name: "IT", DefaultWorkflowId: candidateWorkflowID, Owners: []string{"cfo"}},
			},
			rulesets: map[string][]*corev1.CategoryRule{"it": {approveRule("ceo")}},
		},
		children: map[string][]*corev1.Category{
			"": {{Id: "it", Name: "IT", DefaultWorkflowId: candidateWorkflowID, Owners: []string{"cfo"}}},
		},
	}

	got, err := resolvers.WorkflowApproverCandidatesResolver(
		ctxWithRoles(t, "u-admin", []string{"template-admin"}), candidateResolver(candidateWorkflow(), gc), candidateWorkflowID)
	if err != nil {
		t.Fatalf("WorkflowApproverCandidatesResolver: %v", err)
	}
	if !got.Attached {
		t.Fatalf("attached = false, want true for a workflow the IT category uses")
	}
	if got.WorkflowID != candidateWorkflowID {
		t.Fatalf("workflowId = %q, want %q", got.WorkflowID, candidateWorkflowID)
	}
	if len(got.CategoryIds) != 1 || got.CategoryIds[0] != "it" {
		t.Fatalf("categoryIds = %v, want [it]", got.CategoryIds)
	}
	// The owner and the user the rows allow; neither the bystander nor root, who is exempt for
	// Read, Author and Manage only.
	sameIDs(t, candidateIDs(got), []string{"ceo", "cfo"})
}

func TestWorkflowApproverCandidates_RootAppearsOnlyWhenTheRowsAllowApprove(t *testing.T) {
	gc := &viewerCategoryClient{
		raciCategoryClient: raciCategoryClient{
			groups:   map[string]*corev1.Category{"it": {Id: "it", Name: "IT", DefaultWorkflowId: candidateWorkflowID}},
			rulesets: map[string][]*corev1.CategoryRule{"it": {approveRule("root-id")}},
		},
		children: map[string][]*corev1.Category{
			"": {{Id: "it", Name: "IT", DefaultWorkflowId: candidateWorkflowID}},
		},
	}

	got, err := resolvers.WorkflowApproverCandidatesResolver(
		ctxWithRoles(t, "u-admin", []string{"template-admin"}), candidateResolver(candidateWorkflow(), gc), candidateWorkflowID)
	if err != nil {
		t.Fatalf("WorkflowApproverCandidatesResolver: %v", err)
	}
	sameIDs(t, candidateIDs(got), []string{"root-id"})
}

func TestWorkflowApproverCandidates_NotAttachedIsEmptyAndSaysSo(t *testing.T) {
	gc := &viewerCategoryClient{
		raciCategoryClient: raciCategoryClient{
			groups: map[string]*corev1.Category{
				"it": {Id: "it", Name: "IT", DefaultWorkflowId: "wf-other", Owners: []string{"cfo"}},
			},
			rulesets: map[string][]*corev1.CategoryRule{"it": {approveRule("ceo")}},
		},
		children: map[string][]*corev1.Category{
			"": {{Id: "it", Name: "IT", DefaultWorkflowId: "wf-other", Owners: []string{"cfo"}}},
		},
	}

	got, err := resolvers.WorkflowApproverCandidatesResolver(
		ctxWithRoles(t, "u-admin", []string{"template-admin"}), candidateResolver(candidateWorkflow(), gc), candidateWorkflowID)
	if err != nil {
		t.Fatalf("WorkflowApproverCandidatesResolver: %v", err)
	}
	if got.Attached {
		t.Fatalf("attached = true, want false: no category uses %s", candidateWorkflowID)
	}
	if got.Users == nil || len(got.Users) != 0 {
		t.Fatalf("users = %v, want an empty non-nil list, not a global list", got.Users)
	}
	if got.CategoryIds == nil || len(got.CategoryIds) != 0 {
		t.Fatalf("categoryIds = %v, want an empty non-nil list", got.CategoryIds)
	}
}

func TestWorkflowApproverCandidates_UnionsEveryAttachedCategoryOnce(t *testing.T) {
	it := &corev1.Category{Id: "it", Name: "IT", DefaultWorkflowId: candidateWorkflowID}
	cyber := &corev1.Category{Id: "cyber", Name: "Cyber", ParentId: "it", DefaultWorkflowId: candidateWorkflowID}
	hr := &corev1.Category{Id: "hr", Name: "HR", DefaultWorkflowId: candidateWorkflowID}
	gc := &viewerCategoryClient{
		raciCategoryClient: raciCategoryClient{
			groups: map[string]*corev1.Category{"it": it, "cyber": cyber, "hr": hr},
			rulesets: map[string][]*corev1.CategoryRule{
				"it": {approveRule("ceo")},
				"hr": {approveRule("ceo"), approveRule("cfo")},
			},
		},
		children: map[string][]*corev1.Category{"": {it, hr}, "it": {cyber}},
	}

	got, err := resolvers.WorkflowApproverCandidatesResolver(
		ctxWithRoles(t, "u-admin", []string{"template-admin"}), candidateResolver(candidateWorkflow(), gc), candidateWorkflowID)
	if err != nil {
		t.Fatalf("WorkflowApproverCandidatesResolver: %v", err)
	}
	cats := append([]string(nil), got.CategoryIds...)
	sort.Strings(cats)
	sameIDs(t, cats, []string{"cyber", "hr", "it"})
	sameIDs(t, candidateIDs(got), []string{"ceo", "cfo"})
}

func TestWorkflowApproverCandidates_NeedsWorkflowManage(t *testing.T) {
	gc := &viewerCategoryClient{}
	_, err := resolvers.WorkflowApproverCandidatesResolver(
		ctxWithRoles(t, "u-plain", nil), candidateResolver(candidateWorkflow(), gc), candidateWorkflowID)
	if err == nil {
		t.Fatal("a caller without workflow management got the approver candidates")
	}
}

func TestWorkflowApproverCandidates_UnknownWorkflowIsAnError(t *testing.T) {
	wf := candidateWorkflow()
	wf.getDefErr = status.Error(codes.NotFound, "workflow not found")
	gc := &viewerCategoryClient{}
	_, err := resolvers.WorkflowApproverCandidatesResolver(
		ctxWithRoles(t, "u-admin", []string{"template-admin"}), candidateResolver(wf, gc), "wf-missing")
	if err == nil {
		t.Fatal("an unknown workflow returned candidates")
	}
}
