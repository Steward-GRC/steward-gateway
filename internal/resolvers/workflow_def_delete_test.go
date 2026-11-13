// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	apperr "github.com/Bugs5382/go-apperr"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// categoriesDefaulting builds a category forest where the named ids default to workflowID and
// the others default to something else.
func categoriesDefaulting(workflowID string, ids ...string) *fakeCategoryClient {
	groups := map[string]*corev1.Category{
		"root":  {Id: "root", DefaultWorkflowId: "other"},
		"child": {Id: "child", ParentId: "root", DefaultWorkflowId: "other"},
	}
	for _, id := range ids {
		groups[id] = &corev1.Category{Id: id, ParentId: "child", DefaultWorkflowId: workflowID}
	}
	return &fakeCategoryClient{groups: groups}
}

func deleteCtx(t *testing.T) context.Context {
	return ctxWithRoles(t, "u-actor", []string{"template-admin"})
}

// An author lacks workflow.manage: nothing is read or sent.
func TestDeleteWorkflowDefResolver_AuthorDenied(t *testing.T) {
	wf := &fakeWorkflowClient{}
	_, err := resolvers.DeleteWorkflowDefResolver(ctxWithRoles(t, "u1", []string{"author"}), nopLogger(), wf, categoriesDefaulting("def-1"), "def-1")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if wf.deleteDefCalls != 0 {
		t.Fatal("workflow must not be called for an unauthorized caller")
	}
}

func TestDeleteWorkflowDefResolver_Unauthenticated(t *testing.T) {
	wf := &fakeWorkflowClient{}
	_, err := resolvers.DeleteWorkflowDefResolver(context.Background(), nopLogger(), wf, categoriesDefaulting("def-1"), "def-1")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}

// A category default refuses with the stable code and the count, and workflow is never called.
func TestDeleteWorkflowDefResolver_CategoryDefaultRefusedWithCount(t *testing.T) {
	wf := &fakeWorkflowClient{}
	_, err := resolvers.DeleteWorkflowDefResolver(deleteCtx(t), nopLogger(), wf, categoriesDefaulting("def-1", "a", "b", "c"), "def-1")
	if err == nil {
		t.Fatal("want a refusal")
	}
	code, ok := apperr.Code(err)
	if !ok || code != errcodes.CodeWorkflowDefInUseByCategory {
		t.Fatalf("code = %v (ok %v), want %d", code, ok, errcodes.CodeWorkflowDefInUseByCategory)
	}
	if got := apperr.Metadata(err)["category_count"]; got != "3" {
		t.Fatalf("category_count = %q, want 3", got)
	}
	if got := apperr.Metadata(err)["id"]; got != "def-1" {
		t.Fatalf("id = %q, want def-1", got)
	}
	if wf.deleteDefCalls != 0 {
		t.Fatal("workflow must not be called while a category defaults to the definition")
	}
}

// A failure to list categories is returned, and workflow is not called on a guess.
func TestDeleteWorkflowDefResolver_CategoryListFailureStops(t *testing.T) {
	wf := &fakeWorkflowClient{}
	cats := &failingCategoryLister{err: status.Error(codes.Unavailable, "core down")}
	_, err := resolvers.DeleteWorkflowDefResolver(deleteCtx(t), nopLogger(), wf, cats, "def-1")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	if wf.deleteDefCalls != 0 {
		t.Fatal("workflow must not be called when categories could not be checked")
	}
}

type failingCategoryLister struct {
	corev1.CategoryServiceClient
	err error
}

func (f *failingCategoryLister) ListCategoryChildren(context.Context, *corev1.ListCategoryChildrenRequest, ...grpc.CallOption) (*corev1.ListCategoryChildrenResponse, error) {
	return nil, f.err
}

// Workflow's in-use refusal passes through unchanged with its code and counts.
func TestDeleteWorkflowDefResolver_WorkflowInUsePassesThrough(t *testing.T) {
	in := backendCodedErr(codes.FailedPrecondition, 6013, "WORKFLOW_DEF_IN_USE", "workflow",
		map[string]string{"id": "def-1", "run_count": "4", "override_count": "2"})
	wf := &fakeWorkflowClient{deleteDefErr: in}
	_, err := resolvers.DeleteWorkflowDefResolver(deleteCtx(t), nopLogger(), wf, categoriesDefaulting("def-1"), "def-1")
	if !errors.Is(err, in) && err != in {
		t.Fatalf("want workflow's error unchanged, got %v", err)
	}
	st := wireStatus(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v", st.Code())
	}
	if wf.deleteDefCalls != 1 {
		t.Fatalf("workflow calls = %d, want 1", wf.deleteDefCalls)
	}
}

func TestDeleteWorkflowDefResolver_NotFoundPassesThrough(t *testing.T) {
	in := backendCodedErr(codes.NotFound, 6014, "WORKFLOW_DEF_NOT_FOUND", "workflow", map[string]string{"id": "def-9"})
	wf := &fakeWorkflowClient{deleteDefErr: in}
	ok, err := resolvers.DeleteWorkflowDefResolver(deleteCtx(t), nopLogger(), wf, categoriesDefaulting("def-9"), "def-9")
	if ok || err != in {
		t.Fatalf("ok=%v err=%v, want false and the workflow error unchanged", ok, err)
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v", status.Code(err))
	}
}

// A category that defaults to a different workflow does not block the delete; the actor is the
// signed-in user.
func TestDeleteWorkflowDefResolver_HappyPathSendsIDAndActor(t *testing.T) {
	wf := &fakeWorkflowClient{}
	ok, err := resolvers.DeleteWorkflowDefResolver(deleteCtx(t), nopLogger(), wf, categoriesDefaulting("def-1"), "def-1")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if wf.lastDeleteDef.GetId() != "def-1" || wf.lastDeleteDef.GetActorUserId() != "u-actor" {
		t.Fatalf("request = %+v, want id def-1 actor u-actor", wf.lastDeleteDef)
	}
	if wf.deleteDefCalls != 1 {
		t.Fatalf("workflow calls = %d, want 1", wf.deleteDefCalls)
	}
}
