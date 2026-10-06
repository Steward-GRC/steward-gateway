// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stageEligibleAssignees shows the reassign picker the stage's eligible pool
// before the admin submits a swap. The pool is the one SwapAssignee checks
// against, read from workflow, and gated like swapAssignee because workflow
// does no authz on this read.

func poolIdentity() *labelIdentityFake {
	return &labelIdentityFake{users: map[string]*identityv1.User{
		"u-3": {Id: "u-3", Name: "Grace Hopper", Email: "grace@example.com"},
		"u-1": {Id: "u-1", Name: "Alan Turing", Email: "alan@example.com"},
		"u-2": {Id: "u-2", Name: "Ada Lovelace"},
	}}
}

func TestStageEligibleAssignees_ResolvesThePoolInDefinitionOrder(t *testing.T) {
	wf := &fakeWorkflowClient{poolResp: &workflowv1.GetStageEligiblePoolResponse{
		StageIndex: 1, StageName: "Legal review",
		EligibleUserIds: []string{"u-3", "u-1", "u-2", "u-gone"},
	}}

	got, err := resolvers.StageEligibleAssigneesResolver(
		ctxWithRoles(t, "u-admin", []string{"template-admin"}), wf, poolIdentity(), "pv-1", 1)
	if err != nil {
		t.Fatalf("StageEligibleAssigneesResolver: %v", err)
	}
	if wf.lastPool.GetPolicyVersionId() != "pv-1" || wf.lastPool.GetStageIndex() != 1 {
		t.Fatalf("request = %+v, want pv-1 stage 1", wf.lastPool)
	}
	if got.StageIndex != 1 || got.StageName != "Legal review" {
		t.Fatalf("stage = %d %q, want 1 Legal review", got.StageIndex, got.StageName)
	}
	want := []struct {
		id, name string
		email    *string
	}{
		{"u-3", "Grace Hopper", new("grace@example.com")},
		{"u-1", "Alan Turing", new("alan@example.com")},
		{"u-2", "Ada Lovelace", nil},
		{"u-gone", "u-gone", nil},
	}
	if len(got.Assignees) != len(want) {
		t.Fatalf("assignees = %d, want %d", len(got.Assignees), len(want))
	}
	for i, w := range want {
		a := got.Assignees[i]
		if a.ID != w.id || a.Name != w.name {
			t.Errorf("assignee[%d] = %s %q, want %s %q", i, a.ID, a.Name, w.id, w.name)
		}
		if derefStr(a.Email) != derefStr(w.email) || (a.Email == nil) != (w.email == nil) {
			t.Errorf("assignee[%d] email = %v, want %v", i, derefStr(a.Email), derefStr(w.email))
		}
	}
}

func TestStageEligibleAssignees_EmptyPoolIsAnEmptyList(t *testing.T) {
	wf := &fakeWorkflowClient{poolResp: &workflowv1.GetStageEligiblePoolResponse{StageName: "Group stage"}}

	got, err := resolvers.StageEligibleAssigneesResolver(
		ctxWithRoles(t, "u-admin", []string{"site-admin"}), wf, poolIdentity(), "pv-1", 0)
	if err != nil {
		t.Fatalf("StageEligibleAssigneesResolver: %v", err)
	}
	if got.Assignees == nil || len(got.Assignees) != 0 {
		t.Fatalf("assignees = %v, want an empty non-nil list", got.Assignees)
	}
}

func TestStageEligibleAssignees_AllowsWorkflowManagers(t *testing.T) {
	for _, role := range []string{"template-admin", "site-admin"} {
		t.Run(role, func(t *testing.T) {
			wf := &fakeWorkflowClient{poolResp: &workflowv1.GetStageEligiblePoolResponse{}}
			if _, err := resolvers.StageEligibleAssigneesResolver(
				ctxWithRoles(t, "u-x", []string{role}), wf, poolIdentity(), "pv-1", 0); err != nil {
				t.Fatalf("%s refused: %v", role, err)
			}
		})
	}
}

func TestStageEligibleAssignees_RefusesNonManagers(t *testing.T) {
	for _, roles := range [][]string{nil, {"reader"}, {"author"}, {"approver"}, {"compliance-admin"}} {
		t.Run(func() string {
			if len(roles) == 0 {
				return "no role"
			}
			return roles[0]
		}(), func(t *testing.T) {
			wf := &fakeWorkflowClient{poolResp: &workflowv1.GetStageEligiblePoolResponse{EligibleUserIds: []string{"u-1"}}}
			_, err := resolvers.StageEligibleAssigneesResolver(
				ctxWithRoles(t, "u-x", roles), wf, poolIdentity(), "pv-1", 0)
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("code = %v, want PermissionDenied (err %v)", status.Code(err), err)
			}
			if wf.lastPool != nil {
				t.Fatal("workflow was called before the gate refused")
			}
		})
	}
}

func TestStageEligibleAssignees_RefusesAnonymousCallers(t *testing.T) {
	wf := &fakeWorkflowClient{poolResp: &workflowv1.GetStageEligiblePoolResponse{}}
	_, err := resolvers.StageEligibleAssigneesResolver(t.Context(), wf, poolIdentity(), "pv-1", 0)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err %v)", status.Code(err), err)
	}
	if wf.lastPool != nil {
		t.Fatal("workflow was called for an anonymous caller")
	}
}

func TestStageEligibleAssignees_RelaysWorkflowCodes(t *testing.T) {
	cases := []struct {
		grpcCode codes.Code
		num      int
		symbol   string
		md       map[string]string
	}{
		{codes.InvalidArgument, 6011, "STAGE_INDEX_OUT_OF_RANGE", map[string]string{"stage": "4", "stage_count": "2"}},
		{codes.NotFound, 6012, "APPROVAL_RUN_NOT_FOUND", map[string]string{"policy_version_id": "pv-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.symbol, func(t *testing.T) {
			wf := &fakeWorkflowClient{poolErr: backendCodedErr(tc.grpcCode, tc.num, tc.symbol, "workflow", tc.md)}
			_, err := resolvers.StageEligibleAssigneesResolver(
				ctxWithRoles(t, "u-admin", []string{"site-admin"}), wf, poolIdentity(), "pv-1", 4)
			if status.Code(err) != tc.grpcCode {
				t.Fatalf("code = %v, want %v", status.Code(err), tc.grpcCode)
			}
			info, ok := apperrgrpc.FromStatus(status.Convert(err))
			if !ok || info.Code != tc.num || info.Symbol != tc.symbol || info.Domain != "workflow" {
				t.Fatalf("relayed ErrorInfo = %+v (ok %v), want %d %s workflow", info, ok, tc.num, tc.symbol)
			}
			for k, v := range tc.md {
				if info.Metadata[k] != v {
					t.Errorf("metadata %s = %q, want %q", k, info.Metadata[k], v)
				}
			}
		})
	}
}

func TestStageEligibleAssignees_ThroughTheSchema(t *testing.T) {
	wf := &fakeWorkflowClient{poolResp: &workflowv1.GetStageEligiblePoolResponse{
		StageIndex: 0, StageName: "Review", EligibleUserIds: []string{"u-1", "u-2"},
	}}
	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{
		Resolvers: &resolvers.Resolver{WorkflowClient: wf, IdentityClient: poolIdentity()},
	}))
	srv.AddTransport(transport.POST{})
	body, err := json.Marshal(map[string]any{
		"query": `{ stageEligibleAssignees(policyVersionId: "pv-1", stageIndex: 0) { stageIndex stageName assignees { id name email } } }`,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest("POST", "/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithRoles(t, "u-admin", []string{"template-admin"}))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	var out struct {
		Data struct {
			Pool struct {
				StageIndex int    `json:"stageIndex"`
				StageName  string `json:"stageName"`
				Assignees  []struct {
					ID    string  `json:"id"`
					Name  string  `json:"name"`
					Email *string `json:"email"`
				} `json:"assignees"`
			} `json:"stageEligibleAssignees"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	if len(out.Errors) != 0 {
		t.Fatalf("errors: %+v", out.Errors)
	}
	p := out.Data.Pool
	if p.StageName != "Review" || len(p.Assignees) != 2 || p.Assignees[0].ID != "u-1" || p.Assignees[1].Name != "Ada Lovelace" {
		t.Fatalf("pool = %+v", p)
	}
	if p.Assignees[0].Email == nil || *p.Assignees[0].Email != "alan@example.com" || p.Assignees[1].Email != nil {
		t.Fatalf("emails = %v / %v", derefStr(p.Assignees[0].Email), derefStr(p.Assignees[1].Email))
	}
}
