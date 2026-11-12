// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"encoding/json"
	"testing"

	apperr "github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// Moving several documents at once (#82). The mock server is the reference for
// what steward-web sees: steward-mock-server src/product/bulk-move.test.ts. Each
// test below is one row of the parity table in the PR; its name says which mock
// test it follows. The audit entries (policy.moved per document, policy.bulk_moved
// for the batch) are written by steward-core, so the gateway tests assert only
// that the call reaches core once, with the actor bound from the signed-in user.

// bulkMoveCore is the policy client for these tests: it records the bulk calls it
// sees and answers with the canned response or error.
type bulkMoveCore struct {
	corev1.PolicyServiceClient
	previewReq  []*corev1.PreviewMovePoliciesRequest
	moveReq     []*corev1.MovePoliciesRequest
	previewResp *corev1.PreviewMovePoliciesResponse
	moveResp    *corev1.MovePoliciesResponse
	err         error
}

func (f *bulkMoveCore) PreviewMovePolicies(_ context.Context, in *corev1.PreviewMovePoliciesRequest, _ ...grpc.CallOption) (*corev1.PreviewMovePoliciesResponse, error) {
	f.previewReq = append(f.previewReq, in)
	return f.previewResp, f.err
}

func (f *bulkMoveCore) MovePolicies(_ context.Context, in *corev1.MovePoliciesRequest, _ ...grpc.CallOption) (*corev1.MovePoliciesResponse, error) {
	f.moveReq = append(f.moveReq, in)
	return f.moveResp, f.err
}

const (
	bulkPreviewQuery = `query { previewMovePolicies(policyIds: ["p1", "p2"], homeCategoryId: "cat-finance") { items { policyId title number newNumber refusal } } }`
	bulkMoveMutation = `mutation { movePolicies(policyIds: ["p1", "p2"], homeCategoryId: "cat-finance") { moved { policyId title number newNumber refusal } } }`
)

type bulkItem struct {
	PolicyID  string  `json:"policyId"`
	Title     string  `json:"title"`
	Number    string  `json:"number"`
	NewNumber *string `json:"newNumber"`
	Refusal   *string `json:"refusal"`
}

func bulkAdminCtx(t *testing.T) context.Context {
	t.Helper()
	return ctxWithRoles(t, "admin-1", []string{"site-admin"})
}

// moveRefusedStatus is the status core sends for a refused batch: its MOVE_REFUSED
// code (4006), built over core's own registry entry so the metadata and the
// rendered sentence are what the wire carries.
func moveRefusedStatus(t *testing.T, document, reason, refusal string) error {
	t.Helper()
	reg, err := apperr.NewRegistry([]apperr.Entry{{
		Code: 4006, Symbol: "MOVE_REFUSED", Category: apperr.CategoryFailedPrecondition,
		Title: "move documents", Cause: "a bulk move was refused whole", UserSafe: true,
		Message: "Can't move {document}: {refusal}",
	}}, apperr.WithService(4))
	require.NoError(t, err)
	cause := apperr.WithMeta(apperr.Coded(4006, nil),
		apperr.Meta("document", document), apperr.Meta("reason", reason), apperr.Meta("refusal", refusal))
	return apperrgrpc.Error(context.Background(), reg, cause, 4000, "core")
}

func decodeItems(t *testing.T, data json.RawMessage, field, list string) []bulkItem {
	t.Helper()
	var out map[string]map[string][]bulkItem
	require.NoError(t, json.Unmarshal(data, &out))
	return out[field][list]
}

// mock "previewMovePolicies says what each document would get and changes
// nothing": the dry run calls core's preview only, in the order asked, and maps
// every item; no move is made.
func TestBulkMoveParity_PreviewSaysWhatEachWouldGetAndChangesNothing(t *testing.T) {
	core := &bulkMoveCore{previewResp: &corev1.PreviewMovePoliciesResponse{Items: []*corev1.MovePoliciesItem{
		{PolicyId: "p1", Title: "Travel", Number: "POL-EXPENSES-000001", NewNumber: "POL-FINANCE-000007"},
		{PolicyId: "p2", Title: "Meals", Number: "POL-EXPENSES-000002", NewNumber: "POL-FINANCE-000008"},
	}}}
	data, errs := reviewGQL(t, bulkAdminCtx(t), &resolvers.Resolver{PolicyClient: core}, bulkPreviewQuery)
	require.Empty(t, errs)

	items := decodeItems(t, data, "previewMovePolicies", "items")
	require.Len(t, items, 2)
	require.Equal(t, "p1", items[0].PolicyID)
	require.Equal(t, "Travel", items[0].Title)
	require.Equal(t, "POL-EXPENSES-000001", items[0].Number)
	require.NotNil(t, items[0].NewNumber)
	require.Equal(t, "POL-FINANCE-000007", *items[0].NewNumber)
	require.Nil(t, items[0].Refusal)
	require.Equal(t, "POL-FINANCE-000008", *items[1].NewNumber)

	require.Len(t, core.previewReq, 1)
	require.Equal(t, []string{"p1", "p2"}, core.previewReq[0].GetPolicyIds())
	require.Equal(t, "cat-finance", core.previewReq[0].GetHomeCategoryId())
	require.Equal(t, "admin-1", core.previewReq[0].GetActorUserId(), "actor must be bound from claims")
	require.Empty(t, core.moveReq, "a dry run must not move anything")
}

// mock "gives a refusal, not a number, to a document the target does not hold":
// core's empty new_number is null and its refusal sentence is passed on as is.
func TestBulkMoveParity_PreviewGivesARefusalNotANumber(t *testing.T) {
	const sentence = "CATEGORY_REFUSES_TYPE: Conduct does not hold this type of document."
	core := &bulkMoveCore{previewResp: &corev1.PreviewMovePoliciesResponse{Items: []*corev1.MovePoliciesItem{
		{PolicyId: "p1", Title: "Travel", Number: "POL-EXPENSES-000001", RefusalCode: "CATEGORY_REFUSES_TYPE", Refusal: sentence},
	}}}
	data, errs := reviewGQL(t, bulkAdminCtx(t), &resolvers.Resolver{PolicyClient: core}, bulkPreviewQuery)
	require.Empty(t, errs)

	items := decodeItems(t, data, "previewMovePolicies", "items")
	require.Len(t, items, 1)
	require.Nil(t, items[0].NewNumber)
	require.NotNil(t, items[0].Refusal)
	require.Equal(t, sentence, *items[0].Refusal)
}

// mock "moves them all, renumbering in the target's sequence": every moved
// document comes back with its new number, in order, from a single core call.
func TestBulkMoveParity_MovesThemAllRenumberedInTheTargetsSequence(t *testing.T) {
	core := &bulkMoveCore{moveResp: &corev1.MovePoliciesResponse{Moved: []*corev1.MovePoliciesItem{
		{PolicyId: "p1", Title: "Travel", Number: "POL-EXPENSES-000001", NewNumber: "POL-FINANCE-000007"},
		{PolicyId: "p2", Title: "Meals", Number: "POL-EXPENSES-000002", NewNumber: "POL-FINANCE-000008"},
	}}}
	data, errs := reviewGQL(t, bulkAdminCtx(t), &resolvers.Resolver{PolicyClient: core}, bulkMoveMutation)
	require.Empty(t, errs)

	moved := decodeItems(t, data, "movePolicies", "moved")
	require.Len(t, moved, 2)
	require.Equal(t, "POL-FINANCE-000007", *moved[0].NewNumber)
	require.Equal(t, "POL-FINANCE-000008", *moved[1].NewNumber)
	require.Nil(t, moved[0].Refusal)

	require.Len(t, core.moveReq, 1, "one call for the whole batch")
	require.Equal(t, []string{"p1", "p2"}, core.moveReq[0].GetPolicyIds())
	require.Equal(t, "cat-finance", core.moveReq[0].GetHomeCategoryId())
	require.Equal(t, "admin-1", core.moveReq[0].GetActorUserId(), "actor must be bound from claims")
	require.Empty(t, core.previewReq)
}

// mock "refuses the whole batch when one document would be refused, and moves
// nothing": core's MOVE_REFUSED reaches the web as an error, not a result, with
// the originating code, the sentence core rendered, and the reason metadata. The
// mock spells the code FailedPrecondition; core's own symbol is the difference.
func TestBulkMoveParity_RefusesTheWholeBatchWithCoresCode(t *testing.T) {
	const sentence = "CATEGORY_REFUSES_TYPE: Conduct does not hold this type of document."
	core := &bulkMoveCore{err: moveRefusedStatus(t, "POL-EXPENSES-000001", "CATEGORY_REFUSES_TYPE", sentence)}
	data, errs := reviewGQL(t, bulkAdminCtx(t), &resolvers.Resolver{PolicyClient: core}, bulkMoveMutation)

	require.Equal(t, "MOVE_REFUSED", errCodeOf(t, errs))
	require.Equal(t, "Can't move POL-EXPENSES-000001: "+sentence, errs[0].Message)
	require.Contains(t, errs[0].Message, "CATEGORY_REFUSES_TYPE")
	require.EqualValues(t, 4006, errs[0].Extensions["codeNum"])
	require.Equal(t, "business", errs[0].Extensions["kind"])
	require.Equal(t, "CATEGORY_REFUSES_TYPE", errs[0].Extensions["reason"])
	require.Equal(t, sentence, errs[0].Extensions["refusal"])
	require.JSONEq(t, `null`, string(data), "a refused batch returns no moved list")
}

// mock "refuses an empty batch and an unknown target": core's InvalidArgument
// and NotFound pass through unchanged.
func TestBulkMoveParity_EmptyBatchAndUnknownTargetPassThrough(t *testing.T) {
	empty := &bulkMoveCore{err: status.Error(codes.InvalidArgument, "pick at least one document to move")}
	_, errs := reviewGQL(t, bulkAdminCtx(t), &resolvers.Resolver{PolicyClient: empty},
		`mutation { movePolicies(policyIds: [], homeCategoryId: "cat-finance") { moved { policyId } } }`)
	require.Equal(t, "InvalidArgument", errCodeOf(t, errs))
	require.Equal(t, "pick at least one document to move", errs[0].Message)

	unknown := &bulkMoveCore{err: status.Error(codes.NotFound, "target category not found")}
	_, errs = reviewGQL(t, bulkAdminCtx(t), &resolvers.Resolver{PolicyClient: unknown}, bulkMoveMutation)
	require.Equal(t, "NotFound", errCodeOf(t, errs))
}

// mock "is for a site admin only": neither the dry run nor the move reaches core
// for anyone else.
func TestBulkMoveParity_SiteAdminOnly(t *testing.T) {
	core := &bulkMoveCore{}
	author := ctxWithRoles(t, "u-1", []string{"policy-author"})

	_, errs := reviewGQL(t, author, &resolvers.Resolver{PolicyClient: core}, bulkMoveMutation)
	require.Equal(t, "PermissionDenied", errCodeOf(t, errs))
	_, errs = reviewGQL(t, author, &resolvers.Resolver{PolicyClient: core}, bulkPreviewQuery)
	require.Equal(t, "PermissionDenied", errCodeOf(t, errs))

	require.Empty(t, core.previewReq)
	require.Empty(t, core.moveReq)

	_, err := resolvers.MovePolicies(author, core, nil, []string{"p1"}, "cat-finance")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = resolvers.PreviewMovePolicies(author, core, nil, []string{"p1"}, "cat-finance")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}
