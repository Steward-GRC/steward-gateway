// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/bff"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

func TestSchemaOffersTransferRootNotGrantOrRevokeRoot(t *testing.T) {
	m := resolvers.NewExecutableSchema(resolvers.Config{}).Schema().Mutation
	if m == nil {
		t.Fatal("schema has no Mutation type")
	}
	tr := m.Fields.ForName("transferRoot")
	if tr == nil {
		t.Fatal("transferRoot mutation is missing")
	}
	if got := tr.Type.String(); got != "User!" {
		t.Errorf("transferRoot returns %s, want User!", got)
	}
	if tr.Arguments.ForName("userId") == nil || tr.Arguments.ForName("otp") == nil {
		t.Errorf("transferRoot must take userId and otp, got %d args", len(tr.Arguments))
	}
	for _, gone := range []string{"grantRoot", "revokeRoot"} {
		if m.Fields.ForName(gone) != nil {
			t.Errorf("%s must be removed from the schema", gone)
		}
	}
}

// seatIdentity is identity's one-root seat as the gateway sees it: GetUser
// answers from the current holder, TransferRoot moves the seat. Claims are
// rebuilt from it on every request, as the middleware does.
type seatIdentity struct {
	identityv1.IdentityReadServiceClient
	identityv1.IdentityAdminServiceClient
	root string
}

func (s *seatIdentity) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	return &identityv1.GetUserResponse{User: &identityv1.User{
		Id: in.GetUserId(), Enabled: true, Roles: []string{"site-admin"}, IsRoot: in.GetUserId() == s.root,
	}}, nil
}

func (s *seatIdentity) TransferRoot(_ context.Context, in *identityv1.TransferRootRequest, _ ...grpc.CallOption) (*identityv1.TransferRootResponse, error) {
	s.root = in.GetToUserId()
	return &identityv1.TransferRootResponse{User: &identityv1.User{Id: s.root, Enabled: true, IsRoot: true, Roles: []string{"site-admin"}}}, nil
}

// viewAsFreshRequest rebuilds the caller's claims from identity, then loads a
// sensitive policy the category rules do not let anyone read.
func viewAsFreshRequest(t *testing.T, id *seatIdentity, userID string) *resolvers.PolicyViewerCan {
	t.Helper()
	claims, err := bff.ClaimsForUserFromIdentity(id)(context.Background(), userID)
	if err != nil {
		t.Fatalf("claims for %s: %v", userID, err)
	}
	gc := newRaciReadClient(
		map[string]*corev1.Category{"g-it": {Id: "g-it", Name: "IT"}},
		map[string][]*corev1.CategoryRule{"g-it": nil},
	)
	pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
		"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT pol", CurrentPublishedVersionId: "pol-it-v1", Sensitivity: corev1.Sensitivity_SENSITIVITY_SENSITIVE},
	}}
	p, err := resolvers.GetPolicy(principal.WithClaims(context.Background(), claims), pc, gc, nil, nil, nil, "pol-it")
	if err != nil {
		t.Fatalf("GetPolicy as %s: %v", userID, err)
	}
	return p.ViewerCan
}

func isFullRoot(vc *resolvers.PolicyViewerCan) bool {
	return vc.Read && !vc.ContentObfuscated && !vc.CanBreakGlass && vc.Edit && vc.Submit && vc.Approve
}

func TestRootOverrideFollowsTheSeatAfterTransfer(t *testing.T) {
	id := &seatIdentity{root: "u-old"}

	if !isFullRoot(viewAsFreshRequest(t, id, "u-old")) {
		t.Fatal("before the transfer the holder must get the root override")
	}
	if isFullRoot(viewAsFreshRequest(t, id, "u-new")) {
		t.Fatal("before the transfer a site-admin who is not root must not get the root override")
	}

	out, err := resolvers.TransferRootResolver(ctxWithUser(t, "u-old"), id, "u-new", "123456")
	if err != nil {
		t.Fatalf("TransferRootResolver: %v", err)
	}
	if out.UserID != "u-new" || !out.IsRoot {
		t.Fatalf("unexpected new root: %+v", out)
	}

	if !isFullRoot(viewAsFreshRequest(t, id, "u-new")) {
		t.Error("after the transfer the new holder must get the root override")
	}
	if isFullRoot(viewAsFreshRequest(t, id, "u-old")) {
		t.Error("after the transfer the old holder must no longer get the root override")
	}
	old, _ := bff.ClaimsForUserFromIdentity(id)(context.Background(), "u-old")
	if !hasRole(old.Roles(), "site-admin") {
		t.Error("the old holder keeps site-admin")
	}
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}
