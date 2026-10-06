// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeMfaAdmin is a focused IdentityAdminServiceClient fake recording the admin
// MFA factor RPCs. All other methods panic (embedded interface) so an
// unexpected call surfaces immediately.
type fakeMfaAdmin struct {
	identityv1.IdentityAdminServiceClient // embed so unused methods are nil-call panics

	listResp *identityv1.AdminListUserFactorsResponse
	listErr  error
	lastList *identityv1.AdminListUserFactorsRequest

	removeErr  error
	lastRemove *identityv1.AdminRemoveUserFactorRequest

	renameErr  error
	lastRename *identityv1.AdminRenameUserFactorRequest
}

func (f *fakeMfaAdmin) AdminListUserFactors(_ context.Context, in *identityv1.AdminListUserFactorsRequest, _ ...grpc.CallOption) (*identityv1.AdminListUserFactorsResponse, error) {
	f.lastList = in
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResp, nil
}

func (f *fakeMfaAdmin) AdminRemoveUserFactor(_ context.Context, in *identityv1.AdminRemoveUserFactorRequest, _ ...grpc.CallOption) (*identityv1.AdminRemoveUserFactorResponse, error) {
	f.lastRemove = in
	if f.removeErr != nil {
		return nil, f.removeErr
	}
	return &identityv1.AdminRemoveUserFactorResponse{}, nil
}

func (f *fakeMfaAdmin) AdminRenameUserFactor(_ context.Context, in *identityv1.AdminRenameUserFactorRequest, _ ...grpc.CallOption) (*identityv1.AdminRenameUserFactorResponse, error) {
	f.lastRename = in
	if f.renameErr != nil {
		return nil, f.renameErr
	}
	return &identityv1.AdminRenameUserFactorResponse{}, nil
}

// Auth contexts reuse the package-shared helpers: siteAdminCtx (site-admin,
// confers UserManage — the capability the admin MFA resolvers gate on) and
// nonAdminCtx (reader-only, no user.manage).

func TestUserFactorsResolver_HappyPath(t *testing.T) {
	admin := &fakeMfaAdmin{listResp: &identityv1.AdminListUserFactorsResponse{
		Factors: []*identityv1.UserFactor{
			{Id: "totp", Kind: "totp", EnrolledAt: "2026-01-02T03:04:05Z", Label: "Phone authenticator"},
			{Id: "cred-abc", Kind: "passkey", EnrolledAt: "2026-02-02T03:04:05Z", Label: ""},
			{Id: "email", Kind: "email"},
		},
	}}
	out, err := resolvers.UserFactorsResolver(siteAdminCtx(t), admin, "target-42")
	if err != nil {
		t.Fatalf("UserFactorsResolver: %v", err)
	}
	if admin.lastList == nil || admin.lastList.GetUserId() != "target-42" {
		t.Fatalf("AdminListUserFactors got userId %v, want target-42", admin.lastList)
	}
	if len(out) != 3 {
		t.Fatalf("got %d factors, want 3", len(out))
	}
	if out[0].ID != "totp" || out[0].Kind != "totp" || out[0].Label == nil || *out[0].Label != "Phone authenticator" {
		t.Errorf("totp factor mapped wrong: %+v", out[0])
	}
	if out[0].EnrolledAt == nil || *out[0].EnrolledAt != "2026-01-02T03:04:05Z" {
		t.Errorf("totp enrolledAt mapped wrong: %+v", out[0].EnrolledAt)
	}
	// Empty label maps to nil (client default).
	if out[1].ID != "cred-abc" || out[1].Label != nil {
		t.Errorf("passkey factor mapped wrong: %+v", out[1])
	}
	// Implicit email factor: no enrolledAt.
	if out[2].ID != "email" || out[2].Kind != "email" || out[2].EnrolledAt != nil {
		t.Errorf("email factor mapped wrong: %+v", out[2])
	}
}

func TestUserFactorsResolver_NonAdminDenied(t *testing.T) {
	admin := &fakeMfaAdmin{}
	_, err := resolvers.UserFactorsResolver(nonAdminCtx(t), admin, "target-42")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v, want PermissionDenied", err)
	}
	if admin.lastList != nil {
		t.Error("identity was called despite denied authz")
	}
}

func TestUserFactorsResolver_Unauthenticated(t *testing.T) {
	admin := &fakeMfaAdmin{}
	_, err := resolvers.UserFactorsResolver(context.Background(), admin, "target-42")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v, want Unauthenticated", err)
	}
}

func TestUserFactorsResolver_NilClient(t *testing.T) {
	_, err := resolvers.UserFactorsResolver(siteAdminCtx(t), nil, "target-42")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("got %v, want Unavailable", err)
	}
}

func TestUserFactorsResolver_ErrorPassthrough(t *testing.T) {
	admin := &fakeMfaAdmin{listErr: errors.New("boom")}
	_, err := resolvers.UserFactorsResolver(siteAdminCtx(t), admin, "target-42")
	if err == nil || err.Error() != "boom" {
		t.Fatalf("got %v, want boom passthrough", err)
	}
}

func TestRemoveUserMfaFactorResolver_HappyPath(t *testing.T) {
	admin := &fakeMfaAdmin{}
	ok, err := resolvers.RemoveUserMfaFactorResolver(siteAdminCtx(t), admin, "target-42", "totp")
	if err != nil || !ok {
		t.Fatalf("RemoveUserMfaFactorResolver: ok=%v err=%v", ok, err)
	}
	if admin.lastRemove == nil || admin.lastRemove.GetUserId() != "target-42" || admin.lastRemove.GetMethodId() != "totp" {
		t.Fatalf("AdminRemoveUserFactor got %+v, want userId=target-42 methodId=totp", admin.lastRemove)
	}
}

func TestRemoveUserMfaFactorResolver_NonAdminDenied(t *testing.T) {
	admin := &fakeMfaAdmin{}
	_, err := resolvers.RemoveUserMfaFactorResolver(nonAdminCtx(t), admin, "target-42", "cred-x")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v, want PermissionDenied", err)
	}
	if admin.lastRemove != nil {
		t.Error("identity was called despite denied authz")
	}
}

func TestRemoveUserMfaFactorResolver_ErrorPassthrough(t *testing.T) {
	admin := &fakeMfaAdmin{removeErr: status.Error(codes.FailedPrecondition, "the email factor is implicit and cannot be removed")}
	_, err := resolvers.RemoveUserMfaFactorResolver(siteAdminCtx(t), admin, "target-42", "email")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition passthrough", err)
	}
}

func TestRenameUserMfaFactorResolver_HappyPath(t *testing.T) {
	admin := &fakeMfaAdmin{}
	ok, err := resolvers.RenameUserMfaFactorResolver(siteAdminCtx(t), admin, "target-42", "cred-abc", "Work YubiKey")
	if err != nil || !ok {
		t.Fatalf("RenameUserMfaFactorResolver: ok=%v err=%v", ok, err)
	}
	if admin.lastRename == nil ||
		admin.lastRename.GetUserId() != "target-42" ||
		admin.lastRename.GetMethodId() != "cred-abc" ||
		admin.lastRename.GetLabel() != "Work YubiKey" {
		t.Fatalf("AdminRenameUserFactor got %+v, want userId=target-42 methodId=cred-abc label=Work YubiKey", admin.lastRename)
	}
}

func TestRenameUserMfaFactorResolver_NonAdminDenied(t *testing.T) {
	admin := &fakeMfaAdmin{}
	_, err := resolvers.RenameUserMfaFactorResolver(nonAdminCtx(t), admin, "target-42", "totp", "x")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v, want PermissionDenied", err)
	}
	if admin.lastRename != nil {
		t.Error("identity was called despite denied authz")
	}
}

func TestRenameUserMfaFactorResolver_NilClient(t *testing.T) {
	_, err := resolvers.RenameUserMfaFactorResolver(siteAdminCtx(t), nil, "target-42", "totp", "x")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("got %v, want Unavailable", err)
	}
}
