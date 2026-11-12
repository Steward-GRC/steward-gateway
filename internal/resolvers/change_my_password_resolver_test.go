// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// fakeReadWithChangePassword answers identity's ChangeMyPassword and records
// the request (steward-gateway#72).
type fakeReadWithChangePassword struct {
	fakeReadClient

	err  error
	last *identityv1.ChangeMyPasswordRequest
}

func (f *fakeReadWithChangePassword) ChangeMyPassword(_ context.Context, in *identityv1.ChangeMyPasswordRequest, _ ...grpc.CallOption) (*identityv1.ChangeMyPasswordResponse, error) {
	f.last = in
	if f.err != nil {
		return nil, f.err
	}
	return &identityv1.ChangeMyPasswordResponse{}, nil
}

func TestChangeMyPasswordNilClient(t *testing.T) {
	_, err := resolvers.ChangeMyPasswordResolver(context.Background(), log.Nop(), nil, "old", "new")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", status.Code(err))
	}
}

func TestChangeMyPasswordRequiresBothPasswords(t *testing.T) {
	read := &fakeReadWithChangePassword{}
	for _, c := range [][2]string{{"", "new"}, {"old", ""}} {
		_, err := resolvers.ChangeMyPasswordResolver(ctxWithUser(t, "u-me"), log.Nop(), read, c[0], c[1])
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%q/%q: expected InvalidArgument, got %v", c[0], c[1], err)
		}
	}
	if read.last != nil {
		t.Fatal("identity must not be called with an empty password")
	}
}

func TestChangeMyPasswordForwardsBothPasswords(t *testing.T) {
	read := &fakeReadWithChangePassword{}
	ok, err := resolvers.ChangeMyPasswordResolver(ctxWithUser(t, "u-me"), log.Nop(), read, "old-pw", "new-pw")
	if err != nil || !ok {
		t.Fatalf("got %v, %v", ok, err)
	}
	if read.last.GetCurrentPassword() != "old-pw" || read.last.GetNewPassword() != "new-pw" {
		t.Errorf("request not forwarded as given")
	}
}

func TestChangeMyPasswordRelaysIdentityErrorUntouched(t *testing.T) {
	want := status.Error(codes.PermissionDenied, "The current password is wrong.")
	read := &fakeReadWithChangePassword{err: want}
	ok, err := resolvers.ChangeMyPasswordResolver(ctxWithUser(t, "u-me"), log.Nop(), read, "old", "new")
	if ok || !errors.Is(err, want) {
		t.Fatalf("expected the identity error untouched, got %v, %v", ok, err)
	}
}
