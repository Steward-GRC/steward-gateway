// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// DeletePolicyAppendix behaves as core does: only a retired appendix is removed
// (FailedPrecondition for a live one, NotFound for an unknown id), and the
// request is kept so a test can read the actor it carried.
func (c *appendixCore) DeletePolicyAppendix(_ context.Context, in *corev1.DeletePolicyAppendixRequest, _ ...grpc.CallOption) (*corev1.DeletePolicyAppendixResponse, error) {
	c.writes++
	c.deletes = append(c.deletes, in)
	a, err := c.find(in.GetId())
	if err != nil {
		return nil, err
	}
	if !a.retired {
		return nil, status.Error(codes.FailedPrecondition, "only a retired appendix can be deleted")
	}
	c.list = slices.DeleteFunc(c.list, func(o *fakeAppendix) bool { return o == a })
	return &corev1.DeletePolicyAppendixResponse{}, nil
}

// Deleting for good (#142). Each test names the mock server test it ports
// (steward-mock-server src/product/appendices.test.ts).

// mock: "refuses an author deleting for good, which is the site admin's"
func TestDeleteAppendixForever_RefusesAnAuthor(t *testing.T) {
	e := newApxEnv(t)
	if _, err := e.r.Mutation().RetireAppendix(apxCtx(t, "bob"), apxSeeded); err != nil {
		t.Fatalf("retireAppendix: %v", err)
	}
	writes := e.core.writes
	ok, err := e.r.Mutation().DeleteAppendixForever(apxCtx(t, "bob"), apxSeeded)
	if status.Code(err) != codes.PermissionDenied || ok {
		t.Fatalf("author: ok=%v err=%v, want PermissionDenied", ok, err)
	}
	if e.core.writes != writes || len(e.core.deletes) != 0 {
		t.Fatal("core must not be called for an author")
	}
	if len(e.list(t, "bob", true)) != 1 {
		t.Fatal("the appendix must still be there")
	}
}

func TestDeleteAppendixForever_RefusesAReaderAndNoUser(t *testing.T) {
	e := newApxEnv(t)
	if ok, err := e.r.Mutation().DeleteAppendixForever(apxCtx(t, "erin"), apxSeeded); status.Code(err) != codes.PermissionDenied || ok {
		t.Fatalf("reader: ok=%v err=%v, want PermissionDenied", ok, err)
	}
	if ok, err := e.r.Mutation().DeleteAppendixForever(context.Background(), apxSeeded); status.Code(err) != codes.Unauthenticated || ok {
		t.Fatalf("no user: ok=%v err=%v, want Unauthenticated", ok, err)
	}
	if len(e.core.deletes) != 0 {
		t.Fatal("core must not be called")
	}
}

// mock: "lets a site admin delete a retired appendix for good, history and all"
func TestDeleteAppendixForever_SiteAdminDeletesARetiredAppendix(t *testing.T) {
	e := newApxEnv(t)
	if _, err := e.r.Mutation().RetireAppendix(apxCtx(t, "bob"), apxSeeded); err != nil {
		t.Fatalf("retireAppendix: %v", err)
	}
	ok, err := e.r.Mutation().DeleteAppendixForever(apxCtx(t, "sam"), apxSeeded)
	if err != nil || !ok {
		t.Fatalf("site admin: ok=%v err=%v, want true", ok, err)
	}
	if len(e.core.deletes) != 1 || e.core.deletes[0].GetId() != apxSeeded || e.core.deletes[0].GetActorUserId() != "sam" {
		t.Fatalf("core was sent %v, want the id and the actor sam", e.core.deletes)
	}
	if len(e.list(t, "sam", true)) != 0 {
		t.Fatal("the appendix must be gone, retired ones included")
	}
}

// A live appendix is refused: it has to be retired first.
func TestDeleteAppendixForever_RefusesALiveAppendix(t *testing.T) {
	e := newApxEnv(t)
	ok, err := e.r.Mutation().DeleteAppendixForever(apxCtx(t, "sam"), apxSeeded)
	st, _ := status.FromError(err)
	if ok || st.Code() != codes.FailedPrecondition || st.Message() != "Retire the appendix first; only a retired appendix can be deleted for good." {
		t.Fatalf("live: ok=%v err=%v, want the retire-first refusal", ok, err)
	}
	if len(e.list(t, "sam", false)) != 1 {
		t.Fatal("the live appendix must still be there")
	}
}

func TestDeleteAppendixForever_UnknownIDIsNotFound(t *testing.T) {
	e := newApxEnv(t)
	ok, err := e.r.Mutation().DeleteAppendixForever(apxCtx(t, "sam"), "nope")
	st, _ := status.FromError(err)
	if ok || st.Code() != codes.NotFound || st.Message() != "appendix not found" {
		t.Fatalf("unknown id: ok=%v err=%v, want NotFound", ok, err)
	}
}

func TestDeleteAppendixForever_NoCoreClientIsUnavailable(t *testing.T) {
	e := newApxEnv(t)
	e.r.PolicyAppendixClient = nil
	if _, err := e.r.Mutation().DeleteAppendixForever(apxCtx(t, "sam"), apxSeeded); status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}
