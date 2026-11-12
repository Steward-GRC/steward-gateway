// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"
	"time"

	deliveryv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/delivery/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeMagicRegistryClient stubs the list and remove RPCs of the magic link registry (steward-gateway#71).
type fakeMagicRegistryClient struct {
	deliveryv1.DeliveryServiceClient
	listResp    *deliveryv1.ListMagicLinksResponse
	listErr     error
	lastListReq *deliveryv1.ListMagicLinksRequest
	listCalls   int

	removeResp    *deliveryv1.RemoveMagicLinkResponse
	removeErr     error
	lastRemoveReq *deliveryv1.RemoveMagicLinkRequest
	removeCalls   int
}

func (f *fakeMagicRegistryClient) ListMagicLinks(_ context.Context, in *deliveryv1.ListMagicLinksRequest, _ ...grpc.CallOption) (*deliveryv1.ListMagicLinksResponse, error) {
	f.listCalls++
	f.lastListReq = in
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResp, nil
}

func (f *fakeMagicRegistryClient) RemoveMagicLink(_ context.Context, in *deliveryv1.RemoveMagicLinkRequest, _ ...grpc.CallOption) (*deliveryv1.RemoveMagicLinkResponse, error) {
	f.removeCalls++
	f.lastRemoveReq = in
	if f.removeErr != nil {
		return nil, f.removeErr
	}
	return f.removeResp, nil
}

func TestListMagicLinksMapsFieldsAndStatuses(t *testing.T) {
	created := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	expires := created.Add(72 * time.Hour)
	revoked := created.Add(time.Hour)
	client := &fakeMagicRegistryClient{listResp: &deliveryv1.ListMagicLinksResponse{
		Links: []*deliveryv1.MagicLinkInfo{
			{Token: "tok-a", Fingerprint: "fp-a", PolicyVersionId: "pv-1", CreatedByUserId: "u-1", Sensitive: true,
				Status: "active", CreatedAt: timestamppb.New(created), ExpiresAt: timestamppb.New(expires)},
			{Token: "tok-b", Fingerprint: "fp-b", PolicyVersionId: "pv-2", CreatedByUserId: "u-2",
				Status: "revoked", CreatedAt: timestamppb.New(created), ExpiresAt: timestamppb.New(expires),
				RevokedAt: timestamppb.New(revoked), RevokedByUserId: "u-3"},
			{Token: "tok-c", Fingerprint: "fp-c", PolicyVersionId: "pv-2", CreatedByUserId: "u-2",
				Status: "expired", CreatedAt: timestamppb.New(created), ExpiresAt: timestamppb.New(expires)},
		},
		NextPageToken: "next-1",
	}}
	got, err := resolvers.ListMagicLinksResolver(siteAdminCtx(t), client, []string{"pv-1", "pv-2"}, nil, nil)
	if err != nil {
		t.Fatalf("ListMagicLinksResolver: %v", err)
	}
	if len(got.Links) != 3 {
		t.Fatalf("links = %d, want 3", len(got.Links))
	}
	a := got.Links[0]
	if a.Token != "tok-a" || a.Fingerprint != "fp-a" || a.PolicyVersionID != "pv-1" || a.CreatedByUserID != "u-1" ||
		!a.Sensitive || a.Status != "active" || a.CreatedAt != "2026-11-01T09:00:00Z" || a.ExpiresAt != "2026-11-04T09:00:00Z" {
		t.Fatalf("active link mapped wrong: %+v", a)
	}
	if a.RevokedAt != nil || a.RevokedByUserID != nil {
		t.Fatalf("active link must have null revoked fields: %+v", a)
	}
	b := got.Links[1]
	if b.Status != "revoked" || b.RevokedAt == nil || *b.RevokedAt != "2026-11-01T10:00:00Z" ||
		b.RevokedByUserID == nil || *b.RevokedByUserID != "u-3" {
		t.Fatalf("revoked link mapped wrong: %+v", b)
	}
	if got.Links[2].Status != "expired" {
		t.Fatalf("status = %q, want expired", got.Links[2].Status)
	}
	if got.NextPageToken == nil || *got.NextPageToken != "next-1" {
		t.Fatalf("nextPageToken = %v, want next-1", got.NextPageToken)
	}
	if ids := client.lastListReq.GetPolicyVersionIds(); len(ids) != 2 || ids[0] != "pv-1" || ids[1] != "pv-2" {
		t.Fatalf("policy_version_ids not forwarded: %v", ids)
	}
}

func TestListMagicLinksLastPageHasNullToken(t *testing.T) {
	client := &fakeMagicRegistryClient{listResp: &deliveryv1.ListMagicLinksResponse{}}
	got, err := resolvers.ListMagicLinksResolver(siteAdminCtx(t), client, nil, nil, nil)
	if err != nil {
		t.Fatalf("ListMagicLinksResolver: %v", err)
	}
	if got.NextPageToken != nil || got.Links == nil || len(got.Links) != 0 {
		t.Fatalf("want empty non-nil links and null token, got %+v", got)
	}
}

func TestListMagicLinksPassesPagingThrough(t *testing.T) {
	client := &fakeMagicRegistryClient{listResp: &deliveryv1.ListMagicLinksResponse{}}
	size, token := 25, "page-2"
	if _, err := resolvers.ListMagicLinksResolver(siteAdminCtx(t), client, nil, &size, &token); err != nil {
		t.Fatalf("ListMagicLinksResolver: %v", err)
	}
	if client.lastListReq.GetPageSize() != 25 || client.lastListReq.GetPageToken() != "page-2" {
		t.Fatalf("paging not forwarded: %+v", client.lastListReq)
	}
}

func TestListMagicLinksRequiresSiteAdmin(t *testing.T) {
	client := &fakeMagicRegistryClient{listResp: &deliveryv1.ListMagicLinksResponse{}}
	_, err := resolvers.ListMagicLinksResolver(ctxWithRoles(t, "u", []string{"author"}), client, nil, nil, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.listCalls != 0 {
		t.Fatalf("delivery must not be called for a non-admin")
	}
}

func TestListMagicLinksUnauthenticated(t *testing.T) {
	client := &fakeMagicRegistryClient{listResp: &deliveryv1.ListMagicLinksResponse{}}
	if _, err := resolvers.ListMagicLinksResolver(context.Background(), client, nil, nil, nil); err == nil {
		t.Fatalf("expected an error without claims")
	}
	if client.listCalls != 0 {
		t.Fatalf("delivery must not be called without claims")
	}
}

func TestListMagicLinksRelaysBadPageToken(t *testing.T) {
	rpcErr := status.Error(codes.InvalidArgument, "bad page token")
	client := &fakeMagicRegistryClient{listErr: rpcErr}
	token := "garbage"
	_, err := resolvers.ListMagicLinksResolver(siteAdminCtx(t), client, nil, nil, &token)
	if err != rpcErr {
		t.Fatalf("delivery error must be relayed untouched, got %v", err)
	}
}

func TestRemoveMagicLinkHappyPath(t *testing.T) {
	client := &fakeMagicRegistryClient{removeResp: &deliveryv1.RemoveMagicLinkResponse{Removed: true}}
	got, err := resolvers.RemoveMagicLinkResolver(siteAdminCtx(t), client, "tok-b")
	if err != nil || !got {
		t.Fatalf("RemoveMagicLinkResolver = %v, %v; want true, nil", got, err)
	}
	if client.lastRemoveReq.GetToken() != "tok-b" || client.lastRemoveReq.GetRemovedByUserId() != "admin-1" {
		t.Fatalf("token or removed_by_user_id not bound: %+v", client.lastRemoveReq)
	}
}

func TestRemoveMagicLinkRequiresSiteAdmin(t *testing.T) {
	client := &fakeMagicRegistryClient{removeResp: &deliveryv1.RemoveMagicLinkResponse{Removed: true}}
	_, err := resolvers.RemoveMagicLinkResolver(ctxWithRoles(t, "u", []string{"author"}), client, "tok")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if client.removeCalls != 0 {
		t.Fatalf("delivery must not be called for a non-admin")
	}
}

func TestRemoveMagicLinkUnauthenticated(t *testing.T) {
	client := &fakeMagicRegistryClient{removeResp: &deliveryv1.RemoveMagicLinkResponse{Removed: true}}
	if _, err := resolvers.RemoveMagicLinkResolver(context.Background(), client, "tok"); err == nil {
		t.Fatalf("expected an error without claims")
	}
	if client.removeCalls != 0 {
		t.Fatalf("delivery must not be called without claims")
	}
}

func TestRemoveMagicLinkRelaysDeliveryErrors(t *testing.T) {
	for name, rpcErr := range map[string]error{
		"MAGIC_LINK_ACTIVE":    status.Error(codes.FailedPrecondition, "MAGIC_LINK_ACTIVE"),
		"MAGIC_LINK_NOT_FOUND": status.Error(codes.NotFound, "MAGIC_LINK_NOT_FOUND"),
	} {
		client := &fakeMagicRegistryClient{removeErr: rpcErr}
		got, err := resolvers.RemoveMagicLinkResolver(siteAdminCtx(t), client, "tok")
		if err != rpcErr || got {
			t.Fatalf("%s: want the delivery error untouched and false, got %v, %v", name, got, err)
		}
	}
}
