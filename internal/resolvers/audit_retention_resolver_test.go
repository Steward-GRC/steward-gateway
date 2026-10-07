// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"
	"time"

	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeRetentionClient struct {
	auditv1.AuditServiceClient
	shredReq   *auditv1.ShredSubjectRequest
	createReq  *auditv1.CreateLegalHoldRequest
	listReq    *auditv1.ListLegalHoldsRequest
	releaseReq *auditv1.ReleaseLegalHoldRequest
	hold       *auditv1.LegalHold
	err        error
}

func (f *fakeRetentionClient) ShredSubject(_ context.Context, in *auditv1.ShredSubjectRequest, _ ...grpc.CallOption) (*auditv1.ShredSubjectResponse, error) {
	f.shredReq = in
	if f.err != nil {
		return nil, f.err
	}
	return &auditv1.ShredSubjectResponse{RecordsTombstoned: 3, RecordId: 9001}, nil
}

func (f *fakeRetentionClient) CreateLegalHold(_ context.Context, in *auditv1.CreateLegalHoldRequest, _ ...grpc.CallOption) (*auditv1.CreateLegalHoldResponse, error) {
	f.createReq = in
	return &auditv1.CreateLegalHoldResponse{Hold: f.hold}, f.err
}

func (f *fakeRetentionClient) ListLegalHolds(_ context.Context, in *auditv1.ListLegalHoldsRequest, _ ...grpc.CallOption) (*auditv1.ListLegalHoldsResponse, error) {
	f.listReq = in
	return &auditv1.ListLegalHoldsResponse{Holds: []*auditv1.LegalHold{f.hold}}, f.err
}

func (f *fakeRetentionClient) ReleaseLegalHold(_ context.Context, in *auditv1.ReleaseLegalHoldRequest, _ ...grpc.CallOption) (*auditv1.ReleaseLegalHoldResponse, error) {
	f.releaseReq = in
	return &auditv1.ReleaseLegalHoldResponse{Hold: f.hold}, f.err
}

func sampleHold(released bool) *auditv1.LegalHold {
	h := &auditv1.LegalHold{
		HoldUuid: "hold-1", SubjectFilter: "policy:POL-000001", GroupFilter: "g-1", Reason: "litigation",
		HeldBy: "u-compliance", CreatedAt: timestamppb.New(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)),
	}
	if released {
		h.ReleasedAt = timestamppb.New(time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC))
	}
	return h
}

func complianceCtx(t *testing.T) context.Context {
	t.Helper()
	return ctxWithRoles(t, "u-compliance", []string{"compliance-admin"})
}

func TestShredAuditSubjectForwardsTheRequestAndRequester(t *testing.T) {
	client := &fakeRetentionClient{}
	out, err := resolvers.ShredAuditSubjectResolver(complianceCtx(t), client, "subject-key-1", "erasure request")
	if err != nil {
		t.Fatalf("ShredAuditSubject: %v", err)
	}
	if out.RecordsTombstoned != 3 || out.RecordID != "9001" {
		t.Fatalf("result=%+v", out)
	}
	r := client.shredReq
	if r.GetSubjectKey() != "subject-key-1" || r.GetReason() != "erasure request" || r.GetRequester().GetUserId() != "u-compliance" {
		t.Fatalf("request=%+v", r)
	}
}

func TestCreateAuditLegalHoldForwardsFiltersAndMapsTheHold(t *testing.T) {
	client := &fakeRetentionClient{hold: sampleHold(false)}
	subject, group := "policy:POL-000001", "g-1"
	out, err := resolvers.CreateAuditLegalHoldResolver(complianceCtx(t), client, &subject, &group, "litigation")
	if err != nil {
		t.Fatalf("CreateAuditLegalHold: %v", err)
	}
	r := client.createReq
	if r.GetSubjectFilter() != subject || r.GetGroupFilter() != group || r.GetReason() != "litigation" || r.GetRequester().GetUserId() != "u-compliance" {
		t.Fatalf("request=%+v", r)
	}
	if out.HoldUUID != "hold-1" || out.HeldBy != "u-compliance" || out.CreatedAt != "2026-09-01T12:00:00Z" || out.ReleasedAt != nil {
		t.Fatalf("hold=%+v", out)
	}
}

func TestCreateAuditLegalHoldSendsEmptyFiltersWhenUnset(t *testing.T) {
	client := &fakeRetentionClient{hold: sampleHold(false)}
	if _, err := resolvers.CreateAuditLegalHoldResolver(complianceCtx(t), client, nil, nil, "freeze everything"); err != nil {
		t.Fatalf("CreateAuditLegalHold: %v", err)
	}
	if client.createReq.GetSubjectFilter() != "" || client.createReq.GetGroupFilter() != "" {
		t.Fatalf("request=%+v", client.createReq)
	}
}

func TestAuditLegalHoldsListsAndReleaseMapsReleasedAt(t *testing.T) {
	client := &fakeRetentionClient{hold: sampleHold(true)}
	include := true
	holds, err := resolvers.AuditLegalHoldsResolver(complianceCtx(t), client, &include)
	if err != nil {
		t.Fatalf("AuditLegalHolds: %v", err)
	}
	if !client.listReq.GetIncludeReleased() || len(holds) != 1 || holds[0].ReleasedAt == nil || *holds[0].ReleasedAt != "2026-09-02T12:00:00Z" {
		t.Fatalf("request=%+v holds=%+v", client.listReq, holds)
	}
	out, err := resolvers.ReleaseAuditLegalHoldResolver(complianceCtx(t), client, "hold-1")
	if err != nil {
		t.Fatalf("ReleaseAuditLegalHold: %v", err)
	}
	if client.releaseReq.GetHoldUuid() != "hold-1" || client.releaseReq.GetRequester().GetUserId() != "u-compliance" || out.ReleasedAt == nil {
		t.Fatalf("request=%+v hold=%+v", client.releaseReq, out)
	}
}

func TestRetentionResolversNeedComplianceManage(t *testing.T) {
	client := &fakeRetentionClient{hold: sampleHold(false)}
	for _, roles := range [][]string{{"reader"}, {"template-admin"}, {"approver"}} {
		ctx := ctxWithRoles(t, "u", roles)
		if _, err := resolvers.ShredAuditSubjectResolver(ctx, client, "k", "r"); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%v shred: want PermissionDenied, got %v", roles, err)
		}
		if _, err := resolvers.CreateAuditLegalHoldResolver(ctx, client, nil, nil, "r"); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%v create: want PermissionDenied, got %v", roles, err)
		}
		if _, err := resolvers.AuditLegalHoldsResolver(ctx, client, nil); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%v list: want PermissionDenied, got %v", roles, err)
		}
		if _, err := resolvers.ReleaseAuditLegalHoldResolver(ctx, client, "hold-1"); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%v release: want PermissionDenied, got %v", roles, err)
		}
	}
	if client.shredReq != nil || client.createReq != nil || client.listReq != nil || client.releaseReq != nil {
		t.Fatal("audit was called for a caller without compliance.manage")
	}
	if _, err := resolvers.ShredAuditSubjectResolver(context.Background(), client, "k", "r"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("signed out: want Unauthenticated, got %v", err)
	}
}

func TestRetentionResolversPassAuditErrorsThrough(t *testing.T) {
	client := &fakeRetentionClient{err: status.Error(codes.NotFound, "no such hold")}
	if _, err := resolvers.ReleaseAuditLegalHoldResolver(complianceCtx(t), client, "missing"); status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound, got %v", err)
	}
}
