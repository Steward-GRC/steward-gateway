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
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeAuditClient stubs auditv1.AuditServiceClient.
type fakeAuditClient struct {
	auditv1.AuditServiceClient
	queryResp    *auditv1.QueryAuditLogResponse
	queryErr     error
	lastQueryReq *auditv1.QueryAuditLogRequest

	exportResp    *auditv1.ExportAuditSegmentResponse
	exportErr     error
	lastExportReq *auditv1.ExportAuditSegmentRequest

	verifyResp    *auditv1.VerifyAuditChainResponse
	verifyErr     error
	lastVerifyReq *auditv1.VerifyAuditChainRequest
}

func (f *fakeAuditClient) QueryAuditLog(_ context.Context, in *auditv1.QueryAuditLogRequest, _ ...grpc.CallOption) (*auditv1.QueryAuditLogResponse, error) {
	f.lastQueryReq = in
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return f.queryResp, nil
}

func (f *fakeAuditClient) ExportAuditSegment(_ context.Context, in *auditv1.ExportAuditSegmentRequest, _ ...grpc.CallOption) (*auditv1.ExportAuditSegmentResponse, error) {
	f.lastExportReq = in
	if f.exportErr != nil {
		return nil, f.exportErr
	}
	return f.exportResp, nil
}

func (f *fakeAuditClient) VerifyAuditChain(_ context.Context, in *auditv1.VerifyAuditChainRequest, _ ...grpc.CallOption) (*auditv1.VerifyAuditChainResponse, error) {
	f.lastVerifyReq = in
	if f.verifyErr != nil {
		return nil, f.verifyErr
	}
	return f.verifyResp, nil
}

func TestQueryAuditLogForwardsFilters(t *testing.T) {
	occurred := time.Date(2026, 5, 15, 9, 30, 0, 0, time.UTC)
	client := &fakeAuditClient{
		queryResp: &auditv1.QueryAuditLogResponse{
			Records: []*auditv1.AuditRecord{
				{
					Id:               12345,
					RecordUuid:       "rec-uuid-1",
					Tier:             "audit",
					Action:           "policy.published",
					ActorUserId:      "u-9",
					Subject:          "policy:p-1",
					GroupId:          "g-1",
					OccurredAt:       timestamppb.New(occurred),
					PrevHash:         "0xprev",
					RecordHash:       "0xrec",
					LegalBasisExempt: false,
				},
			},
			NextPageToken: "12345",
		},
	}
	tier := "audit"
	groupID := "g-1"
	actor := "u-9"
	pageSize := 25
	out, err := resolvers.QueryAuditLogResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), client,
		nil, nil, nil, nil,
		&tier, &groupID, &actor, nil, &pageSize, nil)
	if err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	if len(out.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(out.Records))
	}
	rec := out.Records[0]
	// Id is int64 in the proto but rendered as a String at the GraphQL
	// surface to avoid 32-bit-int truncation on JS clients. Assertion
	// guards against the proto field accidentally riding through as an int.
	if rec.ID != "12345" {
		t.Fatalf("record id: got %q want %q", rec.ID, "12345")
	}
	if rec.OccurredAt != "2026-05-15T09:30:00Z" {
		t.Fatalf("occurred_at: got %q", rec.OccurredAt)
	}
	if out.NextPageToken != "12345" {
		t.Fatalf("next page token: got %q", out.NextPageToken)
	}
	if client.lastQueryReq.Tier != "audit" || client.lastQueryReq.GroupId != "g-1" {
		t.Fatalf("filter fields not forwarded: %+v", client.lastQueryReq)
	}
	if client.lastQueryReq.PageSize != 25 {
		t.Fatalf("page size: got %d", client.lastQueryReq.PageSize)
	}
}

func TestQueryAuditLogUnauthenticated(t *testing.T) {
	client := &fakeAuditClient{}
	_, err := resolvers.QueryAuditLogResolver(context.Background(), client,
		nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastQueryReq != nil {
		t.Fatal("audit query should not be invoked without claims")
	}
}

func TestExportAuditSegmentParsesRecordIDs(t *testing.T) {
	anchored := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	client := &fakeAuditClient{
		exportResp: &auditv1.ExportAuditSegmentResponse{
			Records: []*auditv1.AuditRecord{
				{Id: 100, RecordUuid: "u100"},
				{Id: 101, RecordUuid: "u101"},
			},
			Checkpoints: []*auditv1.Checkpoint{
				{
					CheckpointUuid: "cp-1",
					MerkleRoot:     "0xroot",
					AnchorType:     "tsa",
					AnchorUrl:      "https://tsa.example/token",
					TsaToken:       []byte{0x01, 0x02, 0x03},
					AnchoredAt:     timestamppb.New(anchored),
				},
			},
		},
	}
	out, err := resolvers.ExportAuditSegmentResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), client, "100", "200")
	if err != nil {
		t.Fatalf("ExportAuditSegment: %v", err)
	}
	if client.lastExportReq.FromRecordId != 100 || client.lastExportReq.ToRecordId != 200 {
		t.Fatalf("ids not parsed correctly: %+v", client.lastExportReq)
	}
	if len(out.Records) != 2 || out.Records[0].ID != "100" {
		t.Fatalf("records: %+v", out.Records)
	}
	if len(out.Checkpoints) != 1 {
		t.Fatalf("expected 1 checkpoint")
	}
	// TSA token bytes must be base64-encoded for transit (no Bytes scalar in
	// this schema). "AQID" = base64(0x01,0x02,0x03).
	if out.Checkpoints[0].TsaToken != "AQID" {
		t.Fatalf("tsa token encoding: got %q want %q", out.Checkpoints[0].TsaToken, "AQID")
	}
}

func TestExportAuditSegmentRejectsBadRecordID(t *testing.T) {
	client := &fakeAuditClient{}
	_, err := resolvers.ExportAuditSegmentResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), client, "not-a-number", "200")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if client.lastExportReq != nil {
		t.Fatal("export should not be invoked when ids are unparseable")
	}
}

func TestVerifyAuditChain(t *testing.T) {
	client := &fakeAuditClient{
		verifyResp: &auditv1.VerifyAuditChainResponse{
			Valid:          false,
			RecordsChecked: 50,
			Errors:         []string{"hash mismatch at id=37"},
		},
	}
	out, err := resolvers.VerifyAuditChainResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), client, nil, "1", "100")
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if out.Valid || out.RecordsChecked != 50 {
		t.Fatalf("verdict: %+v", out)
	}
	if len(out.Errors) != 1 || out.Errors[0] != "hash mismatch at id=37" {
		t.Fatalf("errors: %+v", out.Errors)
	}
}
