// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeAckClient is an in-package stub of obligationsv1.AckServiceClient. It
// captures the last request per method so tests can assert that the gateway
// binds the user from claims rather than from input.
type fakeAckClient struct {
	obligationsv1.AckServiceClient
	recordResp    *obligationsv1.RecordAckResponse
	recordErr     error
	lastRecordReq *obligationsv1.RecordAckRequest

	statusResp    *obligationsv1.GetAckStatusResponse
	statusErr     error
	lastStatusReq *obligationsv1.GetAckStatusRequest
}

func (f *fakeAckClient) RecordAck(_ context.Context, in *obligationsv1.RecordAckRequest, _ ...grpc.CallOption) (*obligationsv1.RecordAckResponse, error) {
	f.lastRecordReq = in
	if f.recordErr != nil {
		return nil, f.recordErr
	}
	return f.recordResp, nil
}

func (f *fakeAckClient) GetAckStatus(_ context.Context, in *obligationsv1.GetAckStatusRequest, _ ...grpc.CallOption) (*obligationsv1.GetAckStatusResponse, error) {
	f.lastStatusReq = in
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return f.statusResp, nil
}

func (f *fakeAckClient) RecordView(_ context.Context, _ *obligationsv1.RecordViewRequest, _ ...grpc.CallOption) (*obligationsv1.RecordViewResponse, error) {
	return &obligationsv1.RecordViewResponse{}, nil
}

// TransferAcknowledgments satisfies the interface (added in contracts v1.3.0).
// The gateway exposes no resolver for it -- it is a server-to-server
// account-merge RPC -- so the stub is never exercised.
func (f *fakeAckClient) TransferAcknowledgments(_ context.Context, _ *obligationsv1.TransferAcknowledgmentsRequest, _ ...grpc.CallOption) (*obligationsv1.TransferAcknowledgmentsResponse, error) {
	return &obligationsv1.TransferAcknowledgmentsResponse{}, nil
}

// fakeNotifPrefClient stubs NotifPrefServiceClient.
type fakeNotifPrefClient struct {
	obligationsv1.NotifPrefServiceClient
	upsertResp    *obligationsv1.UpsertNotifPrefResponse
	upsertErr     error
	lastUpsertReq *obligationsv1.UpsertNotifPrefRequest

	getResp    *obligationsv1.GetNotifPrefResponse
	getErr     error
	lastGetReq *obligationsv1.GetNotifPrefRequest

	settingsResp *obligationsv1.GetNotificationSettingsResponse
	settingsErr  error

	setCatResp    *obligationsv1.SetCategoryCadenceResponse
	setCatErr     error
	lastSetCatReq *obligationsv1.SetCategoryCadenceRequest

	setTypeResp    *obligationsv1.SetTypeCadenceResponse
	setTypeErr     error
	lastSetTypeReq *obligationsv1.SetTypeCadenceRequest

	setDigestResp    *obligationsv1.SetDigestWindowResponse
	setDigestErr     error
	lastSetDigestReq *obligationsv1.SetDigestWindowRequest

	listTypesResp  *obligationsv1.ListNotifTypesResponse
	listTypesErr   error
	listTypesCalls int
}

func (f *fakeNotifPrefClient) UpsertNotifPref(_ context.Context, in *obligationsv1.UpsertNotifPrefRequest, _ ...grpc.CallOption) (*obligationsv1.UpsertNotifPrefResponse, error) {
	f.lastUpsertReq = in
	if f.upsertErr != nil {
		return nil, f.upsertErr
	}
	return f.upsertResp, nil
}

func (f *fakeNotifPrefClient) GetNotifPref(_ context.Context, in *obligationsv1.GetNotifPrefRequest, _ ...grpc.CallOption) (*obligationsv1.GetNotifPrefResponse, error) {
	f.lastGetReq = in
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getResp, nil
}

func (f *fakeNotifPrefClient) GetNotificationSettings(_ context.Context, _ *obligationsv1.GetNotificationSettingsRequest, _ ...grpc.CallOption) (*obligationsv1.GetNotificationSettingsResponse, error) {
	if f.settingsErr != nil {
		return nil, f.settingsErr
	}
	return f.settingsResp, nil
}

func (f *fakeNotifPrefClient) SetCategoryCadence(_ context.Context, in *obligationsv1.SetCategoryCadenceRequest, _ ...grpc.CallOption) (*obligationsv1.SetCategoryCadenceResponse, error) {
	f.lastSetCatReq = in
	if f.setCatErr != nil {
		return nil, f.setCatErr
	}
	return f.setCatResp, nil
}

func (f *fakeNotifPrefClient) SetTypeCadence(_ context.Context, in *obligationsv1.SetTypeCadenceRequest, _ ...grpc.CallOption) (*obligationsv1.SetTypeCadenceResponse, error) {
	f.lastSetTypeReq = in
	if f.setTypeErr != nil {
		return nil, f.setTypeErr
	}
	return f.setTypeResp, nil
}

func (f *fakeNotifPrefClient) SetDigestWindow(_ context.Context, in *obligationsv1.SetDigestWindowRequest, _ ...grpc.CallOption) (*obligationsv1.SetDigestWindowResponse, error) {
	f.lastSetDigestReq = in
	if f.setDigestErr != nil {
		return nil, f.setDigestErr
	}
	return f.setDigestResp, nil
}

func (f *fakeNotifPrefClient) ListNotifTypes(_ context.Context, _ *obligationsv1.ListNotifTypesRequest, _ ...grpc.CallOption) (*obligationsv1.ListNotifTypesResponse, error) {
	f.listTypesCalls++
	if f.listTypesErr != nil {
		return nil, f.listTypesErr
	}
	return f.listTypesResp, nil
}

// fakeObligationClient stubs ObligationServiceClient.
type fakeObligationClient struct {
	obligationsv1.ObligationServiceClient
	myObligationsResp    *obligationsv1.GetMyObligationsResponse
	myObligationsErr     error
	lastMyObligationsReq *obligationsv1.GetMyObligationsRequest

	audienceCountResp    *obligationsv1.GetObligatedAudienceCountResponse
	audienceCountErr     error
	lastAudienceCountReq *obligationsv1.GetObligatedAudienceCountRequest

	ackSummaryResp    *obligationsv1.MyAckSummaryResponse
	ackSummaryErr     error
	lastAckSummaryReq *obligationsv1.MyAckSummaryRequest
}

func (f *fakeObligationClient) MyAckSummary(_ context.Context, in *obligationsv1.MyAckSummaryRequest, _ ...grpc.CallOption) (*obligationsv1.MyAckSummaryResponse, error) {
	f.lastAckSummaryReq = in
	if f.ackSummaryErr != nil {
		return nil, f.ackSummaryErr
	}
	return f.ackSummaryResp, nil
}

func (f *fakeObligationClient) GetMyObligations(_ context.Context, in *obligationsv1.GetMyObligationsRequest, _ ...grpc.CallOption) (*obligationsv1.GetMyObligationsResponse, error) {
	f.lastMyObligationsReq = in
	if f.myObligationsErr != nil {
		return nil, f.myObligationsErr
	}
	return f.myObligationsResp, nil
}

func (f *fakeObligationClient) GetObligatedAudienceCount(_ context.Context, in *obligationsv1.GetObligatedAudienceCountRequest, _ ...grpc.CallOption) (*obligationsv1.GetObligatedAudienceCountResponse, error) {
	f.lastAudienceCountReq = in
	if f.audienceCountErr != nil {
		return nil, f.audienceCountErr
	}
	return f.audienceCountResp, nil
}

// fakeReportingClient stubs ReportingServiceClient.
type fakeReportingClient struct {
	obligationsv1.ReportingServiceClient
	reportResp *obligationsv1.GetCompletionReportResponse
	reportErr  error

	exportResp *obligationsv1.ExportAcksResponse
	exportErr  error

	roster    *obligationsv1.GetAckRosterResponse
	rosterErr error

	activity    *obligationsv1.GetAckActivityResponse
	activityErr error
}

func (f *fakeReportingClient) GetCompletionReport(_ context.Context, _ *obligationsv1.GetCompletionReportRequest, _ ...grpc.CallOption) (*obligationsv1.GetCompletionReportResponse, error) {
	if f.reportErr != nil {
		return nil, f.reportErr
	}
	return f.reportResp, nil
}

func (f *fakeReportingClient) ExportAcks(_ context.Context, _ *obligationsv1.ExportAcksRequest, _ ...grpc.CallOption) (*obligationsv1.ExportAcksResponse, error) {
	if f.exportErr != nil {
		return nil, f.exportErr
	}
	return f.exportResp, nil
}

func (f *fakeReportingClient) GetAckRoster(_ context.Context, _ *obligationsv1.GetAckRosterRequest, _ ...grpc.CallOption) (*obligationsv1.GetAckRosterResponse, error) {
	if f.rosterErr != nil {
		return nil, f.rosterErr
	}
	return f.roster, nil
}

func (f *fakeReportingClient) GetAckActivity(_ context.Context, _ *obligationsv1.GetAckActivityRequest, _ ...grpc.CallOption) (*obligationsv1.GetAckActivityResponse, error) {
	if f.activityErr != nil {
		return nil, f.activityErr
	}
	return f.activity, nil
}

func TestRecordAckBindsUserFromClaims(t *testing.T) {
	acked := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	client := &fakeAckClient{
		recordResp: &obligationsv1.RecordAckResponse{
			Acknowledgment: &obligationsv1.Acknowledgment{
				Id: "ack-1", UserId: "u-9", PolicyVersionId: "pv-1",
				AckedAt: timestamppb.New(acked),
			},
		},
	}
	out, err := resolvers.RecordAckResolver(ctxWithUser(t, "u-9"), client, "pv-1")
	if err != nil {
		t.Fatalf("RecordAck: %v", err)
	}
	if out.UserID != "u-9" || out.ID != "ack-1" {
		t.Fatalf("unexpected ack payload: %+v", out)
	}
	if out.AckedAt != "2026-05-31T12:00:00Z" {
		t.Fatalf("acked_at: got %q want RFC3339 UTC", out.AckedAt)
	}
}

func TestRecordAckUnauthenticated(t *testing.T) {
	client := &fakeAckClient{}
	_, err := resolvers.RecordAckResolver(context.Background(), client, "pv-1")
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastRecordReq != nil {
		t.Fatal("RecordAck should not be invoked without claims")
	}
}

func TestRecordAckPropagatesError(t *testing.T) {
	rpcErr := errors.New("rpc error")
	client := &fakeAckClient{recordErr: rpcErr}
	_, err := resolvers.RecordAckResolver(ctxWithUser(t, "u-1"), client, "pv-1")
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	if !errors.Is(err, rpcErr) {
		t.Fatalf("expected wrapped rpcErr; got %v", err)
	}
}

func TestGetAckStatusAcknowledged(t *testing.T) {
	at := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	client := &fakeAckClient{
		statusResp: &obligationsv1.GetAckStatusResponse{
			Acknowledged: true,
			AckedAt:      timestamppb.New(at),
		},
	}
	out, err := resolvers.GetAckStatusResolver(ctxWithUser(t, "u-1"), client, "pv-1")
	if err != nil {
		t.Fatalf("GetAckStatus: %v", err)
	}
	if !out.Acknowledged {
		t.Fatalf("expected acknowledged=true")
	}
	if out.AckedAt == nil || *out.AckedAt != "2026-04-01T10:00:00Z" {
		t.Fatalf("acked_at: %v", out.AckedAt)
	}
	if client.lastStatusReq.UserId != "u-1" {
		t.Fatalf("user id not bound from claims: %q", client.lastStatusReq.UserId)
	}
}

func TestGetAckStatusUnacknowledged(t *testing.T) {
	client := &fakeAckClient{
		statusResp: &obligationsv1.GetAckStatusResponse{Acknowledged: false},
	}
	out, err := resolvers.GetAckStatusResolver(ctxWithUser(t, "u-1"), client, "pv-1")
	if err != nil {
		t.Fatalf("GetAckStatus: %v", err)
	}
	if out.Acknowledged {
		t.Fatalf("expected acknowledged=false")
	}
	if out.AckedAt != nil {
		t.Fatalf("acked_at must be nil when not acknowledged; got %v", *out.AckedAt)
	}
}

func TestUpsertNotificationPrefBindsUserFromClaims(t *testing.T) {
	client := &fakeNotifPrefClient{
		upsertResp: &obligationsv1.UpsertNotifPrefResponse{
			Pref: &obligationsv1.NotificationPref{UserId: "u-7", Email: true, InApp: false, Push: true},
		},
	}
	out, err := resolvers.UpsertNotificationPrefResolver(ctxWithUser(t, "u-7"), client, resolvers.NotificationPrefInput{
		Email: true, InApp: false, Push: true,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if out.UserID != "u-7" {
		t.Fatalf("response user id: got %q", out.UserID)
	}
	// Sourcing the user id from claims (not input) is a security invariant.
	if client.lastUpsertReq.Pref == nil || client.lastUpsertReq.Pref.UserId != "u-7" {
		t.Fatalf("user id not bound from claims: %+v", client.lastUpsertReq.Pref)
	}
}

func TestGetNotificationPrefUnauthenticated(t *testing.T) {
	client := &fakeNotifPrefClient{}
	_, err := resolvers.GetNotificationPrefResolver(context.Background(), client)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastGetReq != nil {
		t.Fatal("GetNotifPref should not be invoked without claims")
	}
}

func TestGetCompletionReport(t *testing.T) {
	client := &fakeReportingClient{
		reportResp: &obligationsv1.GetCompletionReportResponse{
			TotalAudience: 10, TotalAcked: 7, CompletionPct: 0.7,
			Overdue: []*obligationsv1.OverdueEntry{
				{UserId: "a", Email: "a@x"},
				{UserId: "b", Email: "b@x"},
			},
		},
	}
	out, err := resolvers.GetCompletionReportResolver(ctxWithRoles(t, "u-1", []string{"site-admin"}), client, &fakeComplianceIdentityClient{}, "pv-1", nil)
	if err != nil {
		t.Fatalf("CompletionReport: %v", err)
	}
	if out.TotalAudience != 10 || out.TotalAcked != 7 {
		t.Fatalf("totals: %+v", out)
	}
	if len(out.Overdue) != 2 || out.Overdue[0].UserID != "a" {
		t.Fatalf("overdue: %+v", out.Overdue)
	}
}

func TestExportAcksBase64Encodes(t *testing.T) {
	client := &fakeReportingClient{
		exportResp: &obligationsv1.ExportAcksResponse{
			Data:        []byte("hello"),
			ContentType: "text/csv",
		},
	}
	out, err := resolvers.ExportAcksResolver(ctxWithRoles(t, "u-1", []string{"compliance-admin"}), client, "pv-1", "csv")
	if err != nil {
		t.Fatalf("ExportAcks: %v", err)
	}
	if out.ContentType != "text/csv" {
		t.Fatalf("content type: %q", out.ContentType)
	}
	// "hello" base64-encoded is "aGVsbG8=" — guards against a future refactor
	// silently dropping the encoding step.
	if out.Data != "aGVsbG8=" {
		t.Fatalf("base64 encoding: got %q want %q", out.Data, "aGVsbG8=")
	}
}

func TestMyObligationsBindsUserFromClaims(t *testing.T) {
	client := &fakeObligationClient{
		myObligationsResp: &obligationsv1.GetMyObligationsResponse{
			Obligations: []*obligationsv1.ObligationItem{
				{
					PolicyId:        "pol-1",
					Number:          "POL-001",
					Title:           "Data Retention",
					VersionNo:       3,
					PolicyVersionId: "pv-1",
				},
			},
		},
	}
	out, err := resolvers.MyObligationsResolver(ctxWithUser(t, "u-42"), client)
	if err != nil {
		t.Fatalf("MyObligations: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 obligation; got %d", len(out))
	}
	o := out[0]
	if o.PolicyID != "pol-1" {
		t.Errorf("policyId: got %q want %q", o.PolicyID, "pol-1")
	}
	if o.Number != "POL-001" {
		t.Errorf("number: got %q want %q", o.Number, "POL-001")
	}
	if o.Title != "Data Retention" {
		t.Errorf("title: got %q want %q", o.Title, "Data Retention")
	}
	if o.PolicyVersionID != "pv-1" {
		t.Errorf("policyVersionId: got %q want %q", o.PolicyVersionID, "pv-1")
	}
	// Security invariant: user id must come from claims, not from client input.
	if client.lastMyObligationsReq.UserId != "u-42" {
		t.Fatalf("user id not bound from claims: got %q", client.lastMyObligationsReq.UserId)
	}
}

func TestMyAckSummaryBindsUserFromClaims(t *testing.T) {
	client := &fakeObligationClient{
		ackSummaryResp: &obligationsv1.MyAckSummaryResponse{Required: 3, Done: 1},
	}
	out, err := resolvers.MyAckSummaryResolver(ctxWithUser(t, "u-42"), client)
	if err != nil {
		t.Fatalf("MyAckSummary: %v", err)
	}
	if out.Required != 3 {
		t.Errorf("required: got %d want 3", out.Required)
	}
	if out.Done != 1 {
		t.Errorf("done: got %d want 1", out.Done)
	}
	// Security invariant: user id must come from claims, not from client input.
	if client.lastAckSummaryReq.UserId != "u-42" {
		t.Fatalf("user id not bound from claims: got %q", client.lastAckSummaryReq.UserId)
	}
}

func TestMyAckSummaryUnauthenticated(t *testing.T) {
	client := &fakeObligationClient{}
	_, err := resolvers.MyAckSummaryResolver(context.Background(), client)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastAckSummaryReq != nil {
		t.Fatal("MyAckSummary should not be invoked without claims")
	}
}

func TestMyObligationsUnauthenticated(t *testing.T) {
	client := &fakeObligationClient{}
	_, err := resolvers.MyObligationsResolver(context.Background(), client)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastMyObligationsReq != nil {
		t.Fatal("GetMyObligations should not be invoked without claims")
	}
}

func TestMyObligationsPropagatesError(t *testing.T) {
	rpcErr := errors.New("rpc error")
	client := &fakeObligationClient{myObligationsErr: rpcErr}
	_, err := resolvers.MyObligationsResolver(ctxWithUser(t, "u-1"), client)
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	if !errors.Is(err, rpcErr) {
		t.Fatalf("expected wrapped rpcErr; got %v", err)
	}
}

func TestObligatedAudienceCountForwardsPolicy(t *testing.T) {
	client := &fakeObligationClient{
		audienceCountResp: &obligationsv1.GetObligatedAudienceCountResponse{Count: 57},
	}
	count, err := resolvers.ObligatedAudienceCountResolver(ctxWithRoles(t, "u-1", []string{"compliance-admin"}), client, "pol-99")
	if err != nil {
		t.Fatalf("ObligatedAudienceCount: %v", err)
	}
	if count != 57 {
		t.Fatalf("count: got %d want 57", count)
	}
	if client.lastAudienceCountReq.PolicyId != "pol-99" {
		t.Fatalf("policy id not forwarded: got %q", client.lastAudienceCountReq.PolicyId)
	}
}

func TestObligatedAudienceCountUnauthenticated(t *testing.T) {
	client := &fakeObligationClient{}
	_, err := resolvers.ObligatedAudienceCountResolver(context.Background(), client, "pol-1")
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastAudienceCountReq != nil {
		t.Fatal("GetObligatedAudienceCount should not be invoked without claims")
	}
}

// fakeComplianceIdentityClient stubs identityv1.IdentityReadServiceClient for
// compliance resolver tests. GetUser returns a name from the names map; all
// other methods return zero values.
type fakeComplianceIdentityClient struct {
	identityv1.IdentityReadServiceClient
	names map[string]string
}

func (f *fakeComplianceIdentityClient) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	name := f.names[in.GetUserId()]
	return &identityv1.GetUserResponse{User: &identityv1.User{Id: in.GetUserId(), Name: name}}, nil
}
func (f *fakeComplianceIdentityClient) GetUserByEmail(context.Context, *identityv1.GetUserByEmailRequest, ...grpc.CallOption) (*identityv1.GetUserByEmailResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) JitProvisionByEmail(context.Context, *identityv1.JitProvisionByEmailRequest, ...grpc.CallOption) (*identityv1.JitProvisionByEmailResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ResolveClaims(context.Context, *identityv1.ResolveClaimsRequest, ...grpc.CallOption) (*identityv1.ResolveClaimsResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ListUsersInGroup(context.Context, *identityv1.ListUsersInGroupRequest, ...grpc.CallOption) (*identityv1.ListUsersInGroupResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) GetGroup(context.Context, *identityv1.GetGroupRequest, ...grpc.CallOption) (*identityv1.GetGroupResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ListGroupDescendants(context.Context, *identityv1.ListGroupDescendantsRequest, ...grpc.CallOption) (*identityv1.ListGroupDescendantsResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ListGroupAncestors(context.Context, *identityv1.ListGroupAncestorsRequest, ...grpc.CallOption) (*identityv1.ListGroupAncestorsResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ResolveEmail(context.Context, *identityv1.ResolveEmailRequest, ...grpc.CallOption) (*identityv1.ResolveEmailResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ResolveFCMToken(context.Context, *identityv1.ResolveFCMTokenRequest, ...grpc.CallOption) (*identityv1.ResolveFCMTokenResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ListUserGroups(context.Context, *identityv1.ListUserGroupsRequest, ...grpc.CallOption) (*identityv1.ListUserGroupsResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ListUsersByEmail(context.Context, *identityv1.ListUsersByEmailRequest, ...grpc.CallOption) (*identityv1.ListUsersByEmailResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ListGroups(context.Context, *identityv1.ListGroupsRequest, ...grpc.CallOption) (*identityv1.ListGroupsResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ListUsersByIdpGroups(context.Context, *identityv1.ListUsersByIdpGroupsRequest, ...grpc.CallOption) (*identityv1.ListUsersByIdpGroupsResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) ListAllUsers(context.Context, *identityv1.ListAllUsersRequest, ...grpc.CallOption) (*identityv1.ListAllUsersResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) CountAllUsers(context.Context, *identityv1.CountAllUsersRequest, ...grpc.CallOption) (*identityv1.CountAllUsersResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) CountUsersByIdpGroups(context.Context, *identityv1.CountUsersByIdpGroupsRequest, ...grpc.CallOption) (*identityv1.CountUsersByIdpGroupsResponse, error) {
	return nil, nil
}
func (f *fakeComplianceIdentityClient) RevokeMySessions(context.Context, *identityv1.RevokeMySessionsRequest, ...grpc.CallOption) (*identityv1.RevokeMySessionsResponse, error) {
	return nil, nil
}

func TestGetCompletionReportResolver_EnrichesAndMaps(t *testing.T) {
	reporting := &fakeReportingClient{reportResp: &obligationsv1.GetCompletionReportResponse{
		TotalAudience: 10, TotalAcked: 7, CompletionPct: 70, AvgDaysToAck: 3.5, ViewedNotAckedCount: 2,
		Overdue: []*obligationsv1.OverdueEntry{{UserId: "u1", Email: "u1@example.org"}},
	}}
	identity := &fakeComplianceIdentityClient{names: map[string]string{"u1": "Uma One"}}

	out, err := resolvers.GetCompletionReportResolver(
		ctxWithRoles(t, "u", []string{"compliance-admin"}), reporting, identity, "pv1", nil)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if out.AvgDaysToAck != 3.5 || out.ViewedNotAckedCount != 2 {
		t.Fatalf("metrics: %+v", out)
	}
	if len(out.Overdue) != 1 || out.Overdue[0].UserName == nil || *out.Overdue[0].UserName != "Uma One" {
		t.Fatalf("overdue userName not enriched: %+v", out.Overdue[0])
	}
}

func TestGetCompletionReportResolver_DeniesWithoutComplianceReport(t *testing.T) {
	_, err := resolvers.GetCompletionReportResolver(
		ctxWithRoles(t, "u", []string{"author"}), &fakeReportingClient{}, &fakeComplianceIdentityClient{}, "pv1", nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

func TestRecordViewResolver_RequiresAuth(t *testing.T) {
	if _, err := resolvers.RecordViewResolver(context.Background(), &fakeAckClient{}, "pv1"); err == nil {
		t.Fatal("want unauthenticated error")
	}
	ok, err := resolvers.RecordViewResolver(ctxWithRoles(t, "u", []string{"reader"}), &fakeAckClient{}, "pv1")
	if err != nil || !ok {
		t.Fatalf("authenticated recordView: ok=%v err=%v", ok, err)
	}
}

func TestAckRosterResolver_EnrichesNames(t *testing.T) {
	reporting := &fakeReportingClient{roster: &obligationsv1.GetAckRosterResponse{
		Acked:   []*obligationsv1.AckRosterEntry{{UserId: "u1", Email: "u1@example.org"}},
		Pending: []*obligationsv1.AckRosterEntry{{UserId: "u2", Email: "u2@example.org"}},
	}}
	identity := &fakeComplianceIdentityClient{names: map[string]string{"u1": "Uma One"}}
	out, err := resolvers.AckRosterResolver(ctxWithRoles(t, "u", []string{"compliance-admin"}), reporting, identity, "pv1", nil)
	if err != nil {
		t.Fatalf("roster: %v", err)
	}
	if len(out.Acked) != 1 || out.Acked[0].UserName == nil || *out.Acked[0].UserName != "Uma One" {
		t.Fatalf("acked enrich: %+v", out.Acked)
	}
	if len(out.Pending) != 1 {
		t.Fatalf("pending: %+v", out.Pending)
	}
}

func TestGetNotificationSettingsBindsUserAndMaps(t *testing.T) {
	client := &fakeNotifPrefClient{
		settingsResp: &obligationsv1.GetNotificationSettingsResponse{
			Settings: &obligationsv1.NotificationSettings{
				Channels: &obligationsv1.NotificationPref{UserId: "u-9", Email: true, InApp: false, Push: true},
				Categories: []*obligationsv1.CategoryPref{{
					Category:  obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE,
					Cadence:   obligationsv1.NotifCadence_NOTIF_CADENCE_DAILY,
					Mandatory: true,
				}},
				Overrides: []*obligationsv1.TypePref{{
					Kind:     "policy-published",
					Category: obligationsv1.NotifCategory_NOTIF_CATEGORY_INFORMATIONAL,
					Cadence:  obligationsv1.NotifCadence_NOTIF_CADENCE_WEEKLY,
				}},
				Digest: &obligationsv1.DigestWindow{DailyHour: 9, WeeklyDow: 3},
			},
		},
	}
	out, err := resolvers.GetNotificationSettingsResolver(ctxWithUser(t, "u-9"), client)
	if err != nil {
		t.Fatalf("GetNotificationSettings: %v", err)
	}
	if !out.Channels.Email || out.Channels.InApp || !out.Channels.Push {
		t.Errorf("channels mismapped: %+v", out.Channels)
	}
	if len(out.Categories) != 1 || out.Categories[0].Category != resolvers.NotifCategoryCompliance ||
		out.Categories[0].Cadence != resolvers.NotifCadenceDaily || !out.Categories[0].Mandatory {
		t.Errorf("categories mismapped: %+v", out.Categories)
	}
	if len(out.Overrides) != 1 || out.Overrides[0].Kind != "policy-published" ||
		out.Overrides[0].Cadence != resolvers.NotifCadenceWeekly {
		t.Errorf("overrides mismapped: %+v", out.Overrides)
	}
	if out.Digest.DailyHour != 9 || out.Digest.WeeklyDow != 3 {
		t.Errorf("digest mismapped: %+v", out.Digest)
	}
}

func TestSetCategoryCadenceBindsUserFromClaims(t *testing.T) {
	client := &fakeNotifPrefClient{
		setCatResp: &obligationsv1.SetCategoryCadenceResponse{
			Settings: &obligationsv1.NotificationSettings{Channels: &obligationsv1.NotificationPref{UserId: "u-3"}},
		},
	}
	_, err := resolvers.SetCategoryCadenceResolver(ctxWithUser(t, "u-3"), client,
		resolvers.NotifCategoryInformational, resolvers.NotifCadenceWeekly)
	if err != nil {
		t.Fatalf("SetCategoryCadence: %v", err)
	}
	if client.lastSetCatReq == nil || client.lastSetCatReq.UserId != "u-3" {
		t.Fatalf("user id not bound from claims: %+v", client.lastSetCatReq)
	}
	if client.lastSetCatReq.Category != obligationsv1.NotifCategory_NOTIF_CATEGORY_INFORMATIONAL ||
		client.lastSetCatReq.Cadence != obligationsv1.NotifCadence_NOTIF_CADENCE_WEEKLY {
		t.Errorf("category/cadence not forwarded: %+v", client.lastSetCatReq)
	}
}

func TestSetCategoryCadencePropagatesServerError(t *testing.T) {
	client := &fakeNotifPrefClient{setCatErr: errors.New("rpc error: code = InvalidArgument")}
	_, err := resolvers.SetCategoryCadenceResolver(ctxWithUser(t, "u-1"), client,
		resolvers.NotifCategoryCompliance, resolvers.NotifCadenceOff)
	if err == nil {
		t.Fatal("expected the server's mandatory-off rejection to propagate")
	}
}

func TestSetDigestWindowUnauthenticated(t *testing.T) {
	client := &fakeNotifPrefClient{}
	_, err := resolvers.SetDigestWindowResolver(context.Background(), client, 9, 3)
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if client.lastSetDigestReq != nil {
		t.Fatal("SetDigestWindow should not be invoked without claims")
	}
}

func TestSetNotificationChannelsBindsUserAndReturnsSettings(t *testing.T) {
	client := &fakeNotifPrefClient{
		upsertResp: &obligationsv1.UpsertNotifPrefResponse{Pref: &obligationsv1.NotificationPref{UserId: "u-5"}},
		settingsResp: &obligationsv1.GetNotificationSettingsResponse{
			Settings: &obligationsv1.NotificationSettings{Channels: &obligationsv1.NotificationPref{UserId: "u-5", Email: false}},
		},
	}
	out, err := resolvers.SetNotificationChannelsResolver(ctxWithUser(t, "u-5"), client,
		resolvers.NotificationPrefInput{Email: false, InApp: true, Push: false})
	if err != nil {
		t.Fatalf("SetNotificationChannels: %v", err)
	}
	if client.lastUpsertReq.Pref.UserId != "u-5" {
		t.Fatalf("user id not bound from claims: %+v", client.lastUpsertReq.Pref)
	}
	if out.Channels.Email {
		t.Errorf("expected returned settings to reflect email=false")
	}
}

func TestNotificationTypeCatalogMapsTaxonomy(t *testing.T) {
	client := &fakeNotifPrefClient{
		listTypesResp: &obligationsv1.ListNotifTypesResponse{
			Types: []*obligationsv1.NotifTypeDef{
				{
					Kind:      "ack-required",
					Category:  obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE,
					Mandatory: true,
					Delivery:  obligationsv1.NotifDelivery_NOTIF_DELIVERY_IMMEDIATE_ONLY,
				},
				{
					Kind:      "policy-retired",
					Category:  obligationsv1.NotifCategory_NOTIF_CATEGORY_INFORMATIONAL,
					Mandatory: false,
					Delivery:  obligationsv1.NotifDelivery_NOTIF_DELIVERY_DIGEST_PREFERRED,
				},
			},
		},
	}
	out, err := resolvers.NotificationTypeCatalogResolver(ctxWithUser(t, "u-1"), client)
	if err != nil {
		t.Fatalf("NotificationTypeCatalog: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d types, want 2", len(out))
	}
	if out[0].Kind != "ack-required" || out[0].Category != resolvers.NotifCategoryCompliance ||
		!out[0].Mandatory || out[0].Delivery != resolvers.NotifDeliveryImmediateOnly {
		t.Errorf("row 0 mismapped: %+v", out[0])
	}
	if out[1].Kind != "policy-retired" || out[1].Category != resolvers.NotifCategoryInformational ||
		out[1].Mandatory || out[1].Delivery != resolvers.NotifDeliveryDigestPreferred {
		t.Errorf("row 1 mismapped: %+v", out[1])
	}
}

// TestNotificationTypeCatalogRequiresAuth pins that the catalog is not public:
// it describes every notification the platform sends.
func TestNotificationTypeCatalogRequiresAuth(t *testing.T) {
	client := &fakeNotifPrefClient{listTypesResp: &obligationsv1.ListNotifTypesResponse{}}
	if _, err := resolvers.NotificationTypeCatalogResolver(context.Background(), client); err == nil {
		t.Fatal("expected unauthenticated error with no claims")
	}
	if client.listTypesCalls != 0 {
		t.Errorf("unauthenticated call reached the backend %d times", client.listTypesCalls)
	}
}

// TestNotificationTypeCatalogSendsNoUserID guards that the catalog stays
// user-independent reference data: a per-user request would let the response
// vary by caller and make it uncacheable.
func TestNotificationTypeCatalogSendsNoUserID(t *testing.T) {
	client := &fakeNotifPrefClient{listTypesResp: &obligationsv1.ListNotifTypesResponse{}}
	if _, err := resolvers.NotificationTypeCatalogResolver(ctxWithUser(t, "u-1"), client); err != nil {
		t.Fatalf("NotificationTypeCatalog: %v", err)
	}
	if client.listTypesCalls != 1 {
		t.Fatalf("backend called %d times, want 1", client.listTypesCalls)
	}
}

// TestNotificationTypeCatalogPropagatesBackendError asserts a backend failure
// surfaces rather than rendering as an empty catalog, which the UI would show
// as "no notification types" instead of an error.
func TestNotificationTypeCatalogPropagatesBackendError(t *testing.T) {
	client := &fakeNotifPrefClient{listTypesErr: errors.New("rpc error: code = Unavailable")}
	if _, err := resolvers.NotificationTypeCatalogResolver(ctxWithUser(t, "u-1"), client); err == nil {
		t.Fatal("expected the backend error to propagate")
	}
}

// TestOverrideCarriesDeliveryPolicy asserts a per-type override row carries the
// delivery policy through to the client. Without it a UI would have to guess
// batchability from `mandatory`, which is wrong: setTypeCadence ACCEPTS a
// digest cadence for an immediate-only kind and clamps at send time.
func TestOverrideCarriesDeliveryPolicy(t *testing.T) {
	client := &fakeNotifPrefClient{
		settingsResp: &obligationsv1.GetNotificationSettingsResponse{
			Settings: &obligationsv1.NotificationSettings{
				Channels: &obligationsv1.NotificationPref{UserId: "u-9"},
				Overrides: []*obligationsv1.TypePref{{
					Kind:      "ack-required",
					Category:  obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE,
					Cadence:   obligationsv1.NotifCadence_NOTIF_CADENCE_IMMEDIATE,
					Mandatory: true,
					Delivery:  obligationsv1.NotifDelivery_NOTIF_DELIVERY_IMMEDIATE_ONLY,
				}},
			},
		},
	}
	out, err := resolvers.GetNotificationSettingsResolver(ctxWithUser(t, "u-9"), client)
	if err != nil {
		t.Fatalf("GetNotificationSettings: %v", err)
	}
	if len(out.Overrides) != 1 || out.Overrides[0].Delivery != resolvers.NotifDeliveryImmediateOnly {
		t.Errorf("override delivery mismapped: %+v", out.Overrides)
	}
}

// TestUnspecifiedDeliveryFallsBackToImmediateOnly pins the conservative
// mapping: an unclassified kind must not be reported as batchable, since the
// schema field is non-null and the server promised nothing.
func TestUnspecifiedDeliveryFallsBackToImmediateOnly(t *testing.T) {
	client := &fakeNotifPrefClient{
		listTypesResp: &obligationsv1.ListNotifTypesResponse{
			Types: []*obligationsv1.NotifTypeDef{{Kind: "brand-new-kind"}},
		},
	}
	out, err := resolvers.NotificationTypeCatalogResolver(ctxWithUser(t, "u-1"), client)
	if err != nil {
		t.Fatalf("NotificationTypeCatalog: %v", err)
	}
	if len(out) != 1 || out[0].Delivery != resolvers.NotifDeliveryImmediateOnly {
		t.Errorf("UNSPECIFIED delivery mismapped: %+v", out)
	}
}
