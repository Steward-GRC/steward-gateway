// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	deliveryv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/delivery/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeDeliveryClient is an in-package stub of deliveryv1.DeliveryServiceClient.
// Mirrors the fakeCollabClient style: per-RPC response + error fields plus
// last-request captures so tests can assert that the gateway forwards the
// authenticated user id rather than trusting client input.
type fakeDeliveryClient struct {
	deliveryv1.DeliveryServiceClient
	renderedResp *deliveryv1.GetRenderedContentResponse
	renderedErr  error

	diffResp *deliveryv1.GetDiffResponse
	diffErr  error

	pdfDownloadResp *deliveryv1.GetPDFDownloadLinkResponse
	pdfDownloadErr  error

	requestPDFResp    *deliveryv1.RequestPDFExportResponse
	requestPDFErr     error
	lastRequestPDFReq *deliveryv1.RequestPDFExportRequest

	createMagicResp    *deliveryv1.CreateMagicLinkResponse
	createMagicErr     error
	lastCreateMagicReq *deliveryv1.CreateMagicLinkRequest

	revokeMagicResp    *deliveryv1.RevokeMagicLinkResponse
	revokeMagicErr     error
	lastRevokeMagicReq *deliveryv1.RevokeMagicLinkRequest
}

func (f *fakeDeliveryClient) GetRenderedContent(_ context.Context, _ *deliveryv1.GetRenderedContentRequest, _ ...grpc.CallOption) (*deliveryv1.GetRenderedContentResponse, error) {
	if f.renderedErr != nil {
		return nil, f.renderedErr
	}
	return f.renderedResp, nil
}

func (f *fakeDeliveryClient) GetDiff(_ context.Context, _ *deliveryv1.GetDiffRequest, _ ...grpc.CallOption) (*deliveryv1.GetDiffResponse, error) {
	if f.diffErr != nil {
		return nil, f.diffErr
	}
	return f.diffResp, nil
}

func (f *fakeDeliveryClient) RequestPDFExport(_ context.Context, in *deliveryv1.RequestPDFExportRequest, _ ...grpc.CallOption) (*deliveryv1.RequestPDFExportResponse, error) {
	f.lastRequestPDFReq = in
	if f.requestPDFErr != nil {
		return nil, f.requestPDFErr
	}
	return f.requestPDFResp, nil
}

func (f *fakeDeliveryClient) GetPDFDownloadLink(_ context.Context, _ *deliveryv1.GetPDFDownloadLinkRequest, _ ...grpc.CallOption) (*deliveryv1.GetPDFDownloadLinkResponse, error) {
	if f.pdfDownloadErr != nil {
		return nil, f.pdfDownloadErr
	}
	return f.pdfDownloadResp, nil
}

func (f *fakeDeliveryClient) CreateMagicLink(_ context.Context, in *deliveryv1.CreateMagicLinkRequest, _ ...grpc.CallOption) (*deliveryv1.CreateMagicLinkResponse, error) {
	f.lastCreateMagicReq = in
	if f.createMagicErr != nil {
		return nil, f.createMagicErr
	}
	return f.createMagicResp, nil
}

func (f *fakeDeliveryClient) RevokeMagicLink(_ context.Context, in *deliveryv1.RevokeMagicLinkRequest, _ ...grpc.CallOption) (*deliveryv1.RevokeMagicLinkResponse, error) {
	f.lastRevokeMagicReq = in
	if f.revokeMagicErr != nil {
		return nil, f.revokeMagicErr
	}
	return f.revokeMagicResp, nil
}

// ---------- renderedContent ----------

func TestGetRenderedContentHappyPath(t *testing.T) {
	client := &fakeDeliveryClient{
		renderedResp: &deliveryv1.GetRenderedContentResponse{Html: "<article>policy body</article>"},
	}
	got, err := resolvers.GetRenderedContent(context.Background(), client, "pv-1")
	if err != nil {
		t.Fatalf("GetRenderedContent: %v", err)
	}
	if got == nil || got.HTML != "<article>policy body</article>" {
		t.Fatalf("html: got %+v", got)
	}
}

func TestGetRenderedContentPropagatesError(t *testing.T) {
	rpcErr := errors.New("not found")
	client := &fakeDeliveryClient{renderedErr: rpcErr}
	got, err := resolvers.GetRenderedContent(context.Background(), client, "pv-missing")
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	if !errors.Is(err, rpcErr) {
		t.Fatalf("expected wrapped rpcErr; got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result on error; got %+v", got)
	}
}

// ---------- policyDiff ----------

func TestGetPolicyDiffHappyPath(t *testing.T) {
	client := &fakeDeliveryClient{
		diffResp: &deliveryv1.GetDiffResponse{Sections: []*deliveryv1.SectionDiff{
			{SectionKey: "purpose", ChangeType: "changed", DiffHtml: "<ins>updated</ins>", Boilerplate: false},
			{SectionKey: "scope", ChangeType: "unchanged", DiffHtml: "", Boilerplate: true},
		}},
	}
	got, err := resolvers.GetPolicyDiff(context.Background(), client, "pv-1", "pv-2")
	if err != nil {
		t.Fatalf("GetPolicyDiff: %v", err)
	}
	if got == nil || len(got.Sections) != 2 {
		t.Fatalf("sections: got %+v", got)
	}
	if got.Sections[0].SectionKey != "purpose" || got.Sections[0].ChangeType != "changed" {
		t.Fatalf("first section: %+v", got.Sections[0])
	}
	if got.Sections[0].WordDiffHTML == nil || *got.Sections[0].WordDiffHTML != "<ins>updated</ins>" {
		t.Fatalf("expected WordDiffHTML=<ins>updated</ins>; got %v", got.Sections[0].WordDiffHTML)
	}
	if got.Sections[0].IsBoilerplate {
		t.Fatalf("first section IsBoilerplate: want false")
	}
	// Empty diff_html should become nil *string via nilIfEmpty, matching the
	// pattern used by DiffVersions.
	if got.Sections[1].WordDiffHTML != nil {
		t.Fatalf("expected nil WordDiffHTML for empty diff_html; got %v", *got.Sections[1].WordDiffHTML)
	}
	if !got.Sections[1].IsBoilerplate {
		t.Fatal("second section IsBoilerplate: want true")
	}
}

func TestGetPolicyDiffPropagatesError(t *testing.T) {
	rpcErr := errors.New("boom")
	client := &fakeDeliveryClient{diffErr: rpcErr}
	if _, err := resolvers.GetPolicyDiff(context.Background(), client, "a", "b"); err == nil || !errors.Is(err, rpcErr) {
		t.Fatalf("expected wrapped rpcErr; got %v", err)
	}
}

// ---------- pdfDownloadLink ----------

func TestGetPDFDownloadLinkHappyPath(t *testing.T) {
	expires := time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)
	client := &fakeDeliveryClient{
		pdfDownloadResp: &deliveryv1.GetPDFDownloadLinkResponse{
			SignedUrl: "https://s3.example/pv-1.pdf?sig=xyz",
			ExpiresAt: timestamppb.New(expires),
		},
	}
	got, err := resolvers.GetPDFDownloadLink(context.Background(), client, "job-1")
	if err != nil {
		t.Fatalf("GetPDFDownloadLink: %v", err)
	}
	if got.SignedURL != "https://s3.example/pv-1.pdf?sig=xyz" {
		t.Fatalf("signed url: %q", got.SignedURL)
	}
	if got.ExpiresAt != "2026-05-31T10:00:00Z" {
		t.Fatalf("expires_at: got %q; want RFC3339 UTC", got.ExpiresAt)
	}
}

func TestGetPDFDownloadLinkPropagatesError(t *testing.T) {
	rpcErr := errors.New("expired")
	client := &fakeDeliveryClient{pdfDownloadErr: rpcErr}
	if _, err := resolvers.GetPDFDownloadLink(context.Background(), client, "job-1"); err == nil || !errors.Is(err, rpcErr) {
		t.Fatalf("expected wrapped rpcErr; got %v", err)
	}
}

// ---------- requestPDFExport (mutation, requires auth) ----------

func TestRequestPDFExportHappyPath(t *testing.T) {
	client := &fakeDeliveryClient{
		requestPDFResp: &deliveryv1.RequestPDFExportResponse{JobId: "job-42"},
	}
	ctx := ctxWithUser(t, "u-7")
	got, err := resolvers.RequestPDFExport(ctx, client, "pv-1")
	if err != nil {
		t.Fatalf("RequestPDFExport: %v", err)
	}
	if got == nil || got.JobID != "job-42" {
		t.Fatalf("job: got %+v", got)
	}
	if client.lastRequestPDFReq == nil || client.lastRequestPDFReq.RequesterUserId != "u-7" {
		t.Fatalf("requester user id not bound from context; got %+v", client.lastRequestPDFReq)
	}
	if client.lastRequestPDFReq.PolicyVersionId != "pv-1" {
		t.Fatalf("policy version id not forwarded; got %+v", client.lastRequestPDFReq)
	}
}

func TestRequestPDFExportUnauthenticated(t *testing.T) {
	client := &fakeDeliveryClient{}
	if _, err := resolvers.RequestPDFExport(context.Background(), client, "pv-1"); err == nil {
		t.Fatal("expected unauthenticated error when no claims on context")
	}
	if client.lastRequestPDFReq != nil {
		t.Fatalf("RequestPDFExport should not be invoked without claims; got %+v", client.lastRequestPDFReq)
	}
}

func TestRequestPDFExportPropagatesError(t *testing.T) {
	rpcErr := errors.New("queue full")
	client := &fakeDeliveryClient{requestPDFErr: rpcErr}
	if _, err := resolvers.RequestPDFExport(ctxWithUser(t, "u-1"), client, "pv-1"); err == nil || !errors.Is(err, rpcErr) {
		t.Fatalf("expected wrapped rpcErr; got %v", err)
	}
}

// ---------- createMagicLink ----------

func TestCreateMagicLinkHappyPath(t *testing.T) {
	expires := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	client := &fakeDeliveryClient{
		createMagicResp: &deliveryv1.CreateMagicLinkResponse{
			Token:     "tok-abc",
			ExpiresAt: timestamppb.New(expires),
		},
	}
	got, err := resolvers.CreateMagicLinkResolver(ctxWithUser(t, "u-9"), client, "pv-1", true)
	if err != nil {
		t.Fatalf("CreateMagicLinkResolver: %v", err)
	}
	if got == nil || got.Token != "tok-abc" {
		t.Fatalf("token: got %+v", got)
	}
	if got.ExpiresAt != "2026-06-30T00:00:00Z" {
		t.Fatalf("expires_at: got %q; want RFC3339 UTC", got.ExpiresAt)
	}
	if client.lastCreateMagicReq == nil || client.lastCreateMagicReq.CreatedByUserId != "u-9" {
		t.Fatalf("created_by_user_id not bound from context; got %+v", client.lastCreateMagicReq)
	}
	if !client.lastCreateMagicReq.Sensitive {
		t.Fatalf("sensitive flag not forwarded; got %+v", client.lastCreateMagicReq)
	}
}

func TestCreateMagicLinkUnauthenticated(t *testing.T) {
	client := &fakeDeliveryClient{}
	if _, err := resolvers.CreateMagicLinkResolver(context.Background(), client, "pv-1", false); err == nil {
		t.Fatal("expected unauthenticated error when no claims on context")
	}
	if client.lastCreateMagicReq != nil {
		t.Fatalf("CreateMagicLink should not be invoked without claims; got %+v", client.lastCreateMagicReq)
	}
}

func TestCreateMagicLinkPropagatesError(t *testing.T) {
	rpcErr := errors.New("policy version is sensitive but caller did not opt in")
	client := &fakeDeliveryClient{createMagicErr: rpcErr}
	if _, err := resolvers.CreateMagicLinkResolver(ctxWithUser(t, "u-1"), client, "pv-1", false); err == nil || !errors.Is(err, rpcErr) {
		t.Fatalf("expected wrapped rpcErr; got %v", err)
	}
}

// ---------- revokeMagicLink ----------

func TestRevokeMagicLinkHappyPath(t *testing.T) {
	client := &fakeDeliveryClient{
		revokeMagicResp: &deliveryv1.RevokeMagicLinkResponse{Revoked: true},
	}
	got, err := resolvers.RevokeMagicLinkResolver(ctxWithRoles(t, "u-2", []string{"site-admin"}), client, "tok-abc")
	if err != nil {
		t.Fatalf("RevokeMagicLinkResolver: %v", err)
	}
	if !got {
		t.Fatal("expected revoked=true")
	}
	if client.lastRevokeMagicReq == nil || client.lastRevokeMagicReq.RevokedByUserId != "u-2" {
		t.Fatalf("revoked_by_user_id not bound from context; got %+v", client.lastRevokeMagicReq)
	}
	if client.lastRevokeMagicReq.Token != "tok-abc" {
		t.Fatalf("token not forwarded; got %+v", client.lastRevokeMagicReq)
	}
}

func TestRevokeMagicLinkUnauthenticated(t *testing.T) {
	client := &fakeDeliveryClient{}
	if _, err := resolvers.RevokeMagicLinkResolver(context.Background(), client, "tok-x"); err == nil {
		t.Fatal("expected unauthenticated error when no claims on context")
	}
	if client.lastRevokeMagicReq != nil {
		t.Fatalf("RevokeMagicLink should not be invoked without claims; got %+v", client.lastRevokeMagicReq)
	}
}

func TestRevokeMagicLinkPropagatesError(t *testing.T) {
	rpcErr := errors.New("already revoked")
	client := &fakeDeliveryClient{revokeMagicErr: rpcErr}
	if _, err := resolvers.RevokeMagicLinkResolver(ctxWithRoles(t, "u-1", []string{"site-admin"}), client, "tok-x"); err == nil || !errors.Is(err, rpcErr) {
		t.Fatalf("expected wrapped rpcErr; got %v", err)
	}
}
