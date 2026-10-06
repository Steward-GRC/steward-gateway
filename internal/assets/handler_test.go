// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package assets

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	log "github.com/Bugs5382/go-log"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// fakeAssetClient is a stub AssetServiceClient.
type fakeAssetClient struct {
	uploadResp *corev1.UploadAssetResponse
	uploadErr  error
	getResp    *corev1.GetAssetResponse
	getErr     error
	gotUpload  *corev1.UploadAssetRequest
}

func (f *fakeAssetClient) UploadAsset(_ context.Context, in *corev1.UploadAssetRequest, _ ...grpc.CallOption) (*corev1.UploadAssetResponse, error) {
	f.gotUpload = in
	return f.uploadResp, f.uploadErr
}

func (f *fakeAssetClient) GetAsset(_ context.Context, _ *corev1.GetAssetRequest, _ ...grpc.CallOption) (*corev1.GetAssetResponse, error) {
	return f.getResp, f.getErr
}

func multipartBody(t *testing.T, field, filename, contentType string, data []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{`form-data; name="` + field + `"; filename="` + filename + `"`}
	if contentType != "" {
		h["Content-Type"] = []string{contentType}
	}
	pw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if _, err := pw.Write(data); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

func withStaff(r *http.Request, uid string) *http.Request {
	return r.WithContext(principal.WithClaims(r.Context(), principal.Static{UserIDValue: uid, EmailValue: "alice@example.org", RolesValue: []string{"author"}}))
}

func TestUpload_Success(t *testing.T) {
	client := &fakeAssetClient{uploadResp: &corev1.UploadAssetResponse{Asset: &corev1.Asset{
		Id: "asset-1", Url: "/api/assets/asset-1", ContentType: "image/png", SizeBytes: 12, Filename: "logo.png",
	}}}
	h := New(client, log.Nop())

	body, ct := multipartBody(t, "file", "logo.png", "image/png", []byte("\x89PNG image!"))
	req := withStaff(httptest.NewRequest(http.MethodPost, "/api/assets", body), "user-1")
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()

	h.Upload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got uploadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.URL != "/api/assets/asset-1" || got.ID != "asset-1" || got.ContentType != "image/png" {
		t.Errorf("unexpected response: %+v", got)
	}
	if client.gotUpload.GetCreatedByUserId() != "user-1" {
		t.Errorf("created_by = %q, want the authenticated staff user user-1", client.gotUpload.GetCreatedByUserId())
	}
}

func TestUpload_Unauthenticated(t *testing.T) {
	h := New(&fakeAssetClient{}, log.Nop())
	body, ct := multipartBody(t, "file", "logo.png", "image/png", []byte("x"))
	req := httptest.NewRequest(http.MethodPost, "/api/assets", body) // no claims attached
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()

	h.Upload(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestUpload_CoreValidationError_MapsTo400(t *testing.T) {
	client := &fakeAssetClient{uploadErr: status.Error(codes.InvalidArgument, "asset: unsupported content type")}
	h := New(client, log.Nop())
	body, ct := multipartBody(t, "file", "x.txt", "text/plain", []byte("not an image"))
	req := withStaff(httptest.NewRequest(http.MethodPost, "/api/assets", body), "user-1")
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()

	h.Upload(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestUpload_MissingFilePart(t *testing.T) {
	h := New(&fakeAssetClient{}, log.Nop())
	// A multipart form with the wrong field name.
	body, ct := multipartBody(t, "wrongfield", "logo.png", "image/png", []byte("x"))
	req := withStaff(httptest.NewRequest(http.MethodPost, "/api/assets", body), "user-1")
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()

	h.Upload(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestServe_Success(t *testing.T) {
	content := []byte("\x89PNG served bytes")
	client := &fakeAssetClient{getResp: &corev1.GetAssetResponse{
		Data: content, ContentType: "image/png", SizeBytes: int64(len(content)), Filename: "logo.png",
	}}
	h := New(client, log.Nop())

	req := withStaff(httptest.NewRequest(http.MethodGet, "/api/assets/asset-1", nil), "user-1")
	req.SetPathValue("id", "asset-1")
	rec := httptest.NewRecorder()

	h.Serve(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("content-type = %q, want image/png", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing nosniff header")
	}
	got, _ := io.ReadAll(rec.Body)
	if !bytes.Equal(got, content) {
		t.Errorf("body mismatch")
	}
}

func TestServe_NotFound(t *testing.T) {
	client := &fakeAssetClient{getErr: status.Error(codes.NotFound, "asset not found")}
	h := New(client, log.Nop())
	req := withStaff(httptest.NewRequest(http.MethodGet, "/api/assets/missing", nil), "user-1")
	req.SetPathValue("id", "missing")
	rec := httptest.NewRecorder()

	h.Serve(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// The read path skips the CSRF header for <img>, so the bytes must stay away
// from cross-origin documents.
func TestServe_KeepsBytesSameOrigin(t *testing.T) {
	client := &fakeAssetClient{getResp: &corev1.GetAssetResponse{Data: []byte("PNGBYTES"), ContentType: "image/png", SizeBytes: 8}}
	req := withStaff(httptest.NewRequest(http.MethodGet, "/api/assets/a1", nil), "user-1")
	req.SetPathValue("id", "a1")
	rec := httptest.NewRecorder()

	New(client, log.Nop()).Serve(rec, req)

	if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
		t.Fatalf("Cross-Origin-Resource-Policy = %q, want same-origin", got)
	}
}
