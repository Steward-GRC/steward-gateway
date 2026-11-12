// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package assets

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// These tests follow the mock's assets.test.ts ("POST /api/assets with
// attachment files" and the size-cap cases) for the editor's file card.

func upload(t *testing.T, h *Handler, filename, declared string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, ct := multipartBody(t, "file", filename, declared, data)
	req := withStaff(httptest.NewRequest(http.MethodPost, "/api/assets", body), "user-1")
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	h.Upload(rec, req)
	return rec
}

func errorText(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var e errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return e.Error
}

func serve(t *testing.T, client *fakeAssetClient, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := withStaff(httptest.NewRequest(http.MethodGet, "/api/assets/"+id, nil), "user-1")
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	New(client, log.Nop()).Serve(rec, req)
	return rec
}

// "keeps ${name} and serves it back as a download"
func TestUpload_FileKeepsTheSameResponseShape(t *testing.T) {
	client := &fakeAssetClient{uploadResp: &corev1.UploadAssetResponse{Asset: &corev1.Asset{
		Id: "asset-9", Url: "/api/assets/asset-9", ContentType: "application/pdf", SizeBytes: 9, Filename: "report.pdf",
		ServeAs: "file", Kind: "pdf",
	}}}
	rec := upload(t, New(client, log.Nop()), "report.pdf", "application/pdf", []byte("%PDF-1.4\n"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"id": "asset-9", "url": "/api/assets/asset-9", "contentType": "application/pdf", "sizeBytes": float64(9), "filename": "report.pdf"}
	if len(got) != len(want) {
		t.Fatalf("response = %v, want exactly %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if client.gotUpload.GetFilename() != "report.pdf" || client.gotUpload.GetContentType() != "application/pdf" {
		t.Errorf("core got name %q type %q", client.gotUpload.GetFilename(), client.gotUpload.GetContentType())
	}
}

// The multipart limit follows core's larger file cap and the gRPC call limit
// is raised to match core's message size.
func TestUpload_LimitsFollowTheFileCap(t *testing.T) {
	if MaxUploadBytes != 25<<20 {
		t.Fatalf("MaxUploadBytes = %d, want 25 MiB", MaxUploadBytes)
	}
	if maxAssetCallBytes < MaxUploadBytes+multipartOverhead {
		t.Fatalf("maxAssetCallBytes = %d, too small for a file at the cap", maxAssetCallBytes)
	}
	if maxAssetCallBytes != 32<<20 {
		t.Fatalf("maxAssetCallBytes = %d, want core's 32 MiB", maxAssetCallBytes)
	}
	client := &fakeAssetClient{uploadResp: &corev1.UploadAssetResponse{Asset: &corev1.Asset{Id: "a"}}}
	upload(t, New(client, log.Nop()), "r.pdf", "application/pdf", []byte("%PDF-1.4"))
	var send int
	for _, o := range client.uploadOpts {
		if m, ok := o.(grpc.MaxSendMsgSizeCallOption); ok {
			send = m.MaxSendMsgSize
		}
	}
	if send != maxAssetCallBytes {
		t.Errorf("send limit = %d, want %d", send, maxAssetCallBytes)
	}
	var recv int
	srv := &fakeAssetClient{getResp: &corev1.GetAssetResponse{Data: []byte("x"), ContentType: "image/png", SizeBytes: 1, ServeAs: "image"}}
	serve(t, srv, "a")
	for _, o := range srv.getOpts {
		if m, ok := o.(grpc.MaxRecvMsgSizeCallOption); ok {
			recv = m.MaxRecvMsgSize
		}
	}
	if recv != maxAssetCallBytes {
		t.Errorf("receive limit = %d, want %d", recv, maxAssetCallBytes)
	}
}

// "refuses a file over the size cap": above the hard cap the gateway refuses
// without sending the bytes on; a file at the cap goes through.
func TestUpload_OverTheHardCapIsRefusedBeforeCore(t *testing.T) {
	client := &fakeAssetClient{uploadResp: &corev1.UploadAssetResponse{Asset: &corev1.Asset{Id: "a"}}}
	h := New(client, log.Nop())

	rec := upload(t, h, "big.pdf", "application/pdf", make([]byte, MaxUploadBytes+1))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if msg := errorText(t, rec); !strings.Contains(msg, "File too large") || !strings.Contains(msg, "25 MB") {
		t.Errorf("error = %q, want the too-large text naming 25 MB", msg)
	}
	if client.uploads != 0 {
		t.Errorf("core was called %d times for an over-cap file", client.uploads)
	}

	rec = upload(t, h, "edge.pdf", "application/pdf", make([]byte, MaxUploadBytes))
	if rec.Code != http.StatusOK {
		t.Fatalf("at the cap: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if client.uploads != 1 {
		t.Errorf("core calls = %d, want 1", client.uploads)
	}
}

// Core's per-kind cap (images 10 MiB, text 5 MiB) is core's call; its text
// comes back unchanged with the same status.
func TestUpload_CoreKindCapRefusalPassesThrough(t *testing.T) {
	msg := "asset: image too large (max 10 MiB)"
	client := &fakeAssetClient{uploadErr: status.Error(codes.InvalidArgument, msg)}
	rec := upload(t, New(client, log.Nop()), "big.png", "image/png", make([]byte, 11<<20))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := errorText(t, rec); got != msg {
		t.Errorf("error = %q, want core's %q", got, msg)
	}
}

// "refuses never-allowed kinds, even renamed" and "takes the kind from the
// bytes": the byte check is core's, and its refusal text is passed through.
func TestUpload_CoreRefusalsPassThroughUnchanged(t *testing.T) {
	for _, msg := range []string{
		`asset: the contents of "letter.pdf" do not match its name (found application/vnd.openxmlformats-officedocument.wordprocessingml.document)`,
		"asset: files of this kind are not allowed (a web page, script or markup)",
		"asset: empty upload",
		"asset: this kind of file is switched off",
	} {
		client := &fakeAssetClient{uploadErr: status.Error(codes.InvalidArgument, msg)}
		rec := upload(t, New(client, log.Nop()), "letter.pdf", "application/pdf", []byte("PK\x03\x04word/"))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q: status = %d, want 400", msg, rec.Code)
		}
		if got := errorText(t, rec); got != msg {
			t.Errorf("error = %q, want %q", got, msg)
		}
		if client.uploads != 1 {
			t.Errorf("%q: renamed file must reach core for the byte check", msg)
		}
	}
}

// The status codes stay as they are today; Unavailable carries its own typed text.
func TestUpload_CoreErrorStatusCodesAreUnchanged(t *testing.T) {
	cases := []struct {
		code codes.Code
		want int
		text string
	}{
		{codes.Unavailable, http.StatusServiceUnavailable, "Uploads are unavailable right now."},
		{codes.Internal, http.StatusInternalServerError, "Failed to store image"},
		{codes.PermissionDenied, http.StatusForbidden, "Failed to store image"},
	}
	for _, tc := range cases {
		client := &fakeAssetClient{uploadErr: status.Error(tc.code, "secret internal detail")}
		rec := upload(t, New(client, log.Nop()), "r.pdf", "application/pdf", []byte("%PDF-1.4"))
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.code, rec.Code, tc.want)
		}
		if got := errorText(t, rec); got != tc.text {
			t.Errorf("%s: error = %q, want %q (internal text must not leak)", tc.code, got, tc.text)
		}
	}
}

// Early refusal on what is cheap to see: a never-allowed extension, whatever
// the bytes or the declared type say. Core is not called.
func TestUpload_NeverAllowedExtensionIsRefusedBeforeCore(t *testing.T) {
	names := []string{
		"setup.exe", "a.msi", "a.dmg", "a.app", "a.dll", "a.jar", "a.com", "a.bat", "a.cmd", "run.sh", "a.ps1", "a.vbs",
		"page.html", "page.htm", "image.svg", "data.xml", "a.xhtml", "app.js", "style.css",
		"macro.docm", "macro.xlsm", "macro.pptm",
		"UPPER.EXE", "Page.HTML", "report.pdf.exe",
	}
	for _, name := range names {
		client := &fakeAssetClient{uploadResp: &corev1.UploadAssetResponse{Asset: &corev1.Asset{Id: "a"}}}
		rec := upload(t, New(client, log.Nop()), name, "application/octet-stream", []byte("%PDF-1.4"))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
		if msg := errorText(t, rec); !strings.HasPrefix(msg, "asset: files of this kind are not allowed") {
			t.Errorf("%s: error = %q", name, msg)
		}
		if client.uploads != 0 {
			t.Errorf("%s: reached core", name)
		}
	}
}

// Names that look close to a refused one but are not, go on to core.
func TestUpload_OrdinaryNamesReachCore(t *testing.T) {
	for _, name := range []string{"report.pdf", "notes.txt", "notes.md", "rows.csv", "letter.docx", "deck.pptx", "clip.mp4", "noextension", "exe", "my.exe.pdf", ".hidden"} {
		client := &fakeAssetClient{uploadResp: &corev1.UploadAssetResponse{Asset: &corev1.Asset{Id: "a"}}}
		rec := upload(t, New(client, log.Nop()), name, "application/octet-stream", []byte("x"))
		if rec.Code != http.StatusOK || client.uploads != 1 {
			t.Errorf("%s: status = %d, core calls = %d, want 200 and 1", name, rec.Code, client.uploads)
		}
	}
}

func TestUpload_MissingFileMessageNamesAFile(t *testing.T) {
	body, ct := multipartBody(t, "wrongfield", "x.pdf", "application/pdf", []byte("x"))
	req := withStaff(httptest.NewRequest(http.MethodPost, "/api/assets", body), "user-1")
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	New(&fakeAssetClient{}, log.Nop()).Upload(rec, req)
	if got, want := errorText(t, rec), `Missing file — attach a single file under the "file" field`; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

// "keeps ${name} and serves it back as a download"
func TestServe_FileIsADownload(t *testing.T) {
	cases := []struct {
		name, contentType, kind string
	}{
		{"report.pdf", "application/pdf", "pdf"},
		{"letter.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "word"},
		{"clip.mp4", "video/mp4", "video"},
		{"notes.txt", "text/plain; charset=utf-8", "text"},
		{"notes.md", "text/markdown; charset=utf-8", "markdown"},
		{"rows.csv", "text/csv; charset=utf-8", "office"},
	}
	for _, tc := range cases {
		data := []byte("file bytes for " + tc.name)
		client := &fakeAssetClient{getResp: &corev1.GetAssetResponse{
			Data: data, ContentType: tc.contentType, SizeBytes: int64(len(data)), Filename: tc.name, ServeAs: "file", Kind: tc.kind,
		}}
		rec := serve(t, client, "f1")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", tc.name, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != tc.contentType {
			t.Errorf("%s: content-type = %q, want %q", tc.name, got, tc.contentType)
		}
		if got, want := rec.Header().Get("Content-Disposition"), `attachment; filename="`+tc.name+`"`; !strings.HasPrefix(got, want) {
			t.Errorf("%s: content-disposition = %q, want it to start with %q", tc.name, got, want)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: nosniff = %q", tc.name, got)
		}
		if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
			t.Errorf("%s: corp = %q", tc.name, got)
		}
		if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "sandbox") {
			t.Errorf("%s: csp = %q, want a sandbox", tc.name, got)
		}
		if got, _ := io.ReadAll(rec.Body); !bytes.Equal(got, data) {
			t.Errorf("%s: body differs", tc.name)
		}
	}
}

// "keeps serving an image inline"
func TestServe_ImageStaysInline(t *testing.T) {
	client := &fakeAssetClient{getResp: &corev1.GetAssetResponse{
		Data: []byte("PNG"), ContentType: "image/png", SizeBytes: 3, Filename: "logo.png", ServeAs: "image", Kind: "image",
	}}
	rec := serve(t, client, "i1")
	if got := rec.Header().Get("Content-Disposition"); got != "" {
		t.Errorf("content-disposition = %q, want none for an inline image", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("nosniff = %q", got)
	}
}

// Never run inline: anything core does not mark as an image, and an SVG even
// if it were mislabelled, is only ever a download.
func TestServe_OnlyAMarkedRasterImageIsInline(t *testing.T) {
	cases := []struct{ name, serveAs, contentType string }{
		{"no serve_as", "", "image/png"},
		{"unknown serve_as", "page", "image/png"},
		{"file with an html type", "file", "text/html"},
		{"image marked but html bytes", "image", "text/html"},
		{"image marked but svg", "image", "image/svg+xml"},
	}
	for _, tc := range cases {
		client := &fakeAssetClient{getResp: &corev1.GetAssetResponse{
			Data: []byte("x"), ContentType: tc.contentType, SizeBytes: 1, Filename: "a.bin", ServeAs: tc.serveAs,
		}}
		rec := serve(t, client, "x")
		if !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment") {
			t.Errorf("%s: content-disposition = %q, want attachment", tc.name, rec.Header().Get("Content-Disposition"))
		}
	}
}

// A stored name is quoted and encoded; it cannot break out of the header.
func TestServe_FilenameCannotInjectHeaders(t *testing.T) {
	for _, name := range []string{"a\"b.pdf", "a\r\nSet-Cookie: x=1.pdf", "café report.pdf", "semi;colon.pdf", ""} {
		client := &fakeAssetClient{getResp: &corev1.GetAssetResponse{
			Data: []byte("x"), ContentType: "application/pdf", SizeBytes: 1, Filename: name, ServeAs: "file",
		}}
		rec := serve(t, client, "x")
		cd := rec.Header().Get("Content-Disposition")
		if !strings.HasPrefix(cd, "attachment") {
			t.Errorf("%q: content-disposition = %q", name, cd)
		}
		if strings.ContainsAny(cd, "\r\n") || rec.Header().Get("Set-Cookie") != "" {
			t.Errorf("%q: header injection: %q", name, cd)
		}
	}
}

// "answers 404 for an id that was never stored" with the {error} body.
func TestServe_NotFoundBody(t *testing.T) {
	rec := serve(t, &fakeAssetClient{getErr: status.Error(codes.NotFound, "asset not found")}, "nope")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := errorText(t, rec); got != "Asset not found" {
		t.Errorf("error = %q", got)
	}
}
