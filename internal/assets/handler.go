// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package assets serves the editor's images and files over core's
// AssetService: a multipart upload that core checks and stores, and a read that
// streams the stored bytes back from /api/assets/{id}. An image is served
// inline; any other file only as a download. The object store stays inside the
// cluster, so the gateway carries the bytes both ways instead of handing out
// presigned URLs. Both routes sit behind the session gate.
package assets

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

const (
	// MaxUploadBytes is core's largest cap of any kind (its max_file_bytes:
	// 25 MiB for files; images stay 10 MiB and text 5 MiB, which core
	// enforces per kind). multipartOverhead leaves room for the multipart
	// framing, so a file right at the cap isn't refused on framing bytes; the
	// size check still enforces the cap.
	MaxUploadBytes    = 25 << 20
	multipartOverhead = 64 << 10

	// maxAssetCallBytes lifts the per-call gRPC limits above the 4 MiB
	// default so a full-size asset travels in one message; it matches core's
	// 32 MiB message limit.
	maxAssetCallBytes = 32 << 20

	// serveAsImage is core's serve_as value for a file shown inline.
	serveAsImage = "image"
)

// refusedExtensions are the names the gateway turns away before sending the
// bytes on: executables and installers, web and script files, and Office
// files that carry macros. Core refuses the same kinds by their bytes; this
// only saves the transfer. It is not the allow list, which is core's admin
// setting.
var refusedExtensions = map[string]struct{}{
	"exe": {}, "msi": {}, "dmg": {}, "app": {}, "dll": {}, "jar": {}, "com": {}, "bat": {}, "cmd": {}, "sh": {}, "ps1": {}, "vbs": {},
	"html": {}, "htm": {}, "svg": {}, "xml": {}, "xhtml": {}, "js": {}, "css": {},
	"docm": {}, "xlsm": {}, "pptm": {},
}

// refusedName reports whether name ends in a never-allowed extension.
func refusedName(name string) (string, bool) {
	dot := strings.LastIndexByte(name, '.')
	if dot <= 0 || dot == len(name)-1 {
		return "", false
	}
	ext := strings.ToLower(name[dot+1:])
	_, refused := refusedExtensions[ext]
	return ext, refused
}

// downloadDisposition builds a Content-Disposition for a stored name, as the
// mock does: a quoted ASCII form and a UTF-8 encoded form, neither of which
// can break out of the header.
func downloadDisposition(name string) string {
	quoted := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	if quoted == "" {
		quoted = "download"
	}
	return `attachment; filename="` + quoted + `"; filename*=UTF-8''` + strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
}

// inline reports whether a stored file may be shown in the page: core marked
// it an image and the type is a raster image, never SVG.
func inline(serveAs, contentType string) bool {
	if serveAs != serveAsImage {
		return false
	}
	ct := strings.ToLower(contentType)
	return strings.HasPrefix(ct, "image/") && !strings.HasPrefix(ct, "image/svg")
}

// Handler serves the asset upload and read routes.
type Handler struct {
	client corev1.AssetServiceClient
	logger log.Logger
}

// New returns a Handler over core's AssetService.
func New(client corev1.AssetServiceClient, logger log.Logger) *Handler {
	return &Handler{client: client, logger: logger}
}

type uploadResponse struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	ContentType string `json:"contentType"`
	SizeBytes   int64  `json:"sizeBytes"`
	Filename    string `json:"filename,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, statusCode int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

func httpStatusForGRPC(err error) int {
	switch status.Code(err) {
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.NotFound:
		return http.StatusNotFound
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	case codes.PermissionDenied:
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// Upload serves POST /api/assets: one multipart file part named "file" goes
// to core's UploadAsset, which checks and stores it. The creator is the
// signed-in user from the session, never the request.
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	claims, ok := principal.FromContext(r.Context())
	if !ok || claims.UserID() == "" {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	lg := h.logger.Ctx(r.Context())

	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes+multipartOverhead)
	if err := r.ParseMultipartForm(MaxUploadBytes + multipartOverhead); err != nil { // #nosec G120 -- the body is bounded by MaxBytesReader above
		lg.Debug("asset upload: malformed or oversized form")
		writeError(w, http.StatusBadRequest, "File too large or malformed upload — max upload size is 25 MB")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, `Missing file — attach a single file under the "file" field`)
		return
	}
	defer func() { _ = file.Close() }()

	name := filepath.Base(header.Filename)
	if ext, refused := refusedName(name); refused {
		lg.Debug("asset upload: refused by extension before core", log.F("extension", ext))
		writeError(w, http.StatusBadRequest, "asset: files of this kind are not allowed (."+ext+")")
		return
	}

	if header.Size > MaxUploadBytes {
		writeError(w, http.StatusBadRequest, "File too large — max upload size is 25 MB")
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxUploadBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Failed to read uploaded file")
		return
	}
	if int64(len(data)) > MaxUploadBytes {
		writeError(w, http.StatusBadRequest, "File too large — max upload size is 25 MB")
		return
	}

	start := time.Now()
	resp, err := h.client.UploadAsset(r.Context(), &corev1.UploadAssetRequest{
		Data:            data,
		ContentType:     header.Header.Get("Content-Type"),
		Filename:        name,
		CreatedByUserId: claims.UserID(),
	}, grpc.MaxCallSendMsgSize(maxAssetCallBytes))
	took := log.F("duration_ms", time.Since(start).Milliseconds())
	if err != nil {
		code := httpStatusForGRPC(err)
		lg.Warn("asset upload: core refused", log.F("grpc_code", status.Code(err).String()), took)
		msg := "Failed to store image"
		if code == http.StatusBadRequest {
			msg = status.Convert(err).Message()
		}
		writeError(w, code, msg)
		return
	}

	a := resp.GetAsset()
	lg.Info("asset upload: stored", log.F("asset_id", a.GetId()), log.F("kind", a.GetKind()), log.F("size_bytes", a.GetSizeBytes()), took)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(uploadResponse{
		ID:          a.GetId(),
		URL:         a.GetUrl(),
		ContentType: a.GetContentType(),
		SizeBytes:   a.GetSizeBytes(),
		Filename:    a.GetFilename(),
	})
}

// Serve serves GET /api/assets/{id} with the stored content type. It must
// stay a pure read: it is mounted behind the session gate's safe-read
// variant, which skips the CSRF header so an <img> can load it.
func (h *Handler) Serve(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Missing asset id")
		return
	}

	start := time.Now()
	resp, err := h.client.GetAsset(r.Context(), &corev1.GetAssetRequest{Id: id}, grpc.MaxCallRecvMsgSize(maxAssetCallBytes))
	if err != nil {
		h.logger.Ctx(r.Context()).Debug("asset read: core refused", log.F("asset_id", id),
			log.F("grpc_code", status.Code(err).String()), log.F("duration_ms", time.Since(start).Milliseconds()))
		writeError(w, httpStatusForGRPC(err), "Asset not found")
		return
	}

	ct := resp.GetContentType()
	if ct == "" {
		ct = "application/octet-stream"
	}
	asImage := inline(resp.GetServeAs(), ct)
	log.Trace(h.logger.Ctx(r.Context()), "asset read: serving", log.F("asset_id", id), log.F("kind", resp.GetKind()),
		log.F("inline", asImage), log.F("size_bytes", resp.GetSizeBytes()))
	w.Header().Set("Content-Type", ct)
	if !asImage {
		// A file is only ever a download, and nothing in it may run in the
		// page's origin.
		w.Header().Set("Content-Disposition", downloadDisposition(resp.GetFilename()))
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	}
	w.Header().Set("Content-Length", strconv.FormatInt(resp.GetSizeBytes(), 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The read path skips CSRF, so keep the bytes away from cross-origin
	// documents as well.
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Cache-Control", "private, max-age=86400, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp.GetData())
}
