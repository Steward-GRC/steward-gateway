// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package assets serves the editor's images over core's AssetService: a
// multipart upload that core stores, and a read that streams the stored bytes
// back from /api/assets/{id}. The object store stays inside the cluster, so
// the gateway carries the bytes both ways instead of handing out presigned
// URLs. Both routes sit behind the session gate.
package assets

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

const (
	// MaxUploadBytes matches core's asset size cap. multipartOverhead leaves
	// room for the multipart framing, so a file right at the cap isn't
	// refused on framing bytes; the size check still enforces the cap.
	MaxUploadBytes    = 10 << 20
	multipartOverhead = 64 << 10

	// maxAssetCallBytes lifts the per-call gRPC limits above the 4 MiB
	// default so a full-size asset travels in one message; core matches it.
	maxAssetCallBytes = 16 << 20
)

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
		writeError(w, http.StatusBadRequest, "File too large or malformed upload — max upload size is 10 MB")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, `Missing file — attach a single image under the "file" field`)
		return
	}
	defer func() { _ = file.Close() }()

	if header.Size > MaxUploadBytes {
		writeError(w, http.StatusBadRequest, "File too large — max upload size is 10 MB")
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxUploadBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Failed to read uploaded file")
		return
	}
	if int64(len(data)) > MaxUploadBytes {
		writeError(w, http.StatusBadRequest, "File too large — max upload size is 10 MB")
		return
	}

	start := time.Now()
	resp, err := h.client.UploadAsset(r.Context(), &corev1.UploadAssetRequest{
		Data:            data,
		ContentType:     header.Header.Get("Content-Type"),
		Filename:        filepath.Base(header.Filename),
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
	lg.Info("asset upload: stored", log.F("asset_id", a.GetId()), log.F("size_bytes", a.GetSizeBytes()), took)
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
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.FormatInt(resp.GetSizeBytes(), 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The read path skips CSRF, so keep the bytes away from cross-origin
	// documents as well.
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Cache-Control", "private, max-age=86400, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp.GetData())
}
