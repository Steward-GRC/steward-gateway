// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package assets

import (
	"encoding/json"
	"net/http"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	authz "github.com/Steward-GRC/steward-gateway/internal/authz"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// Admin serves the site admin's view of the stored editor files: a list with
// where each is used, and a delete that works at once even for a file a
// document still links to. Core removes the bytes, the record and the cards,
// and writes the audit entry (who, when, which file); the gateway checks the
// caller is a site admin and adds nothing about the caller's network. Reporting
// attachments are another store and never appear here.
type Admin struct {
	client corev1.AssetServiceClient
	logger log.Logger
}

// NewAdmin returns an Admin over core's AssetService.
func NewAdmin(client corev1.AssetServiceClient, logger log.Logger) *Admin {
	return &Admin{client: client, logger: logger}
}

// Register mounts the admin routes behind gate, the session gate that also
// requires the CSRF token (the list is read with the token like any other
// admin call):
//
//	GET    /api/admin/assets[?unlinked=true]
//	DELETE /api/admin/assets/{id}
func (a *Admin) Register(mux *http.ServeMux, gate func(http.Handler) http.Handler) {
	mux.Handle("GET /api/admin/assets", gate(http.HandlerFunc(a.List)))
	mux.Handle("DELETE /api/admin/assets/{id}", gate(http.HandlerFunc(a.Delete)))
}

type documentLink struct {
	PolicyID string `json:"policyId"`
	Title    string `json:"title"`
	Location string `json:"location"`
}

type storedFile struct {
	ID              string         `json:"id"`
	URL             string         `json:"url"`
	Filename        string         `json:"filename"`
	Kind            string         `json:"kind"`
	ContentType     string         `json:"contentType"`
	SizeBytes       int64          `json:"sizeBytes"`
	CreatedAt       string         `json:"createdAt"`
	CreatedByUserID string         `json:"createdByUserId"`
	Linked          bool           `json:"linked"`
	Documents       []documentLink `json:"documents"`
}

type listResponse struct {
	Assets []storedFile `json:"assets"`
}

type deleteResponse struct {
	ID          string         `json:"id"`
	Filename    string         `json:"filename"`
	Kind        string         `json:"kind"`
	RemovedFrom []documentLink `json:"removedFrom"`
}

func links(in []*corev1.AssetDocumentLink) []documentLink {
	out := make([]documentLink, 0, len(in))
	for _, l := range in {
		out = append(out, documentLink{PolicyID: l.GetPolicyId(), Title: l.GetTitle(), Location: l.GetLocation()})
	}
	return out
}

// adminStatus maps core's refusals for the admin calls. Only an invalid
// request keeps core's text; the rest get a fixed one so no internal detail
// reaches the browser.
func adminStatus(err error, what string) (int, string) {
	switch status.Code(err) {
	case codes.InvalidArgument:
		return http.StatusBadRequest, status.Convert(err).Message()
	case codes.NotFound:
		return http.StatusNotFound, "Asset not found"
	case codes.Unavailable:
		return http.StatusServiceUnavailable, "Failed to " + what + " files"
	case codes.FailedPrecondition:
		return http.StatusConflict, "File administration is not available"
	default:
		return http.StatusInternalServerError, "Failed to " + what + " files"
	}
}

// requireSiteAdmin answers 401 without a signed-in user and 403 for anyone who
// is not a site admin, and returns the admin's user id otherwise.
func (a *Admin) requireSiteAdmin(w http.ResponseWriter, r *http.Request, op string) (string, bool) {
	lg := a.logger.Ctx(r.Context())
	c, ok := principal.FromContext(r.Context())
	if !ok || c.UserID() == "" {
		lg.Debug("admin assets: no session", log.F("op", op))
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return "", false
	}
	if !principal.HasRole(c, string(authz.RoleSiteAdmin)) {
		lg.Warn("admin assets: refused, not a site admin", log.F("op", op), log.F("user_id", c.UserID()))
		writeError(w, http.StatusForbidden, "site-admin role required")
		return "", false
	}
	return c.UserID(), true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// List serves GET /api/admin/assets: the stored files, newest first as core
// orders them, with the documents each is used in. ?unlinked=true keeps only
// the files no document links to.
func (a *Admin) List(w http.ResponseWriter, r *http.Request) {
	adminID, ok := a.requireSiteAdmin(w, r, "list")
	if !ok {
		return
	}
	lg := a.logger.Ctx(r.Context())
	unlinked := r.URL.Query().Get("unlinked") == "true"
	lg.Debug("admin assets: list", log.F("admin_user_id", adminID), log.F("unlinked_only", unlinked))

	start := time.Now()
	resp, err := a.client.ListAssets(r.Context(), &corev1.ListAssetsRequest{UnlinkedOnly: unlinked})
	took := log.F("duration_ms", time.Since(start).Milliseconds())
	if err != nil {
		code, msg := adminStatus(err, "list")
		lg.Warn("admin assets: list refused by core", log.F("grpc_code", status.Code(err).String()), took)
		writeError(w, code, msg)
		return
	}

	out := listResponse{Assets: make([]storedFile, 0, len(resp.GetAssets()))}
	for _, s := range resp.GetAssets() {
		f := s.GetAsset()
		out.Assets = append(out.Assets, storedFile{
			ID:              f.GetId(),
			URL:             f.GetUrl(),
			Filename:        f.GetFilename(),
			Kind:            f.GetKind(),
			ContentType:     f.GetContentType(),
			SizeBytes:       f.GetSizeBytes(),
			CreatedAt:       f.GetCreatedAt(),
			CreatedByUserID: f.GetCreatedByUserId(),
			Linked:          s.GetLinked(),
			Documents:       links(s.GetDocuments()),
		})
	}
	lg.Info("admin assets: listed", log.F("count", len(out.Assets)), log.F("unlinked_only", unlinked), took)
	writeJSON(w, out)
}

// Delete serves DELETE /api/admin/assets/{id}: the file goes at once, linked
// or not, and the answer says which documents it was taken out of. The actor
// core records is the signed-in admin, never the request.
func (a *Admin) Delete(w http.ResponseWriter, r *http.Request) {
	adminID, ok := a.requireSiteAdmin(w, r, "delete")
	if !ok {
		return
	}
	lg := a.logger.Ctx(r.Context())
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Missing asset id")
		return
	}
	lg.Info("admin assets: delete requested", log.F("asset_id", id), log.F("admin_user_id", adminID))

	start := time.Now()
	resp, err := a.client.DeleteAsset(r.Context(), &corev1.DeleteAssetRequest{Id: id, ActorUserId: adminID})
	took := log.F("duration_ms", time.Since(start).Milliseconds())
	if err != nil {
		code, msg := adminStatus(err, "delete")
		lg.Warn("admin assets: delete refused by core", log.F("asset_id", id), log.F("grpc_code", status.Code(err).String()), took)
		writeError(w, code, msg)
		return
	}

	out := deleteResponse{
		ID:          resp.GetId(),
		Filename:    resp.GetFilename(),
		Kind:        resp.GetKind(),
		RemovedFrom: links(resp.GetRemovedFrom()),
	}
	lg.Info("admin assets: deleted", log.F("asset_id", out.ID), log.F("kind", out.Kind),
		log.F("documents", len(out.RemovedFrom)), log.F("admin_user_id", adminID), took)
	writeJSON(w, out)
}
