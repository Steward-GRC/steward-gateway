// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package notifyunsub

import (
	"context"
	"encoding/json"
	"net/http"

	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CategorySetter is the narrow slice of obligationsv1.NotifPrefServiceClient the
// handler needs: apply a category cadence for a user. The real gRPC client
// satisfies it; tests supply a fake.
type CategorySetter interface {
	SetCategoryCadence(ctx context.Context, in *obligationsv1.SetCategoryCadenceRequest, opts ...grpc.CallOption) (*obligationsv1.SetCategoryCadenceResponse, error)
}

// Handlers serves the unauthenticated one-click unsubscribe + manage-preferences
// endpoints. It verifies the signed token a mail client presents and maps an
// unsubscribe to "set that category OFF" via obligations'
// NotifPrefService. A mandatory category (compliance/security/transactional) is
// rejected server-side by the compliance floor (InvalidArgument); the endpoint
// then points the user at their preferences page instead of erroring.
type Handlers struct {
	verifier *Verifier
	prefs    CategorySetter
	prefsURL string
}

// New returns Handlers wired to the token verifier, the obligations NotifPref
// client, and the preferences-page URL browser clicks redirect to.
func New(verifier *Verifier, prefs CategorySetter, prefsURL string) *Handlers {
	return &Handlers{verifier: verifier, prefs: prefs, prefsURL: prefsURL}
}

// OneClickHandler serves POST /notify/unsubscribe — the RFC 8058 one-click path
// a mail provider POSTs directly (no credentials). It always responds 2xx for a
// valid token (a mandatory category is "handled" by pointing at preferences, not
// by erroring) so the provider records the unsubscribe as honored.
func (h *Handlers) OneClickHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		claims, ok := h.verify(w, r)
		if !ok {
			return
		}
		cat, ok := categoryToProto(claims.Category)
		if !ok {
			writeJSONErr(w, http.StatusBadRequest, "unknown category")
			return
		}
		switch err := h.setOff(r.Context(), claims.UserID, cat); status.Code(err) {
		case codes.OK:
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "unsubscribed", "category": claims.Category})
		case codes.InvalidArgument:
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "see_preferences", "preferencesUrl": h.prefsURL})
		default:
			writeJSONErr(w, http.StatusBadGateway, "could not apply preference")
		}
	}
}

// ManageHandler serves GET /notify/unsubscribe — the browser path (a footer link
// click, or a mail client opening the List-Unsubscribe URL). It applies the
// unsubscribe when it can and always lands the user on their preferences page so
// they can review/adjust, including when the category is mandatory.
func (h *Handlers) ManageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := h.verifyHTML(w, r)
		if !ok {
			return
		}
		if cat, ok := categoryToProto(claims.Category); ok {
			_ = h.setOff(r.Context(), claims.UserID, cat)
		}
		http.Redirect(w, r, h.prefsURL, http.StatusFound)
	}
}

// setOff calls SetCategoryCadence(OFF) for (userID, category), returning the
// gRPC error verbatim so callers can branch on its status code.
func (h *Handlers) setOff(ctx context.Context, userID string, cat obligationsv1.NotifCategory) error {
	_, err := h.prefs.SetCategoryCadence(ctx, &obligationsv1.SetCategoryCadenceRequest{
		UserId:   userID,
		Category: cat,
		Cadence:  obligationsv1.NotifCadence_NOTIF_CADENCE_OFF,
	})
	return err
}

// verify pulls the token query param and verifies it as an unsubscribe token,
// writing a JSON error and returning ok=false on any failure.
func (h *Handlers) verify(w http.ResponseWriter, r *http.Request) (Claims, bool) {
	token := r.URL.Query().Get("token")
	claims, err := h.verifier.Verify(token, PurposeUnsubscribe)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid or expired unsubscribe link")
		return Claims{}, false
	}
	return claims, true
}

// verifyHTML is verify's browser-facing twin: a bad token yields a small plain
// 400 rather than JSON.
func (h *Handlers) verifyHTML(w http.ResponseWriter, r *http.Request) (Claims, bool) {
	token := r.URL.Query().Get("token")
	claims, err := h.verifier.Verify(token, PurposeUnsubscribe)
	if err != nil {
		http.Error(w, "This unsubscribe link is invalid or has expired.", http.StatusBadRequest)
		return Claims{}, false
	}
	return claims, true
}

func writeJSONErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

// categoryToProto maps a lowercase category string (as carried in
// the token) to the obligations proto enum.
func categoryToProto(cat string) (obligationsv1.NotifCategory, bool) {
	switch cat {
	case "compliance":
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE, true
	case "security":
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_SECURITY, true
	case "transactional":
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_TRANSACTIONAL, true
	case "workflow":
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_WORKFLOW, true
	case "informational":
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_INFORMATIONAL, true
	default:
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_UNSPECIFIED, false
	}
}
