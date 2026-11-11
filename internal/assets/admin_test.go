// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package assets

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// fakeStore is a stateful stand-in for core's AssetService: a delete removes
// the file, so the editor's read answers NotFound afterwards, as core does.
type fakeStore struct {
	corev1.AssetServiceClient
	files      []*corev1.StoredAsset
	listErr    error
	deleteErr  error
	lists      int
	deletes    int
	lastList   *corev1.ListAssetsRequest
	lastDelete *corev1.DeleteAssetRequest
}

func (f *fakeStore) ListAssets(_ context.Context, in *corev1.ListAssetsRequest, _ ...grpc.CallOption) (*corev1.ListAssetsResponse, error) {
	f.lists++
	f.lastList = in
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := &corev1.ListAssetsResponse{}
	for _, s := range f.files {
		if in.GetUnlinkedOnly() && s.GetLinked() {
			continue
		}
		out.Assets = append(out.Assets, s)
	}
	return out, nil
}

func (f *fakeStore) DeleteAsset(_ context.Context, in *corev1.DeleteAssetRequest, _ ...grpc.CallOption) (*corev1.DeleteAssetResponse, error) {
	f.deletes++
	f.lastDelete = in
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	for i, s := range f.files {
		if s.GetAsset().GetId() == in.GetId() {
			f.files = append(f.files[:i], f.files[i+1:]...)
			return &corev1.DeleteAssetResponse{
				Id: s.GetAsset().GetId(), Filename: s.GetAsset().GetFilename(), Kind: s.GetAsset().GetKind(), RemovedFrom: s.GetDocuments(),
			}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "asset not found")
}

func (f *fakeStore) GetAsset(_ context.Context, in *corev1.GetAssetRequest, _ ...grpc.CallOption) (*corev1.GetAssetResponse, error) {
	for _, s := range f.files {
		if s.GetAsset().GetId() == in.GetId() {
			return &corev1.GetAssetResponse{Data: []byte("x"), ContentType: s.GetAsset().GetContentType(), SizeBytes: 1, Filename: s.GetAsset().GetFilename(), ServeAs: s.GetAsset().GetServeAs()}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "asset not found")
}

func sampleFiles() []*corev1.StoredAsset {
	return []*corev1.StoredAsset{
		{
			Asset: &corev1.Asset{Id: "linked-1", Url: "/api/assets/linked-1", ContentType: "application/pdf", SizeBytes: 2048, Filename: "policy.pdf",
				CreatedByUserId: "user-7", CreatedAt: "2026-11-02T09:00:00Z", ServeAs: "file", Kind: "pdf"},
			Linked: true,
			Documents: []*corev1.AssetDocumentLink{
				{PolicyId: "pol-1", Title: "Visitor policy", Location: "policy"},
				{PolicyId: "pol-1", Title: "Visitor policy", Location: "appendix"},
			},
		},
		{
			Asset: &corev1.Asset{Id: "loose-1", Url: "/api/assets/loose-1", ContentType: "image/png", SizeBytes: 100, Filename: "logo.png",
				CreatedByUserId: "user-8", CreatedAt: "2026-11-01T09:00:00Z", ServeAs: "image", Kind: "image"},
		},
	}
}

func errorBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var e errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return e.Error
}

func asUser(r *http.Request, uid string, roles ...string) *http.Request {
	return r.WithContext(principal.WithClaims(r.Context(), principal.Static{UserIDValue: uid, EmailValue: uid + "@example.org", RolesValue: roles}))
}

func adminReq(method, target string) *http.Request {
	return asUser(httptest.NewRequest(method, target, nil), "admin-1", "site-admin")
}

func doList(h *Admin, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.List(rec, r)
	return rec
}

func doDelete(h *Admin, r *http.Request, id string) *httptest.ResponseRecorder {
	r.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	h.Delete(rec, r)
	return rec
}

type listBody struct {
	Assets []struct {
		ID              string `json:"id"`
		URL             string `json:"url"`
		Filename        string `json:"filename"`
		Kind            string `json:"kind"`
		ContentType     string `json:"contentType"`
		SizeBytes       int64  `json:"sizeBytes"`
		CreatedAt       string `json:"createdAt"`
		CreatedByUserID string `json:"createdByUserId"`
		Linked          bool   `json:"linked"`
		Documents       []struct {
			PolicyID string `json:"policyId"`
			Title    string `json:"title"`
			Location string `json:"location"`
		} `json:"documents"`
	} `json:"assets"`
}

func TestAdminList_ReturnsFilesWithLinkStatus(t *testing.T) {
	store := &fakeStore{files: sampleFiles()}
	rec := doList(NewAdmin(store, log.Nop()), adminReq(http.MethodGet, "/api/admin/assets"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got listBody
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Assets) != 2 {
		t.Fatalf("assets = %d, want 2", len(got.Assets))
	}
	a := got.Assets[0]
	if a.ID != "linked-1" || a.Filename != "policy.pdf" || a.Kind != "pdf" || a.ContentType != "application/pdf" || a.SizeBytes != 2048 ||
		a.CreatedAt != "2026-11-02T09:00:00Z" || a.CreatedByUserID != "user-7" || !a.Linked || a.URL != "/api/assets/linked-1" {
		t.Errorf("first = %+v", a)
	}
	if len(a.Documents) != 2 || a.Documents[0].PolicyID != "pol-1" || a.Documents[0].Title != "Visitor policy" || a.Documents[1].Location != "appendix" {
		t.Errorf("documents = %+v", a.Documents)
	}
	if got.Assets[1].Linked || got.Assets[1].Documents == nil || len(got.Assets[1].Documents) != 0 {
		t.Errorf("second = %+v, want unlinked with an empty documents list", got.Assets[1])
	}
	if store.lastList.GetUnlinkedOnly() {
		t.Error("unlinked_only was set without being asked")
	}
}

func TestAdminList_FiltersToUnlinked(t *testing.T) {
	store := &fakeStore{files: sampleFiles()}
	rec := doList(NewAdmin(store, log.Nop()), adminReq(http.MethodGet, "/api/admin/assets?unlinked=true"))
	var got listBody
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !store.lastList.GetUnlinkedOnly() {
		t.Error("unlinked_only not sent to core")
	}
	if len(got.Assets) != 1 || got.Assets[0].ID != "loose-1" {
		t.Errorf("assets = %+v, want only the unlinked file", got.Assets)
	}
}

func TestAdminList_EmptyIsAnEmptyArray(t *testing.T) {
	rec := doList(NewAdmin(&fakeStore{}, log.Nop()), adminReq(http.MethodGet, "/api/admin/assets"))
	if got := strings.TrimSpace(rec.Body.String()); got != `{"assets":[]}` {
		t.Errorf("body = %s", got)
	}
}

func TestAdmin_RefusesEveryoneButASiteAdmin(t *testing.T) {
	for name, roles := range map[string][]string{"reader": {"reader"}, "author": {"author"}, "template admin": {"template-admin"}, "compliance admin": {"compliance-admin"}, "none": nil} {
		store := &fakeStore{files: sampleFiles()}
		h := NewAdmin(store, log.Nop())
		list := doList(h, asUser(httptest.NewRequest(http.MethodGet, "/api/admin/assets", nil), "user-1", roles...))
		del := doDelete(h, asUser(httptest.NewRequest(http.MethodDelete, "/api/admin/assets/linked-1", nil), "user-1", roles...), "linked-1")
		if list.Code != http.StatusForbidden || del.Code != http.StatusForbidden {
			t.Errorf("%s: list = %d, delete = %d, want 403 for both", name, list.Code, del.Code)
		}
		if errorBody(t, del) == "" {
			t.Errorf("%s: no {error} text", name)
		}
		if store.lists != 0 || store.deletes != 0 || len(store.files) != 2 {
			t.Errorf("%s: core was reached (lists %d, deletes %d)", name, store.lists, store.deletes)
		}
	}
}

func TestAdmin_NoSessionIs401(t *testing.T) {
	store := &fakeStore{files: sampleFiles()}
	h := NewAdmin(store, log.Nop())
	if rec := doList(h, httptest.NewRequest(http.MethodGet, "/api/admin/assets", nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("list = %d, want 401", rec.Code)
	}
	if rec := doDelete(h, httptest.NewRequest(http.MethodDelete, "/api/admin/assets/x", nil), "x"); rec.Code != http.StatusUnauthorized {
		t.Errorf("delete = %d, want 401", rec.Code)
	}
	if store.lists+store.deletes != 0 {
		t.Error("core was reached without a session")
	}
}

type deleteBody struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	Kind        string `json:"kind"`
	RemovedFrom []struct {
		PolicyID string `json:"policyId"`
		Title    string `json:"title"`
		Location string `json:"location"`
	} `json:"removedFrom"`
}

func TestAdminDelete_UnlinkedFile(t *testing.T) {
	store := &fakeStore{files: sampleFiles()}
	rec := doDelete(NewAdmin(store, log.Nop()), adminReq(http.MethodDelete, "/api/admin/assets/loose-1"), "loose-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got deleteBody
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "loose-1" || got.Filename != "logo.png" || got.Kind != "image" {
		t.Errorf("body = %+v", got)
	}
	if got.RemovedFrom == nil || len(got.RemovedFrom) != 0 {
		t.Errorf("removedFrom = %+v, want an empty list", got.RemovedFrom)
	}
	if !strings.Contains(rec.Body.String(), `"removedFrom":[]`) {
		t.Errorf("body = %s, want removedFrom as []", rec.Body.String())
	}
}

func TestAdminDelete_LinkedFileSaysWhereItCameOut(t *testing.T) {
	store := &fakeStore{files: sampleFiles()}
	rec := doDelete(NewAdmin(store, log.Nop()), adminReq(http.MethodDelete, "/api/admin/assets/linked-1"), "linked-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got deleteBody
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "linked-1" || got.Kind != "pdf" || len(got.RemovedFrom) != 2 || got.RemovedFrom[0].Title != "Visitor policy" || got.RemovedFrom[1].Location != "appendix" {
		t.Errorf("body = %+v", got)
	}
}

// The admin is the signed-in user from the session; nothing in the request
// can name someone else.
func TestAdminDelete_ActorIsTheSignedInAdmin(t *testing.T) {
	store := &fakeStore{files: sampleFiles()}
	r := adminReq(http.MethodDelete, "/api/admin/assets/loose-1?actor_user_id=someone-else")
	r.Header.Set("X-Actor-User-Id", "someone-else")
	doDelete(NewAdmin(store, log.Nop()), r, "loose-1")
	if store.lastDelete.GetActorUserId() != "admin-1" || store.lastDelete.GetId() != "loose-1" {
		t.Errorf("core got %+v", store.lastDelete)
	}
}

func TestAdminDelete_CoreErrorsMapToStatuses(t *testing.T) {
	cases := []struct {
		code codes.Code
		want int
	}{
		{codes.NotFound, http.StatusNotFound},
		{codes.InvalidArgument, http.StatusBadRequest},
		{codes.Unavailable, http.StatusServiceUnavailable},
		{codes.FailedPrecondition, http.StatusConflict},
		{codes.Internal, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		store := &fakeStore{deleteErr: status.Error(tc.code, "secret internal detail /var/db")}
		rec := doDelete(NewAdmin(store, log.Nop()), adminReq(http.MethodDelete, "/api/admin/assets/x"), "x")
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.code, rec.Code, tc.want)
		}
		if strings.Contains(rec.Body.String(), "secret internal detail") && tc.code != codes.InvalidArgument {
			t.Errorf("%s: core's internal text leaked: %s", tc.code, rec.Body.String())
		}
		if errorBody(t, rec) == "" {
			t.Errorf("%s: no {error} text", tc.code)
		}
	}
}

func TestAdminList_CoreErrorsMapToStatuses(t *testing.T) {
	for code, want := range map[codes.Code]int{codes.Unavailable: 503, codes.FailedPrecondition: 409, codes.Internal: 500} {
		store := &fakeStore{listErr: status.Error(code, "detail")}
		rec := doList(NewAdmin(store, log.Nop()), adminReq(http.MethodGet, "/api/admin/assets"))
		if rec.Code != want {
			t.Errorf("%s: status = %d, want %d", code, rec.Code, want)
		}
	}
}

func TestAdminDelete_MissingIDIs400(t *testing.T) {
	store := &fakeStore{}
	rec := doDelete(NewAdmin(store, log.Nop()), adminReq(http.MethodDelete, "/api/admin/assets/"), "")
	if rec.Code != http.StatusBadRequest || store.deletes != 0 {
		t.Errorf("status = %d, core deletes = %d", rec.Code, store.deletes)
	}
}

// "the 404 after a delete": the editor's read keeps working for a file that
// is still there, and answers 404 once it is deleted.
func TestAdminDelete_EditorReadIs404AfterwardsAndStillWorksForOthers(t *testing.T) {
	store := &fakeStore{files: sampleFiles()}
	get := func(id string) int {
		req := asUser(httptest.NewRequest(http.MethodGet, "/api/assets/"+id, nil), "user-1", "reader")
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		New(store, log.Nop()).Serve(rec, req)
		return rec.Code
	}
	if get("linked-1") != http.StatusOK || get("loose-1") != http.StatusOK {
		t.Fatal("both files should be readable before the delete")
	}
	if rec := doDelete(NewAdmin(store, log.Nop()), adminReq(http.MethodDelete, "/api/admin/assets/linked-1"), "linked-1"); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	if got := get("linked-1"); got != http.StatusNotFound {
		t.Errorf("deleted file read = %d, want 404", got)
	}
	if got := get("loose-1"); got != http.StatusOK {
		t.Errorf("other file read = %d, want 200", got)
	}
	// A second delete of the same file is a 404, not an error page.
	if rec := doDelete(NewAdmin(store, log.Nop()), adminReq(http.MethodDelete, "/api/admin/assets/linked-1"), "linked-1"); rec.Code != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", rec.Code)
	}
}

// The routes sit behind the session gate the caller hands in (session and
// CSRF in the server), so a request the gate stops never reaches core.
func TestAdminRegister_RoutesAreBehindTheGate(t *testing.T) {
	store := &fakeStore{files: sampleFiles()}
	gated := 0
	gate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gated++
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		})
	}
	mux := http.NewServeMux()
	NewAdmin(store, log.Nop()).Register(mux, gate)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/admin/assets"},
		{http.MethodDelete, "/api/admin/assets/linked-1"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, bytes.NewReader(nil)))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want the gate's 401", tc.method, tc.path, rec.Code)
		}
	}
	if gated != 2 || store.lists+store.deletes != 0 {
		t.Errorf("gate ran %d times, core reached %d times", gated, store.lists+store.deletes)
	}
	// Other methods on the paths are not routed to the handlers.
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/admin/assets"},
		{http.MethodGet, "/api/admin/assets/linked-1"},
		{http.MethodPut, "/api/admin/assets/linked-1"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 or 405", tc.method, tc.path, rec.Code)
		}
	}
}
