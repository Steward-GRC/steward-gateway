// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// TestUserLabelEmailIsNullableInSchema asserts against the compiled schema
// (the source of truth) that email exists on UserLabel and is NULLABLE, while
// id/name keep their existing non-null contract. A non-null email would break
// every existing consumer the moment identity holds a user without one.
func TestUserLabelEmailIsNullableInSchema(t *testing.T) {
	schema := resolvers.NewExecutableSchema(resolvers.Config{}).Schema()
	def := schema.Types["UserLabel"]
	if def == nil {
		t.Fatal("UserLabel type missing from schema")
	}
	got := map[string]string{}
	for _, f := range def.Fields {
		got[f.Name] = f.Type.String()
	}
	if got["id"] != "ID!" {
		t.Errorf("UserLabel.id: got %q want %q", got["id"], "ID!")
	}
	if got["name"] != "String!" {
		t.Errorf("UserLabel.name: got %q want %q", got["name"], "String!")
	}
	if got["email"] != "String" {
		t.Errorf("UserLabel.email must be nullable String, got %q", got["email"])
	}
}

// TestSearchUsersReturnsEmail verifies searchUsers populates email from the
// user rows ListUsersByEmail already returns — the RPC response carries email
// today (it is the field being substring-matched), so no second call is made.
func TestSearchUsersReturnsEmail(t *testing.T) {
	read := &fakeReadClient{
		listResp: &identityv1.ListUsersByEmailResponse{
			Users: []*identityv1.User{
				{Id: "u-1", Name: "Alice Example", Email: "alice@example.org"},
				{Id: "u-2", Name: "Alice Example", Email: "bob@example.org"},
			},
		},
	}
	out, err := resolvers.SearchUsersResolver(ctxWithUser(t, "u-caller"), read, "alice", nil)
	if err != nil {
		t.Fatalf("SearchUsersResolver: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 results, got %d", len(out))
	}
	// Two identically-named accounts must now be distinguishable.
	if out[0].Email == nil || *out[0].Email != "alice@example.org" {
		t.Errorf("result[0].Email: got %v want %q", derefStr(out[0].Email), "alice@example.org")
	}
	if out[1].Email == nil || *out[1].Email != "bob@example.org" {
		t.Errorf("result[1].Email: got %v want %q", derefStr(out[1].Email), "bob@example.org")
	}
	if out[0].Name != "Alice Example" || out[1].Name != "Alice Example" {
		t.Errorf("names must be unchanged: %q / %q", out[0].Name, out[1].Name)
	}
}

// TestSearchUsersEmailNilWhenUserHasNoEmail verifies a user with no email
// resolves to null rather than an empty string or an error.
func TestSearchUsersEmailNilWhenUserHasNoEmail(t *testing.T) {
	read := &fakeReadClient{
		listResp: &identityv1.ListUsersByEmailResponse{
			Users: []*identityv1.User{
				{Id: "u-9", Name: "Emailless Account", Email: ""},
			},
		},
	}
	out, err := resolvers.SearchUsersResolver(ctxWithUser(t, "u-caller"), read, "emailless", nil)
	if err != nil {
		t.Fatalf("SearchUsersResolver: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out))
	}
	if out[0].Email != nil {
		t.Errorf("Email must be nil for a user with no email, got %q", *out[0].Email)
	}
	if out[0].Name != "Emailless Account" {
		t.Errorf("Name: got %q", out[0].Name)
	}
}

// TestSearchUsersMakesNoExtraRPCForEmail guards the "no second round-trip"
// constraint: one ListUsersByEmail call, and GetUser is never dialed.
func TestSearchUsersMakesNoExtraRPCForEmail(t *testing.T) {
	read := &fakeReadClient{
		listResp: &identityv1.ListUsersByEmailResponse{
			Users: []*identityv1.User{
				{Id: "u-1", Name: "Alice Smith", Email: "alice@example.com"},
			},
		},
	}
	if _, err := resolvers.SearchUsersResolver(ctxWithUser(t, "u-caller"), read, "alice", nil); err != nil {
		t.Fatalf("SearchUsersResolver: %v", err)
	}
	if read.lastGetUserReq != nil {
		t.Fatalf("GetUser must not be dialed to source email, got %+v", read.lastGetUserReq)
	}
}

// TestResolveUserLabelsReturnsEmail verifies resolveUserLabels populates email
// from the same GetUser response it already reads the display name from.
func TestResolveUserLabelsReturnsEmail(t *testing.T) {
	id := &labelIdentityFake{users: map[string]*identityv1.User{
		"u-1": {Id: "u-1", Name: "Alice Example", Email: "alice@example.org"},
		"u-2": {Id: "u-2", Name: "Alice Example", Email: "carol@example.org"},
	}}
	out, err := resolvers.ResolveUserLabelsResolver(ctxWithUser(t, "u-caller"), id, []string{"u-1", "u-2"})
	if err != nil {
		t.Fatalf("ResolveUserLabelsResolver: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(out))
	}
	if out[0].Name != "Alice Example" || out[0].Email == nil || *out[0].Email != "alice@example.org" {
		t.Errorf("label[0]: name=%q email=%v", out[0].Name, derefStr(out[0].Email))
	}
	if out[1].Name != "Alice Example" || out[1].Email == nil || *out[1].Email != "carol@example.org" {
		t.Errorf("label[1]: name=%q email=%v", out[1].Name, derefStr(out[1].Email))
	}
	// One GetUser per distinct id — the name+email pair comes from the same call.
	if id.getUserN != 2 {
		t.Errorf("expected 2 GetUser calls (one per id), got %d", id.getUserN)
	}
}

// TestResolveUserLabelsEmailNilWhenUserHasNoEmail verifies null (not "") for a
// user identity holds with no email address.
func TestResolveUserLabelsEmailNilWhenUserHasNoEmail(t *testing.T) {
	id := &labelIdentityFake{users: map[string]*identityv1.User{
		"u-3": {Id: "u-3", Name: "Emailless Account", Email: ""},
	}}
	out, err := resolvers.ResolveUserLabelsResolver(ctxWithUser(t, "u-caller"), id, []string{"u-3"})
	if err != nil {
		t.Fatalf("ResolveUserLabelsResolver: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 label, got %d", len(out))
	}
	if out[0].Email != nil {
		t.Errorf("Email must be nil for a user with no email, got %q", *out[0].Email)
	}
	if out[0].Name != "Emailless Account" {
		t.Errorf("Name: got %q", out[0].Name)
	}
}

// TestResolveUserLabelsUnknownIDKeepsIDFallbackAndNilEmail preserves the
// existing miss behaviour (name=id so the UI always renders something) and
// pins email to nil on a miss rather than leaking the raw id into it.
func TestResolveUserLabelsUnknownIDKeepsIDFallbackAndNilEmail(t *testing.T) {
	id := &labelIdentityFake{users: map[string]*identityv1.User{}}
	out, err := resolvers.ResolveUserLabelsResolver(ctxWithUser(t, "u-caller"), id, []string{"u-missing"})
	if err != nil {
		t.Fatalf("ResolveUserLabelsResolver: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 label, got %d", len(out))
	}
	if out[0].Name != "u-missing" {
		t.Errorf("miss must fall back to the id, got %q", out[0].Name)
	}
	if out[0].Email != nil {
		t.Errorf("miss must yield a nil email, got %q", *out[0].Email)
	}
}

// TestSearchUsersGraphQLIDNameOnlyStillWorks is the backward-compatibility
// regression: an EXISTING caller that selects only { id name } — every picker
// in the estate today — must keep working unchanged against the widened type.
func TestSearchUsersGraphQLIDNameOnlyStillWorks(t *testing.T) {
	read := &fakeReadClient{
		listResp: &identityv1.ListUsersByEmailResponse{
			Users: []*identityv1.User{
				{Id: "u-1", Name: "Alice Smith", Email: "alice@example.com"},
			},
		},
	}
	body := graphqlUserLabelQuery(t, `query { searchUsers(query: "alice") { id name } }`, read)
	var out struct {
		Data struct {
			SearchUsers []struct {
				ID    string  `json:"id"`
				Name  string  `json:"name"`
				Email *string `json:"email"`
			} `json:"searchUsers"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, body)
	}
	if len(out.Errors) > 0 {
		t.Fatalf("an { id name } selection must not error: %+v\nbody: %s", out.Errors, body)
	}
	if len(out.Data.SearchUsers) != 1 {
		t.Fatalf("expected 1 result, got %d (body: %s)", len(out.Data.SearchUsers), body)
	}
	if out.Data.SearchUsers[0].ID != "u-1" || out.Data.SearchUsers[0].Name != "Alice Smith" {
		t.Errorf("id/name selection: got %+v", out.Data.SearchUsers[0])
	}
	// An unselected nullable field must not appear in the payload at all.
	if out.Data.SearchUsers[0].Email != nil {
		t.Errorf("email must be absent when not selected, got %q", *out.Data.SearchUsers[0].Email)
	}
}

// TestSearchUsersGraphQLEmailSelectionEndToEnd drives the exact selection the
// ui will use — searchUsers { id name email } — through the generated
// executable schema, proving the field marshals over the wire.
func TestSearchUsersGraphQLEmailSelectionEndToEnd(t *testing.T) {
	read := &fakeReadClient{
		listResp: &identityv1.ListUsersByEmailResponse{
			Users: []*identityv1.User{
				{Id: "u-1", Name: "Alice Example", Email: "alice@example.org"},
				{Id: "u-2", Name: "Alice Example", Email: ""},
			},
		},
	}
	body := graphqlUserLabelQuery(t, `query { searchUsers(query: "alice") { id name email } }`, read)
	var out struct {
		Data struct {
			SearchUsers []struct {
				ID    string  `json:"id"`
				Name  string  `json:"name"`
				Email *string `json:"email"`
			} `json:"searchUsers"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, body)
	}
	if len(out.Errors) > 0 {
		t.Fatalf("unexpected GraphQL errors: %+v\nbody: %s", out.Errors, body)
	}
	if len(out.Data.SearchUsers) != 2 {
		t.Fatalf("expected 2 results, got %d (body: %s)", len(out.Data.SearchUsers), body)
	}
	if out.Data.SearchUsers[0].Email == nil || *out.Data.SearchUsers[0].Email != "alice@example.org" {
		t.Errorf("result[0].email: got %v", derefStr(out.Data.SearchUsers[0].Email))
	}
	// Nullable, so the emailless account serialises as JSON null — not "".
	if out.Data.SearchUsers[1].Email != nil {
		t.Errorf("result[1].email must be null, got %q", *out.Data.SearchUsers[1].Email)
	}
}

// TestResolveUserLabelsGraphQLIDNameOnlyStillWorks is the backward-compat
// regression for the other consumer: audit/history display-name lookups keep
// selecting { id name } and must be unaffected.
func TestResolveUserLabelsGraphQLIDNameOnlyStillWorks(t *testing.T) {
	id := &labelIdentityFake{users: map[string]*identityv1.User{
		"u-1": {Id: "u-1", Name: "Alice Example", Email: "alice@example.org"},
	}}
	body := graphqlUserLabelQuery(t, `query { resolveUserLabels(ids: ["u-1"]) { id name } }`, id)
	var out struct {
		Data struct {
			ResolveUserLabels []struct {
				ID    string  `json:"id"`
				Name  string  `json:"name"`
				Email *string `json:"email"`
			} `json:"resolveUserLabels"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, body)
	}
	if len(out.Errors) > 0 {
		t.Fatalf("an { id name } selection must not error: %+v\nbody: %s", out.Errors, body)
	}
	if len(out.Data.ResolveUserLabels) != 1 {
		t.Fatalf("expected 1 label, got %d (body: %s)", len(out.Data.ResolveUserLabels), body)
	}
	if out.Data.ResolveUserLabels[0].Name != "Alice Example" {
		t.Errorf("name: got %q", out.Data.ResolveUserLabels[0].Name)
	}
	if out.Data.ResolveUserLabels[0].Email != nil {
		t.Errorf("email must be absent when not selected, got %q", *out.Data.ResolveUserLabels[0].Email)
	}
}

// graphqlUserLabelQuery executes query against the generated executable schema
// with identity as the only wired downstream client, and returns the raw
// response body.
func graphqlUserLabelQuery(t *testing.T, query string, identity identityv1.IdentityReadServiceClient) []byte {
	t.Helper()
	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{
		Resolvers: &resolvers.Resolver{IdentityClient: identity},
	}))
	srv.AddTransport(transport.POST{})

	body, err := json.Marshal(map[string]any{"query": query})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest("POST", "/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithUser(t, "u-caller"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.Bytes()
}

// derefStr renders a *string for a test failure message.
func derefStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
