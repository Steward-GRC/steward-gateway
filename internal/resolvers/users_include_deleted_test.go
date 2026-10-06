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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUsersResolver_IncludeDeletedForwarded(t *testing.T) {
	read := &fakeReadClient{listResp: &identityv1.ListUsersByEmailResponse{}}
	include := true
	if _, err := resolvers.UsersResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), read, nil, nil, nil, &include); err != nil {
		t.Fatalf("UsersResolver: %v", err)
	}
	if read.lastListReq == nil || !read.lastListReq.GetIncludeDeleted() {
		t.Fatalf("include_deleted not forwarded: %+v", read.lastListReq)
	}
}

func TestUsersResolver_IncludeDeletedDefaultsFalse(t *testing.T) {
	for name, include := range map[string]*bool{"omitted": nil, "false": new(bool)} {
		t.Run(name, func(t *testing.T) {
			read := &fakeReadClient{listResp: &identityv1.ListUsersByEmailResponse{}}
			if _, err := resolvers.UsersResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), read, nil, nil, nil, include); err != nil {
				t.Fatalf("UsersResolver: %v", err)
			}
			if read.lastListReq.GetIncludeDeleted() {
				t.Fatal("include_deleted must default to false")
			}
		})
	}
}

func TestUsersResolver_IncludeDeletedDeniedForNonAdmins(t *testing.T) {
	include := true
	for _, roles := range [][]string{nil, {"author"}, {"approver"}, {"template-admin"}, {"compliance-admin"}} {
		read := &fakeReadClient{listResp: &identityv1.ListUsersByEmailResponse{}}
		_, err := resolvers.UsersResolver(ctxWithRoles(t, "u-1", roles), read, nil, nil, nil, &include)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("roles %v: want PermissionDenied, got %v", roles, err)
		}
		if read.lastListReq != nil {
			t.Fatalf("roles %v: identity must not be called when unauthorized", roles)
		}
	}
}

func TestUsersResolver_MapsDeletedState(t *testing.T) {
	read := &fakeReadClient{listResp: &identityv1.ListUsersByEmailResponse{Users: []*identityv1.User{
		{Id: "u-live"},
		{Id: "u-deleted", DeletedAt: "2026-09-15T14:02:11Z"},
		{Id: "u-merged", DeletedAt: "2026-09-16T09:30:00Z", MergedIntoUserId: "u-live"},
	}}}
	include := true
	out, err := resolvers.UsersResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), read, nil, nil, nil, &include)
	if err != nil {
		t.Fatalf("UsersResolver: %v", err)
	}
	live, deleted, merged := out.Users[0], out.Users[1], out.Users[2]
	if live.DeletedAt != nil || live.MergedIntoUserID != nil {
		t.Errorf("live user must carry null deleted state: %+v", live)
	}
	if deleted.DeletedAt == nil || *deleted.DeletedAt != "2026-09-15T14:02:11Z" || deleted.MergedIntoUserID != nil {
		t.Errorf("deleted user: deletedAt=%v mergedIntoUserId=%v", deleted.DeletedAt, deleted.MergedIntoUserID)
	}
	if merged.DeletedAt == nil || *merged.DeletedAt != "2026-09-16T09:30:00Z" ||
		merged.MergedIntoUserID == nil || *merged.MergedIntoUserID != "u-live" {
		t.Errorf("merged user: deletedAt=%v mergedIntoUserId=%v", merged.DeletedAt, merged.MergedIntoUserID)
	}
}

func TestSearchUsersResolver_NeverIncludesDeleted(t *testing.T) {
	read := &fakeReadClient{listResp: &identityv1.ListUsersByEmailResponse{}}
	if _, err := resolvers.SearchUsersResolver(ctxWithRoles(t, "u-admin", []string{"site-admin"}), read, "alice", nil); err != nil {
		t.Fatalf("SearchUsersResolver: %v", err)
	}
	if read.lastListReq == nil || read.lastListReq.GetIncludeDeleted() {
		t.Fatalf("the typeahead must never request deleted accounts: %+v", read.lastListReq)
	}
}

func TestUsersGraphQL_IncludeDeletedArgumentAndFields(t *testing.T) {
	read := &fakeReadClient{listResp: &identityv1.ListUsersByEmailResponse{Users: []*identityv1.User{
		{Id: "u-merged", DeletedAt: "2026-09-16T09:30:00Z", MergedIntoUserId: "u-live"},
	}}}
	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{
		Resolvers: &resolvers.Resolver{IdentityClient: read},
	}))
	srv.AddTransport(transport.POST{})
	body, err := json.Marshal(map[string]any{
		"query": `{ users(includeDeleted: true) { users { userId deletedAt mergedIntoUserId } } }`,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest("POST", "/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithRoles(t, "u-admin", []string{"site-admin"}))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	var out struct {
		Data struct {
			Users struct {
				Users []struct {
					UserID           string  `json:"userId"`
					DeletedAt        *string `json:"deletedAt"`
					MergedIntoUserID *string `json:"mergedIntoUserId"`
				} `json:"users"`
			} `json:"users"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, rec.Body.String())
	}
	if len(out.Errors) > 0 {
		t.Fatalf("graphql errors: %+v", out.Errors)
	}
	if !read.lastListReq.GetIncludeDeleted() {
		t.Fatal("includeDeleted argument not forwarded as include_deleted")
	}
	u := out.Data.Users.Users
	if len(u) != 1 || u[0].DeletedAt == nil || *u[0].DeletedAt != "2026-09-16T09:30:00Z" ||
		u[0].MergedIntoUserID == nil || *u[0].MergedIntoUserID != "u-live" {
		t.Fatalf("deleted state not exposed: %s", rec.Body.String())
	}
}
