// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// groupMembersRead adds ListUsersInGroup to the managed-groups identity fake.
type groupMembersRead struct {
	*managedGroupsRead
	members map[string][]string
	err     error
	reqs    []*identityv1.ListUsersInGroupRequest
}

func (f *groupMembersRead) ListUsersInGroup(_ context.Context, in *identityv1.ListUsersInGroupRequest, _ ...grpc.CallOption) (*identityv1.ListUsersInGroupResponse, error) {
	f.reqs = append(f.reqs, in)
	if f.err != nil {
		return nil, f.err
	}
	out := &identityv1.ListUsersInGroupResponse{}
	for _, id := range f.members[in.GetGroupId()] {
		out.Users = append(out.Users, &identityv1.User{Id: id})
	}
	return out, nil
}

func memberRead() *groupMembersRead {
	return &groupMembersRead{
		managedGroupsRead: managerRead(),
		members:           map[string][]string{"g-sec": {"u-1", "u-2"}, "g-empty": nil},
	}
}

func str(s string) *string { return &s }

func TestQueryAuditLogForwardsActionsAndSubjectType(t *testing.T) {
	client := &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{}}
	filter := resolvers.AuditLogFilter{
		Actions:     []string{"policy.published", "policy.draft_saved"},
		SubjectType: str("policy"),
	}

	if _, err := resolvers.QueryAuditLogResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), log.Nop(), client,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, filter); err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	got := client.lastQueryReq
	if len(got.GetActions()) != 2 || got.GetActions()[0] != "policy.published" || got.GetActions()[1] != "policy.draft_saved" {
		t.Fatalf("actions=%v, want both codes in order", got.GetActions())
	}
	if got.GetSubjectType() != "policy" {
		t.Fatalf("subject_type=%q, want policy", got.GetSubjectType())
	}
	if got.GetActorUsers() != nil {
		t.Fatalf("actor_users=%v, want unset when no actor group is named", got.GetActorUsers())
	}
}

func TestQueryAuditLogLeavesFiltersUnsetByDefault(t *testing.T) {
	client := &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{}}

	if _, err := resolvers.QueryAuditLogResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), log.Nop(), client,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, resolvers.AuditLogFilter{}); err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	got := client.lastQueryReq
	if len(got.GetActions()) != 0 || got.GetSubjectType() != "" || got.GetActorUsers() != nil {
		t.Fatalf("filters=%+v, want none set", got)
	}
}

func TestQueryAuditLogResolvesAnActorGroupToItsMembers(t *testing.T) {
	client := &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{}}
	read := memberRead()

	if _, err := resolvers.QueryAuditLogResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), log.Nop(), client,
		read, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		resolvers.AuditLogFilter{ActorGroupID: str("g-sec")}); err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	users := client.lastQueryReq.GetActorUsers()
	if users == nil || len(users.GetUserIds()) != 2 || users.GetUserIds()[0] != "u-1" || users.GetUserIds()[1] != "u-2" {
		t.Fatalf("actor_users=%v, want the group's members", users)
	}
	if len(read.reqs) != 1 || read.reqs[0].GetGroupId() != "g-sec" {
		t.Fatalf("identity member reads=%v, want one read of g-sec", read.reqs)
	}
}

func TestQueryAuditLogActorGroupWithNoMembersSendsAnEmptySet(t *testing.T) {
	client := &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{}}

	if _, err := resolvers.QueryAuditLogResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), log.Nop(), client,
		memberRead(), nil, nil, nil, nil, nil, nil, nil, nil, nil,
		resolvers.AuditLogFilter{ActorGroupID: str("g-empty")}); err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	// Set but empty means match nothing; unset would widen the query to every actor.
	if users := client.lastQueryReq.GetActorUsers(); users == nil || len(users.GetUserIds()) != 0 {
		t.Fatalf("actor_users=%v, want a set that is present and empty", users)
	}
}

func TestQueryAuditLogActorGroupLookupFailureIsNotAnUnfilteredRead(t *testing.T) {
	client := &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{}}
	read := memberRead()
	read.err = status.Error(codes.Unavailable, "identity down")

	_, err := resolvers.QueryAuditLogResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), log.Nop(), client,
		read, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		resolvers.AuditLogFilter{ActorGroupID: str("g-sec")})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err=%v, want Unavailable from identity", err)
	}
	if client.lastQueryReq != nil {
		t.Fatal("audit must not be queried when the actor group could not be resolved")
	}
}

func TestQueryAuditLogActorGroupNeedsIdentity(t *testing.T) {
	client := &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{}}

	_, err := resolvers.QueryAuditLogResolver(ctxWithRoles(t, "auditor-1", []string{"site-admin"}), log.Nop(), client,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		resolvers.AuditLogFilter{ActorGroupID: str("g-sec")})
	if err == nil {
		t.Fatal("expected an error when identity is not wired")
	}
	if client.lastQueryReq != nil {
		t.Fatal("audit must not be queried without the actor group resolved")
	}
}

func TestQueryAuditLogGroupManagerMayFilterByAGroupTheyManage(t *testing.T) {
	client := &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{}}
	read := memberRead()

	if _, err := resolvers.QueryAuditLogResolver(groupManagerCtx(t), log.Nop(), client, read, nil, nil, nil,
		nil, str("g-sec"), nil, nil, nil, nil,
		resolvers.AuditLogFilter{ActorGroupID: str("g-sec"), SubjectType: str("policy")}); err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	if got := client.lastQueryReq.GetActorUsers().GetUserIds(); len(got) != 2 {
		t.Fatalf("actor_users=%v, want the managed group's members", got)
	}
}

func TestQueryAuditLogGroupManagerCannotProbeAnotherGroupsMembers(t *testing.T) {
	client := &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{}}
	read := memberRead()

	_, err := resolvers.QueryAuditLogResolver(groupManagerCtx(t), log.Nop(), client, read, nil, nil, nil,
		nil, str("g-sec"), nil, nil, nil, nil,
		resolvers.AuditLogFilter{ActorGroupID: str("g-other")})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err=%v, want PermissionDenied for a group the caller does not manage", err)
	}
	if len(read.reqs) != 0 {
		t.Fatalf("member reads=%v, want none for a refused filter", read.reqs)
	}
	if client.lastQueryReq != nil {
		t.Fatal("audit must not be queried for a refused filter")
	}
}

func TestQueryAuditLogFiltersStillNeedAuditAccess(t *testing.T) {
	client := &fakeAuditClient{queryResp: &auditv1.QueryAuditLogResponse{}}

	_, err := resolvers.QueryAuditLogResolver(ctxWithRoles(t, "u", []string{"author"}), log.Nop(), client,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		resolvers.AuditLogFilter{Actions: []string{"policy.published"}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err=%v, want PermissionDenied", err)
	}
}
