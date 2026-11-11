// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// fakeInboxClient is obligations' inbox for one actor: it holds that actor's
// notices, newest first, and pages them the way the service does (the token is
// the index of the next notice). It records every request, which carries no
// user id, so a test can see what the gateway asked for.
type fakeInboxClient struct {
	obligationsv1.InboxServiceClient

	notices []*obligationsv1.Notice

	listErr error
	listed  []*obligationsv1.ListNoticesRequest

	countResp int64
	countErr  error
	counts    int

	markErr    error
	markedIDs  []string
	markAllN   int64
	markAllErr error
	markAlls   int
}

func (f *fakeInboxClient) ListNotices(_ context.Context, in *obligationsv1.ListNoticesRequest, _ ...grpc.CallOption) (*obligationsv1.ListNoticesResponse, error) {
	f.listed = append(f.listed, in)
	if f.listErr != nil {
		return nil, f.listErr
	}
	var matching []*obligationsv1.Notice
	for _, n := range f.notices {
		switch in.GetFilter() {
		case obligationsv1.InboxFilter_INBOX_FILTER_NEEDS_ACTION:
			if !n.GetNeedsAction() {
				continue
			}
		case obligationsv1.InboxFilter_INBOX_FILTER_UPDATES:
			if n.GetNeedsAction() {
				continue
			}
		}
		matching = append(matching, n)
	}
	start := 0
	if tok := in.GetPageToken(); tok != "" {
		i, err := strconv.Atoi(tok)
		if err != nil {
			return nil, inboxCoded(codes.InvalidArgument, 7009, "INBOX_PAGE_INVALID", "That page of notifications isn't valid — reload the list.")
		}
		start = i
	}
	size := int(in.GetPageSize())
	if size <= 0 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	end := min(start+size, len(matching))
	resp := &obligationsv1.ListNoticesResponse{Notices: matching[start:end]}
	if end < len(matching) {
		resp.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

func (f *fakeInboxClient) CountUnread(_ context.Context, _ *obligationsv1.CountUnreadRequest, _ ...grpc.CallOption) (*obligationsv1.CountUnreadResponse, error) {
	f.counts++
	if f.countErr != nil {
		return nil, f.countErr
	}
	return &obligationsv1.CountUnreadResponse{Unread: f.countResp}, nil
}

func (f *fakeInboxClient) MarkRead(_ context.Context, in *obligationsv1.MarkReadRequest, _ ...grpc.CallOption) (*obligationsv1.MarkReadResponse, error) {
	f.markedIDs = append(f.markedIDs, in.GetId())
	if f.markErr != nil {
		return nil, f.markErr
	}
	for _, n := range f.notices {
		if n.GetId() == in.GetId() {
			if n.ReadAt == nil {
				n.ReadAt = timestamppb.New(time.Date(2026, 11, 11, 18, 0, 0, 0, time.UTC))
			}
			return &obligationsv1.MarkReadResponse{Notice: n}, nil
		}
	}
	return nil, inboxCoded(codes.NotFound, 7008, "INBOX_NOTICE_NOT_FOUND", "That notification is no longer here.")
}

func (f *fakeInboxClient) MarkAllRead(_ context.Context, _ *obligationsv1.MarkAllReadRequest, _ ...grpc.CallOption) (*obligationsv1.MarkAllReadResponse, error) {
	f.markAlls++
	if f.markAllErr != nil {
		return nil, f.markAllErr
	}
	return &obligationsv1.MarkAllReadResponse{Marked: f.markAllN}, nil
}

// inboxCoded is the status obligations sends for a coded refusal: the gRPC
// code, the user-safe message and the ErrorInfo apperrgrpc builds.
func inboxCoded(c codes.Code, num int, symbol, message string) error {
	st, err := status.New(c, message).WithDetails(&errdetails.ErrorInfo{
		Reason: symbol, Domain: "obligations",
		Metadata: map[string]string{apperrgrpc.MetaCodeNum: strconv.Itoa(num)},
	})
	if err != nil {
		panic(err)
	}
	return st.Err()
}

func notice(id, kind string, cat obligationsv1.NotifCategory, needsAction bool, created time.Time, read *time.Time, payload map[string]any) *obligationsv1.Notice {
	p, err := structpb.NewStruct(payload)
	if err != nil {
		panic(err)
	}
	n := &obligationsv1.Notice{Id: id, Kind: kind, Category: cat, NeedsAction: needsAction, Payload: p, CreatedAt: timestamppb.New(created)}
	if read != nil {
		n.ReadAt = timestamppb.New(*read)
	}
	return n
}

var (
	day10 = time.Date(2026, 11, 10, 15, 20, 0, 0, time.UTC)
	day9  = time.Date(2026, 11, 9, 9, 5, 0, 0, time.UTC)
	day8  = time.Date(2026, 11, 8, 8, 0, 0, 0, time.UTC)
	day5  = time.Date(2026, 11, 5, 12, 30, 0, 0, time.UTC)
)

// erinsNotices is the mock's seed for Erin, newest first, over the policies
// decidedCore knows: two reminders that wait on her and one update she read.
func erinsNotices() []*obligationsv1.Notice {
	read := day5.Add(30 * time.Minute)
	return []*obligationsv1.Notice{
		notice("n3", "ack-required", obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE, true, day10, nil,
			map[string]any{"policy_version_id": "pv-open-1"}),
		notice("n4", "policy-ack-reminder", obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE, true, day8, nil,
			map[string]any{"policy_version_id": "pv-open-1", "reminder_type": "reminder"}),
		notice("n5", "policy-published", obligationsv1.NotifCategory_NOTIF_CATEGORY_INFORMATIONAL, false, day5, &read,
			map[string]any{"policy_version_id": "pv-open-2"}),
	}
}

func inboxDeps(inbox obligationsv1.InboxServiceClient) resolvers.InboxDeps {
	pc, groups := decidedCore()
	return resolvers.InboxDeps{Inbox: inbox, Policies: pc, Categories: groups, Admin: noGrant()}
}

func ptr[T any](v T) *T { return &v }

func listAs(t *testing.T, ctx context.Context, deps resolvers.InboxDeps, filter *resolvers.NotificationFilter, first *int, after *string) (*resolvers.NotificationPage, error) {
	t.Helper()
	return resolvers.MyNotificationsResolver(ctx, log.Nop(), deps, filter, first, after)
}

func TestMyNotifications_MapsTheFactsAndRendersTheWordsFromKindAndPayload(t *testing.T) {
	inbox := &fakeInboxClient{notices: erinsNotices()}
	page, err := listAs(t, readerCtx(t), inboxDeps(inbox), nil, nil, nil)
	if err != nil {
		t.Fatalf("MyNotifications: %v", err)
	}
	if len(page.Items) != 3 || page.HasMore || page.EndCursor != nil {
		t.Fatalf("page = %d items, hasMore %v, cursor %v", len(page.Items), page.HasMore, page.EndCursor)
	}
	ack, reminder, published := page.Items[0], page.Items[1], page.Items[2]

	if ack.ID != "n3" || ack.Kind != "ack-required" || ack.Category != resolvers.NotifCategoryCompliance || !ack.NeedsAction {
		t.Fatalf("facts not mapped: %+v", ack)
	}
	if ack.Title != "Acknowledgement required" || ack.Line != "Please read and acknowledge the Desk Booking Policy." {
		t.Fatalf("ack wording = %q / %q", ack.Title, ack.Line)
	}
	if ack.Link == nil || ack.Link.Kind != resolvers.NotificationLinkKindPolicy || ack.Link.Ref != "POL-OP-1" {
		t.Fatalf("ack link = %+v, want the policy number", ack.Link)
	}
	if ack.CreatedAt != "2026-11-10T15:20:00Z" || ack.ReadAt != nil {
		t.Fatalf("times = %q / %v", ack.CreatedAt, ack.ReadAt)
	}
	if reminder.Title != "Acknowledgement reminder" || reminder.Line != "The Desk Booking Policy is still waiting for your acknowledgement." {
		t.Fatalf("reminder wording = %q / %q", reminder.Title, reminder.Line)
	}
	if published.Title != "Policy published" || published.Line != "Desk Booking Policy is now published." || published.NeedsAction {
		t.Fatalf("published = %+v", published)
	}
	if published.ReadAt == nil || *published.ReadAt != "2026-11-05T13:00:00Z" {
		t.Fatalf("readAt = %v, want 2026-11-05T13:00:00Z", published.ReadAt)
	}
}

func TestMyNotifications_AnApprovalNoticeLinksTheVersionAndNeedsNoPolicyRead(t *testing.T) {
	inbox := &fakeInboxClient{notices: []*obligationsv1.Notice{
		notice("n1", "workflow-awaiting-approval", obligationsv1.NotifCategory_NOTIF_CATEGORY_WORKFLOW, true, day10, nil,
			map[string]any{"policy_version_id": "version-2"}),
	}}
	pc, groups := decidedCore()
	counted := &countedVersions{coreLikeVersions: pc}
	deps := resolvers.InboxDeps{Inbox: inbox, Policies: counted, Categories: groups, Admin: noGrant()}
	page, err := listAs(t, readerCtx(t), deps, nil, nil, nil)
	if err != nil {
		t.Fatalf("MyNotifications: %v", err)
	}
	n := page.Items[0]
	if n.Title != "Approval needed" || n.Line != "A policy version is waiting for your approval." {
		t.Fatalf("wording = %q / %q", n.Title, n.Line)
	}
	if n.Link == nil || n.Link.Kind != resolvers.NotificationLinkKindApproval || n.Link.Ref != "version-2" {
		t.Fatalf("link = %+v", n.Link)
	}
	if counted.reads != 0 {
		t.Fatalf("core was asked %d times for a notice whose words need no policy", counted.reads)
	}
}

func TestMyNotifications_AskedOncePerVersionAcrossTheNotices(t *testing.T) {
	inbox := &fakeInboxClient{notices: erinsNotices()}
	pc, groups := decidedCore()
	counted := &countedVersions{coreLikeVersions: pc}
	deps := resolvers.InboxDeps{Inbox: inbox, Policies: counted, Categories: groups, Admin: noGrant()}
	if _, err := listAs(t, readerCtx(t), deps, nil, nil, nil); err != nil {
		t.Fatalf("MyNotifications: %v", err)
	}
	// pv-open-1 twice and pv-open-2 once: two distinct versions.
	if counted.reads != 2 {
		t.Fatalf("version reads = %d, want 2", counted.reads)
	}
}

func TestMyNotifications_APolicyTheCallerCannotReadKeepsItsTitleAndLinkOut(t *testing.T) {
	inbox := &fakeInboxClient{notices: []*obligationsv1.Notice{
		notice("n1", "ack-required", obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE, true, day10, nil,
			map[string]any{"policy_version_id": "pv-hidden-1"}),
	}}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", RolesValue: []string{"reader"}, IdpGroupsValue: []string{"Admins"}})
	page, err := listAs(t, ctx, inboxDeps(inbox), nil, nil, nil)
	if err != nil {
		t.Fatalf("a hidden policy must not fail the list: %v", err)
	}
	n := page.Items[0]
	if strings.Contains(n.Line, "Board Minutes") || strings.Contains(n.Title, "Board Minutes") {
		t.Fatalf("title of an unreadable policy leaked: %q / %q", n.Title, n.Line)
	}
	if n.Link != nil {
		t.Fatalf("link to an unreadable policy: %+v", n.Link)
	}
	if n.Title != "Acknowledgement required" || n.Line == "" {
		t.Fatalf("still worded: %q / %q", n.Title, n.Line)
	}
}

func TestMyNotifications_APolicyCoreDoesNotKnowOrCannotAnswerStillListsTheNotice(t *testing.T) {
	for name, versionID := range map[string]string{"unknown": "pv-gone", "no id in the payload": ""} {
		payload := map[string]any{}
		if versionID != "" {
			payload["policy_version_id"] = versionID
		}
		inbox := &fakeInboxClient{notices: []*obligationsv1.Notice{
			notice("n1", "policy-published", obligationsv1.NotifCategory_NOTIF_CATEGORY_INFORMATIONAL, false, day9, nil, payload),
		}}
		page, err := listAs(t, readerCtx(t), inboxDeps(inbox), nil, nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n := page.Items[0]
		if n.Title != "Policy published" || n.Line != "A policy was published." || n.Link != nil {
			t.Fatalf("%s: got %q / %q / %+v", name, n.Title, n.Line, n.Link)
		}
	}

	// Core down: the bell still lists the notice, in plain words.
	inbox := &fakeInboxClient{notices: erinsNotices()[:1]}
	pc, groups := decidedCore()
	down := &countedVersions{coreLikeVersions: pc, failIDs: map[string]bool{"pv-open-1": true}}
	deps := resolvers.InboxDeps{Inbox: inbox, Policies: down, Categories: groups, Admin: noGrant()}
	page, err := listAs(t, readerCtx(t), deps, nil, nil, nil)
	if err != nil {
		t.Fatalf("core down must not fail the list: %v", err)
	}
	if n := page.Items[0]; n.Title != "Acknowledgement required" || n.Link != nil || n.Line == "" {
		t.Fatalf("core down: %q / %q / %+v", n.Title, n.Line, n.Link)
	}
}

func TestMyNotifications_AnUnknownKindIsListedWithPlainWords(t *testing.T) {
	inbox := &fakeInboxClient{notices: []*obligationsv1.Notice{
		notice("n1", "brand-new-kind", obligationsv1.NotifCategory_NOTIF_CATEGORY_INFORMATIONAL, false, day9, nil, map[string]any{}),
	}}
	page, err := listAs(t, readerCtx(t), inboxDeps(inbox), nil, nil, nil)
	if err != nil {
		t.Fatalf("MyNotifications: %v", err)
	}
	n := page.Items[0]
	if n.Kind != "brand-new-kind" || n.Category != resolvers.NotifCategoryInformational || n.Title != "Notification" || n.Line != "You have a new notification." || n.Link != nil {
		t.Fatalf("unknown kind = %+v", n)
	}
}

func TestMyNotifications_TheTabsBecomeObligationsFilters(t *testing.T) {
	cases := []struct {
		name   string
		filter *resolvers.NotificationFilter
		want   obligationsv1.InboxFilter
	}{
		{"no filter", nil, obligationsv1.InboxFilter_INBOX_FILTER_ALL},
		{"empty filter", &resolvers.NotificationFilter{}, obligationsv1.InboxFilter_INBOX_FILTER_ALL},
		{"needs action", &resolvers.NotificationFilter{NeedsAction: ptr(true)}, obligationsv1.InboxFilter_INBOX_FILTER_NEEDS_ACTION},
		{"updates", &resolvers.NotificationFilter{NeedsAction: ptr(false)}, obligationsv1.InboxFilter_INBOX_FILTER_UPDATES},
	}
	for _, tc := range cases {
		inbox := &fakeInboxClient{notices: erinsNotices()}
		if _, err := listAs(t, readerCtx(t), inboxDeps(inbox), tc.filter, nil, nil); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(inbox.listed) != 1 || inbox.listed[0].GetFilter() != tc.want {
			t.Fatalf("%s: asked for %v, want %v", tc.name, inbox.listed, tc.want)
		}
	}

	inbox := &fakeInboxClient{notices: erinsNotices()}
	page, err := listAs(t, readerCtx(t), inboxDeps(inbox), &resolvers.NotificationFilter{NeedsAction: ptr(false)}, nil, nil)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "n5" {
		t.Fatalf("updates tab = %+v, %v", page, err)
	}
}

func TestMyNotifications_UnreadAndCategoryNarrowTheListToo(t *testing.T) {
	inbox := &fakeInboxClient{notices: erinsNotices()}
	page, err := listAs(t, readerCtx(t), inboxDeps(inbox), &resolvers.NotificationFilter{Unread: ptr(true)}, nil, nil)
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("unread = %+v, %v", page, err)
	}
	for _, n := range page.Items {
		if n.ReadAt != nil {
			t.Fatalf("a read notice in the unread list: %+v", n)
		}
	}
	cat := resolvers.NotifCategoryInformational
	page, err = listAs(t, readerCtx(t), inboxDeps(inbox), &resolvers.NotificationFilter{Category: &cat}, nil, nil)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "n5" {
		t.Fatalf("category = %+v, %v", page, err)
	}
	page, err = listAs(t, readerCtx(t), inboxDeps(inbox), &resolvers.NotificationFilter{Unread: ptr(true), Category: &cat}, nil, nil)
	if err != nil || len(page.Items) != 0 || page.HasMore || page.EndCursor != nil {
		t.Fatalf("unread and informational = %+v, %v", page, err)
	}
}

// manyNotices is n notices, newest first; every third is read and every other
// one needs action, so the filters cut across the pages.
func manyNotices(n int) []*obligationsv1.Notice {
	out := make([]*obligationsv1.Notice, 0, n)
	for i := range n {
		created := day10.Add(-time.Duration(i) * time.Hour)
		var read *time.Time
		if i%3 == 0 {
			r := created.Add(time.Minute)
			read = &r
		}
		cat := obligationsv1.NotifCategory_NOTIF_CATEGORY_INFORMATIONAL
		kind := "policy-published"
		if i%2 == 0 {
			cat, kind = obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE, "ack-required"
		}
		out = append(out, notice("n"+strconv.Itoa(i), kind, cat, i%2 == 0, created, read, map[string]any{"policy_version_id": "pv-open-1"}))
	}
	return out
}

// walk pages through the list with the given page size and filter, and returns
// the ids in the order they came, failing on a runaway cursor.
func walk(t *testing.T, deps resolvers.InboxDeps, filter *resolvers.NotificationFilter, first int) []string {
	t.Helper()
	var ids []string
	var after *string
	for guard := 0; guard < 100; guard++ {
		page, err := listAs(t, readerCtx(t), deps, filter, &first, after)
		if err != nil {
			t.Fatalf("page %d: %v", guard, err)
		}
		if len(page.Items) > first {
			t.Fatalf("page %d has %d items, asked for %d", guard, len(page.Items), first)
		}
		for _, n := range page.Items {
			ids = append(ids, n.ID)
		}
		if !page.HasMore {
			if page.EndCursor != nil {
				t.Fatalf("the last page carries a cursor %q", *page.EndCursor)
			}
			return ids
		}
		if page.EndCursor == nil || *page.EndCursor == "" {
			t.Fatalf("page %d says there is more but gives no cursor", guard)
		}
		after = page.EndCursor
	}
	t.Fatal("paging did not end")
	return nil
}

func idsOf(notices []*obligationsv1.Notice, keep func(*obligationsv1.Notice) bool) []string {
	var ids []string
	for _, n := range notices {
		if keep(n) {
			ids = append(ids, n.GetId())
		}
	}
	return ids
}

func sameIDs(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ids = %v, want %v", got, want)
	}
}

func TestMyNotifications_PagesNewestFirstWithoutRepeatingOrSkipping(t *testing.T) {
	all := manyNotices(11)
	everything := func(*obligationsv1.Notice) bool { return true }
	for _, first := range []int{1, 2, 3, 5, 11, 12, 100} {
		inbox := &fakeInboxClient{notices: all}
		sameIDs(t, walk(t, inboxDeps(inbox), nil, first), idsOf(all, everything))
	}
}

func TestMyNotifications_AnExactMultipleOfThePageSizeEndsOnTheLastFullPage(t *testing.T) {
	inbox := &fakeInboxClient{notices: manyNotices(4)}
	first := 2
	deps := inboxDeps(inbox)
	p1, err := listAs(t, readerCtx(t), deps, nil, &first, nil)
	if err != nil || !p1.HasMore || p1.EndCursor == nil {
		t.Fatalf("page 1 = %+v, %v", p1, err)
	}
	p2, err := listAs(t, readerCtx(t), deps, nil, &first, p1.EndCursor)
	if err != nil || p2.HasMore || p2.EndCursor != nil || len(p2.Items) != 2 {
		t.Fatalf("page 2 = %+v, %v; want the last two with no more", p2, err)
	}
}

func TestMyNotifications_PagesTheFilteredListsTooAcrossObligationsPages(t *testing.T) {
	all := manyNotices(250)
	unread := func(n *obligationsv1.Notice) bool { return n.GetReadAt() == nil }
	compliance := func(n *obligationsv1.Notice) bool {
		return n.GetCategory() == obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE
	}

	// A tab alone is obligations' own paging.
	inbox := &fakeInboxClient{notices: all}
	sameIDs(t, walk(t, inboxDeps(inbox), &resolvers.NotificationFilter{NeedsAction: ptr(true)}, 7),
		idsOf(all, func(n *obligationsv1.Notice) bool { return n.GetNeedsAction() }))

	// Unread is cut here, so a page of the gateway can span several of obligations'.
	inbox = &fakeInboxClient{notices: all}
	sameIDs(t, walk(t, inboxDeps(inbox), &resolvers.NotificationFilter{Unread: ptr(true)}, 7), idsOf(all, unread))

	inbox = &fakeInboxClient{notices: all}
	cat := resolvers.NotifCategoryCompliance
	sameIDs(t, walk(t, inboxDeps(inbox), &resolvers.NotificationFilter{Unread: ptr(true), Category: &cat}, 4),
		idsOf(all, func(n *obligationsv1.Notice) bool { return unread(n) && compliance(n) }))
}

func TestMyNotifications_DefaultsToTwentyAndReadsMoreThanAHundredAsAHundred(t *testing.T) {
	inbox := &fakeInboxClient{notices: manyNotices(150)}
	page, err := listAs(t, readerCtx(t), inboxDeps(inbox), nil, nil, nil)
	if err != nil || len(page.Items) != 20 || !page.HasMore {
		t.Fatalf("default page = %d items, hasMore %v, %v", len(page.Items), page.HasMore, err)
	}
	page, err = listAs(t, readerCtx(t), inboxDeps(inbox), nil, ptr(500), nil)
	if err != nil || len(page.Items) != 100 || !page.HasMore {
		t.Fatalf("500 asked = %d items, hasMore %v, %v", len(page.Items), page.HasMore, err)
	}
}

func TestMyNotifications_RefusesAPageSizeBelowOneAndACursorItDidNotHandOut(t *testing.T) {
	for name, tc := range map[string]struct {
		first *int
		after *string
	}{
		"zero":            {first: ptr(0)},
		"negative":        {first: ptr(-3)},
		"nonsense cursor": {after: ptr("nonsense")},
		"empty cursor":    {after: ptr("")},
	} {
		inbox := &fakeInboxClient{notices: erinsNotices()}
		_, err := listAs(t, readerCtx(t), inboxDeps(inbox), nil, tc.first, tc.after)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: code = %v (%v), want InvalidArgument", name, status.Code(err), err)
		}
		if _, ok := apperrgrpc.FromError(err); ok {
			t.Fatalf("%s: the refusal carries a service code the mock does not", name)
		}
		if len(inbox.listed) != 0 {
			t.Fatalf("%s: obligations was asked anyway", name)
		}
	}
}

func TestMyNotifications_ACursorObligationsRefusesIsInvalidArgumentToo(t *testing.T) {
	inbox := &fakeInboxClient{notices: manyNotices(10)}
	deps := inboxDeps(inbox)
	// Well formed to the gateway, but not a position obligations ever issued.
	forged := resolvers.ForgedInboxCursorForTest("not-a-token", 0)
	_, err := listAs(t, readerCtx(t), deps, nil, ptr(2), &forged)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v (%v), want InvalidArgument", status.Code(err), err)
	}
	if _, ok := apperrgrpc.FromError(err); ok {
		t.Fatal("the refusal still carries obligations' code")
	}
}

func TestInboxResolvers_NeedASignedInUserAndAskNobodyElse(t *testing.T) {
	inbox := &fakeInboxClient{notices: erinsNotices()}
	deps := inboxDeps(inbox)
	ctx := context.Background()

	if _, err := listAs(t, ctx, deps, nil, nil, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("list: %v", err)
	}
	if _, err := resolvers.MyUnreadNotificationCountResolver(ctx, log.Nop(), deps); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("count: %v", err)
	}
	if _, err := resolvers.MarkNotificationReadResolver(ctx, log.Nop(), deps, "n3"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("mark: %v", err)
	}
	if _, err := resolvers.MarkAllNotificationsReadResolver(ctx, log.Nop(), deps); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("mark all: %v", err)
	}
	if len(inbox.listed)+inbox.counts+len(inbox.markedIDs)+inbox.markAlls != 0 {
		t.Fatal("obligations was called without a signed-in user")
	}
}

func TestMyUnreadNotificationCount_IsObligationsCount(t *testing.T) {
	inbox := &fakeInboxClient{countResp: 7}
	n, err := resolvers.MyUnreadNotificationCountResolver(readerCtx(t), log.Nop(), inboxDeps(inbox))
	if err != nil || n != 7 || inbox.counts != 1 {
		t.Fatalf("count = %d, %v (%d calls)", n, err, inbox.counts)
	}
	inbox = &fakeInboxClient{countErr: status.Error(codes.Unavailable, "obligations down")}
	if _, err := resolvers.MyUnreadNotificationCountResolver(readerCtx(t), log.Nop(), inboxDeps(inbox)); status.Code(err) != codes.Unavailable {
		t.Fatalf("a service fault stays a fault: %v", err)
	}
}

func TestMarkNotificationRead_ReturnsTheNoticeReadAndKeepsTheFirstReadTime(t *testing.T) {
	inbox := &fakeInboxClient{notices: erinsNotices()}
	deps := inboxDeps(inbox)
	got, err := resolvers.MarkNotificationReadResolver(readerCtx(t), log.Nop(), deps, "n3")
	if err != nil {
		t.Fatalf("MarkNotificationRead: %v", err)
	}
	if got.ID != "n3" || got.ReadAt == nil || *got.ReadAt != "2026-11-11T18:00:00Z" {
		t.Fatalf("marked = %+v", got)
	}
	if got.Title != "Acknowledgement required" || got.Link == nil || got.Link.Ref != "POL-OP-1" {
		t.Fatalf("the marked notice is worded like the listed one: %+v", got)
	}
	again, err := resolvers.MarkNotificationReadResolver(readerCtx(t), log.Nop(), deps, "n3")
	if err != nil || again.ReadAt == nil || *again.ReadAt != *got.ReadAt {
		t.Fatalf("second mark = %+v, %v", again, err)
	}
	if strings.Join(inbox.markedIDs, ",") != "n3,n3" {
		t.Fatalf("marked ids = %v", inbox.markedIDs)
	}
}

func TestMarkNotificationRead_SomeoneElsesOrUnknownNoticeIsNotFoundWithTheMocksError(t *testing.T) {
	inbox := &fakeInboxClient{notices: erinsNotices()}
	_, err := resolvers.MarkNotificationReadResolver(readerCtx(t), log.Nop(), inboxDeps(inbox), "someone-elses")
	if status.Code(err) != codes.NotFound || status.Convert(err).Message() != "Notification not found" {
		t.Fatalf("err = %v, want NotFound \"Notification not found\"", err)
	}
	if _, ok := apperrgrpc.FromError(err); ok {
		t.Fatal("the refusal still carries obligations' INBOX_NOTICE_NOT_FOUND code")
	}
}

func TestMarkAllNotificationsRead_SaysHowManyItMarked(t *testing.T) {
	inbox := &fakeInboxClient{markAllN: 4}
	n, err := resolvers.MarkAllNotificationsReadResolver(readerCtx(t), log.Nop(), inboxDeps(inbox))
	if err != nil || n != 4 || inbox.markAlls != 1 {
		t.Fatalf("marked = %d, %v", n, err)
	}
	inbox = &fakeInboxClient{markAllErr: status.Error(codes.Unavailable, "obligations down")}
	if _, err := resolvers.MarkAllNotificationsReadResolver(readerCtx(t), log.Nop(), inboxDeps(inbox)); status.Code(err) != codes.Unavailable {
		t.Fatalf("a service fault stays a fault: %v", err)
	}
}

func TestInboxErrors_ObligationsCodesBecomeTheMocksErrors(t *testing.T) {
	cases := []struct {
		name    string
		symbol  string
		code    codes.Code
		wantErr codes.Code
	}{
		{"auth required", "INBOX_AUTH_REQUIRED", codes.Unauthenticated, codes.Unauthenticated},
		{"page invalid", "INBOX_PAGE_INVALID", codes.InvalidArgument, codes.InvalidArgument},
		{"notice not found", "INBOX_NOTICE_NOT_FOUND", codes.NotFound, codes.NotFound},
	}
	for _, tc := range cases {
		coded := inboxCoded(tc.code, 7007, tc.symbol, "service words")
		inbox := &fakeInboxClient{listErr: coded, countErr: coded, markErr: coded, markAllErr: coded}
		deps := inboxDeps(inbox)
		errs := map[string]error{}
		_, errs["list"] = listAs(t, readerCtx(t), deps, nil, nil, nil)
		_, errs["count"] = resolvers.MyUnreadNotificationCountResolver(readerCtx(t), log.Nop(), deps)
		_, errs["mark"] = resolvers.MarkNotificationReadResolver(readerCtx(t), log.Nop(), deps, "n1")
		_, errs["mark all"] = resolvers.MarkAllNotificationsReadResolver(readerCtx(t), log.Nop(), deps)
		for op, err := range errs {
			if status.Code(err) != tc.wantErr {
				t.Fatalf("%s %s: code = %v, want %v", tc.name, op, status.Code(err), tc.wantErr)
			}
			if _, ok := apperrgrpc.FromError(err); ok {
				t.Fatalf("%s %s: still carries the service code", tc.name, op)
			}
		}
	}
}

// inboxOverGraphQL runs one operation through the generated executable schema
// with the real resolver wiring, for the signed-in user.
func inboxOverGraphQL(t *testing.T, inbox obligationsv1.InboxServiceClient, query string, vars map[string]any) map[string]any {
	t.Helper()
	pc, groups := decidedCore()
	srv := handler.New(resolvers.NewExecutableSchema(resolvers.Config{
		Resolvers: &resolvers.Resolver{InboxClient: inbox, PolicyClient: pc, CategoryClient: groups, IdentityAdminClient: noGrant()},
	}))
	srv.AddTransport(transport.POST{})
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(readerCtx(t))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response: %v\n%s", err, rec.Body.String())
	}
	return out
}

func TestInboxOverGraphQL_TheMocksOperationsRunAgainstTheRealSchema(t *testing.T) {
	inbox := &fakeInboxClient{notices: erinsNotices(), countResp: 2, markAllN: 2}
	out := inboxOverGraphQL(t, inbox, `query ($filter: NotificationFilter, $first: Int, $after: String) {
	  myNotifications(filter: $filter, first: $first, after: $after) {
	    items { id kind category title line needsAction link { kind ref } createdAt readAt }
	    endCursor
	    hasMore
	  }
	  myUnreadNotificationCount
	}`, map[string]any{"filter": map[string]any{"needsAction": true, "category": "COMPLIANCE"}, "first": 1})
	if out["errors"] != nil {
		t.Fatalf("errors: %v", out["errors"])
	}
	data := out["data"].(map[string]any)
	page := data["myNotifications"].(map[string]any)
	items := page["items"].([]any)
	first := items[0].(map[string]any)
	if len(items) != 1 || first["id"] != "n3" || first["category"] != "COMPLIANCE" || first["title"] != "Acknowledgement required" {
		t.Fatalf("items = %v", items)
	}
	if link := first["link"].(map[string]any); link["kind"] != "POLICY" || link["ref"] != "POL-OP-1" {
		t.Fatalf("link = %v", link)
	}
	if page["hasMore"] != true || page["endCursor"] == nil {
		t.Fatalf("page = %v", page)
	}
	if data["myUnreadNotificationCount"] != float64(2) {
		t.Fatalf("count = %v", data["myUnreadNotificationCount"])
	}

	out = inboxOverGraphQL(t, inbox, `mutation { markNotificationRead(id: "n3") { id readAt } markAllNotificationsRead }`, nil)
	if out["errors"] != nil {
		t.Fatalf("errors: %v", out["errors"])
	}
	data = out["data"].(map[string]any)
	if data["markAllNotificationsRead"] != float64(2) || data["markNotificationRead"].(map[string]any)["readAt"] == nil {
		t.Fatalf("mutations = %v", data)
	}
}
