// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Bugs5382/go-apperr/apperrgrpc"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// The notification inbox (steward-gateway#74): the caller's in-app notices.
// Obligations stores them and scopes every call to the forwarded actor, which
// the backend dial puts on the call from the signed-in user. No request here
// carries a user id, so a client cannot ask for anyone else's notices.
//
// Logs carry notice ids, version ids and counts only, never a payload, a title
// or a line.

const (
	inboxDefaultPage = 20
	// inboxMaxPage is obligations' own limit per page.
	inboxMaxPage = 100
	// inboxMaxFetches bounds the pages one request reads from obligations when
	// unread or category cut the list.
	inboxMaxFetches = 10
)

// The mock's messages for the two refusals the gateway decides or maps.
const (
	inboxNotFoundMessage = "Notification not found"
	inboxBadPageMessage  = "That page isn't valid — check first and after."
)

// InboxDeps are the clients the inbox resolvers use: obligations for the notices
// and core (with identity's break-glass reads) for the policy a notice is about.
type InboxDeps struct {
	Inbox      obligationsv1.InboxServiceClient
	Policies   corev1.PolicyServiceClient
	Categories corev1.CategoryServiceClient
	Admin      identityv1.IdentityAdminServiceClient
}

func inboxUser(ctx context.Context, logger log.Logger, op string) error {
	if claims, ok := principal.FromContext(ctx); !ok || claims.UserID() == "" {
		logger.Debug("inbox refused: no signed-in user", log.F("op", op))
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}
	return nil
}

// inboxError turns obligations' INBOX_* codes into the errors the mock answers
// (NotFound, InvalidArgument, Unauthenticated); anything else keeps its status.
func inboxError(logger log.Logger, op string, err error) error {
	if info, ok := apperrgrpc.FromError(err); ok {
		switch info.Symbol {
		case "INBOX_NOTICE_NOT_FOUND":
			logger.Debug("inbox: notice not found for the caller", log.F("op", op))
			return status.Error(codes.NotFound, inboxNotFoundMessage)
		case "INBOX_PAGE_INVALID":
			logger.Debug("inbox: page refused by obligations", log.F("op", op))
			return status.Error(codes.InvalidArgument, inboxBadPageMessage)
		case "INBOX_AUTH_REQUIRED":
			logger.Warn("inbox: obligations saw no actor", log.F("op", op))
			return status.Error(codes.Unauthenticated, "unauthenticated")
		}
	}
	logger.Error(err, "inbox: obligations call failed", log.F("op", op), log.F("code", status.Code(err).String()))
	return fmt.Errorf("inbox %s: %w", op, err)
}

// inboxCursor is a position in the caller's list: the obligations page token a
// page starts at, and how many of that page's notices are already behind us.
type inboxCursor struct {
	token string
	skip  int
}

func (c inboxCursor) encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(c.skip) + "|" + c.token))
}

func decodeInboxCursor(s string) (inboxCursor, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return inboxCursor{}, false
	}
	skip, token, ok := strings.Cut(string(raw), "|")
	n, convErr := strconv.Atoi(skip)
	if !ok || convErr != nil || n < 0 {
		return inboxCursor{}, false
	}
	return inboxCursor{token: token, skip: n}, true
}

func inboxFilterFor(f *NotificationFilter) obligationsv1.InboxFilter {
	switch {
	case f == nil || f.NeedsAction == nil:
		return obligationsv1.InboxFilter_INBOX_FILTER_ALL
	case *f.NeedsAction:
		return obligationsv1.InboxFilter_INBOX_FILTER_NEEDS_ACTION
	default:
		return obligationsv1.InboxFilter_INBOX_FILTER_UPDATES
	}
}

// noticeLookup finds the policy a notice is about, once per version for the
// request. A policy the caller cannot read, one core does not know and a core
// fault all read as nil, so the notice is still listed, in plain words.
type noticeLookup struct {
	ctx    context.Context
	logger log.Logger
	deps   InboxDeps
	seen   map[string]*noticePolicy
	byPol  map[string]*decidedPolicy
}

func newNoticeLookup(ctx context.Context, logger log.Logger, deps InboxDeps) *noticeLookup {
	return &noticeLookup{ctx: ctx, logger: logger, deps: deps, seen: map[string]*noticePolicy{}, byPol: map[string]*decidedPolicy{}}
}

func (l *noticeLookup) policyFor(versionID string) *noticePolicy {
	if p, done := l.seen[versionID]; done {
		return p
	}
	p := l.resolve(versionID)
	l.seen[versionID] = p
	return p
}

func (l *noticeLookup) resolve(versionID string) *noticePolicy {
	vr, err := l.deps.Policies.GetPolicyVersion(l.ctx, &corev1.GetPolicyVersionRequest{Id: versionID})
	if err != nil {
		l.logger.Warn("inbox: policy version not read, notice worded plainly",
			log.F("policy_version_id", versionID), log.F("code", status.Code(err).String()))
		return nil
	}
	pid := vr.GetVersion().GetPolicyId()
	pol, known := l.byPol[pid]
	if !known {
		var perr error
		pol, perr = decidedPolicyFor(l.ctx, l.logger, l.deps.Policies, l.deps.Categories, l.deps.Admin, pid)
		if perr != nil {
			l.logger.Warn("inbox: policy not read, notice worded plainly",
				log.F("policy_id", pid), log.F("code", status.Code(perr).String()))
			pol = &decidedPolicy{}
		}
		l.byPol[pid] = pol
	}
	if !pol.visible {
		log.Trace(l.logger, "inbox: policy not readable by the caller, title and link left out", log.F("policy_id", pid))
		return nil
	}
	return &noticePolicy{number: pol.number, title: pol.title}
}

func notifCategoryOf(c obligationsv1.NotifCategory) NotifCategory {
	return notifCategoryFromProto(c)
}

func (l *noticeLookup) present(n *obligationsv1.Notice) *Notification {
	versionID, _ := n.GetPayload().AsMap()["policy_version_id"].(string)
	title, line, link := renderNotice(n.GetKind(), versionID, func() *noticePolicy { return l.policyFor(versionID) })
	out := &Notification{
		ID:          n.GetId(),
		Kind:        n.GetKind(),
		Category:    notifCategoryOf(n.GetCategory()),
		Title:       title,
		Line:        line,
		NeedsAction: n.GetNeedsAction(),
		Link:        link,
	}
	if t := n.GetCreatedAt(); t != nil {
		out.CreatedAt = t.AsTime().UTC().Format(time.RFC3339)
	}
	if t := n.GetReadAt(); t != nil {
		s := t.AsTime().UTC().Format(time.RFC3339)
		out.ReadAt = &s
	}
	return out
}

// MyNotificationsResolver lists the caller's notices, newest first, one page at
// a time. needsAction is obligations' own tab filter; unread and category are
// cut here, reading on through obligations' pages until the page is full, and
// the cursor is a position in obligations' list so a page never repeats or
// skips a notice.
func MyNotificationsResolver(ctx context.Context, logger log.Logger, deps InboxDeps, filter *NotificationFilter, first *int, after *string) (*NotificationPage, error) {
	if err := inboxUser(ctx, logger, "list"); err != nil {
		return nil, err
	}
	size := inboxDefaultPage
	if first != nil {
		size = *first
	}
	if size < 1 {
		return nil, status.Error(codes.InvalidArgument, inboxBadPageMessage)
	}
	size = min(size, inboxMaxPage)
	var pos inboxCursor
	if after != nil {
		c, ok := decodeInboxCursor(*after)
		if !ok {
			logger.Debug("inbox list: cursor refused")
			return nil, status.Error(codes.InvalidArgument, inboxBadPageMessage)
		}
		pos = c
	}

	unreadOnly := filter != nil && filter.Unread != nil && *filter.Unread
	var category *NotifCategory
	if filter != nil {
		category = filter.Category
	}
	cut := unreadOnly || category != nil
	pageSize := size
	if cut {
		pageSize = inboxMaxPage
	}
	keep := func(n *obligationsv1.Notice) bool {
		if unreadOnly && n.GetReadAt() != nil {
			return false
		}
		return category == nil || notifCategoryOf(n.GetCategory()) == *category
	}

	start := time.Now()
	log.Trace(logger, "inbox list", log.F("filter", inboxFilterFor(filter).String()), log.F("first", size), log.F("cut", cut))
	var (
		kept    []*obligationsv1.Notice
		hasMore bool
		end     = pos
		fetches int
	)
scan:
	for {
		if fetches == inboxMaxFetches {
			// Too sparse to fill the page within the bound: hand back what we have
			// and the position reached, and say there is more.
			hasMore = true
			end = pos
			break
		}
		fetches++
		resp, err := deps.Inbox.ListNotices(ctx, &obligationsv1.ListNoticesRequest{
			Filter: inboxFilterFor(filter), PageSize: int32(pageSize), PageToken: pos.token,
		})
		if err != nil {
			return nil, inboxError(logger, "list", err)
		}
		items, next := resp.GetNotices(), resp.GetNextPageToken()
		for i := pos.skip; i < len(items); i++ {
			if !keep(items[i]) {
				continue
			}
			if len(kept) == size {
				hasMore = true
				break scan
			}
			kept = append(kept, items[i])
			end = inboxCursor{token: pos.token, skip: i + 1}
			if end.skip >= len(items) && next != "" {
				end = inboxCursor{token: next}
			}
		}
		if next == "" {
			break
		}
		if !cut && len(kept) == size {
			// Nothing is cut, so a next page means there is another notice.
			hasMore = true
			end = inboxCursor{token: next}
			break
		}
		pos = inboxCursor{token: next}
		if len(kept) == 0 {
			end = pos
		}
	}

	lookup := newNoticeLookup(ctx, logger, deps)
	page := &NotificationPage{Items: make([]*Notification, 0, len(kept)), HasMore: hasMore}
	for _, n := range kept {
		page.Items = append(page.Items, lookup.present(n))
	}
	if hasMore {
		c := end.encode()
		page.EndCursor = &c
	}
	logger.Debug("inbox list done", log.F("returned", len(page.Items)), log.F("has_more", hasMore),
		log.F("fetches", fetches), log.F("duration_ms", time.Since(start).Milliseconds()))
	return page, nil
}

// MyUnreadNotificationCountResolver answers the caller's unread count for the bell's badge.
func MyUnreadNotificationCountResolver(ctx context.Context, logger log.Logger, deps InboxDeps) (int, error) {
	if err := inboxUser(ctx, logger, "count"); err != nil {
		return 0, err
	}
	resp, err := deps.Inbox.CountUnread(ctx, &obligationsv1.CountUnreadRequest{})
	if err != nil {
		return 0, inboxError(logger, "count", err)
	}
	log.Trace(logger, "inbox count", log.F("unread", resp.GetUnread()))
	return int(resp.GetUnread()), nil
}

// MarkNotificationReadResolver marks one of the caller's notices read. A notice
// that is missing or someone else's is NotFound, the same for both.
func MarkNotificationReadResolver(ctx context.Context, logger log.Logger, deps InboxDeps, id string) (*Notification, error) {
	if err := inboxUser(ctx, logger, "mark_read"); err != nil {
		return nil, err
	}
	resp, err := deps.Inbox.MarkRead(ctx, &obligationsv1.MarkReadRequest{Id: id})
	if err != nil {
		logger.Debug("inbox mark read failed", log.F("notice_id", id))
		return nil, inboxError(logger, "mark_read", err)
	}
	logger.Debug("inbox notice read", log.F("notice_id", id), log.F("unread", resp.GetUnread()))
	return newNoticeLookup(ctx, logger, deps).present(resp.GetNotice()), nil
}

// MarkAllNotificationsReadResolver marks every unread notice of the caller read
// and says how many it marked.
func MarkAllNotificationsReadResolver(ctx context.Context, logger log.Logger, deps InboxDeps) (int, error) {
	if err := inboxUser(ctx, logger, "mark_all_read"); err != nil {
		return 0, err
	}
	resp, err := deps.Inbox.MarkAllRead(ctx, &obligationsv1.MarkAllReadRequest{})
	if err != nil {
		return 0, inboxError(logger, "mark_all_read", err)
	}
	logger.Debug("inbox all read", log.F("marked", resp.GetMarked()))
	return int(resp.GetMarked()), nil
}
