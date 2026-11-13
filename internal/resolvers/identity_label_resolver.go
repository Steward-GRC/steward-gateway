// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"strings"
	"unicode/utf8"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ResolveUserLabelsResolver resolves a list of user ids to id→name pairs for display.
func ResolveUserLabelsResolver(
	ctx context.Context,
	identity identityv1.IdentityReadServiceClient,
	ids []string,
) ([]*UserLabel, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	labels := newLabelResolver(identity, nil, nil, nil)
	out := make([]*UserLabel, 0, len(ids))
	for _, id := range ids {
		name, email := labels.userLabelFields(ctx, id)
		if name == "" {
			name = id
		}
		out = append(out, &UserLabel{ID: id, Name: name, Email: nilIfEmpty(email)})
	}
	return out, nil
}

// minUserSearchLen is the fewest characters (after trimming) a people search needs. A shorter
// query would list the directory, which the required argument is there to prevent.
const minUserSearchLen = 2

// SearchUsersResolver is a lightweight typeahead backed by IdentityReadService.ListUsersByEmail.
// Despite that name, identity matches the query, case-insensitively as a substring, against the
// email, username, first name, last name, stored display name and "first last". A query under
// minUserSearchLen characters answers nothing and does not call identity. Of what identity
// returns, people whose name or email starts with the query come first, each group in identity's
// order, and the answer is cut to the limit. Identity decides which accounts are offered (it
// leaves out deleted ones).
func SearchUsersResolver(
	ctx context.Context,
	identity identityv1.IdentityReadServiceClient,
	query string,
	limit *int,
) ([]*UserLabel, error) {
	if _, err := signedIn(ctx); err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, status.Error(codes.Unavailable, "identity service unavailable")
	}
	query = strings.TrimSpace(query)
	if utf8.RuneCountInString(query) < minUserSearchLen {
		return []*UserLabel{}, nil
	}
	const defaultLimit = 20
	lim := int32(defaultLimit)
	if limit != nil && *limit > 0 {
		lim = toInt32(*limit)
	}
	resp, err := identity.ListUsersByEmail(ctx, &identityv1.ListUsersByEmailRequest{
		EmailSubstring: query,
		Limit:          lim,
	})
	if err != nil {
		return nil, err
	}
	needle := strings.ToLower(query)
	starts := func(u *identityv1.User) bool {
		return strings.HasPrefix(strings.ToLower(u.GetName()), needle) ||
			strings.HasPrefix(strings.ToLower(u.GetEmail()), needle)
	}
	ordered := make([]*identityv1.User, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		if starts(u) {
			ordered = append(ordered, u)
		}
	}
	for _, u := range resp.GetUsers() {
		if !starts(u) {
			ordered = append(ordered, u)
		}
	}
	if len(ordered) > int(lim) {
		ordered = ordered[:lim]
	}
	out := make([]*UserLabel, 0, len(ordered))
	for _, u := range ordered {
		name := u.GetName()
		if name == "" {
			name = u.GetEmail()
		}
		out = append(out, &UserLabel{ID: u.GetId(), Name: name, Email: nilIfEmpty(u.GetEmail())})
	}
	return out, nil
}
