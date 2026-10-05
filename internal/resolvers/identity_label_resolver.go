// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

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

// SearchUsersResolver is a lightweight typeahead backed by IdentityReadService.ListUsersByEmail.
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
	out := make([]*UserLabel, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		name := u.GetName()
		if name == "" {
			name = u.GetEmail()
		}
		out = append(out, &UserLabel{ID: u.GetId(), Name: name, Email: nilIfEmpty(u.GetEmail())})
	}
	return out, nil
}
