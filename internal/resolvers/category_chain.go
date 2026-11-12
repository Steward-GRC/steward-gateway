// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	"github.com/Bugs5382/go-authz/ordered"
	authz "github.com/Steward-GRC/steward-gateway/internal/authz"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// maxCategoryDepth bounds every ancestor walk, so a cycle in stored data can't
// loop forever. Core caps the tree at three levels.
const maxCategoryDepth = 20

// categoryLineage returns the category ids from leafID up to the root.
func categoryLineage(ctx context.Context, categoryClient corev1.CategoryServiceClient, leafID string) ([]string, error) {
	ids, _, err := categoryLineageNamed(ctx, categoryClient, leafID)
	return ids, err
}

// categoryLineageNamed returns the category ids and names from leafID up to
// the root. Scoped grants and rule chains are keyed by category name.
func categoryLineageNamed(ctx context.Context, categoryClient corev1.CategoryServiceClient, leafID string) (ids, names []string, err error) {
	for id := leafID; id != "" && len(ids) < maxCategoryDepth; {
		resp, err := categoryClient.GetCategory(ctx, &corev1.GetCategoryRequest{Id: id})
		if err != nil {
			return nil, nil, fmt.Errorf("get category %s: %w", id, err)
		}
		ids = append(ids, id)
		names = append(names, resp.GetCategory().GetName())
		id = resp.GetCategory().GetParentId()
	}
	return ids, names, nil
}

// subjectForUser builds the Subject for a user other than the caller (the
// access simulator, approver pools): roles and root from GetUser, IdP group
// names from ListUserIdpGroups for group-rule matching.
func subjectForUser(ctx context.Context, ic identityv1.IdentityReadServiceClient, userID string) (authz.Subject, error) {
	ur, err := ic.GetUser(ctx, &identityv1.GetUserRequest{UserId: userID})
	if err != nil {
		return authz.Subject{}, fmt.Errorf("get user: %w", err)
	}
	gr, err := ic.ListUserIdpGroups(ctx, &identityv1.ListUserIdpGroupsRequest{UserId: userID})
	if err != nil {
		return authz.Subject{}, fmt.Errorf("list user idp groups: %w", err)
	}
	u := ur.GetUser()
	roles := make([]authz.Role, 0, len(u.GetRoles()))
	for _, r := range u.GetRoles() {
		roles = append(roles, authz.Role(r))
	}
	return authz.Subject{UserID: userID, Roles: roles, Root: u.GetIsRoot(), Groups: gr.GetIdpGroups()}, nil
}

// personFromSubject is the person the ordered engine decides for. Roles do not
// matter to the rows, which name users, groups and Everyone; the one role the
// engine knows is root, set from identity's is_root flag.
func personFromSubject(subj authz.Subject) ordered.Person {
	p := ordered.Person{ID: subj.UserID, Groups: subj.Groups}
	if subj.Root {
		p.Roles = []string{rootRole}
	}
	return p
}

// personForUser is personFromSubject for a user other than the caller.
func personForUser(ctx context.Context, ic identityv1.IdentityReadServiceClient, userID string) (ordered.Person, error) {
	subj, err := subjectForUser(ctx, ic, userID)
	if err != nil {
		return ordered.Person{}, err
	}
	return personFromSubject(subj), nil
}
