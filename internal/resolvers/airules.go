// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Bugs5382/go-authz/ordered"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// The gateway's AI authorization rules: the read scope every AI request
// carries and the category gate on an operation's optional category.

// aiReadScope is the caller's AI read scope. Root reads every category;
// anyone else, a site admin included, reads the categories the category rules
// let them read (owners included). Sensitive documents need the individual
// read-sensitive grant either way.
func aiReadScope(ctx context.Context, categoryClient corev1.CategoryServiceClient) (*aiv1.ReadScope, error) {
	subj, err := subjectFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	scope := &aiv1.ReadScope{IncludeSensitive: subj.ReadSensitive}
	if subj.Root {
		scope.AllCategories = true
		return scope, nil
	}
	if categoryClient == nil {
		return scope, nil
	}
	scope.CategoryIds = readableCategoryIDs(ctx, categoryClient, personFromSubject(subj))
	return scope, nil
}

// readableCategoryIDs walks the category tree from the roots and returns every
// category whose rules let subj read. A category whose chain can't be built is
// left out.
func readableCategoryIDs(ctx context.Context, categoryClient corev1.CategoryServiceClient, person ordered.Person) []string {
	out := []string{}
	seen := map[string]bool{}
	queue := []string{""}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		resp, err := categoryClient.ListCategoryChildren(ctx, &corev1.ListCategoryChildrenRequest{ParentId: parent})
		if err != nil {
			continue
		}
		for _, c := range resp.GetCategories() {
			id := c.GetId()
			if seen[id] {
				continue
			}
			seen[id] = true
			queue = append(queue, id)
			access, err := loadCategoryAccess(ctx, categoryClient, id)
			if err != nil {
				continue
			}
			if access.decide(person).Read.Allowed {
				out = append(out, id)
			}
		}
	}
	return out
}

// aiScopeGrant is the category-rule grant an AI operation's optional category
// needs: read for search and answer, author for drafting.
type aiScopeGrant int

const (
	aiScopeRead aiScopeGrant = iota
	aiScopeAuthor
)

// authorizeAICategoryScope checks the caller may target category gid with an
// AI operation. An empty gid asks for no category. Root may target any
// category; anyone else, a site admin included, needs the grant on gid through
// the category rules.
func authorizeAICategoryScope(ctx context.Context, categoryClient corev1.CategoryServiceClient, claims principal.Claims, gid string, grant aiScopeGrant) error {
	if gid == "" || claims.IsRoot() {
		return nil
	}
	if categoryClient != nil {
		if uid, subj, err := evalSubjectFromCtx(ctx); err == nil {
			allowed := false
			if grant == aiScopeAuthor {
				allowed = canAuthorCategory(ctx, categoryClient, uid, subj, gid)
			} else {
				allowed = canReadCategory(ctx, categoryClient, uid, subj, gid)
			}
			if allowed {
				return nil
			}
		}
	}
	return status.Errorf(codes.PermissionDenied, "you don't have access to the selected category (%q); ask a site administrator for author access to it, or choose another category", gid)
}
