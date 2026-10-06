// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authz "github.com/Steward-GRC/steward-authz"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// The gateway's AI authorization rules: the read scope every AI request
// carries and the category gate on an operation's optional category.

// isSiteAdmin reports whether claims holds the site-admin role.
func isSiteAdmin(claims principal.Claims) bool {
	return principal.HasRole(claims, string(authz.RoleSiteAdmin))
}

// aiReadScope is the caller's AI read scope. A site admin or root reads every
// category; anyone else reads the categories the category rules let them read
// on merit (owners included). Sensitive documents need the individual
// read-sensitive grant either way.
func aiReadScope(ctx context.Context, categoryClient corev1.CategoryServiceClient) (*aiv1.ReadScope, error) {
	subj, err := subjectFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	scope := &aiv1.ReadScope{IncludeSensitive: subj.ReadSensitive}
	if subj.SiteAdmin() || subj.Root {
		scope.AllCategories = true
		return scope, nil
	}
	if categoryClient == nil {
		return scope, nil
	}
	scope.CategoryIds = readableCategoryIDs(ctx, categoryClient, meritSubject(subj))
	return scope, nil
}

// readableCategoryIDs walks the category tree from the roots and returns every
// category whose rules let subj read. A category whose chain can't be built is
// left out.
func readableCategoryIDs(ctx context.Context, categoryClient corev1.CategoryServiceClient, subj authz.Subject) []string {
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
			chain, err := buildCategoryChain(ctx, categoryClient, id)
			if err != nil {
				continue
			}
			if authz.Resolve(ctx, subj, chain).Read.Allowed {
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
// AI operation. An empty gid asks for no category. A site admin may target any
// category; anyone else needs the grant on gid through the category rules.
func authorizeAICategoryScope(ctx context.Context, categoryClient corev1.CategoryServiceClient, claims principal.Claims, gid string, grant aiScopeGrant) error {
	if gid == "" || isSiteAdmin(claims) {
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
