// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
)

// searchPolicies (steward-gateway#41): core ranks the published text, the gateway decides who
// sees what. The query text and the policy text are never logged, only the query's length.

const (
	searchDefaultPage = 20
	searchMaxPage     = 100
	// searchMaxCoreCalls bounds the core pages one request reads while hits the viewer can't
	// see are skipped. A request that runs out returns a short page with a token.
	searchMaxCoreCalls = 5
	searchTokenPrefix  = "search:"
)

var searchLog = log.NewLogger("gateway")

// searchOffset reads the core offset out of a page token this file handed out.
func searchOffset(after *string) (int, error) {
	if after == nil || *after == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(*after)
	bad := status.Error(codes.InvalidArgument, "the page token isn't one searchPolicies gave")
	if err != nil || !strings.HasPrefix(string(raw), searchTokenPrefix) {
		return 0, bad
	}
	n, err := strconv.Atoi(strings.TrimPrefix(string(raw), searchTokenPrefix))
	if err != nil || n < 0 {
		return 0, bad
	}
	return n, nil
}

func searchToken(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(searchTokenPrefix + strconv.Itoa(offset)))
}

func searchSnippetFromProto(s *corev1.PolicySearchSnippet) *PolicySearchSnippet {
	if s == nil {
		return nil
	}
	out := &PolicySearchSnippet{Text: s.GetText(), Matches: make([]*TextSpan, 0, len(s.GetMatches()))}
	for _, m := range s.GetMatches() {
		out.Matches = append(out.Matches, &TextSpan{Start: int(m.GetStart()), Length: int(m.GetLength())})
	}
	return out
}

// SearchPolicies answers the searchPolicies query. Core pages the ranked hits; the gateway drops
// the ones the viewer can't read (the same read model as policies) and shapes the rest. For a
// viewer whose content is obfuscated, or who reads a policy only under a break-glass grant, a
// hit stays only when the query matched its title and number alone, with that rank and no
// snippet, so search can't reveal hidden text one guess at a time.
//
// The page token is the core offset of the first hit not yet returned, so a page can end in the
// middle of a core page.
func SearchPolicies(ctx context.Context, client corev1.PolicyServiceClient, categoryClient corev1.CategoryServiceClient, adminClient identityv1.IdentityAdminServiceClient, identity identityv1.IdentityReadServiceClient, workflow workflowv1.WorkflowServiceClient, query string, documentType *DocumentType, first *int, after *string) (*PolicySearchPage, error) {
	subj, err := subjectFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	size := searchDefaultPage
	if first != nil {
		if *first < 1 {
			return nil, status.Error(codes.InvalidArgument, "ask for at least one result")
		}
		size = min(*first, searchMaxPage)
	}
	offset, err := searchOffset(after)
	if err != nil {
		return nil, err
	}
	empty := &PolicySearchPage{Hits: []*PolicySearchHit{}}
	if strings.TrimSpace(query) == "" {
		searchLog.Debug("search policies, blank query", log.F("query_len", len(query)))
		return empty, nil
	}
	searchLog.Debug("search policies", log.F("query_len", len(query)), log.F("first", size), log.F("offset", offset))

	// A grant-only read is searched like an obfuscated one.
	grants := activeBreakGlassFor(ctx, adminClient, subj.SiteAdmin())

	chunk := min(size+1, searchMaxPage)
	hits := make([]*PolicySearchHit, 0, size)
	next := ""
	for call := 0; call < searchMaxCoreCalls; call++ {
		resp, err := client.SearchPolicies(ctx, &corev1.SearchPoliciesRequest{
			Query: query, DocumentType: documentTypeToProto(documentType), Limit: int32(chunk), Offset: int32(offset), // #nosec G115 -- chunk is at most 100, offset a page-token integer
		})
		if err != nil {
			searchLog.Debug("search policies, core failed", log.F("query_len", len(query)), log.F("code", status.Code(err).String()))
			return nil, err
		}
		raw := resp.GetHits()
		policies := make([]*Policy, 0, len(raw))
		for _, h := range raw {
			if p := policyFromProto(h.GetPolicy()); p != nil {
				policies = append(policies, p)
			}
		}
		visible, err := resolvePolicyReadModel(ctx, policies, client, categoryClient, adminClient, identity, workflow)
		if err != nil {
			return nil, err
		}
		byID := make(map[string]*Policy, len(visible))
		for _, p := range visible {
			byID[p.ID] = p
		}

		full := false
		for i, h := range raw {
			p, ok := byID[h.GetPolicy().GetId()]
			if !ok {
				continue
			}
			hit := &PolicySearchHit{Policy: p, Rank: h.GetRank(), Snippet: searchSnippetFromProto(h.GetSnippet())}
			if p.ViewerCan.ContentObfuscated || grants[p.Number] {
				if !h.GetTitleMatch() {
					continue
				}
				hit.Rank, hit.Snippet = h.GetTitleRank(), nil
			}
			if len(hits) == size {
				next, full = searchToken(offset+i), true
				break
			}
			hits = append(hits, hit)
		}
		if full {
			break
		}
		offset += chunk
		if !resp.GetHasMore() {
			break
		}
		if call == searchMaxCoreCalls-1 {
			next = searchToken(offset)
		}
	}
	searchLog.Debug("search policies done", log.F("query_len", len(query)), log.F("hits", len(hits)), log.F("more", next != ""))
	return &PolicySearchPage{Hits: hits, NextPageToken: next}, nil
}
