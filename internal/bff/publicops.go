// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// publicQueries are the query fields a signed-out page may read: the
// banners and maintenance state the sign-in page shows.
var publicQueries = map[string]bool{
	"globalSettings": true,
	"__typename":     true,
}

// publicMutations are the anonymous reporting operations. They run without a
// session even for a signed-in user, so nothing on the call can identify the
// reporter.
var publicMutations = map[string]bool{
	"submitAnonymousReport": true,
	"checkReport":           true,
	"replyToReport":         true,
}

const maxPublicBody = 1 << 20

// isPublicOperation reports whether body is a single GraphQL operation whose
// every top-level field is public for its operation type.
func isPublicOperation(body []byte) bool {
	var req struct {
		Query         string `json:"query"`
		OperationName string `json:"operationName"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Query == "" {
		return false
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: req.Query})
	if err != nil {
		return false
	}
	var op *ast.OperationDefinition
	for _, o := range doc.Operations {
		if req.OperationName == "" || o.Name == req.OperationName {
			op = o
			break
		}
	}
	if op == nil || len(op.SelectionSet) == 0 {
		return false
	}
	var allowed map[string]bool
	switch op.Operation {
	case ast.Query:
		allowed = publicQueries
	case ast.Mutation:
		allowed = publicMutations
	default:
		return false
	}
	for _, sel := range op.SelectionSet {
		f, ok := sel.(*ast.Field)
		if !ok || !allowed[f.Name] {
			return false
		}
	}
	return true
}

// isPublicQuery is the query half of isPublicOperation, kept for the specs.
func isPublicQuery(body []byte) bool { return isPublicOperation(body) }

// PublicOps sends a public GraphQL operation to publicNext, with no session,
// and everything else to authNext. The body is buffered (up to 1 MiB) and
// restored for whichever handler runs.
func PublicOps(authNext, publicNext http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxPublicBody))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if isPublicOperation(body) {
			publicNext.ServeHTTP(w, r)
			return
		}
		authNext.ServeHTTP(w, r)
	})
}
