// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
)

// Core's category document-type refusals (steward-core#34) are relayed in the
// generic coded shape through the real presenter: code = symbol, codeNum,
// domain core, business kind, metadata keys as extensions (so a client reads
// the count of a CATEGORY_HOLDS_DOCUMENTS). No gateway code table is involved.
func TestCategoryDocumentTypesRefusalsRelayCoreCodes(t *testing.T) {
	cases := []struct {
		num     int
		symbol  string
		md      map[string]string
		message string
	}{
		{4007, "CATEGORY_REFUSES_TYPE",
			map[string]string{"category": "Workplace", "type": "policy", "types": "policies", "accepts": "none", "hint": "It only holds other categories. Pick a child category."},
			"Category Workplace does not accept policies. It only holds other categories. Pick a child category."},
		{4008, "CATEGORY_HOLDS_DOCUMENTS",
			map[string]string{"category": "Expenses", "count": "5", "policies": "3", "procedures": "2"},
			"Can't change what Expenses accepts: it holds 5 documents the new setting would not accept (3 policies, 2 procedures). Move them to another category first."},
	}
	for _, tc := range cases {
		t.Run(tc.symbol, func(t *testing.T) {
			in := fmt.Errorf("core: %w", relayedStatus(t, codes.FailedPrecondition, tc.num, tc.symbol, "core", tc.message, tc.md))
			got := present(context.Background(), in)
			if got.Message != tc.message {
				t.Errorf("message = %q, want %q", got.Message, tc.message)
			}
			if got.Extensions["code"] != tc.symbol || got.Extensions["codeNum"] != tc.num {
				t.Errorf("code/codeNum = %v/%v, want %s/%d", got.Extensions["code"], got.Extensions["codeNum"], tc.symbol, tc.num)
			}
			if got.Extensions["domain"] != "core" || got.Extensions["kind"] != "business" {
				t.Errorf("domain/kind = %v/%v, want core/business", got.Extensions["domain"], got.Extensions["kind"])
			}
			for k, v := range tc.md {
				if got.Extensions[k] != v {
					t.Errorf("extensions %s = %v, want %q", k, got.Extensions[k], v)
				}
			}
		})
	}
}
