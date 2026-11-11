// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
)

// Core's category template lock refusals (steward-core#74) are relayed in the
// generic coded shape: code = symbol, codeNum, domain core, business kind,
// metadata keys as extensions. No gateway code table is involved, so a client
// can branch on CATEGORY_TEMPLATE_LOCKED and TEMPLATE_LOCK_NEEDS_DEFAULT.
func TestTemplateLockRefusalsRelayCoreCodes(t *testing.T) {
	cases := []struct {
		num     int
		symbol  string
		md      map[string]string
		message string
	}{
		{4004, "CATEGORY_TEMPLATE_LOCKED", map[string]string{"template": "Standard Policy"},
			"This category requires the Standard Policy template."},
		{4005, "TEMPLATE_LOCK_NEEDS_DEFAULT", map[string]string{"category": "Travel"},
			"Choose a default template for Travel before locking it."},
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
