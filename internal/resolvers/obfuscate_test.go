// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"strings"
	"testing"
)

func TestObfuscate_PreservesStructureHidesText(t *testing.T) {
	raw := `{"root":{"children":[{"type":"paragraph","children":[{"type":"text","text":"Secret policy text"}]}],"type":"root","version":1}}`
	out := obfuscateContentJSON(raw)
	if strings.Contains(out, "Secret") || strings.Contains(out, "policy text") {
		t.Fatalf("real text leaked: %s", out)
	}
	if !strings.Contains(out, `"type":"paragraph"`) {
		t.Fatalf("structure lost: %s", out)
	}
}
