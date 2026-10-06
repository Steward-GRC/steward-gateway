// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import "encoding/json"

// redactedDoc is a minimal, structurally-valid Lexical document used as a safe fallback when
// content cannot be parsed for obfuscation.
const redactedDoc = `{"root":{"children":[{"type":"paragraph","format":"","indent":0,"version":1,"children":[{"type":"text","text":"[content hidden]","format":0,"detail":0,"mode":"normal","style":"","version":1}]}],"type":"root","format":"","indent":0,"version":1}}`

// scrambleAlphabet is the fixed substitution alphabet used to map readable runes onto unreadable
// ones.
const scrambleAlphabet = "xqzjvbkwflgncmdptrhsyuoaei"

// obfuscateContentJSON parses a Lexical content document, replaces every text node's "text" with
// structure-preserving gibberish (same length, spaces kept, letters scrambled), and re-serializes.
func obfuscateContentJSON(raw string) string {
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return redactedDoc
	}
	obfuscateNode(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		return redactedDoc
	}
	return string(out)
}

// obfuscateNode recursively walks the decoded Lexical tree.
func obfuscateNode(n any) {
	switch v := n.(type) {
	case map[string]any:
		if t, ok := v["type"].(string); ok && t == "text" {
			if s, ok := v["text"].(string); ok {
				v["text"] = scrambleText(s)
			}
		}
		for _, child := range v {
			obfuscateNode(child)
		}
	case []any:
		for _, child := range v {
			obfuscateNode(child)
		}
	}
}

// scrambleText maps each ASCII letter onto a fixed scrambled alphabet char, preserving case,
// spaces, and any non-letter runes.
func scrambleText(s string) string {
	out := []rune(s)
	for i, r := range out {
		switch {
		case r >= 'a' && r <= 'z':
			out[i] = rune(scrambleAlphabet[r-'a'])
		case r >= 'A' && r <= 'Z':
			out[i] = rune(scrambleAlphabet[r-'A'] - 'a' + 'A')
		default:
		}
	}
	return string(out)
}
