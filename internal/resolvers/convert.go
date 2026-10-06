// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import "math"

// toInt32 narrows a bounded domain int (page sizes, orders, levels, day
// counts) for a proto field, clamping so a corrupt value never wraps negative.
func toInt32(n int) int32 {
	switch {
	case n < 0:
		return 0
	case n > math.MaxInt32:
		return math.MaxInt32
	default:
		return int32(n) //nosec G115 -- bounded by the guards above
	}
}

// aiQueryLimitToInt32 is toInt32 that keeps negatives, so the -1 "unlimited"
// sentinel (and an invalid -5, which ai rejects) reach ai unchanged.
func aiQueryLimitToInt32(n int) int32 {
	switch {
	case n < math.MinInt32:
		return math.MinInt32
	case n > math.MaxInt32:
		return math.MaxInt32
	default:
		return int32(n) //nosec G115 -- bounded by the guards above
	}
}

// nilIfEmpty returns nil when s is empty; otherwise a pointer to s.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// derefOrEmpty returns the pointee or empty string when p is nil.
func derefOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// derefBool returns the pointee or false when p is nil.
func derefBool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

func orEmpty[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
