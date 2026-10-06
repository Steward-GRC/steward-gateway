// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"regexp"
	"strings"

	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

// localeTagPattern is the BCP-47 shape the gateway will persist as a user's account-level language
// preference language ("en", "es", "fil") — 2-3 letters, required script ("Hant", "Latn") — exactly
// 4 letters, optional region ("US", "419") — 2 letters or 3 digits, optional It is deliberately a
// SUBSET of full BCP-47: variant, extension ("-u-co-...") and private-use ("-x-...") subtags are
// rejected.
var localeTagPattern = regexp.MustCompile(`^[A-Za-z]{2,3}(?:-[A-Za-z]{4})?(?:-(?:[A-Za-z]{2}|[0-9]{3}))?$`)

// normalizeLocale validates and canonicalizes a user-supplied locale for updateMyProfile.
func normalizeLocale(in string) (string, error) {
	tag := strings.TrimSpace(in)
	if tag == "" {
		return "", nil
	}
	if !localeTagPattern.MatchString(tag) {
		return "", errcodes.New(errcodes.CodeProfileLocaleInvalid, "locale", tag)
	}
	parts := strings.Split(tag, "-")
	for i, p := range parts {
		switch {
		case i == 0:
			parts[i] = strings.ToLower(p)
		case len(p) == 4:
			parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
		default:
			parts[i] = strings.ToUpper(p)
		}
	}
	return strings.Join(parts, "-"), nil
}
