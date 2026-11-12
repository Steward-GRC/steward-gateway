// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// maxCustomFramingRunes caps the author's own CUSTOM wording, counted in
// characters. It matches steward-ai, which rejects longer wording before any
// model call; checking here fails the mutation up front instead of leaving a
// job that fails later. See steward-gateway#63.
const maxCustomFramingRunes = 500

// resolveFraming validates a draft framing and its custom wording and returns
// the values for the DRAFT or REVISE job input. An absent framing returns
// empty strings, so both keys are left out and the default tone stays.
// Refusals are InvalidArgument statuses, so the error presenter shows the
// message to the client as a business refusal instead of the generic fault.
// The wording is trimmed and only carried for CUSTOM, where it is required.
func resolveFraming(framing *DraftFraming, custom *string) (string, string, error) {
	if framing == nil {
		return "", "", nil
	}
	f := DraftFraming(strings.ToUpper(strings.TrimSpace(string(*framing))))
	switch f {
	case DraftFramingPlain, DraftFramingProfessional, DraftFramingFormal:
		return string(f), "", nil
	case DraftFramingCustom:
		wording := strings.TrimSpace(derefOrEmpty(custom))
		if wording == "" {
			return "", "", status.Error(codes.InvalidArgument, "Custom framing needs wording.")
		}
		if n := utf8.RuneCountInString(wording); n > maxCustomFramingRunes {
			return "", "", status.Errorf(codes.InvalidArgument, "Custom wording is %d characters; the limit is %d.", n, maxCustomFramingRunes)
		}
		return string(f), wording, nil
	default:
		return "", "", status.Errorf(codes.InvalidArgument, "Unknown framing %q.", string(f))
	}
}
