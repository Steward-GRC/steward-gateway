// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

// LiveEventsResolver exposes liveEventsResolver to the external test package.
var LiveEventsResolver = liveEventsResolver

// ForgedInboxCursorForTest is a well-formed cursor to a position obligations
// never issued.
func ForgedInboxCursorForTest(token string, skip int) string {
	return inboxCursor{token: token, skip: skip}.encode()
}
