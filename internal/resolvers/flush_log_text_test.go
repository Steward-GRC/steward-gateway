// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"bytes"
	"strings"
	"testing"

	golog "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The collab flush helper is shared by publishDraft and publishAppendix (#164).
// Its warning on a failed flush must read true for both, so it says the draft
// was not published rather than naming the policy.
func TestPublishAppendix_FlushFailureWarnsTheDraftWasNotPublished(t *testing.T) {
	t.Setenv("LOG_LEVEL", "warn")
	t.Setenv("LOG_FORMAT", "json")
	var buf bytes.Buffer
	e := newApxEnv(t)
	e.r.Log = golog.NewLoggerWithOptions("steward-gateway-test", golog.WithOutput(&buf))
	_, room, _ := e.withCollab()
	room.flushErr = status.Error(codes.Unavailable, "collab down")
	publishableApx(t, e)

	if _, err := e.r.Mutation().PublishAppendix(apxCtx(t, "bob"), apxSeeded); err == nil {
		t.Fatal("publish succeeded after a failed flush")
	}

	out := buf.String()
	if !strings.Contains(out, "collab flush failed; the draft was not published") {
		t.Fatalf("warning does not say the draft was not published: %s", out)
	}
	if strings.Contains(out, "the policy was not published") {
		t.Errorf("warning still names the policy for an appendix flush: %s", out)
	}
	if !strings.Contains(out, apxRoomKey) {
		t.Errorf("warning lost the draft_id field %q: %s", apxRoomKey, out)
	}
}
