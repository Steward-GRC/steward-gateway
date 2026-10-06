// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package aijobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	redis "github.com/Bugs5382/go-redis"
)

// ErrResultNotFound is returned by ContentReader.Fetch when resultRef doesn't resolve to a value in
// Valkey: the job hasn't written its result yet, or the key has expired.
var ErrResultNotFound = errors.New("aijobs: job result not found")

// resultEnvelope is the JSON the ai operator writes under a job's resultRef:
// the generation payload with an operation tag.
type resultEnvelope struct {
	Operation string          `json:"operation"`
	Result    json.RawMessage `json:"result"`
}

// Content is a job result's envelope, decoded just enough to route it: the operation tag, plus the
// generation payload as opaque JSON (ResultJSON) — same posture as the schema's
// saveDraft(contentJson:).
type Content struct {
	Operation  string
	ResultJSON string
}

// ContentReader fetches a completed async AI job's generated content from Redis by resultRef — the
// same key the operator's reconciler writes under.
type ContentReader struct {
	rdb redis.UniversalClient
}

// NewContentReader wraps a connected go-redis client — the same rdb the BFF session store and the
// AI job broker's consumer already use.
func NewContentReader(rdb redis.UniversalClient) *ContentReader {
	return &ContentReader{rdb: rdb}
}

// Fetch reads resultRef and decodes its envelope into Content.
func (r *ContentReader) Fetch(ctx context.Context, resultRef string) (*Content, error) {
	raw, err := r.rdb.Get(ctx, resultRef).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrResultNotFound
		}
		return nil, fmt.Errorf("aijobs: redis get %q: %w", resultRef, err)
	}

	var env resultEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("aijobs: decode result envelope: %w", err)
	}
	if env.Operation == "" {
		return nil, fmt.Errorf("aijobs: result envelope at %q has no operation", resultRef)
	}
	return &Content{Operation: env.Operation, ResultJSON: string(env.Result)}, nil
}
