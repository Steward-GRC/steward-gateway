// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	redis "github.com/Bugs5382/go-redis"
)

// kv is the JSON-record access the short-lived sign-in stores share.
type kv struct{ c *redis.Client }

func (k kv) put(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return k.c.Redis().Set(ctx, key, b, ttl).Err()
}

// replace overwrites an existing record only, keeping it alive for ttl.
func (k kv) replace(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return k.c.Redis().SetXX(ctx, key, b, ttl).Err()
}

func (k kv) get(ctx context.Context, key string, v any) (bool, error) {
	b, err := k.c.Redis().Get(ctx, key).Bytes()
	return decodeRecord(b, err, v)
}

// take reads and deletes the record in one step, so it is single-use.
func (k kv) take(ctx context.Context, key string, v any) (bool, error) {
	b, err := k.c.Redis().GetDel(ctx, key).Bytes()
	return decodeRecord(b, err, v)
}

func (k kv) del(ctx context.Context, key string) error {
	return k.c.Redis().Del(ctx, key).Err()
}

func decodeRecord(b []byte, err error, v any) (bool, error) {
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, err
	}
	return true, nil
}
