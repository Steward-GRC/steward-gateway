// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"
)

// SSOState is what /auth/sso/start parks under the OAuth state for the
// callback.
type SSOState struct {
	// Connection is the alias the sign-in started with; empty for an
	// IdP-initiated sign-in.
	Connection string `json:"connection"`
	// Mode is login or test. A test run records the connection's result and
	// never issues a session.
	Mode         string `json:"mode"`
	ConnectionID string `json:"connection_id"`
	// ReturnPath is the validated admin page a test run returns to.
	ReturnPath string `json:"return_path"`
	Tenant     string `json:"tenant"`
	// AdminUserID is the admin who started a test run. The callback checks
	// that user again instead of relying on the session cookie surviving the
	// cross-site round trip.
	AdminUserID string `json:"admin_user_id"`
}

// SSOStateStore parks SSO state between start and callback. *Store
// implements it on Valkey.
type SSOStateStore interface {
	PutSSOState(ctx context.Context, state string, s SSOState, ttl time.Duration) error
	// TakeSSOState reads and deletes the state, so a replayed callback misses.
	TakeSSOState(ctx context.Context, state string) (SSOState, bool, error)
}

func ssoStateKey(state string) string { return "ssostate:" + state }

func (s *Store) PutSSOState(ctx context.Context, state string, v SSOState, ttl time.Duration) error {
	return kv{s.c}.put(ctx, ssoStateKey(state), v, ttl)
}

func (s *Store) TakeSSOState(ctx context.Context, state string) (SSOState, bool, error) {
	var v SSOState
	ok, err := kv{s.c}.take(ctx, ssoStateKey(state), &v)
	return v, ok, err
}

// SSOTestLinkRecord is a shareable connection-test link minted by an admin
// for someone who can sign in at the IdP but has no admin session.
type SSOTestLinkRecord struct {
	ConnectionID string `json:"connection_id"`
	Alias        string `json:"alias"`
	Tenant       string `json:"tenant"`
	ReturnPath   string `json:"return_path"`
	AdminUserID  string `json:"admin_user_id"`
}

// SSOTestLinkStore keeps test links until they expire. A link may be opened
// more than once within its TTL.
type SSOTestLinkStore interface {
	PutSSOTestLink(ctx context.Context, token string, rec SSOTestLinkRecord, ttl time.Duration) error
	GetSSOTestLink(ctx context.Context, token string) (SSOTestLinkRecord, bool, error)
}

func ssoTestLinkKey(token string) string { return "ssotestlink:" + token }

func (s *Store) PutSSOTestLink(ctx context.Context, token string, rec SSOTestLinkRecord, ttl time.Duration) error {
	return kv{s.c}.put(ctx, ssoTestLinkKey(token), rec, ttl)
}

func (s *Store) GetSSOTestLink(ctx context.Context, token string) (SSOTestLinkRecord, bool, error) {
	var rec SSOTestLinkRecord
	ok, err := kv{s.c}.get(ctx, ssoTestLinkKey(token), &rec)
	return rec, ok, err
}

// GenerateState returns a fresh URL-safe OAuth state.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
