// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"time"
)

// pendingTTL bounds the window for the second factor: one sign-in attempt.
const pendingTTL = 5 * time.Minute

// maxPendingAttempts is the verify budget per pending id; it doubles as the
// verify endpoint's rate limit.
const maxPendingAttempts = 5

// PendingAuth is a verified first factor waiting for the second. The Kratos
// session token is never returned to the client.
type PendingAuth struct {
	AccessToken    string    `json:"access_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
	UserID         string    `json:"user_id"`
	// Factors are the kinds the user may finish with.
	Factors []string `json:"factors"`
	// Enroll marks a first sign-in that must enrol a factor before the
	// session is issued.
	Enroll            bool      `json:"enroll,omitempty"`
	Attempts          int       `json:"attempts"`
	WebauthnSessionID string    `json:"webauthn_session_id,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// PendingStore keeps pending sign-ins. *Store implements it on Valkey.
type PendingStore interface {
	CreatePending(ctx context.Context, id string, p PendingAuth) error
	GetPending(ctx context.Context, id string) (PendingAuth, bool, error)
	SavePending(ctx context.Context, id string, p PendingAuth) error
	// ConsumePending reads and deletes the record atomically, so a pending id
	// promotes to a session once.
	ConsumePending(ctx context.Context, id string) (PendingAuth, bool, error)
	DeletePending(ctx context.Context, id string) error
}

func pendingKey(id string) string { return "pendauth:" + id }

func (s *Store) CreatePending(ctx context.Context, id string, p PendingAuth) error {
	return kv{s.c}.put(ctx, pendingKey(id), p, pendingTTL)
}

// SavePending updates an existing record without extending its window.
func (s *Store) SavePending(ctx context.Context, id string, p PendingAuth) error {
	ttl := time.Until(p.ExpiresAt)
	if ttl <= 0 {
		return s.DeletePending(ctx, id)
	}
	return kv{s.c}.replace(ctx, pendingKey(id), p, ttl)
}

func (s *Store) GetPending(ctx context.Context, id string) (PendingAuth, bool, error) {
	var p PendingAuth
	ok, err := kv{s.c}.get(ctx, pendingKey(id), &p)
	return p, ok, err
}

func (s *Store) ConsumePending(ctx context.Context, id string) (PendingAuth, bool, error) {
	var p PendingAuth
	ok, err := kv{s.c}.take(ctx, pendingKey(id), &p)
	return p, ok, err
}

func (s *Store) DeletePending(ctx context.Context, id string) error {
	return kv{s.c}.del(ctx, pendingKey(id))
}
