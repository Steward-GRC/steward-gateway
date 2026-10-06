// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	redis "github.com/Bugs5382/go-redis"
	"github.com/Bugs5382/go-redis/script"
)

// Session is one signed-in browser session, stored server-side and addressed
// by the opaque cookie value.
type Session struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	CSRFToken    string    `json:"csrf_token"`
	UserID       string    `json:"user_id"`
	// MFAVerified records whether this session was issued after a verified
	// second factor (2-step login). Server-side marker only — not exposed on
	// any endpoint yet; authorization may distinguish on it later.
	MFAVerified bool `json:"mfa_verified"`
	// Impersonation, when set and Active, marks this admin session as acting-as
	// another user: the impersonation middleware swaps the effective claims to
	// the target while retaining the admin for audit. Persisted with the rest of
	// the Session via the existing JSON-marshaling Store; omitted when absent.
	Impersonation *ImpersonationState `json:"impersonation,omitempty"`
	// PasskeyReg holds the in-flight Kratos passkey-registration settings flow
	// between the begin and finish round-trips: the browser runs
	// navigator.credentials.create in between, so the flow id + its anti-CSRF
	// token and cookies must survive across the two authenticated requests. Set
	// on begin, cleared on finish (or when expired). Omitted when absent.
	PasskeyReg *PasskeyRegState `json:"passkey_reg,omitempty"`
}

// PasskeyRegState is the transient Kratos passkey-registration flow state carried
// on the caller's BFF session between /auth/passkey/register/begin and /finish
// Cookies are Kratos's own browser-flow cookies (the anti-CSRF
// cookie the settings submit's csrf_token must match); they are flow-scoped, not
// credentials.
type PasskeyRegState struct {
	FlowID    string            `json:"flow_id"`
	CSRFToken string            `json:"csrf_token"`
	Cookies   map[string]string `json:"cookies"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// ImpersonationState is the site-admin "act as" record carried on an admin's
// BFF session. TargetUserID is the user being acted as; AdminUserID is the real
// admin; Reason is the required justification; StartedAt/ExpiresAt bound the
// 30-minute window enforced by Active.
type ImpersonationState struct {
	TargetUserID string    `json:"target_user_id"`
	AdminUserID  string    `json:"admin_user_id"`
	Reason       string    `json:"reason"`
	StartedAt    time.Time `json:"started_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Active reports whether the impersonation record is present and not yet
// expired at now. A nil receiver is never active.
func (s *ImpersonationState) Active(now time.Time) bool {
	return s != nil && now.Before(s.ExpiresAt)
}

// SessionStore is the persistence seam the BFF handler depends on. *Store is
// the Redis-backed implementation; tests inject fakes to exercise error paths.
type SessionStore interface {
	Create(ctx context.Context, id string, sess Session) error
	Save(ctx context.Context, id string, sess Session) error
	Get(ctx context.Context, id string) (Session, bool, error)
	Delete(ctx context.Context, id string) error
	// AcquireRefreshLock elects a single refresher for a session's token refresh
	// across all replicas. On success it returns a unique owner
	// token to hand back to ReleaseRefreshLock and ok=true; ok=false means
	// another caller currently holds the lock.
	AcquireRefreshLock(ctx context.Context, id string, ttl time.Duration) (token string, ok bool, err error)
	// ReleaseRefreshLock releases a lock taken with AcquireRefreshLock, but only
	// if the caller still owns it (token match), so a lock that already expired
	// and was re-taken by another replica is never released out from under it.
	ReleaseRefreshLock(ctx context.Context, id, token string) error
}

// Store is the Valkey-backed SessionStore, on go-redis.
type Store struct {
	c   *redis.Client
	ttl time.Duration
}

// NewStore returns a Store whose sessions live for ttl from their last save.
func NewStore(c *redis.Client, ttl time.Duration) *Store { return &Store{c: c, ttl: ttl} }

func key(id string) string { return "sess:" + id }

func (s *Store) Create(ctx context.Context, id string, sess Session) error {
	return s.Save(ctx, id, sess)
}

func (s *Store) Save(ctx context.Context, id string, sess Session) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.c.Redis().Set(ctx, key(id), b, s.ttl).Err()
}

func (s *Store) Get(ctx context.Context, id string) (Session, bool, error) {
	b, err := s.c.Redis().Get(ctx, key(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	var sess Session
	if err := json.Unmarshal(b, &sess); err != nil {
		return Session{}, false, err
	}
	return sess, true, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	return s.c.Redis().Del(ctx, key(id)).Err()
}

func refreshLockKey(id string) string { return "refreshlock:" + id }

// releaseLockScript deletes the refresh lock only when it still carries the
// caller's owner token, so a lock that already expired and was taken again by
// another replica is never deleted by the previous owner.
var releaseLockScript = script.New(`
if redis.call("get", KEYS[1]) == ARGV[1] then
	return redis.call("del", KEYS[1])
end
return 0
`, script.WithName("session-refresh-unlock"))

// AcquireRefreshLock takes the per-session single-flight refresh lock with SET
// NX and a TTL safety net. The value is a fresh random owner token returned to
// the caller for ReleaseRefreshLock.
func (s *Store) AcquireRefreshLock(ctx context.Context, id string, ttl time.Duration) (string, bool, error) {
	token, err := newLockToken()
	if err != nil {
		return "", false, err
	}
	ok, err := s.c.Redis().SetNX(ctx, refreshLockKey(id), token, ttl).Result()
	if err != nil {
		return "", false, err
	}
	return token, ok, nil
}

// ReleaseRefreshLock releases the lock if the caller still owns it.
func (s *Store) ReleaseRefreshLock(ctx context.Context, id, token string) error {
	return releaseLockScript.Run(ctx, s.c, []string{refreshLockKey(id)}, token).Err()
}

func newLockToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
