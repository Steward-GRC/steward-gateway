// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package notifyunsub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Purpose distinguishes what a token authorizes so an unsubscribe token can
// never be replayed as a preferences token or vice-versa.
type Purpose string

const (
	PurposeUnsubscribe Purpose = "unsub"
	PurposePreferences Purpose = "prefs"
	PurposeEmailVerify Purpose = "email-verify"
)

// tokenVersion is the payload schema version the obligations signer stamps.
const tokenVersion = 1

var (
	ErrMalformed    = errors.New("notifyunsub: malformed token")
	ErrBadSignature = errors.New("notifyunsub: signature mismatch")
	ErrExpired      = errors.New("notifyunsub: token expired")
	ErrPurpose      = errors.New("notifyunsub: unexpected purpose")
	ErrNoSecret     = errors.New("notifyunsub: empty signing secret")
)

type payload struct {
	V   int     `json:"v"`
	P   Purpose `json:"p"`
	U   string  `json:"u"`
	C   string  `json:"c,omitempty"`
	Em  string  `json:"em,omitempty"`
	Exp int64   `json:"e"`
}

// Claims is the verified content of a token.
type Claims struct {
	Purpose  Purpose
	UserID   string
	Category string
	Email    string
}

// Verifier checks tokens against the shared HMAC-SHA256 secret. Safe for
// concurrent use.
type Verifier struct {
	secret []byte
	now    func() time.Time // injectable clock for tests; nil means time.Now
}

// NewVerifier returns a Verifier keyed by secret. An empty secret is rejected
// so a misconfigured deployment fails loudly rather than accepting anything.
func NewVerifier(secret string) (*Verifier, error) {
	if secret == "" {
		return nil, ErrNoSecret
	}
	return &Verifier{secret: []byte(secret)}, nil
}

func (v *Verifier) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

func (v *Verifier) mac(segment string) string {
	m := hmac.New(sha256.New, v.secret)
	m.Write([]byte(segment))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Verify checks a token's signature, expiry, and purpose, returning its claims.
func (v *Verifier) Verify(token string, want Purpose) (Claims, error) {
	segment, sig, ok := strings.Cut(token, ".")
	if !ok || segment == "" || sig == "" {
		return Claims{}, ErrMalformed
	}
	if !hmac.Equal([]byte(sig), []byte(v.mac(segment))) {
		return Claims{}, ErrBadSignature
	}
	body, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return Claims{}, ErrMalformed
	}
	if p.V != tokenVersion || p.U == "" {
		return Claims{}, ErrMalformed
	}
	if p.P != want {
		return Claims{}, ErrPurpose
	}
	if p.P == PurposeEmailVerify && p.Em == "" {
		return Claims{}, ErrMalformed
	}
	if v.clock().After(time.Unix(p.Exp, 0)) {
		return Claims{}, ErrExpired
	}
	return Claims{Purpose: p.P, UserID: p.U, Category: p.C, Email: p.Em}, nil
}
