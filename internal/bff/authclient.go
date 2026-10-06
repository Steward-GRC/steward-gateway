// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"errors"
	"time"
)

// ErrInvalidCredentials is a rejected credential: a plain 401 to the client,
// never a coded internal error.
var ErrInvalidCredentials = errors.New("invalid credentials")

// AuthResult is a verified Kratos sign-in. AccessToken is the opaque Kratos
// session token; whoami extends it and logout revokes it. SessionID is the
// Kratos session's id, which identity records last-seen times under.
type AuthResult struct {
	AccessToken string
	SessionID   string
	ExpiresAt   time.Time
	Subject     string
	Email       string
}

// authClient is the Kratos surface local sign-in, refresh and logout use.
// *KratosClient implements it; tests fake it.
type authClient interface {
	VerifyPassword(ctx context.Context, username, password string) (AuthResult, error)
	Refresh(ctx context.Context, sessionToken string) (AuthResult, error)
	Logout(ctx context.Context, sessionToken string) error
}
