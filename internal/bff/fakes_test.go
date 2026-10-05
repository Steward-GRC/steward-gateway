// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"sync"
	"time"
)

// fakeAuth is the Kratos seam. Each hook defaults to a successful answer.
type fakeAuth struct {
	mu sync.Mutex

	verify  func(username, password string) (AuthResult, error)
	refresh func(token string) (AuthResult, error)
	logout  func(token string) error

	refreshCalls  int
	refreshTokens []string
	logoutTokens  []string
}

const testSessionToken = "kratos-session-token"

func okAuth() *fakeAuth { return &fakeAuth{} }

func (f *fakeAuth) VerifyPassword(_ context.Context, username, password string) (AuthResult, error) {
	if f.verify != nil {
		return f.verify(username, password)
	}
	return AuthResult{AccessToken: testSessionToken, ExpiresAt: time.Now().Add(time.Hour), Subject: "kratos-id-1", Email: "alice@example.org"}, nil
}

func (f *fakeAuth) Refresh(_ context.Context, token string) (AuthResult, error) {
	f.mu.Lock()
	f.refreshCalls++
	f.refreshTokens = append(f.refreshTokens, token)
	f.mu.Unlock()
	if f.refresh != nil {
		return f.refresh(token)
	}
	return AuthResult{AccessToken: token, ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}

func (f *fakeAuth) Logout(_ context.Context, token string) error {
	f.mu.Lock()
	f.logoutTokens = append(f.logoutTokens, token)
	f.mu.Unlock()
	if f.logout != nil {
		return f.logout(token)
	}
	return nil
}

func (f *fakeAuth) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshCalls
}
