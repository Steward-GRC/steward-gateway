// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// NewCSRFToken returns a fresh random double-submit token.
func NewCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CSRFEqual compares two tokens in constant time; an empty one never matches.
func CSRFEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SafeMethod reports whether method is GET or HEAD, the methods
// AuthenticateSafeRead exempts from the CSRF check.
func SafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}
