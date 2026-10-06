// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package errcodes

import (
	"os"
	"testing"

	apperr "github.com/Bugs5382/go-apperr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryBuilds(t *testing.T) {
	require.NotNil(t, Registry())
}

func TestEveryCodeIsInBandOne(t *testing.T) {
	for _, e := range Entries() {
		assert.GreaterOrEqual(t, e.Code, 1000, e.Symbol)
		assert.Less(t, e.Code, 2000, e.Symbol)
	}
}

func TestNewCarriesCodeAndMetadata(t *testing.T) {
	err := New(CodeCollabFlushRejected, "reason", "stale")
	code, ok := apperr.Code(err)
	require.True(t, ok)
	assert.Equal(t, CodeCollabFlushRejected, code)
	assert.Equal(t, "stale", apperr.Metadata(err)["reason"])
	msg, n := Registry().Present(err, CodeInternal)
	assert.Equal(t, CodeCollabFlushRejected, n)
	assert.Contains(t, msg, "stale")
}

func TestKindOf(t *testing.T) {
	assert.Equal(t, KindReach, KindOf(apperr.CategoryInternal))
	assert.Equal(t, KindReach, KindOf(apperr.CategoryUnavailable))
	assert.Equal(t, KindReach, KindOf(apperr.CategoryDeadlineExceeded))
	assert.Equal(t, KindBusiness, KindOf(apperr.CategoryPermissionDenied))
	assert.Equal(t, KindBusiness, KindOf(apperr.CategoryInvalid))
	assert.Equal(t, KindBusiness, KindOf(apperr.CategoryNotFound))
}

func TestErrorCodesDocIsCurrent(t *testing.T) {
	b, err := os.ReadFile("../../docs/error-codes.md")
	require.NoError(t, err, "write docs/error-codes.md from errcodes.Doc()")
	assert.Equal(t, Doc(), string(b), "docs/error-codes.md is stale: regenerate it from errcodes.Doc()")
}
