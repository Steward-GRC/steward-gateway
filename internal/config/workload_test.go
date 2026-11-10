// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWorkloadTokenFileDefault(t *testing.T) {
	assert.Equal(t, "/var/run/secrets/steward/token", WorkloadTokenFile)
}
