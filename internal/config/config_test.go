// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := Load(env(map[string]string{"WORKLOAD_AUTH": "disabled"}))
	require.NoError(t, err)
	assert.Equal(t, ":8080", c.HTTPAddr)
	assert.Equal(t, "steward-core:9090", c.Backends["core"])
	assert.Len(t, c.Backends, 9)
	assert.False(t, c.WorkloadAuth)
	assert.Empty(t, c.TokenFile, "disabled sends no token")
	assert.Equal(t, 168*time.Hour, c.SessionTTL)
	assert.Empty(t, c.KubernetesAPI)
}

func TestWorkloadAuthIsOnByDefaultAndFailsClosedWithoutTheToken(t *testing.T) {
	_, err := Load(env(map[string]string{"WORKLOAD_TOKEN_FILE": filepath.Join(t.TempDir(), "absent")}))
	require.Error(t, err)

	tok := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tok, []byte("t"), 0o600))
	c, err := Load(env(map[string]string{"WORKLOAD_TOKEN_FILE": tok}))
	require.NoError(t, err)
	assert.True(t, c.WorkloadAuth)
	assert.Equal(t, tok, c.TokenFile)
}

func TestWorkloadAuthAcceptsOnlyDisabled(t *testing.T) {
	_, err := Load(env(map[string]string{"WORKLOAD_AUTH": "off"}))
	require.Error(t, err)
}

func TestOverridesAndLists(t *testing.T) {
	c, err := Load(env(map[string]string{
		"WORKLOAD_AUTH":           "disabled",
		"STEWARD_IDENTITY_ADDR":   "identity.example.org:9090",
		"ALLOWED_ORIGINS":         "https://app.example.org, https://admin.example.org",
		"DIAGNOSTICS_HTTP_PROBES": "pdf-renderer=http://renderer.example.org/readyz",
		"KUBERNETES_SERVICE_HOST": "192.0.2.1",
	}))
	require.NoError(t, err)
	assert.Equal(t, "identity.example.org:9090", c.Backends["identity"])
	assert.Equal(t, []string{"https://app.example.org", "https://admin.example.org"}, c.AllowedOrigins)
	assert.Equal(t, "http://renderer.example.org/readyz", c.HTTPProbes["pdf-renderer"])
	assert.Equal(t, "https://192.0.2.1:443", c.KubernetesAPI)
}

func TestBadValuesAreRefused(t *testing.T) {
	for k, v := range map[string]string{"SESSION_TTL": "soon", "COLLAB_WS_MAX_MESSAGE_BYTES": "-1", "DIAGNOSTICS_HTTP_PROBES": "nourl"} {
		_, err := Load(env(map[string]string{"WORKLOAD_AUTH": "disabled", k: v}))
		assert.Error(t, err, k)
	}
}
