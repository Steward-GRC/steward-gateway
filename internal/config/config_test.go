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

func TestAuthSettings(t *testing.T) {
	c, err := Load(env(map[string]string{"WORKLOAD_AUTH": "disabled"}))
	require.NoError(t, err)
	assert.Equal(t, "edge", c.Auth.MFAMode)
	assert.Equal(t, "X-Steward-Edge", c.Auth.MFAEdgeHeader)
	assert.Equal(t, "public", c.Auth.MFAEdgePublicValue)
	assert.True(t, c.Auth.PasskeyLogin)
	assert.Equal(t, "steward", c.Auth.PolisProduct)
	assert.Equal(t, 30*time.Minute, c.Auth.SSOTestLinkTTL)
	assert.Equal(t, "local", c.Auth.DefaultLoginMethod)
	assert.Equal(t, 5*time.Second, c.Auth.MaintenanceCacheTTL)
	assert.Empty(t, c.Auth.ReportProblemURL, "the report-a-problem link is off until the adopter sets it")
	assert.Empty(t, c.Auth.SetupToken)
	assert.False(t, c.Auth.CookieInsecure)

	c, err = Load(env(map[string]string{"WORKLOAD_AUTH": "disabled", "REPORT_PROBLEM_URL": "https://support.example.org/report",
		"MFA_ENFORCE": "always", "COOKIE_INSECURE": "true", "PASSKEY_LOGIN_ENABLED": "false"}))
	require.NoError(t, err)
	assert.Equal(t, "https://support.example.org/report", c.Auth.ReportProblemURL)
	assert.Equal(t, "always", c.Auth.MFAMode)
	assert.True(t, c.Auth.CookieInsecure)
	assert.False(t, c.Auth.PasskeyLogin)
}

func TestSSONeedsItsIssuerAndRedirectBase(t *testing.T) {
	_, err := Load(env(map[string]string{"WORKLOAD_AUTH": "disabled", "POLIS_PUBLIC_URL": "https://sso.example.org"}))
	require.Error(t, err)
	c, err := Load(env(map[string]string{"WORKLOAD_AUTH": "disabled", "POLIS_PUBLIC_URL": "https://sso.example.org",
		"POLIS_ISSUER_URL": "http://polis.example.org:5225", "SSO_REDIRECT_BASE": "https://app.example.org"}))
	require.NoError(t, err)
	assert.Equal(t, "http://polis.example.org:5225", c.Auth.PolisIssuerURL)
}

func TestNotifyLinksNeedThePreferencesURL(t *testing.T) {
	_, err := Load(env(map[string]string{"WORKLOAD_AUTH": "disabled", "NOTIFY_UNSUB_SECRET": "test-secret-not-real-0123456789"}))
	require.Error(t, err)
}

func TestBadMFAModeIsRefused(t *testing.T) {
	_, err := Load(env(map[string]string{"WORKLOAD_AUTH": "disabled", "MFA_ENFORCE": "sometimes"}))
	require.Error(t, err)
}
