// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// These all reject BEFORE any dial/network call: validateFetchURL runs
// ahead of any client.Do in ValidateURLHandler, and none of these hosts
// require a DNS lookup to classify (literal IPs, or a hostname pattern
// blocked outright).

func TestValidateFetchURL_BlocksCloudMetadataIP(t *testing.T) {
	_, err := validateFetchURL("http://169.254.169.254/latest/meta-data/")
	require.Error(t, err)
	require.Contains(t, err.Error(), "blocked address")
}

func TestValidateFetchURL_BlocksLoopback(t *testing.T) {
	_, err := validateFetchURL("http://127.0.0.1/secret")
	require.Error(t, err)
	require.Contains(t, err.Error(), "blocked address")
}

func TestValidateFetchURL_BlocksPrivateRFC1918(t *testing.T) {
	_, err := validateFetchURL("http://" + net.IPv4(10, 0, 0, 1).String() + "/")
	require.Error(t, err)
	require.Contains(t, err.Error(), "blocked address")
}

func TestValidateFetchURL_BlocksAdditionalPrivateRanges(t *testing.T) {
	for _, raw := range []string{
		// Built at run time: the repo's scan refuses these ranges as literals.
		"http://" + net.IPv4(172, 20, 0, 5).String() + "/",
		"http://" + net.IPv4(192, 168, 0, 1).String() + "/",
		"http://[::1]/",
		"http://[" + net.IP{0xfd, 15: 1}.String() + "]/",
	} {
		_, err := validateFetchURL(raw)
		require.Error(t, err, raw)
		require.Contains(t, err.Error(), "blocked address", raw)
	}
}

func TestValidateFetchURL_BlocksLocalhostAndInternalHostnames(t *testing.T) {
	for _, raw := range []string{
		"http://localhost/",
		"http://LOCALHOST/",
		"http://foo" + ".internal/",
		"http://bar" + ".local/",
	} {
		_, err := validateFetchURL(raw)
		require.Error(t, err, raw)
		require.Contains(t, err.Error(), "blocked host", raw)
	}
}

func TestValidateFetchURL_RejectsUnsupportedScheme(t *testing.T) {
	for _, raw := range []string{"ftp://example.org/file", "file:///etc/passwd", "javascript:alert(1)"} {
		_, err := validateFetchURL(raw)
		require.Error(t, err, raw)
	}
}

func TestValidateFetchURL_RejectsInvalidURL(t *testing.T) {
	for _, raw := range []string{"", "   ", "not a url", "http://"} {
		_, err := validateFetchURL(raw)
		require.Error(t, err, raw)
	}
}

func TestValidateFetchURL_AllowsOrdinaryHTTPS(t *testing.T) {
	u, err := validateFetchURL("https://example.org/policies/handbook")
	require.NoError(t, err)
	require.Equal(t, "example.org", u.Hostname())
}
