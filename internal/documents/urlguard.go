// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	fetchTimeout = 10 * time.Second
	maxRedirects = 5
)

// blockedHostSuffixes are hostname patterns rejected outright, before any
// DNS resolution — conventional LAN-only TLDs that a public DNS lookup would
// never legitimately resolve for this gateway's use case.
var blockedHostSuffixes = []string{".local", ".internal"}

// validateFetchURL parses rawURL and enforces the SSRF policy that doesn't
// require a DNS lookup: scheme must be http/https, and the hostname must not
// be localhost/*.local/*.internal or a literal IP in a blocked range. Hosts
// that are ordinary DNS names are deferred to the dialer (safeDialContext),
// which re-checks every resolved address right before connecting — that is
// the only point a rebind between validation and connection can't happen.
func validateFetchURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, extractErrf("Missing url — provide a URL to check")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, extractErrf("Invalid URL — could not parse %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, extractErrf("Unsupported URL scheme %q — only http and https are allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "" || u.Host == "" {
		return nil, extractErrf("Invalid URL — missing host")
	}
	if isBlockedHostname(host) {
		return nil, extractErrf("This URL points to a blocked host — internal/local addresses are not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && isBlockedIP(ip) {
		return nil, extractErrf("This URL points to a blocked address — internal/private/link-local addresses are not allowed")
	}
	return u, nil
}

// isBlockedHostname reports whether host — before any DNS resolution — is a
// name this policy blocks outright: localhost, or a *.local/*.internal name.
func isBlockedHostname(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" {
		return true
	}
	for _, suffix := range blockedHostSuffixes {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// isBlockedIP reports loopback, private (RFC 1918 and IPv6 unique-local),
// link-local (which covers the cloud metadata address) and unspecified
// addresses.
func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

// newSafeFetchClient builds an http.Client whose Transport resolves and
// validates the destination address itself (safeDialContext) rather than
// trusting net/http's default dialer, and whose CheckRedirect caps the
// redirect chain and re-checks scheme/hostname on every hop before that
// hop's connection is ever dialed.
func newSafeFetchClient() *http.Client {
	dialer := &net.Dialer{Timeout: fetchTimeout}
	return &http.Client{
		Timeout: fetchTimeout,
		Transport: &http.Transport{
			DialContext: safeDialContext(dialer),
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q", req.URL.Scheme)
			}
			if isBlockedHostname(req.URL.Hostname()) {
				return fmt.Errorf("redirect to blocked host %q", req.URL.Hostname())
			}
			return nil
		},
	}
}

// safeDialContext resolves addr's host itself, rejects the connection if any
// resolved address (or a literal-IP host) is blocked, and — critically —
// dials the specific IP it just validated rather than the hostname again, so
// a second, attacker-controlled DNS answer (a rebind) between validation and
// connection can't slip a blocked address past this check. It runs for the
// initial request and for every redirect hop, since each is a fresh dial.
func safeDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}
		if isBlockedHostname(host) {
			return nil, fmt.Errorf("blocked host %q", host)
		}
		if ip := net.ParseIP(host); ip != nil {
			if isBlockedIP(ip) {
				return nil, fmt.Errorf("blocked address %s", ip)
			}
			return dialer.DialContext(ctx, network, addr)
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("could not resolve host %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("host %q did not resolve to any address", host)
		}
		for _, resolved := range ips {
			if isBlockedIP(resolved.IP) {
				return nil, fmt.Errorf("host %q resolves to a blocked address %s", host, resolved.IP)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}
