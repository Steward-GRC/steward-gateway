// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package origin holds the browser Origin policy for websocket upgrades. A
// browser can't set headers on a websocket handshake, so the Origin it sends
// is the one thing that tells the app's own pages from a cross-site page.
package origin

import (
	"net/http"
	"net/url"
	"strings"
)

// Allowed reports whether r's Origin may open a websocket:
//
//   - no Origin: not a browser; the request's own credential decides;
//   - the Origin's host is the request's host, or the first X-Forwarded-Host
//     entry when the edge doesn't pass the original Host through;
//   - the Origin is in extra (a split-origin dev server);
//   - anything else, including "null", is refused.
func Allowed(r *http.Request, extra []string) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	for _, host := range requestHosts(r) {
		if strings.EqualFold(host, u.Host) {
			return true
		}
	}
	for _, allowed := range extra {
		if strings.EqualFold(allowed, o) {
			return true
		}
	}
	return false
}

// requestHosts is r.Host plus the client-facing X-Forwarded-Host entry.
// Trusting the forwarded host grants nothing new: a cross-site page can only
// present its own Origin, and a client that can forge headers can omit Origin.
func requestHosts(r *http.Request) []string {
	hosts := make([]string, 0, 2)
	if r.Host != "" {
		hosts = append(hosts, r.Host)
	}
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		first, _, _ := strings.Cut(fwd, ",")
		if first = strings.TrimSpace(first); first != "" {
			hosts = append(hosts, first)
		}
	}
	return hosts
}
