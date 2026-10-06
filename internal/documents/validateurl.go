// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// maxRequestBodyBytes bounds the incoming {"url": "..."} JSON body itself —
// it should never be more than a URL string, so this is generous headroom
// rather than a real limit.
const maxRequestBodyBytes = 64 << 10 // 64 KiB

// maxTitlePeekBytes caps how much of a response body this endpoint will
// ever read — just enough to reach a <title> in virtually any real page.
// This is a display nicety, never content extraction: the endpoint's job is
// a readability verdict, not parsing the page.
const maxTitlePeekBytes = 64 << 10 // 64 KiB

type validateURLRequest struct {
	URL string `json:"url"`
}

type validateURLResponse struct {
	Readable bool   `json:"readable"`
	Reason   string `json:"reason,omitempty"`
	Title    string `json:"title,omitempty"`
	FinalURL string `json:"finalUrl,omitempty"`
}

// ValidateURLHandler serves POST /documents/validate-url. It doesn't fetch the
// page's content; the URL itself goes to the AI drafting flow. It only checks,
// server-side so the SSRF risk stays here, that {"url": "..."} is reachable and
// readable without a login, answering {"readable","reason","title","finalUrl"},
// or {"error"} with a 400 for a bad or blocked URL.
func ValidateURLHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req validateURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, `Malformed request — expected JSON {"url": "https://..."}`)
		return
	}

	u, err := validateFetchURL(req.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	fetchCtx, cancel := context.WithTimeout(r.Context(), fetchTimeout)
	defer cancel()
	result := checkReadability(fetchCtx, newSafeFetchClient(), u)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// checkReadability makes a lightweight request against u — HEAD first, since
// this only needs a status code and final URL, falling back to a small, size
// -capped GET when HEAD isn't supported (405/501) — and turns the outcome
// into a readability verdict. On a genuinely readable page it makes one more
// small, capped GET purely to grab a <title> for display; it never reads a
// full response body for content. client is injected so tests can supply a
// fake Transport instead of hitting the network.
func checkReadability(ctx context.Context, client *http.Client, u *url.URL) validateURLResponse {
	headResp, err := doGuardedRequest(ctx, client, http.MethodHead, u)
	if err != nil {
		return validateURLResponse{Readable: false, Reason: "couldn't be reached"}
	}
	defer func() { _ = headResp.Body.Close() }()

	// Some servers don't support HEAD; its status alone isn't trustworthy
	// then, so redo the check with a small, capped GET instead — and reuse
	// that response's body for the title peek below, rather than a third
	// request.
	if headResp.StatusCode == http.StatusMethodNotAllowed || headResp.StatusCode == http.StatusNotImplemented {
		getResp, getErr := doGuardedRequest(ctx, client, http.MethodGet, u)
		if getErr != nil {
			return validateURLResponse{Readable: false, Reason: "couldn't be reached"}
		}
		defer func() { _ = getResp.Body.Close() }()
		result := verdictFromResponse(getResp, u)
		if result.Readable {
			result.Title = peekTitle(getResp.Body)
		}
		return finalizeTitle(result, u)
	}

	result := verdictFromResponse(headResp, u)
	if result.Readable {
		if getResp, getErr := doGuardedRequest(ctx, client, http.MethodGet, u); getErr == nil {
			defer func() { _ = getResp.Body.Close() }()
			result.Title = peekTitle(getResp.Body)
		}
	}
	return finalizeTitle(result, u)
}

// doGuardedRequest issues method against u through client (expected to be an
// SSRF-guarded client — see newSafeFetchClient), tagged with a descriptive
// User-Agent for the sites it probes.
func doGuardedRequest(ctx context.Context, client *http.Client, method string, u *url.URL) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "steward-gateway-url-check/1.0")
	return client.Do(req)
}

// loginPathMarkers are path substrings strongly associated with an
// authentication wall — deliberately narrow so ordinary content pages
// (e.g. "/authors") aren't misclassified.
var loginPathMarkers = []string{"login", "signin", "sign-in", "/sso", "authwall"}

// verdictFromResponse classifies resp into a readable/unreadable verdict —
// 401/403 or a redirect that landed on an obvious login path both mean
// "requires a login"; 2xx means readable; anything else is a generic
// server-error verdict. It also records the final URL (post-redirect, from
// resp.Request) so the caller/UI can see where a redirect actually landed.
func verdictFromResponse(resp *http.Response, requested *url.URL) validateURLResponse {
	finalURL := requested.String()
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return validateURLResponse{Readable: false, Reason: "requires a login", FinalURL: finalURL}
	case looksLikeLoginURL(finalURL):
		return validateURLResponse{Readable: false, Reason: "requires a login", FinalURL: finalURL}
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return validateURLResponse{Readable: true, FinalURL: finalURL}
	default:
		return validateURLResponse{
			Readable: false,
			Reason:   fmt.Sprintf("server returned HTTP %d", resp.StatusCode),
			FinalURL: finalURL,
		}
	}
}

// looksLikeLoginURL reports whether rawURL's path contains one of
// loginPathMarkers — used to catch the common case of a redirect (still
// answered 200 for the login page itself) landing on a sign-in screen.
func looksLikeLoginURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for _, marker := range loginPathMarkers {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

// finalizeTitle fills in result.Title with the titleFromURL fallback when no
// <title> was captured (either because the page had none, or because it
// wasn't readable in the first place, so no title peek was attempted).
func finalizeTitle(result validateURLResponse, u *url.URL) validateURLResponse {
	if result.Title == "" {
		result.Title = titleFromURL(u)
	}
	return result
}

// titleFromURL builds the fallback title used when a checked page has no
// usable <title>: the URL's host+path, e.g. "example.com/policies/handbook".
func titleFromURL(u *url.URL) string {
	host := u.Hostname()
	path := u.EscapedPath()
	if path == "" || path == "/" {
		return host
	}
	return host + path
}

// peekTitle reads at most maxTitlePeekBytes of body looking for a <title>
// element via a streaming tokenizer — it stops the moment </title> closes,
// so on a typical page (title near the top of <head>) it reads far less than
// the cap. This is a display nicety only; it is not a content extractor.
func peekTitle(body io.Reader) string {
	z := html.NewTokenizer(io.LimitReader(body, maxTitlePeekBytes))
	var sb strings.Builder
	inTitle := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return normalizeText(sb.String())
		case html.StartTagToken:
			if strings.ToLower(z.Token().Data) == "title" {
				inTitle = true
			}
		case html.EndTagToken:
			if strings.ToLower(z.Token().Data) == "title" {
				return normalizeText(sb.String())
			}
		case html.TextToken:
			if inTitle {
				sb.Write(z.Text())
			}
		}
	}
}
