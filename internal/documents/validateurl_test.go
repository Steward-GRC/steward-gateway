// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// newValidateURLRequest builds a POST /documents/validate-url request with
// the given raw JSON body string.
func newValidateURLRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodPost, "/documents/validate-url", strings.NewReader(body))
}

// fakeRoundTripper lets tests stand in for the network entirely: fn decides
// the response (or error) for every request checkReadability issues, so no
// test in this file makes a real DNS lookup or network call.
type fakeRoundTripper struct {
	fn func(req *http.Request) (*http.Response, error)
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f.fn(req)
}

func fakeClient(fn func(req *http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{Transport: &fakeRoundTripper{fn: fn}}
}

func htmlResponse(req *http.Request, status int, body string) (*http.Response, error) {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// --- ValidateURLHandler: cases that reject before any network call ---------

func TestValidateURLHandler_BlockedHostReturns400(t *testing.T) {
	req := newValidateURLRequest(t, `{"url":"http://169.254.169.254/latest/meta-data/"}`)
	rec := httptest.NewRecorder()

	ValidateURLHandler(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var got errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Contains(t, got.Error, "blocked")
}

func TestValidateURLHandler_InvalidURLReturns400(t *testing.T) {
	req := newValidateURLRequest(t, `{"url":"not a url"}`)
	rec := httptest.NewRecorder()

	ValidateURLHandler(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var got errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.NotEmpty(t, got.Error)
}

func TestValidateURLHandler_MissingURLReturns400(t *testing.T) {
	req := newValidateURLRequest(t, `{}`)
	rec := httptest.NewRecorder()

	ValidateURLHandler(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var got errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Contains(t, got.Error, "Missing url")
}

func TestValidateURLHandler_MalformedJSONReturns400(t *testing.T) {
	req := newValidateURLRequest(t, `{not json`)
	rec := httptest.NewRecorder()

	ValidateURLHandler(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var got errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Contains(t, got.Error, "Malformed request")
}

// --- checkReadability: exercised against a fake Transport, never the
// network — covers the 200/401/403/unreachable/login-redirect verdicts. ----

func TestCheckReadability_PublicPageIsReadableWithTitle(t *testing.T) {
	u, err := url.Parse("https://example.org/handbook")
	require.NoError(t, err)

	client := fakeClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return htmlResponse(req, http.StatusOK, "")
		}
		return htmlResponse(req, http.StatusOK, `<html><head><title>Handbook</title></head><body>hi</body></html>`)
	})

	got := checkReadability(context.Background(), client, u)

	require.True(t, got.Readable)
	require.Empty(t, got.Reason)
	require.Equal(t, "Handbook", got.Title)
	require.Equal(t, "https://example.org/handbook", got.FinalURL)
}

func TestCheckReadability_401IsUnreadableRequiresLogin(t *testing.T) {
	u, err := url.Parse("https://example.org/private")
	require.NoError(t, err)

	client := fakeClient(func(req *http.Request) (*http.Response, error) {
		return htmlResponse(req, http.StatusUnauthorized, "")
	})

	got := checkReadability(context.Background(), client, u)

	require.False(t, got.Readable)
	require.Equal(t, "requires a login", got.Reason)
	// No <title> peek is attempted for an unreadable page — the title falls
	// back to the URL itself, same as FinalURL, so the UI still has
	// something to show.
	require.Equal(t, "example.org/private", got.Title)
}

func TestCheckReadability_403IsUnreadableRequiresLogin(t *testing.T) {
	u, err := url.Parse("https://example.org/private")
	require.NoError(t, err)

	client := fakeClient(func(req *http.Request) (*http.Response, error) {
		return htmlResponse(req, http.StatusForbidden, "")
	})

	got := checkReadability(context.Background(), client, u)

	require.False(t, got.Readable)
	require.Equal(t, "requires a login", got.Reason)
}

func TestCheckReadability_RedirectToLoginPathIsUnreadable(t *testing.T) {
	u, err := url.Parse("https://example.org/doc")
	require.NoError(t, err)

	client := fakeClient(func(req *http.Request) (*http.Response, error) {
		// Simulate: the client already followed the redirect chain, and the
		// final request landed on a login page that itself answers 200.
		finalReq := req.Clone(req.Context())
		finalReq.URL, _ = url.Parse("https://example.org/login?next=/doc")
		return htmlResponse(finalReq, http.StatusOK, `<html><head><title>Sign In</title></head></html>`)
	})

	got := checkReadability(context.Background(), client, u)

	require.False(t, got.Readable)
	require.Equal(t, "requires a login", got.Reason)
	require.Equal(t, "https://example.org/login?next=/doc", got.FinalURL)
}

func TestCheckReadability_NetworkErrorIsUnreachable(t *testing.T) {
	u, err := url.Parse("https://example.org/doc")
	require.NoError(t, err)

	client := fakeClient(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: connection refused")
	})

	got := checkReadability(context.Background(), client, u)

	require.False(t, got.Readable)
	require.Equal(t, "couldn't be reached", got.Reason)
}

func TestCheckReadability_HEADUnsupportedFallsBackToGET(t *testing.T) {
	u, err := url.Parse("https://example.org/doc")
	require.NoError(t, err)

	var sawGET bool
	client := fakeClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return htmlResponse(req, http.StatusMethodNotAllowed, "")
		}
		sawGET = true
		return htmlResponse(req, http.StatusOK, `<html><head><title>Doc Title</title></head></html>`)
	})

	got := checkReadability(context.Background(), client, u)

	require.True(t, sawGET, "HEAD 405 should trigger a GET fallback")
	require.True(t, got.Readable)
	require.Equal(t, "Doc Title", got.Title)
}

func TestCheckReadability_ServerErrorIsUnreadable(t *testing.T) {
	u, err := url.Parse("https://example.org/doc")
	require.NoError(t, err)

	client := fakeClient(func(req *http.Request) (*http.Response, error) {
		return htmlResponse(req, http.StatusInternalServerError, "")
	})

	got := checkReadability(context.Background(), client, u)

	require.False(t, got.Readable)
	require.Contains(t, got.Reason, "500")
}

func TestCheckReadability_NoTitleFallsBackToURL(t *testing.T) {
	u, err := url.Parse("https://example.org/policies/handbook")
	require.NoError(t, err)

	client := fakeClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return htmlResponse(req, http.StatusOK, "")
		}
		return htmlResponse(req, http.StatusOK, `<html><body>no title here</body></html>`)
	})

	got := checkReadability(context.Background(), client, u)

	require.True(t, got.Readable)
	require.Equal(t, "example.org/policies/handbook", got.Title)
}

// --- peekTitle unit coverage -------------------------------------------------

func TestPeekTitle_ExtractsTitle(t *testing.T) {
	got := peekTitle(strings.NewReader(`<html><head><title>  Hello World  </title></head><body></body></html>`))
	require.Equal(t, "Hello World", got)
}

func TestPeekTitle_NoTitleReturnsEmpty(t *testing.T) {
	got := peekTitle(strings.NewReader(`<html><body><p>no title</p></body></html>`))
	require.Empty(t, got)
}
