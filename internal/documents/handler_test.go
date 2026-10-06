// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// newMultipartRequest builds a POST with a single "file" part named filename
// containing content — the exact shape ExtractHandler expects.
func newMultipartRequest(t *testing.T, filename string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", filename)
	require.NoError(t, err)
	_, err = part.Write(content)
	require.NoError(t, err)
	require.NoError(t, mw.Close())

	req := httptest.NewRequest(http.MethodPost, "/documents/extract", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func TestExtractHandler_TxtSuccess(t *testing.T) {
	req := newMultipartRequest(t, "policy-notes.txt", []byte("hello   world"))
	rec := httptest.NewRecorder()

	ExtractHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var got extractResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "policy-notes", got.Title)
	require.Equal(t, "hello world", got.Content)
}

func TestExtractHandler_UnsupportedType(t *testing.T) {
	req := newMultipartRequest(t, "budget.xlsx", []byte("whatever"))
	rec := httptest.NewRecorder()

	ExtractHandler(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var got errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Contains(t, got.Error, "Unsupported file type: .xlsx")
}

func TestExtractHandler_Oversized(t *testing.T) {
	big := bytes.Repeat([]byte("a"), MaxUploadBytes+1)
	req := newMultipartRequest(t, "huge.txt", big)
	rec := httptest.NewRecorder()

	ExtractHandler(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var got errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Contains(t, got.Error, "too large")
}

func TestExtractHandler_MissingFilePart(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	require.NoError(t, mw.WriteField("notfile", "value"))
	require.NoError(t, mw.Close())

	req := httptest.NewRequest(http.MethodPost, "/documents/extract", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()

	ExtractHandler(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var got errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Contains(t, got.Error, "Missing file")
}

func TestExtractHandler_TitleStripsExtensionOnly(t *testing.T) {
	req := newMultipartRequest(t, "Q3.Policy.Draft.md", []byte("content"))
	rec := httptest.NewRecorder()

	ExtractHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got extractResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "Q3.Policy.Draft", got.Title)
}

func TestExtractHandler_ContentTruncatedAtMax(t *testing.T) {
	req := newMultipartRequest(t, "long.txt", bytes.Repeat([]byte("a"), MaxContentChars+500))
	rec := httptest.NewRecorder()

	ExtractHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got extractResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got.Content, MaxContentChars)
}
