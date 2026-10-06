// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

// MaxUploadBytes bounds the uploaded file itself. multipartOverhead gives
// ParseMultipartForm's underlying http.MaxBytesReader a little extra budget
// for multipart boundary/header bytes so a file right at the 10 MB line isn't
// rejected on request-framing overhead alone; the file-size check below still
// enforces the real 10 MB ceiling.
const (
	MaxUploadBytes    = 10 << 20 // 10 MiB
	multipartOverhead = 64 << 10
)

type extractResponse struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

// ExtractHandler serves POST /documents/extract: one multipart file part named
// "file" in, {"title","content"} out, or {"error"} with a 400.
func ExtractHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes+multipartOverhead)
	if err := r.ParseMultipartForm(MaxUploadBytes + multipartOverhead); err != nil {
		writeError(w, http.StatusBadRequest, "File too large or malformed upload — max upload size is 10 MB")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, `Missing file — attach a single file under the "file" field`)
		return
	}
	defer func() { _ = file.Close() }()

	if header.Size > MaxUploadBytes {
		writeError(w, http.StatusBadRequest, "File too large — max upload size is 10 MB")
		return
	}

	data, err := io.ReadAll(io.LimitReader(file, MaxUploadBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Failed to read uploaded file")
		return
	}
	if int64(len(data)) > MaxUploadBytes {
		writeError(w, http.StatusBadRequest, "File too large — max upload size is 10 MB")
		return
	}

	filename := filepath.Base(header.Filename)
	content, err := extractText(filename, data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	content = truncateChars(content, MaxContentChars)
	title := strings.TrimSuffix(filename, filepath.Ext(filename))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(extractResponse{Title: title, Content: content})
}
