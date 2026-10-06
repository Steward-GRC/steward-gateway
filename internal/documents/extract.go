// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package documents serves the AI drafting flow's reference material: it
// turns an uploaded PDF, Word, RTF, Markdown or text file into plain text
// (POST /documents/extract), and checks that a staff-supplied URL is publicly
// readable (POST /documents/validate-url) behind an SSRF guard. Both run
// behind the session gate; the handlers do no authentication themselves.
package documents

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/ledongthuc/pdf"
	"github.com/richardlehane/mscfb"
)

// MaxContentChars caps extracted content length. It is generous enough for a
// real reference document while bounding what the gateway forwards into an AI
// job input.
const MaxContentChars = 200_000

// unsupportedTypeError reports a file extension outside the supported set.
// Its message is the exact 400 body text (POST /documents/extract's error
// contract), so callers should surface Error() directly.
type unsupportedTypeError struct{ ext string }

func (e *unsupportedTypeError) Error() string {
	return fmt.Sprintf(
		"Unsupported file type: %s — attach a PDF, Word (.docx or .doc), RTF, Markdown, or text file",
		e.ext,
	)
}

// extractErr is a user-facing failure: its text is the 400 body, so it is a
// whole sentence rather than a wrappable fragment.
type extractErr string

func (e extractErr) Error() string { return string(e) }

func extractErrf(format string, args ...any) error {
	return extractErr(fmt.Sprintf(format, args...))
}

// extractText dispatches on the file's extension (case-insensitive) and
// returns whitespace-normalized, control-char-stripped UTF-8 text. It does
// NOT truncate to MaxContentChars — callers do that once, after choosing the
// title, so extraction and truncation stay independently testable.
func extractText(filename string, data []byte) (string, error) {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".txt", ".md":
		return normalizeText(string(data)), nil
	case ".pdf":
		return extractPDFText(data)
	case ".docx":
		return extractDocxText(data)
	case ".doc":
		return extractLegacyDocText(data)
	case ".rtf":
		return extractRTFText(data)
	default:
		return "", &unsupportedTypeError{ext: ext}
	}
}

// --- PDF -------------------------------------------------------------------

// extractPDFText reads every page's plain text with ledongthuc/pdf (pure Go,
// no cgo).
func extractPDFText(data []byte) (string, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("%PDF")) {
		return "", extractErrf("This file doesn't look like a valid PDF — check the file and try again")
	}
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", extractErrf("Failed to read PDF: %v", err)
	}
	rd, err := r.GetPlainText()
	if err != nil {
		return "", extractErrf("Failed to extract text from PDF: %v", err)
	}
	buf, err := io.ReadAll(rd)
	if err != nil {
		return "", extractErrf("Failed to extract text from PDF: %v", err)
	}
	return normalizeText(string(buf)), nil
}

// --- DOCX --------------------------------------------------------------

// extractDocxText treats the .docx as what it is — a zip archive — and reads
// word/document.xml with the standard library's archive/zip + encoding/xml,
// avoiding a heavy or commercial docx dependency.
func extractDocxText(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", extractErrf("This file doesn't look like a valid Word (.docx) file — check the file and try again")
	}
	var docFile *zip.File
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			docFile = f
			break
		}
	}
	if docFile == nil {
		return "", extractErrf("This .docx file is missing word/document.xml — it may be corrupt")
	}
	rc, err := docFile.Open()
	if err != nil {
		return "", extractErrf("Failed to read .docx contents: %v", err)
	}
	defer func() { _ = rc.Close() }()
	xmlBytes, err := io.ReadAll(rc)
	if err != nil {
		return "", extractErrf("Failed to read .docx contents: %v", err)
	}
	return normalizeText(docxXMLToText(xmlBytes)), nil
}

// docxXMLToText walks word/document.xml's tokens and keeps only the character
// data (the <w:t> run text), turning paragraph/line/tab elements into a
// newline or tab so words from different runs don't run together. It ignores
// the namespace prefix on element names (Go's xml.Decoder reports whatever
// prefix the document used, e.g. "w", even when the "w:" xmlns isn't in
// scope for a bare fragment) and matches on local name only.
func docxXMLToText(b []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(b))
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "p":
				sb.WriteString("\n")
			case "tab":
				sb.WriteString("\t")
			case "br", "cr":
				sb.WriteString("\n")
			}
		case xml.CharData:
			sb.Write(t)
		}
	}
	return sb.String()
}

// --- legacy .doc (best-effort) ----------------------------------------

// extractLegacyDocText extracts text from a legacy binary (OLE/CFB) Word
// document on a BEST-EFFORT basis only. The real format requires parsing the
// FIB header and piece table to know which byte ranges are live document text
// versus revision/formatting metadata — out of scope here. Instead this opens
// the compound file with mscfb, locates the WordDocument stream, and scrapes
// it for runs of plausible text (plain ASCII and UTF-16LE-encoded ASCII,
// which is how older Word stores Unicode runs). That heuristic is lossy —
// expect noise around headers/footers/revision marks and no reliable
// paragraph structure — but it beats refusing the file outright. Prefer
// .docx, .pdf, or .rtf for full-fidelity extraction.
func extractLegacyDocText(data []byte) (string, error) {
	r, err := mscfb.New(bytes.NewReader(data))
	if err != nil {
		return "", extractErrf("This file doesn't look like a valid legacy Word (.doc) file — check the file and try again")
	}
	var wordDoc []byte
	for entry, entryErr := r.Next(); entryErr == nil; entry, entryErr = r.Next() {
		if strings.EqualFold(entry.Name, "WordDocument") {
			wordDoc, err = io.ReadAll(entry)
			if err != nil {
				return "", extractErrf("Failed to read .doc contents: %v", err)
			}
			break
		}
	}
	if len(wordDoc) == 0 {
		return "", extractErrf("This .doc file has no WordDocument stream — it may be corrupt")
	}
	text := scrapeLegacyDocText(wordDoc)
	if strings.TrimSpace(text) == "" {
		return "", extractErrf("Could not extract any readable text from this .doc file — try saving it as .docx or PDF")
	}
	return normalizeText(text), nil
}

// minRunLen is the shortest run of plausible text bytes worth keeping — below
// this, a "run" is more likely a coincidental byte sequence in binary
// metadata than actual words.
const minRunLen = 3

// scrapeLegacyDocText scans raw WordDocument stream bytes for runs of
// printable ASCII and runs of UTF-16LE-encoded ASCII (low byte printable,
// high byte 0x00 — how older Word encodes Unicode text runs), joining
// whatever it finds with spaces. This intentionally does not attempt to
// resolve the FIB/piece table, so ordering across streams/tables is not
// guaranteed — it is a heuristic scrape, not a structural parse.
func scrapeLegacyDocText(b []byte) string {
	var tokens []string

	appendRun := func(run []byte) {
		if len(run) >= minRunLen {
			tokens = append(tokens, string(run))
		}
	}

	// UTF-16LE pass: pairs of (printable-ascii, 0x00).
	var u16run []byte
	i := 0
	for i+1 < len(b) {
		lo, hi := b[i], b[i+1]
		if hi == 0x00 && isPrintableASCII(lo) {
			u16run = append(u16run, lo)
			i += 2
			continue
		}
		appendRun(u16run)
		u16run = nil
		i++
	}
	appendRun(u16run)

	// Plain ASCII pass (catches 8-bit runs the UTF-16LE pass skips over).
	var run []byte
	for _, c := range b {
		if isPrintableASCII(c) {
			run = append(run, c)
			continue
		}
		appendRun(run)
		run = nil
	}
	appendRun(run)

	return strings.Join(tokens, " ")
}

func isPrintableASCII(c byte) bool {
	return (c >= 0x20 && c <= 0x7E) || c == '\t'
}

// --- RTF -----------------------------------------------------------------

// rtfSkipGroups are control words whose whole group is metadata, not body
// text. Everything inside one (nested groups included) is dropped.
var rtfSkipGroups = map[string]bool{
	"fonttbl":    true,
	"colortbl":   true,
	"stylesheet": true,
	"generator":  true,
	"info":       true,
}

// extractRTFText strips RTF control words/groups down to plain text with a
// small hand-rolled scanner (no RTF library): control words (\word or
// \word123) are consumed and dropped except \par/\line (→ newline) and \tab
// (→ tab); \\, \{, \} are unescaped; \'hh hex escapes are decoded; and whole
// groups opened by rtfSkipGroups are skipped, braces and all.
func extractRTFText(data []byte) (string, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte(`{\rtf`)) {
		return "", extractErrf("This file doesn't look like a valid RTF file — check the file and try again")
	}
	var out strings.Builder
	skip := []bool{false} // stack of "am I inside a skip group" per brace depth
	n := len(data)
	i := 0
	top := func() bool { return skip[len(skip)-1] }

	for i < n {
		c := data[i]
		switch c {
		case '{':
			skip = append(skip, top())
			i++
		case '}':
			if len(skip) > 1 {
				skip = skip[:len(skip)-1]
			}
			i++
		case '\\':
			i++
			if i >= n {
				break
			}
			switch data[i] {
			case '\\', '{', '}':
				if !top() {
					out.WriteByte(data[i])
				}
				i++
			case '\'':
				i++
				if i+1 < n {
					if v, err := strconv.ParseUint(string(data[i:i+2]), 16, 8); err == nil && !top() {
						out.WriteByte(byte(v))
					}
					i += 2
				}
			default:
				start := i
				for i < n && isAlpha(data[i]) {
					i++
				}
				word := string(data[start:i])
				// Optional numeric parameter (control words like \b0, \f2, \'…
				// already handled above).
				if i < n && (data[i] == '-' || isDigit(data[i])) {
					if data[i] == '-' {
						i++
					}
					for i < n && isDigit(data[i]) {
						i++
					}
				}
				// A single trailing space is the control word's delimiter, not
				// document text — consume it.
				if i < n && data[i] == ' ' {
					i++
				}
				if !top() {
					switch word {
					case "par", "line":
						out.WriteByte('\n')
					case "tab":
						out.WriteByte('\t')
					}
				}
				if rtfSkipGroups[word] {
					skip[len(skip)-1] = true
				}
			}
		default:
			if !top() && c != '\r' && c != '\n' {
				out.WriteByte(c)
			}
			i++
		}
	}
	return normalizeText(out.String()), nil
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// --- shared normalization -------------------------------------------------

var (
	controlCharsRe = regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`)
	whitespaceRe   = regexp.MustCompile(`\s+`)
)

// normalizeText makes extracted text safe and consistent regardless of
// source format: valid UTF-8 only, no control characters, and no runs of
// whitespace longer than a single space.
func normalizeText(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = controlCharsRe.ReplaceAllString(s, "")
	s = whitespaceRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// truncateChars cuts s to at most max runes — a plain cut, nothing appended —
// without splitting a multi-byte UTF-8 sequence.
func truncateChars(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}
