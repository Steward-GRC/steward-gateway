// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractText_TxtAndMd(t *testing.T) {
	got, err := extractText("notes.txt", []byte("hello   world\n\nline two"))
	require.NoError(t, err)
	require.Equal(t, "hello world line two", got)

	got, err = extractText("README.md", []byte("# Title\n\nsome *markdown*"))
	require.NoError(t, err)
	require.Equal(t, "# Title some *markdown*", got)
}

func TestExtractText_UnsupportedType(t *testing.T) {
	_, err := extractText("budget.xlsx", []byte("whatever"))
	require.Error(t, err)
	require.Equal(t,
		"Unsupported file type: .xlsx — attach a PDF, Word (.docx or .doc), RTF, Markdown, or text file",
		err.Error(),
	)
}

func TestExtractText_Docx(t *testing.T) {
	data := buildTestDocx(t, "<w:p><w:r><w:t>hello world</w:t></w:r></w:p>")
	got, err := extractText("memo.docx", data)
	require.NoError(t, err)
	require.Equal(t, "hello world", got)
}

func TestExtractText_DocxMultiParagraphAndTab(t *testing.T) {
	body := "<w:p><w:r><w:t>first</w:t></w:r></w:p>" +
		"<w:p><w:r><w:t>second</w:t><w:tab/><w:t>third</w:t></w:r></w:p>"
	data := buildTestDocx(t, body)
	got, err := extractText("memo.docx", data)
	require.NoError(t, err)
	require.Equal(t, "first second third", got)
}

func TestExtractText_DocxNotAZip(t *testing.T) {
	_, err := extractText("fake.docx", []byte("not a zip file"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't look like a valid Word (.docx) file")
}

func TestExtractText_RTF(t *testing.T) {
	got, err := extractText("note.rtf", []byte(`{\rtf1\ansi hello \b world\b0\par}`))
	require.NoError(t, err)
	require.Equal(t, "hello world", got)
}

func TestExtractText_RTFDropsFontAndColorTables(t *testing.T) {
	rtf := `{\rtf1\ansi{\fonttbl{\f0\fswiss Arial;}}{\colortbl;\red0\green0\blue0;}` +
		`\pard actual body text\par}`
	got, err := extractText("note.rtf", []byte(rtf))
	require.NoError(t, err)
	require.Equal(t, "actual body text", got)
}

func TestExtractText_RTFHexEscape(t *testing.T) {
	// \'68\'69 -> "hi"
	got, err := extractText("note.rtf", []byte(`{\rtf1 \'68\'69 there\par}`))
	require.NoError(t, err)
	require.Equal(t, "hi there", got)
}

func TestExtractText_RTFNotRTF(t *testing.T) {
	_, err := extractText("note.rtf", []byte("plain text, not rtf at all"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't look like a valid RTF file")
}

func TestExtractText_PDF(t *testing.T) {
	data := buildTestPDF(t, "hello world from pdf")
	got, err := extractText("report.pdf", data)
	require.NoError(t, err)
	require.Contains(t, got, "hello world from pdf")
}

func TestExtractText_PDFNotAPDF(t *testing.T) {
	_, err := extractText("fake.pdf", []byte("not a pdf"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't look like a valid PDF")
}

// TestScrapeLegacyDocText exercises the .doc BEST-EFFORT heuristic directly
// on synthetic WordDocument-stream-shaped bytes: real Word binary streams mix
// FIB/piece-table metadata with the actual text, so this only asserts the
// scrape recovers plausible words out of a noisy byte soup — not a full
// compound-file round trip (building a valid CFB/OLE container by hand for a
// test fixture was not worth the complexity for a heuristic, best-effort
// path; extractLegacyDocText's mscfb container parsing itself is covered by
// mscfb's own upstream tests). This is the "documented best-effort" note
// called out in the MR.
func TestScrapeLegacyDocText(t *testing.T) {
	var b []byte
	b = append(b, 0x00, 0x01, 0x02, 0xFF) // binary noise, too short to matter
	b = append(b, []byte("hello")...)     // plain ASCII run
	b = append(b, 0x00, 0x00, 0x00)       // more noise
	// UTF-16LE encoded "world"
	for _, c := range []byte("world") {
		b = append(b, c, 0x00)
	}
	b = append(b, 0x0F, 0x1A) // trailing noise

	got := scrapeLegacyDocText(b)
	require.Contains(t, got, "hello")
	require.Contains(t, got, "world")
}

func TestExtractText_DocNotOLE(t *testing.T) {
	_, err := extractText("fake.doc", []byte("not an OLE compound file"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't look like a valid legacy Word (.doc) file")
}

func TestNormalizeText(t *testing.T) {
	got := normalizeText("hello\x00\x01  \t\nworld\x7f  !")
	require.Equal(t, "hello world !", got)
}

func TestTruncateChars(t *testing.T) {
	require.Equal(t, "hello", truncateChars("hello", 10))
	require.Equal(t, "hel", truncateChars("hello", 3))
	// Must not split a multi-byte rune.
	require.Equal(t, "héllo", truncateChars("héllo world", 5))
}

// --- test fixtures ---------------------------------------------------------

// buildTestDocx assembles a minimal .docx (a zip containing
// word/document.xml wrapping bodyXML) — enough for docxXMLToText to exercise
// the real archive/zip + encoding/xml path end to end.
func buildTestDocx(t *testing.T, bodyXML string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("word/document.xml")
	require.NoError(t, err)
	xmlDoc := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body>` + bodyXML + `</w:body></w:document>`
	_, err = w.Write([]byte(xmlDoc))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// buildTestPDF hand-assembles a minimal, valid single-page PDF containing
// text drawn with a Tj operator, computing real object byte offsets for the
// xref table (rather than hardcoding them) so ledongthuc/pdf's normal
// xref-table code path parses it — this is a genuine end-to-end extraction
// test, not just a type-dispatch check.
func buildTestPDF(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	var offsets []int

	writeObj := func(id int, body string) {
		offsets = append(offsets, buf.Len())
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", id, body)
	}

	buf.WriteString("%PDF-1.4\n")
	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	writeObj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "+
		"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>")
	content := fmt.Sprintf("BT /F1 24 Tf 72 700 Td (%s) Tj ET", text)
	writeObj(4, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content))
	writeObj(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	xrefOffset := buf.Len()
	buf.WriteString("xref\n")
	fmt.Fprintf(&buf, "0 %d\n", len(offsets)+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	buf.WriteString("trailer\n")
	fmt.Fprintf(&buf, "<< /Size %d /Root 1 0 R >>\n", len(offsets)+1)
	buf.WriteString("startxref\n")
	fmt.Fprintf(&buf, "%d\n", xrefOffset)
	buf.WriteString("%%EOF")
	return buf.Bytes()
}
