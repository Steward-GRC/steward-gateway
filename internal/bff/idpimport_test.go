// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

// testCertB64 is a real, self-signed ECDSA P-256 certificate (base64 DER) used
// across the parse/normalize fixtures so x509.ParseCertificate genuinely
// validates it rather than the tests exercising a hand-waved blob.
const testCertB64 = "MIIBITCBx6ADAgECAgEBMAoGCCqGSM49BAMCMBoxGDAWBgNVBAMTD2lkcC5leGFtcGxlLm9yZzAeFw0yMDA5MTMxMjI2NDBaFw0zMzA1MTgwMzMzMjBaMBoxGDAWBgNVBAMTD2lkcC5leGFtcGxlLm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIk91IcrEymrQyybtzLzn3mAe9yqa/pCxYaT66PnY1zQv+E+L03daAhoAbjjyHi8ZqlerSOfNtynr/5qP395ticwCgYIKoZIzj0EAwIDSQAwRgIhAITehwnvtD0saw+EzxJjtUt4PzdGdu5oTDQBeoKbHkCsAiEA81LBaOGqdWds5G/8nKAV1AwE88Ner/ZwWDFU4XXmlh8="

// sampleMetadata is a realistic SAML 2.0 IdP metadata document: md:/ds:
// prefixed, a signing + an encryption KeyDescriptor, both HTTP-POST and
// HTTP-Redirect SSO bindings (Redirect must win), and an Organization block.
// The signing certificate body is deliberately indented/newline-wrapped to
// exercise the whitespace tolerance in certBase64ToPEM.
func sampleMetadata(t *testing.T) []byte {
	t.Helper()
	var wrapped strings.Builder
	for i := 0; i < len(testCertB64); i += 64 {
		end := min(i+64, len(testCertB64))
		wrapped.WriteString("            ")
		wrapped.WriteString(testCertB64[i:end])
		wrapped.WriteString("\n")
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.org/saml/metadata">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
` + wrapped.String() + `          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>` + testCertB64 + `</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://idp.example.org/saml/sso/post"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp.example.org/saml/sso/redirect"/>
  </md:IDPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">Example Org Inc</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">Example Organization</md:OrganizationDisplayName>
  </md:Organization>
</md:EntityDescriptor>`)
}

func TestParseSAMLMetadata_ExtractsFields(t *testing.T) {
	meta, err := parseSAMLMetadata(sampleMetadata(t))
	if err != nil {
		t.Fatalf("parseSAMLMetadata: %v", err)
	}
	if meta.EntityID != "https://idp.example.org/saml/metadata" {
		t.Errorf("entityId = %q", meta.EntityID)
	}
	if meta.SSOURL != "https://idp.example.org/saml/sso/redirect" {
		t.Errorf("ssoUrl = %q, want the HTTP-Redirect Location", meta.SSOURL)
	}
	if !strings.HasPrefix(meta.SigningCertificate, "-----BEGIN CERTIFICATE-----") ||
		!strings.Contains(meta.SigningCertificate, "END CERTIFICATE") {
		t.Errorf("signingCertificate is not a PEM block:\n%s", meta.SigningCertificate)
	}
	if got := normalizeOrFail(t, []byte(meta.SigningCertificate)); got != canonicalPEM(t) {
		t.Errorf("signingCertificate does not round-trip to the input cert")
	}
	if meta.DisplayName != "Example Organization" {
		t.Errorf("displayName = %q", meta.DisplayName)
	}
}

func TestParseSAMLMetadata_PostBindingFallback(t *testing.T) {
	xml := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.net/idp">
	  <md:IDPSSODescriptor>
	    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>
	      <ds:X509Certificate>` + testCertB64 + `</ds:X509Certificate>
	    </ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
	    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	                            Location="https://idp.example.net/sso/post"/>
	  </md:IDPSSODescriptor>
	</md:EntityDescriptor>`
	meta, err := parseSAMLMetadata([]byte(xml))
	if err != nil {
		t.Fatalf("parseSAMLMetadata: %v", err)
	}
	if meta.SSOURL != "https://idp.example.net/sso/post" {
		t.Errorf("ssoUrl = %q, want HTTP-POST fallback", meta.SSOURL)
	}
	if meta.DisplayName != "idp.example.net" {
		t.Errorf("displayName = %q, want entityID host fallback", meta.DisplayName)
	}
}

func TestParseSAMLMetadata_Errors(t *testing.T) {
	cases := map[string]string{
		"garbage":             "this is not xml at all <<<",
		"missing entityID":    `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:IDPSSODescriptor/></md:EntityDescriptor>`,
		"no IDPSSODescriptor": `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://x/idp"/>`,
	}
	for name, xml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSAMLMetadata([]byte(xml)); err == nil {
				t.Fatalf("expected error for %q", name)
			}
		})
	}
}

func TestNormalizeCertPEM(t *testing.T) {
	der := mustDER(t)
	pemIn := "-----BEGIN CERTIFICATE-----\n" + wrap64(testCertB64) + "-----END CERTIFICATE-----\n"

	t.Run("PEM in -> PEM out", func(t *testing.T) {
		out, err := normalizeCertPEM([]byte(pemIn))
		if err != nil {
			t.Fatalf("normalizeCertPEM(PEM): %v", err)
		}
		if !strings.HasPrefix(out, "-----BEGIN CERTIFICATE-----") {
			t.Errorf("not a PEM block: %s", out)
		}
	})

	t.Run("DER in -> PEM out", func(t *testing.T) {
		out, err := normalizeCertPEM(der)
		if err != nil {
			t.Fatalf("normalizeCertPEM(DER): %v", err)
		}
		if !strings.HasPrefix(out, "-----BEGIN CERTIFICATE-----") {
			t.Errorf("not a PEM block: %s", out)
		}
	})

	t.Run("PEM and DER normalize to the same canonical block", func(t *testing.T) {
		fromPEM, _ := normalizeCertPEM([]byte(pemIn))
		fromDER, _ := normalizeCertPEM(der)
		if fromPEM != fromDER {
			t.Errorf("PEM and DER inputs produced different output")
		}
	})

	t.Run("garbage -> error", func(t *testing.T) {
		if _, err := normalizeCertPEM([]byte("not a certificate")); err == nil {
			t.Fatal("expected error for garbage input")
		}
	})

	t.Run("PEM block that is not an X509 cert -> error", func(t *testing.T) {
		bad := "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n"
		if _, err := normalizeCertPEM([]byte(bad)); err == nil {
			t.Fatal("expected error for non-x509 PEM CERTIFICATE block")
		}
	})
}

func TestIsBlockedFetchIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"169.254.169.254", "169.254.1.1", // link-local (cloud metadata)
		net.IPv4(10, 0, 0, 5).String(), net.IPv4(172, 20, 0, 1).String(), net.IPv4(192, 168, 1, 10).String(),
		net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}.String(), // IPv6 unique local
		net.IP{0xfd, 0x12, 0x34, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}.String(),
		"fe80::1",   // IPv6 link-local
		"0.0.0.0",   // unspecified
		"224.0.0.1", // multicast
	}
	for _, s := range blocked {
		if !isBlockedFetchIP(parseIP(t, s)) {
			t.Errorf("expected %s to be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::1"}
	for _, s := range allowed {
		if isBlockedFetchIP(parseIP(t, s)) {
			t.Errorf("expected %s to be allowed", s)
		}
	}
}

func TestIdpValidateFetchURL(t *testing.T) {
	if _, err := idpValidateFetchURL("https://idp.example.org/metadata"); err != nil {
		t.Errorf("https URL should be allowed: %v", err)
	}
	rejects := []string{
		"http://idp.example.org/metadata",                  // not https
		"ftp://idp.example.org/x",                          // not https
		"file:///etc/passwd",                               // not https
		"https://127.0.0.1/x",                              // literal loopback
		"https://169.254.169.254/latest",                   // literal cloud metadata
		"https://" + net.IPv4(10, 0, 0, 1).String() + "/x", // literal private
		"", // empty
	}
	for _, u := range rejects {
		if _, err := idpValidateFetchURL(u); err == nil {
			t.Errorf("expected %q to be rejected", u)
		}
	}
}

func TestIdpDialControl(t *testing.T) {
	blocked := []string{"127.0.0.1:443", "169.254.169.254:80", net.IPv4(10, 0, 0, 9).String() + ":443", "[::1]:443"}
	for _, a := range blocked {
		if err := idpDialControl("tcp", a, nil); err == nil {
			t.Errorf("expected dial to %s to be blocked", a)
		}
	}
	if err := idpDialControl("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("expected dial to public IP to be allowed: %v", err)
	}
}

// fakeRoundTripper serves canned responses without touching the network, so
// the fetch mechanics (status handling, size cap, happy path) can be exercised
// against an https URL that passes SSRF validation.
type fakeRoundTripper struct {
	status int
	body   []byte
	err    error
}

func (f fakeRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(bytes.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

func fakeClient(rt fakeRoundTripper) *http.Client { return &http.Client{Transport: rt} }

func TestFetchIDPDocument(t *testing.T) {
	ctx := context.Background()

	t.Run("rejects non-https before any fetch", func(t *testing.T) {
		_, err := fetchIDPDocument(ctx, fakeClient(fakeRoundTripper{status: 200, body: []byte("x")}), "http://idp.example.org/m")
		assertFetchStatus(t, err, http.StatusBadRequest)
	})

	t.Run("rejects blocked literal IP before any fetch", func(t *testing.T) {
		_, err := fetchIDPDocument(ctx, fakeClient(fakeRoundTripper{status: 200, body: []byte("x")}), "https://169.254.169.254/latest")
		assertFetchStatus(t, err, http.StatusBadRequest)
	})

	t.Run("non-2xx -> 502", func(t *testing.T) {
		_, err := fetchIDPDocument(ctx, fakeClient(fakeRoundTripper{status: 404, body: []byte("nope")}), "https://idp.example.org/m")
		assertFetchStatus(t, err, http.StatusBadGateway)
	})

	t.Run("oversized body -> 502", func(t *testing.T) {
		big := bytes.Repeat([]byte("A"), maxIDPFetchBytes+10)
		_, err := fetchIDPDocument(ctx, fakeClient(fakeRoundTripper{status: 200, body: big}), "https://idp.example.org/m")
		assertFetchStatus(t, err, http.StatusBadGateway)
	})

	t.Run("happy path returns body", func(t *testing.T) {
		body, err := fetchIDPDocument(ctx, fakeClient(fakeRoundTripper{status: 200, body: []byte("hello")}), "https://idp.example.org/m")
		if err != nil {
			t.Fatalf("fetchIDPDocument: %v", err)
		}
		if string(body) != "hello" {
			t.Errorf("body = %q", body)
		}
	})
}

// TestFetchIDPDocument_GuardBlocksLoopbackEndToEnd proves the real hardened
// client refuses a live connection to a loopback address: an httptest server
// (which always listens on 127.0.0.1) is unreachable through it. Uses a literal
// -IP https URL so the connect-time Control hook is what does the blocking.
func TestFetchIDPDocument_GuardBlocksLoopbackEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should never be reached"))
	}))
	defer srv.Close()
	target := strings.Replace(srv.URL, "http://", "https://", 1)
	if _, err := fetchIDPDocument(context.Background(), newIDPFetchClient(), target); err == nil {
		t.Fatal("expected the guarded client to block a loopback address")
	}
}

func siteAdminClaims() principal.Claims {
	return principal.Static{UserIDValue: "admin-1", RolesValue: []string{"admin", "site-admin"}}
}

func nonAdminClaims() principal.Claims {
	return principal.Static{UserIDValue: "user-1", RolesValue: []string{"reader"}}
}

// serveWithClaims serves body to h with claims on the context, as
// Authenticate leaves them.
func serveWithClaims(h http.HandlerFunc, claims principal.Claims, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/idp/import-metadata", strings.NewReader(body))
	if claims != nil {
		req = req.WithContext(principal.WithClaims(req.Context(), claims))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestImportMetadataHandler_ForbiddenNonSiteAdmin(t *testing.T) {
	rec := serveWithClaims(ImportMetadataHandler, nonAdminClaims(), `{"url":"https://idp.example.org/m"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestImportMetadataHandler_UnauthorizedNoClaims(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/idp/import-metadata", strings.NewReader(`{"url":"https://idp.example.org/m"}`))
	rec := httptest.NewRecorder()
	ImportMetadataHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestImportMetadataHandler_BadBody(t *testing.T) {
	rec := serveWithClaims(ImportMetadataHandler, siteAdminClaims(), `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestImportMetadataHandler_HappyPath(t *testing.T) {
	restore := newIDPFetchClientFn
	newIDPFetchClientFn = func() *http.Client {
		return fakeClient(fakeRoundTripper{status: 200, body: sampleMetadata(t)})
	}
	defer func() { newIDPFetchClientFn = restore }()

	rec := serveWithClaims(ImportMetadataHandler, siteAdminClaims(), `{"url":"https://idp.example.org/metadata"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp importMetadataResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.EntityID != "https://idp.example.org/saml/metadata" {
		t.Errorf("entityId = %q", resp.EntityID)
	}
	if resp.SSOURL != "https://idp.example.org/saml/sso/redirect" {
		t.Errorf("ssoUrl = %q", resp.SSOURL)
	}
	if !strings.Contains(resp.SigningCertificate, "BEGIN CERTIFICATE") {
		t.Errorf("signingCertificate missing PEM: %q", resp.SigningCertificate)
	}
	if resp.DisplayName != "Example Organization" {
		t.Errorf("displayName = %q", resp.DisplayName)
	}
}

func TestFetchCertHandler_HappyPath(t *testing.T) {
	restore := newIDPFetchClientFn
	pemIn := "-----BEGIN CERTIFICATE-----\n" + wrap64(testCertB64) + "-----END CERTIFICATE-----\n"
	newIDPFetchClientFn = func() *http.Client {
		return fakeClient(fakeRoundTripper{status: 200, body: []byte(pemIn)})
	}
	defer func() { newIDPFetchClientFn = restore }()

	rec := serveWithClaims(FetchCertHandler, siteAdminClaims(), `{"url":"https://idp.example.org/cert.pem"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp fetchCertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.HasPrefix(resp.CertificatePem, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("certificatePem = %q", resp.CertificatePem)
	}
}

func TestFetchCertHandler_ForbiddenNonSiteAdmin(t *testing.T) {
	rec := serveWithClaims(FetchCertHandler, nonAdminClaims(), `{"url":"https://idp.example.org/cert.pem"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// metadataBody wraps raw SAML metadata XML into the parse-metadata endpoint's
// {"metadata": "<xml>"} JSON request body.
func metadataBody(t *testing.T, xml []byte) string {
	t.Helper()
	b, err := json.Marshal(idpMetadataRequest{Metadata: string(xml)})
	if err != nil {
		t.Fatalf("marshal metadata body: %v", err)
	}
	return string(b)
}

func TestParseMetadataHandler_HappyPath(t *testing.T) {
	rec := serveWithClaims(ParseMetadataHandler, siteAdminClaims(), metadataBody(t, sampleMetadata(t)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp importMetadataResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.EntityID != "https://idp.example.org/saml/metadata" {
		t.Errorf("entityId = %q", resp.EntityID)
	}
	if resp.SSOURL != "https://idp.example.org/saml/sso/redirect" {
		t.Errorf("ssoUrl = %q", resp.SSOURL)
	}
	if !strings.Contains(resp.SigningCertificate, "BEGIN CERTIFICATE") {
		t.Errorf("signingCertificate missing PEM: %q", resp.SigningCertificate)
	}
	if resp.DisplayName != "Example Organization" {
		t.Errorf("displayName = %q", resp.DisplayName)
	}
}

func TestParseMetadataHandler_ForbiddenNonSiteAdmin(t *testing.T) {
	rec := serveWithClaims(ParseMetadataHandler, nonAdminClaims(), metadataBody(t, sampleMetadata(t)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestParseMetadataHandler_BadBody(t *testing.T) {
	rec := serveWithClaims(ParseMetadataHandler, siteAdminClaims(), `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestParseMetadataHandler_EmptyMetadata(t *testing.T) {
	rec := serveWithClaims(ParseMetadataHandler, siteAdminClaims(), `{"metadata":"   "}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestParseMetadataHandler_NotMetadata(t *testing.T) {
	rec := serveWithClaims(ParseMetadataHandler, siteAdminClaims(), metadataBody(t, []byte(`<html>not saml</html>`)))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (body: %s)", rec.Code, rec.Body.String())
	}
}

func parseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad test IP %q", s)
	}
	return ip
}

func mustDER(t *testing.T) []byte {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(testCertB64)
	if err != nil {
		t.Fatalf("decode testCertB64: %v", err)
	}
	return der
}

func canonicalPEM(t *testing.T) string {
	t.Helper()
	out, err := normalizeCertPEM(mustDER(t))
	if err != nil {
		t.Fatalf("canonicalPEM: %v", err)
	}
	return out
}

func normalizeOrFail(t *testing.T, data []byte) string {
	t.Helper()
	out, err := normalizeCertPEM(data)
	if err != nil {
		t.Fatalf("normalizeCertPEM: %v", err)
	}
	return out
}

func wrap64(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 64 {
		end := min(i+64, len(s))
		b.WriteString(s[i:end])
		b.WriteString("\n")
	}
	return b.String()
}

func assertFetchStatus(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error with status %d, got nil", want)
	}
	fe, ok := err.(*fetchError)
	if !ok {
		t.Fatalf("error is not *fetchError: %T (%v)", err, err)
	}
	if fe.status != want {
		t.Fatalf("status = %d, want %d (%s)", fe.status, want, fe.msg)
	}
}
