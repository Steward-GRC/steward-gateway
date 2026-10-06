// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	stewardauthz "github.com/Steward-GRC/steward-authz"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

const (
	idpFetchTimeout = 5 * time.Second

	maxIDPFetchBytes = 1 << 20 // 1 MiB

	maxIDPRequestBodyBytes = 8 << 10 // 8 KiB

	idpUserAgent = "steward-gateway-idp-import/1.0"
)

// SAML SSO binding identifiers. The metadata / xmldsig namespace URIs the
// parser matches on are spelled inline in the struct tags below, since Go
// struct tags cannot reference constants — matching on the namespace URI (not
// the element prefix) means the parser handles metadata that uses md:/ds:
// prefixes, a default namespace, or any other prefix.
// siteAdminRole gates the admin-only auth routes, as it did before the port.
var siteAdminRole = string(stewardauthz.RoleSiteAdmin)

const (
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// SAMLMetadata is the subset of an IdP's SAML 2.0 metadata the admin wizard
// prefills an organization connection from.
type SAMLMetadata struct {
	EntityID           string
	SSOURL             string
	SigningCertificate string // PEM CERTIFICATE block
	DisplayName        string
}

type idpURLRequest struct {
	URL string `json:"url"`
}

// idpMetadataRequest carries the raw SAML metadata XML the admin uploaded from
// a file downloaded off their IdP (the parse-metadata endpoint parses this
// directly — there is no network fetch, so no SSRF surface).
type idpMetadataRequest struct {
	Metadata string `json:"metadata"`
}

type importMetadataResponse struct {
	EntityID           string `json:"entityId"`
	SSOURL             string `json:"ssoUrl"`
	SigningCertificate string `json:"signingCertificate"`
	DisplayName        string `json:"displayName"`
}

type fetchCertResponse struct {
	CertificatePem string `json:"certificatePem"`
}

// fetchError carries the HTTP status a fetch/validation failure should surface
// to the client along with a safe, non-internal message. The guarded fetcher
// returns these so the thin handlers can map failures to a status without
// re-classifying — and never leak dial/DNS detail.
type fetchError struct {
	status int
	msg    string
}

func (e *fetchError) Error() string { return e.msg }

// isBlockedFetchIP reports whether ip is an address a server-side fetch of an
// admin-supplied URL must never reach: loopback, private and unique-local
// ranges (IsPrivate), link-local unicast (which covers the cloud-metadata
// address), any multicast, or the unspecified address. A nil IP is blocked.
func isBlockedFetchIP(ip net.IP) bool {
	return ip == nil ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// idpDialControl is the net.Dialer.Control hook that enforces the SSRF policy
// at connect time: address is the concrete "ip:port" the dialer is about to
// connect to (already resolved), so rejecting a blocked IP here defeats a
// DNS-rebind that resolved to an internal address after URL validation. It
// runs for the initial connection and, were redirects enabled, each hop — but
// the client disables redirects outright, so it is the sole connect gate.
func idpDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid dial address")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("dial address is not an IP literal")
	}
	if isBlockedFetchIP(ip) {
		return fmt.Errorf("connection to a blocked address is not allowed")
	}
	return nil
}

// newIDPFetchClientFn constructs the client the handlers fetch through. It is a
// var (not a direct call) solely so tests can substitute a fake transport;
// production always uses newIDPFetchClient.
var newIDPFetchClientFn = newIDPFetchClient

// newIDPFetchClient builds the hardened http.Client every IdP fetch goes
// through: a Dialer with the SSRF Control hook, an overall timeout, and
// CheckRedirect that refuses to follow any redirect (so a 3xx can't bounce the
// fetch to an internal address). https-only is enforced by idpValidateFetchURL
// before the request is issued.
func newIDPFetchClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: idpFetchTimeout,
		Control: idpDialControl,
	}
	return &http.Client{
		Timeout: idpFetchTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   idpFetchTimeout,
			ResponseHeaderTimeout: idpFetchTimeout,
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not followed")
		},
	}
}

// idpValidateFetchURL parses raw and enforces the scheme/host policy that does
// not need a DNS lookup: https only, a non-empty host, and — as a fast path — a
// literal-IP host must not be a blocked address. Hostnames that resolve are
// deferred to idpDialControl, the only point a rebind can't happen. It returns
// a *fetchError (400) so the handler surfaces a clean bad-request message.
func idpValidateFetchURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, &fetchError{http.StatusBadRequest, "Missing url — provide a URL"}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, &fetchError{http.StatusBadRequest, "Invalid URL — could not parse it"}
	}
	if u.Scheme != "https" {
		return nil, &fetchError{http.StatusBadRequest, "Only https URLs are allowed"}
	}
	if u.Hostname() == "" {
		return nil, &fetchError{http.StatusBadRequest, "Invalid URL — missing host"}
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedFetchIP(ip) {
		return nil, &fetchError{http.StatusBadRequest, "This URL points to a blocked address — internal/private addresses are not allowed"}
	}
	return u, nil
}

// fetchIDPDocument validates raw, fetches it through the guarded client, and
// returns the (size-capped) response body. client is injected so tests can
// supply a fake transport; production passes newIDPFetchClient(). Every
// failure is a *fetchError with a safe message: URL problems map to 400, and
// an SSRF-blocked / unreachable / non-2xx / oversized fetch maps to 502 with a
// message that never echoes internal resolution detail.
func fetchIDPDocument(ctx context.Context, client *http.Client, raw string) ([]byte, error) {
	u, err := idpValidateFetchURL(raw)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, &fetchError{http.StatusBadRequest, "Invalid URL"}
	}
	req.Header.Set("User-Agent", idpUserAgent)
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml, application/x-x509-ca-cert, application/pkix-cert, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, &fetchError{http.StatusBadGateway, "Could not fetch the URL — it may be unreachable or points to a blocked address"}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &fetchError{http.StatusBadGateway, fmt.Sprintf("The URL returned an unexpected status (HTTP %d)", resp.StatusCode)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIDPFetchBytes+1))
	if err != nil {
		return nil, &fetchError{http.StatusBadGateway, "Could not read the response from the URL"}
	}
	if int64(len(body)) > maxIDPFetchBytes {
		return nil, &fetchError{http.StatusBadGateway, "The response from the URL is too large"}
	}
	return body, nil
}

type mdEntityDescriptor struct {
	XMLName      xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID     string              `xml:"entityID,attr"`
	IDPSSODesc   *mdIDPSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	Organization *mdOrganization     `xml:"urn:oasis:names:tc:SAML:2.0:metadata Organization"`
}

type mdIDPSSODescriptor struct {
	KeyDescriptors []mdKeyDescriptor       `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	SSOServices    []mdSingleSignOnService `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
}

type mdKeyDescriptor struct {
	Use     string    `xml:"use,attr"`
	KeyInfo mdKeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type mdKeyInfo struct {
	X509Data mdX509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type mdX509Data struct {
	Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type mdSingleSignOnService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type mdOrganization struct {
	DisplayNames []mdLocalizedName `xml:"urn:oasis:names:tc:SAML:2.0:metadata OrganizationDisplayName"`
}

type mdLocalizedName struct {
	Value string `xml:",chardata"`
}

// parseSAMLMetadata parses SAML 2.0 IdP metadata XML into the fields the admin
// wizard prefills a connection from. It extracts the entityID, the SSO
// endpoint (HTTP-Redirect binding preferred, HTTP-POST fallback), the signing
// certificate (a use="signing" KeyDescriptor, else an un-`use`d one) wrapped
// into a validated PEM CERTIFICATE block, and a best-effort display name.
func parseSAMLMetadata(data []byte) (SAMLMetadata, error) {
	var ed mdEntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		return SAMLMetadata{}, fmt.Errorf("could not parse SAML metadata XML: %w", err)
	}
	if ed.EntityID == "" {
		return SAMLMetadata{}, errors.New("metadata is missing an entityID")
	}
	if ed.IDPSSODesc == nil {
		return SAMLMetadata{}, errors.New("metadata has no IDPSSODescriptor — is this IdP (not SP) metadata?")
	}

	ssoURL := pickSSOURL(ed.IDPSSODesc.SSOServices)
	if ssoURL == "" {
		return SAMLMetadata{}, errors.New("metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService")
	}

	certB64 := pickSigningCert(ed.IDPSSODesc.KeyDescriptors)
	if certB64 == "" {
		return SAMLMetadata{}, errors.New("metadata has no signing X509Certificate")
	}
	certPEM, err := certBase64ToPEM(certB64)
	if err != nil {
		return SAMLMetadata{}, err
	}

	return SAMLMetadata{
		EntityID:           ed.EntityID,
		SSOURL:             ssoURL,
		SigningCertificate: certPEM,
		DisplayName:        pickDisplayName(ed),
	}, nil
}

// pickSSOURL returns the IdP's SSO endpoint, preferring the HTTP-Redirect
// binding and falling back to HTTP-POST when Redirect is absent.
func pickSSOURL(svcs []mdSingleSignOnService) string {
	var post string
	for _, s := range svcs {
		if s.Location == "" {
			continue
		}
		if s.Binding == bindingRedirect {
			return s.Location
		}
		if s.Binding == bindingPOST && post == "" {
			post = s.Location
		}
	}
	return post
}

// pickSigningCert returns the base64 body of the IdP's signing certificate: a
// use="signing" KeyDescriptor wins; otherwise the first KeyDescriptor with no
// `use` attribute (which SAML treats as valid for both signing and encryption)
// is used. Encryption-only KeyDescriptors are skipped.
func pickSigningCert(kds []mdKeyDescriptor) string {
	var fallback string
	for _, kd := range kds {
		cert := strings.TrimSpace(kd.KeyInfo.X509Data.Certificate)
		if cert == "" {
			continue
		}
		if strings.EqualFold(kd.Use, "signing") {
			return cert
		}
		if kd.Use == "" && fallback == "" {
			fallback = cert
		}
	}
	return fallback
}

// pickDisplayName returns a best-effort human name for the IdP: the first
// non-empty OrganizationDisplayName, else the entityID's host, else the raw
// entityID.
func pickDisplayName(ed mdEntityDescriptor) string {
	if ed.Organization != nil {
		for _, dn := range ed.Organization.DisplayNames {
			if v := strings.TrimSpace(dn.Value); v != "" {
				return v
			}
		}
	}
	if u, err := url.Parse(ed.EntityID); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return ed.EntityID
}

// certBase64ToPEM decodes a base64 DER certificate body (as it appears inside
// a <ds:X509Certificate> element, whitespace/newlines tolerated), validates it
// parses as an X.509 certificate, and returns it as a PEM CERTIFICATE block.
func certBase64ToPEM(b64 string) (string, error) {
	clean := strings.Join(strings.Fields(b64), "")
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("signing certificate is not valid base64: %w", err)
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return "", fmt.Errorf("signing certificate is not a valid X.509 certificate: %w", err)
	}
	return encodeCertPEM(der), nil
}

// encodeCertPEM wraps DER certificate bytes in a PEM CERTIFICATE block.
func encodeCertPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// normalizeCertPEM accepts a certificate as PEM (one or more blocks) or raw
// DER and returns a single, canonical PEM CERTIFICATE block. The certificate
// must parse as X.509; anything else is an error. A PEM input is scanned for
// the first CERTIFICATE block (ignoring any surrounding text or non-cert
// blocks); a non-PEM input is tried as DER.
func normalizeCertPEM(data []byte) (string, error) {
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return "", fmt.Errorf("PEM CERTIFICATE block is not a valid X.509 certificate: %w", err)
			}
			return encodeCertPEM(block.Bytes), nil
		}
		rest = r
	}
	if cert, err := x509.ParseCertificate(data); err == nil {
		return encodeCertPEM(cert.Raw), nil
	}
	return "", errors.New("data is neither a PEM CERTIFICATE nor a DER-encoded X.509 certificate")
}

// idpWriteError writes a JSON {"error": msg} body with the given status.
func idpWriteError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// requireSiteAdminHTTP enforces the site-admin gate for the REST IdP-import
// endpoints, reading the claims principal.HTTP attached to the request context —
// the same claims path the GraphQL resolvers' requireSiteAdmin uses. It writes
// 401 when there is no authenticated caller and 403 when the caller lacks the
// site-admin role, returning false in either case; true means proceed.
func requireSiteAdminHTTP(w http.ResponseWriter, r *http.Request) bool {
	c, ok := principal.FromContext(r.Context())
	if !ok || c == nil || c.UserID() == "" {
		idpWriteError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	if !principal.HasRole(c, siteAdminRole) {
		idpWriteError(w, http.StatusForbidden, "site-admin role required")
		return false
	}
	return true
}

// decodeIDPURLBody reads and validates the {"url": "..."} request body,
// writing a 400 and returning ok=false on a malformed or empty body.
func decodeIDPURLBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxIDPRequestBodyBytes)
	var req idpURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		idpWriteError(w, http.StatusBadRequest, `Malformed request — expected JSON {"url": "https://..."}`)
		return "", false
	}
	if strings.TrimSpace(req.URL) == "" {
		idpWriteError(w, http.StatusBadRequest, "Missing url — provide a URL")
		return "", false
	}
	return req.URL, true
}

// decodeIDPMetadataBody reads and validates the {"metadata": "<xml>"} request
// body — the raw SAML metadata XML the admin uploaded from a file downloaded
// off their IdP. The document itself is the payload (not a URL), so the body
// cap is the 1 MiB document cap (maxIDPFetchBytes), not the small URL cap.
func decodeIDPMetadataBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxIDPFetchBytes)
	var req idpMetadataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		idpWriteError(w, http.StatusBadRequest, `Malformed request — expected JSON {"metadata": "<xml>"}`)
		return "", false
	}
	if strings.TrimSpace(req.Metadata) == "" {
		idpWriteError(w, http.StatusBadRequest, "Missing metadata — upload a SAML metadata XML file")
		return "", false
	}
	return req.Metadata, true
}

// writeFetchError maps a fetchIDPDocument error to its HTTP status + safe
// message. Any non-*fetchError (should not happen) degrades to a generic 502.
func writeFetchError(w http.ResponseWriter, err error) {
	if fe, ok := errors.AsType[*fetchError](err); ok {
		idpWriteError(w, fe.status, fe.msg)
		return
	}
	idpWriteError(w, http.StatusBadGateway, "Could not fetch the URL")
}

// ImportMetadataHandler implements POST /admin/idp/import-metadata: given
// {"url": "https://..."} it fetches the URL (SSRF-guarded), parses SAML 2.0
// IdP metadata, and returns
// {"entityId","ssoUrl","signingCertificate","displayName"} on 200. Errors:
// 401/403 (auth), 400 (bad body / non-https or unparseable URL), 502 (fetch
// blocked/failed), 422 (fetched but not parseable as SAML metadata).
func ImportMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if !requireSiteAdminHTTP(w, r) {
		return
	}
	rawURL, ok := decodeIDPURLBody(w, r)
	if !ok {
		return
	}
	body, err := fetchIDPDocument(r.Context(), newIDPFetchClientFn(), rawURL)
	if err != nil {
		writeFetchError(w, err)
		return
	}
	meta, err := parseSAMLMetadata(body)
	if err != nil {
		idpWriteError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, importMetadataResponse(meta))
}

// ParseMetadataHandler implements POST /admin/idp/parse-metadata: given
// {"metadata": "<xml>"} — the raw SAML 2.0 IdP metadata XML from a file the
// admin downloaded off their IdP (e.g. Google Workspace's metadata download) —
// it parses the document directly (no network fetch, so no SSRF surface) and
// returns the same {"entityId","ssoUrl","signingCertificate","displayName"}
// shape as ImportMetadataHandler. Errors: 401/403 (auth), 400 (bad/empty
// body), 422 (body is not parseable SAML IdP metadata).
func ParseMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if !requireSiteAdminHTTP(w, r) {
		return
	}
	metadata, ok := decodeIDPMetadataBody(w, r)
	if !ok {
		return
	}
	meta, err := parseSAMLMetadata([]byte(metadata))
	if err != nil {
		idpWriteError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, importMetadataResponse(meta))
}

// FetchCertHandler implements POST /admin/idp/fetch-cert: given
// {"url": "https://..."} it fetches the URL (SSRF-guarded), accepts a PEM or
// DER certificate, and returns {"certificatePem":"<PEM>"} on 200. Errors mirror
// ImportMetadataHandler: 401/403, 400, 502, and 422 when the fetched bytes are
// not a valid certificate.
func FetchCertHandler(w http.ResponseWriter, r *http.Request) {
	if !requireSiteAdminHTTP(w, r) {
		return
	}
	rawURL, ok := decodeIDPURLBody(w, r)
	if !ok {
		return
	}
	body, err := fetchIDPDocument(r.Context(), newIDPFetchClientFn(), rawURL)
	if err != nil {
		writeFetchError(w, err)
		return
	}
	certPEM, err := normalizeCertPEM(body)
	if err != nil {
		idpWriteError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fetchCertResponse{CertificatePem: certPEM})
}
