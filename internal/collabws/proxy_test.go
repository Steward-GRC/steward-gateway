// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package collabws_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	log "github.com/Bugs5382/go-log"

	"github.com/Steward-GRC/steward-gateway/internal/collabws"
)

// ---------------------------------------------------------------------------
// Test doubles
//
// Everything below runs over REAL httptest servers and REAL websocket
// handshakes — browser ⇄ gateway proxy ⇄ fake collab — because the things most
// likely to break here (hijacking through the mux, hop-by-hop headers, frame
// types, close codes) are exactly the things a mocked ReadMessage/WriteMessage
// pair would not exercise.
// ---------------------------------------------------------------------------

const testDraftID = "0f8e1d2c-3b4a-5967-8899-aabbccddeeff"

// upstreamCall records what the fake collab actually received on its handshake.
type upstreamCall struct {
	mu           sync.Mutex
	path         string
	rawQuery     string
	authHeader   string
	hasOrigin    bool
	origin       string
	xff          string
	subprotocols string
	seen         bool
}

func (u *upstreamCall) record(r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.seen = true
	u.path = r.URL.Path
	u.rawQuery = r.URL.RawQuery
	u.authHeader = r.Header.Get("Authorization")
	u.origin = r.Header.Get("Origin")
	_, u.hasOrigin = r.Header["Origin"]
	u.xff = r.Header.Get("X-Forwarded-For")
	u.subprotocols = r.Header.Get("Sec-WebSocket-Protocol")
}

func (u *upstreamCall) snapshot() upstreamCall {
	u.mu.Lock()
	defer u.mu.Unlock()
	return upstreamCall{
		path: u.path, rawQuery: u.rawQuery, authHeader: u.authHeader,
		hasOrigin: u.hasOrigin, origin: u.origin, xff: u.xff,
		subprotocols: u.subprotocols, seen: u.seen,
	}
}

// fakeCollabOpts configures the stand-in for the collab ws listener.
type fakeCollabOpts struct {
	// onConn runs on the upgraded upstream connection. Required unless
	// rejectStatus is set.
	onConn func(*websocket.Conn)
	// rejectStatus, when non-zero, makes the upstream answer with that HTTP
	// status instead of upgrading — how collab rejects a bad token (401).
	rejectStatus int
	// rejectBody is the body written alongside rejectStatus.
	rejectBody string
	// subprotocols the upstream will negotiate.
	subprotocols []string
	// readLimit mirrors collab's own SetReadLimit; 0 leaves it unbounded.
	readLimit int64
}

// newFakeCollab starts a stand-in for collab's /ws/{draftID} listener and
// returns its "host:port" (what Config.Upstream takes) plus the call recorder.
func newFakeCollab(t *testing.T, opts fakeCollabOpts) (string, *upstreamCall) {
	t.Helper()
	call := &upstreamCall{}
	up := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		Subprotocols:    opts.subprotocols,
		// Mirrors collab's tightened CheckOrigin: no Origin = the gateway proxy
		// dialing server-to-server, which is the only sanctioned path.
		CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/", func(w http.ResponseWriter, r *http.Request) {
		call.record(r)
		if opts.rejectStatus != 0 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="steward.collab", error="invalid_token"`)
			http.Error(w, opts.rejectBody, opts.rejectStatus)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if opts.readLimit > 0 {
			c.SetReadLimit(opts.readLimit)
		}
		opts.onConn(c)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse fake collab url: %v", err)
	}
	return u.Host, call
}

// staticSession is a session check with a fixed answer.
func staticSession(live bool) collabws.SessionCheck {
	return func(*http.Request) bool { return live }
}

// newProxyServer mounts a Proxy on the real route pattern behind an
// httptest.Server, so r.PathValue("draftID") resolves the way it does in the
// gateway's mux.
func newProxyServer(t *testing.T, cfg collabws.Config, session collabws.SessionCheck) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(collabws.RoutePattern, collabws.New(cfg, session, log.Nop()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// testConfig is a Config pointed at upstreamHost with test-friendly timings.
func testConfig(upstreamHost string) collabws.Config {
	return collabws.Config{
		Upstream:         upstreamHost,
		MaxMessageBytes:  collabws.DefaultMaxMessageBytes,
		IdleTimeout:      collabws.DefaultIdleTimeout,
		HandshakeTimeout: 5 * time.Second,
	}
}

// dialProxy opens a client websocket against the proxy. token is appended as
// ?token= (the browser transport); hdr may add Origin etc.
func dialProxy(t *testing.T, srv *httptest.Server, draftID, token string, hdr http.Header) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	target := "ws://" + u.Host + "/collab/ws/" + draftID
	if token != "" {
		target += "?token=" + url.QueryEscape(token)
	}
	c, resp, err := websocket.DefaultDialer.Dial(target, hdr)
	if c != nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return c, resp, err
}

// echoBinary is an upstream handler that reflects every message back with its
// type preserved, so a round-trip test can observe both directions.
func echoBinary(c *websocket.Conn) {
	defer func() { _ = c.Close() }()
	for {
		mt, data, err := c.ReadMessage()
		if err != nil {
			return
		}
		if err := c.WriteMessage(mt, data); err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Transport: binary round-trip, both directions, unmodified
// ---------------------------------------------------------------------------

// The collab wire protocol is entirely binary (Sync/Awareness/Snapshot frames).
// A proxy that flipped the opcode to text, or mangled the bytes, would leave
// the peer's decoder rejecting everything — so assert the type AND the payload
// survive in both directions.
func TestProxy_RoundTripsBinaryFramesBothWays(t *testing.T) {
	host, call := newFakeCollab(t, fakeCollabOpts{onConn: func(c *websocket.Conn) {
		defer func() { _ = c.Close() }()
		// collab speaks first (its initial Sync1) — collab → browser.
		if err := c.WriteMessage(websocket.BinaryMessage, []byte{0x00, 0x00, 0x01, 0xff, 0xfe}); err != nil {
			return
		}
		echoBinary(c)
	}})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	conn, _, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// collab → browser
	mt, got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read server-first frame: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("server-first frame type: got %d, want %d (binary)", mt, websocket.BinaryMessage)
	}
	if want := []byte{0x00, 0x00, 0x01, 0xff, 0xfe}; !bytes.Equal(got, want) {
		t.Fatalf("server-first payload: got %x, want %x", got, want)
	}

	// browser → collab → browser, over a payload with every byte value and
	// embedded NULs, which is what a real compacted Yjs update looks like.
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	mt, got, err = conn.ReadMessage()
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("echo frame type: got %d, want binary", mt)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo payload differs from what was sent (%d vs %d bytes)", len(got), len(payload))
	}

	// The upstream saw the collab-side path, not the gateway's.
	if c := call.snapshot(); c.path != "/ws/"+testDraftID {
		t.Fatalf("upstream path: got %q, want %q", c.path, "/ws/"+testDraftID)
	}
}

// A text frame must stay a text frame — the proxy preserves the opcode rather
// than forcing binary.
func TestProxy_PreservesTextFrameType(t *testing.T) {
	host, _ := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})
	srv := newProxyServer(t, testConfig(host), staticSession(true))
	conn, _, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mt != websocket.TextMessage || string(got) != "hello" {
		t.Fatalf("got type=%d payload=%q, want type=%d payload=%q", mt, got, websocket.TextMessage, "hello")
	}
}

// ---------------------------------------------------------------------------
// Message size
// ---------------------------------------------------------------------------

// The protocol carries full Yjs state blobs, and collab's own write side is
// unbounded, so a state frame LARGER than collab's own read limit can
// legitimately travel collab → browser. The proxy's limit is deliberately above
// collab's so it is never the component that truncates: such a frame must
// arrive whole, byte-for-byte.
//
// The sizes here are derived from the two constants rather than written as
// literals, so this test keeps testing the same property when either limit
// moves.
func TestProxy_RelaysFrameLargerThanCollabsOwnReadLimit(t *testing.T) {
	// Above collab's own read limit, below the proxy's cap.
	const size = collabws.CollabReadLimitBytes + (256 << 10)
	if size >= collabws.DefaultMaxMessageBytes {
		t.Fatalf("test blob (%d) must stay under the proxy cap (%d)",
			size, collabws.DefaultMaxMessageBytes)
	}
	blob := make([]byte, size)
	if _, err := rand.Read(blob); err != nil {
		t.Fatalf("make blob: %v", err)
	}
	host, _ := newFakeCollab(t, fakeCollabOpts{
		readLimit: collabws.CollabReadLimitBytes, // exactly what collab's Client sets
		onConn: func(c *websocket.Conn) {
			defer func() { _ = c.Close() }()
			_ = c.WriteMessage(websocket.BinaryMessage, blob)
			// Hold the conn open until the client is done reading.
			_, _, _ = c.ReadMessage()
		},
	})
	srv := newProxyServer(t, testConfig(host), staticSession(true))
	conn, _, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	conn.SetReadLimit(collabws.DefaultMaxMessageBytes)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read large frame: %v", err)
	}
	if len(got) != size {
		t.Fatalf("large frame truncated: got %d bytes, want %d", len(got), size)
	}
	if !bytes.Equal(got, blob) {
		t.Fatal("large frame payload was modified in transit")
	}
}

// Above the proxy's own limit the failure must be LOUD: a 1009 close, not a
// truncated payload that would silently corrupt the CRDT document.
func TestProxy_OversizedFrameClosesWithMessageTooBig(t *testing.T) {
	host, _ := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})
	cfg := testConfig(host)
	cfg.MaxMessageBytes = 4096
	srv := newProxyServer(t, cfg, staticSession(true))

	conn, _, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, make([]byte, 8192)); err != nil {
		t.Fatalf("write oversize: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("expected the oversize frame to close the connection")
	}
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("expected a websocket close error, got %T: %v", err, err)
	}
	if ce.Code != websocket.CloseMessageTooBig {
		t.Fatalf("close code: got %d, want %d (message too big)", ce.Code, websocket.CloseMessageTooBig)
	}
}

// ---------------------------------------------------------------------------
// Gate 1: the authenticated gateway session
// ---------------------------------------------------------------------------

// Defense in depth: with no gateway session the upgrade is refused BEFORE the
// upstream is dialled, so collab never sees traffic from an anonymous caller
// even though it would have rejected the request itself.
func TestProxy_RejectsUpgradeWithoutGatewaySession(t *testing.T) {
	host, call := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})
	srv := newProxyServer(t, testConfig(host), staticSession(false))

	_, resp, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err == nil {
		t.Fatal("expected the upgrade to be refused")
	}
	if resp == nil {
		t.Fatalf("expected an HTTP response, got err=%v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
	if call.snapshot().seen {
		t.Fatal("upstream was dialled despite the missing gateway session")
	}
}

// A live session is not sufficient on its own: the collab token is the second,
// independent credential and its absence is still a 401 (with a Bearer
// challenge), again without touching the upstream.
func TestProxy_RejectsMissingCollabToken(t *testing.T) {
	host, call := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	_, resp, err := dialProxy(t, srv, testDraftID, "", nil)
	if err == nil {
		t.Fatal("expected the upgrade to be refused")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got resp=%v err=%v", resp, err)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Fatalf("WWW-Authenticate: got %q, want a Bearer challenge", got)
	}
	if call.snapshot().seen {
		t.Fatal("upstream was dialled despite the missing collab token")
	}
}

// ---------------------------------------------------------------------------
// Gate 2: the collab JWT — forwarded intact, and never in the upstream URL
// ---------------------------------------------------------------------------

// The browser presents the token as ?token= (its only option). The proxy must
// hand collab the exact same string — a truncated or re-encoded token fails
// signature verification — and must move it into the Authorization header so
// the JWT never lands in collab's URL or access log.
func TestProxy_ForwardsTokenIntactAsBearerAndStripsItFromQuery(t *testing.T) {
	// JWT-shaped: three base64url segments with dots, dashes and underscores.
	const token = "test-header.test_payload-not-real.test-signature_not-real"

	host, call := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})
	srv := newProxyServer(t, testConfig(host), staticSession(true))
	if _, _, err := dialProxy(t, srv, testDraftID, token, nil); err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	c := call.snapshot()
	if got, want := c.authHeader, "Bearer "+token; got != want {
		t.Fatalf("upstream Authorization:\n got %q\nwant %q", got, want)
	}
	// The token must NOT be duplicated into the upstream query string.
	if strings.Contains(c.rawQuery, "token") {
		t.Fatalf("upstream query still carries the token: %q", c.rawQuery)
	}
	// The gateway must not leak its own session cookie or an Origin to collab —
	// an absent Origin is what collab's tightened CheckOrigin allows.
	if c.hasOrigin {
		t.Fatalf("upstream received an Origin header (%q); collab expects none from the proxy", c.origin)
	}
	// No client address leaves the gateway (the no-IP rule); collab reads none.
	if c.xff != "" {
		t.Fatalf("upstream received X-Forwarded-For %q; the proxy must forward no client address", c.xff)
	}
}

// A non-browser client may present the token in an Authorization header
// instead; it is forwarded the same way.
func TestProxy_AcceptsTokenFromAuthorizationHeader(t *testing.T) {
	host, call := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer header-token-99")
	if _, _, err := dialProxy(t, srv, testDraftID, "", hdr); err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if got, want := call.snapshot().authHeader, "Bearer header-token-99"; got != want {
		t.Fatalf("upstream Authorization: got %q, want %q", got, want)
	}
}

// Non-token query parameters are forwarded untouched, so the transport does not
// have to change if the protocol ever adds one.
func TestProxy_ForwardsOtherQueryParams(t *testing.T) {
	host, call := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	u, _ := url.Parse(srv.URL)
	target := "ws://" + u.Host + "/collab/ws/" + testDraftID + "?token=t1&resume=42"
	conn, _, err := websocket.DefaultDialer.Dial(target, nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	q, err := url.ParseQuery(call.snapshot().rawQuery)
	if err != nil {
		t.Fatalf("parse upstream query: %v", err)
	}
	if got := q.Get("resume"); got != "42" {
		t.Fatalf("upstream resume param: got %q, want %q", got, "42")
	}
	if q.Has("token") {
		t.Fatal("token must not be forwarded in the query")
	}
}

// collab rejecting the token must reach the caller as collab's OWN status and
// challenge — not a 101 followed by a mystery close, which is what upgrading
// the client before the upstream handshake would produce.
func TestProxy_RelaysUpstreamRejectionStatus(t *testing.T) {
	host, _ := newFakeCollab(t, fakeCollabOpts{
		rejectStatus: http.StatusUnauthorized,
		rejectBody:   "invalid token",
	})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	_, resp, err := dialProxy(t, srv, testDraftID, "expired-jwt", nil)
	if err == nil {
		t.Fatal("expected the upgrade to fail")
	}
	if resp == nil {
		t.Fatalf("expected an HTTP response, got err=%v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 (collab's own)", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "steward.collab") {
		t.Fatalf("WWW-Authenticate: got %q, want collab's challenge relayed", got)
	}
}

// An unreachable collab is a dependency failure, not a client error: 502.
func TestProxy_UnreachableUpstreamIs502(t *testing.T) {
	// Port 1 on loopback: nothing listens, so the dial is refused immediately.
	srv := newProxyServer(t, testConfig("127.0.0.1:1"), staticSession(true))
	_, resp, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err == nil {
		t.Fatal("expected the upgrade to fail")
	}
	if resp == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got resp=%v err=%v", resp, err)
	}
}

// ---------------------------------------------------------------------------
// Origin
// ---------------------------------------------------------------------------

func TestProxy_OriginPolicy(t *testing.T) {
	host, _ := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})

	tests := []struct {
		name       string
		origin     string // "" sends no Origin header
		allowed    []string
		fwdHost    string // X-Forwarded-Host, as an edge would set it
		sameOrigin bool   // send Origin equal to the proxy's own host
		wantStatus int    // 101 = accepted
	}{
		// Non-browser clients (Go, curl, the e2e suite) send no Origin.
		{name: "no origin", wantStatus: http.StatusSwitchingProtocols},
		// The production case: the SPA and the gateway share an origin.
		{name: "same origin", sameOrigin: true, wantStatus: http.StatusSwitchingProtocols},
		// A cross-site page cannot open the socket even with a token.
		{name: "foreign origin", origin: "https://evil.example.net", wantStatus: http.StatusForbidden},
		// Split-origin dev server, explicitly allowlisted.
		{
			name:       "allowlisted origin",
			origin:     "http://localhost:5173",
			allowed:    []string{"http://localhost:5173"},
			wantStatus: http.StatusSwitchingProtocols,
		},
		// An allowlist entry does not admit look-alikes.
		{
			name:       "allowlist does not admit look-alike",
			origin:     "http://localhost:5173.evil.example.net",
			allowed:    []string{"http://localhost:5173"},
			wantStatus: http.StatusForbidden,
		},
		// An edge that does NOT pass the original Host through would otherwise
		// 403 every editor session; X-Forwarded-Host names the public host the
		// browser's Origin refers to, so it counts as same-origin.
		{
			name:       "forwarded host counts as same origin",
			origin:     "https://steward.example.org",
			fwdHost:    "steward.example.org",
			wantStatus: http.StatusSwitchingProtocols,
		},
		// A proxy chain appends, so only the FIRST (client-facing) entry counts.
		{
			name:       "first forwarded host in a chain counts",
			origin:     "https://steward.example.org",
			fwdHost:    "steward.example.org, inner.example.net",
			wantStatus: http.StatusSwitchingProtocols,
		},
		// A forwarded host that does not match the Origin grants nothing.
		{
			name:       "forwarded host mismatch still refused",
			origin:     "https://evil.example.net",
			fwdHost:    "steward.example.org",
			wantStatus: http.StatusForbidden,
		},
		// "null" (sandboxed iframe / file:// document) is not a host.
		{name: "null origin", origin: "null", wantStatus: http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(host)
			cfg.AllowedOrigins = tc.allowed
			srv := newProxyServer(t, cfg, staticSession(true))

			hdr := http.Header{}
			switch {
			case tc.sameOrigin:
				u, _ := url.Parse(srv.URL)
				hdr.Set("Origin", "http://"+u.Host)
			case tc.origin != "":
				hdr.Set("Origin", tc.origin)
			}
			if tc.fwdHost != "" {
				hdr.Set("X-Forwarded-Host", tc.fwdHost)
			}

			_, resp, err := dialProxy(t, srv, testDraftID, "jwt-abc", hdr)
			if tc.wantStatus == http.StatusSwitchingProtocols {
				if err != nil {
					t.Fatalf("expected the upgrade to succeed, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected the upgrade to be refused")
			}
			if resp == nil || resp.StatusCode != tc.wantStatus {
				t.Fatalf("status: got %v, want %d", resp, tc.wantStatus)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Subprotocol passthrough
// ---------------------------------------------------------------------------

// If a client ever offers a subprotocol, collab picks it and the proxy echoes
// collab's choice back — the negotiation stays collab's, not the proxy's.
func TestProxy_PassesSubprotocolThrough(t *testing.T) {
	host, call := newFakeCollab(t, fakeCollabOpts{
		subprotocols: []string{"yjs-v1"},
		onConn:       echoBinary,
	})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	u, _ := url.Parse(srv.URL)
	d := &websocket.Dialer{Subprotocols: []string{"yjs-v1", "other"}}
	conn, _, err := d.Dial("ws://"+u.Host+"/collab/ws/"+testDraftID+"?token=t", nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if got := conn.Subprotocol(); got != "yjs-v1" {
		t.Fatalf("client subprotocol: got %q, want %q", got, "yjs-v1")
	}
	if got := call.snapshot().subprotocols; !strings.Contains(got, "yjs-v1") {
		t.Fatalf("upstream Sec-WebSocket-Protocol: got %q, want it to offer yjs-v1", got)
	}
}

// ---------------------------------------------------------------------------
// Keepalive / idle
// ---------------------------------------------------------------------------

// An editing session idles between keystrokes. With a short idle timeout and
// NO application traffic, the proxy's own pings must draw pongs from both peers
// and keep the connection alive well past that timeout — this is the assertion
// that a real idle editor does not get dropped.
func TestProxy_KeepaliveSurvivesIdlePeriodLongerThanTimeout(t *testing.T) {
	// The upstream mirrors collab's own Client pumps exactly: a bounded read
	// deadline refreshed ONLY by an inbound pong, plus its own ping ticker at
	// 90% of that deadline. That is what makes this a real end-to-end keepalive
	// test — the proxy has to answer collab's pings AND ping the browser, or one
	// of the two deadlines expires.
	const upstreamPongWait = 400 * time.Millisecond
	host, _ := newFakeCollab(t, fakeCollabOpts{onConn: func(c *websocket.Conn) {
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(upstreamPongWait))
		c.SetPongHandler(func(string) error {
			return c.SetReadDeadline(time.Now().Add(upstreamPongWait))
		})
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			tk := time.NewTicker(upstreamPongWait * 9 / 10)
			defer tk.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tk.C:
					if err := c.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
						return
					}
				}
			}
		}()
		for {
			mt, data, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(mt, data); err != nil {
				return
			}
		}
	}})
	cfg := testConfig(host)
	// 300ms idle timeout → the proxy pings every 135ms.
	cfg.IdleTimeout = 300 * time.Millisecond
	srv := newProxyServer(t, cfg, staticSession(true))

	conn, _, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	// A browser answers pings at the protocol level whether or not the page is
	// reading; gorilla only processes control frames from inside a read call, so
	// the test client needs a reader running to behave like one. It sends
	// nothing of its own — the session is genuinely idle for the whole window.
	type frame struct {
		mt   int
		data []byte
	}
	frames := make(chan frame, 4)
	readErr := make(chan error, 1)
	go func() {
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				readErr <- err
				return
			}
			frames <- frame{mt: mt, data: data}
		}
	}()

	idleFor := 4 * cfg.IdleTimeout // 1.2s: 4x the timeout, ~9 ping cycles
	select {
	case err := <-readErr:
		t.Fatalf("connection died after less than %s idle: %v", idleFor, err)
	case f := <-frames:
		t.Fatalf("unexpected frame during the idle window: type=%d payload=%x", f.mt, f.data)
	case <-time.After(idleFor):
	}

	// Still alive? A round-trip proves it end to end.
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte{0x42}); err != nil {
		t.Fatalf("write after %s idle: %v", idleFor, err)
	}
	select {
	case f := <-frames:
		if f.mt != websocket.BinaryMessage || !bytes.Equal(f.data, []byte{0x42}) {
			t.Fatalf("after idle: got type=%d payload=%x", f.mt, f.data)
		}
	case err := <-readErr:
		t.Fatalf("read after %s idle: %v", idleFor, err)
	case <-time.After(5 * time.Second):
		t.Fatalf("no echo after %s idle", idleFor)
	}
}

// ---------------------------------------------------------------------------
// Close propagation
// ---------------------------------------------------------------------------

// collab closing (e.g. 1008 on a policy violation, or 1000 on shutdown) must
// reach the browser as THAT code and reason, so the editor can tell "go away"
// from "reconnect".
func TestProxy_PropagatesUpstreamCloseToClient(t *testing.T) {
	host, _ := newFakeCollab(t, fakeCollabOpts{onConn: func(c *websocket.Conn) {
		_ = c.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "draft locked"),
			time.Now().Add(time.Second),
		)
		time.Sleep(50 * time.Millisecond)
		_ = c.Close()
	}})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	conn, _, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("expected the upstream close to reach the client")
	}
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("expected a close error, got %T: %v", err, err)
	}
	if ce.Code != websocket.ClosePolicyViolation {
		t.Fatalf("close code: got %d, want %d", ce.Code, websocket.ClosePolicyViolation)
	}
	if ce.Text != "draft locked" {
		t.Fatalf("close text: got %q, want %q", ce.Text, "draft locked")
	}
}

// The browser closing (tab closed, navigation) must reach collab, otherwise the
// room keeps a phantom collaborator and never flushes its snapshot on
// last-leaver.
func TestProxy_PropagatesClientCloseToUpstream(t *testing.T) {
	closed := make(chan *websocket.CloseError, 1)
	host, _ := newFakeCollab(t, fakeCollabOpts{onConn: func(c *websocket.Conn) {
		defer func() { _ = c.Close() }()
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				if ce, ok := errors.AsType[*websocket.CloseError](err); ok {
					closed <- ce
				} else {
					closed <- nil
				}
				return
			}
		}
	}})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	conn, _, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if err := conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"),
		time.Now().Add(time.Second),
	); err != nil {
		t.Fatalf("write close: %v", err)
	}

	select {
	case ce := <-closed:
		if ce == nil {
			t.Fatal("upstream saw a non-close error, not the relayed close frame")
		}
		if ce.Code != websocket.CloseNormalClosure {
			t.Fatalf("upstream close code: got %d, want %d", ce.Code, websocket.CloseNormalClosure)
		}
		if ce.Text != "bye" {
			t.Fatalf("upstream close text: got %q, want %q", ce.Text, "bye")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never saw the client's close frame")
	}
}

// A client that vanishes without a close frame (1006/abnormal, which the RFC
// forbids on the wire) must still produce a legal close upstream — 1001, not a
// silently dropped connection.
func TestProxy_AbruptClientDisconnectClosesUpstreamCleanly(t *testing.T) {
	closed := make(chan int, 1)
	host, _ := newFakeCollab(t, fakeCollabOpts{onConn: func(c *websocket.Conn) {
		defer func() { _ = c.Close() }()
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				if ce, ok := errors.AsType[*websocket.CloseError](err); ok {
					closed <- ce.Code
				} else {
					closed <- 0
				}
				return
			}
		}
	}})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	conn, _, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	// Rip the TCP conn away with no close handshake.
	if err := conn.UnderlyingConn().Close(); err != nil {
		t.Fatalf("close underlying conn: %v", err)
	}

	select {
	case code := <-closed:
		if code != websocket.CloseGoingAway {
			t.Fatalf("upstream close code: got %d, want %d (going away)", code, websocket.CloseGoingAway)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream was never told the client had gone")
	}
}

// ---------------------------------------------------------------------------
// Route hygiene
// ---------------------------------------------------------------------------

// The route has no plain-HTTP meaning — a GET that is not an upgrade is a 400,
// not a hang or a 200 with an empty body.
func TestProxy_RejectsNonUpgradeRequest(t *testing.T) {
	host, call := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	resp, err := srv.Client().Get(srv.URL + "/collab/ws/" + testDraftID + "?token=t")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
	if call.snapshot().seen {
		t.Fatal("a non-upgrade request reached the upstream")
	}
}

// A missing draft id is a 400. It is also the only reason a request can reach
// the handler with an empty PathValue, so this pins the route pattern too.
func TestProxy_RejectsMissingDraftID(t *testing.T) {
	host, _ := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})
	srv := newProxyServer(t, testConfig(host), staticSession(true))

	u, _ := url.Parse(srv.URL)
	_, resp, err := websocket.DefaultDialer.Dial("ws://"+u.Host+"/collab/ws/?token=t", nil)
	if err == nil {
		t.Fatal("expected the upgrade to be refused")
	}
	// Go's ServeMux does not match "{draftID}" against an empty segment, so
	// this is a 404 from the mux rather than the handler's own 400 — either way
	// it must never reach the upstream.
	if resp == nil || (resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound) {
		t.Fatalf("expected 400 or 404, got resp=%v err=%v", resp, err)
	}
}

// RoutePattern is a shared contract with collab's grpcsvc.WsPathPrefix, which
// is what issueCollabToken hands the browser as ws_url. Pin it so a rename here
// cannot silently 404 every editor session.
func TestRoutePattern_MatchesCollabWsURL(t *testing.T) {
	if got, want := collabws.RoutePattern, "GET /collab/ws/{draftID}"; got != want {
		t.Fatalf("RoutePattern: got %q, want %q — collab's grpcsvc.WsPathPrefix must change too", got, want)
	}
}

// The proxy's limit must stay strictly above collab's own read limit, so the
// proxy is never what rejects a browser→collab frame that collab would have
// accepted. It is written against the mirrored constant, not a literal, so a
// change to either limit is caught here.
func TestDefaultMaxMessageBytes_ExceedsCollabReadLimit(t *testing.T) {
	if collabws.DefaultMaxMessageBytes <= collabws.CollabReadLimitBytes {
		t.Fatalf(
			"DefaultMaxMessageBytes (%d) must exceed collab's own read limit (%d): "+
				"the proxy must not be the tighter of the two limits",
			collabws.DefaultMaxMessageBytes, collabws.CollabReadLimitBytes,
		)
	}
}

// The mirror itself is the part that can rot silently, because nothing in this
// module can see collab's source. Pin the expected value so that changing the
// mirror is a deliberate act that lands in a diff next to this comment, and so
// the reciprocal test in collab has a stated number to agree with.
func TestCollabReadLimitBytes_MatchesCollabsMaxMessageSize(t *testing.T) {
	// steward-collab internal/ws/client.go: maxMessageSize = 2 * 1024 * 1024.
	const collabMaxMessageSize = 2 * 1024 * 1024
	if collabws.CollabReadLimitBytes != collabMaxMessageSize {
		t.Fatalf(
			"CollabReadLimitBytes (%d) no longer mirrors collab's maxMessageSize (%d); "+
				"update both sides together",
			collabws.CollabReadLimitBytes, collabMaxMessageSize,
		)
	}
}

// A missing session check refuses every upgrade: the gate fails closed, so a
// wiring mistake can never open the socket to anonymous callers.
func TestProxy_NilSessionCheckRefusesEveryUpgrade(t *testing.T) {
	host, call := newFakeCollab(t, fakeCollabOpts{onConn: echoBinary})
	srv := newProxyServer(t, testConfig(host), nil)
	_, resp, err := dialProxy(t, srv, testDraftID, "jwt-abc", nil)
	if err == nil {
		t.Fatal("expected the upgrade to be refused")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got resp=%v err=%v", resp, err)
	}
	if call.snapshot().seen {
		t.Fatal("upstream was dialled without a session check")
	}
}
