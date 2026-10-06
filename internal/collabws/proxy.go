// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package collabws is the gateway's websocket reverse proxy for live
// co-editing. steward-collab serves its rooms on an in-cluster listener at
// /ws/{draftID}; the browser reaches them through the gateway, same origin,
// at /collab/ws/{draftID}, so collab never needs a public address.
//
// Two independent gates guard the upgrade. The gateway checks that the
// request carries a live session (proof of some signed-in user, never used to
// pick the collab identity). Collab checks its own short-lived token, minted
// by issueCollabToken: signature, audience, expiry and that the token names
// the draft in the path. Collab stays the authority; this package never
// parses, rewrites or re-signs the token.
//
// A browser can't set headers on a websocket handshake, so the CSRF header
// isn't available here. The Origin allow-list refuses cross-site pages, and
// the collab token itself only comes from a CSRF-checked GraphQL mutation.
//
// The browser sends the token as ?token=. The proxy moves it to an
// Authorization header on the upstream dial and drops it from the upstream
// query, so it never lands in collab's URL or logs.
package collabws

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/gorilla/websocket"

	"github.com/Steward-GRC/steward-gateway/internal/origin"
)

const (
	// DefaultUpstream is collab's websocket listener in the cluster.
	DefaultUpstream = "steward-collab:8081"

	// CollabReadLimitBytes mirrors collab's per-frame read limit
	// (maxMessageSize in its internal/ws). It can't be imported, so collab
	// carries a reciprocal test that fails if the two drift.
	CollabReadLimitBytes = 2 << 20

	// DefaultMaxMessageBytes is the read limit for both directions. Above
	// collab's own limit, so collab's limit trips first browser to collab,
	// and a full Yjs state blob (collab's writes are unbounded) passes collab
	// to browser.
	DefaultMaxMessageBytes = 2 * CollabReadLimitBytes

	// DefaultIdleTimeout is how long a connection may go with no frame and
	// no pong. Keepalive pings refresh it, so only a dead peer reaches it.
	DefaultIdleTimeout = 120 * time.Second

	// DefaultHandshakeTimeout bounds the upstream dial and upgrade.
	DefaultHandshakeTimeout = 10 * time.Second

	writeWait          = 10 * time.Second
	closeGrace         = 2 * time.Second
	maxUpstreamErrBody = 4 << 10
	maxCloseReason     = 123
)

// RoutePattern is the mux pattern the proxy is mounted on. It must match the
// websocket path collab's IssueToken hands the browser.
const RoutePattern = "GET /collab/ws/{draftID}"

// SessionCheck reports whether the upgrade request carries a live gateway
// session. The session layer provides it.
type SessionCheck func(r *http.Request) bool

// Config is the proxy's settings, filled by internal/config.
type Config struct {
	// Upstream is collab's websocket listener as host:port.
	Upstream string
	// AllowedOrigins are browser Origins accepted beyond same-origin.
	AllowedOrigins []string
	// MaxMessageBytes is the per-message read limit for both directions.
	MaxMessageBytes int64
	// IdleTimeout is the no-frame-and-no-pong deadline for both directions.
	IdleTimeout time.Duration
	// HandshakeTimeout bounds the upstream dial and upgrade.
	HandshakeTimeout time.Duration
}

// Proxy is the handler for RoutePattern.
type Proxy struct {
	cfg        Config
	hasSession SessionCheck
	logger     log.Logger
}

// New builds a Proxy. A nil hasSession refuses every upgrade.
func New(cfg Config, hasSession SessionCheck, logger log.Logger) *Proxy {
	return &Proxy{cfg: cfg, hasSession: hasSession, logger: logger}
}

// ServeHTTP dials collab first and upgrades the browser only once collab has
// agreed, so a collab refusal reaches the browser as collab's own status (a
// 401 with its challenge) instead of a 101 followed by a close.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	draftID := r.PathValue("draftID")
	if draftID == "" {
		http.Error(w, "draft id required", http.StatusBadRequest)
		return
	}
	if !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	lg := p.logger.With(log.F("draft_id", draftID))
	if !origin.Allowed(r, p.cfg.AllowedOrigins) {
		lg.Warn("collab proxy: origin not allowed")
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if p.hasSession == nil || !p.hasSession(r) {
		lg.Warn("collab proxy: no gateway session")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token := extractToken(r)
	if token == "" {
		lg.Warn("collab proxy: no collab token")
		w.Header().Set("WWW-Authenticate", `Bearer realm="steward.collab", error="invalid_token"`)
		http.Error(w, "missing collab token", http.StatusUnauthorized)
		return
	}

	start := time.Now()
	upstream, resp, err := p.dial(p.upstreamURL(r, draftID), upstreamHeader(r, token), websocket.Subprotocols(r))
	if err != nil {
		p.relayFailure(w, resp, err, lg, time.Since(start))
		return
	}
	respHeader := http.Header{}
	if sp := upstream.Subprotocol(); sp != "" {
		respHeader.Set("Sec-WebSocket-Protocol", sp)
	}
	upgrader := websocket.Upgrader{
		HandshakeTimeout: p.cfg.HandshakeTimeout,
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
		// Origin was checked above with a readable 403.
		CheckOrigin: func(*http.Request) bool { return true },
	}
	client, err := upgrader.Upgrade(w, r, respHeader)
	if err != nil {
		_ = upstream.Close()
		lg.Error(err, "collab proxy: client upgrade failed")
		return
	}
	lg.Info("collab proxy: session open", log.F("dial_ms", time.Since(start).Milliseconds()))
	p.relay(client, upstream, lg)
}

// dial opens the collab side. Compression stays off on both legs: the proxy
// re-frames messages, so a negotiated extension couldn't pass through.
func (p *Proxy) dial(target string, hdr http.Header, subprotocols []string) (*websocket.Conn, *http.Response, error) {
	d := &websocket.Dialer{
		HandshakeTimeout: p.cfg.HandshakeTimeout,
		Subprotocols:     subprotocols,
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
	}
	return d.Dial(target, hdr)
}

func (p *Proxy) upstreamURL(r *http.Request, draftID string) string {
	u := url.URL{Scheme: "ws", Host: p.cfg.Upstream, Path: "/ws/" + draftID}
	q := r.URL.Query()
	q.Del("token")
	u.RawQuery = q.Encode()
	return u.String()
}

// upstreamHeader starts empty: the dialer writes the upgrade headers itself
// and fails if they are supplied twice. No cookie, no Origin (collab refuses a
// browser Origin, which keeps this proxy the only path) and no client address.
func upstreamHeader(r *http.Request, token string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		h.Set("X-Forwarded-Proto", proto)
	}
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		h.Set("X-Forwarded-Host", host)
	} else if r.Host != "" {
		h.Set("X-Forwarded-Host", r.Host)
	}
	return h
}

// relayFailure passes collab's refusal through (status, challenge, a bounded
// body). Anything else is a dependency failure: 502.
func (p *Proxy) relayFailure(w http.ResponseWriter, resp *http.Response, err error, lg log.Logger, took time.Duration) {
	if errors.Is(err, websocket.ErrBadHandshake) && resp != nil {
		defer func() { _ = resp.Body.Close() }()
		lg.Warn("collab proxy: collab refused the upgrade", log.F("upstream_status", resp.StatusCode), log.F("dial_ms", took.Milliseconds()))
		if wa := resp.Header.Get("WWW-Authenticate"); wa != "" {
			w.Header().Set("WWW-Authenticate", wa)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, maxUpstreamErrBody))
		return
	}
	lg.Warn("collab proxy: collab unreachable", log.F("dial_ms", took.Milliseconds()), log.F("error_class", errorClass(err)))
	http.Error(w, "collab unavailable", http.StatusBadGateway)
}

// errorClass names a dial failure without its text, which carries addresses.
func errorClass(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case strings.Contains(err.Error(), "connection refused"):
		return "connection-refused"
	default:
		return "network"
	}
}

// extractToken reads the collab token from ?token= or an Authorization Bearer
// header. Collab validates it.
func extractToken(r *http.Request) string {
	if t := r.URL.Query().Get("token"); t != "" {
		return t
	}
	if after, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

// relay pumps both directions until one ends, tells the other side with the
// same close code, then tears both down.
func (p *Proxy) relay(client, upstream *websocket.Conn, lg log.Logger) {
	p.configure(client)
	p.configure(upstream)

	stopPing := make(chan struct{})
	defer close(stopPing)
	go p.keepalive(client, upstream, stopPing)

	done := make(chan direction, 2)
	go p.pump(upstream, client, done)
	go p.pump(client, upstream, done)

	first := <-done
	writeClose(first.peer, first.code, first.text)
	lg.Info("collab proxy: session closing", log.F("close_code", first.code))

	select {
	case <-done:
	case <-time.After(closeGrace):
	}
	_ = client.Close()
	_ = upstream.Close()
}

func (p *Proxy) configure(c *websocket.Conn) {
	c.SetReadLimit(p.cfg.MaxMessageBytes)
	_ = c.SetReadDeadline(time.Now().Add(p.cfg.IdleTimeout))
	c.SetPongHandler(func(string) error {
		return c.SetReadDeadline(time.Now().Add(p.cfg.IdleTimeout))
	})
}

// keepalive pings both peers at 45% of the idle timeout, so two lost pings
// still leave the deadline unreached. A browser never pings on its own.
func (p *Proxy) keepalive(a, b *websocket.Conn, stop <-chan struct{}) {
	period := p.cfg.IdleTimeout * 45 / 100
	if period <= 0 {
		period = DefaultIdleTimeout * 45 / 100
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			deadline := time.Now().Add(writeWait)
			if err := a.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
				return
			}
			if err := b.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
				return
			}
		}
	}
}

// direction is how one copy direction ended; peer is the still-live side.
type direction struct {
	peer *websocket.Conn
	code int
	text string
}

// pump copies messages from src to dst byte for byte, keeping the message
// type: the collab protocol is binary and a type flip breaks the decoder.
func (p *Proxy) pump(dst, src *websocket.Conn, done chan<- direction) {
	for {
		mt, payload, err := src.ReadMessage()
		if err != nil {
			done <- direction{peer: dst, code: closeCode(err), text: closeText(err)}
			return
		}
		_ = src.SetReadDeadline(time.Now().Add(p.cfg.IdleTimeout))
		_ = dst.SetWriteDeadline(time.Now().Add(writeWait))
		if err := dst.WriteMessage(mt, payload); err != nil {
			done <- direction{peer: src, code: websocket.CloseInternalServerErr, text: "relay write failed"}
			return
		}
	}
}

// closeCode maps a read error to the code for the other peer. 1005, 1006 and
// 1015 can't go on the wire, so a vanished peer is 1001. An oversize frame is
// 1009, the same code the overrunning peer got, so it fails loudly instead of
// truncating the document.
func closeCode(err error) int {
	if ce, ok := errors.AsType[*websocket.CloseError](err); ok {
		switch ce.Code {
		case websocket.CloseNoStatusReceived, websocket.CloseAbnormalClosure, websocket.CloseTLSHandshake:
			return websocket.CloseGoingAway
		default:
			return ce.Code
		}
	}
	if errors.Is(err, websocket.ErrReadLimit) {
		return websocket.CloseMessageTooBig
	}
	if errors.Is(err, io.EOF) || isTimeout(err) {
		return websocket.CloseGoingAway
	}
	return websocket.CloseInternalServerErr
}

// closeText forwards a peer's reason as is, and otherwise a short fixed text,
// never the Go error (it can carry addresses).
func closeText(err error) string {
	if ce, ok := errors.AsType[*websocket.CloseError](err); ok {
		return ce.Text
	}
	switch {
	case errors.Is(err, websocket.ErrReadLimit):
		return "message too big"
	case isTimeout(err):
		return "idle timeout"
	default:
		return "peer closed"
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func writeClose(c *websocket.Conn, code int, text string) {
	if len(text) > maxCloseReason {
		text = text[:maxCloseReason]
	}
	_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, text), time.Now().Add(writeWait))
}
