// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	log "github.com/Bugs5382/go-log"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// RequestIDHeader carries the request id back to the browser.
const RequestIDHeader = "X-Request-Id"

// Wrap puts the edge middleware around the mux: a trace span, a fresh request
// id on the context and the response, panic recovery and one access-log line
// per request. The access log carries the method, the path, the status and the
// duration only: never an address, a query string or a header value.
func Wrap(next http.Handler, lg log.Logger) http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set(RequestIDHeader, id)
		ctx := WithRequestID(r.Context(), id)
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				lg.Ctx(ctx).Error(fmt.Errorf("panic: %v", v), "gateway: http handler panic", log.F("path", r.URL.Path))
				if !sr.wrote {
					http.Error(sr, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}
			lg.Ctx(ctx).Info("http request", log.F("method", r.Method), log.F("path", r.URL.Path),
				log.F("status", sr.status), log.F("dur_ms", time.Since(start).Milliseconds()), log.F("request_id", id))
		}()
		next.ServeHTTP(sr, r.WithContext(ctx))
	})
	return otelhttp.NewHandler(h, "gateway", otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
		return r.Method + " " + r.URL.Path
	}))
}

type reqKey struct{}

// WithRequest stores the request on its context, so the subscription
// websocket's init can read the session cookie from the upgrade request.
func WithRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reqKey{}, r)))
	})
}

// RequestFromContext returns the request WithRequest stored.
func RequestFromContext(ctx context.Context) (*http.Request, bool) {
	r, ok := ctx.Value(reqKey{}).(*http.Request)
	return r, ok
}

func newRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status, s.wrote = code, true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

// Hijack keeps the recorder transparent to websocket upgrades.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("server: the response writer can't be hijacked")
	}
	return hj.Hijack()
}

// Flush passes flushes through, for streamed responses.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
