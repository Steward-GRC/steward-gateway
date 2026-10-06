// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/99designs/gqlgen/graphql"
	apperr "github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	log "github.com/Bugs5382/go-log"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

// ServerFaultMessage is the one message every failure on our side shows. The
// web pairs it with a Try again and the code as a reference.
const ServerFaultMessage = "Something went wrong on our side. Please try again."

const internalSymbol = "INTERNAL"

// reserved are the extension keys the presenter owns; a backend's metadata
// never overwrites them.
var reserved = map[string]bool{
	"code": true, "codeNum": true, "domain": true, "kind": true,
	"requestId": true, "traceId": true,
}

type requestIDKey struct{}

// WithRequestID returns ctx carrying the request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext returns the request id, or "".
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// ErrorPresenter turns every resolver error into the client contract: a coded
// refusal keeps its code, domain, kind, user-safe message and metadata; every
// fault gets the generic message, kind reach and a numeric reference. Every
// error carries requestId and traceId.
func ErrorPresenter(lg log.Logger) graphql.ErrorPresenterFunc {
	return func(ctx context.Context, err error) *gqlerror.Error {
		var gqlErr *gqlerror.Error
		if errors.As(err, &gqlErr) {
			if gqlErr.Unwrap() == nil {
				out := *gqlErr
				out.Extensions = withIDs(ctx, gqlErr.Extensions)
				return &out
			}
		}
		out := presentErr(ctx, lg, err)
		if gqlErr != nil {
			out.Path = gqlErr.Path
			out.Locations = gqlErr.Locations
		}
		out.Extensions = withIDs(ctx, out.Extensions)
		return out
	}
}

// RecoverFunc turns a resolver panic into a fault with the same contract.
func RecoverFunc(lg log.Logger) graphql.RecoverFunc {
	return func(ctx context.Context, v any) error {
		lg.Ctx(ctx).Error(fmt.Errorf("panic: %v", v), "gateway: resolver panic", log.F("code", errcodes.CodeInternal))
		return &gqlerror.Error{Message: ServerFaultMessage, Extensions: map[string]any{
			"code": internalSymbol, "codeNum": errcodes.CodeInternal, "domain": errcodes.Domain, "kind": string(errcodes.KindReach),
		}}
	}
}

func presentErr(ctx context.Context, lg log.Logger, err error) *gqlerror.Error {
	if code, ok := apperr.Code(err); ok {
		return presentGateway(ctx, lg, err, code)
	}
	if st, ok := innermostStatus(err); ok {
		return presentStatus(ctx, lg, err, st)
	}
	return fault(ctx, lg, err, errcodes.CodeInternal, errcodes.Domain)
}

func presentGateway(ctx context.Context, lg log.Logger, err error, code int) *gqlerror.Error {
	reg := errcodes.Registry()
	entry, ok := reg.Describe(code)
	if !ok || !entry.UserSafe {
		return fault(ctx, lg, err, code, errcodes.Domain)
	}
	msg, _ := reg.Present(err, errcodes.CodeInternal)
	ext := metaExtensions(apperr.Metadata(err))
	ext["code"], ext["codeNum"], ext["domain"] = entry.Symbol, code, errcodes.Domain
	ext["kind"] = string(errcodes.KindOf(entry.Category))
	if ext["kind"] == string(errcodes.KindReach) {
		logFault(ctx, lg, err, code)
	}
	return &gqlerror.Error{Message: msg, Extensions: ext}
}

func presentStatus(ctx context.Context, lg log.Logger, err error, st *status.Status) *gqlerror.Error {
	info, hasInfo := apperrgrpc.FromStatus(st)
	kind := errcodes.KindOfGRPC(st.Code())
	if st.Code() == codes.ResourceExhausted && !hasInfo {
		kind = errcodes.KindReach
	}
	if kind == errcodes.KindReach {
		if hasInfo && info.Code != 0 {
			return fault(ctx, lg, err, info.Code, info.Domain)
		}
		return fault(ctx, lg, err, errcodes.CodeInternal, errcodes.Domain)
	}
	ext := map[string]any{"kind": string(kind)}
	if hasInfo {
		ext = metaExtensions(info.Metadata)
		ext["kind"] = string(kind)
		ext["code"] = info.Symbol
		if info.Symbol == "" {
			ext["code"] = st.Code().String()
		}
		ext["codeNum"], ext["domain"] = info.Code, info.Domain
	} else {
		ext["code"] = st.Code().String()
	}
	return &gqlerror.Error{Message: st.Message(), Extensions: ext}
}

func fault(ctx context.Context, lg log.Logger, err error, code int, domain string) *gqlerror.Error {
	logFault(ctx, lg, err, code)
	ext := map[string]any{"code": internalSymbol, "codeNum": code, "kind": string(errcodes.KindReach)}
	if domain != "" {
		ext["domain"] = domain
	}
	return &gqlerror.Error{Message: ServerFaultMessage, Extensions: ext}
}

var addrPattern = regexp.MustCompile(`\[?[0-9a-fA-F]*:[0-9a-fA-F:]+:[0-9a-fA-F]*\]?|\b\d{1,3}(?:\.\d{1,3}){3}\b`)

func logFault(ctx context.Context, lg log.Logger, err error, code int) {
	lg.Ctx(ctx).Error(errors.New(addrPattern.ReplaceAllString(err.Error(), "[addr]")),
		"gateway: sanitized internal error", log.F("code", code))
}

func innermostStatus(err error) (*status.Status, bool) {
	var found *status.Status
	for e := err; e != nil; e = errors.Unwrap(e) {
		if s, ok := e.(interface{ GRPCStatus() *status.Status }); ok {
			found = s.GRPCStatus()
		}
	}
	return found, found != nil
}

func metaExtensions(md map[string]string) map[string]any {
	ext := map[string]any{}
	for k, v := range md {
		if !reserved[k] {
			ext[k] = v
		}
	}
	return ext
}

func withIDs(ctx context.Context, ext map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range ext {
		out[k] = v
	}
	out["requestId"] = RequestIDFromContext(ctx)
	out["traceId"] = ""
	if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
		out["traceId"] = sc.TraceID().String()
	}
	return out
}
