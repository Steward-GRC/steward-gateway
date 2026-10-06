// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	log "github.com/Bugs5382/go-log"
	coderws "github.com/coder/websocket"
	"github.com/vektah/gqlparser/v2/ast"

	"github.com/Steward-GRC/steward-gateway/internal/origin"
)

// GraphQLOptions configure the GraphQL handler.
type GraphQLOptions struct {
	Logger log.Logger
	// WebsocketInit authenticates a subscription connection from its
	// connection_init payload and the upgrade request's session cookie.
	WebsocketInit transport.WebsocketInitFunc
	// AllowedOrigins are the extra browser origins (besides same-origin) a
	// subscription websocket may come from.
	AllowedOrigins []string
	// OperationMiddleware runs around every operation, in order (the
	// maintenance gate, the act-as refusals).
	OperationMiddleware []graphql.OperationMiddleware
}

// NewGraphQL returns the GraphQL handler over schema: POST, GET and
// multipart queries, websocket subscriptions, the error presenter and panic
// recovery, a parsed-query cache and persisted queries.
func NewGraphQL(schema graphql.ExecutableSchema, o GraphQLOptions) *handler.Server {
	srv := handler.New(schema)
	srv.SetErrorPresenter(ErrorPresenter(o.Logger))
	srv.SetRecoverFunc(RecoverFunc(o.Logger))
	for _, mw := range o.OperationMiddleware {
		srv.AroundOperations(mw)
	}
	extra := o.AllowedOrigins
	srv.AddTransport(transport.Websocket{
		KeepAlivePingInterval: 10 * time.Second,
		InitFunc:              o.WebsocketInit,
		Implementation:        originChecked{extra: extra},
	})
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})
	srv.AddTransport(transport.MultipartForm{})
	srv.SetQueryCache(lru.New[*ast.QueryDocument](1000))
	srv.Use(extension.Introspection{})
	srv.Use(extension.AutomaticPersistedQuery{Cache: lru.New[string](100)})
	return srv
}

// originChecked accepts a subscription websocket only from the gateway's own
// origin or a listed one; the session check in the init payload still
// decides who it is.
type originChecked struct{ extra []string }

func (o originChecked) Accept(w http.ResponseWriter, r *http.Request, opts transport.WebsocketAcceptOptions) (transport.WebsocketConn, error) {
	if !origin.Allowed(r, o.extra) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return nil, errors.New("server: websocket origin not allowed")
	}
	return transport.CoderWebsocketImplementation{AcceptOptions: coderws.AcceptOptions{InsecureSkipVerify: true}}.Accept(w, r, opts)
}
