// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package resolvers implements the GraphQL schema in graphql/. gqlgen writes
// generated.go, models_gen.go and one <area>.resolvers.go per schema file; the
// rest is the hand-written mapping onto each backend's API.
//
// Who a request is for always comes from principal.FromContext, never from
// client input, and every backend call carries that user through go-grpc-actor.
package resolvers

import (
	"context"

	log "github.com/Bugs5382/go-log"

	"github.com/Steward-GRC/steward-gateway/internal/aijobs"
	"github.com/Steward-GRC/steward-gateway/internal/backend"
	"github.com/Steward-GRC/steward-gateway/internal/bff"
	"github.com/Steward-GRC/steward-gateway/internal/diagnostics"
	"github.com/Steward-GRC/steward-gateway/internal/live"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	collabv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/collab/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	deliveryv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/delivery/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	reportingv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/reporting/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
)

// Resolver is the root resolver: the backend clients and the gateway's own
// dependencies, wired in cmd/server.
type Resolver struct {
	// identity
	IdentityClient      identityv1.IdentityReadServiceClient
	IdentityAdminClient identityv1.IdentityAdminServiceClient
	SSOAdminClient      identityv1.IdentitySSOAdminServiceClient

	// core
	CategoryClient          corev1.CategoryServiceClient
	TemplateClient          corev1.TemplateServiceClient
	PolicyClient            corev1.PolicyServiceClient
	SettingsClient          corev1.SettingsServiceClient
	AppendixClient          corev1.AppendixServiceClient
	RelationClient          corev1.RelationServiceClient
	ContactClient           corev1.ContactServiceClient
	ReferenceClient         corev1.ReferenceServiceClient
	DefinitionLibraryClient corev1.DefinitionLibraryServiceClient
	AssetClient             corev1.AssetServiceClient

	// workflow
	WorkflowClient workflowv1.WorkflowServiceClient

	// obligations
	AckClient        obligationsv1.AckServiceClient
	NotifPrefClient  obligationsv1.NotifPrefServiceClient
	ReportingClient  obligationsv1.ReportingServiceClient
	ObligationClient obligationsv1.ObligationServiceClient
	WelcomeClient    obligationsv1.WelcomeServiceClient

	// audit
	AuditClient auditv1.AuditServiceClient

	// delivery
	DeliveryClient deliveryv1.DeliveryServiceClient

	// collab. CollabRoomClient may be nil (no collab): publish then skips the
	// flush and the freeze.
	CollabClient     collabv1.CollabTokenServiceClient
	CollabRoomClient collabv1.CollabRoomServiceClient

	// ai
	AIClient aiv1.AiServiceClient

	// reporting (cases and intake)
	CaseClient   reportingv1.CaseServiceClient
	IntakeClient reportingv1.IntakeServiceClient

	// SessionStore holds the browser sessions; act-as lives on the admin's.
	SessionStore bff.SessionStore
	// AuditEmitter publishes the gateway's own audit events (act-as start and
	// stop). Nil skips emission.
	AuditEmitter AuditEmitter

	// AllowHardDelete gates deleteTemplate; off unless the operator turns it on.
	AllowHardDelete bool

	// Area-owned dependencies go below, one block per area.

	// core (and every area): the request logger. Nil logs nothing.
	Log log.Logger

	// ai: AIJobBroker fans job completions out to aiJobResult subscribers;
	// AIJobContentReader reads job results by resultRef. Either may be nil:
	// aiJobResult and aiJobResultContent then return an error.
	AIJobBroker        *aijobs.Broker
	AIJobContentReader *aijobs.ContentReader

	// live: Bus feeds the liveEvents subscription. Nil makes it return an
	// error.
	Bus *live.Bus

	// reporting: ReportLimiter throttles anonymous report checks and replies.
	// Nil refuses them.
	ReportLimiter ReportLimiter

	// diagnostics: the build and version probes behind the diagnostics query.
	// Nil reports the actor and the gateway only.
	Diagnostics *diagnostics.Service
}

// logger returns r.Log, or a logger that writes nothing.
func (r *Resolver) logger() log.Logger {
	if r.Log == nil {
		return log.Nop()
	}
	return r.Log
}

// AuditEmitter publishes one steward-audit AuditEvent.
type AuditEmitter interface {
	Emit(ctx context.Context, ev *auditv1.AuditEvent) error
}

// FromClients fills the backend clients from c.
func (r *Resolver) FromClients(c *backend.Clients) *Resolver {
	r.IdentityClient, r.IdentityAdminClient, r.SSOAdminClient = c.IdentityRead, c.IdentityAdmin, c.IdentitySSOAdmin
	r.CategoryClient, r.TemplateClient, r.PolicyClient, r.SettingsClient = c.Category, c.Template, c.Policy, c.Settings
	r.AppendixClient, r.RelationClient, r.ContactClient = c.Appendix, c.Relation, c.Contact
	r.ReferenceClient, r.DefinitionLibraryClient, r.AssetClient = c.Reference, c.DefinitionLibrary, c.Asset
	r.WorkflowClient = c.Workflow
	r.AckClient, r.NotifPrefClient, r.ReportingClient, r.ObligationClient, r.WelcomeClient = c.Ack, c.NotifPref, c.Reporting, c.Obligation, c.Welcome
	r.AuditClient = c.Audit
	r.DeliveryClient = c.Delivery
	r.CollabClient, r.CollabRoomClient = c.CollabToken, c.CollabRoom
	r.AIClient = c.AI
	r.CaseClient, r.IntakeClient = c.Cases, c.Intake
	return r
}
