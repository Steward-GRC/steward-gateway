// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package backend dials every Steward service the gateway calls and holds the
// generated clients. Each connection sends the gateway's projected
// service-account token, read again on every call, and the request's
// go-grpc-actor Actor, so every callee knows both the calling service and the
// user it acts for.
package backend

import (
	"errors"
	"fmt"

	"google.golang.org/grpc"

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

// Service names, as the diagnostics read and the logs name them.
const (
	Identity    = "identity"
	Core        = "core"
	Workflow    = "workflow"
	Obligations = "obligations"
	Audit       = "audit"
	Delivery    = "delivery"
	Collab      = "collab"
	AI          = "ai"
	Reporting   = "reporting"
)

// Names lists every service the gateway calls, in a stable order.
func Names() []string {
	return []string{Identity, Core, Workflow, Obligations, Audit, Delivery, Collab, AI, Reporting}
}

// Clients holds one generated client per backend service.
type Clients struct {
	IdentityRead     identityv1.IdentityReadServiceClient
	IdentityAdmin    identityv1.IdentityAdminServiceClient
	IdentitySSOAdmin identityv1.IdentitySSOAdminServiceClient

	Category          corev1.CategoryServiceClient
	Template          corev1.TemplateServiceClient
	Policy            corev1.PolicyServiceClient
	Settings          corev1.SettingsServiceClient
	Appendix          corev1.AppendixServiceClient
	Relation          corev1.RelationServiceClient
	Contact           corev1.ContactServiceClient
	Reference         corev1.ReferenceServiceClient
	DefinitionLibrary corev1.DefinitionLibraryServiceClient
	Asset             corev1.AssetServiceClient

	Workflow workflowv1.WorkflowServiceClient

	Ack        obligationsv1.AckServiceClient
	NotifPref  obligationsv1.NotifPrefServiceClient
	Reporting  obligationsv1.ReportingServiceClient
	Obligation obligationsv1.ObligationServiceClient
	Welcome    obligationsv1.WelcomeServiceClient

	Audit auditv1.AuditServiceClient

	Delivery deliveryv1.DeliveryServiceClient

	CollabToken collabv1.CollabTokenServiceClient
	CollabRoom  collabv1.CollabRoomServiceClient

	AI aiv1.AiServiceClient

	Cases  reportingv1.CaseServiceClient
	Intake reportingv1.IntakeServiceClient
}

// Conns holds the open connections, by service name. The diagnostics read and
// readiness use them for the standard health check.
type Conns map[string]*grpc.ClientConn

// Close closes every connection.
func (c Conns) Close() error {
	var errs []error
	for _, conn := range c {
		errs = append(errs, conn.Close())
	}
	return errors.Join(errs...)
}

// NewClients builds the clients over conns, which must hold every name in
// Names.
func NewClients(conns Conns) (*Clients, error) {
	for _, n := range Names() {
		if conns[n] == nil {
			return nil, fmt.Errorf("backend: no connection for %s", n)
		}
	}
	id, core, wf, ob := conns[Identity], conns[Core], conns[Workflow], conns[Obligations]
	return &Clients{
		IdentityRead:     identityv1.NewIdentityReadServiceClient(id),
		IdentityAdmin:    identityv1.NewIdentityAdminServiceClient(id),
		IdentitySSOAdmin: identityv1.NewIdentitySSOAdminServiceClient(id),

		Category:          corev1.NewCategoryServiceClient(core),
		Template:          corev1.NewTemplateServiceClient(core),
		Policy:            corev1.NewPolicyServiceClient(core),
		Settings:          corev1.NewSettingsServiceClient(core),
		Appendix:          corev1.NewAppendixServiceClient(core),
		Relation:          corev1.NewRelationServiceClient(core),
		Contact:           corev1.NewContactServiceClient(core),
		Reference:         corev1.NewReferenceServiceClient(core),
		DefinitionLibrary: corev1.NewDefinitionLibraryServiceClient(core),
		Asset:             corev1.NewAssetServiceClient(core),

		Workflow: workflowv1.NewWorkflowServiceClient(wf),

		Ack:        obligationsv1.NewAckServiceClient(ob),
		NotifPref:  obligationsv1.NewNotifPrefServiceClient(ob),
		Reporting:  obligationsv1.NewReportingServiceClient(ob),
		Obligation: obligationsv1.NewObligationServiceClient(ob),
		Welcome:    obligationsv1.NewWelcomeServiceClient(ob),

		Audit: auditv1.NewAuditServiceClient(conns[Audit]),

		Delivery: deliveryv1.NewDeliveryServiceClient(conns[Delivery]),

		CollabToken: collabv1.NewCollabTokenServiceClient(conns[Collab]),
		CollabRoom:  collabv1.NewCollabRoomServiceClient(conns[Collab]),

		AI: aiv1.NewAiServiceClient(conns[AI]),

		Cases:  reportingv1.NewCaseServiceClient(conns[Reporting]),
		Intake: reportingv1.NewIntakeServiceClient(conns[Reporting]),
	}, nil
}
