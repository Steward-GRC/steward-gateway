// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	authz "github.com/Steward-GRC/steward-authz"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	obligationsv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/obligations/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
)

func ackFromProto(a *obligationsv1.Acknowledgment) *Acknowledgment {
	if a == nil {
		return nil
	}
	out := &Acknowledgment{
		ID:              a.GetId(),
		UserID:          a.GetUserId(),
		PolicyVersionID: a.GetPolicyVersionId(),
	}
	if t := a.GetAckedAt(); t != nil {
		out.AckedAt = t.AsTime().UTC().Format(time.RFC3339)
	}
	return out
}

func notifPrefFromProto(p *obligationsv1.NotificationPref) *NotificationPref {
	if p == nil {
		return nil
	}
	return &NotificationPref{
		UserID: p.GetUserId(),
		Email:  p.GetEmail(),
		InApp:  p.GetInApp(),
		Push:   p.GetPush(),
	}
}

// RecordAckResolver records an acknowledgment for the authenticated user against the supplied
// policy version.
func RecordAckResolver(ctx context.Context, client obligationsv1.AckServiceClient, policyVersionID string) (*Acknowledgment, error) {
	if _, ok := principal.FromContext(ctx); !ok {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.RecordAck(ctx, &obligationsv1.RecordAckRequest{
		PolicyVersionId: policyVersionID,
	})
	if err != nil {
		return nil, fmt.Errorf("compliance record ack: %w", err)
	}
	return ackFromProto(resp.GetAcknowledgment()), nil
}

// GetAckStatusResolver returns whether the authenticated user has acknowledged the supplied policy
// version.
func GetAckStatusResolver(ctx context.Context, client obligationsv1.AckServiceClient, policyVersionID string) (*AckStatus, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.GetAckStatus(ctx, &obligationsv1.GetAckStatusRequest{
		UserId:          claims.UserID(),
		PolicyVersionId: policyVersionID,
	})
	if err != nil {
		return nil, fmt.Errorf("compliance get ack status: %w", err)
	}
	out := &AckStatus{Acknowledged: resp.GetAcknowledged()}
	if t := resp.GetAckedAt(); t != nil {
		s := t.AsTime().UTC().Format(time.RFC3339)
		out.AckedAt = &s
	}
	return out, nil
}

// UpsertNotificationPrefResolver writes the authenticated user's notification preferences.
func UpsertNotificationPrefResolver(ctx context.Context, client obligationsv1.NotifPrefServiceClient, input NotificationPrefInput) (*NotificationPref, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.UpsertNotifPref(ctx, &obligationsv1.UpsertNotifPrefRequest{
		Pref: &obligationsv1.NotificationPref{
			UserId: claims.UserID(),
			Email:  input.Email,
			InApp:  input.InApp,
			Push:   input.Push,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("compliance upsert notif pref: %w", err)
	}
	return notifPrefFromProto(resp.GetPref()), nil
}

// GetNotificationPrefResolver reads the authenticated user's notification preferences.
func GetNotificationPrefResolver(ctx context.Context, client obligationsv1.NotifPrefServiceClient) (*NotificationPref, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.GetNotifPref(ctx, &obligationsv1.GetNotifPrefRequest{UserId: claims.UserID()})
	if err != nil {
		return nil, fmt.Errorf("compliance get notif pref: %w", err)
	}
	return notifPrefFromProto(resp.GetPref()), nil
}

// GetCompletionReportResolver returns the audience-completion summary for a policy version,
// enriching each overdue entry with a display name.
func GetCompletionReportResolver(ctx context.Context, client obligationsv1.ReportingServiceClient, identity identityv1.IdentityReadServiceClient, policyVersionID string, groupID *string) (*CompletionReport, error) {
	if err := authorizeOp(ctx, authz.ComplianceReport); err != nil {
		return nil, err
	}
	resp, err := client.GetCompletionReport(ctx, &obligationsv1.GetCompletionReportRequest{
		PolicyVersionId: policyVersionID,
		GroupId:         derefOrEmpty(groupID),
	})
	if err != nil {
		return nil, fmt.Errorf("compliance get completion report: %w", err)
	}
	labels := newLabelResolver(identity, nil, nil, nil)
	overdue := make([]*OverdueEntry, 0, len(resp.GetOverdue()))
	for _, o := range resp.GetOverdue() {
		e := &OverdueEntry{UserID: o.GetUserId(), Email: o.GetEmail()}
		if name := labels.userName(ctx, o.GetUserId()); name != "" {
			e.UserName = &name
		}
		overdue = append(overdue, e)
	}
	return &CompletionReport{
		TotalAudience:       int(resp.GetTotalAudience()),
		TotalAcked:          int(resp.GetTotalAcked()),
		CompletionPct:       float64(resp.GetCompletionPct()),
		AvgDaysToAck:        float64(resp.GetAvgDaysToAck()),
		ViewedNotAckedCount: int(resp.GetViewedNotAckedCount()),
		Overdue:             overdue,
	}, nil
}

// MyObligationsResolver returns outstanding obligations for the authenticated user.
func MyObligationsResolver(ctx context.Context, client obligationsv1.ObligationServiceClient) ([]*Obligation, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.GetMyObligations(ctx, &obligationsv1.GetMyObligationsRequest{UserId: claims.UserID()})
	if err != nil {
		return nil, fmt.Errorf("compliance get my obligations: %w", err)
	}
	out := make([]*Obligation, 0, len(resp.GetObligations()))
	for _, item := range resp.GetObligations() {
		out = append(out, obligationFromProto(item))
	}
	return out, nil
}

// MyAckSummaryResolver returns the authenticated user's acknowledgement- compliance summary
// (required / done).
func MyAckSummaryResolver(ctx context.Context, client obligationsv1.ObligationServiceClient) (*AckSummary, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.MyAckSummary(ctx, &obligationsv1.MyAckSummaryRequest{UserId: claims.UserID()})
	if err != nil {
		return nil, fmt.Errorf("compliance my ack summary: %w", err)
	}
	return &AckSummary{
		Required: int(resp.GetRequired()),
		Done:     int(resp.GetDone()),
	}, nil
}

// ObligatedAudienceCountResolver returns the number of users obligated to acknowledge a policy.
func ObligatedAudienceCountResolver(ctx context.Context, client obligationsv1.ObligationServiceClient, policyID string) (int, error) {
	if err := authorizeOp(ctx, authz.ComplianceManage); err != nil {
		return 0, err
	}
	resp, err := client.GetObligatedAudienceCount(ctx, &obligationsv1.GetObligatedAudienceCountRequest{PolicyId: policyID})
	if err != nil {
		return 0, fmt.Errorf("compliance get obligated audience count: %w", err)
	}
	return int(resp.GetCount()), nil
}

func obligationFromProto(item *obligationsv1.ObligationItem) *Obligation {
	if item == nil {
		return nil
	}
	return &Obligation{
		PolicyID:        item.GetPolicyId(),
		Number:          item.GetNumber(),
		Title:           item.GetTitle(),
		Version:         fmt.Sprintf("%d", item.GetVersionNo()),
		PolicyVersionID: item.GetPolicyVersionId(),
	}
}

// ExportAcksResolver returns a base64-encoded acknowledgment export.
func ExportAcksResolver(ctx context.Context, client obligationsv1.ReportingServiceClient, policyVersionID, format string) (*AckExport, error) {
	if err := authorizeOp(ctx, authz.ComplianceReport); err != nil {
		return nil, err
	}
	resp, err := client.ExportAcks(ctx, &obligationsv1.ExportAcksRequest{
		PolicyVersionId: policyVersionID,
		Format:          format,
	})
	if err != nil {
		return nil, fmt.Errorf("compliance export acks: %w", err)
	}
	return &AckExport{
		Data:        base64.StdEncoding.EncodeToString(resp.GetData()),
		ContentType: resp.GetContentType(),
	}, nil
}

// RecordViewResolver records that the authenticated caller viewed a policy version.
func RecordViewResolver(ctx context.Context, client obligationsv1.AckServiceClient, policyVersionID string) (bool, error) {
	if _, ok := principal.FromContext(ctx); !ok {
		return false, fmt.Errorf("unauthenticated")
	}
	if _, err := client.RecordView(ctx, &obligationsv1.RecordViewRequest{PolicyVersionId: policyVersionID}); err != nil {
		return false, fmt.Errorf("compliance record view: %w", err)
	}
	return true, nil
}

func rosterEntryFromProto(ctx context.Context, labels *labelResolver, e *obligationsv1.AckRosterEntry) *AckRosterEntry {
	out := &AckRosterEntry{UserID: e.GetUserId(), Email: e.GetEmail()}
	if name := labels.userName(ctx, e.GetUserId()); name != "" {
		out.UserName = &name
	}
	if t := e.GetAckedAt(); t != nil {
		s := t.AsTime().UTC().Format(time.RFC3339)
		out.AckedAt = &s
	}
	return out
}

// AckRosterResolver returns the acked/pending audience split, names enriched.
func AckRosterResolver(ctx context.Context, client obligationsv1.ReportingServiceClient, identity identityv1.IdentityReadServiceClient, policyVersionID string, groupID *string) (*AckRoster, error) {
	if err := authorizeOp(ctx, authz.ComplianceReport); err != nil {
		return nil, err
	}
	resp, err := client.GetAckRoster(ctx, &obligationsv1.GetAckRosterRequest{
		PolicyVersionId: policyVersionID,
		GroupId:         derefOrEmpty(groupID),
	})
	if err != nil {
		return nil, fmt.Errorf("compliance get ack roster: %w", err)
	}
	labels := newLabelResolver(identity, nil, nil, nil)
	out := &AckRoster{
		Acked:   make([]*AckRosterEntry, 0, len(resp.GetAcked())),
		Pending: make([]*AckRosterEntry, 0, len(resp.GetPending())),
	}
	for _, e := range resp.GetAcked() {
		out.Acked = append(out.Acked, rosterEntryFromProto(ctx, labels, e))
	}
	for _, e := range resp.GetPending() {
		out.Pending = append(out.Pending, rosterEntryFromProto(ctx, labels, e))
	}
	return out, nil
}

// AckActivityResolver returns the daily ack/view series for the version.
func AckActivityResolver(ctx context.Context, client obligationsv1.ReportingServiceClient, policyVersionID string, groupID *string, days int) ([]*AckActivityDay, error) {
	if err := authorizeOp(ctx, authz.ComplianceReport); err != nil {
		return nil, err
	}
	resp, err := client.GetAckActivity(ctx, &obligationsv1.GetAckActivityRequest{
		PolicyVersionId: policyVersionID,
		GroupId:         derefOrEmpty(groupID),
		Days:            toInt32(days),
	})
	if err != nil {
		return nil, fmt.Errorf("compliance get ack activity: %w", err)
	}
	out := make([]*AckActivityDay, 0, len(resp.GetDays()))
	for _, d := range resp.GetDays() {
		out = append(out, &AckActivityDay{Date: d.GetDate(), Acks: int(d.GetAcks()), Views: int(d.GetViews())})
	}
	return out, nil
}

func notifCadenceToProto(c NotifCadence) obligationsv1.NotifCadence {
	switch c {
	case NotifCadenceImmediate:
		return obligationsv1.NotifCadence_NOTIF_CADENCE_IMMEDIATE
	case NotifCadenceDaily:
		return obligationsv1.NotifCadence_NOTIF_CADENCE_DAILY
	case NotifCadenceWeekly:
		return obligationsv1.NotifCadence_NOTIF_CADENCE_WEEKLY
	case NotifCadenceOff:
		return obligationsv1.NotifCadence_NOTIF_CADENCE_OFF
	default:
		return obligationsv1.NotifCadence_NOTIF_CADENCE_UNSPECIFIED
	}
}

func notifCadenceFromProto(c obligationsv1.NotifCadence) NotifCadence {
	switch c {
	case obligationsv1.NotifCadence_NOTIF_CADENCE_IMMEDIATE:
		return NotifCadenceImmediate
	case obligationsv1.NotifCadence_NOTIF_CADENCE_DAILY:
		return NotifCadenceDaily
	case obligationsv1.NotifCadence_NOTIF_CADENCE_WEEKLY:
		return NotifCadenceWeekly
	default:
		return NotifCadenceOff
	}
}

func notifCategoryToProto(c NotifCategory) obligationsv1.NotifCategory {
	switch c {
	case NotifCategoryCompliance:
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE
	case NotifCategorySecurity:
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_SECURITY
	case NotifCategoryTransactional:
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_TRANSACTIONAL
	case NotifCategoryWorkflow:
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_WORKFLOW
	case NotifCategoryInformational:
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_INFORMATIONAL
	default:
		return obligationsv1.NotifCategory_NOTIF_CATEGORY_UNSPECIFIED
	}
}

func notifCategoryFromProto(c obligationsv1.NotifCategory) NotifCategory {
	switch c {
	case obligationsv1.NotifCategory_NOTIF_CATEGORY_COMPLIANCE:
		return NotifCategoryCompliance
	case obligationsv1.NotifCategory_NOTIF_CATEGORY_SECURITY:
		return NotifCategorySecurity
	case obligationsv1.NotifCategory_NOTIF_CATEGORY_TRANSACTIONAL:
		return NotifCategoryTransactional
	case obligationsv1.NotifCategory_NOTIF_CATEGORY_WORKFLOW:
		return NotifCategoryWorkflow
	default:
		return NotifCategoryInformational
	}
}

func notifSettingsFromProto(s *obligationsv1.NotificationSettings) *NotificationSettings {
	if s == nil {
		return nil
	}
	out := &NotificationSettings{
		Channels: notifPrefFromProto(s.GetChannels()),
		Digest:   &DigestWindow{},
	}
	if d := s.GetDigest(); d != nil {
		out.Digest = &DigestWindow{DailyHour: int(d.GetDailyHour()), WeeklyDow: int(d.GetWeeklyDow())}
	}
	for _, c := range s.GetCategories() {
		out.Categories = append(out.Categories, &CategoryPref{
			Category:  notifCategoryFromProto(c.GetCategory()),
			Cadence:   notifCadenceFromProto(c.GetCadence()),
			Mandatory: c.GetMandatory(),
		})
	}
	for _, o := range s.GetOverrides() {
		out.Overrides = append(out.Overrides, &TypePref{
			Kind:      o.GetKind(),
			Category:  notifCategoryFromProto(o.GetCategory()),
			Cadence:   notifCadenceFromProto(o.GetCadence()),
			Mandatory: o.GetMandatory(),
			Delivery:  notifDeliveryFromProto(o.GetDelivery()),
		})
	}
	return out
}

// notifDeliveryFromProto maps the wire delivery policy to the GraphQL enum.
func notifDeliveryFromProto(d obligationsv1.NotifDelivery) NotifDelivery {
	switch d {
	case obligationsv1.NotifDelivery_NOTIF_DELIVERY_IMMEDIATE_OR_DIGEST:
		return NotifDeliveryImmediateOrDigest
	case obligationsv1.NotifDelivery_NOTIF_DELIVERY_REMINDER_SCHEDULE:
		return NotifDeliveryReminderSchedule
	case obligationsv1.NotifDelivery_NOTIF_DELIVERY_DIGEST_PREFERRED:
		return NotifDeliveryDigestPreferred
	default:
		return NotifDeliveryImmediateOnly
	}
}

// NotificationTypeCatalogResolver reads the notification-type taxonomy: every type the platform
// sends, with its category, mandatory flag, and delivery policy.
func NotificationTypeCatalogResolver(ctx context.Context, client obligationsv1.NotifPrefServiceClient) ([]*NotifTypeDef, error) {
	if claims, ok := principal.FromContext(ctx); !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.ListNotifTypes(ctx, &obligationsv1.ListNotifTypesRequest{})
	if err != nil {
		return nil, fmt.Errorf("compliance list notif types: %w", err)
	}
	types := resp.GetTypes()
	out := make([]*NotifTypeDef, 0, len(types))
	for _, t := range types {
		out = append(out, &NotifTypeDef{
			Kind:      t.GetKind(),
			Category:  notifCategoryFromProto(t.GetCategory()),
			Mandatory: t.GetMandatory(),
			Delivery:  notifDeliveryFromProto(t.GetDelivery()),
		})
	}
	return out, nil
}

// GetNotificationSettingsResolver reads the authenticated user's full notification settings
// (channels + category cadences + overrides + digest).
func GetNotificationSettingsResolver(ctx context.Context, client obligationsv1.NotifPrefServiceClient) (*NotificationSettings, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.GetNotificationSettings(ctx, &obligationsv1.GetNotificationSettingsRequest{UserId: claims.UserID()})
	if err != nil {
		return nil, fmt.Errorf("compliance get notification settings: %w", err)
	}
	return notifSettingsFromProto(resp.GetSettings()), nil
}

// SetCategoryCadenceResolver sets a category cadence for the authenticated user.
func SetCategoryCadenceResolver(ctx context.Context, client obligationsv1.NotifPrefServiceClient, category NotifCategory, cadence NotifCadence) (*NotificationSettings, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.SetCategoryCadence(ctx, &obligationsv1.SetCategoryCadenceRequest{
		UserId:   claims.UserID(),
		Category: notifCategoryToProto(category),
		Cadence:  notifCadenceToProto(cadence),
	})
	if err != nil {
		return nil, fmt.Errorf("compliance set category cadence: %w", err)
	}
	return notifSettingsFromProto(resp.GetSettings()), nil
}

// SetTypeCadenceResolver sets an advanced per-type override for the authenticated user.
func SetTypeCadenceResolver(ctx context.Context, client obligationsv1.NotifPrefServiceClient, kind string, cadence NotifCadence) (*NotificationSettings, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.SetTypeCadence(ctx, &obligationsv1.SetTypeCadenceRequest{
		UserId:  claims.UserID(),
		Kind:    kind,
		Cadence: notifCadenceToProto(cadence),
	})
	if err != nil {
		return nil, fmt.Errorf("compliance set type cadence: %w", err)
	}
	return notifSettingsFromProto(resp.GetSettings()), nil
}

// SetDigestWindowResolver sets the authenticated user's digest window.
func SetDigestWindowResolver(ctx context.Context, client obligationsv1.NotifPrefServiceClient, dailyHour, weeklyDow int) (*NotificationSettings, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	resp, err := client.SetDigestWindow(ctx, &obligationsv1.SetDigestWindowRequest{
		UserId:    claims.UserID(),
		DailyHour: toInt32(dailyHour),
		WeeklyDow: toInt32(weeklyDow),
	})
	if err != nil {
		return nil, fmt.Errorf("compliance set digest window: %w", err)
	}
	return notifSettingsFromProto(resp.GetSettings()), nil
}

// SetNotificationChannelsResolver writes the authenticated user's channel master switches
// (superseding upsertNotificationPref) and returns the full settings.
func SetNotificationChannelsResolver(ctx context.Context, client obligationsv1.NotifPrefServiceClient, input NotificationPrefInput) (*NotificationSettings, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	if _, err := client.UpsertNotifPref(ctx, &obligationsv1.UpsertNotifPrefRequest{
		Pref: &obligationsv1.NotificationPref{
			UserId: claims.UserID(),
			Email:  input.Email,
			InApp:  input.InApp,
			Push:   input.Push,
		},
	}); err != nil {
		return nil, fmt.Errorf("compliance set notification channels: %w", err)
	}
	resp, err := client.GetNotificationSettings(ctx, &obligationsv1.GetNotificationSettingsRequest{UserId: claims.UserID()})
	if err != nil {
		return nil, fmt.Errorf("compliance get notification settings: %w", err)
	}
	return notifSettingsFromProto(resp.GetSettings()), nil
}
