// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	golog "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	reportingv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/reporting/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

type fakeModule struct {
	reportingv1.ModuleServiceClient
	calls     int
	lastSet   *reportingv1.SetComplianceModuleRequest
	lastReset *reportingv1.ExecuteHardResetRequest
	setErr    error
	resetErr  error
}

func (f *fakeModule) SetComplianceModule(_ context.Context, in *reportingv1.SetComplianceModuleRequest, _ ...grpc.CallOption) (*reportingv1.SetComplianceModuleResponse, error) {
	f.calls++
	f.lastSet = in
	if f.setErr != nil {
		return nil, f.setErr
	}
	return &reportingv1.SetComplianceModuleResponse{ModuleEnabled: in.GetEnabled()}, nil
}

func (f *fakeModule) ExecuteHardReset(_ context.Context, in *reportingv1.ExecuteHardResetRequest, _ ...grpc.CallOption) (*reportingv1.ExecuteHardResetResponse, error) {
	f.calls++
	f.lastReset = in
	if f.resetErr != nil {
		return nil, f.resetErr
	}
	return &reportingv1.ExecuteHardResetResponse{CasesDeleted: 12, RequestedByUserId: "u-root", ApprovedByUserId: "u-second"}, nil
}

type fakeComplianceSettings struct {
	reportingv1.SettingsServiceClient
	calls   int
	enabled bool
	err     error
}

func (f *fakeComplianceSettings) GetSettings(context.Context, *reportingv1.GetSettingsRequest, ...grpc.CallOption) (*reportingv1.GetSettingsResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &reportingv1.GetSettingsResponse{Settings: &reportingv1.ComplianceSettings{ModuleEnabled: f.enabled, RetentionDays: 365}}, nil
}

// ctxSiteAdmin is a signed-in site admin who is not root.
func ctxSiteAdmin(t *testing.T, uid string) context.Context {
	t.Helper()
	return ctxWithStubClaims(t, principal.Static{UserIDValue: uid, RolesValue: []string{"site-admin"}})
}

func moduleResolver(m reportingv1.ModuleServiceClient, s reportingv1.SettingsServiceClient) (*resolvers.Resolver, *bytes.Buffer) {
	var buf bytes.Buffer
	return &resolvers.Resolver{
		ModuleClient: m, ComplianceSettingsClient: s,
		Log: golog.NewLoggerWithOptions("gateway-test", golog.WithOutput(&buf), golog.WithDefaultFormat(golog.FormatJSON), golog.WithDefaultLevel(golog.LevelTrace)),
	}, &buf
}

func TestComplianceSettings_ReadsTheModuleSwitch(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{"compliance admin", ctxWithRoles(t, "u-co", []string{"compliance-admin"})},
		{"site admin", ctxSiteAdmin(t, "u-sa")},
		{"root", ctxRoot(t, "u-root")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeComplianceSettings{enabled: true}
			r, _ := moduleResolver(nil, s)
			got, err := r.ComplianceSettingsResolver(tc.ctx)
			if err != nil || !got.ModuleEnabled || s.calls != 1 {
				t.Fatalf("got %+v, %v, calls %d", got, err, s.calls)
			}
		})
	}
}

func TestComplianceSettings_RefusesEveryoneElseBeforeCallingReporting(t *testing.T) {
	s := &fakeComplianceSettings{enabled: true}
	r, _ := moduleResolver(nil, s)
	if _, err := r.ComplianceSettingsResolver(ctxWithUser(t, "u-plain")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("plain user: want PermissionDenied, got %v", err)
	}
	if _, err := r.ComplianceSettingsResolver(context.Background()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("signed out: want Unauthenticated, got %v", err)
	}
	if s.calls != 0 {
		t.Fatalf("reporting was called %d times for a refused caller", s.calls)
	}
}

func TestComplianceSettings_UnavailableWithoutAClient(t *testing.T) {
	r, _ := moduleResolver(nil, nil)
	if _, err := r.ComplianceSettingsResolver(ctxRoot(t, "u-root")); status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
}

func TestSetComplianceModule_ComplianceManagersAndRootMaySwitchIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{"compliance admin", ctxWithRoles(t, "u-co", []string{"compliance-admin"})},
		{"root", ctxRoot(t, "u-root")},
	} {
		for _, enabled := range []bool{false, true} {
			t.Run(tc.name, func(t *testing.T) {
				m := &fakeModule{}
				r, _ := moduleResolver(m, nil)
				got, err := r.SetComplianceModuleResolver(tc.ctx, enabled)
				if err != nil || got.ModuleEnabled != enabled || m.lastSet.GetEnabled() != enabled {
					t.Fatalf("got %+v, %v, sent %+v", got, err, m.lastSet)
				}
			})
		}
	}
}

func TestSetComplianceModule_RefusesOthersWithoutCallingReporting(t *testing.T) {
	m := &fakeModule{}
	r, _ := moduleResolver(m, nil)
	if _, err := r.SetComplianceModuleResolver(ctxWithUser(t, "u-plain"), false); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("plain user: want PermissionDenied, got %v", err)
	}
	if _, err := r.SetComplianceModuleResolver(ctxWithRoles(t, "u-au", []string{"author"}), false); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("author: want PermissionDenied, got %v", err)
	}
	if _, err := r.SetComplianceModuleResolver(context.Background(), false); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("signed out: want Unauthenticated, got %v", err)
	}
	if m.calls != 0 {
		t.Fatalf("reporting was called %d times for refused callers", m.calls)
	}
}

func TestSetComplianceModule_RelaysReportingsRefusalAndLogsTheChange(t *testing.T) {
	refusal := backendCodedErr(codes.PermissionDenied, 8118, "HARD_RESET_ROOT_REQUIRED", "reporting", nil)
	m := &fakeModule{setErr: refusal}
	r, buf := moduleResolver(m, nil)
	_, err := r.SetComplianceModuleResolver(ctxRoot(t, "u-root"), false)
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "8118") && !strings.Contains(err.Error(), "HARD_RESET_ROOT_REQUIRED") {
		t.Fatalf("want reporting's refusal relayed, got %v", err)
	}
	if !strings.Contains(buf.String(), "compliance module") {
		t.Fatalf("expected a log line about the module switch, got %q", buf.String())
	}
}

func TestExecuteHardReset_RootOnlyAndPassesTheRequestThrough(t *testing.T) {
	m := &fakeModule{}
	r, buf := moduleResolver(m, nil)
	got, err := r.ExecuteHardResetResolver(ctxRoot(t, "u-root"), "hr-1", "RESET COMPLIANCE DATA")
	if err != nil {
		t.Fatalf("ExecuteHardResetResolver: %v", err)
	}
	if got.CasesDeleted != 12 || got.RequestedBy != "u-root" || got.ApprovedBy != "u-second" {
		t.Fatalf("result = %+v", got)
	}
	if m.lastReset.GetRequestId() != "hr-1" || m.lastReset.GetConfirmation() != "RESET COMPLIANCE DATA" {
		t.Fatalf("sent %+v", m.lastReset)
	}
	if strings.Contains(buf.String(), "RESET COMPLIANCE DATA") {
		t.Fatalf("the confirmation phrase must not be logged: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "hr-1") {
		t.Fatalf("expected the request id in the log: %s", buf.String())
	}
}

func TestExecuteHardReset_RefusesNonRootBeforeCallingReporting(t *testing.T) {
	m := &fakeModule{}
	r, _ := moduleResolver(m, nil)
	for name, ctx := range map[string]context.Context{
		"site admin":       ctxSiteAdmin(t, "u-sa"),
		"compliance admin": ctxWithRoles(t, "u-co", []string{"compliance-admin"}),
		"plain":            ctxWithUser(t, "u-plain"),
	} {
		if _, err := r.ExecuteHardResetResolver(ctx, "hr-1", "RESET COMPLIANCE DATA"); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: want PermissionDenied, got %v", name, err)
		}
	}
	if _, err := r.ExecuteHardResetResolver(context.Background(), "hr-1", "x"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("signed out: want Unauthenticated, got %v", err)
	}
	if m.calls != 0 {
		t.Fatalf("reporting was called %d times for refused callers", m.calls)
	}
}

func TestExecuteHardReset_RelaysEachHardResetRefusalUnchanged(t *testing.T) {
	for _, tc := range []struct {
		code   codes.Code
		num    int
		symbol string
	}{
		{codes.InvalidArgument, 8114, "HARD_RESET_CONFIRMATION"},
		{codes.FailedPrecondition, 8115, "HARD_RESET_MODULE_ON"},
		{codes.FailedPrecondition, 8116, "HARD_RESET_LEGAL_HOLD"},
		{codes.FailedPrecondition, 8117, "HARD_RESET_NOT_APPROVED"},
		{codes.PermissionDenied, 8118, "HARD_RESET_ROOT_REQUIRED"},
	} {
		t.Run(tc.symbol, func(t *testing.T) {
			refusal := backendCodedErr(tc.code, tc.num, tc.symbol, "reporting", nil)
			r, _ := moduleResolver(&fakeModule{resetErr: refusal}, nil)
			_, err := r.ExecuteHardResetResolver(ctxRoot(t, "u-root"), "hr-1", "RESET COMPLIANCE DATA")
			if err != refusal && status.Code(err) != tc.code {
				t.Fatalf("want %v relayed, got %v", tc.code, err)
			}
		})
	}
}

func TestExecuteHardReset_UnavailableWithoutAClient(t *testing.T) {
	r, _ := moduleResolver(nil, nil)
	if _, err := r.ExecuteHardResetResolver(ctxRoot(t, "u-root"), "hr-1", "x"); status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
}

// The identity half: the gateway gates first (request needs root, the rest a
// site admin) and identity still decides who may do what.

func hardResetAdmin() *fakeAdminClient {
	req := &identityv1.HardResetRequest{Id: "hr-1", Module: "compliance", State: identityv1.HardResetState_HARD_RESET_STATE_PENDING}
	return &fakeAdminClient{
		requestHardResetResp: &identityv1.RequestHardResetResponse{Request: req},
		approveHardResetResp: &identityv1.ApproveHardResetResponse{Request: req},
		cancelHardResetResp:  &identityv1.CancelHardResetResponse{Request: req},
		listHardResetResp:    &identityv1.ListHardResetRequestsResponse{Requests: []*identityv1.HardResetRequest{req}},
	}
}

func TestHardResetIdentityActions_GatedByGatewayRole(t *testing.T) {
	type action func(ctx context.Context, admin *fakeAdminClient) error
	lg := golog.Nop()
	actions := map[string]struct {
		run     action
		allowed map[string]bool // caller kind -> allowed
	}{
		"request": {func(ctx context.Context, a *fakeAdminClient) error {
			_, err := resolvers.RequestHardResetResolver(ctx, lg, a, "compliance", "private reason")
			return err
		}, map[string]bool{"root": true}},
		"approve": {func(ctx context.Context, a *fakeAdminClient) error {
			_, err := resolvers.ApproveHardResetResolver(ctx, lg, a, "hr-1")
			return err
		}, map[string]bool{"root": true, "site admin": true}},
		"cancel": {func(ctx context.Context, a *fakeAdminClient) error {
			_, err := resolvers.CancelHardResetResolver(ctx, lg, a, "hr-1")
			return err
		}, map[string]bool{"root": true, "site admin": true}},
		"list": {func(ctx context.Context, a *fakeAdminClient) error {
			m := "compliance"
			_, err := resolvers.HardResetRequestsResolver(ctx, lg, a, &m)
			return err
		}, map[string]bool{"root": true, "site admin": true}},
	}
	callers := map[string]context.Context{
		"root":             ctxRoot(t, "u-root"),
		"site admin":       ctxSiteAdmin(t, "u-sa"),
		"compliance admin": ctxWithRoles(t, "u-co", []string{"compliance-admin"}),
		"plain":            ctxWithUser(t, "u-plain"),
	}
	for name, act := range actions {
		for kind, ctx := range callers {
			t.Run(name+"/"+kind, func(t *testing.T) {
				admin := hardResetAdmin()
				err := act.run(ctx, admin)
				if act.allowed[kind] {
					if err != nil {
						t.Fatalf("want allowed, got %v", err)
					}
					return
				}
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("want PermissionDenied, got %v", err)
				}
				if admin.hardResetCalls != 0 {
					t.Fatalf("identity was called for a refused caller")
				}
			})
		}
		t.Run(name+"/signed out", func(t *testing.T) {
			if err := act.run(context.Background(), hardResetAdmin()); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("want Unauthenticated, got %v", err)
			}
		})
	}
}

func TestHardResetRequest_DoesNotLogTheReason(t *testing.T) {
	var buf bytes.Buffer
	lg := golog.NewLoggerWithOptions("gateway-test", golog.WithOutput(&buf), golog.WithDefaultFormat(golog.FormatJSON), golog.WithDefaultLevel(golog.LevelTrace))
	if _, err := resolvers.RequestHardResetResolver(ctxRoot(t, "u-root"), lg, hardResetAdmin(), "compliance", "confidential-reason-text"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "confidential-reason-text") {
		t.Fatalf("the reason must not be logged: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "compliance") {
		t.Fatalf("expected the module in the log: %s", buf.String())
	}
}
