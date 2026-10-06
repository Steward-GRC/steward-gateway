// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	apperr "github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	log "github.com/Bugs5382/go-log"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

func present(ctx context.Context, e error) *gqlerror.Error {
	return ErrorPresenter(log.Nop())(ctx, e)
}

// relayedStatus is what a backend sends for a coded refusal: the gRPC code,
// its rendered message and an ErrorInfo (symbol, domain, metadata, codeNum),
// as apperrgrpc builds it.
func relayedStatus(t *testing.T, c codes.Code, num int, symbol, domain, message string, md map[string]string) error {
	t.Helper()
	meta := map[string]string{apperrgrpc.MetaCodeNum: strconv.Itoa(num)}
	for k, v := range md {
		meta[k] = v
	}
	st, err := status.New(c, message).WithDetails(&errdetails.ErrorInfo{Reason: symbol, Domain: domain, Metadata: meta})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

// TestSanitizingErrorPresenter locks the client-visible output. Resolvers wrap
// backend errors, so the presenter must use the innermost status's own message,
// never the wrapped chain with its envelope and raw detail.
func TestSanitizingErrorPresenter(t *testing.T) {
	validationErr := &gqlerror.Error{Message: "Field \"foo\" is not defined."}

	cases := []struct {
		name           string
		in             error
		wantMessage    string
		wantCode       string
		wantKind       string
		mustNotContain []string
	}{
		{
			name:           "wrapped client-facing NotFound",
			in:             fmt.Errorf("obligations my ack summary: %w", status.Error(codes.NotFound, "policy not found")),
			wantMessage:    "policy not found",
			wantCode:       "NotFound",
			wantKind:       "business",
			mustNotContain: []string{"rpc error", "desc =", "obligations my ack summary", "code ="},
		},
		{
			name:           "client-facing FailedPrecondition rename-pending message",
			in:             status.Error(codes.FailedPrecondition, "A change is pending approval. Resolve or withdraw that draft before renaming."),
			wantMessage:    "A change is pending approval. Resolve or withdraw that draft before renaming.",
			wantCode:       "FailedPrecondition",
			wantKind:       "business",
			mustNotContain: []string{"rpc error", "desc =", "code ="},
		},
		{
			name:           "wrapped server-fault Internal with DB detail",
			in:             fmt.Errorf("x: %w", status.Error(codes.Internal, "pq: duplicate key value violates unique constraint \"policies_pkey\"")),
			wantMessage:    ServerFaultMessage,
			wantCode:       "INTERNAL",
			wantKind:       "reach",
			mustNotContain: []string{"pq:", "duplicate key", "constraint", "policies_pkey", "rpc error"},
		},
		{
			name:           "plain non-gRPC Go error",
			in:             errors.New("dial tcp 192.0.2.5:5432: connect: connection refused"),
			wantMessage:    ServerFaultMessage,
			wantCode:       "INTERNAL",
			wantKind:       "reach",
			mustNotContain: []string{"dial tcp", "connection refused", "192.0.2.5"},
		},
		{
			name:           "apperr-coded internal error relays its own code",
			in:             apperr.Coded(1998, errors.New("pq: duplicate key value violates unique constraint \"policies_pkey\"")),
			wantMessage:    ServerFaultMessage,
			wantCode:       "INTERNAL",
			wantKind:       "reach",
			mustNotContain: []string{"pq:", "duplicate key", "constraint", "policies_pkey"},
		},
		{
			name:           "wrapped apperr-coded internal error relays its own code",
			in:             fmt.Errorf("resolver: %w", apperr.Coded(1999, errors.New("boom"))),
			wantMessage:    ServerFaultMessage,
			wantCode:       "INTERNAL",
			wantKind:       "reach",
			mustNotContain: []string{"boom", "resolver"},
		},
		{
			name:        "pre-resolver gqlerror validation error",
			in:          validationErr,
			wantMessage: "Field \"foo\" is not defined.",
			wantCode:    "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := present(context.Background(), tc.in)
			if got == nil {
				t.Fatal("presenter returned nil")
			}
			if got.Message != tc.wantMessage {
				t.Fatalf("message = %q, want %q", got.Message, tc.wantMessage)
			}
			gotCode, _ := got.Extensions["code"].(string)
			if gotCode != tc.wantCode {
				t.Fatalf("extensions code = %q, want %q", gotCode, tc.wantCode)
			}
			gotKind, _ := got.Extensions["kind"].(string)
			if gotKind != tc.wantKind {
				t.Fatalf("extensions kind = %q, want %q", gotKind, tc.wantKind)
			}
			for _, sub := range tc.mustNotContain {
				if strings.Contains(got.Message, sub) {
					t.Fatalf("client message %q leaked forbidden substring %q", got.Message, sub)
				}
			}
		})
	}
}

func spanCtx(t *testing.T) (context.Context, trace.TraceID) {
	t.Helper()
	traceID, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	spanID, _ := trace.SpanIDFromHex("0102030405060708")
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled})
	return trace.ContextWithSpanContext(context.Background(), sc), traceID
}

// The structured line for a coded internal error carries the code and the
// trace id, so the Reference a user reports leads straight to it.
func TestSanitizingErrorPresenterLogsCodeAndTraceID(t *testing.T) {
	ctx, traceID := spanCtx(t)
	var buf bytes.Buffer
	lg := log.NewLoggerWithOptions("gateway", log.WithOutput(&buf), log.WithDefaultFormat(log.FormatJSON))

	got := ErrorPresenter(lg)(ctx, apperr.Coded(1998, errors.New("boom")))

	if got.Message != ServerFaultMessage {
		t.Fatalf("message = %q, want the generic %q", got.Message, ServerFaultMessage)
	}
	if got.Extensions["codeNum"] != 1998 {
		t.Fatalf("extensions codeNum = %v, want 1998", got.Extensions["codeNum"])
	}
	out := buf.String()
	if !strings.Contains(out, `"code":1998`) {
		t.Fatalf("expected log line to carry code=1998, got %q", out)
	}
	if !strings.Contains(out, `"trace_id":"`+traceID.String()+`"`) {
		t.Fatalf("expected log line to carry the trace id, got %q", out)
	}
}

// The error text is logged for the operator, but never a client address.
func TestSanitizingErrorPresenterLogsNoAddress(t *testing.T) {
	var buf bytes.Buffer
	lg := log.NewLoggerWithOptions("gateway", log.WithOutput(&buf), log.WithDefaultFormat(log.FormatJSON))

	_ = ErrorPresenter(lg)(context.Background(), errors.New("dial tcp 198.51.100.7:4433 and [2001:db8::7]:443: connection refused"))

	out := buf.String()
	if strings.Contains(out, "198.51.100.7") || strings.Contains(out, "2001:db8::7") {
		t.Fatalf("log line carries an address: %q", out)
	}
	if !strings.Contains(out, "connection refused") {
		t.Fatalf("log line lost the error text: %q", out)
	}
}

// A spent AI quota (ResourceExhausted with an ErrorInfo) relays the
// originating code, its user-safe message and its metadata.
func TestSanitizingErrorPresenter_aiQuotaExceeded(t *testing.T) {
	st := relayedStatus(t, codes.ResourceExhausted, 3001, "AI_QUOTA_EXCEEDED", "ai",
		"You've reached your daily AI limit of 50. It resets at 2026-08-25T00:00:00Z.",
		map[string]string{"limit": "50", "used": "51", "reset_at": "2026-08-25T00:00:00Z"})
	in := fmt.Errorf("ai search and answer: %w", st)

	got := present(context.Background(), in)
	wantMsg := "You've reached your daily AI limit of 50. It resets at 2026-08-25T00:00:00Z."
	if got.Message != wantMsg {
		t.Fatalf("message = %q, want %q", got.Message, wantMsg)
	}
	if got.Extensions["code"] != "AI_QUOTA_EXCEEDED" {
		t.Fatalf("extensions code = %v, want AI_QUOTA_EXCEEDED", got.Extensions["code"])
	}
	if got.Extensions["codeNum"] != 3001 {
		t.Fatalf("extensions codeNum = %v, want 3001", got.Extensions["codeNum"])
	}
	if got.Extensions["domain"] != "ai" {
		t.Fatalf("extensions domain = %v, want ai", got.Extensions["domain"])
	}
	if got.Extensions["limit"] != "50" {
		t.Fatalf("extensions limit = %v, want \"50\"", got.Extensions["limit"])
	}
	if got.Extensions["kind"] != "business" {
		t.Fatalf("extensions kind = %v, want business", got.Extensions["kind"])
	}
	if got.Extensions["reset_at"] != "2026-08-25T00:00:00Z" {
		t.Fatalf("extensions reset_at = %v", got.Extensions["reset_at"])
	}
	if _, leaked := got.Extensions[apperrgrpc.MetaCodeNum].(string); leaked {
		t.Fatalf("extensions %q leaked as a raw metadata string", apperrgrpc.MetaCodeNum)
	}
}

// A backend's coded business refusal, built the way the backends build it
// (apperrgrpc over their registry), is relayed with the originating code,
// domain, metadata and message; the gateway never re-codes it.
func TestSanitizingErrorPresenter_relaysOriginatingBusinessCode(t *testing.T) {
	reg, err := apperr.NewRegistry([]apperr.Entry{{
		Code: 4001, Symbol: "POLICY_ACCESS_DENIED", Category: apperr.CategoryPermissionDenied,
		Title: "authz", Cause: "no access", UserSafe: true, Message: "You don't have access to category {category}.",
	}}, apperr.WithService(4))
	if err != nil {
		t.Fatal(err)
	}
	st := apperrgrpc.Error(context.Background(), reg, apperr.WithMeta(apperr.Coded(4001, nil), apperr.Meta("category", "Finance")), 4000, "core")
	in := fmt.Errorf("core rename policy: %w", st)

	got := present(context.Background(), in)
	if got.Message != "You don't have access to category Finance." {
		t.Fatalf("message = %q, want the relayed user-safe message", got.Message)
	}
	if got.Extensions["code"] != "POLICY_ACCESS_DENIED" {
		t.Fatalf("extensions code = %v, want the originating symbol", got.Extensions["code"])
	}
	if got.Extensions["codeNum"] != 4001 {
		t.Fatalf("extensions codeNum = %v, want 4001", got.Extensions["codeNum"])
	}
	if got.Extensions["domain"] != "core" {
		t.Fatalf("extensions domain = %v, want core", got.Extensions["domain"])
	}
	if got.Extensions["category"] != "Finance" {
		t.Fatalf("extensions category = %v, want Finance", got.Extensions["category"])
	}
	if got.Extensions["kind"] != "business" {
		t.Fatalf("extensions kind = %v, want business", got.Extensions["kind"])
	}
}

// A declared internal fault keeps its originating number but gets the generic
// message and kind reach.
func TestSanitizingErrorPresenter_serverFaultWithInfoRelaysCodeNum(t *testing.T) {
	in := fmt.Errorf("identity create org: %w", relayedStatus(t, codes.Internal, 5001, "IDP_ADMIN_UNREACHABLE", "identity", "Code 5001: Internal Error", nil))

	got := present(context.Background(), in)
	if got.Message != ServerFaultMessage {
		t.Fatalf("message = %q, want the generic message", got.Message)
	}
	if got.Extensions["kind"] != "reach" {
		t.Fatalf("extensions kind = %v, want reach", got.Extensions["kind"])
	}
	if got.Extensions["code"] != "INTERNAL" {
		t.Fatalf("extensions code = %v, want INTERNAL", got.Extensions["code"])
	}
	if got.Extensions["codeNum"] != 5001 {
		t.Fatalf("extensions codeNum = %v, want 5001", got.Extensions["codeNum"])
	}
}

// A ResourceExhausted without an ErrorInfo is a fault, not a quota.
func TestSanitizingErrorPresenter_unrelatedResourceExhausted(t *testing.T) {
	got := present(context.Background(), fmt.Errorf("x: %w", status.Error(codes.ResourceExhausted, "some backend backpressure")))
	if got.Extensions["code"] != "INTERNAL" {
		t.Fatalf("extensions code = %v, want INTERNAL", got.Extensions["code"])
	}
	if got.Extensions["codeNum"] != 1000 {
		t.Fatalf("extensions codeNum = %v, want 1000", got.Extensions["codeNum"])
	}
	if strings.Contains(got.Message, "backpressure") {
		t.Fatalf("client message leaked backend detail: %q", got.Message)
	}
}

// An admin password reset that fails on the identity provider shows plain
// copy, the reference number and a retry, and leaks nothing.
func TestSanitizingErrorPresenter_adminResetPasswordFault(t *testing.T) {
	in := fmt.Errorf("reset user password: %w",
		apperr.Coded(errcodes.CodeKratosAdminSetPasswordFailed, status.Error(codes.Internal, "PATCH admin/identities/9f3: 502 Bad Gateway from kratos-admin.steward.svc")))

	got := present(context.Background(), in)
	if got.Message != ServerFaultMessage {
		t.Fatalf("message = %q, want %q", got.Message, ServerFaultMessage)
	}
	if strings.HasPrefix(got.Message, "Code ") {
		t.Fatalf("message %q is a bare code", got.Message)
	}
	if got.Extensions["code"] != "INTERNAL" {
		t.Fatalf("extensions code = %v, want INTERNAL", got.Extensions["code"])
	}
	if got.Extensions["codeNum"] != 1227 {
		t.Fatalf("extensions codeNum = %v, want 1227", got.Extensions["codeNum"])
	}
	if got.Extensions["kind"] != "reach" {
		t.Fatalf("extensions kind = %v, want reach", got.Extensions["kind"])
	}
	for _, leak := range []string{"kratos", "admin/identities", "502", "svc"} {
		if strings.Contains(strings.ToLower(got.Message), strings.ToLower(leak)) {
			t.Fatalf("client message %q leaked %q", got.Message, leak)
		}
	}
}

func TestSanitizingErrorPresenter_kratosUnreachable(t *testing.T) {
	in := fmt.Errorf("bff login: %w",
		apperr.Coded(errcodes.CodeKratosUnreachable, errors.New("Post \"https://kratos-public/self-service/login\": dial tcp 192.0.2.9:4433: connect: connection refused")))

	got := present(context.Background(), in)
	if got.Message != ServerFaultMessage {
		t.Fatalf("message = %q, want the generic reach copy", got.Message)
	}
	if got.Extensions["codeNum"] != 1212 {
		t.Fatalf("extensions codeNum = %v, want 1212", got.Extensions["codeNum"])
	}
	if got.Extensions["kind"] != "reach" {
		t.Fatalf("extensions kind = %v, want reach", got.Extensions["kind"])
	}
	for _, leak := range []string{"dial tcp", "connection refused", "192.0.2.9", "kratos"} {
		if strings.Contains(got.Message, leak) {
			t.Fatalf("client message %q leaked %q", got.Message, leak)
		}
	}
}

// The wire kind for a relayed code is the authoritative errcodes.KindOfGRPC
// answer; the presenter invents none of its own.
func TestSanitizingErrorPresenter_kindMatchesTheRegistry(t *testing.T) {
	for _, tc := range []struct {
		name string
		code codes.Code
	}{
		{"authz denial", codes.PermissionDenied},
		{"validation", codes.InvalidArgument},
		{"not found", codes.NotFound},
		{"conflict", codes.AlreadyExists},
		{"precondition", codes.FailedPrecondition},
		{"quota", codes.ResourceExhausted},
		{"server fault", codes.Internal},
		{"dependency down", codes.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := fmt.Errorf("resolver: %w", relayedStatus(t, tc.code, 4900, "TEST_RELAYED", "core", "A relayed outcome.", nil))
			got := present(context.Background(), in)
			want := string(errcodes.KindOfGRPC(tc.code))
			if got.Extensions["kind"] != want {
				t.Fatalf("extensions kind = %v, want %q", got.Extensions["kind"], want)
			}
		})
	}
}

// No genericised fault ever shows a bare code as its message.
func TestSanitizingErrorPresenter_neverEmitsABareCodeAsTheMessage(t *testing.T) {
	faults := []error{
		errors.New("boom"),
		status.Error(codes.Internal, "pq: deadlock detected"),
		status.Error(codes.Unavailable, "no healthy upstream"),
		status.Error(codes.DataLoss, "truncated read"),
		apperr.Coded(1000, errors.New("unclassified")),
		apperr.Coded(1227, errors.New("identity provider admin patch failed")),
		fmt.Errorf("wrapped: %w", relayedStatus(t, codes.Internal, 5001, "IDP_ADMIN_UNREACHABLE", "identity", "Code 5001: Internal Error", nil)),
	}
	for _, in := range faults {
		got := present(context.Background(), in)
		if got.Message != ServerFaultMessage {
			t.Errorf("for %v: message = %q, want the generic message", in, got.Message)
		}
		if strings.Contains(got.Message, "Internal Error") || strings.HasPrefix(got.Message, "Code ") {
			t.Errorf("for %v: message %q reintroduces the internal phrasing", in, got.Message)
		}
		if got.Extensions["kind"] != "reach" {
			t.Errorf("for %v: kind = %v, want reach", in, got.Extensions["kind"])
		}
		if _, ok := got.Extensions["codeNum"].(int); !ok {
			t.Errorf("for %v: extensions carries no numeric codeNum", in)
		}
	}
}

// A recovered panic has the same client contract as any other fault.
func TestRecoverAndSanitize_isReachWithAReference(t *testing.T) {
	err := RecoverFunc(log.Nop())(context.Background(), "nil map write")
	got, ok := errors.AsType[*gqlerror.Error](err)
	if !ok {
		t.Fatalf("RecoverFunc returned %T, want *gqlerror.Error", err)
	}
	if got.Message != ServerFaultMessage {
		t.Fatalf("message = %q, want %q", got.Message, ServerFaultMessage)
	}
	if strings.Contains(got.Message, "nil map write") {
		t.Fatalf("client message %q leaked the panic value", got.Message)
	}
	if got.Extensions["code"] != "INTERNAL" {
		t.Fatalf("extensions code = %v, want INTERNAL", got.Extensions["code"])
	}
	if got.Extensions["codeNum"] != errcodes.CodeInternal {
		t.Fatalf("extensions codeNum = %v, want %d", got.Extensions["codeNum"], errcodes.CodeInternal)
	}
	if got.Extensions["kind"] != "reach" {
		t.Fatalf("extensions kind = %v, want reach", got.Extensions["kind"])
	}
	presented := present(context.Background(), got)
	if presented.Extensions["kind"] != "reach" || presented.Message != ServerFaultMessage {
		t.Fatalf("presenter altered the recovered panic error: %+v", presented)
	}
}

// A gateway code the registry marks user-safe carries copy written for the
// user; the presenter relays it, kind reach so a retry is offered.
func TestSanitizingErrorPresenter_gatewayUserSafeReachRelaysItsMessage(t *testing.T) {
	in := fmt.Errorf("publish: %w", errcodes.New(errcodes.CodeCollabFlushUnavailable))
	entry, _ := errcodes.Registry().Describe(errcodes.CodeCollabFlushUnavailable)

	got := present(context.Background(), in)
	if got.Message != entry.Message {
		t.Fatalf("message = %q, want the registry copy %q", got.Message, entry.Message)
	}
	if got.Extensions["code"] != "COLLAB_FLUSH_UNAVAILABLE" {
		t.Errorf("extensions code = %v, want COLLAB_FLUSH_UNAVAILABLE", got.Extensions["code"])
	}
	if got.Extensions["codeNum"] != 1242 {
		t.Errorf("extensions codeNum = %v, want 1242", got.Extensions["codeNum"])
	}
	if got.Extensions["domain"] != "gateway" {
		t.Errorf("extensions domain = %v, want gateway", got.Extensions["domain"])
	}
	if got.Extensions["kind"] != "reach" {
		t.Errorf("extensions kind = %v, want reach", got.Extensions["kind"])
	}
}

// A gateway business code fills its message from its metadata and relays the
// metadata.
func TestSanitizingErrorPresenter_gatewayBusinessCodeFillsItsMessage(t *testing.T) {
	got := present(context.Background(), errcodes.New(errcodes.CodeCollabFlushRejected, "reason", "stale"))
	if got.Message != "The latest edits couldn't be saved, so the policy was not published: stale" {
		t.Fatalf("message = %q", got.Message)
	}
	if got.Extensions["code"] != "COLLAB_FLUSH_REJECTED" || got.Extensions["kind"] != "business" || got.Extensions["reason"] != "stale" {
		t.Fatalf("extensions = %v", got.Extensions)
	}
}

// Another service's reach message is generic whatever it claims: the gateway
// has no registry entry to vouch for it.
func TestSanitizingErrorPresenter_foreignUserSafeReachStaysGeneric(t *testing.T) {
	in := fmt.Errorf("x: %w", relayedStatus(t, codes.Unavailable, 5001, "IDP_ADMIN_UNREACHABLE", "identity", "The identity provider is temporarily unavailable.", nil))

	got := present(context.Background(), in)
	if got.Message != ServerFaultMessage {
		t.Fatalf("message = %q, want the generic message", got.Message)
	}
	if got.Extensions["codeNum"] != 5001 {
		t.Errorf("extensions codeNum = %v, want 5001", got.Extensions["codeNum"])
	}
}

// A backend's metadata can't overwrite the presenter's own extensions.
func TestSanitizingErrorPresenter_metadataCantOverrideReservedKeys(t *testing.T) {
	ctx := WithRequestID(context.Background(), "req-1")
	in := relayedStatus(t, codes.NotFound, 4002, "POLICY_NOT_FOUND", "core", "That policy doesn't exist.",
		map[string]string{"kind": "reach", "domain": "gateway", "requestId": "forged", "traceId": "forged", "code": "X"})

	got := present(ctx, in)
	if got.Extensions["kind"] != "business" || got.Extensions["domain"] != "core" || got.Extensions["code"] != "POLICY_NOT_FOUND" {
		t.Fatalf("metadata overrode a reserved key: %v", got.Extensions)
	}
	if got.Extensions["requestId"] != "req-1" {
		t.Fatalf("requestId = %v, want req-1", got.Extensions["requestId"])
	}
}

// Every error, validation errors included, carries the request and trace ids.
func TestEveryErrorCarriesRequestAndTraceIDs(t *testing.T) {
	ctx, traceID := spanCtx(t)
	ctx = WithRequestID(ctx, "req-42")
	for _, in := range []error{
		&gqlerror.Error{Message: "Field \"foo\" is not defined."},
		status.Error(codes.NotFound, "policy not found"),
		errors.New("boom"),
		errcodes.New(errcodes.CodeImpersonationDenied),
	} {
		got := present(ctx, in)
		if got.Extensions["requestId"] != "req-42" {
			t.Errorf("for %v: requestId = %v", in, got.Extensions["requestId"])
		}
		if got.Extensions["traceId"] != traceID.String() {
			t.Errorf("for %v: traceId = %v", in, got.Extensions["traceId"])
		}
	}
}

// workflow's coded swap and pool refusals reach GraphQL in the relayed shape
// (code = symbol, codeNum, domain workflow, metadata keys as extensions), so
// the reassign picker can mark the refused candidate.
func TestWorkflowRefusalsRelayWorkflowCodes(t *testing.T) {
	cases := []struct {
		code    codes.Code
		num     int
		symbol  string
		md      map[string]string
		message string
	}{
		{codes.InvalidArgument, 6004, "SWAP_REASON_REQUIRED", nil, "Give a reason for the reassignment."},
		{codes.InvalidArgument, 6005, "SWAP_USERS_REQUIRED", nil, "Choose both the current approver and the person to reassign to."},
		{codes.InvalidArgument, 6006, "SWAP_SAME_USER", nil, "That person already holds this approval. Choose someone else."},
		{codes.InvalidArgument, 6007, "SWAP_INITIATOR_ROLE_REQUIRED", nil, "The reassignment request didn't say which role it was made under."},
		{codes.NotFound, 6008, "SWAP_ASSIGNMENT_NOT_FOUND", map[string]string{"stage": "1", "current_user_id": "u-1"},
			"The person you're replacing isn't assigned to stage 1 any more. Refresh and try again."},
		{codes.FailedPrecondition, 6009, "SWAP_ASSIGNMENT_NOT_PENDING", map[string]string{"stage": "1", "current_user_id": "u-1", "state": "approved"},
			"This approval is already approved, so it can't be reassigned."},
		{codes.FailedPrecondition, 6010, "SWAP_ASSIGNEE_NOT_ELIGIBLE", map[string]string{"stage": "1", "stage_name": "Legal review", "new_user_id": "u-9"},
			"That person isn't an eligible approver for stage 1 (Legal review)."},
		{codes.InvalidArgument, 6011, "STAGE_INDEX_OUT_OF_RANGE", map[string]string{"stage": "4", "stage_count": "2"},
			"Stage 4 isn't part of this workflow. Refresh and try again."},
		{codes.NotFound, 6012, "APPROVAL_RUN_NOT_FOUND", map[string]string{"policy_version_id": "pv-1"},
			"This policy version has no approval run. Refresh and try again."},
	}
	for _, tc := range cases {
		t.Run(tc.symbol, func(t *testing.T) {
			in := fmt.Errorf("workflow swap assignee: %w", relayedStatus(t, tc.code, tc.num, tc.symbol, "workflow", tc.message, tc.md))
			got := present(context.Background(), in)
			if got.Message != tc.message {
				t.Errorf("message = %q, want %q", got.Message, tc.message)
			}
			if got.Extensions["code"] != tc.symbol {
				t.Errorf("extensions code = %v, want %s", got.Extensions["code"], tc.symbol)
			}
			if got.Extensions["codeNum"] != tc.num {
				t.Errorf("extensions codeNum = %v, want %d", got.Extensions["codeNum"], tc.num)
			}
			if got.Extensions["domain"] != "workflow" {
				t.Errorf("extensions domain = %v, want workflow", got.Extensions["domain"])
			}
			if got.Extensions["kind"] != "business" {
				t.Errorf("extensions kind = %v, want business", got.Extensions["kind"])
			}
			for k, v := range tc.md {
				if got.Extensions[k] != v {
					t.Errorf("extensions %s = %v, want %q", k, got.Extensions[k], v)
				}
			}
		})
	}
}
