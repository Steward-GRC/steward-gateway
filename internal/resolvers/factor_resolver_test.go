// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"strings"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeFactorClient struct {
	fakeReadClient

	listFactorsResp    *identityv1.ListUserFactorsResponse
	listFactorsErr     error
	lastListFactorsReq *identityv1.ListUserFactorsRequest

	totpBeginResp    *identityv1.EnrollTotpBeginResponse
	totpBeginErr     error
	lastTotpBeginReq *identityv1.EnrollTotpBeginRequest

	totpConfirmErr     error
	lastTotpConfirmReq *identityv1.EnrollTotpConfirmRequest

	sendOtpErr     error
	lastSendOtpReq *identityv1.SendEmailOtpRequest

	verifyOtpResp    *identityv1.VerifyEmailOtpResponse
	verifyOtpErr     error
	lastVerifyOtpReq *identityv1.VerifyEmailOtpRequest

	removeFactorErr     error
	lastRemoveFactorReq *identityv1.RemoveFactorRequest

	regBeginResp    *identityv1.WebauthnRegisterBeginResponse
	regBeginErr     error
	lastRegBeginReq *identityv1.WebauthnRegisterBeginRequest

	regFinishErr     error
	lastRegFinishReq *identityv1.WebauthnRegisterFinishRequest

	listCredsResp    *identityv1.ListWebauthnCredentialsResponse
	listCredsErr     error
	lastListCredsReq *identityv1.ListWebauthnCredentialsRequest

	removeCredErr     error
	lastRemoveCredReq *identityv1.RemoveWebauthnCredentialRequest

	renameErr     error
	lastRenameReq *identityv1.RenameMFAMethodRequest
}

func (f *fakeFactorClient) RenameMFAMethod(_ context.Context, in *identityv1.RenameMFAMethodRequest, _ ...grpc.CallOption) (*identityv1.RenameMFAMethodResponse, error) {
	f.lastRenameReq = in
	if f.renameErr != nil {
		return nil, f.renameErr
	}
	return &identityv1.RenameMFAMethodResponse{}, nil
}

func (f *fakeFactorClient) ListUserFactors(_ context.Context, in *identityv1.ListUserFactorsRequest, _ ...grpc.CallOption) (*identityv1.ListUserFactorsResponse, error) {
	f.lastListFactorsReq = in
	if f.listFactorsErr != nil {
		return nil, f.listFactorsErr
	}
	return f.listFactorsResp, nil
}

func (f *fakeFactorClient) EnrollTotpBegin(_ context.Context, in *identityv1.EnrollTotpBeginRequest, _ ...grpc.CallOption) (*identityv1.EnrollTotpBeginResponse, error) {
	f.lastTotpBeginReq = in
	if f.totpBeginErr != nil {
		return nil, f.totpBeginErr
	}
	return f.totpBeginResp, nil
}

func (f *fakeFactorClient) EnrollTotpConfirm(_ context.Context, in *identityv1.EnrollTotpConfirmRequest, _ ...grpc.CallOption) (*identityv1.EnrollTotpConfirmResponse, error) {
	f.lastTotpConfirmReq = in
	if f.totpConfirmErr != nil {
		return nil, f.totpConfirmErr
	}
	return &identityv1.EnrollTotpConfirmResponse{}, nil
}

func (f *fakeFactorClient) SendEmailOtp(_ context.Context, in *identityv1.SendEmailOtpRequest, _ ...grpc.CallOption) (*identityv1.SendEmailOtpResponse, error) {
	f.lastSendOtpReq = in
	if f.sendOtpErr != nil {
		return nil, f.sendOtpErr
	}
	return &identityv1.SendEmailOtpResponse{}, nil
}

func (f *fakeFactorClient) VerifyEmailOtp(_ context.Context, in *identityv1.VerifyEmailOtpRequest, _ ...grpc.CallOption) (*identityv1.VerifyEmailOtpResponse, error) {
	f.lastVerifyOtpReq = in
	if f.verifyOtpErr != nil {
		return nil, f.verifyOtpErr
	}
	return f.verifyOtpResp, nil
}

func (f *fakeFactorClient) RemoveFactor(_ context.Context, in *identityv1.RemoveFactorRequest, _ ...grpc.CallOption) (*identityv1.RemoveFactorResponse, error) {
	f.lastRemoveFactorReq = in
	if f.removeFactorErr != nil {
		return nil, f.removeFactorErr
	}
	return &identityv1.RemoveFactorResponse{}, nil
}

func (f *fakeFactorClient) WebauthnRegisterBegin(_ context.Context, in *identityv1.WebauthnRegisterBeginRequest, _ ...grpc.CallOption) (*identityv1.WebauthnRegisterBeginResponse, error) {
	f.lastRegBeginReq = in
	if f.regBeginErr != nil {
		return nil, f.regBeginErr
	}
	return f.regBeginResp, nil
}

func (f *fakeFactorClient) WebauthnRegisterFinish(_ context.Context, in *identityv1.WebauthnRegisterFinishRequest, _ ...grpc.CallOption) (*identityv1.WebauthnRegisterFinishResponse, error) {
	f.lastRegFinishReq = in
	if f.regFinishErr != nil {
		return nil, f.regFinishErr
	}
	return &identityv1.WebauthnRegisterFinishResponse{}, nil
}

func (f *fakeFactorClient) ListWebauthnCredentials(_ context.Context, in *identityv1.ListWebauthnCredentialsRequest, _ ...grpc.CallOption) (*identityv1.ListWebauthnCredentialsResponse, error) {
	f.lastListCredsReq = in
	if f.listCredsErr != nil {
		return nil, f.listCredsErr
	}
	return f.listCredsResp, nil
}

func (f *fakeFactorClient) RemoveWebauthnCredential(_ context.Context, in *identityv1.RemoveWebauthnCredentialRequest, _ ...grpc.CallOption) (*identityv1.RemoveWebauthnCredentialResponse, error) {
	f.lastRemoveCredReq = in
	if f.removeCredErr != nil {
		return nil, f.removeCredErr
	}
	return &identityv1.RemoveWebauthnCredentialResponse{}, nil
}

// --- myFactors ---

func TestMyFactorsResolver_MapsKindsAndEnrolledAt(t *testing.T) {
	f := &fakeFactorClient{listFactorsResp: &identityv1.ListUserFactorsResponse{
		Factors: []*identityv1.UserFactor{
			{Kind: "totp", EnrolledAt: "2026-07-14T10:00:00Z", Label: "Phone authenticator"},
			{Kind: "email"}, // implicit factor: no enrolled_at, no label
		},
	}}
	got, err := resolvers.MyFactorsResolver(ctxWithClaims(t, "u1"), f)
	if err != nil {
		t.Fatalf("MyFactorsResolver: %v", err)
	}
	if f.lastListFactorsReq.GetUserId() != "u1" {
		t.Errorf("user_id = %q, want claims caller u1", f.lastListFactorsReq.GetUserId())
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Kind != "totp" || got[0].EnrolledAt == nil || *got[0].EnrolledAt != "2026-07-14T10:00:00Z" {
		t.Errorf("factor[0] = %+v, want totp @2026-07-14T10:00:00Z", got[0])
	}
	if got[0].Label == nil || *got[0].Label != "Phone authenticator" {
		t.Errorf("factor[0].label = %v, want 'Phone authenticator'", got[0].Label)
	}
	if got[1].Kind != "email" || got[1].EnrolledAt != nil || got[1].Label != nil {
		t.Errorf("factor[1] = %+v, want email with nil enrolledAt + nil label", got[1])
	}
}

func TestMyFactorsResolver_Unauthenticated(t *testing.T) {
	if _, err := resolvers.MyFactorsResolver(context.Background(), &fakeFactorClient{}); err == nil {
		t.Fatal("expected unauthenticated error, got nil")
	}
}

func TestMyFactorsResolver_NilClientUnavailable(t *testing.T) {
	_, err := resolvers.MyFactorsResolver(ctxWithClaims(t, "u1"), nil)
	if err == nil || !strings.Contains(err.Error(), "factor service unavailable") {
		t.Fatalf("err = %v, want factor service unavailable", err)
	}
}

// --- myWebauthnCredentials ---

func TestMyWebauthnCredentialsResolver_Maps(t *testing.T) {
	f := &fakeFactorClient{listCredsResp: &identityv1.ListWebauthnCredentialsResponse{
		Credentials: []*identityv1.WebauthnCredential{
			{Id: "cred-1", Label: "YubiKey", CreatedAt: "2026-07-01T00:00:00Z", LastUsedAt: "2026-07-10T00:00:00Z", Transports: []string{"usb", "nfc"}},
			{Id: "cred-2", CreatedAt: "2026-07-02T00:00:00Z"}, // never used, unlabeled
		},
	}}
	got, err := resolvers.MyWebauthnCredentialsResolver(ctxWithClaims(t, "u2"), f)
	if err != nil {
		t.Fatalf("MyWebauthnCredentialsResolver: %v", err)
	}
	if f.lastListCredsReq.GetUserId() != "u2" {
		t.Errorf("user_id = %q, want u2", f.lastListCredsReq.GetUserId())
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	c := got[0]
	if c.ID != "cred-1" || c.Label == nil || *c.Label != "YubiKey" || c.CreatedAt != "2026-07-01T00:00:00Z" ||
		c.LastUsedAt == nil || *c.LastUsedAt != "2026-07-10T00:00:00Z" || len(c.Transports) != 2 {
		t.Errorf("cred[0] = %+v, want full mapping", c)
	}
	if got[1].Label != nil || got[1].LastUsedAt != nil {
		t.Errorf("cred[1] = %+v, want nil label + nil lastUsedAt", got[1])
	}
}

func TestMyWebauthnCredentialsResolver_Unauthenticated(t *testing.T) {
	if _, err := resolvers.MyWebauthnCredentialsResolver(context.Background(), &fakeFactorClient{}); err == nil {
		t.Fatal("expected unauthenticated error, got nil")
	}
}

// --- enrollTotpBegin / enrollTotpConfirm ---

func TestEnrollTotpBeginResolver_ReturnsURI(t *testing.T) {
	f := &fakeFactorClient{totpBeginResp: &identityv1.EnrollTotpBeginResponse{
		OtpauthUri:   "otpauth://totp/Policy:u1@x?secret=ABC",
		SecretMasked: "****WXYZ",
	}}
	got, err := resolvers.EnrollTotpBeginResolver(ctxWithClaims(t, "u1"), f)
	if err != nil {
		t.Fatalf("EnrollTotpBeginResolver: %v", err)
	}
	if f.lastTotpBeginReq.GetUserId() != "u1" {
		t.Errorf("user_id = %q, want u1", f.lastTotpBeginReq.GetUserId())
	}
	if got.OtpauthURI != "otpauth://totp/Policy:u1@x?secret=ABC" {
		t.Errorf("otpauthUri = %q", got.OtpauthURI)
	}
	if got.SecretMasked == nil || *got.SecretMasked != "****WXYZ" {
		t.Errorf("secretMasked = %v, want ****WXYZ", got.SecretMasked)
	}
}

func TestEnrollTotpBeginResolver_AlreadyExists(t *testing.T) {
	f := &fakeFactorClient{totpBeginErr: status.Error(codes.AlreadyExists, "totp already enrolled")}
	_, err := resolvers.EnrollTotpBeginResolver(ctxWithClaims(t, "u1"), f)
	if err == nil || !strings.Contains(err.Error(), "already enrolled — remove first") {
		t.Fatalf("err = %v, want already-enrolled mapping", err)
	}
}

func TestEnrollTotpConfirmResolver_PassesCode(t *testing.T) {
	f := &fakeFactorClient{}
	ok, err := resolvers.EnrollTotpConfirmResolver(ctxWithClaims(t, "u1"), f, "123456")
	if err != nil || !ok {
		t.Fatalf("EnrollTotpConfirmResolver = (%v, %v), want (true, nil)", ok, err)
	}
	if f.lastTotpConfirmReq.GetUserId() != "u1" || f.lastTotpConfirmReq.GetCode() != "123456" {
		t.Errorf("req = %+v, want u1/123456", f.lastTotpConfirmReq)
	}
}

func TestEnrollTotpConfirmResolver_FailedPreconditionPassesMessage(t *testing.T) {
	f := &fakeFactorClient{totpConfirmErr: status.Error(codes.FailedPrecondition, "no pending TOTP enrollment")}
	_, err := resolvers.EnrollTotpConfirmResolver(ctxWithClaims(t, "u1"), f, "123456")
	if err == nil || !strings.Contains(err.Error(), "no pending TOTP enrollment") {
		t.Fatalf("err = %v, want FailedPrecondition message passthrough", err)
	}
}

// --- sendEnrollEmailOtp / verifyEnrollEmailOtp ---

func TestSendEnrollEmailOtpResolver_EnrollPurpose(t *testing.T) {
	f := &fakeFactorClient{}
	ok, err := resolvers.SendEnrollEmailOtpResolver(ctxWithClaims(t, "u3"), f)
	if err != nil || !ok {
		t.Fatalf("SendEnrollEmailOtpResolver = (%v, %v), want (true, nil)", ok, err)
	}
	if f.lastSendOtpReq.GetUserId() != "u3" || f.lastSendOtpReq.GetPurpose() != "enroll" {
		t.Errorf("req = %+v, want u3/enroll", f.lastSendOtpReq)
	}
}

func TestSendEnrollEmailOtpResolver_RateLimited(t *testing.T) {
	f := &fakeFactorClient{sendOtpErr: status.Error(codes.ResourceExhausted, "rate limited")}
	_, err := resolvers.SendEnrollEmailOtpResolver(ctxWithClaims(t, "u3"), f)
	if err == nil || !strings.Contains(err.Error(), "try again shortly") {
		t.Fatalf("err = %v, want try-again-shortly mapping", err)
	}
}

func TestVerifyEnrollEmailOtpResolver_PassesCodeAndPurpose(t *testing.T) {
	f := &fakeFactorClient{verifyOtpResp: &identityv1.VerifyEmailOtpResponse{Ok: true}}
	ok, err := resolvers.VerifyEnrollEmailOtpResolver(ctxWithClaims(t, "u3"), f, "654321")
	if err != nil || !ok {
		t.Fatalf("VerifyEnrollEmailOtpResolver = (%v, %v), want (true, nil)", ok, err)
	}
	req := f.lastVerifyOtpReq
	if req.GetUserId() != "u3" || req.GetCode() != "654321" || req.GetPurpose() != "enroll" {
		t.Errorf("req = %+v, want u3/654321/enroll", req)
	}
}

func TestVerifyEnrollEmailOtpResolver_BadCodeFalse(t *testing.T) {
	f := &fakeFactorClient{verifyOtpResp: &identityv1.VerifyEmailOtpResponse{Ok: false}}
	ok, err := resolvers.VerifyEnrollEmailOtpResolver(ctxWithClaims(t, "u3"), f, "000000")
	if err != nil || ok {
		t.Fatalf("VerifyEnrollEmailOtpResolver = (%v, %v), want (false, nil)", ok, err)
	}
}

// --- webauthnRegisterBegin / webauthnRegisterFinish ---

func TestWebauthnRegisterBeginResolver_ReturnsOptionsAndSession(t *testing.T) {
	f := &fakeFactorClient{regBeginResp: &identityv1.WebauthnRegisterBeginResponse{
		OptionsJson: `{"publicKey":{}}`,
		SessionId:   "sess-9",
	}}
	got, err := resolvers.WebauthnRegisterBeginResolver(ctxWithClaims(t, "u4"), f)
	if err != nil {
		t.Fatalf("WebauthnRegisterBeginResolver: %v", err)
	}
	if f.lastRegBeginReq.GetUserId() != "u4" {
		t.Errorf("user_id = %q, want u4", f.lastRegBeginReq.GetUserId())
	}
	if got.OptionsJSON != `{"publicKey":{}}` || got.SessionID != "sess-9" {
		t.Errorf("got = %+v, want options+sessionId", got)
	}
}

func TestWebauthnRegisterFinishResolver_PassesSessionCredentialLabel(t *testing.T) {
	f := &fakeFactorClient{}
	label := "MacBook Touch ID"
	ok, err := resolvers.WebauthnRegisterFinishResolver(ctxWithClaims(t, "u4"), f, "sess-9", `{"id":"abc"}`, &label)
	if err != nil || !ok {
		t.Fatalf("WebauthnRegisterFinishResolver = (%v, %v), want (true, nil)", ok, err)
	}
	req := f.lastRegFinishReq
	if req.GetUserId() != "u4" || req.GetSessionId() != "sess-9" ||
		req.GetCredentialJson() != `{"id":"abc"}` || req.GetLabel() != "MacBook Touch ID" {
		t.Errorf("req = %+v, want full passthrough", req)
	}
}

func TestWebauthnRegisterFinishResolver_NilLabel(t *testing.T) {
	f := &fakeFactorClient{}
	ok, err := resolvers.WebauthnRegisterFinishResolver(ctxWithClaims(t, "u4"), f, "sess-9", `{"id":"abc"}`, nil)
	if err != nil || !ok {
		t.Fatalf("WebauthnRegisterFinishResolver = (%v, %v), want (true, nil)", ok, err)
	}
	if f.lastRegFinishReq.GetLabel() != "" {
		t.Errorf("label = %q, want empty for nil", f.lastRegFinishReq.GetLabel())
	}
}

// --- removeFactor / removeWebauthnCredential ---

func TestRemoveFactorResolver_PassesKind(t *testing.T) {
	f := &fakeFactorClient{}
	ok, err := resolvers.RemoveFactorResolver(ctxWithClaims(t, "u5"), f, "totp")
	if err != nil || !ok {
		t.Fatalf("RemoveFactorResolver = (%v, %v), want (true, nil)", ok, err)
	}
	if f.lastRemoveFactorReq.GetUserId() != "u5" || f.lastRemoveFactorReq.GetKind() != "totp" {
		t.Errorf("req = %+v, want u5/totp", f.lastRemoveFactorReq)
	}
}

func TestRemoveFactorResolver_Unauthenticated(t *testing.T) {
	if _, err := resolvers.RemoveFactorResolver(context.Background(), &fakeFactorClient{}, "totp"); err == nil {
		t.Fatal("expected unauthenticated error, got nil")
	}
}

func TestRemoveWebauthnCredentialResolver_PassesID(t *testing.T) {
	f := &fakeFactorClient{}
	ok, err := resolvers.RemoveWebauthnCredentialResolver(ctxWithClaims(t, "u5"), f, "cred-7")
	if err != nil || !ok {
		t.Fatalf("RemoveWebauthnCredentialResolver = (%v, %v), want (true, nil)", ok, err)
	}
	if f.lastRemoveCredReq.GetUserId() != "u5" || f.lastRemoveCredReq.GetCredentialId() != "cred-7" {
		t.Errorf("req = %+v, want u5/cred-7", f.lastRemoveCredReq)
	}
}

func TestRemoveWebauthnCredentialResolver_UnavailableMapped(t *testing.T) {
	f := &fakeFactorClient{removeCredErr: status.Error(codes.Unavailable, "conn refused")}
	_, err := resolvers.RemoveWebauthnCredentialResolver(ctxWithClaims(t, "u5"), f, "cred-7")
	if err == nil || !strings.Contains(err.Error(), "factor service unavailable") {
		t.Fatalf("err = %v, want factor-service-unavailable mapping", err)
	}
}

// --- renameMfaMethod ---

func TestRenameMfaMethodResolver_PassesMethodIDAndLabel(t *testing.T) {
	f := &fakeFactorClient{}
	ok, err := resolvers.RenameMfaMethodResolver(ctxWithClaims(t, "u6"), f, "totp", "Phone authenticator")
	if err != nil || !ok {
		t.Fatalf("RenameMfaMethodResolver = (%v, %v), want (true, nil)", ok, err)
	}
	req := f.lastRenameReq
	// The owner is bound to the context actor, never an argument.
	if req.GetUserId() != "u6" || req.GetMethodId() != "totp" || req.GetLabel() != "Phone authenticator" {
		t.Errorf("req = %+v, want u6/totp/'Phone authenticator'", req)
	}
}

func TestRenameMfaMethodResolver_PasskeyMethodID(t *testing.T) {
	f := &fakeFactorClient{}
	if _, err := resolvers.RenameMfaMethodResolver(ctxWithClaims(t, "u6"), f, "cred-abc", "1Password"); err != nil {
		t.Fatalf("RenameMfaMethodResolver (passkey): %v", err)
	}
	if f.lastRenameReq.GetMethodId() != "cred-abc" || f.lastRenameReq.GetLabel() != "1Password" {
		t.Errorf("req = %+v, want cred-abc/1Password", f.lastRenameReq)
	}
}

func TestRenameMfaMethodResolver_Unauthenticated(t *testing.T) {
	if _, err := resolvers.RenameMfaMethodResolver(context.Background(), &fakeFactorClient{}, "totp", "x"); err == nil {
		t.Fatal("expected unauthenticated error, got nil")
	}
}

func TestRenameMfaMethodResolver_FailedPreconditionPassesMessage(t *testing.T) {
	f := &fakeFactorClient{renameErr: status.Error(codes.FailedPrecondition, "the email factor is implicit and cannot be labelled")}
	_, err := resolvers.RenameMfaMethodResolver(ctxWithClaims(t, "u6"), f, "email", "x")
	if err == nil || !strings.Contains(err.Error(), "cannot be labelled") {
		t.Fatalf("err = %v, want FailedPrecondition message passthrough", err)
	}
}
