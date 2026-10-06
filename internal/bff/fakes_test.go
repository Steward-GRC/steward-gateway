// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"sync"
	"time"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeAuth is the Kratos seam. Each hook defaults to a successful answer.
type fakeAuth struct {
	mu sync.Mutex

	verify  func(username, password string) (AuthResult, error)
	refresh func(token string) (AuthResult, error)
	logout  func(token string) error

	refreshCalls  int
	refreshTokens []string
	logoutTokens  []string
}

const testSessionToken = "kratos-session-token"

func okAuth() *fakeAuth { return &fakeAuth{} }

func (f *fakeAuth) VerifyPassword(_ context.Context, username, password string) (AuthResult, error) {
	if f.verify != nil {
		return f.verify(username, password)
	}
	return AuthResult{AccessToken: testSessionToken, ExpiresAt: time.Now().Add(time.Hour), Subject: "kratos-id-1", Email: "alice@example.org"}, nil
}

func (f *fakeAuth) Refresh(_ context.Context, token string) (AuthResult, error) {
	f.mu.Lock()
	f.refreshCalls++
	f.refreshTokens = append(f.refreshTokens, token)
	f.mu.Unlock()
	if f.refresh != nil {
		return f.refresh(token)
	}
	return AuthResult{AccessToken: token, ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}

func (f *fakeAuth) Logout(_ context.Context, token string) error {
	f.mu.Lock()
	f.logoutTokens = append(f.logoutTokens, token)
	f.mu.Unlock()
	if f.logout != nil {
		return f.logout(token)
	}
	return nil
}

func (f *fakeAuth) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshCalls
}

// fakeMfaIdentity fakes identity's read service. Fields set the answers;
// last* fields capture each request so tests can assert the RPC contract.
// Methods a test doesn't override panic through the nil embedded client.
type fakeMfaIdentity struct {
	identityv1.IdentityReadServiceClient

	// user is the platform user GetUserByEmail resolves; nil answers
	// NotFound, the way identity answers an email with no user.
	user       *identityv1.User
	emailErr   error
	factors    []string
	factorsErr error

	jitUser *identityv1.User
	jitErr  error

	getUser    *identityv1.User
	getUserErr error

	totpOK  bool
	emailOK bool

	btg    *identityv1.CheckBreakGlassEligibilityResponse
	btgErr error

	discover *identityv1.DiscoverResponse

	assertOptions  string
	assertSession  string
	assertBeginErr error
	assertOK       bool

	sendErr error

	enrollTotpURI        string
	enrollTotpSecret     string
	enrollTotpBeginErr   error
	enrollTotpConfirmErr error
	regBeginOptions      string
	regBeginSession      string
	regBeginErr          error
	regFinishErr         error

	lastGetUserByEmail      *identityv1.GetUserByEmailRequest
	lastJitProvisionByEmail *identityv1.JitProvisionByEmailRequest
	lastGetUser             *identityv1.GetUserRequest
	lastFactors             *identityv1.ListUserFactorsRequest
	lastSend                *identityv1.SendEmailOtpRequest
	lastVerifyTotp          *identityv1.VerifyTotpRequest
	lastVerifyEmail         *identityv1.VerifyEmailOtpRequest
	lastAssertBegin         *identityv1.WebauthnAssertBeginRequest
	lastAssertFinish        *identityv1.WebauthnAssertFinishRequest
	lastEnrollTotpBegin     *identityv1.EnrollTotpBeginRequest
	lastEnrollTotpConfirm   *identityv1.EnrollTotpConfirmRequest
	lastRegBegin            *identityv1.WebauthnRegisterBeginRequest
	lastRegFinish           *identityv1.WebauthnRegisterFinishRequest
	lastBreakGlass          *identityv1.CheckBreakGlassEligibilityRequest
	lastDiscover            *identityv1.DiscoverRequest
}

func (f *fakeMfaIdentity) GetUserByEmail(_ context.Context, in *identityv1.GetUserByEmailRequest, _ ...grpc.CallOption) (*identityv1.GetUserByEmailResponse, error) {
	f.lastGetUserByEmail = in
	if f.emailErr != nil {
		return nil, f.emailErr
	}
	if f.user == nil {
		return nil, status.Error(codes.NotFound, "no platform user for email")
	}
	return &identityv1.GetUserByEmailResponse{User: f.user}, nil
}

func (f *fakeMfaIdentity) JitProvisionByEmail(_ context.Context, in *identityv1.JitProvisionByEmailRequest, _ ...grpc.CallOption) (*identityv1.JitProvisionByEmailResponse, error) {
	f.lastJitProvisionByEmail = in
	if f.jitErr != nil {
		return nil, f.jitErr
	}
	return &identityv1.JitProvisionByEmailResponse{User: f.jitUser}, nil
}

func (f *fakeMfaIdentity) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	f.lastGetUser = in
	if f.getUserErr != nil {
		return nil, f.getUserErr
	}
	return &identityv1.GetUserResponse{User: f.getUser}, nil
}

func (f *fakeMfaIdentity) ListUserFactors(_ context.Context, in *identityv1.ListUserFactorsRequest, _ ...grpc.CallOption) (*identityv1.ListUserFactorsResponse, error) {
	f.lastFactors = in
	if f.factorsErr != nil {
		return nil, f.factorsErr
	}
	out := &identityv1.ListUserFactorsResponse{}
	for _, k := range f.factors {
		out.Factors = append(out.Factors, &identityv1.UserFactor{Kind: k})
	}
	return out, nil
}

func (f *fakeMfaIdentity) SendEmailOtp(_ context.Context, in *identityv1.SendEmailOtpRequest, _ ...grpc.CallOption) (*identityv1.SendEmailOtpResponse, error) {
	f.lastSend = in
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return &identityv1.SendEmailOtpResponse{}, nil
}

func (f *fakeMfaIdentity) VerifyTotp(_ context.Context, in *identityv1.VerifyTotpRequest, _ ...grpc.CallOption) (*identityv1.VerifyTotpResponse, error) {
	f.lastVerifyTotp = in
	return &identityv1.VerifyTotpResponse{Ok: f.totpOK}, nil
}

func (f *fakeMfaIdentity) VerifyEmailOtp(_ context.Context, in *identityv1.VerifyEmailOtpRequest, _ ...grpc.CallOption) (*identityv1.VerifyEmailOtpResponse, error) {
	f.lastVerifyEmail = in
	return &identityv1.VerifyEmailOtpResponse{Ok: f.emailOK}, nil
}

func (f *fakeMfaIdentity) WebauthnAssertBegin(_ context.Context, in *identityv1.WebauthnAssertBeginRequest, _ ...grpc.CallOption) (*identityv1.WebauthnAssertBeginResponse, error) {
	f.lastAssertBegin = in
	if f.assertBeginErr != nil {
		return nil, f.assertBeginErr
	}
	return &identityv1.WebauthnAssertBeginResponse{OptionsJson: f.assertOptions, SessionId: f.assertSession}, nil
}

func (f *fakeMfaIdentity) WebauthnAssertFinish(_ context.Context, in *identityv1.WebauthnAssertFinishRequest, _ ...grpc.CallOption) (*identityv1.WebauthnAssertFinishResponse, error) {
	f.lastAssertFinish = in
	return &identityv1.WebauthnAssertFinishResponse{Ok: f.assertOK}, nil
}

func (f *fakeMfaIdentity) EnrollTotpBegin(_ context.Context, in *identityv1.EnrollTotpBeginRequest, _ ...grpc.CallOption) (*identityv1.EnrollTotpBeginResponse, error) {
	f.lastEnrollTotpBegin = in
	if f.enrollTotpBeginErr != nil {
		return nil, f.enrollTotpBeginErr
	}
	return &identityv1.EnrollTotpBeginResponse{OtpauthUri: f.enrollTotpURI, SecretMasked: f.enrollTotpSecret}, nil
}

func (f *fakeMfaIdentity) EnrollTotpConfirm(_ context.Context, in *identityv1.EnrollTotpConfirmRequest, _ ...grpc.CallOption) (*identityv1.EnrollTotpConfirmResponse, error) {
	f.lastEnrollTotpConfirm = in
	if f.enrollTotpConfirmErr != nil {
		return nil, f.enrollTotpConfirmErr
	}
	return &identityv1.EnrollTotpConfirmResponse{}, nil
}

func (f *fakeMfaIdentity) WebauthnRegisterBegin(_ context.Context, in *identityv1.WebauthnRegisterBeginRequest, _ ...grpc.CallOption) (*identityv1.WebauthnRegisterBeginResponse, error) {
	f.lastRegBegin = in
	if f.regBeginErr != nil {
		return nil, f.regBeginErr
	}
	return &identityv1.WebauthnRegisterBeginResponse{OptionsJson: f.regBeginOptions, SessionId: f.regBeginSession}, nil
}

func (f *fakeMfaIdentity) WebauthnRegisterFinish(_ context.Context, in *identityv1.WebauthnRegisterFinishRequest, _ ...grpc.CallOption) (*identityv1.WebauthnRegisterFinishResponse, error) {
	f.lastRegFinish = in
	if f.regFinishErr != nil {
		return nil, f.regFinishErr
	}
	return &identityv1.WebauthnRegisterFinishResponse{}, nil
}

func (f *fakeMfaIdentity) Discover(_ context.Context, in *identityv1.DiscoverRequest, _ ...grpc.CallOption) (*identityv1.DiscoverResponse, error) {
	f.lastDiscover = in
	if f.discover != nil {
		return f.discover, nil
	}
	return &identityv1.DiscoverResponse{}, nil
}

func (f *fakeMfaIdentity) CheckBreakGlassEligibility(_ context.Context, in *identityv1.CheckBreakGlassEligibilityRequest, _ ...grpc.CallOption) (*identityv1.CheckBreakGlassEligibilityResponse, error) {
	f.lastBreakGlass = in
	if f.btgErr != nil {
		return nil, f.btgErr
	}
	if f.btg != nil {
		return f.btg, nil
	}
	return &identityv1.CheckBreakGlassEligibilityResponse{}, nil
}
