// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"errors"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// factorCaller returns the caller's user id from claims, enforcing the any-authenticated-user gate
// and the identity-client presence in one place.
func factorCaller(ctx context.Context, identity identityv1.IdentityReadServiceClient) (string, error) {
	claims, ok := principal.FromContext(ctx)
	if !ok || claims.UserID() == "" {
		return "", status.Error(codes.Unauthenticated, "no authenticated user")
	}
	if identity == nil {
		return "", errors.New("factor service unavailable")
	}
	return claims.UserID(), nil
}

// mapFactorError translates identity gRPC codes into clean GraphQL error messages for the
// enrollment widget.
func mapFactorError(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.AlreadyExists:
		return errors.New("already enrolled — remove first")
	case codes.ResourceExhausted:
		return errors.New("try again shortly")
	case codes.FailedPrecondition:
		return errors.New(status.Convert(err).Message())
	case codes.Unavailable:
		return errors.New("factor service unavailable")
	}
	return err
}

// optStr maps an empty proto string to a nil GraphQL nullable.
func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// MyFactorsResolver lists the caller's enrolled second factors.
func MyFactorsResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient) ([]*UserFactor, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return nil, err
	}
	resp, err := identity.ListUserFactors(ctx, &identityv1.ListUserFactorsRequest{UserId: uid})
	if err != nil {
		return nil, mapFactorError(err)
	}
	out := make([]*UserFactor, 0, len(resp.GetFactors()))
	for _, f := range resp.GetFactors() {
		out = append(out, &UserFactor{
			Kind:       f.GetKind(),
			EnrolledAt: optStr(f.GetEnrolledAt()),
			Label:      optStr(f.GetLabel()),
		})
	}
	return out, nil
}

// MyWebauthnCredentialsResolver lists the caller's registered passkeys.
func MyWebauthnCredentialsResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient) ([]*WebauthnCredentialInfo, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return nil, err
	}
	resp, err := identity.ListWebauthnCredentials(ctx, &identityv1.ListWebauthnCredentialsRequest{UserId: uid})
	if err != nil {
		return nil, mapFactorError(err)
	}
	out := make([]*WebauthnCredentialInfo, 0, len(resp.GetCredentials()))
	for _, c := range resp.GetCredentials() {
		out = append(out, &WebauthnCredentialInfo{
			ID:         c.GetId(),
			Label:      optStr(c.GetLabel()),
			CreatedAt:  c.GetCreatedAt(),
			LastUsedAt: optStr(c.GetLastUsedAt()),
			Transports: c.GetTransports(),
		})
	}
	return out, nil
}

// EnrollTotpBeginResolver starts (or restarts) TOTP enrollment for the caller.
func EnrollTotpBeginResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient) (*TotpEnrollment, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return nil, err
	}
	resp, err := identity.EnrollTotpBegin(ctx, &identityv1.EnrollTotpBeginRequest{UserId: uid})
	if err != nil {
		return nil, mapFactorError(err)
	}
	return &TotpEnrollment{
		OtpauthURI:   resp.GetOtpauthUri(),
		SecretMasked: optStr(resp.GetSecretMasked()),
	}, nil
}

// EnrollTotpConfirmResolver activates the caller's pending TOTP enrollment by proving possession of
// the secret with a current code.
func EnrollTotpConfirmResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient, code string) (bool, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return false, err
	}
	if _, err := identity.EnrollTotpConfirm(ctx, &identityv1.EnrollTotpConfirmRequest{UserId: uid, Code: code}); err != nil {
		return false, mapFactorError(err)
	}
	return true, nil
}

// emailOtpPurposeEnroll scopes enrollment email-OTP challenges apart from the login flow's
// (identity verifies purpose on both mint and verify).
const emailOtpPurposeEnroll = "enroll"

// SendEnrollEmailOtpResolver emails the caller a single-use enrollment code.
func SendEnrollEmailOtpResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient) (bool, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return false, err
	}
	if _, err := identity.SendEmailOtp(ctx, &identityv1.SendEmailOtpRequest{UserId: uid, Purpose: emailOtpPurposeEnroll}); err != nil {
		return false, mapFactorError(err)
	}
	return true, nil
}

// VerifyEnrollEmailOtpResolver verifies the caller's emailed enrollment code.
func VerifyEnrollEmailOtpResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient, code string) (bool, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return false, err
	}
	resp, err := identity.VerifyEmailOtp(ctx, &identityv1.VerifyEmailOtpRequest{UserId: uid, Code: code, Purpose: emailOtpPurposeEnroll})
	if err != nil {
		return false, mapFactorError(err)
	}
	return resp.GetOk(), nil
}

// WebauthnRegisterBeginResolver starts a passkey registration ceremony for the caller.
func WebauthnRegisterBeginResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient) (*WebauthnRegistration, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return nil, err
	}
	resp, err := identity.WebauthnRegisterBegin(ctx, &identityv1.WebauthnRegisterBeginRequest{UserId: uid})
	if err != nil {
		return nil, mapFactorError(err)
	}
	return &WebauthnRegistration{
		OptionsJSON: resp.GetOptionsJson(),
		SessionID:   resp.GetSessionId(),
	}, nil
}

// WebauthnRegisterFinishResolver completes the caller's passkey registration ceremony with the
// authenticator's attestation response.
func WebauthnRegisterFinishResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient, sessionID, credentialJSON string, label *string) (bool, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return false, err
	}
	req := &identityv1.WebauthnRegisterFinishRequest{
		UserId:         uid,
		SessionId:      sessionID,
		CredentialJson: credentialJSON,
	}
	if label != nil {
		req.Label = *label
	}
	if _, err := identity.WebauthnRegisterFinish(ctx, req); err != nil {
		return false, mapFactorError(err)
	}
	return true, nil
}

// RemoveFactorResolver deletes the caller's credential for the given kind ("totp", or "passkey" for
// ALL passkeys — identity validates the kind).
func RemoveFactorResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient, kind string) (bool, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return false, err
	}
	if _, err := identity.RemoveFactor(ctx, &identityv1.RemoveFactorRequest{UserId: uid, Kind: kind}); err != nil {
		return false, mapFactorError(err)
	}
	return true, nil
}

// RemoveWebauthnCredentialResolver deletes one of the caller's passkeys by its credential id.
func RemoveWebauthnCredentialResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient, credentialID string) (bool, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return false, err
	}
	if _, err := identity.RemoveWebauthnCredential(ctx, &identityv1.RemoveWebauthnCredentialRequest{UserId: uid, CredentialId: credentialID}); err != nil {
		return false, mapFactorError(err)
	}
	return true, nil
}

// RenameMfaMethodResolver relabels one of the caller's enrolled second-factor methods.
func RenameMfaMethodResolver(ctx context.Context, identity identityv1.IdentityReadServiceClient, methodID, label string) (bool, error) {
	uid, err := factorCaller(ctx, identity)
	if err != nil {
		return false, err
	}
	if _, err := identity.RenameMFAMethod(ctx, &identityv1.RenameMFAMethodRequest{UserId: uid, MethodId: methodID, Label: label}); err != nil {
		return false, mapFactorError(err)
	}
	return true, nil
}
