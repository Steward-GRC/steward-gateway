// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package errcodes holds the gateway's own coded errors (band 1, 1000 to 1999)
// on go-apperr. Errors relayed from a backend keep that backend's code and
// domain; these are the failures the gateway itself decides.
//
// Each code's category decides its kind, the one bit the web branches on:
// business (the caller or their data decided the outcome; shown inline with
// the user-safe message, no retry) or reach (we failed; a generic message and
// a Try again, the code shown as a reference).
package errcodes

import (
	"sync"

	apperr "github.com/Bugs5382/go-apperr"
)

// Domain is the domain every gateway-coded error carries.
const Domain = "gateway"

// The gateway's codes.
const (
	CodeInternal                       = 1000
	CodeKratosLoginFlowInitFailed      = 1210
	CodeKratosPasswordVerifyFailed     = 1211
	CodeKratosUnreachable              = 1212
	CodeKratosSessionRefreshFailed     = 1213
	CodeKratosLogoutFailed             = 1214
	CodeKratosEmailNoPlatformUser      = 1215
	CodeKratosVerifyNoSessionPrincipal = 1216
	CodeKratosSessionUserLookupFailed  = 1217
	CodePolisCodeExchangeFailed        = 1218
	CodePolisUserinfoFailed            = 1219
	CodeKratosAdminIdentityLookup      = 1221
	CodeKratosAdminRecoveryCodeFailed  = 1222
	CodeKratosRecoveryFlowFailed       = 1223
	CodeKratosSettingsPasswordFailed   = 1224
	CodePolisJitProvisionFailed        = 1225
	CodeKratosAdminSetPasswordFailed   = 1227
	CodeKratosPasskeyLoginInitFailed   = 1228
	CodeKratosPasskeyLoginVerifyFailed = 1229
	CodeImpersonationNotSiteAdmin      = 1230
	CodeImpersonationReasonRequired    = 1231
	CodeImpersonationTargetProtected   = 1232
	CodeImpersonationAlreadyActive     = 1233
	CodeImpersonationDenied            = 1234
	CodeKratosPasskeyRegisterVerify    = 1235
	CodeKratosPasskeyRegisterInit      = 1236
	CodeNotifyVerifyEmailPersistFailed = 1240
	CodeProfileLocaleInvalid           = 1241
	CodeCollabFlushUnavailable         = 1242
	CodeCollabFlushRejected            = 1243
	CodeCollabFlushFailed              = 1244
)

// Entries returns the registry entries.
func Entries() []apperr.Entry {
	return []apperr.Entry{
		{Code: CodeInternal, Symbol: "UNCLASSIFIED_INTERNAL", Category: apperr.CategoryInternal,
			Title: "gateway", Cause: "an error reached the presenter with no code at all; find the log line by its trace id and give the site a specific code"},
		{Code: CodeKratosLoginFlowInitFailed, Symbol: "KRATOS_LOGIN_FLOW_INIT_FAILED", Category: apperr.CategoryInternal,
			Title: "sign-in", Cause: "Kratos answered the login-flow start with a non-2xx status or a flow with no id"},
		{Code: CodeKratosPasswordVerifyFailed, Symbol: "KRATOS_PASSWORD_VERIFY_FAILED", Category: apperr.CategoryInternal,
			Title: "sign-in", Cause: "Kratos answered the password submit with an unexpected status or no session token; a wrong password is a plain 401, not this code"},
		{Code: CodeKratosUnreachable, Symbol: "KRATOS_UNREACHABLE", Category: apperr.CategoryUnavailable,
			Title: "sign-in", Cause: "a Kratos call failed in transport (dial or timeout)"},
		{Code: CodeKratosSessionRefreshFailed, Symbol: "KRATOS_SESSION_REFRESH_FAILED", Category: apperr.CategoryInternal,
			Title: "session", Cause: "Kratos whoami answered with an unexpected status or an unreadable body"},
		{Code: CodeKratosLogoutFailed, Symbol: "KRATOS_LOGOUT_FAILED", Category: apperr.CategoryInternal,
			Title: "session", Cause: "Kratos refused the logout; the gateway drops its own session regardless"},
		{Code: CodeKratosEmailNoPlatformUser, Symbol: "KRATOS_EMAIL_NO_PLATFORM_USER", Category: apperr.CategoryInternal,
			Title: "sign-in", Cause: "the credential checked out with Kratos but identity has no user with that email; the client sees a plain 401"},
		{Code: CodeKratosVerifyNoSessionPrincipal, Symbol: "KRATOS_VERIFY_NO_SESSION_PRINCIPAL", Category: apperr.CategoryInternal,
			Title: "session", Cause: "a request reached the per-request check without passing the session cookie and CSRF gate; fails closed to 401"},
		{Code: CodeKratosSessionUserLookupFailed, Symbol: "KRATOS_SESSION_USER_LOOKUP_FAILED", Category: apperr.CategoryInternal,
			Title: "session", Cause: "identity GetUser for the session's user failed, found nobody, or found a disabled user; fails closed to 401"},
		{Code: CodePolisCodeExchangeFailed, Symbol: "POLIS_CODE_EXCHANGE_FAILED", Category: apperr.CategoryInternal,
			Title: "sso", Cause: "the Polis authorization-code exchange failed (transport, status, body or no access token); the callback fails closed"},
		{Code: CodePolisUserinfoFailed, Symbol: "POLIS_USERINFO_FAILED", Category: apperr.CategoryInternal,
			Title: "sso", Cause: "the Polis userinfo lookup failed (transport, status or body); the callback fails closed"},
		{Code: CodeKratosAdminIdentityLookup, Symbol: "KRATOS_ADMIN_IDENTITY_LOOKUP_FAILED", Category: apperr.CategoryInternal,
			Title: "recovery", Cause: "the Kratos admin identity lookup answered with a non-2xx status or an unreadable body; an absent identity is answered 200 to stop enumeration"},
		{Code: CodeKratosAdminRecoveryCodeFailed, Symbol: "KRATOS_ADMIN_RECOVERY_CODE_FAILED", Category: apperr.CategoryInternal,
			Title: "recovery", Cause: "Kratos refused to create a recovery code or returned none"},
		{Code: CodeKratosRecoveryFlowFailed, Symbol: "KRATOS_RECOVERY_FLOW_FAILED", Category: apperr.CategoryInternal,
			Title: "recovery", Cause: "the Kratos recovery flow answered with an unexpected status or body; a wrong code is a plain 400"},
		{Code: CodeKratosSettingsPasswordFailed, Symbol: "KRATOS_SETTINGS_PASSWORD_FAILED", Category: apperr.CategoryInternal,
			Title: "recovery", Cause: "the Kratos settings flow failed to set the new password (status, missing csrf_token or a cookie fault)"},
		{Code: CodePolisJitProvisionFailed, Symbol: "POLIS_JIT_PROVISION_FAILED", Category: apperr.CategoryInternal,
			Title: "sso", Cause: "identity JitProvisionByEmail failed or returned nobody for a first-seen federated email; the callback fails closed"},
		{Code: CodeKratosAdminSetPasswordFailed, Symbol: "KRATOS_ADMIN_SET_PASSWORD_FAILED", Category: apperr.CategoryInternal,
			Title: "users", Cause: "an admin password set failed on the Kratos admin API, or the user could not be mapped to a Kratos identity"},
		{Code: CodeKratosPasskeyLoginInitFailed, Symbol: "KRATOS_PASSKEY_LOGIN_INIT_FAILED", Category: apperr.CategoryInternal,
			Title: "passkey", Cause: "the Kratos passkey login flow failed to start or carries no passkey challenge (the method is off in Kratos)"},
		{Code: CodeKratosPasskeyLoginVerifyFailed, Symbol: "KRATOS_PASSKEY_LOGIN_VERIFY_FAILED", Category: apperr.CategoryInternal,
			Title: "passkey", Cause: "Kratos answered the passkey login submit with an unexpected status or no session token; a rejected assertion is a plain 401"},
		{Code: CodeImpersonationNotSiteAdmin, Symbol: "IMPERSONATION_NOT_SITE_ADMIN", Category: apperr.CategoryPermissionDenied,
			Title: "act-as", Cause: "the real caller isn't a site admin",
			UserSafe: true, Message: "Only a site administrator may act as another user."},
		{Code: CodeImpersonationReasonRequired, Symbol: "IMPERSONATION_REASON_REQUIRED", Category: apperr.CategoryInvalid,
			Title: "act-as", Cause: "the required reason was blank",
			UserSafe: true, Message: "A reason is required to act as another user."},
		{Code: CodeImpersonationTargetProtected, Symbol: "IMPERSONATION_TARGET_PROTECTED", Category: apperr.CategoryPermissionDenied,
			Title: "act-as", Cause: "the target is a site admin or the root user",
			UserSafe: true, Message: "You cannot act as a site administrator or the root user."},
		{Code: CodeImpersonationAlreadyActive, Symbol: "IMPERSONATION_ALREADY_ACTIVE", Category: apperr.CategoryFailedPrecondition,
			Title: "act-as", Cause: "the caller's session already acts as someone; act-as doesn't nest",
			UserSafe: true, Message: "You are already acting as another user. Stop the current session before starting a new one."},
		{Code: CodeImpersonationDenied, Symbol: "IMPERSONATION_DENIED", Category: apperr.CategoryPermissionDenied,
			Title: "act-as", Cause: "a high-risk mutation was refused because the request acts as another user",
			UserSafe: true, Message: "This action is not allowed while acting as another user."},
		{Code: CodeKratosPasskeyRegisterVerify, Symbol: "KRATOS_PASSKEY_REGISTER_VERIFY_FAILED", Category: apperr.CategoryInternal,
			Title: "passkey", Cause: "Kratos answered the passkey registration submit with an unexpected status"},
		{Code: CodeKratosPasskeyRegisterInit, Symbol: "KRATOS_PASSKEY_REGISTER_INIT_FAILED", Category: apperr.CategoryInternal,
			Title: "passkey", Cause: "the Kratos settings flow for passkey registration failed to open or carries no passkey data (the method is off in Kratos)"},
		{Code: CodeNotifyVerifyEmailPersistFailed, Symbol: "NOTIFY_VERIFY_EMAIL_PERSIST_FAILED", Category: apperr.CategoryInternal,
			Title: "email", Cause: "a valid email-verification link was opened but identity MarkEmailVerified failed for a non-user reason"},
		{Code: CodeProfileLocaleInvalid, Symbol: "PROFILE_LOCALE_INVALID", Category: apperr.CategoryInvalid,
			Title: "profile", Cause: "the locale isn't a well-formed BCP 47 tag in the language[-Script][-REGION] form the gateway stores",
			UserSafe: true, Message: "That is not a valid language tag. Use a form like \"en\" or \"en-US\"."},
		{Code: CodeCollabFlushUnavailable, Symbol: "COLLAB_FLUSH_UNAVAILABLE", Category: apperr.CategoryUnavailable,
			Title: "publish", Cause: "collab couldn't save the live room's newest checkpoint to core in time, or collab couldn't be reached; nothing was published",
			UserSafe: true, Message: "Couldn't save the latest edits, so the policy was not published. Please try again."},
		{Code: CodeCollabFlushRejected, Symbol: "COLLAB_FLUSH_REJECTED", Category: apperr.CategoryFailedPrecondition,
			Title: "publish", Cause: "core refused the live room's content, or the room belongs to another policy; nothing was published",
			UserSafe: true, Message: "The latest edits couldn't be saved, so the policy was not published: {reason}"},
		{Code: CodeCollabFlushFailed, Symbol: "COLLAB_FLUSH_FAILED", Category: apperr.CategoryInternal,
			Title: "publish", Cause: "collab's flush failed for any other reason; nothing was published"},
	}
}

var (
	regOnce sync.Once
	reg     *apperr.Registry
)

// Registry returns the gateway registry.
func Registry() *apperr.Registry {
	regOnce.Do(func() {
		r, err := apperr.NewRegistry(Entries(), apperr.WithService(1), apperr.WithCodeDigits(4))
		if err != nil {
			panic(err)
		}
		reg = r
	})
	return reg
}

// New returns a coded error for code carrying the metadata pairs, in key,
// value order. The cause is the code's symbol.
func New(code int, kv ...string) error {
	pairs := make([]apperr.MetaPair, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		pairs = append(pairs, apperr.Meta(kv[i], kv[i+1]))
	}
	entry, _ := Registry().Describe(code)
	return apperr.WithMeta(apperr.Coded(code, refusal(entry.Symbol)), pairs...)
}

// Wrap returns cause coded with code.
func Wrap(code int, cause error) error { return apperr.Coded(code, cause) }

// Kind is the user-facing classification a client branches on.
type Kind string

// The two kinds.
const (
	KindBusiness Kind = "business"
	KindReach    Kind = "reach"
)

// KindOf classifies a category: our failures (internal, unavailable, deadline)
// are reach, everything the caller or their data decided is business.
func KindOf(c apperr.Category) Kind {
	switch c {
	case apperr.CategoryInternal, apperr.CategoryUnavailable, apperr.CategoryDeadlineExceeded:
		return KindReach
	default:
		return KindBusiness
	}
}

// Doc is the Markdown body of docs/error-codes.md.
func Doc() string {
	return "# Error codes\n\nThe gateway's own codes (band 1). Each GraphQL error's `extensions` carry `code` (the\n" +
		"symbol), `codeNum`, `domain` (`" + Domain + "` here, or the backend's domain for a relayed error),\n" +
		"`kind` (`business` or `reach`), `requestId` and `traceId`. Only user-safe messages reach the\n" +
		"caller; every other code is sent as a generic message with the code as a reference.\n\n" +
		Registry().Markdown()
}

type refusal string

func (r refusal) Error() string { return "gateway: " + string(r) }
