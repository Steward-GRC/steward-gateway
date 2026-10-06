# Error codes

The gateway's own codes (band 1). Each GraphQL error's `extensions` carry `code` (the
symbol), `codeNum`, `domain` (`gateway` here, or the backend's domain for a relayed error),
`kind` (`business` or `reach`), `requestId` and `traceId`. Only user-safe messages reach the
caller; every other code is sent as a generic message with the code as a reference.

| Code | Symbol | Area | Cause | User-safe |
| --- | --- | --- | --- | --- |
| 1000 | `UNCLASSIFIED_INTERNAL` | gateway | an error reached the presenter with no code at all; find the log line by its trace id and give the site a specific code | no |
| 1210 | `KRATOS_LOGIN_FLOW_INIT_FAILED` | sign-in | Kratos answered the login-flow start with a non-2xx status or a flow with no id | no |
| 1211 | `KRATOS_PASSWORD_VERIFY_FAILED` | sign-in | Kratos answered the password submit with an unexpected status or no session token; a wrong password is a plain 401, not this code | no |
| 1212 | `KRATOS_UNREACHABLE` | sign-in | a Kratos call failed in transport (dial or timeout) | no |
| 1213 | `KRATOS_SESSION_REFRESH_FAILED` | session | Kratos whoami answered with an unexpected status or an unreadable body | no |
| 1214 | `KRATOS_LOGOUT_FAILED` | session | Kratos refused the logout; the gateway drops its own session regardless | no |
| 1215 | `KRATOS_EMAIL_NO_PLATFORM_USER` | sign-in | the credential checked out with Kratos but identity has no user with that email; the client sees a plain 401 | no |
| 1216 | `KRATOS_VERIFY_NO_SESSION_PRINCIPAL` | session | a request reached the per-request check without passing the session cookie and CSRF gate; fails closed to 401 | no |
| 1217 | `KRATOS_SESSION_USER_LOOKUP_FAILED` | session | identity GetUser for the session's user failed, found nobody, or found a disabled user; fails closed to 401 | no |
| 1218 | `POLIS_CODE_EXCHANGE_FAILED` | sso | the Polis authorization-code exchange failed (transport, status, body or no access token); the callback fails closed | no |
| 1219 | `POLIS_USERINFO_FAILED` | sso | the Polis userinfo lookup failed (transport, status or body); the callback fails closed | no |
| 1221 | `KRATOS_ADMIN_IDENTITY_LOOKUP_FAILED` | recovery | the Kratos admin identity lookup answered with a non-2xx status or an unreadable body; an absent identity is answered 200 to stop enumeration | no |
| 1222 | `KRATOS_ADMIN_RECOVERY_CODE_FAILED` | recovery | Kratos refused to create a recovery code or returned none | no |
| 1223 | `KRATOS_RECOVERY_FLOW_FAILED` | recovery | the Kratos recovery flow answered with an unexpected status or body; a wrong code is a plain 400 | no |
| 1224 | `KRATOS_SETTINGS_PASSWORD_FAILED` | recovery | the Kratos settings flow failed to set the new password (status, missing csrf_token or a cookie fault) | no |
| 1225 | `POLIS_JIT_PROVISION_FAILED` | sso | identity JitProvisionByEmail failed or returned nobody for a first-seen federated email; the callback fails closed | no |
| 1227 | `KRATOS_ADMIN_SET_PASSWORD_FAILED` | users | an admin password set failed on the Kratos admin API, or the user could not be mapped to a Kratos identity | no |
| 1228 | `KRATOS_PASSKEY_LOGIN_INIT_FAILED` | passkey | the Kratos passkey login flow failed to start or carries no passkey challenge (the method is off in Kratos) | no |
| 1229 | `KRATOS_PASSKEY_LOGIN_VERIFY_FAILED` | passkey | Kratos answered the passkey login submit with an unexpected status or no session token; a rejected assertion is a plain 401 | no |
| 1230 | `IMPERSONATION_NOT_SITE_ADMIN` | act-as | the real caller isn't a site admin | yes |
| 1231 | `IMPERSONATION_REASON_REQUIRED` | act-as | the required reason was blank | yes |
| 1232 | `IMPERSONATION_TARGET_PROTECTED` | act-as | the target is a site admin or the root user | yes |
| 1233 | `IMPERSONATION_ALREADY_ACTIVE` | act-as | the caller's session already acts as someone; act-as doesn't nest | yes |
| 1234 | `IMPERSONATION_DENIED` | act-as | a high-risk mutation was refused because the request acts as another user | yes |
| 1235 | `KRATOS_PASSKEY_REGISTER_VERIFY_FAILED` | passkey | Kratos answered the passkey registration submit with an unexpected status | no |
| 1236 | `KRATOS_PASSKEY_REGISTER_INIT_FAILED` | passkey | the Kratos settings flow for passkey registration failed to open or carries no passkey data (the method is off in Kratos) | no |
| 1240 | `NOTIFY_VERIFY_EMAIL_PERSIST_FAILED` | email | a valid email-verification link was opened but identity MarkEmailVerified failed for a non-user reason | no |
| 1241 | `PROFILE_LOCALE_INVALID` | profile | the locale isn't a well-formed BCP 47 tag in the language[-Script][-REGION] form the gateway stores | yes |
| 1242 | `COLLAB_FLUSH_UNAVAILABLE` | publish | collab couldn't save the live room's newest checkpoint to core in time, or collab couldn't be reached; nothing was published | yes |
| 1243 | `COLLAB_FLUSH_REJECTED` | publish | core refused the live room's content, or the room belongs to another policy; nothing was published | yes |
| 1244 | `COLLAB_FLUSH_FAILED` | publish | collab's flush failed for any other reason; nothing was published | no |
| 1245 | `REPORT_CHECKS_THROTTLED` | anonymous report | too many checks or replies for this case code, or for all case codes together, in the throttle window; reporting was not called | yes |
| 1246 | `REPORT_THROTTLE_UNAVAILABLE` | anonymous report | the throttle store (Valkey) could not be asked, so the check or reply was refused rather than let through unthrottled | yes |
| 1250 | `UNAUTHENTICATED` | session | the request has no signed-in session | yes |
