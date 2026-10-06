# Sign-in and session routes

The gateway owns the browser session. Kratos checks passwords and passkeys,
Polis brokers SSO, and identity maps every sign-in to a platform user and runs
the second factor. The browser only ever holds the `steward_sid` cookie and a
CSRF token; Kratos session tokens stay in Valkey.

## Routes

Public:

| Route | What it does |
|---|---|
| `POST /auth/login` | Kratos password sign-in; a session, or `{mfaRequired, pendingId, factors}` |
| `POST /auth/logout` | Revokes the Kratos session and drops the local one |
| `GET /auth/session` | Whether a session is live, its CSRF token and the user's email |
| `POST /auth/discover` | `{method, connectionAlias, idpInitiatedSsoUrl, allowLocal}` for an identifier |
| `POST /auth/breakglass` | Password sign-in for eligible accounts while SSO is down; still owes the second factor |
| `GET /auth/sso/start` | Starts an SSO sign-in (`mode=login`) or a connection test (`mode=test`) |
| `GET /auth/sso/callback` | Polis returns here; issues the session, the second-factor step, or records the test |
| `POST /auth/sso/idp-initiated` | IdP-initiated SSO |
| `POST /auth/mfa/otp/send`, `/auth/mfa/webauthn/begin`, `/auth/mfa/verify` | Second factor for a pending sign-in |
| `POST /auth/mfa/enroll/{totp,email,webauthn}/...` | First sign-in factor enrolment |
| `POST /auth/passkey/login/begin`, `/finish` | Passkey sign-in; a verified passkey needs no second factor |
| `GET /auth/config` | Sign-in settings the page loads first |
| `POST /auth/password-reset/request`, `/confirm` | Password reset by emailed code (identity sets the password) |
| `POST /auth/login-otp/request`, `/verify` | Emailed sign-in code |
| `GET /setup/state`, `POST /setup/bootstrap` | First-run root admin, guarded by the setup token |
| `GET /maintenance` | Maintenance state, readable before sign-in |
| `POST /notify/unsubscribe`, `GET /notify/unsubscribe` | Signed one-click and browser unsubscribe |
| `GET /notify/verify-email` | Signed email-verification link |

Behind a session (`Authenticate`, CSRF header on writes):

| Route | What it does |
|---|---|
| `POST /auth/passkey/register/begin`, `/finish` | Adds a passkey to the signed-in account |
| `POST /admin/idp/import-metadata`, `/parse-metadata`, `/fetch-cert` | SAML metadata helpers; site admins only, https only, private addresses refused |
| `POST /admin/sso/test-link` | A shareable connection-test link; site admins only |

While maintenance is on, GraphQL operations from anyone but a site admin are
refused with the `MAINTENANCE` code, except `me` and `globalSettings`.

## Second factor

`MFA_ENFORCE` decides when a sign-in owes a second factor: `edge` (default)
when the public edge marks the request (`MFA_EDGE_HEADER`, default
`X-Steward-Edge`, equal to `MFA_EDGE_PUBLIC_VALUE`, default `public`),
`always`, or `never`. With `MFA_REQUIRE_STRONG=true` a user with only the email
factor must enrol a TOTP app or a passkey first. A pending sign-in lives five
minutes and allows five wrong codes.

## SSO sessions

An SSO session keeps no Polis token: it lives for the gateway's session TTL
and is not refreshed against Kratos.

## Settings

| Setting | Default | Required | Use |
|---|---|---|---|
| `KRATOS_PUBLIC_URL` | none | yes | Kratos public API (sign-in, whoami, logout, passkeys) |
| `KRATOS_ADMIN_URL` | none | no | Kratos admin API; only pinned as an allowed base |
| `SESSION_TTL` | `168h` | no | Browser session lifetime |
| `COOKIE_INSECURE` | `false` | no | `true` drops the cookie's Secure flag for local HTTP |
| `MFA_ENFORCE` | `edge` | no | `edge`, `always` or `never` |
| `MFA_EDGE_HEADER` | `X-Steward-Edge` | no | Header the public edge sets |
| `MFA_EDGE_PUBLIC_VALUE` | `public` | no | Its value on the public edge |
| `MFA_REQUIRE_STRONG` | `false` | no | Email alone doesn't satisfy the second factor |
| `PASSKEY_LOGIN_ENABLED` | `true` | no | Offers passkey sign-in when Kratos supports it |
| `POLIS_PUBLIC_URL` | empty | no | Polis URL the browser reaches; empty turns SSO off |
| `POLIS_ISSUER_URL` | none | with SSO | Polis URL for the token and userinfo calls |
| `POLIS_PRODUCT` | `steward` | no | Polis product the connections are filed under |
| `SSO_REDIRECT_BASE` | none | with SSO | Public origin of the gateway, for `/auth/sso/callback` |
| `SSO_TEST_LINK_TTL` | `30m` | no | Lifetime of a shareable connection-test link |
| `DEFAULT_LOGIN_METHOD` | `local` | no | `local` or `sso`, the form the sign-in page shows first |
| `SETUP_TOKEN` | empty | no | Guards `POST /setup/bootstrap`; empty turns it off |
| `MAINTENANCE_CACHE_TTL` | `5s` | no | How long the maintenance state is cached |
| `NOTIFY_UNSUB_SECRET` | empty | no | Verifies the signed notify links; must match obligations; empty turns the routes off |
| `NOTIFY_PREFERENCES_URL` | empty | with the secret | Where the browser unsubscribe lands |
