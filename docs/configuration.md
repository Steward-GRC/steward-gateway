# Configuration

Every setting is an environment variable, read and checked once at start-up
(`internal/config`). A bad value stops the gateway with a message naming it.

## Edge and backends

| Variable | Default | Use |
|---|---|---|
| `GATEWAY_HTTP_ADDR` | `:8080` | Listen address of the browser-facing edge |
| `STEWARD_<SVC>_ADDR` | `steward-<svc>:9090` | One per backend: `AI`, `AUDIT`, `COLLAB`, `CORE`, `DELIVERY`, `IDENTITY`, `OBLIGATIONS`, `REPORTING`, `WORKFLOW` |
| `WORKLOAD_TOKEN_FILE` | `/var/run/secrets/steward/token` | The gateway's projected service-account token (audience `steward`), sent on every backend call and read again on each; an unreadable file stops the boot |
| `WORKLOAD_AUTH` | unset (on) | `disabled` sends no token, for local runs only; any other value is refused |
| `ALLOWED_ORIGINS` | empty | Extra browser origins (comma list) that may open the subscription and co-editing websockets; the gateway's own origin is always allowed |

## Valkey, RabbitMQ, telemetry

| Variable | Default | Use |
|---|---|---|
| `VALKEY_ADDR` | `steward-valkey:6379` | Sessions, sign-in state, AI job results, the anonymous-report throttle |
| `VALKEY_PASSWORD` | empty | Valkey password |
| `RABBITMQ_URL` | empty | Live updates, AI job results and act-as audit events; empty turns all three off |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | empty | OpenTelemetry collector; empty exports nothing |
| `LOG_LEVEL`, `LOG_FORMAT` | `info`, `json` | go-log level and format; local runs use `trace` and `console` |

## Sign-in

| Variable | Default | Use |
|---|---|---|
| `KRATOS_PUBLIC_URL` | `http://steward-kratos:4433` | Kratos public API |
| `KRATOS_ADMIN_URL` | `http://steward-kratos:4434` | Kratos admin API: readiness, diagnostics |
| `SESSION_TTL` | `168h` | Browser session lifetime |
| `COOKIE_INSECURE` | `false` | `true` drops the cookie's Secure flag, for local HTTP |
| `MFA_ENFORCE` | `edge` | `edge`, `always` or `never` |
| `MFA_EDGE_HEADER`, `MFA_EDGE_PUBLIC_VALUE` | `X-Steward-Edge`, `public` | The header and value the public edge sets |
| `MFA_REQUIRE_STRONG` | `false` | The email factor alone isn't enough |
| `PASSKEY_LOGIN_ENABLED` | `true` | Offers passkey sign-in when Kratos supports it |
| `POLIS_PUBLIC_URL` | empty | Polis address the browser reaches; empty turns SSO off |
| `POLIS_ISSUER_URL` | none | Polis in-cluster address; required with SSO |
| `POLIS_PRODUCT` | `steward` | Polis product the connections are filed under |
| `SSO_REDIRECT_BASE` | none | Public origin of the gateway; required with SSO |
| `SSO_TEST_LINK_TTL` | `30m` | Lifetime of a connection-test link |
| `DEFAULT_LOGIN_METHOD` | `local` | `local` or `sso`: the form the sign-in page shows first |
| `SETUP_TOKEN` | empty | Guards `POST /setup/bootstrap`; empty turns first-run setup off |
| `MAINTENANCE_CACHE_TTL` | `5s` | How long the maintenance state is cached |
| `NOTIFY_UNSUB_SECRET` | empty | Verifies the signed notification links; must match obligations; empty turns those routes off |
| `NOTIFY_PREFERENCES_URL` | none | Where a browser unsubscribe lands; required with the secret |
| `REPORT_PROBLEM_URL` | empty | The adopter's "report a problem" target, served by `/auth/config` as `reportProblemUrl`; empty hides the link |

## Co-editing, templates, diagnostics

| Variable | Default | Use |
|---|---|---|
| `COLLAB_WS_UPSTREAM` | `steward-collab:8081` | collab's websocket listener |
| `COLLAB_WS_MAX_MESSAGE_BYTES` | 4 MiB | Largest frame the proxy relays (above collab's own limit) |
| `COLLAB_WS_IDLE_TIMEOUT` | `120s` | Idle time before the proxy pings both legs |
| `STEWARD_ALLOW_TEMPLATE_DELETE` | `false` | Enables the hard `deleteTemplate`; leave off outside development |
| `STEWARD_RELEASE` | empty | The pinned release version the diagnostics read reports |
| `STEWARD_APPLIANCE_VERSION_FILE` | empty | The appliance's version file; set only on the appliance |
| `DIAGNOSTICS_HTTP_PROBES` | empty | Probe-only components as `name=url` pairs (comma list), read for their `Steward-Version` and `Steward-Commit` headers |
