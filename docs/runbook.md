# Runbook

## Health

- **Liveness:** `GET /livez` checks the process only, never a dependency, so an outage never
  restarts the pod.
- **Readiness:** `GET /readyz` is 503 while Valkey (sessions) or Kratos is down and recovers on its
  own. RabbitMQ, Polis and every backend service are optional and show as `degraded`: one backend
  outage fails only the operations that need it. Checks are short-timeout pings cached for five
  seconds.
- The body lists each dependency's state, whether it's required, the last error class, the time of
  the check and its version. Both probes carry `Steward-Version` and `Steward-Commit`:

  ```sh
  curl -si localhost:8080/readyz
  ```

## Build info

The image takes `VERSION` (the tag) and `COMMIT` (the full SHA) as build arguments and stamps them
into go-buildinfo; an unstamped build reports `dev` and `unknown`. Signed-in users see every
component's version through the `diagnostics` query.

## Service-to-service calls

Every backend call carries the projected token from `WORKLOAD_TOKEN_FILE`. A callee answering
`Unauthenticated` means the token mount or its audience (`steward`) is wrong; `PermissionDenied`
means the callee doesn't list `steward-gateway` for that method. `WORKLOAD_AUTH=disabled` sends no
token and is for local runs only.

## Sessions

Sessions live in Valkey under `sess:<id>` for `SESSION_TTL`. Losing Valkey signs everyone out and
takes readiness down until it's back. Revoking a user's sessions in identity ends them at Kratos;
the gateway's copy fails its next whoami.

## Maintenance

While maintenance is on (core's global settings), GraphQL operations from anyone but a site admin
are refused except `me` and `globalSettings`. The state is cached for `MAINTENANCE_CACHE_TTL`.
