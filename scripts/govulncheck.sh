#!/usr/bin/env bash
# Runs govulncheck and fails on every vulnerability the code calls, except the
# IDs in allowed below. GOVULNCHECK names the binary (govulncheck on PATH by
# default).
#
# GO-2026-6443: grpc-go's server panics on a request with no authority or Host
# header. The reachable path is the xDS server's routing on the authority; the
# gateway serves no gRPC at all (it is a gRPC client behind an HTTP edge) and
# Steward uses no xDS routing. Tracked in
# https://github.com/Steward-GRC/steward-core/issues/13; remove when grpc
# 1.84.1+ or 1.85.
set -euo pipefail

allowed=("GO-2026-6443")

out="$(mktemp)"
trap 'rm -f "$out"' EXIT
"${GOVULNCHECK:-govulncheck}" -format json ./... > "$out"

mapfile -t called < <(jq -r 'select(.finding != null)
  | select((.finding.trace[0].function // "") != "")
  | .finding.osv' "$out" | sort -u)

failed=0
for id in "${called[@]}"; do
  skip=0
  for a in "${allowed[@]}"; do
    [[ "$id" == "$a" ]] && skip=1
  done
  if [[ $skip -eq 1 ]]; then
    echo "govulncheck: $id is called but excluded (see scripts/govulncheck.sh)"
  else
    echo "govulncheck: $id is called: https://pkg.go.dev/vuln/$id" >&2
    failed=1
  fi
done
if [[ $failed -eq 0 ]]; then
  echo "govulncheck: no called vulnerability outside the exclusions"
fi
exit "$failed"
