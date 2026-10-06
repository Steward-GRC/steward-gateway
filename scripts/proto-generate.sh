#!/usr/bin/env bash
# Regenerates gen/go/thirdparty from the callee protos pinned in
# proto-refs.env. The gateway has no proto of its own. The callee protos are
# fetched into .protos/ (git-ignored) and never committed; only the generated
# stubs are.
#
# STEWARD_<NAME>_PROTO_DIR points at a local proto/ directory instead, for
# trying an unmerged proto change (for example STEWARD_CORE_PROTO_DIR).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$root/proto-refs.env"

protos="$root/.protos"
rm -rf "$protos" "$root/gen/go/thirdparty"

# fetch <service>: the callee's whole steward/<service> package at its pin.
fetch() {
  local svc="$1" repo="steward-$1" upper ref local_dir
  upper="$(tr '[:lower:]' '[:upper:]' <<<"$svc")"
  ref="STEWARD_${upper}_REF"
  local_dir="STEWARD_${upper}_PROTO_DIR"
  local dest="$protos/$repo"
  mkdir -p "$dest"
  if [[ -n "${!local_dir:-}" ]]; then
    echo "proto: $repo from ${!local_dir}"
    mkdir -p "$dest/steward"
    cp -R "${!local_dir}/steward/$svc" "$dest/steward/$svc"
    return
  fi
  echo "proto: $repo at ${!ref}"
  curl -sSfL "https://codeload.github.com/Steward-GRC/$repo/tar.gz/${!ref}" |
    tar -xz -C "$dest" --strip-components=2 --wildcards "*/proto/steward/$svc/*"
}

for svc in ai audit collab core delivery identity obligations reporting workflow; do
  fetch "$svc"
done

cd "$root"
buf generate
