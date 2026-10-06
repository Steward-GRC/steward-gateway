#!/usr/bin/env bash
# Regenerates the GraphQL execution code, the models and the resolver stubs
# from graphql/*.graphqls (gqlgen.yml), then puts the licence header back on
# the files gqlgen rewrites. CI runs it and fails if anything changed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
go tool gqlgen generate
go run github.com/Bugs5382/golic/cmd/golic@v0.3.0 inject -t spdx-apache2 -c "2026 The Steward Authors" >/dev/null 2>&1
gofmt -w internal/resolvers
