# steward-gateway 🐹

> 🧭 GraphQL gateway for Steward: the browser-facing edge with sessions, sign-in, first-run setup, the co-editing proxy and document extract

## 🎯 What it is

The only service the Steward web apps talk to. It serves the GraphQL schema in `graphql/`, owns
the browser session (Kratos sign-in, Polis SSO, the CSRF double-submit), and calls every Steward
service over gRPC on behalf of the signed-in user, with its own service-account token on every
call. It also proxies the co-editing websocket to collab, extracts text from uploaded documents
and serves editor images.

- 🔐 **Sessions** live server-side in Valkey; the browser holds an opaque cookie and a CSRF token.
- 🎭 **Act-as**: the real admin travels with every call and high-risk actions are refused.
- 🩺 **Health**: `/livez` checks the process, `/readyz` follows Valkey and Kratos.
- 🧾 **Diagnostics**: one signed-in query with every service's version and commit.

## 📚 More

- [Sign-in and session routes](docs/auth.md)
- [Error codes](docs/error-codes.md)

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # gofmt check + golangci-lint + yamllint
task license  # check Apache-2.0 headers (golic)
scripts/proto-generate.sh   # fetch the pinned callee protos and regenerate gen/
```

## 🙏 Acknowledgements

Steward was originally written by [@Bugs5382](https://github.com/Bugs5382).

## ⚖️ License

Apache-2.0 (c) 2026 The Steward Authors
