# Torii gate ⛩️

**Edge-native Token Handler BFF — RFC 9700 compliant, vendor agnostic, TypeScript throughout.**

A torii gate marks the boundary between the ordinary and the protected — nothing passes
without authorization. Torii the library does the same for your SPA: tokens never reach
the browser, sessions are managed entirely behind the gate, and the whole stack runs on
Cloudflare Workers, Deno Deploy, or Docker without changing a line of code.

The npm scope `@torii-gate` reflects exactly this: every package in this project is
part of the gate that stands between your frontend and your protected resources.

[![CI](https://github.com/toriijs/torii/actions/workflows/ci.yml/badge.svg)](https://github.com/toriijs/torii/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@torii-gate/core)](https://www.npmjs.com/package/@torii-gate/core)
[![License: EUPL-1.2](https://img.shields.io/badge/License-EUPL_1.2-blue.svg)](https://opensource.org/licenses/EUPL-1.2)

---

## About the Name

In Japanese culture, a torii (鳥居) is a traditional gate that marks the transition from the mundane to the sacred. It stands as a symbolic boundary, distinguishing a protected, inner space from the world outside.We chose this name because it perfectly mirrors the role of a BFF in modern software architecture:

- **The Gateway**: Like a torii, this package serves as the singular "portal" or entry point for your frontend.
- **The Boundary**: It acts as a clean boundary between external client requests and your internal microservices.
- **The Guard**: Just as a torii is sometimes said to ward off "unclean" things, this service ensures your frontend only receives the precise, purified data it needs.

We use this name with deep respect for its cultural significance as a symbol of transition, harmony, and protection.

---

## What Torii does

Torii implements the [RFC 9700 Token Handler Pattern](https://datatracker.ietf.org/doc/html/rfc9700). It sits between your SPA and your backend API:

```
Browser → Torii BFF → Backend API
           ↕
        Keycloak / Zitadel / Auth0 / any OIDC provider
```

- PKCE S256 — authorization code flow, no implicit grant
- Tokens stored **server-side only** — the browser receives only an `HttpOnly` session cookie
- Silent token refresh — the SPA sees no interruption when access tokens expire
- API proxy — Torii injects `Authorization: Bearer` on every upstream request
- Mix-up attack defence — RFC 9207 `iss` parameter validated on every callback
- Federated logout — token revocation + end_session_endpoint

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). A CLA signature is required — takes under a minute.
PRs welcome, especially new session adapters.

## License

[EUPL-1.2](./LICENSE) © [2026] [Chathuranga Hengodage](https://github.com/iamchathu)

> Torii is open source under EUPL 1.2. For organizations that require a commercial
> license without copyleft obligations, contact us via a GitHub issue.
