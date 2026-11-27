---
title: Installation
description: Add the module and import only the packages the application uses.
---

Authlume is one module, `github.com/i2bskn/authlume`, for Go 1.26 and later. Its packages are independently importable, and only the application composes them.

```sh
go get github.com/i2bskn/authlume
```

There is no tagged release yet, so `go get` records a commit. Until v1.0.0 the API can change in incompatible ways between commits. Read [Project status](/authlume/reference/status/) before depending on it.

## Packages

| Package | Provides | Dependencies |
| --- | --- | --- |
| [`password`](https://pkg.go.dev/github.com/i2bskn/authlume/password) | Password verification and the policy decision after it | `golang.org/x/crypto` for Argon2id |
| [`session`](https://pkg.go.dev/github.com/i2bskn/authlume/session) | Server-backed web sessions | Standard library only |
| [`totp`](https://pkg.go.dev/github.com/i2bskn/authlume/totp) | RFC 6238 codes as a second factor | Standard library only |
| [`webauthn`](https://pkg.go.dev/github.com/i2bskn/authlume/webauthn) | WebAuthn as a second factor, and optional passkey sign-in | go-webauthn |
| [`oidc`](https://pkg.go.dev/github.com/i2bskn/authlume/oidc) | Sign-in with an OpenID Connect issuer | go-oidc and oauth2 |
| [`mcpoauth`](https://pkg.go.dev/github.com/i2bskn/authlume/mcpoauth) | An OAuth 2.1 authorization server and bearer token verifier for one MCP server | Standard library only |
| [`mcpoauth/storetest`](https://pkg.go.dev/github.com/i2bskn/authlume/mcpoauth/storetest) | Contract tests for an `mcpoauth.Store` implementation | Standard library only |

The package names link to the API reference on pkg.go.dev. `go doc github.com/i2bskn/authlume/<package>` prints the same text locally.

## What the application provides

- **A subject.** An opaque, nonempty string is the only identifier the packages know for a user. Keep email addresses and other personal data out of it.
- **Storage.** Each package reads and writes through a small interface, such as `password.Lookup` or `session.Store`. The in-memory stores that ship with the module serve one process and lose their state on restart.
- **Policy.** The application owns identifier normalization, enrollment rules, authorization, account lifecycle and recovery, rate limits and its database schema.
- **HTTPS and CSRF protection.** Serve every browser flow over HTTPS and protect every state-changing route against CSRF, including login before a session exists.

Next: [verify a password and issue a session](/authlume/getting-started/quickstart/).
