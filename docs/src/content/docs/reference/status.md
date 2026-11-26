---
title: Project status
description: Versioning, compatibility, what the tests cover and how to report a problem.
---

## Versioning

Authlume has no tagged release yet. `go get` records a commit of the `main` branch.

Until v1.0.0 the API can change in incompatible ways between commits. Recent changes of that kind include new parameters and return values on store interfaces and new fields on exported structs. To depend on the module:

- Pin the commit in `go.mod` and upgrade deliberately.
- Read the commit log and the diff of the packages you use before upgrading.
- Run the store contract tests where the module provides them, such as `mcpoauth/storetest`.

From v1.0.0 on, the module will follow semantic versioning.

## Requirements

- Go 1.25 or later
- The `totp` package needs HMAC-SHA-1 and does not work in Go's FIPS 140-only mode. The `password` package offers PBKDF2-HMAC-SHA-256 for applications that need a FIPS-approved algorithm.

## What the tests cover

Run them with `go test -race ./...`.

| Package | Covered by tests |
| --- | --- |
| `password`, `session` | Unit tests, and the HTTPS sample driven through its handler with TLS, a cookie jar and a controlled clock |
| `totp` | The RFC 6238 test vectors, the acceptance window, replay and the HTTPS sample |
| `webauthn` | Registration, verification and passkey sign-in with a software authenticator, and the HTTPS sample's handler |
| `oidc` | The whole flow against a local signed test issuer, including each accepted signature algorithm |
| `mcpoauth` | Authorization, code exchange, refresh, reuse detection and revocation, the store contract and the HTTPS sample |

## What is not covered

- **Real MCP clients.** Some behaviors of the `mcpoauth` package have not been checked against real clients. They are listed in [MCP OAuth store and operations](/authlume/reference/mcp-store/#not-yet-verified-against-real-mcp-clients).
- **Persistent stores.** The module ships in-memory stores only. An application's own store has to meet the contract that each guide describes.
- **The application's duties.** Rate limits, enrollment, recovery, consent screens and audit records are outside the module and outside its tests.

## Not included

- Dynamic client registration and client ID metadata documents for MCP OAuth. An application can provide its own registration and resolve clients through `mcpoauth.ClientLookup`.
- SAML, and out-of-band factors such as codes sent by SMS or email.
- An OpenID Provider. The `oidc` package is a relying party only.
- User management, invitations and roles.

## Reporting problems

- **A vulnerability:** report it privately through the repository's [Security tab](https://github.com/i2bskn/authlume/security), as described in the [security policy](https://github.com/i2bskn/authlume/blob/main/SECURITY.md).
- **A bug or a question:** open an [issue](https://github.com/i2bskn/authlume/issues).
- **A change:** read the [contributing guide](https://github.com/i2bskn/authlume/blob/main/CONTRIBUTING.md) first.
