# authlume

[![Go Reference](https://pkg.go.dev/badge/github.com/i2bskn/authlume.svg)](https://pkg.go.dev/github.com/i2bskn/authlume)

Authlume is a set of authentication building blocks for Go web applications. Each package verifies one thing, such as a password, a session cookie, a TOTP code, a WebAuthn assertion, an OpenID Connect login or an OAuth token for an MCP server. The application composes them and decides when a login is complete.

The packages are independently importable, work with the standard `net/http` package and keep their state behind small store interfaces that the application implements.

| Package | Provides | Dependencies |
| --- | --- | --- |
| [`password`](https://pkg.go.dev/github.com/i2bskn/authlume/password) | Password verification with Argon2id or PBKDF2, and the policy decision after it | `golang.org/x/crypto` |
| [`session`](https://pkg.go.dev/github.com/i2bskn/authlume/session) | Server-backed web sessions with idle and absolute lifetimes | Standard library only |
| [`totp`](https://pkg.go.dev/github.com/i2bskn/authlume/totp) | RFC 6238 codes as a second factor | Standard library only |
| [`webauthn`](https://pkg.go.dev/github.com/i2bskn/authlume/webauthn) | Security keys and passkeys as a second factor, and optional passkey sign-in | go-webauthn |
| [`oidc`](https://pkg.go.dev/github.com/i2bskn/authlume/oidc) | Sign-in with an OpenID Connect issuer | go-oidc and oauth2 |
| [`mcpoauth`](https://pkg.go.dev/github.com/i2bskn/authlume/mcpoauth) | An OAuth 2.1 authorization server and bearer token verifier for one MCP server | Standard library only |

## Status

Authlume has no tagged release yet. Until v1.0.0 the API can change in incompatible ways between commits, so pin the version in `go.mod` and read the commit log before upgrading. See [Project status](https://docs.i2bskn.com/authlume/reference/status/) for what the tests cover and what they do not.

## Install

Authlume needs Go 1.25 or later.

```sh
go get github.com/i2bskn/authlume
```

## Example

```go
auth, err := password.New(lookup, nil) // lookup loads the stored record for an identifier
if err != nil {
    return err
}
sessions, err := session.New(session.NewMemoryStore(), session.Config{})
if err != nil {
    return err
}

// In the login handler:
result, err := auth.Authenticate(r.Context(), identifier, secret)
if err != nil {
    http.Error(w, "Sign-in failed", http.StatusUnauthorized)
    return
}
if result.Decision != password.PasswordOnly {
    // Complete the second factor before issuing a session.
    return
}
if err := sessions.Issue(w, r, result.Subject); err != nil {
    http.Error(w, "Sign-in failed", http.StatusInternalServerError)
    return
}
```

Runnable HTTPS examples for every package are in [`examples/`](examples/).

## Documentation

The documentation is at <https://docs.i2bskn.com/authlume/>.

- [Quickstart](https://docs.i2bskn.com/authlume/getting-started/quickstart/): from a password to a session, and the HTTPS sample
- Guides: [Passwords](https://docs.i2bskn.com/authlume/guides/password/), [Sessions](https://docs.i2bskn.com/authlume/guides/sessions/), [TOTP](https://docs.i2bskn.com/authlume/guides/totp/), [WebAuthn and passkeys](https://docs.i2bskn.com/authlume/guides/webauthn/), [OpenID Connect](https://docs.i2bskn.com/authlume/guides/oidc/), [MCP OAuth](https://docs.i2bskn.com/authlume/guides/mcp-oauth/)
- Reference: [Design notes](https://docs.i2bskn.com/authlume/reference/design/), [MCP OAuth store and operations](https://docs.i2bskn.com/authlume/reference/mcp-store/), [Project status](https://docs.i2bskn.com/authlume/reference/status/)
- API reference: [pkg.go.dev](https://pkg.go.dev/github.com/i2bskn/authlume)

The source of the documentation is in [`docs/`](docs/).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test and propose changes. Report a vulnerability privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## License

[MIT](LICENSE)
