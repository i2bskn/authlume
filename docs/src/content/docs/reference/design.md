---
title: Design notes
description: "The principles behind the packages, and the detailed behavior of password verification and session handling."
---

This page explains why the packages behave as they do. The guides say how to use them.

## Principles

- **The packages verify. The application decides.** A package answers one question, such as "is this password correct for this record". Whether that completes a login, who may enroll, how an account is recovered and how attempts are limited stay with the application.
- **One identifier.** An opaque, nonempty subject string is the only thing the packages know about a user. Normalizing login names and mapping them to subjects is the application's job.
- **Small store interfaces.** Each package states the atomic operations it needs and leaves the schema to the application. The in-memory stores are for one process.
- **Fail closed.** A corrupt record, a store error, a policy error or an unrecognized policy decision fails the attempt. Backend errors are distinct from "invalid credentials", so an outage is not reported to users as a wrong password, and not treated as a logout.
- **Defaults fit an ordinary public web application.** Stricter behavior is available as an option. Checks that make verification correct, such as signature and issuer checks, cannot be turned off.
- **No state in the request decides security.** No header or query parameter chooses which activity counts as user action, which algorithm is used or which checks apply.

## Password verification

### Records

A record is a version tag, the algorithm with its fixed parameters, a salt and a derived key.

| Algorithm | Record |
| --- | --- |
| Argon2id, 19 MiB of memory, 2 passes, 1 thread | `v2$argon2id$m=19456,t=2,p=1$<salt>$<key>` |
| PBKDF2-HMAC-SHA-256, 600,000 iterations | `v1$pbkdf2-sha256$600000$<salt>$<key>` |

The salt is 16 random bytes and the key is 32 bytes, both in unpadded standard Base64 of a fixed length.

- **Parameters are never read from a record.** The verifier accepts only the exact prefix and field sizes above before any derivation. A record cannot ask the server for a cheaper or a more expensive derivation.
- **A different cost or algorithm needs a new record version.** This keeps every accepted format explicit.
- **Argon2id is the default** with the minimum configuration that OWASP recommends. PBKDF2 uses Go's standard library and exists for applications that need FIPS-approved algorithms.
- **Passwords are opaque bytes** of 1 to 1024 bytes. They are never truncated, trimmed or normalized.

### Verification

- An unknown identifier and a wrong password both return `ErrCredentials`.
- An unknown identifier and an invalid record (an empty subject, malformed data or a format that is not accepted) perform a dummy derivation before returning, so they take as long as a failed attempt on a valid record.
- Derived keys are compared in constant time.
- `ErrRecord` signals misconfiguration or data corruption. Show users a generic error and alert on it internally. Never log credentials.

### Migration between algorithms

`WithMigrationFrom` makes the verifier accept the formats of further algorithms. A success for such a record sets `Result.Rehash`, and the application replaces the record with the authenticator's `Hash` while `NeedsRehash` is still true for the stored one. The package never writes a record.

While migration algorithms are set, every attempt performs one derivation per accepted algorithm: the real one for the record's algorithm and a dummy one for each of the others. The response time therefore does not show whether an identifier exists or which accepted algorithm its record uses. The price is that every attempt costs the sum of the algorithms.

### Policy

After a correct password the application's policy returns `PasswordOnly` or `RequireMFA` for the subject. `Authenticate` returns the subject and the decision only after both the verification and the policy succeeded. `RequireMFA` is an incomplete login: the package issues no challenge token and has no cookie or session API, so nothing but the application's own code can turn it into a session.

## Sessions

### Session state

`Issue` creates a random 32-byte ID, sends it to the browser as an unpadded base64url cookie value and stores only its SHA-256 digest as the key. A leaked store therefore does not contain usable session IDs.

The server-side state holds the subject, the authentication time, the last activity, a fixed absolute expiry and the idle lifetime.

### The cookie

The cookie is host-only and named `__Host-authlume` by default, with `Path=/`, `Secure`, `HttpOnly` and `SameSite=Lax`. Its expiry is the absolute deadline rounded up to the next whole second. The server checks the precise deadline.

- **Ambiguous cookies are rejected, not guessed.** Two cookies with the session's name, or a value that is not in canonical form, return `ErrInvalid` on `Read`, `Touch`, `Issue` and `Logout` without changing the store or writing headers.
- **Headers are written only after the store succeeded.** A failed `Issue` leaves no cookie, and a failed `Logout` does not appear to have signed the user out.
- **A custom name must keep the `__Host-` prefix**, so the browser enforces `Secure`, `Path=/` and the absence of a `Domain` attribute. `New` rejects any other name.

### Lifetimes and activity

- A session ends at the idle deadline or at the absolute deadline, whichever comes first. A record is expired when the current time is equal to or later than a deadline.
- `Read` validates without touching. Only `Touch` moves the idle deadline, and the application calls it only for a route it has classified as an intentional user action.
- Activity never changes the authentication time or the absolute deadline. Time never moves the last activity backwards.
- A request that was already authorized can finish even if the session expires meanwhile.

### Rotation and revocation

- Every `Issue` creates a new ID and consumes the session that the browser presented, in the same store operation. A missing old record does not prevent the new login.
- `Logout` deletes the server state before clearing the cookie.
- `Revoke` ends a session by its stored key, independently of HTTP.
- Ending every session of one user needs an index by subject, which the application's store provides.

### Fresh authentication

`RequireFresh` checks the authentication age against a maximum that the application chooses per action. A stale session needs a complete new authentication of the same subject under the current policy, followed by `Issue`. The package has no separate reauthentication protocol: a multi-step authentication is bound to the user and action by the application.

### The store contract

The store has three atomic operations, `Replace`, `Use` and `Delete`, described in [Sessions](/authlume/guides/sessions/#implement-a-store). Operations on the same key must be linearizable. The reasons:

- `Replace` inserts the new session and removes the old one together, so a login never leaves two valid sessions for one browser, and a collision never destroys a working session.
- `Use` checks the deadlines and applies the touch in one step, so a touch cannot revive a session that was deleted or expired in between.
- `Delete` is idempotent, so a repeated logout succeeds.

`MemoryStore` serializes its operations, has a bounded capacity and reclaims expired entries before it reports that it is full.

### Recovering from an unreadable cookie

Strict validation means that a browser holding a malformed or duplicate cookie can neither sign in nor log out. `ResetInvalidCookie` is the way out.

- It clears the cookie for exactly this manager's host-only, root-path scope.
- It acts only on an absent, malformed or duplicate cookie. A single well-formed cookie returns `ErrCookieWellFormed` and is left alone, so that a normal logout can revoke the record.
- It never looks up, authenticates, touches, rotates or revokes a record. A session that exists on the server stays until it expires or is revoked.

Do not guess other paths, domains or cookie names to clear. A cookie outside this scope has to be removed in the browser settings.

## Browser flows

Serve every browser flow over HTTPS and protect every state-changing route against CSRF: login before a session exists, activity updates, reauthentication, cookie reset and logout. Register mutations as POST handlers only. The samples wrap their whole router in Go's `http.NewCrossOriginProtection`.

## References

- [Go Argon2](https://pkg.go.dev/golang.org/x/crypto/argon2) and [Go PBKDF2](https://pkg.go.dev/crypto/pbkdf2)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Go HTTP cross-origin protection](https://pkg.go.dev/net/http#CrossOriginProtection)
- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) (TOTP), [Web Authentication](https://www.w3.org/TR/webauthn-3/), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
