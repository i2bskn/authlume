---
title: Passwords
description: Verify a password, choose between Argon2id and PBKDF2, and migrate records from one algorithm to the other.
---

The `password` package verifies a password against a record that the application stores, then asks the application's policy whether the login is complete. It has no cookie or session API. Enrollment, password rules, login throttling and account recovery belong to the application.

## Verify a password

Give the authenticator a `password.Lookup` that loads the stored record for an identifier. Return `password.ErrNotFound` for an unknown identifier and any other error for a backend failure.

```go
lookup := func(ctx context.Context, identifier string) (password.Credential, error) {
	user, err := users.ByEmail(ctx, identifier) // the application's own store
	if errors.Is(err, ErrNoSuchUser) {
		return password.Credential{}, password.ErrNotFound
	}
	if err != nil {
		return password.Credential{}, err
	}
	return password.Credential{Subject: user.ID, Hash: user.PasswordHash}, nil
}

auth, err := password.New(lookup, nil) // a nil policy completes a login with the password alone
if err != nil {
	return err
}
```

Create the record with the authenticator's `Hash` method when the user sets a password, and store the returned string as it is.

```go
record, err := auth.Hash(secret)
```

In the login handler, call `Authenticate` and look at the error before the result.

```go
result, err := auth.Authenticate(r.Context(), identifier, secret)
switch {
case errors.Is(err, password.ErrCredentials):
	// Unknown identifier or wrong password. Show one generic message for both.
case errors.Is(err, password.ErrRecord):
	// The stored record is corrupt or in a format this authenticator does not
	// accept. Show the same generic message and alert on it internally.
case err != nil:
	// The lookup or the policy failed. Report the service as unavailable.
case result.Decision == password.RequireMFA:
	// The password is correct but the login is not complete.
default:
	// result.Decision == password.PasswordOnly: issue a session for result.Subject.
}
```

A password is 1 to 1024 bytes and is used exactly as supplied. It is never trimmed, normalized or truncated.

## Require a second factor

Pass a policy to decide, for each verified subject, whether the password is enough.

```go
policy := func(ctx context.Context, subject string) (password.Decision, error) {
	if needsMFA(ctx, subject) {
		return password.RequireMFA, nil
	}
	return password.PasswordOnly, nil
}
auth, err := password.New(lookup, policy)
```

`RequireMFA` means the login is incomplete. Verify a [TOTP code](/authlume/guides/totp/) or a [WebAuthn credential](/authlume/guides/webauthn/) for `result.Subject` before issuing a session. A policy error or any other decision fails the login.

## Algorithms

| Algorithm | Parameters | Record prefix |
| --- | --- | --- |
| `password.Argon2id` (default) | 19 MiB of memory, 2 passes, 1 thread | `v2$argon2id$m=19456,t=2,p=1$` |
| `password.PBKDF2SHA256` | HMAC-SHA-256, 600,000 iterations | `v1$pbkdf2-sha256$600000$` |

Both use a 16-byte random salt and a 32-byte key. The parameters are fixed: the verifier accepts only the exact format above and never reads a cost from the record.

To use PBKDF2, for example where FIPS-approved algorithms are required, select it when constructing the authenticator.

```go
auth, err := password.New(lookup, policy, password.WithAlgorithm(password.PBKDF2SHA256))
```

The package-level `password.Hash` always writes Argon2id. An application that passes `WithAlgorithm` must create records with `auth.Hash`.

## Timing and throttling

An unknown identifier and an invalid record spend the same derivation as an ordinary failed attempt, so response time does not show whether an identifier exists.

Argon2id uses about 19 MiB per derivation, including that dummy work. Limit login attempts per account and per client, and also limit how many verifications run at once.

## Migrate to another algorithm

By default the authenticator accepts only records of its configured algorithm, and any other record returns `ErrRecord`. To change the algorithm without resetting passwords, name the old one as well.

```go
auth, err := password.New(lookup, policy,
	password.WithAlgorithm(password.Argon2id),
	password.WithMigrationFrom(password.PBKDF2SHA256),
)
```

A successful `Authenticate` for an old record sets `result.Rehash`. Replace the record then.

```go
if result.Rehash {
	record, err := auth.Hash(secret)
	if err == nil {
		// In one transaction: lock the user's row, read the stored record again
		// and write the new one only if auth.NeedsRehash(stored) is still true.
		err = users.ReplacePasswordHash(ctx, result.Subject, record, auth.NeedsRehash)
	}
	if err != nil {
		log.Printf("password rehash failed: %v", err) // the login still succeeds
	}
}
```

Keep the following in mind.

- **Write with the lock.** Without it, a password change that happens between the verification and the write is overwritten with the old password.
- **`NeedsRehash` compares formats, not records.** It protects a concurrent password change only when that change wrote a record of the new algorithm. If that is not guaranteed, keep the record the lookup returned and write only if the stored record still equals it.
- **Use `auth.Hash`, not `password.Hash`.** The package-level function always writes Argon2id, which is wrong when the new algorithm is PBKDF2.
- **Replace as soon as the password is verified.** It can happen before the second factor completes, because it only re-encodes the same password.
- **Every attempt costs more while the option is set.** `Authenticate` performs one derivation per accepted algorithm on every path, so response time does not show which algorithm a record uses. Allow for the added cost in login throttling.

### Roll out across several instances

An instance without the option rejects records of the other algorithm, so switch in two steps.

1. Deploy every instance with the old algorithm as primary and the new one in `WithMigrationFrom`. Every instance now accepts both and still writes the old format.
2. Swap the two. Every instance now writes the new format.

To roll back, return to step 1. While instances of both steps are running, a record can move back and forth between the formats. Authentication keeps working throughout.

### Records that never migrate

A record is replaced only when its user signs in. Before removing the option, count the remaining records by calling `auth.NeedsRehash` for each one, or by matching the old record prefix in a query, and decide what happens to them, for example a forced password reset. Once the option is removed, those records return `ErrRecord`.

## Try the example

The [password and session example](https://github.com/i2bskn/authlume/tree/main/examples/web) runs a login over HTTPS on a loopback address. The [Quickstart](/authlume/getting-started/quickstart/) shows how to start it.
