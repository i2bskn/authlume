---
title: TOTP
description: Verify an enrolled authenticator code as a second factor after primary authentication.
---

The `totp` package verifies an RFC 6238 code for a subject that the application has already identified with a primary method. A code is consumed when it is accepted, so it works once.

The profile is fixed: six digits, HMAC-SHA-1, a 30-second period and the Unix epoch as T0. These are the settings every authenticator app supports. Because it needs HMAC-SHA-1, the package does not work in Go's FIPS 140-only mode.

Enrollment, recovery, rate limits and the decision to require this factor belong to the application.

## Verify a code

Implement `totp.Store` over the application's enrollments and create a verifier.

```go
verifier, err := totp.New(store, nil) // nil uses time.Now
if err != nil {
	return err
}
```

After the primary method succeeds and the policy requires a second factor, pass the verified subject and the submitted code.

```go
err := verifier.Verify(r.Context(), subject, code)
switch {
case err == nil:
	// The second factor is complete. Issue the session.
case errors.Is(err, totp.ErrInvalid):
	// Wrong code, a code that was already used, or no active enrollment.
case errors.Is(err, totp.ErrRecord):
	// The stored enrollment is invalid, for example a secret shorter than 20 bytes.
default:
	// The store failed.
}
```

The code must be exactly six ASCII digits, including any leading zero. Remove a space that the form allows between the two groups before calling `Verify`.

Limit attempts per account across logins: a six-digit code has only a million values. If issuing the session fails after a successful `Verify`, the code is already consumed, so start a fresh login with a newer code.

For a login that spans several requests, keep the verified subject and its purpose in an expiring, single-use, server-side transaction bound to the browser. Do not trust a subject that the browser sends back.

## Implement the store

A store holds one active enrollment per subject.

```go
type Store interface {
	// Load returns the active credential for subject, or ErrInvalid if absent.
	Load(ctx context.Context, subject string) (Credential, error)
	// Consume atomically checks that id is still active for subject and that
	// step is newer than any step used for this enrollment.
	Consume(ctx context.Context, subject, id string, step int64) error
}
```

`Consume` can be one conditional update that matches the subject and the active enrollment ID and requires the last used step to be null or smaller. Exactly one changed row means success, and anything else is `totp.ErrInvalid`.

```sql
UPDATE totp_enrollments
SET last_step = $3
WHERE subject = $1 AND id = $2 AND (last_step IS NULL OR last_step < $3)
```

- Give each new enrollment a fresh random secret of at least 20 bytes and an ID that is never reused.
- Protect the secrets at rest and return a stable snapshot from `Load`.
- Share the store between instances. Replay protection is only as wide as the store.
- Return a backend failure as an error distinct from `totp.ErrInvalid`.

## Time steps

By default the verifier accepts the code of the server's current 30-second step and of the step before it, which gives the user time to type. A code is therefore usable for up to 60 seconds.

To accept only the current step, pass an option.

```go
verifier, err := totp.New(store, nil, totp.WithCurrentStepOnly())
```

A code is then usable for at most 30 seconds. A code typed near the end of its step fails once the next step begins, and a device whose clock is slow enough to still show the previous step always fails.

In both modes a step ahead of the server is never accepted. If a device clock is fast and already shows the next step, that code works when the server reaches the step. Keep the server clock synchronized.

## Migrate an existing enrollment

The package requires at least 20 decoded bytes per secret. A legacy 16-character Base32 secret decodes to 10 bytes, so `Verify` returns `totp.ErrRecord` for it. Before switching such an account over, use the application's verified enrollment or recovery flow to register and confirm a fresh secret of at least 20 bytes with the user's authenticator.

## Try the example

The [password and TOTP example](https://github.com/i2bskn/authlume/tree/main/examples/totp) runs the flow over HTTPS on a loopback address. Its README shows how to start it.
