---
title: WebAuthn and passkeys
description: Verify a security key or passkey as a second factor, or sign in with a passkey alone.
---

The `webauthn` package verifies WebAuthn in two ways:

- **As a second factor** for a subject that a primary method has already identified. This works with built-in passkeys and with roaming security keys such as a YubiKey.
- **As a standalone passkey sign-in** without a username. This is optional: an application that never calls the passkey methods keeps the second-factor behavior only.

The application authorizes enrollment and owns MFA policy, account state, browser binding, recovery, rate limits and the issuing of sessions.

## Set up

```go
keys, err := webauthn.New(
	"https://app.example.com",          // the fixed HTTPS origin of the application
	"Example App",                      // the name the authenticator shows
	credentials,                        // the application's webauthn.Store
	webauthn.NewMemoryCeremonyStore(),  // pending ceremonies, for one process
)
if err != nil {
	return err
}
```

Use a stable opaque subject of 1 to 64 bytes, and keep email addresses and other personal data out of it.

Every flow has a Begin call and a Finish call. Begin returns options for the browser and a **handle** for the pending ceremony.

1. Return the options to the browser as JSON and pass them to `navigator.credentials.create` or `navigator.credentials.get`.
2. Put the handle in a cookie that is `Secure`, `HttpOnly`, `SameSite` and host-only. The handle binds the ceremony to this browser.
3. Pass the handle and the browser's response to the matching Finish call. It returns the subject of the ceremony.

A ceremony lives for five minutes and is consumed by its Finish call, even when that call fails.

## Second factor

### Register a key

Authorize the enrollment before calling `BeginRegistration`. For an account that already has MFA, require fresh primary authentication plus an existing verified factor, or the application's verified recovery procedure.

```go
options, handle, err := keys.BeginRegistration(r.Context(), subject, userName)
// ... browser ...
subject, err := keys.FinishRegistration(r.Context(), handle, response)
```

Only a successful insert in the store activates the key. Registering a key does not sign the user in.

### Verify a key

After the primary method succeeds and the policy requires a second factor:

```go
options, handle, err := keys.BeginVerification(r.Context(), subject)
// ... browser ...
verified, err := keys.FinishVerification(r.Context(), handle, response)
switch {
case err == nil:
	// The second factor is complete for the returned subject. Issue the session.
case errors.Is(err, webauthn.ErrCloned):
	// The signature counter did not increase. Fail the login, and consider
	// warning the user or revoking the key.
case errors.Is(err, webauthn.ErrInvalid):
	// The ceremony cannot complete. Start the sign-in again.
}
```

The verifier restricts the assertion to that subject's enrolled keys and checks user presence. It accepts keys with or without a local PIN or biometric check. A key registered this way is a second factor only: even when it is discoverable, it never signs in on its own.

## Passkey sign-in

Passkey sign-in requires a discoverable credential and user verification, on a platform passkey or on a security key with a PIN or biometric check.

### Add a passkey

Call `BeginPasskeyRegistration` only for a subject that reauthenticated recently and that the application allows to add a passkey. Check this at both Begin and Finish.

```go
options, handle, err := keys.BeginPasskeyRegistration(r.Context(), state.Subject, userName)
// ... browser ...
subject, err := keys.FinishPasskeyRegistration(r.Context(), handle, response)
if err == nil && subject != state.Subject {
	// The ceremony belongs to another session. Reject it.
}
```

An authenticator may still create a non-discoverable key, which cannot sign in alone. Complete one passkey sign-in before counting a new passkey as a usable sign-in method.

### Sign in

```go
options, handle, err := keys.BeginPasskeyLogin(r.Context()) // no subject
// ... browser ...
subject, err := keys.FinishPasskeyLogin(r.Context(), handle, response)
```

`FinishPasskeyLogin` returns the subject named by the authenticator after checking the signature, user verification and the signature counter. It accepts only credentials enrolled through `FinishPasskeyRegistration`. The application then decides whether to issue a session.

A passkey also works as a second factor through `BeginVerification`.

### Switch a second-factor key to a passkey

No call promotes a second-factor key. Enroll it again with `BeginPasskeyRegistration`. The browser excludes an authenticator that is already registered, so the application has to delete the old key first. Deleting the only factor locks the user out if the new enrollment fails, so do this while another verified factor remains, or enroll a different authenticator as the passkey.

## Implement the stores

### Credentials

`webauthn.Store` holds the public credentials. It is scoped to one relying party.

- **Persist the whole credential**, its subject and a fresh version. Its stored form is go-webauthn's JSON encoding, so check compatibility when upgrading that dependency.
- **Keep credential IDs unique** across all accounts.
- **Update conditionally** on the subject, the credential ID and the version that was read. Require exactly one affected row and assign a new version on every write, including for keys whose counter stays zero.
- **Enforce enrollment preconditions in the insert's transaction**, for example "this is the account's first key".
- **Keep the passkey flag** that `Insert` receives. Treat rows stored before the flag existed as second-factor keys.
- **Match the subject byte for byte in `Load`** and return an empty list for an unknown subject. Passkey sign-in passes a value that is not yet authenticated.

Concurrent or stale ceremonies can fail on the version check. The user then starts again.

### Ceremonies

`webauthn.NewMemoryCeremonyStore` serves a single process and holds 4096 pending ceremonies. Several instances need a shared `CeremonyStore` that returns each ceremony once, rejects expired ones and can delete all ceremonies of a subject. A ceremony record authorizes its subject, so protect the store's integrity and keep its records confidential.

## What the application owns

- **Who may enroll.** User management screens and APIs, invitations and the decision about who may act on an account.
- **Reauthentication.** Require it before adding or deleting a passkey. The package has no deletion call.
- **The last sign-in method.** Never let a user delete it.
- **Account state.** Passkey sign-in has no first-factor step where a suspended account would be stopped. Check the returned subject's state before issuing a session, or have `Store.Load` return an empty list for a subject that may not sign in.
- **MFA policy.** Decide whether a passkey sign-in with user verification satisfies the application's MFA requirement.
- **Limits on unauthenticated begins.** `BeginPasskeyLogin` is reachable before authentication. Limit it per client and overall. About 14 begins per second fill the in-memory ceremony store, and second-factor begins that share it then fail too.
- **Guessable subjects.** Failures are indistinguishable by error, but timing may differ between a known and an unknown subject during passkey sign-in. Do not use guessable subjects.
- **Guiding the user.** The browser's picker may offer a discoverable key that was registered as a second factor only. Choosing it fails, so send the user to the regular sign-in on failure.
- **Lost authenticators.** Keep replacement and revocation behind the application's verified recovery flow. A password reset, a cleared session cookie or an empty credential list does not establish recovery authorization. When revoking, delete the subject's pending ceremonies as well (`Revoke` on `MemoryCeremonyStore`) and revoke affected sessions. Deleting does not stop a Finish whose ceremony was already taken, so recheck the authorization as a precondition of `Insert`.

## Try the example

The [password and WebAuthn example](https://github.com/i2bskn/authlume/tree/main/examples/webauthn) runs both flows over HTTPS on a loopback address, including the browser-side JavaScript. Its README shows how to start it.
