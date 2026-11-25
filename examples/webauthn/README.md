# Password and WebAuthn over HTTPS

This standard `net/http` example requires a password and a registered platform passkey or roaming security key (such as a WebAuthn-capable YubiKey) for its single demo account. The independent `github.com/i2bskn/authlume/webauthn` package can also verify a second factor after another primary method has identified a local application subject. The example then adds a passkey to the signed-in account and signs in with that passkey alone, without a username.

## Run locally

Use Go 1.25 or later, OpenSSL, a WebAuthn authenticator and a browser supporting the WebAuthn JSON conversion methods. Generate a localhost certificate, a demo password and a separate random first-enrollment code. Use the code only for this run.

```bash
certdir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout "$certdir/key.pem" -out "$certdir/cert.pem"
read -rs -p 'Demo password: ' AUTHLUME_PASSWORD
echo
export AUTHLUME_PASSWORD
export AUTHLUME_ENROLLMENT_CODE=$(openssl rand -base64 32)
# Copy this one-time setup value for the registration form.
printf '%s\n' "$AUTHLUME_ENROLLMENT_CODE"
go run ./examples/webauthn -cert "$certdir/cert.pem" -key "$certdir/key.pem"
```

Trust the demo certificate locally and open <https://localhost:8445/>. Use the hostname exactly as shown. With username `demo`, your password and the value of `AUTHLUME_ENROLLMENT_CODE`, choose **Register first key** and complete the browser prompt. Registration leaves you signed out. Enter the username and password again, choose **Sign in** and use the registered key. Success opens `/protected`.

To try passkey sign-in without a username:

1. Within five minutes of signing in, return to <https://localhost:8445/> and choose **Add a passkey**. Use a different authenticator or passkey provider from the first key, because the browser excludes an authenticator that is already registered. The authenticator must verify you with a PIN or biometric check.
2. Choose **Sign out**.
3. Choose **Sign in with a passkey** and pick the new passkey. Success opens `/protected`.

Five begin requests per minute share one budget for the demo account, including unauthenticated passkey sign-in. Adding a passkey is authorized by the fresh session and does not consume the budget. Do not copy this limit to production; limit per account and per client instead. Pending transactions expire after five minutes. Each finish consumes one transaction. Restarting this in-memory demo discards credentials, transactions and sessions and reopens first enrollment. Use a new code on restart. A production account needs durable enrollment state, even when its last key is lost or revoked.

## Integrate with an application

Construct a verifier with `webauthn.New(origin, displayName, credentials, ceremonies)`. Configure a fixed HTTPS origin and use a stable opaque local subject of 1–64 bytes. Keep email addresses and other personal information out of the subject. Return the options to the browser as JSON. Put the returned handle in a cookie with Secure, HttpOnly, SameSite and host-only scope. Pass it back to the matching Finish call, which returns the subject of the ceremony. The ceremony store holds pending ceremonies for five minutes and consumes each one once. A record authorizes its subject, so protect the store's integrity and keep records confidential. `webauthn.NewMemoryCeremonyStore` serves a single process. Multiple instances need a shared `CeremonyStore`.

- **Registration.** Authorize enrollment before calling `BeginRegistration`. For an account with MFA, require fresh primary authentication plus an existing verified factor or the application's verified recovery procedure. For first enrollment, the demo requires a separate operator-provisioned code and enforces the first-key condition in its atomic insert. Pass the handle and browser credential JSON to `FinishRegistration`. Only a successful insert activates the key.
- **Verification.** Apply the application's MFA policy after primary authentication. If WebAuthn is required, call `BeginVerification` with that verified subject. Complete `FinishVerification` with the handle and use the subject it returns. The verifier restricts the assertion to that user's enrolled credentials, checks user presence, and accepts keys with or without local PIN/biometric verification. Registration permits both built-in and roaming authenticators and prefers discoverable credentials when supported. A key registered this way is a second factor only: even when it is discoverable, it never signs in on its own. The verifier rejects non-increasing signature counters when either counter is nonzero and returns `webauthn.ErrCloned`. The application may warn about or revoke that key. A successful conditional credential update completes the second factor. Only then may the application call `sessions.Issue`. A key enrolled as a passkey also works as a second factor.
- **Passkey sign-in.** This is optional. An application that never calls the passkey methods keeps the second-factor behavior above. Call `BeginPasskeyRegistration` only for a subject that reauthenticated recently and that the application allows to add a passkey; the demo requires a session authenticated within five minutes at both begin and finish. The options require a discoverable credential and user verification on a built-in or roaming authenticator. Compare the subject returned by `FinishPasskeyRegistration` with the session that authorized it. `BeginPasskeyLogin` takes no subject and `FinishPasskeyLogin` returns the subject named by the authenticator after checking the signature, user verification and the signature counter. It accepts only credentials enrolled through `FinishPasskeyRegistration`. An authenticator may still create a non-discoverable key, which cannot sign in alone, so complete one passkey sign-in before counting a new passkey as a usable sign-in method.
- **Switching a second-factor key.** No call turns a second-factor key into a passkey. Enroll it again with `BeginPasskeyRegistration`. The same authenticator is excluded until the application deletes the old key. Deleting the only factor first locks the user out if the new enrollment fails, so do this while another verified factor remains, or enroll a different authenticator as the passkey.
- **Storage.** Persist the entire public credential, its subject and a fresh revision. Enforce a unique credential ID across accounts in the RP. Use a conditional update on the active subject, credential ID and original revision. Require exactly one affected row and rotate the revision on every write, including zero-counter assertions. Concurrent or stale ceremonies may require a new login. Enforce account enrollment preconditions in the same transaction as the insert.
- **Lost authenticators.** Keep replacement and revocation behind the application's existing verified recovery or factor-management flow. Bind recovery authorization to the subject and intended change, recheck that it is current when committing, delete the subject's outstanding ceremonies from the `CeremonyStore` (`Revoke` on `MemoryCeremonyStore`), and revoke affected sessions under application policy. A password reset, a cleared session cookie or an empty credential list does not establish recovery authorization. Deletion does not stop a Finish whose ceremony was already taken, so recheck enrollment authorization as an `Insert` precondition in the same transaction. This demo has no replacement or recovery route.

User management screens and APIs, invitations, and decisions about who may act on an account belong to the consuming application. The application owns the decision to accept TOTP or other factors and any requirement for MFA.

For passkey sign-in the application also owns the following:

- **Reauthentication.** Require recent reauthentication before adding or deleting a passkey, and never let the user delete the last usable sign-in method. The package has no deletion call; the demo shows only the adding side.
- **Account state.** Passkey sign-in has no first-factor step where a suspended or locked account would be stopped. Check the returned subject's account state before issuing a session, or have `Store.Load` return an empty list for a subject that may not sign in.
- **MFA policy.** Decide whether a passkey sign-in with user verification satisfies the application's MFA requirement, and whether to issue the regular session at all.
- **Limits on unauthenticated begins.** `BeginPasskeyLogin` is reachable before authentication. Limit it per client and also cap it overall. Ceremonies live for five minutes, so about 14 begins per second fill the 4096 entries of `MemoryCeremonyStore`, and second-factor begins that share the store then fail too. A passkey login ceremony has no subject, so subject-wide revocation does not remove it; revocation takes effect when Finish reloads the credentials.
- **Subject lookup.** `Store.Load` receives an unauthenticated subject during passkey sign-in. Match it byte for byte and return an empty list for an unknown value. Failures are indistinguishable by error, but timing may differ between known and unknown subjects, so do not use guessable subjects.
- **Guiding the user.** The browser's picker may offer a discoverable key that was registered as a second factor only. Choosing it fails, so send the user to the regular sign-in on failure.
- **Recovery.** Losing the only passkey must lead to the application's verified recovery procedure.
