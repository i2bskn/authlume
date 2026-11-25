# Password and WebAuthn over HTTPS

This standard `net/http` example requires a password and a registered platform passkey or roaming security key (such as a WebAuthn-capable YubiKey) for its single demo account. The independent `github.com/i2bskn/authlume/webauthn` package can also verify a second factor after another primary method has identified a local application subject.

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

Five begin requests per minute share one budget for the demo account. Do not copy this limit to production; limit per account and per client instead. Pending transactions expire after five minutes. Each finish consumes one transaction. Restarting this in-memory demo discards credentials, transactions and sessions and reopens first enrollment. Use a new code on restart. A production account needs durable enrollment state, even when its last key is lost or revoked.

## Integrate with an application

Construct a verifier with `webauthn.New(origin, displayName, credentials, ceremonies)`. Configure a fixed HTTPS origin and use a stable opaque local subject of 1–64 bytes. Keep email addresses and other personal information out of the subject. Return the options to the browser as JSON. Put the returned handle in a cookie with Secure, HttpOnly, SameSite and host-only scope. Pass it back to the matching Finish call, which returns the subject of the ceremony. The ceremony store holds pending ceremonies for five minutes and consumes each one once. A record authorizes its subject, so protect the store's integrity and keep records confidential. `webauthn.NewMemoryCeremonyStore` serves a single process. Multiple instances need a shared `CeremonyStore`.

- **Registration.** Authorize enrollment before calling `BeginRegistration`. For an account with MFA, require fresh primary authentication plus an existing verified factor or the application's verified recovery procedure. For first enrollment, the demo requires a separate operator-provisioned code and enforces the first-key condition in its atomic insert. Pass the handle and browser credential JSON to `FinishRegistration`. Only a successful insert activates the key.
- **Verification.** Apply the application's MFA policy after primary authentication. If WebAuthn is required, call `BeginVerification` with that verified subject. Complete `FinishVerification` with the handle and use the subject it returns. The verifier restricts the assertion to that user's enrolled credentials, checks user presence, and accepts keys with or without local PIN/biometric verification. Registration permits both built-in and roaming authenticators and prefers discoverable credentials when supported. Even a discoverable passkey is used only after primary authentication here. It rejects non-increasing signature counters when either counter is nonzero and returns `webauthn.ErrCloned`. The application may warn about or revoke that key. A successful conditional credential update completes the second factor. Only then may the application call `sessions.Issue`. The verifier supplies neither account discovery nor a standalone login endpoint.
- **Storage.** Persist the entire public credential, its subject and a fresh revision. Enforce a unique credential ID across accounts in the RP. Use a conditional update on the active subject, credential ID and original revision. Require exactly one affected row and rotate the revision on every write, including zero-counter assertions. Concurrent or stale ceremonies may require a new login. Enforce account enrollment preconditions in the same transaction as the insert.
- **Lost authenticators.** Keep replacement and revocation behind the application's existing verified recovery or factor-management flow. Bind recovery authorization to the subject and intended change, recheck that it is current when committing, delete the subject's outstanding ceremonies from the `CeremonyStore` (`Revoke` on `MemoryCeremonyStore`), and revoke affected sessions under application policy. A password reset, a cleared session cookie or an empty credential list does not establish recovery authorization. Deletion does not stop a Finish whose ceremony was already taken, so recheck enrollment authorization as an `Insert` precondition in the same transaction. This demo has no replacement or recovery route.

User management screens and APIs, invitations, and decisions about who may act on an account belong to the consuming application. The application owns the decision to accept TOTP or other factors and any requirement for MFA. Use a separate application policy and flow for username-less sign-in.
