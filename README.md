# authlume

Authlume provides independently importable packages for Go 1.25 and later. The password and server-side session packages use the standard library. The [OpenID Connect login example](examples/oidc) uses the optional `oidc` package, which depends on go-oidc and oauth2. The [WebAuthn example](examples/webauthn) uses the optional `webauthn` package, which depends on go-webauthn.

## From a password to a session

Serve the login page and the rest of the browser flow over **HTTPS**. Apply **CSRF protection to every state-changing browser route**, including login before a session exists, activity updates, reauthentication, cookie recovery and logout. Register mutations as POST handlers. For Go 1.25+, the sample protects the whole router with `http.NewCrossOriginProtection().Handler(mux)` and serves that handler over TLS.

Implement a `password.Lookup` function that loads an opaque subject ID and a hash created by `password.Hash`. Return `password.ErrNotFound` for an unknown identifier. The application owns password enrollment, login throttling and account policy.

```go
auth, err := password.New(lookup, nil) // password-only policy
if err != nil {
    return err
}
sessions, err := session.New(session.NewMemoryStore(), session.Config{})
if err != nil {
    return err
}
```

In the login handler, call `auth.Authenticate(r.Context(), identifier, secret)`, handle its error, then inspect the result. Call `sessions.Issue(w, r, result.Subject)` only when the login policy is complete. To require MFA, pass a policy function to `password.New` that returns `password.RequireMFA` for the relevant subject. At that point the app must complete its additional verification before issuing a session. The [sample handler](examples/web) shows both branches.

## Optional second factors

After the primary method identifies a local subject, the application can verify an enrolled [TOTP code](examples/totp) or a [WebAuthn credential](examples/webauthn). The WebAuthn example covers authorized first enrollment, browser-bound verification, and issuing the regular session after both factors succeed. The application owns enrollment authorization, MFA requirements and account recovery.

## Optional passkey sign-in

The `webauthn` package can also sign a user in with a passkey alone, without a username. The application opts in by calling `BeginPasskeyRegistration` and `FinishPasskeyRegistration` for a recently reauthenticated subject, then `BeginPasskeyLogin` and `FinishPasskeyLogin`. These require a discoverable credential and user verification, on a platform passkey or a security key with a PIN or biometric check. A key registered as a second factor is never promoted to standalone sign-in; enroll it again as a passkey after the application deletes the old key, while another verified factor remains. A successful `FinishPasskeyLogin` returns the subject and the application decides whether to issue a session.

The application owns reauthentication before adding or deleting a passkey, keeping the last usable sign-in method, the account state check before issuing a session, the decision to treat a user-verified passkey sign-in as MFA, per-client and overall limits on the unauthenticated begin, and recovery. The [WebAuthn example](examples/webauthn) shows the flow and lists these duties.

## Session policy

| Setting | OSS default | Example i2 application profile |
| --- | --- | --- |
| Idle lifetime | 24 hours | 7 days |
| Absolute lifetime | 7 days | 30 days |

Each zero-valued timeout uses its own OSS default. Set `session.Config{Idle: 7 * 24 * time.Hour, Absolute: 30 * 24 * time.Hour}` in an application to use the i2 profile. A protected handler calls `sessions.Read(r)` to validate the cookie against server state. Polling also uses Read. Only a route representing an intentional user action calls `sessions.Touch(r)` to advance idle expiry. The absolute deadline always applies.

Use `sessions.RequireFresh(r, maxAge)` before a sensitive action. When fresh authentication is needed, verify the intended subject under the current policy and issue a new session. Call `sessions.Logout(w, r)` to revoke the server-side session and clear its cookie. The in-memory store is for one process and loses its sessions on restart. For shared sessions, implement the atomic `session.Store` contract described in the [design](docs/phase-one.md).

## Apps sharing a host

Set `session.Config{CookieName: "__Host-inventory"}` to give an app its own cookie. The empty setting uses `__Host-authlume`. Choose a distinct, valid HTTP cookie name with the exact `__Host-` prefix and a nonempty suffix. Use a separate store or store namespace for each app with independent authentication. Host cookies travel across paths and ports on the same host. Use separate hosts for mutually untrusted apps.

## Recover an unreadable cookie

When login or logout rejects an old-format or ambiguous session cookie, offer an explicit recovery form. Its CSRF-protected POST handler calls `sessions.ResetInvalidCookie(w, r)`, then redirects to sign-in on success. This clears the app’s host-only cookie at `Path=/`. The user signs in again under the current authentication policy. Server records survive a browser reset until expiry or explicit revocation.

If the method returns `session.ErrCookieWellFormed`, use the normal logout flow. If a legacy browser cookie with a different path or domain persists, remove that specific cookie in browser settings. The [sample handler](examples/web/main.go) includes the recovery form and route.

## Run the HTTPS sample

Generate a temporary localhost certificate, set a demo password, and run from the repository root. This example uses Bash and OpenSSL.

```bash
certdir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "$certdir/key.pem" -out "$certdir/cert.pem"
read -rs -p 'Demo password: ' AUTHLUME_PASSWORD
echo
export AUTHLUME_PASSWORD
go run ./examples/web -cert "$certdir/cert.pem" -key "$certdir/key.pem"
```

Open <https://127.0.0.1:8443/> with the temporary certificate trusted for this demo. Sign in as `demo`, visit the protected page, then log out. To run with an app-specific cookie, add `-cookie-name __Host-inventory`. For a short expiry run, add `-idle 5s`. Sign in, wait five seconds without an activity POST, then reload the protected page. For the MFA decision path, add `-require-mfa` and sign in again. This sample stops at the second-factor requirement.

Run `go test -race ./...` for package tests and the HTTPS handler flow. Run `go vet ./...` for static checks.
