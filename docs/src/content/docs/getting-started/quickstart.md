---
title: Quickstart
description: Verify a password and issue a server-side session, then run the HTTPS sample.
---

## From a password to a session

Serve the login page and the rest of the browser flow over **HTTPS**. Apply **CSRF protection to every state-changing browser route**, including login before a session exists, activity updates, reauthentication, cookie recovery and logout. Register mutations as POST handlers. For Go 1.25+, the sample protects the whole router with `http.NewCrossOriginProtection().Handler(mux)` and serves that handler over TLS.

Implement a `password.Lookup` function that loads an opaque subject ID and a hash created by `auth.Hash`, the method of the configured authenticator. Return `password.ErrNotFound` for an unknown identifier. The application owns password enrollment, login throttling and account policy.

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

In the login handler, call `auth.Authenticate(r.Context(), identifier, secret)`, handle its error, then inspect the result. Call `sessions.Issue(w, r, result.Subject)` only when the login policy is complete. To require MFA, pass a policy function to `password.New` that returns `password.RequireMFA` for the relevant subject. At that point the app must complete its additional verification before issuing a session. The [sample handler](https://github.com/i2bskn/authlume/tree/main/examples/web) shows both branches.

Choosing the password algorithm and migrating records between algorithms are covered in [Passwords](/authlume/guides/password/).

## Add a second factor

After the primary method identifies a local subject, the application can verify an enrolled [TOTP code](/authlume/guides/totp/) or a [WebAuthn credential](/authlume/guides/webauthn/). The [WebAuthn example](https://github.com/i2bskn/authlume/tree/main/examples/webauthn) covers authorized first enrollment, browser-bound verification, and issuing the regular session after both factors succeed. The application owns enrollment authorization, MFA requirements and account recovery.

## Run the HTTPS sample

Clone the repository, generate a temporary localhost certificate, set a demo password, and run the sample from the repository root. This example uses Bash and OpenSSL.

```bash
git clone https://github.com/i2bskn/authlume.git
cd authlume
```

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

## Next steps

- [Passwords](/authlume/guides/password/): algorithms, errors and migrating records
- [Sessions](/authlume/guides/sessions/): lifetimes, fresh authentication and a shared store
- [TOTP](/authlume/guides/totp/) and [WebAuthn and passkeys](/authlume/guides/webauthn/): second factors
- [OpenID Connect](/authlume/guides/oidc/) and [MCP OAuth](/authlume/guides/mcp-oauth/)
