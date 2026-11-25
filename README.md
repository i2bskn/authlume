# authlume

Authlume provides password authentication and server-side Web sessions for Go 1.25 and later. Both packages use the standard library. Use either package independently or connect them in an application handler.

## From a password to a session

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

## Session policy

| Setting | OSS default | Example i2 application profile |
| --- | --- | --- |
| Idle lifetime | 24 hours | 7 days |
| Absolute lifetime | 7 days | 30 days |

Each zero-valued timeout uses its own OSS default. Set `session.Config{Idle: 7 * 24 * time.Hour, Absolute: 30 * 24 * time.Hour}` in an application to use the i2 profile. A protected handler calls `sessions.Read(r)` to validate the cookie against server state. Polling also uses Read. Only a route representing an intentional user action calls `sessions.Touch(r)` to advance idle expiry. The absolute deadline always applies.

Use `sessions.RequireFresh(r, maxAge)` before a sensitive action. When fresh authentication is needed, verify the intended subject under the current policy and issue a new session. Handle logout with `sessions.Logout(w, r)` on a POST endpoint with cross-origin request protection. Deploy with HTTPS. The in-memory store is for one process and loses its sessions on restart. For shared sessions, implement the atomic `session.Store` contract described in the [design](docs/phase-one.md).

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

Open <https://127.0.0.1:8443/> with the temporary certificate trusted for this demo. Sign in as `demo`, visit the protected page, then log out. For a short expiry run, add `-idle 5s`. Sign in, wait five seconds without an activity POST, then reload the protected page. For the MFA decision path, add `-require-mfa` and sign in again. This sample stops at the second-factor requirement.

Run `go test -race ./...` for package tests and the HTTPS handler flow. Run `go vet ./...` for static checks.
