# Sign in with OpenID Connect

This HTTPS example links one operator-approved external identity to a local account. To run it, register a confidential web client with the exact callback `https://127.0.0.1:8443/callback`. Use a provider on a separate trusted HTTPS host that supports discovery, RS256 ID tokens, the authorization code flow, client_secret_basic and S256 PKCE. RS256 is the default. Set `oidc.Config.SigningAlgs` to choose among RS256, PS256, ES256 and EdDSA; an ID token signed with an algorithm left off the list is rejected.

The client accepts ID tokens with one audience (the registered client ID) and integer Unix timestamps. If discovery advertises an authorization response issuer parameter, the callback must include it.

Set `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` from your registration. Set `OIDC_SUBJECT` to the exact subject assigned by that issuer for this client, and `LOCAL_ACCOUNT` to the corresponding opaque local account ID. Keep the client secret server-side. For a local test certificate and key, run the following from the repository root.

```sh
certdir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "$certdir/key.pem" -out "$certdir/cert.pem"
go run ./examples/oidc -cert "$certdir/cert.pem" -key "$certdir/key.pem"
```

Trust the local test certificate and open <https://127.0.0.1:8443/>. Sign in with the provider. The sample requires MFA by default and displays “Additional authentication required” after account resolution. To explicitly trust a provider guarantee, set `OIDC_ACCEPTED_ACR` to the exact authentication class your configured issuer defines as sufficient. The sample also requires a signed `auth_time` less than five minutes old. With required MFA and an accepted ACR configured, the example sends `acr_values` and `max_age=300` to the provider. A missing or stale signed `auth_time` fails the protocol check. The application then checks the actual ACR before issuing a session. It requests only the `openid` scope. To exercise a policy that permits this account to log in with OIDC alone, run with `-require-mfa=false`. A completed login redirects to the account page.

## Integrate with an application

1. Construct one `oidc.Client` per trusted issuer/client. Configure distinct registered callback URIs for different issuers. Mount `Begin` (or `BeginWithOptions` for application-selected constraints) on a CSRF-protected HTTPS POST route and `Complete` at the configured GET callback. Protect the start route even before a session exists. Keep callback URLs, codes, cookies, ID tokens and transaction secrets out of logs. Redirect promptly after success.
2. On successful completion, look up `Identity.ID` by the exact, case-sensitive pair of issuer and subject. A matching email, including a verified email, grants no account link. Unknown pairs require an explicit policy. An app may decline, provision a new account under its enrollment rules, or link to a specific existing account after fresh local authentication and explicit confirmation bound to that target and browser. Persist the local account and unique external binding atomically. On a uniqueness conflict, re-read and verify the winning binding before proceeding. The sample uses a preauthorized pair and declines all others.
3. Apply the local account's current authentication policy. For required MFA, check the signed `Identity.Assurance` against the exact issuer's documented guarantee and your freshness requirements, or complete your own additional authentication. Bind any pending challenge to the resolved local account and browser. Only the successful branch calls `session.Issue`. The OIDC package can also be used with other session managers.
4. Apply application-specific login rate limits. The loopback example allows five login starts per minute across the process and returns HTTP 429 with `Retry-After` once that budget is used. Production applications choose a budget and sharing strategy appropriate for their users. The example's bounded memory store serves one process. Provide a shared `oidc.Store` with atomic one-time consumption, confidentiality and expiry cleanup for multiple instances. Each browser/client has one active sign-in at a time. Keep mutually untrusted applications on separate hosts.

Run `go test -race ./oidc ./examples/oidc` to drive the HTTPS flow with a local signed test issuer.

## Authorization requests and operational errors

`BeginWithOptions` accepts an ordered list of ACR preferences, a single OIDC prompt value, and an optional maximum age in seconds. Use trusted application policy for these options. A requested age requires the exact signed `auth_time` claim. A positive age is checked at callback time, and zero requires authentication at or after the request started (to the second). An ACR preference or login prompt alone supplies no proof of MFA. Shared transaction stores must round-trip `StartedAt` and `MaxAgeSeconds`, including the distinction between absent and zero. Upgrade all callback handlers and stores before enabling freshness requests.

Discovery uses the startup context. The client refreshes signing keys through a shared cache using its own time-bounded HTTP client. Invalid credentials and rejected claims return `oidc.ErrInvalid`. Discovery and JWKS GET responses are limited to 1 MiB. A token service failure, or a network error, oversized document or non-200 response fetching keys, returns `oidc.ErrProviderUnavailable`. A malformed key document returned with HTTP 200 can produce an untyped upstream verification failure, which is handled as an invalid login. The caller's canceled context remains distinguishable. The token's `nbf` is enforced from the stated second; keep service clocks synchronized.

An unmatched or failed transaction lookup preserves the browser cookie so another pending sign-in can finish. A new login replaces it and it expires after ten minutes. If a completed login encounters a malformed application session cookie, use the example's reset form, then sign in again.
