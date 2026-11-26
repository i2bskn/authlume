---
title: OpenID Connect
description: Sign a browser in with an OpenID Connect issuer and link the verified identity to a local account.
---

The `oidc` package signs a browser in with one configured OpenID Connect issuer, using the authorization code flow with PKCE, and returns a verified external identity. The application owns account linking, enrollment, additional authentication and the issuing of sessions.

## Provider requirements

- Discovery, on a separate trusted HTTPS host
- The authorization code flow with S256 PKCE
- A confidential client that authenticates with `client_secret_basic`
- ID tokens with one audience, the registered client ID, and integer Unix timestamps
- ID tokens signed with RS256, unless [`SigningAlgs`](#signature-algorithms) says otherwise

If discovery advertises the authorization response issuer parameter, the callback must include it.

## Set up

```go
client, err := oidc.New(ctx, oidc.Config{
	Issuer:       "https://id.example.com",
	ClientID:     clientID,
	ClientSecret: clientSecret,
	RedirectURL:  "https://app.example.com/callback",
}, oidc.NewMemoryStore())
if err != nil {
	return err
}
```

Construct one client per issuer and registration, and reuse it across requests. Register a distinct callback URL for each issuer. `RedirectURL` is a dedicated HTTPS URL without a query string.

`oidc.NewMemoryStore` serves one process. Several instances need a shared `oidc.Store` whose `Take` consumes a pending login exactly once, keeps its records confidential and cleans up expired ones.

## Start and complete a login

Mount `Begin` on a CSRF-protected HTTPS POST route and `Complete` at the registered GET callback. Protect the start route even before a session exists.

```go
mux.HandleFunc("POST /login/oidc", func(w http.ResponseWriter, r *http.Request) {
	if err := client.Begin(w, r); err != nil {
		http.Error(w, "Sign-in unavailable", http.StatusServiceUnavailable)
	}
})

mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
	identity, err := client.Complete(w, r)
	switch {
	case errors.Is(err, oidc.ErrInvalid):
		// The login is invalid or incomplete. Offer to start again.
		return
	case err != nil:
		// oidc.ErrProviderUnavailable, a store failure or a canceled request.
		return
	}
	// identity.ID is the verified pair of issuer and subject.
})
```

Keep callback URLs, codes, cookies, ID tokens and transaction secrets out of logs, and redirect promptly after success.

## Link the identity to an account

Look up `identity.ID` by the exact, case-sensitive pair of issuer and subject.

- **A matching email grants nothing.** Not even a verified one links an external identity to an existing account.
- **An unknown pair needs an explicit policy.** The application may decline, create a new account under its enrollment rules, or link to a specific existing account after fresh local authentication and a confirmation bound to that account and browser.
- **Persist the binding atomically** with a uniqueness constraint. On a conflict, read the winning binding again before proceeding.

## Apply the account's policy

Apply the local account's current authentication policy before issuing a session. When the account requires MFA, either complete the application's own second factor, or accept the provider's assurance explicitly.

```go
a := identity.Assurance
if a.ACR == acceptedACR && time.Since(a.AuthTime) < 5*time.Minute {
	// The issuer's documented guarantee for this ACR, and its freshness,
	// satisfy the local requirement.
}
```

The presence of a claim proves nothing by itself. Check the signed value against what this exact issuer documents for it. Only the branch that satisfies the policy calls `sessions.Issue`.

## Read other claims

List additional scopes in `Config.Scopes` and read the claims of the verified ID token from `identity.Claims`. `openid` is always requested and is not listed.

```go
client, err := oidc.New(ctx, oidc.Config{
	// ...
	Scopes: []string{"email"},
}, store)

// After a successful Complete:
email, ok := identity.Claims.Text("email")
verified, isBool := identity.Claims.Bool("email_verified")
if !ok || !isBool || !verified {
	// This issuer did not assert a verified address. Decline, or fall back to
	// the application's own verification.
}
```

- `Text` and `Bool` return a value only when the claim has that JSON type. The string `"true"` is not true. Check both results of `Bool`.
- Read any other claim from `identity.Claims[name]` with `json.Unmarshal`. Decoding into a struct folds the case of field names and lets `null` through, so decode a single value, not the whole map into a struct.
- Claims come from the ID token only. The package does not call the UserInfo endpoint, so a provider that returns a claim only there does not supply it. It does not send the `claims` request parameter.
- Scopes only change what the ID token contains. The access token is discarded, `offline_access` is refused, and the list is not compared with the provider's metadata: a scope the provider rejects makes every login fail with `oidc.ErrInvalid`.
- What a claim means depends on the issuer. Check what this exact issuer guarantees for `email_verified`, and read issuer-specific claims such as Google's `hd` the same way.
- The rule in [Link the identity to an account](#link-the-identity-to-an-account) is unchanged: a matching address never links an identity to an existing account. Use claims to decide whether to accept an unknown issuer and subject pair, at the first sign-in. On later sign-ins the account is found by issuer and subject alone.
- Claims can contain personal data. `Claims` prints as a count in logs, but read the claims you need and do not store or serialize the whole map.

## Ask the provider for more

`BeginWithOptions` sends constraints chosen by trusted application policy.

```go
maxAge := int64(300)
err := client.BeginWithOptions(w, r, oidc.AuthorizationOptions{
	MaxAgeSeconds: &maxAge,                // requires a signed auth_time at most this old
	ACRValues:     []string{acceptedACR},  // ordered preferences
	Prompt:        "login",                // or none, consent, select_account
})
```

- A maximum age requires the signed `auth_time` claim and is checked at the callback. Zero requires authentication at or after the start of this login.
- An ACR preference or a login prompt is a request, not proof. Check the actual signed ACR afterwards.
- A shared store must round-trip `StartedAt` and `MaxAgeSeconds`, including the difference between absent and zero. Upgrade every callback handler and store before enabling freshness requests.

## Signature algorithms

By default only RS256 is accepted. List the algorithms to accept in `Config.SigningAlgs`.

```go
SigningAlgs: []oidc.SigningAlg{oidc.ES256, oidc.EdDSA},
```

| Value | Algorithm |
| --- | --- |
| `oidc.RS256` | RSASSA-PKCS1-v1_5 with SHA-256 |
| `oidc.PS256` | RSASSA-PSS with SHA-256 |
| `oidc.ES256` | ECDSA with P-256 and SHA-256 |
| `oidc.EdDSA` | Ed25519 |

An ID token signed with an algorithm that is not listed is rejected, including RS256 when the list omits it. The list is not compared with the provider's metadata, so listing only algorithms the provider does not use makes every login fail.

## Errors and operations

| Situation | Result |
| --- | --- |
| Invalid credentials, rejected claims, a missing or expired pending login | `oidc.ErrInvalid` |
| A token endpoint failure, a network error, or an oversized or non-200 response while fetching keys | `oidc.ErrProviderUnavailable` |
| A malformed key document returned with HTTP 200 | An invalid login |
| The request's context was canceled | The context's error |

- Discovery runs once in `New` with the given context. Signing keys are refreshed through a shared cache with the client's own time-bounded HTTP client. Discovery and key responses are limited to 1 MiB.
- A pending login expires after ten minutes. Each browser has one pending login per client, and a new start replaces it.
- An unmatched or failed lookup keeps the browser's cookie, so that another pending login can still finish.
- The token's `nbf` is enforced to the second. Keep the server clock synchronized.
- Limit login starts per client and overall.
- Keep mutually untrusted applications on separate hosts.

## Try the example

The [OpenID Connect login example](https://github.com/i2bskn/authlume/tree/main/examples/oidc) runs the flow over HTTPS on a loopback address against a provider you register it with. Its README shows how to start it.

`go test -race ./oidc ./examples/oidc` drives the same flow against a local signed test issuer.
