# MCP OAuth over HTTPS

This loopback example is an OAuth 2.1 authorization server and a protected MCP endpoint for one demo user and one pre-registered client. It signs the user in with the `password` and `session` packages and uses `github.com/i2bskn/authlume/mcpoauth` for consent, tokens and bearer verification. The `/mcp` route answers just enough of the MCP protocol for a client to connect and call two tools: `initialize`, `ping`, `tools/list` and `tools/call`. It keeps no MCP session and opens no event stream.

## Run

Use Go 1.25 or later, Bash and OpenSSL. Generate a certificate for the loopback address, set a demo password and register the client's ID and redirect URI.

```bash
certdir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "$certdir/key.pem" -out "$certdir/cert.pem"
read -rs -p 'Demo password: ' AUTHLUME_PASSWORD
echo
export AUTHLUME_PASSWORD
export MCP_CLIENT_ID=demo-client
export MCP_REDIRECT_URI=http://127.0.0.1/callback
go run ./examples/mcp -cert "$certdir/cert.pem" -key "$certdir/key.pem"
```

The redirect URI is an HTTPS URL, or an HTTP URL on `127.0.0.1`, `[::1]` or `localhost`. A loopback URI is registered without a port and matches any port the client listens on. Set `MCP_CLIENT_SECRET` to a random value with at least 256 bits of entropy to make the client confidential. Without it the client is public and identified by its ID alone.

Create a PKCE pair and open the authorization request in a browser that trusts the temporary certificate.

```bash
verifier=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')
challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')
echo "https://127.0.0.1:8446/authorize?response_type=code&client_id=$MCP_CLIENT_ID&redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback&code_challenge=$challenge&code_challenge_method=S256&scope=mcp%3Aread%20mcp%3Awrite&state=demo"
```

Sign in as `demo`, then choose **Allow**. The browser is sent to the redirect URI with `code`, `state` and `iss`. Nothing needs to listen there: copy the code from the address bar and exchange it within 60 seconds.

```bash
code=PASTE_THE_CODE
curl --cacert "$certdir/cert.pem" https://127.0.0.1:8446/token \
  -d grant_type=authorization_code -d client_id="$MCP_CLIENT_ID" \
  -d code="$code" -d code_verifier="$verifier"
```

Call a tool with the access token and renew it with the refresh token.

```bash
curl --cacert "$certdir/cert.pem" -H "Authorization: Bearer $access_token" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}' https://127.0.0.1:8446/mcp
curl --cacert "$certdir/cert.pem" https://127.0.0.1:8446/token \
  -d grant_type=refresh_token -d client_id="$MCP_CLIENT_ID" -d refresh_token="$refresh_token"
```

Every request to `/mcp` needs `mcp:read`. The `whoami` tool reports who the token acts for. The `echo` tool also needs `mcp:write` and answers 403 with an `insufficient_scope` challenge without it. A request that omits `scope` receives `mcp:read` only. Each refresh returns a new access token and a new refresh token. Sending an earlier refresh token again revokes that connection. The signed-in user lists and disconnects connections at <https://127.0.0.1:8446/connections>. The client can revoke its own connection by posting either token to `/revoke`. The metadata documents are at `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource/mcp`. The second one is also served at `/.well-known/oauth-protected-resource` for clients that look at the root.

## Integrate with an application

Construct one server per MCP resource with `mcpoauth.New(cfg, clients, store)`. `Issuer` and `Resource` are canonical HTTPS URLs and enter the key derivation of every code and token, so changing either spelling invalidates everything outstanding. `clients` is a `mcpoauth.ClientLookup` that returns the application's own client records, whether they come from manual registration, dynamic registration or client ID metadata documents. Validate each record with `Client.Validate` when it is registered. Advertise the application's own registration endpoints through `Config.Metadata`.

- **Authorization.** Pass the raw query string of the authorization endpoint to `Authorize` and show the consent screen for the `Request` it returns. Name the client, the host of its redirect URI and the scopes, and warn when `Request.RedirectURI` is a loopback address. On the consent POST, authenticate the user, protect the route against CSRF, forbid framing, and pass the same query string with the user's subject to `Approve`, or to `Deny`. Binding the displayed request to the approved one is the application's duty. The demo carries the query string in a hidden form field. Send the browser to the returned URL with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
- **Rejections.** A `*mcpoauth.RejectError` has a verified client and redirect URI and may be reported to the client through its `RedirectURL`. The demo forwards it because its only client is pre-registered. Where anyone can register a client, forwarding automatically makes the endpoint an open redirector, so show an error page built from `RejectError.Request` or let the user choose to continue. Any other error must never redirect.
- **Tokens.** Mount `Token` and `Revocation` as POST handlers outside the browser's cross-origin protection. Both write the response themselves and return an `Event` and an error for the application's records. `ErrClient` reports failed client authentication, `ErrReused` a rotated refresh token or a consumed authorization code that was presented again, with the connection it revoked, if any, in `Event.ConnectionID`, and an error that does not wrap `ErrInvalid` a backend failure.
- **The protected resource.** Wrap handlers with `Protect(next, scopes...)` and read the result with `mcpoauth.FromContext`. `Verify`, `Challenge` and `InsufficientScope` do the same step by step for an endpoint that also accepts another kind of credential. Allow an operation only when both `Access.Scopes` and the user's current permissions cover it, and reload the user's current state from `Access.Subject`. Never widen the scope of an existing connection.
- **Disconnecting.** `Disconnect` revokes a connection by its ID and with it both tokens. It accepts any ID, so first confirm in the application's store that the connection belongs to the acting user, as the demo does.

The package differs from the specifications in a few places. `redirect_uri` is always required in an authorization request, even with a single registered URI. The port of a loopback redirect URI is ignored for `localhost` as well as for the IP literals, which follows deployed clients although RFC 8252 discourages `localhost`. A refresh request's `scope` is checked for known values only, never narrows or widens the connection, and the response's `scope` reports what was issued. A client record that fails `Client.Validate`, such as one with a custom scheme redirect URI or more than 16 URIs, makes the token endpoint answer 503.

## Operating notes

`MemoryStore` serves one process, holds 4096 codes and 4096 connections and loses them on restart. A shared deployment implements `mcpoauth.Store`:

- Operations on one code or one connection are linearizable across processes. `Rotate` checks the client, the deadlines and the presented refresh token and replaces both tokens in one atomic step, so exactly one of several concurrent refreshes succeeds.
- `TakeCode` marks a record as consumed and keeps it until the code's deadline. A second `TakeCode` before that deadline marks the record as reused and deletes the connection whose `Code` is that key. `Create` checks the code record of a connection that carries a `Code`: it refuses the connection when the record is missing, unconsumed or marked as reused. Keep codes and connections in one backend that can change both atomically, because `Create` must be serialized with every `TakeCode` of the same code.
- Some operations change state while returning an error. `TakeCode` deletes an expired record, and on reuse it marks the record and deletes the connection. `Rotate` deletes an expired connection and one whose refresh token was reused. Commit the change before returning the error. A transaction that rolls back because of the error would revive the code or the connection. If the change cannot be committed, return the backend's error.
- Every method returns the context's error without changing state when the context is already done, and reports backend failures as errors distinct from `mcpoauth.ErrInvalid`.
- Dedicate a store to one issuer and resource pair, keep at least whole seconds of every time, preserve the order of scopes, and treat records as secrets.

Run the contract tests against the implementation.

```go
func TestStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T) mcpoauth.Store { return newEmptyStore(t) })
}
```

The application also owns the following.

- **Revoking by user.** When recovering or suspending an account, delete the user's connections and all of their authorization code records, consumed ones included, in one operation, as `MemoryStore.RevokeSubject` does. Deleting a consumed record also stops a code exchange whose `TakeCode` already succeeded: its `Create` finds no record and fails. Checking the user's state in `Create` adds a second barrier.
- **Withdrawn clients.** Revoke the connections of a client whose registration is removed. Verifying an access token does not consult the client registration.
- **Client scopes.** A client may be granted every scope of `Config.Scopes` unless its record sets `Client.RestrictScopes`, which limits it to `Client.Scopes`; set the flag from the registration's own decision, not from whether the list is empty, since deriving it from the list's length turns an emptied list into full access. An entry that `Config.Scopes` does not define is not reported as an error, and a restricted client whose list shares nothing with `DefaultScopes` must always send `scope`. Narrowing a client's list revokes each affected connection at its next refresh and restoring the list does not restore it, so the `ClientLookup` must return a stable record, while access tokens already issued keep their scope until they expire or the connection is revoked: revoke the connections to cut access at once.
- **Repeated consent.** Each consent adds a connection. An earlier connection of the same user and client stays valid until it is disconnected or expires.
- **Code replay.** Codes live for 60 seconds, are consumed by their first lookup and require the PKCE verifier. A code presented again within those 60 seconds fails and revokes the connection that was created from it, whichever client presents it. After the 60 seconds a replay fails without revoking anything.
- **CORS, rate limits and audit records.** The package sets no CORS headers, so a browser-based client needs them from the application on the metadata, token and revocation routes. Limit authorization, token and revocation requests per client and overall. Store the `Event` and error that `Token` and `Revocation` return. The demo only logs them.

These behaviors have not been verified against real MCP clients:

- A client that sends a refresh again, or two refreshes at once. There is no grace period, so the connection is revoked and the user must authorize again. The same happens when the client disconnects after the store committed a rotation and then retries with the old token.
- A client that did not receive the token response and sends the same authorization code again. The connection is revoked and the user must authorize again. The same happens when the client retries after a 503 from the code exchange.
- A client that never requests `offline_access`. Every connection receives a refresh token regardless.
- A client that sends the issuer's root as `resource`. It is rejected with `invalid_target`; only the configured resource is accepted, with or without one trailing slash.
- Loopback redirect URIs whose port changes on every run.
