---
title: MCP OAuth
description: An OAuth 2.1 authorization server and bearer token verifier for one MCP server.
---

The `mcpoauth` package is an OAuth 2.1 authorization server and bearer token verifier for one MCP server. It is independent of web login: the application keeps its own sign-in, consent screen and client registration.

- Registering a client grants nothing. Access starts with a user's consent, which creates one **connection**.
- A connection has an access token and a rotating refresh token. Both are opaque random values.
- Revoking a connection revokes both tokens together.

## Set up

```go
oauth, err := mcpoauth.New(mcpoauth.Config{
    Issuer:                "https://auth.example.com",
    Resource:              "https://mcp.example.com/mcp",
    AuthorizationEndpoint: "https://auth.example.com/authorize",
    TokenEndpoint:         "https://auth.example.com/token",
    RevocationEndpoint:    "https://auth.example.com/revoke",
    Scopes:                []string{"mcp:read", "mcp:write"},
    DefaultScopes:         []string{"mcp:read"},
}, lookup, mcpoauth.NewMemoryStore())
```

Construct one server per MCP resource. `Issuer` and `Resource` are canonical HTTPS URLs and enter the key derivation of every code and token, so changing either spelling invalidates everything outstanding.

`lookup` is a `mcpoauth.ClientLookup` that returns the application's own client records, whether they come from manual registration, dynamic registration or client ID metadata documents. Validate each record with `Client.Validate` when it is registered. Advertise the application's own registration endpoints through `Config.Metadata`.

`mcpoauth.NewMemoryStore` serves one process. For a shared deployment, implement `mcpoauth.Store` as described in [Store and operations](/authlume/reference/mcp-store/).

## Lifetimes

| Setting | Default | Meaning |
| --- | --- | --- |
| `AccessTTL` | 1 hour | Lifetime of an access token |
| `RefreshIdle` | 90 days | Time since the last refresh after which the connection ends |
| `ConnectionAbsolute` | unlimited | Time since consent after which the connection ends, even when it keeps refreshing |

The 60-second single-use authorization code, refresh token rotation, reuse detection and the binding to the issuer and resource are not configurable.

## Mount the endpoints

| Handler | Route |
| --- | --- |
| `oauth.Token` | POST, the token endpoint |
| `oauth.Revocation` | POST, the revocation endpoint |
| `oauth.Metadata` | GET, at `oauth.MetadataPath()` |
| `oauth.ResourceMetadata` | GET, at `oauth.ResourceMetadataPath()` |

Mount `Token` and `Revocation` outside the browser's cross-origin protection, because clients call them directly. Some clients look for the resource metadata at the root `/.well-known/oauth-protected-resource`, so a resource with a path can mount the same handler there too. The package sets no CORS headers.

## Authorization and consent

The authorization endpoint is the application's own handler.

1. Pass the raw query string (`r.URL.RawQuery`) to `oauth.Authorize` and show the consent screen for the `Request` it returns. Name the client, the host of its redirect URI and the scopes, and warn when the redirect URI is a loopback address.
2. On the consent POST, authenticate the user, protect the route against CSRF and forbid framing.
3. Pass the same query string and the user's subject to `oauth.Approve`, or call `oauth.Deny`.
4. Send the browser to the returned URL with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

Binding the displayed request to the approved one is the application's duty. The demo carries the query string in a hidden form field.

Authorization requires PKCE with S256 and an exactly matching redirect URI. A loopback redirect URI is the one exception: it matches on any port.

### Rejected requests

A `*mcpoauth.RejectError` has a verified client and redirect URI and may be reported to the client through its `RedirectURL`. Where anyone can register a client, forwarding automatically makes the endpoint an open redirector, so show an error page built from `RejectError.Request`, or let the user choose to continue. Any other error must never redirect: the client or its redirect URI is unverified.

## Scopes per client

By default a client may be granted every scope of `Config.Scopes`. To limit a client, set `RestrictScopes` in its record and list what it may be granted.

```go
mcpoauth.Client{
	ID:             "reporting-tool",
	RedirectURIs:   []string{"https://reports.example.com/callback"},
	RestrictScopes: true,
	Scopes:         []string{"mcp:read"},
}
```

- A request for a scope outside the list is rejected with `invalid_scope`. A request that omits `scope` receives the default scopes that are on the list, and is rejected when none is.
- With `RestrictScopes` set and an empty list, the client is granted nothing. Store the flag as the registration's own decision. Deriving it from whether the list is empty turns an emptied list into full access.
- Narrowing the list revokes each connection that holds a removed scope at its next refresh. Restoring the list does not restore the connection, so the lookup must return a stable record.
- Access tokens already issued keep their scope until they expire. To cut access at once, revoke the connections.

## Tokens

`Token` and `Revocation` write the response themselves and return an `Event` and an error for the application's audit record.

| Error | Meaning |
| --- | --- |
| `nil` | The request succeeded |
| wraps `mcpoauth.ErrClient` | Client authentication failed |
| wraps `mcpoauth.ErrReused` | A rotated refresh token or a consumed authorization code was presented again. `Event.ConnectionID` names the connection that was revoked, if any |
| wraps `mcpoauth.ErrInvalid` | Another invalid request, code or token |
| anything else | A backend failure |

A refresh replaces the access token and the refresh token in one atomic step. Presenting a rotated refresh token again revokes that connection only, without a grace period. An authorization code that is presented again before it expires revokes the connection created from it.

## Protect the MCP endpoint

```go
mux.Handle("/mcp", oauth.Protect(handler, "mcp:read"))

// In the handler:
access, _ := mcpoauth.FromContext(r.Context())
if !access.Has("mcp:write") {
	// Refuse the tool call.
}
```

`oauth.Verify`, `oauth.Challenge` and `oauth.InsufficientScope` do the same step by step for an endpoint that also accepts another kind of credential.

Allow an operation only when both `Access.Scopes` and the user's current permissions cover it. Reload the user's current state, such as suspension and roles, from `Access.Subject`. Never widen the scope of an existing connection.

## Disconnect

`oauth.Disconnect` revokes a connection by its ID. It accepts any ID, so first confirm in the application's store that the connection belongs to the acting user. A client can revoke its own connection by posting either token to the revocation endpoint.

## Differences from the specifications

- `redirect_uri` is always required in an authorization request, even with a single registered URI.
- The port of a loopback redirect URI is ignored for `localhost` as well as for the IP literals. This follows deployed clients, although RFC 8252 discourages `localhost`.
- A refresh request's `scope` is checked for known values only. It never narrows or widens the connection, and the response's `scope` reports what was issued.
- A client record that fails `Client.Validate`, such as one with a custom scheme redirect URI or more than 16 URIs, makes the token endpoint answer 503.

## Try the example

The [MCP OAuth example](https://github.com/i2bskn/authlume/tree/main/examples/mcp) runs the whole flow over HTTPS on a loopback address. Its README shows how to start it.

Some behaviors have not been verified against real MCP clients yet. They are listed in [Store and operations](/authlume/reference/mcp-store/#not-yet-verified-against-real-mcp-clients).
