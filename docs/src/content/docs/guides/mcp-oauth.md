---
title: MCP OAuth
description: An OAuth 2.1 authorization server and bearer token verifier for one MCP server.
---

The `mcpoauth` package is an OAuth 2.1 authorization server and bearer token verifier for one MCP server. It is independent of web login: the application keeps its own sign-in and consent screen. Clients can be registered by the application, or the server can accept them without registration through client ID metadata documents and dynamic client registration.

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

`lookup` is a `mcpoauth.ClientLookup` that returns the application's own client records. Validate each record with `Client.Validate` when it is registered. It may be nil when [clients without registration](#clients-without-registration) are enabled and the application registers none itself.

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

## Clients without registration

MCP clients usually connect to a server they have never seen. Two optional mechanisms let them, and both are off by default.

| Mechanism | Enable with | Used by |
| --- | --- | --- |
| Client ID metadata documents (CIMD) | `Config.MetadataDocuments` | Claude, Claude Code and ChatGPT. The client's `client_id` is an HTTPS URL, and the server fetches the client's metadata from it |
| Dynamic client registration (DCR, RFC 7591) | `Config.Registration` | Clients that do not support CIMD. The client posts its metadata to the registration endpoint and receives a `client_id` |

```go
oauth, err := mcpoauth.New(mcpoauth.Config{
    // ... as above
    MetadataDocuments: &mcpoauth.MetadataDocumentConfig{},
    Registration: &mcpoauth.RegistrationConfig{
        Endpoint: "https://auth.example.com/register",
        Store:    mcpoauth.NewMemoryClientStore(),
    },
}, lookup, mcpoauth.NewMemoryStore())

mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
    reg, err := oauth.Register(w, r)
    // Record reg and err.
})
```

The server publishes `client_id_metadata_document_supported` or `registration_endpoint` in its metadata. While a mechanism is enabled, `Config.Metadata` cannot set that member.

A client is resolved in this order:

1. `lookup`. A client the application registered always wins, and a backend error from `lookup` is returned as is, never passed on to the next step.
2. A `client_id` starting with `https://` is resolved from its metadata document, when that is enabled.
3. A `client_id` in the format the registration endpoint issues is resolved from `RegistrationConfig.Store`, when that is enabled.

An unknown client makes `Authorize`, `Approve` and `Deny` return `mcpoauth.ErrUnknownClient`, which wraps `ErrInvalid`. This also happens when a registration has expired: tell the user to connect again from the client.

Every client resolved this way is public. It authenticates at the token endpoint without a secret.

### Metadata documents

The server fetches the document at the `client_id` URL and accepts it only when it is safe to use:

- The URL is canonical: lowercase host name with two or more labels, no IP literal, no user information, query, fragment or dot segments, and a path other than `/`. It must not be on one of this server's own hosts. `AllowedHosts` can limit the hosts further, for example to `claude.ai`.
- The fetch connects only to public addresses, checked on the address actually dialed. It follows no redirect, uses no proxy, sends no cookie or credential and is bounded by `Timeout` (5 seconds) and `MaxSize` (5120 bytes). At most 16 fetches run at once, 4 per host, and concurrent requests for one `client_id` share one fetch.
- The document must be served with status 200 and a JSON media type such as `application/json`. A document served as `text/plain`, as raw files on GitHub are, is refused.
- Its `client_id` must equal the URL exactly. It must not contain `client_secret`, and it must allow the `none` authentication method. Redirect URIs that `Client.Validate` refuses, such as custom schemes, are dropped; at least one must remain.

A document is cached for its `Cache-Control: max-age`, kept between `MinCacheTTL` (5 minutes) and `MaxCacheTTL` (24 hours). The authorization endpoint fetches it again when the cached copy is older than 30 seconds, so a changed document takes effect at the next consent. The token endpoint uses the cache and, when a fetch fails temporarily, a stale copy.

A document that cannot be used returns a `*mcpoauth.MetadataError`, which wraps `ErrInvalid`. Its `ClientID` names the client, and `Mismatch` reports a document that named another `client_id`. The token endpoint answers such a client with 401 `invalid_client`. A temporary failure, such as a timeout or a 5xx or 403 response, is not an `ErrInvalid`; the token endpoint answers it with 503.

### Registration

`Register` serves the registration endpoint. It accepts `redirect_uris`, `client_name`, `grant_types`, `response_types` and `token_endpoint_auth_method`, ignores every other member and always registers a public client.

- `InitialAccessToken` can require a bearer token on every registration request. Without it, anyone can register.
- A registration that is never used for a connection expires after `UnusedTTL`, 7 days by default. The first code exchange makes it permanent. A negative `UnusedTTL` keeps every registration.
- `NewMemoryClientStore` serves one process. A shared deployment implements `mcpoauth.ClientStore`, described in [Store and operations](/authlume/reference/mcp-store/#the-client-store-contract).

### Consent for these clients

`Request.ClientSource` tells where a client came from: `SourceLookup`, `SourceMetadata` or `SourceRegistration`. For a metadata document, `Request.ClientHost` is the host of the `client_id` URL.

- Always show `ClientHost` for a metadata document client. `ClientName` is whatever the client says about itself, for both kinds of client.
- Warn about loopback redirect URIs as before. Anyone can publish a document or register with a loopback redirect URI and a familiar name.
- Forward automatically to `RejectError.RedirectURL` only when `ClientSource` is `SourceLookup`. With these mechanisms enabled, anyone can supply a client and a redirect URI, so automatic forwarding for them makes the endpoint an open redirector.
- If consent is remembered, remember it per `client_id` and resource, and ask again when a document's redirect URIs or name change.

### Scopes for these clients

By default these clients may request every scope of `Config.Scopes`, and the user's consent decides. Set `RestrictDynamicScopes` and `DynamicScopes` to put a ceiling on them:

```go
RestrictDynamicScopes: true,
DynamicScopes:         []string{"mcp:read"},
```

An MCP client often requests every scope the server supports, so a known scope above the ceiling is dropped from the request instead of rejected. A request left with no scope, or naming a scope `Config.Scopes` does not define, is rejected with `invalid_scope`. Keep the scopes passed to `Challenge` and `InsufficientScope` within the ceiling, or a client keeps asking for a scope it cannot get.

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
- For metadata documents and registrations, redirect URIs with a custom scheme (RFC 8252 section 7.1) are dropped rather than accepted, so a client that only uses one cannot connect.
- A metadata document or registration whose `grant_types` lacks `refresh_token` still receives a refresh token.
- A registration's requested `token_endpoint_auth_method` is replaced with `none`, and the response reports `none`.
- For a client from a metadata document or a registration, a scope above `DynamicScopes` is dropped from an authorization request instead of rejected.
- A metadata document is refused when it lists a shared-secret authentication method or does not allow `none`, and a token request from its client that carries any credential is refused with `invalid_client`.
- Only the well-known NAT64 prefix `64:ff9b::/96` is checked for an embedded private IPv4 address. On a network with its own NAT64 prefix, restrict outbound traffic in the network as well. Metadata documents cannot be fetched where outbound traffic must go through a proxy.

## Try the example

The [MCP OAuth example](https://github.com/i2bskn/authlume/tree/main/examples/mcp) runs the whole flow over HTTPS on a loopback address. Its README shows how to start it.

Some behaviors have not been verified against real MCP clients yet. They are listed in [Store and operations](/authlume/reference/mcp-store/#not-yet-verified-against-real-mcp-clients).
