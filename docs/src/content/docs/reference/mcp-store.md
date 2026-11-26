---
title: MCP OAuth store and operations
description: The mcpoauth.Store and ClientStore contracts, the application's duties and behaviors not yet verified against real MCP clients.
---

## The store contract

`MemoryStore` serves one process, holds 4096 codes and 4096 connections and loses them on restart. A shared deployment implements `mcpoauth.Store`:

- Operations on one code or one connection are linearizable across processes. `Rotate` checks the client, the deadlines and the presented refresh token and replaces both tokens in one atomic step, so exactly one of several concurrent refreshes succeeds.
- `TakeCode` marks a record as consumed and keeps it until the code's deadline. A second `TakeCode` before that deadline marks the record as reused and deletes the connection whose `Code` is that key. `Create` checks the code record of a connection that carries a `Code`: it refuses the connection when the record is missing, unconsumed or marked as reused. Keep codes and connections in one backend that can change both atomically, because `Create` must be serialized with every `TakeCode` of the same code.
- Some operations change state while returning an error. `TakeCode` deletes an expired record, and on reuse it marks the record and deletes the connection. `Rotate` deletes an expired connection and one whose refresh token was reused. Commit the change before returning the error. A transaction that rolls back because of the error would revive the code or the connection. If the change cannot be committed, return the backend's error.
- Every method returns the context's error without changing state when the context is already done, and reports backend failures as errors distinct from `mcpoauth.ErrInvalid`.
- Dedicate a store to one issuer and resource pair, keep at least whole seconds of every time, preserve the order of scopes, and treat records as secrets.

## The client store contract

Dynamic client registration keeps its clients in a `mcpoauth.ClientStore`. `MemoryClientStore` serves one process, holds 4096 registrations and loses them on restart. When it is full it first removes expired registrations, then the oldest registration not yet activated, and fails with `ErrCapacity` when every registration has been activated. A shared deployment implements the interface:

- `CreateClient` inserts without overwriting and returns `ErrCollision` when the ID is taken.
- `Client` returns `ErrNotFound` for a missing registration and for one whose nonzero `ExpiresAt` is not after `now`. It changes no registration, though it may remove an expired one.
- `Activate` clears `ExpiresAt` in one atomic step with its check, returns `ErrNotFound` for a missing or expired registration and is idempotent. The first code exchange of a client calls it, so a registration that is never used expires after `RegistrationConfig.UnusedTTL`.
- Every method returns the context's error without changing state when the context is already done, and reports backend failures as errors distinct from `ErrNotFound` and `ErrCollision`.
- Preserve the order of redirect URIs and at least whole seconds of every time. Arrange the physical cleanup of expired registrations.

## Contract tests

Run the contract tests against the implementation.

```go
func TestStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T) mcpoauth.Store { return newEmptyStore(t) })
}

func TestClientStore(t *testing.T) {
	storetest.RunClientStore(t, func(t *testing.T) mcpoauth.ClientStore { return newEmptyClientStore(t) })
}
```

## What the application owns

- **Revoking by user.** When recovering or suspending an account, delete the user's connections and all of their authorization code records, consumed ones included, in one operation, as `MemoryStore.RevokeSubject` does. Deleting a consumed record also stops a code exchange whose `TakeCode` already succeeded: its `Create` finds no record and fails. Checking the user's state in `Create` adds a second barrier.
- **Withdrawn clients.** Revoke the connections of a client whose registration is removed. Verifying an access token does not consult the client registration.
- **Client scopes.** Limiting a client to some scopes, and what happens when the list is narrowed, is described in [Scopes per client](/authlume/guides/mcp-oauth/#scopes-per-client).
- **Repeated consent.** Each consent adds a connection. An earlier connection of the same user and client stays valid until it is disconnected or expires.
- **Code replay.** Codes live for 60 seconds, are consumed by their first lookup and require the PKCE verifier. A code presented again within those 60 seconds fails and revokes the connection that was created from it, whichever client presents it. After the 60 seconds a replay fails without revoking anything.
- **Registrations.** Anyone can call the registration endpoint. Limit it per address and overall, answer the CORS preflight `OPTIONS` request on its route, and set `InitialAccessToken` when only known parties may register. Remove activated registrations whose connections are all gone, because a client may register again every time it connects. `MemoryClientStore.Clients` and `DeleteClient` serve this. Revoke the connections of a registration you delete.
- **Metadata documents.** A `MetadataError` returned by the token endpoint names the client in `ClientID`. Revoke that client's connections when its document has become unusable for good. Each process caches documents on its own, so a change to a document reaches the processes of a deployment at different times, within `MaxCacheTTL`. A client ID URL is not proof of who runs the client: a host that lets its users publish files, as section 10.13 of the draft warns, can serve a document for anyone. Restrict `AllowedHosts` when the set of clients is known.
- **Redirects after consent.** Redirect URIs of clients without registration come from the client itself. Show the client's host and name on the consent screen, as described in [Consent for these clients](/authlume/guides/mcp-oauth/#consent-for-these-clients).
- **CORS, rate limits and audit records.** The package sets no CORS headers, so a browser-based client needs them from the application on the metadata, token and revocation routes. Limit authorization, token and revocation requests per client and overall. Store the `Event` and error that `Token` and `Revocation` return. The demo only logs them.

## Not yet verified against real MCP clients

The following behaviors are covered by tests of this module but have not been checked against real MCP clients.

- A client that sends a refresh again, or two refreshes at once. There is no grace period, so the connection is revoked and the user must authorize again. The same happens when the client disconnects after the store committed a rotation and then retries with the old token.
- A client that did not receive the token response and sends the same authorization code again. The connection is revoked and the user must authorize again. The same happens when the client retries after a 503 from the code exchange.
- A client that never requests `offline_access`. Every connection receives a refresh token regardless.
- A client that sends the issuer's root as `resource`. It is rejected with `invalid_target`; only the configured resource is accepted, with or without one trailing slash.
- Loopback redirect URIs whose port changes on every run.
- Client ID metadata documents with real Claude, Claude Code and ChatGPT clients. The published documents of Claude (`https://claude.ai/oauth/mcp-oauth-client-metadata`) and Claude Code (`https://claude.ai/oauth/claude-code-client-metadata`) were fetched and accepted by `Authorize`, but no full connection has been made.
- A client whose document lists `private_key_jwt`, as ChatGPT's is reported to do. The client is treated as public and must send no `client_assertion`; one that sends it is refused.
- Dynamic client registration with real clients such as Cursor. A client that registers only custom scheme redirect URIs, such as `cursor://`, has them dropped and cannot connect.
