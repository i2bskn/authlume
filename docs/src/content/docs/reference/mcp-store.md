---
title: MCP OAuth store and operations
description: The mcpoauth.Store contract, the application's duties and behaviors not yet verified against real MCP clients.
---

## The store contract

`MemoryStore` serves one process, holds 4096 codes and 4096 connections and loses them on restart. A shared deployment implements `mcpoauth.Store`:

- Operations on one code or one connection are linearizable across processes. `Rotate` checks the client, the deadlines and the presented refresh token and replaces both tokens in one atomic step, so exactly one of several concurrent refreshes succeeds.
- `TakeCode` marks a record as consumed and keeps it until the code's deadline. A second `TakeCode` before that deadline marks the record as reused and deletes the connection whose `Code` is that key. `Create` checks the code record of a connection that carries a `Code`: it refuses the connection when the record is missing, unconsumed or marked as reused. Keep codes and connections in one backend that can change both atomically, because `Create` must be serialized with every `TakeCode` of the same code.
- Some operations change state while returning an error. `TakeCode` deletes an expired record, and on reuse it marks the record and deletes the connection. `Rotate` deletes an expired connection and one whose refresh token was reused. Commit the change before returning the error. A transaction that rolls back because of the error would revive the code or the connection. If the change cannot be committed, return the backend's error.
- Every method returns the context's error without changing state when the context is already done, and reports backend failures as errors distinct from `mcpoauth.ErrInvalid`.
- Dedicate a store to one issuer and resource pair, keep at least whole seconds of every time, preserve the order of scopes, and treat records as secrets.

## Contract tests

Run the contract tests against the implementation.

```go
func TestStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T) mcpoauth.Store { return newEmptyStore(t) })
}
```

## What the application owns

- **Revoking by user.** When recovering or suspending an account, delete the user's connections and all of their authorization code records, consumed ones included, in one operation, as `MemoryStore.RevokeSubject` does. Deleting a consumed record also stops a code exchange whose `TakeCode` already succeeded: its `Create` finds no record and fails. Checking the user's state in `Create` adds a second barrier.
- **Withdrawn clients.** Revoke the connections of a client whose registration is removed. Verifying an access token does not consult the client registration.
- **Client scopes.** Limiting a client to some scopes, and what happens when the list is narrowed, is described in [Scopes per client](/authlume/guides/mcp-oauth/#scopes-per-client).
- **Repeated consent.** Each consent adds a connection. An earlier connection of the same user and client stays valid until it is disconnected or expires.
- **Code replay.** Codes live for 60 seconds, are consumed by their first lookup and require the PKCE verifier. A code presented again within those 60 seconds fails and revokes the connection that was created from it, whichever client presents it. After the 60 seconds a replay fails without revoking anything.
- **CORS, rate limits and audit records.** The package sets no CORS headers, so a browser-based client needs them from the application on the metadata, token and revocation routes. Limit authorization, token and revocation requests per client and overall. Store the `Event` and error that `Token` and `Revocation` return. The demo only logs them.

## Not yet verified against real MCP clients

The following behaviors are covered by tests of this module but have not been checked against real MCP clients.

- A client that sends a refresh again, or two refreshes at once. There is no grace period, so the connection is revoked and the user must authorize again. The same happens when the client disconnects after the store committed a rotation and then retries with the old token.
- A client that did not receive the token response and sends the same authorization code again. The connection is revoked and the user must authorize again. The same happens when the client retries after a 503 from the code exchange.
- A client that never requests `offline_access`. Every connection receives a refresh token regardless.
- A client that sends the issuer's root as `resource`. It is rejected with `invalid_target`; only the configured resource is accepted, with or without one trailing slash.
- Loopback redirect URIs whose port changes on every run.
