---
title: Sessions
description: Issue, read and revoke server-backed sessions, set lifetimes, require fresh authentication and handle cookies for apps that share a host.
---

The `session` package manages server-backed web sessions. The cookie holds a random ID, and everything else is state in a store that the application provides. It is independent of how the user authenticated: call `Issue` only after the application's whole login policy is complete, including any second factor.

## Create a manager

```go
sessions, err := session.New(session.NewMemoryStore(), session.Config{})
if err != nil {
	return err
}
```

`session.NewMemoryStore` serves one process and loses its sessions on restart. For more than one instance, or to keep sessions across restarts, implement [`session.Store`](#implement-a-store).

## Issue, read and log out

```go
// After a complete login:
if err := sessions.Issue(w, r, subject); err != nil {
	// session.ErrInvalid: the request carried a malformed or duplicate cookie.
	// Any other error: the store failed. No cookie was written.
}

// In a protected handler:
state, err := sessions.Read(r)
if errors.Is(err, session.ErrInvalid) {
	// Not signed in: missing, malformed, expired or revoked.
}
// state.Subject is the signed-in user.

// On logout, from a CSRF-protected POST:
err = sessions.Logout(w, r)
```

`Issue` always creates a new session ID and removes the session the browser presented, so the ID changes at every login. `Logout` deletes the server state before clearing the cookie, and an error from the store means the logout did not happen.

To end a session without its browser, for example from an administration screen, call `sessions.Revoke(ctx, key)` with the `Key` of a `State`. Ending every session of one user needs an index by subject in the application's store.

## Lifetimes

| Setting | Default | Meaning |
| --- | --- | --- |
| `Config.Idle` | 24 hours | Time since the last recorded user action |
| `Config.Absolute` | 7 days | Time since the login, whatever the activity |

A zero value selects the default for that field. Both must be positive and `Idle` must not exceed `Absolute`. An application that prefers fewer logins can set longer values.

```go
sessions, err := session.New(store, session.Config{
	Idle:     7 * 24 * time.Hour,
	Absolute: 30 * 24 * time.Hour,
})
```

Only `Touch` moves the idle deadline. `Read` never does.

```go
state, err := sessions.Touch(r) // a route that represents an intentional user action
state, err = sessions.Read(r)   // polling, prefetch, keepalive and every other request
```

The application decides which routes are user actions. Do not let a request header or a query parameter choose, because then a background script can keep a session alive. The absolute deadline always applies.

## Require fresh authentication

Before a sensitive action, such as changing a password or exporting data, check how long ago the user authenticated.

```go
state, err := sessions.RequireFresh(r, 15*time.Minute)
if errors.Is(err, session.ErrReauthenticationRequired) {
	// The session is valid but the login is too old. Authenticate the same
	// subject again under the current policy, then call Issue.
}
```

Activity does not refresh the authentication time. Only a new complete login followed by `Issue` does.

## Apps sharing a host

Set `session.Config{CookieName: "__Host-inventory"}` to give an app its own cookie. The empty setting uses `__Host-authlume`. The name must start with exactly `__Host-`, have a nonempty suffix and be a valid HTTP cookie name.

Use a separate store, or a separate namespace in the store, for each app with independent authentication. Host cookies travel across paths and ports on the same host, so put mutually untrusted apps on separate hosts.

## Recover an unreadable cookie

`Read`, `Touch`, `Issue` and `Logout` all return `session.ErrInvalid` for a malformed cookie or for two cookies with the session's name, and change nothing. A browser can be left in that state by an older deployment or by another app on the host. Offer an explicit recovery form for it.

```go
// A CSRF-protected POST handler:
err := sessions.ResetInvalidCookie(w, r)
switch {
case errors.Is(err, session.ErrCookieWellFormed):
	// The cookie is readable. Use the normal logout instead.
case err == nil:
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
```

The reset clears the app's host-only cookie at `Path=/` and never touches the store, so a session record that exists on the server stays until it expires or is revoked. The user signs in again under the current policy. If a legacy cookie with a different path or domain persists, the user has to remove that cookie in the browser settings.

The [sample handler](https://github.com/i2bskn/authlume/blob/main/examples/web/main.go) includes the recovery form and route.

## Implement a store

A store has three operations. Each must be atomic, and operations on the same key must be linearizable across processes.

| Method | Contract |
| --- | --- |
| `Replace(ctx, previous, next)` | Insert `next` and remove `previous`, if given, in one step. An unknown `previous` is allowed. A collision on the new key fails and leaves `previous` in place. |
| `Use(ctx, key, now, touch)` | Check both deadlines and return `session.ErrInvalid` for a missing or expired record. With `touch`, move the last activity to the later of `now` and the stored value. Never recreate a missing record. |
| `Delete(ctx, key)` | Remove the record. Succeed when it is already gone. |

- The key is the SHA-256 digest of the session ID. The ID itself never reaches the store.
- A record is expired when `now` is equal to or later than a deadline.
- Return a backend failure as an error distinct from `session.ErrInvalid`, so the application can report the service as unavailable instead of signing the user out.
- Remove expired records on a schedule. `Use` may also remove the ones it finds.

The [design notes](/authlume/reference/design/) give the reasons behind these rules.
