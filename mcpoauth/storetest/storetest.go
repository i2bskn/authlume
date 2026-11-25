// Package storetest checks that an implementation of mcpoauth.Store meets the
// interface's contract.
package storetest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2bskn/authlume/mcpoauth"
)

// Run checks the contract against the empty store that newStore returns. It
// calls newStore once per subtest. Every time it passes is a whole second in
// UTC, so a store only needs to keep seconds.
func Run(t *testing.T, newStore func(t *testing.T) mcpoauth.Store) {
	for _, tc := range []struct {
		name string
		run  func(*testing.T, mcpoauth.Store)
	}{
		{"code is consumed once", codeOnce},
		{"code expiry", codeExpiry},
		{"code collision", codeCollision},
		{"concurrent code consumption", codeConcurrent},
		{"code reuse", codeReused},
		{"code reuse before the connection", codeReusedEarly},
		{"code reuse after rotation", codeReusedRotated},
		{"code reuse concurrent with creation", codeReusedConcurrent},
		{"connection round trip", roundTrip},
		{"connection collision", createCollision},
		{"connection without a consumed code", createCode},
		{"connection code collision", createCodeCollision},
		{"rotation", rotate},
		{"rotation of another client", rotateOtherClient},
		{"rotation after expiry", rotateExpired},
		{"rotation reuse", rotateReused},
		{"rotation collision", rotateCollision},
		{"rotation order", rotateOrder},
		{"concurrent rotation", rotateConcurrent},
		{"deadlines", deadlines},
		{"expired access token keeps the connection", expiredAccess},
		{"revocation", revoke},
		{"canceled context", canceled},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newStore(t)) })
	}
}

var start = time.Unix(1_800_000_000, 0).UTC()

func at(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }

// key returns a distinct digest for each kind and number.
func key(kind byte, n int) mcpoauth.Key {
	var k mcpoauth.Key
	k[0], k[1], k[2] = kind, byte(n>>8), byte(n)
	return k
}

func code(expiresAt time.Time) mcpoauth.Code {
	return mcpoauth.Code{
		ClientID: "client", RedirectURI: "https://client.example/callback", Subject: "user",
		Scopes: []string{"write", "read"}, Challenge: "challenge", ExpiresAt: expiresAt,
	}
}

// connection n is created at second 0. Its access token expires at second
// 100 and its refresh token at second 1000.
func connection(n int) mcpoauth.Connection {
	return mcpoauth.Connection{
		ID: "connection-" + string(rune('a'+n)), Selector: key('s', n), Subject: "user", ClientID: "client",
		Scopes: []string{"write", "read"}, CreatedAt: at(0), RefreshedAt: at(0),
		Access: key('a', n), AccessExpiry: at(100), Refresh: key('r', n), RefreshExpiry: at(1000),
	}
}

// rotation n replaces the tokens of a connection at second now.
func rotation(n, now int) mcpoauth.Rotation {
	return mcpoauth.Rotation{
		Access: key('A', n), AccessExpiry: at(now + 100), Refresh: key('R', n), RefreshExpiry: at(now + 1000),
	}
}

func same(t *testing.T, got, want mcpoauth.Connection) {
	t.Helper()
	if got.ID != want.ID || got.Selector != want.Selector || got.Subject != want.Subject ||
		got.ClientID != want.ClientID || !slices.Equal(got.Scopes, want.Scopes) ||
		!got.CreatedAt.Equal(want.CreatedAt) || !got.RefreshedAt.Equal(want.RefreshedAt) ||
		!got.AbsoluteExpiry.Equal(want.AbsoluteExpiry) || got.AbsoluteExpiry.IsZero() != want.AbsoluteExpiry.IsZero() ||
		got.Access != want.Access || !got.AccessExpiry.Equal(want.AccessExpiry) ||
		got.Refresh != want.Refresh || !got.RefreshExpiry.Equal(want.RefreshExpiry) || got.Code != want.Code {
		t.Fatalf("connection\n got %+v\nwant %+v", got, want)
	}
}

func create(t *testing.T, store mcpoauth.Store, conns ...mcpoauth.Connection) {
	t.Helper()
	for _, conn := range conns {
		if err := store.Create(t.Context(), conn); err != nil {
			t.Fatalf("create %s: %v", conn.ID, err)
		}
	}
}

// present requires the connection to be stored unchanged.
func present(t *testing.T, store mcpoauth.Store, want mcpoauth.Connection, now time.Time) {
	t.Helper()
	got, err := store.Lookup(t.Context(), want.Selector, now)
	if err != nil {
		t.Fatalf("lookup %s: %v", want.ID, err)
	}
	same(t, got, want)
}

// absent requires the connection's selector and access token to be unknown.
func absent(t *testing.T, store mcpoauth.Store, conn mcpoauth.Connection, now time.Time) {
	t.Helper()
	if _, err := store.Lookup(t.Context(), conn.Selector, now); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("lookup of a deleted connection: %v", err)
	}
	if _, err := store.Use(t.Context(), conn.Access, now); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("use of a deleted connection: %v", err)
	}
}

// consumed stores code n, which expires at second 60, and takes it at second
// 1, so that a connection can be created from it.
func consumed(t *testing.T, store mcpoauth.Store, n int) mcpoauth.Key {
	t.Helper()
	k := key('c', n)
	if err := store.CreateCode(t.Context(), k, code(at(60))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.TakeCode(t.Context(), k, at(1)); err != nil {
		t.Fatal(err)
	}
	return k
}

// reused requires a failed take that reports reuse and deleted no connection.
func reused(t *testing.T, conn mcpoauth.Connection, err error) {
	t.Helper()
	if !errors.Is(err, mcpoauth.ErrReused) || !errors.Is(err, mcpoauth.ErrInvalid) || conn.ID != "" {
		t.Fatalf("take of a consumed code: %+v, %v", conn, err)
	}
}

// invalid requires a failed take that is not reported as reuse.
func invalid(t *testing.T, conn mcpoauth.Connection, err error) {
	t.Helper()
	if !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) || conn.ID != "" {
		t.Fatalf("take of a missing or expired code: %+v, %v", conn, err)
	}
}

func codeOnce(t *testing.T, store mcpoauth.Store) {
	ctx, want := t.Context(), code(at(60))
	if err := store.CreateCode(ctx, key('c', 1), want); err != nil {
		t.Fatal(err)
	}
	_, conn, err := store.TakeCode(ctx, key('c', 2), at(1))
	invalid(t, conn, err)
	got, conn, err := store.TakeCode(ctx, key('c', 1), at(59))
	if err != nil || conn.ID != "" {
		t.Fatalf("first take: %+v, %v", conn, err)
	}
	if got.ClientID != want.ClientID || got.RedirectURI != want.RedirectURI || got.Subject != want.Subject ||
		!slices.Equal(got.Scopes, want.Scopes) || got.Challenge != want.Challenge || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("code\n got %+v\nwant %+v", got, want)
	}
	// The record is kept until its deadline: every later take is reuse.
	for range 2 {
		again, conn, err := store.TakeCode(ctx, key('c', 1), at(59))
		reused(t, conn, err)
		if again.Subject != "" || again.ClientID != "" || len(again.Scopes) != 0 {
			t.Fatalf("a reused take returned the code: %+v", again)
		}
	}
}

func codeExpiry(t *testing.T, store mcpoauth.Store) {
	ctx := t.Context()
	if err := store.CreateCode(ctx, key('c', 1), code(at(60))); err != nil {
		t.Fatal(err)
	}
	_, conn, err := store.TakeCode(ctx, key('c', 1), at(60))
	invalid(t, conn, err)
	// The expired record is deleted: an earlier clock finds nothing.
	_, conn, err = store.TakeCode(ctx, key('c', 1), at(1))
	invalid(t, conn, err)

	// At its deadline a consumed record is deleted as well. That is not
	// reuse and it keeps the connection.
	linked := connection(1)
	linked.Code = consumed(t, store, 2)
	create(t, store, linked)
	_, conn, err = store.TakeCode(ctx, linked.Code, at(60))
	invalid(t, conn, err)
	present(t, store, linked, at(61))
	_, conn, err = store.TakeCode(ctx, linked.Code, at(1))
	invalid(t, conn, err)
	present(t, store, linked, at(61))

	// Neither does the deadline spare a record already marked as reused.
	marked := consumed(t, store, 3)
	_, conn, err = store.TakeCode(ctx, marked, at(2))
	reused(t, conn, err)
	_, conn, err = store.TakeCode(ctx, marked, at(60))
	invalid(t, conn, err)
	_, conn, err = store.TakeCode(ctx, marked, at(2))
	invalid(t, conn, err)
}

func codeCollision(t *testing.T, store mcpoauth.Store) {
	ctx := t.Context()
	if err := store.CreateCode(ctx, key('c', 1), code(at(60))); err != nil {
		t.Fatal(err)
	}
	other := code(at(60))
	other.Subject = "other"
	if err := store.CreateCode(ctx, key('c', 1), other); !errors.Is(err, mcpoauth.ErrCollision) {
		t.Fatalf("duplicate key: %v", err)
	}
	got, _, err := store.TakeCode(ctx, key('c', 1), at(1))
	if err != nil || got.Subject != "user" {
		t.Fatalf("a collision changed the stored code: %+v, %v", got, err)
	}
}

func codeConcurrent(t *testing.T, store mcpoauth.Store) {
	ctx := t.Context()
	if err := store.CreateCode(ctx, key('c', 1), code(at(60))); err != nil {
		t.Fatal(err)
	}
	var taken atomic.Int32
	var wg sync.WaitGroup
	begin := make(chan struct{})
	for range 16 {
		wg.Go(func() {
			<-begin
			switch _, conn, err := store.TakeCode(ctx, key('c', 1), at(1)); {
			case err == nil:
				taken.Add(1)
			case !errors.Is(err, mcpoauth.ErrReused) || conn.ID != "":
				t.Errorf("losing take: %+v, %v", conn, err)
			}
		})
	}
	close(begin)
	wg.Wait()
	if taken.Load() != 1 {
		t.Fatalf("%d takes succeeded, want 1", taken.Load())
	}
	// A losing take marked the record, so no connection can follow.
	conn := connection(1)
	conn.Code = key('c', 1)
	if err := store.Create(ctx, conn); !errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("connection from a reused code: %v", err)
	}
	absent(t, store, conn, at(1))
}

func codeReused(t *testing.T, store mcpoauth.Store) {
	ctx, conn, other, plain := t.Context(), connection(1), connection(2), connection(3)
	conn.Code, other.Code = consumed(t, store, 1), consumed(t, store, 2)
	create(t, store, conn, other, plain)
	got, deleted, err := store.TakeCode(ctx, conn.Code, at(2))
	if !errors.Is(err, mcpoauth.ErrReused) || !errors.Is(err, mcpoauth.ErrInvalid) || got.Subject != "" {
		t.Fatalf("consumed code: %+v, %v", got, err)
	}
	same(t, deleted, conn)
	// The deletion is committed.
	absent(t, store, conn, at(3))
	if _, err := store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(3), rotation(1, 3)); !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("rotation after code reuse: %v", err)
	}
	// Later takes find no connection, and the mark refuses a new one.
	_, deleted, err = store.TakeCode(ctx, conn.Code, at(4))
	reused(t, deleted, err)
	if err := store.Create(ctx, conn); !errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("connection from a reused code: %v", err)
	}
	absent(t, store, conn, at(5))
	present(t, store, other, at(5))
	present(t, store, plain, at(5))
}

func codeReusedEarly(t *testing.T, store mcpoauth.Store) {
	ctx, conn := t.Context(), connection(1)
	conn.Code = consumed(t, store, 1)
	_, deleted, err := store.TakeCode(ctx, conn.Code, at(2))
	reused(t, deleted, err)
	if err := store.Create(ctx, conn); !errors.Is(err, mcpoauth.ErrReused) || !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("connection from a reused code: %v", err)
	}
	absent(t, store, conn, at(3))
	// Nothing of the refused connection was stored.
	conn.Code = mcpoauth.Key{}
	create(t, store, conn)
}

func codeReusedRotated(t *testing.T, store mcpoauth.Store) {
	ctx, conn := t.Context(), connection(1)
	conn.Code = consumed(t, store, 1)
	create(t, store, conn)
	next := rotation(1, 10)
	want := conn
	want.Access, want.AccessExpiry = next.Access, next.AccessExpiry
	want.Refresh, want.RefreshExpiry = next.Refresh, next.RefreshExpiry
	want.RefreshedAt = at(10)
	got, err := store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(10), next)
	if err != nil {
		t.Fatal(err)
	}
	same(t, got, want)
	present(t, store, want, at(11))
	if got, err = store.Use(ctx, next.Access, at(11)); err != nil {
		t.Fatal(err)
	}
	same(t, got, want)
	_, deleted, err := store.TakeCode(ctx, conn.Code, at(12))
	if !errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("consumed code after rotation: %v", err)
	}
	same(t, deleted, want)
	absent(t, store, want, at(13))
}

// codeReusedConcurrent races the creation of a connection against a second
// take of its code. Whichever comes first, no connection remains.
func codeReusedConcurrent(t *testing.T, store mcpoauth.Store) {
	ctx := t.Context()
	for i := range 64 {
		conn := connection(1)
		conn.Code = consumed(t, store, i)
		var wg sync.WaitGroup
		begin := make(chan struct{})
		wg.Go(func() {
			<-begin
			if err := store.Create(ctx, conn); err != nil && !errors.Is(err, mcpoauth.ErrReused) {
				t.Errorf("create: %v", err)
			}
		})
		wg.Go(func() {
			<-begin
			if _, _, err := store.TakeCode(ctx, conn.Code, at(2)); !errors.Is(err, mcpoauth.ErrReused) {
				t.Errorf("take of a consumed code: %v", err)
			}
		})
		close(begin)
		wg.Wait()
		absent(t, store, conn, at(3))
	}
}

func roundTrip(t *testing.T, store mcpoauth.Store) {
	ctx, conn := t.Context(), connection(1)
	conn.AbsoluteExpiry = at(5000)
	conn.Code = consumed(t, store, 1)
	create(t, store, conn)
	present(t, store, conn, at(1))
	got, err := store.Use(ctx, conn.Access, at(1))
	if err != nil {
		t.Fatal(err)
	}
	same(t, got, conn)
	if _, err := store.Use(ctx, key('a', 9), at(1)); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("unknown access token: %v", err)
	}
	if _, err := store.Lookup(ctx, key('s', 9), at(1)); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("unknown selector: %v", err)
	}
	// The refresh digest is not an access token and the reverse.
	if _, err := store.Use(ctx, conn.Refresh, at(1)); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("refresh digest used as an access token: %v", err)
	}
}

func createCollision(t *testing.T, store mcpoauth.Store) {
	first := connection(1)
	create(t, store, first)
	for name, change := range map[string]func(*mcpoauth.Connection){
		"ID":       func(c *mcpoauth.Connection) { c.ID = first.ID },
		"Selector": func(c *mcpoauth.Connection) { c.Selector = first.Selector },
		"Access":   func(c *mcpoauth.Connection) { c.Access = first.Access },
	} {
		second := connection(2)
		second.Subject = "other"
		change(&second)
		if err := store.Create(t.Context(), second); !errors.Is(err, mcpoauth.ErrCollision) {
			t.Fatalf("duplicate %s: %v", name, err)
		}
		present(t, store, first, at(1))
		got, err := store.Use(t.Context(), first.Access, at(1))
		if err != nil {
			t.Fatalf("duplicate %s: %v", name, err)
		}
		same(t, got, first)
		// No part of the rejected connection may have been stored.
		unused := connection(2)
		if _, err := store.Lookup(t.Context(), unused.Selector, at(1)); name != "Selector" && !errors.Is(err, mcpoauth.ErrInvalid) {
			t.Fatalf("duplicate %s stored a selector: %v", name, err)
		}
		if _, err := store.Use(t.Context(), unused.Access, at(1)); name != "Access" && !errors.Is(err, mcpoauth.ErrInvalid) {
			t.Fatalf("duplicate %s stored an access token: %v", name, err)
		}
	}
	create(t, store, connection(2))
}

// createCode checks that a connection with a Code needs the consumed record.
func createCode(t *testing.T, store mcpoauth.Store) {
	ctx := t.Context()
	if err := store.CreateCode(ctx, key('c', 2), code(at(60))); err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]mcpoauth.Key{"missing": key('c', 1), "unconsumed": key('c', 2)} {
		conn := connection(1)
		conn.Code = k
		if err := store.Create(ctx, conn); !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
			t.Fatalf("connection from a %s code: %v", name, err)
		}
		absent(t, store, conn, at(1))
	}
	// The refusal neither created nor consumed a record.
	_, deleted, err := store.TakeCode(ctx, key('c', 1), at(1))
	invalid(t, deleted, err)
	if _, _, err := store.TakeCode(ctx, key('c', 2), at(1)); err != nil {
		t.Fatalf("a refused connection consumed the code: %v", err)
	}
	conn := connection(1)
	conn.Code = key('c', 2)
	create(t, store, conn)
	present(t, store, conn, at(1))

	// A record deleted at its deadline refuses the connection as a missing one.
	late := connection(2)
	late.Code = consumed(t, store, 3)
	_, deleted, err = store.TakeCode(ctx, late.Code, at(60))
	invalid(t, deleted, err)
	if err := store.Create(ctx, late); !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("connection from a deleted code: %v", err)
	}
	absent(t, store, late, at(1))
}

func createCodeCollision(t *testing.T, store mcpoauth.Store) {
	ctx, first := t.Context(), connection(1)
	first.Code = consumed(t, store, 1)
	create(t, store, first)
	second := connection(2)
	second.Code = first.Code
	if err := store.Create(ctx, second); !errors.Is(err, mcpoauth.ErrCollision) {
		t.Fatalf("duplicate Code: %v", err)
	}
	present(t, store, first, at(1))
	absent(t, store, second, at(1))

	// The zero Code links no code: any number of connections may carry it,
	// and a reused record stored under the zero key deletes none of them.
	plain, other := connection(3), connection(4)
	create(t, store, plain, other)
	if err := store.CreateCode(ctx, mcpoauth.Key{}, code(at(60))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.TakeCode(ctx, mcpoauth.Key{}, at(1)); err != nil {
		t.Fatal(err)
	}
	_, deleted, err := store.TakeCode(ctx, mcpoauth.Key{}, at(2))
	reused(t, deleted, err)
	present(t, store, plain, at(3))
	present(t, store, other, at(3))
	create(t, store, connection(5))
	present(t, store, first, at(3))
}

func rotate(t *testing.T, store mcpoauth.Store) {
	ctx, conn := t.Context(), connection(1)
	create(t, store, conn)
	if _, err := store.Rotate(ctx, key('s', 9), conn.Refresh, "client", at(10), rotation(1, 10)); !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("unknown selector: %v", err)
	}
	next := rotation(1, 10)
	got, err := store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(10), next)
	if err != nil {
		t.Fatal(err)
	}
	want := conn
	want.Access, want.AccessExpiry = next.Access, next.AccessExpiry
	want.Refresh, want.RefreshExpiry = next.Refresh, next.RefreshExpiry
	want.RefreshedAt = at(10)
	same(t, got, want)
	present(t, store, want, at(11))
	if _, err := store.Use(ctx, conn.Access, at(11)); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("previous access token after rotation: %v", err)
	}
	if got, err = store.Use(ctx, next.Access, at(11)); err != nil {
		t.Fatal(err)
	}
	same(t, got, want)
	// The rotated deadline extends the refresh lifetime past the first one.
	if _, err := store.Lookup(ctx, conn.Selector, at(1005)); err != nil {
		t.Fatalf("rotation did not extend the refresh deadline: %v", err)
	}
	// A second rotation continues from the new refresh token.
	if _, err := store.Rotate(ctx, conn.Selector, next.Refresh, "client", at(20), rotation(2, 20)); err != nil {
		t.Fatal(err)
	}
}

func rotateOtherClient(t *testing.T, store mcpoauth.Store) {
	conn := connection(1)
	create(t, store, conn)
	got, err := store.Rotate(t.Context(), conn.Selector, conn.Refresh, "other", at(10), rotation(1, 10))
	if !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) || got.ID != "" {
		t.Fatalf("another client: %+v, %v", got, err)
	}
	present(t, store, conn, at(11))
	if _, err := store.Use(t.Context(), conn.Access, at(11)); err != nil {
		t.Fatalf("another client changed the access token: %v", err)
	}
}

func rotateExpired(t *testing.T, store mcpoauth.Store) {
	idle, absolute := connection(1), connection(2)
	absolute.AbsoluteExpiry = at(500)
	create(t, store, idle, absolute)
	for n, tc := range []struct {
		conn mcpoauth.Connection
		now  int
	}{{idle, 1000}, {absolute, 500}} {
		_, err := store.Rotate(t.Context(), tc.conn.Selector, tc.conn.Refresh, "client", at(tc.now), rotation(n, tc.now))
		if !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
			t.Fatalf("rotation at the deadline: %v", err)
		}
		// The deletion is committed: an earlier clock finds nothing.
		absent(t, store, tc.conn, at(1))
	}
}

func rotateReused(t *testing.T, store mcpoauth.Store) {
	ctx, conn, other := t.Context(), connection(1), connection(2)
	create(t, store, conn, other)
	next := rotation(1, 10)
	if _, err := store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(10), next); err != nil {
		t.Fatal(err)
	}
	want := conn
	want.Access, want.AccessExpiry = next.Access, next.AccessExpiry
	want.Refresh, want.RefreshExpiry = next.Refresh, next.RefreshExpiry
	want.RefreshedAt = at(10)
	got, err := store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(20), rotation(3, 20))
	if !errors.Is(err, mcpoauth.ErrReused) || !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("rotated refresh token: %v", err)
	}
	same(t, got, want)
	absent(t, store, want, at(21))
	if _, err := store.Rotate(ctx, conn.Selector, next.Refresh, "client", at(22), rotation(4, 22)); !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("current refresh token after reuse: %v", err)
	}
	present(t, store, other, at(21))
}

func rotateCollision(t *testing.T, store mcpoauth.Store) {
	ctx, conn, other := t.Context(), connection(1), connection(2)
	create(t, store, conn, other)
	next := rotation(1, 10)
	next.Access = other.Access
	if _, err := store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(10), next); !errors.Is(err, mcpoauth.ErrCollision) {
		t.Fatalf("access digest of another connection: %v", err)
	}
	present(t, store, conn, at(11))
	present(t, store, other, at(11))
	got, err := store.Use(ctx, other.Access, at(11))
	if err != nil {
		t.Fatal(err)
	}
	same(t, got, other)
	if _, err := store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(12), rotation(1, 12)); err != nil {
		t.Fatalf("rotation after a collision: %v", err)
	}
}

// rotateOrder checks that each step is evaluated before the following ones.
func rotateOrder(t *testing.T, store mcpoauth.Store) {
	ctx := t.Context()
	wrong := key('r', 9)

	// Step 2 before 3 and 4: another client deletes nothing, even with an
	// expired connection and a wrong refresh token.
	second := connection(1)
	create(t, store, second)
	if _, err := store.Rotate(ctx, second.Selector, wrong, "other", at(1000), rotation(1, 1000)); !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("another client: %v", err)
	}
	present(t, store, second, at(1))

	// Step 3 before 4: an expired connection is not reported as reuse.
	got, err := store.Rotate(ctx, second.Selector, wrong, "client", at(1000), rotation(1, 1000))
	if !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) || got.ID != "" {
		t.Fatalf("expired connection with a wrong refresh token: %+v, %v", got, err)
	}
	absent(t, store, second, at(1))

	// Step 4 before 5: a wrong refresh token deletes even when the new
	// access digest collides.
	fourth, other := connection(2), connection(3)
	create(t, store, fourth, other)
	next := rotation(2, 10)
	next.Access = other.Access
	if _, err := store.Rotate(ctx, fourth.Selector, wrong, "client", at(10), next); !errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("wrong refresh token with a colliding access digest: %v", err)
	}
	absent(t, store, fourth, at(11))
	present(t, store, other, at(11))
}

func rotateConcurrent(t *testing.T, store mcpoauth.Store) {
	ctx, conn := t.Context(), connection(1)
	create(t, store, conn)
	var rotated atomic.Int32
	var wg sync.WaitGroup
	begin := make(chan struct{})
	for i := range 16 {
		wg.Go(func() {
			<-begin
			switch _, err := store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(10), rotation(10+i, 10)); {
			case err == nil:
				rotated.Add(1)
			case !errors.Is(err, mcpoauth.ErrInvalid):
				t.Error(err)
			}
		})
	}
	close(begin)
	wg.Wait()
	if rotated.Load() != 1 {
		t.Fatalf("%d rotations succeeded, want 1", rotated.Load())
	}
	// The first losing call reused the rotated token and deleted the connection.
	if _, err := store.Lookup(ctx, conn.Selector, at(11)); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("connection survived concurrent rotation: %v", err)
	}
	for i := range 16 {
		if _, err := store.Use(ctx, rotation(10+i, 10).Access, at(11)); !errors.Is(err, mcpoauth.ErrInvalid) {
			t.Fatalf("access token survived concurrent rotation: %v", err)
		}
	}
}

func deadlines(t *testing.T, store mcpoauth.Store) {
	ctx, idle, absolute := t.Context(), connection(1), connection(2)
	absolute.AbsoluteExpiry = at(50)
	create(t, store, idle, absolute)
	for _, tc := range []struct {
		name   string
		conn   mcpoauth.Connection
		now    int
		use    bool
		lookup bool
	}{
		{"before the access deadline", idle, 99, true, true},
		{"at the access deadline", idle, 100, false, true},
		{"before the refresh deadline", idle, 999, false, true},
		{"at the refresh deadline", idle, 1000, false, false},
		{"before the absolute deadline", absolute, 49, true, true},
		{"at the absolute deadline", absolute, 50, false, false},
	} {
		if _, err := store.Use(ctx, tc.conn.Access, at(tc.now)); (err == nil) != tc.use || (err != nil && !errors.Is(err, mcpoauth.ErrInvalid)) {
			t.Fatalf("use %s: %v", tc.name, err)
		}
		if _, err := store.Lookup(ctx, tc.conn.Selector, at(tc.now)); (err == nil) != tc.lookup || (err != nil && !errors.Is(err, mcpoauth.ErrInvalid)) {
			t.Fatalf("lookup %s: %v", tc.name, err)
		}
	}
	// Neither read deleted an expired record.
	present(t, store, idle, at(1))
	present(t, store, absolute, at(1))
}

func expiredAccess(t *testing.T, store mcpoauth.Store) {
	ctx, conn := t.Context(), connection(1)
	create(t, store, conn)
	if _, err := store.Use(ctx, conn.Access, at(200)); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("expired access token: %v", err)
	}
	present(t, store, conn, at(200))
	if _, err := store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(200), rotation(1, 200)); err != nil {
		t.Fatalf("rotation after an expired access token: %v", err)
	}
}

func revoke(t *testing.T, store mcpoauth.Store) {
	ctx, conn, other := t.Context(), connection(1), connection(2)
	if err := store.Revoke(ctx, conn.ID); err != nil {
		t.Fatalf("revoking an unknown connection: %v", err)
	}
	create(t, store, conn, other)
	for range 2 {
		if err := store.Revoke(ctx, conn.ID); err != nil {
			t.Fatal(err)
		}
	}
	absent(t, store, conn, at(1))
	if _, err := store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(1), rotation(1, 1)); !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("rotation after revocation: %v", err)
	}
	present(t, store, other, at(1))
	// A revoked connection's keys can be stored again.
	create(t, store, conn)
}

func canceled(t *testing.T, store mcpoauth.Store) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	check := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, context.Canceled) || errors.Is(err, mcpoauth.ErrInvalid) {
			t.Fatalf("%s with a canceled context: %v", name, err)
		}
	}
	conn, pending, linked, later := connection(1), connection(2), connection(3), connection(4)
	create(t, store, conn)
	if err := store.CreateCode(t.Context(), key('c', 1), code(at(60))); err != nil {
		t.Fatal(err)
	}
	linked.Code, later.Code = consumed(t, store, 3), consumed(t, store, 4)
	create(t, store, linked)

	check("CreateCode", store.CreateCode(ctx, key('c', 2), code(at(60))))
	_, _, err := store.TakeCode(ctx, key('c', 1), at(1))
	check("TakeCode", err)
	// A consumed code would be marked, and its connection deleted, if the
	// call ran. An expired one would be deleted.
	_, _, err = store.TakeCode(ctx, linked.Code, at(2))
	check("TakeCode", err)
	_, _, err = store.TakeCode(ctx, later.Code, at(2))
	check("TakeCode", err)
	_, _, err = store.TakeCode(ctx, later.Code, at(60))
	check("TakeCode", err)
	check("Create", store.Create(ctx, pending))
	// A wrong refresh token would delete the connection if the call ran.
	_, err = store.Rotate(ctx, conn.Selector, key('r', 9), "client", at(1), rotation(1, 1))
	check("Rotate", err)
	_, err = store.Rotate(ctx, conn.Selector, conn.Refresh, "client", at(1), rotation(1, 1))
	check("Rotate", err)
	_, err = store.Lookup(ctx, conn.Selector, at(1))
	check("Lookup", err)
	_, err = store.Use(ctx, conn.Access, at(1))
	check("Use", err)
	check("Revoke", store.Revoke(ctx, conn.ID))

	present(t, store, conn, at(1))
	if _, err := store.Use(t.Context(), conn.Access, at(1)); err != nil {
		t.Fatalf("a canceled call changed the access token: %v", err)
	}
	absent(t, store, pending, at(1))
	if _, _, err := store.TakeCode(t.Context(), key('c', 2), at(1)); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("a canceled CreateCode stored a code: %v", err)
	}
	if _, _, err := store.TakeCode(t.Context(), key('c', 1), at(1)); err != nil {
		t.Fatalf("a canceled TakeCode consumed the code: %v", err)
	}
	present(t, store, linked, at(1))
	if err := store.Create(t.Context(), later); err != nil {
		t.Fatalf("a canceled TakeCode marked or deleted the code: %v", err)
	}
}
