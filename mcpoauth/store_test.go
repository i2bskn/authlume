package mcpoauth_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/i2bskn/authlume/mcpoauth"
	"github.com/i2bskn/authlume/mcpoauth/storetest"
)

func TestMemoryStoreContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) mcpoauth.Store { return mcpoauth.NewMemoryStore() })
	t.Run("zero value", func(t *testing.T) {
		storetest.Run(t, func(*testing.T) mcpoauth.Store { return new(mcpoauth.MemoryStore) })
	})
}

func numbered(kind byte, n int) mcpoauth.Key {
	var k mcpoauth.Key
	k[0] = kind
	binary.BigEndian.PutUint32(k[1:], uint32(n))
	return k
}

func memoryConnection(n int, subject string, created time.Time) mcpoauth.Connection {
	return mcpoauth.Connection{
		ID: fmt.Sprintf("connection-%05d", n), Selector: numbered('s', n), Subject: subject, ClientID: "client",
		Scopes: []string{"read"}, CreatedAt: created, RefreshedAt: created,
		Access: numbered('a', n), AccessExpiry: created.Add(time.Minute),
		Refresh: numbered('r', n), RefreshExpiry: created.Add(time.Hour),
	}
}

func TestMemoryStoreCodeCapacity(t *testing.T) {
	store, ctx := mcpoauth.NewMemoryStore(), context.Background()
	live, expired := time.Now().Add(time.Hour), time.Now().Add(-time.Second)
	for i := range 4096 {
		code := mcpoauth.Code{Subject: "user", ExpiresAt: live}
		if i < 8 {
			code.ExpiresAt = expired
		}
		if err := store.CreateCode(ctx, numbered('c', i), code); err != nil {
			t.Fatal(err)
		}
	}
	// Half of the codes that expire were exchanged before their deadline, and
	// so was a live one. A consumed record keeps its slot until its deadline.
	for _, i := range []int{0, 1, 2, 3, 100} {
		if _, _, err := store.TakeCode(ctx, numbered('c', i), expired.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	// A full store reclaims the eight expired codes, consumed or not, then
	// refuses the ninth.
	for i := range 8 {
		if err := store.CreateCode(ctx, numbered('n', i), mcpoauth.Code{ExpiresAt: live}); err != nil {
			t.Fatalf("expired codes not reclaimed: %v", err)
		}
	}
	if err := store.CreateCode(ctx, numbered('n', 8), mcpoauth.Code{ExpiresAt: live}); !errors.Is(err, mcpoauth.ErrCapacity) {
		t.Fatalf("full store: %v", err)
	}
	if err := store.CreateCode(ctx, numbered('c', 100), mcpoauth.Code{ExpiresAt: live}); !errors.Is(err, mcpoauth.ErrCollision) {
		t.Fatalf("duplicate in a full store: %v", err)
	}
	// The consumed live code is still stored: presenting it again is reuse.
	if _, _, err := store.TakeCode(ctx, numbered('c', 100), time.Now()); !errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("consumed code in a full store: %v", err)
	}
	if err := store.CreateCode(ctx, numbered('n', 8), mcpoauth.Code{ExpiresAt: live}); !errors.Is(err, mcpoauth.ErrCapacity) {
		t.Fatalf("a consumed code gave up its slot: %v", err)
	}
	// The reclaimed consumed codes are gone rather than reused.
	if _, _, err := store.TakeCode(ctx, numbered('c', 0), expired.Add(-time.Minute)); !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("reclaimed consumed code: %v", err)
	}
}

func TestMemoryStoreConnectionCapacity(t *testing.T) {
	store, ctx := mcpoauth.NewMemoryStore(), context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	for i := range 4096 {
		if err := store.Create(ctx, memoryConnection(i, "user", now)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Create(ctx, memoryConnection(5000, "user", now)); !errors.Is(err, mcpoauth.ErrCapacity) {
		t.Fatalf("full store: %v", err)
	}
	if err := store.Create(ctx, memoryConnection(1, "user", now)); !errors.Is(err, mcpoauth.ErrCollision) {
		t.Fatalf("duplicate in a full store: %v", err)
	}
	if err := store.Revoke(ctx, memoryConnection(1, "user", now).ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, memoryConnection(5000, "user", now)); err != nil {
		t.Fatalf("slot of a revoked connection: %v", err)
	}
	// At the refresh deadline of every stored connection the store is reclaimed.
	later := now.Add(time.Hour)
	if err := store.Create(ctx, memoryConnection(5001, "user", later)); err != nil {
		t.Fatalf("expired connections not reclaimed: %v", err)
	}
	if _, err := store.Lookup(ctx, numbered('s', 2), now); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("reclaimed connection is still stored: %v", err)
	}
	if _, err := store.Use(ctx, numbered('a', 2), now); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("reclaimed access token is still stored: %v", err)
	}
	conns, err := store.Connections(ctx, "user", later)
	if err != nil || len(conns) != 1 {
		t.Fatalf("connections after reclaiming: %d, %v", len(conns), err)
	}
}

func TestMemoryStoreConnections(t *testing.T) {
	store, ctx := mcpoauth.NewMemoryStore(), context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	absolute := memoryConnection(5, "user", now)
	absolute.AbsoluteExpiry = now.Add(time.Minute)
	for _, conn := range []mcpoauth.Connection{
		memoryConnection(3, "user", now.Add(time.Second)),
		memoryConnection(2, "user", now),
		memoryConnection(1, "user", now),
		memoryConnection(4, "other", now),
		absolute,
	} {
		if err := store.Create(ctx, conn); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(at time.Time) []string {
		t.Helper()
		conns, err := store.Connections(ctx, "user", at)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, conn := range conns {
			ids = append(ids, conn.ID[len(conn.ID)-1:])
		}
		return ids
	}
	if got := ids(now); !slices.Equal(got, []string{"1", "2", "5", "3"}) {
		t.Fatalf("order: %v", got)
	}
	if got := ids(now.Add(time.Minute)); !slices.Equal(got, []string{"1", "2", "3"}) {
		t.Fatalf("at the absolute deadline: %v", got)
	}
	if got := ids(now.Add(time.Hour)); !slices.Equal(got, []string{"3"}) {
		t.Fatalf("at the refresh deadline: %v", got)
	}

	// A returned or stored snapshot does not alias the store's record.
	conns, err := store.Connections(ctx, "other", now)
	if err != nil || len(conns) != 1 {
		t.Fatal(len(conns), err)
	}
	conns[0].Scopes[0] = "changed"
	if again, _ := store.Lookup(ctx, numbered('s', 4), now); again.Scopes[0] != "read" {
		t.Fatal("a snapshot aliases the stored scopes")
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.Connections(canceled, "user", now); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	if err := store.RevokeSubject(canceled, "user"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	if got := ids(now); len(got) != 4 {
		t.Fatalf("a canceled call revoked connections: %v", got)
	}
}

func TestMemoryStoreRevokeSubject(t *testing.T) {
	store, ctx := mcpoauth.NewMemoryStore(), context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	for n, subject := range []string{"user", "user", "other"} {
		if err := store.Create(ctx, memoryConnection(n, subject, now)); err != nil {
			t.Fatal(err)
		}
		if err := store.CreateCode(ctx, numbered('c', n), mcpoauth.Code{Subject: subject, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	// A consumed code of each subject, with an exchange still in progress.
	for n, subject := range map[int]string{10: "user", 11: "other"} {
		if err := store.CreateCode(ctx, numbered('c', n), mcpoauth.Code{Subject: subject, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.TakeCode(ctx, numbered('c', n), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RevokeSubject(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	// The consumed record is deleted too, which stops the pending connection.
	pending := memoryConnection(10, "user", now)
	pending.Code = numbered('c', 10)
	if err := store.Create(ctx, pending); !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("connection from a revoked subject's consumed code: %v", err)
	}
	if _, err := store.Lookup(ctx, pending.Selector, now); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("a refused connection was stored: %v", err)
	}
	if _, _, err := store.TakeCode(ctx, numbered('c', 10), now); !errors.Is(err, mcpoauth.ErrInvalid) || errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("consumed code of a revoked subject: %v", err)
	}
	surviving := memoryConnection(11, "other", now)
	surviving.Code = numbered('c', 11)
	if err := store.Create(ctx, surviving); err != nil {
		t.Fatalf("another subject's consumed code: %v", err)
	}
	for n := range 2 {
		if _, err := store.Use(ctx, numbered('a', n), now); !errors.Is(err, mcpoauth.ErrInvalid) {
			t.Fatalf("access token of a revoked subject: %v", err)
		}
		if _, err := store.Lookup(ctx, numbered('s', n), now); !errors.Is(err, mcpoauth.ErrInvalid) {
			t.Fatalf("connection of a revoked subject: %v", err)
		}
		if _, _, err := store.TakeCode(ctx, numbered('c', n), now); !errors.Is(err, mcpoauth.ErrInvalid) {
			t.Fatalf("code of a revoked subject: %v", err)
		}
	}
	if _, err := store.Use(ctx, numbered('a', 2), now); err != nil {
		t.Fatalf("another subject's connection: %v", err)
	}
	if _, _, err := store.TakeCode(ctx, numbered('c', 2), now); err != nil {
		t.Fatalf("another subject's code: %v", err)
	}
}

func TestMemoryClientStore(t *testing.T) {
	storetest.RunClientStore(t, func(*testing.T) mcpoauth.ClientStore { return mcpoauth.NewMemoryClientStore() })
	t.Run("zero value", func(t *testing.T) {
		storetest.RunClientStore(t, func(*testing.T) mcpoauth.ClientStore { return new(mcpoauth.MemoryClientStore) })
	})
}
