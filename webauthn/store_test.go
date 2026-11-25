package webauthn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func testKey(n int) Key {
	var k Key
	binary.BigEndian.PutUint64(k[:], uint64(n))
	return k
}

func TestMemoryCeremonyStore(t *testing.T) {
	s := NewMemoryCeremonyStore()
	ctx, now := t.Context(), time.Now()
	expires := now.Add(time.Minute)
	record := []byte("record")
	if err := s.Create(ctx, testKey(1), "alice", record, expires); err != nil {
		t.Fatal(err)
	}
	record[0] = 'X'
	if err := s.Create(ctx, testKey(1), "alice", []byte("other"), expires); err == nil {
		t.Fatal("overwrote a live record")
	}
	got, err := s.Take(ctx, testKey(1), now)
	if err != nil || !bytes.Equal(got, []byte("record")) {
		t.Fatal("take", string(got), err)
	}
	if _, err := s.Take(ctx, testKey(1), now); !errors.Is(err, ErrInvalid) {
		t.Fatal("second take", err)
	}
	if err := s.Create(ctx, testKey(2), "alice", record, expires); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(ctx, testKey(2), expires); !errors.Is(err, ErrInvalid) {
		t.Fatal("take at expiry", err)
	}
}

func TestMemoryCeremonyStoreRevoke(t *testing.T) {
	s := NewMemoryCeremonyStore()
	ctx, expires := t.Context(), time.Now().Add(time.Minute)
	for i, subject := range []string{"alice", "alice", "bob"} {
		if err := s.Create(ctx, testKey(i), subject, []byte(subject), expires); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Revoke(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if _, err := s.Take(ctx, testKey(i), time.Now()); !errors.Is(err, ErrInvalid) {
			t.Fatal("revoked ceremony", i, err)
		}
	}
	if got, err := s.Take(ctx, testKey(2), time.Now()); err != nil || string(got) != "bob" {
		t.Fatal("other subject", err)
	}
}

func TestMemoryCeremonyStoreLimit(t *testing.T) {
	s := NewMemoryCeremonyStore()
	ctx := t.Context()
	live := time.Now().Add(time.Minute)
	if err := s.Create(ctx, testKey(0), "alice", nil, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 4096; i++ {
		if err := s.Create(ctx, testKey(i), "alice", nil, live); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := s.Create(ctx, testKey(4096), "alice", nil, live); err != nil {
		t.Fatal("expired record not reclaimed", err)
	}
	if err := s.Create(ctx, testKey(4097), "alice", nil, live); err == nil {
		t.Fatal("exceeded the limit")
	}
}

func TestMemoryCeremonyStoreConcurrentTake(t *testing.T) {
	s := NewMemoryCeremonyStore()
	if err := s.Create(t.Context(), testKey(1), "alice", []byte("record"), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	results := make(chan error, 8)
	for range cap(results) {
		go func() {
			<-ready
			_, err := s.Take(t.Context(), testKey(1), time.Now())
			results <- err
		}()
	}
	close(ready)
	successes := 0
	for range cap(results) {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("got %d successful takes", successes)
	}
}
