package session

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
)

func memoryRecord(n uint64, now time.Time) State {
	s := State{Subject: "member", AuthenticatedAt: now, LastActivity: now, Idle: time.Hour, AbsoluteExpiry: now.Add(time.Hour)}
	binary.BigEndian.PutUint64(s.Key[:8], n)
	return s
}

func TestMemoryStoreCapacityAndReplacement(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Now()
	for i := range memoryCapacity {
		if err := store.Replace(ctx, nil, memoryRecord(uint64(i), now)); err != nil {
			t.Fatal(err)
		}
	}
	first, second := memoryRecord(0, now), memoryRecord(1, now)
	next := memoryRecord(memoryCapacity, now)
	if err := store.Replace(ctx, nil, next); !errors.Is(err, ErrCapacity) {
		t.Fatalf("full store: %v", err)
	}
	if err := store.Replace(ctx, &first.Key, second); !errors.Is(err, ErrCollision) {
		t.Fatalf("duplicate key: %v", err)
	}
	if _, err := store.Use(ctx, first.Key, now, false); err != nil {
		t.Fatalf("failed rotation changed previous record: %v", err)
	}
	if err := store.Replace(ctx, &first.Key, next); err != nil {
		t.Fatal(err)
	}
	if err := store.Replace(ctx, nil, memoryRecord(memoryCapacity+1, now.Add(time.Hour))); err != nil {
		t.Fatalf("expired records not reclaimed: %v", err)
	}
}

func TestMemoryStoreConcurrentTouchAndDelete(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Now()
	s := memoryRecord(1, now)
	if err := store.Replace(ctx, nil, s); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 32 {
		wg.Go(func() {
			<-start
			_, err := store.Use(ctx, s.Key, now.Add(time.Duration(i)*time.Second), true)
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Error(err)
			}
		})
	}
	wg.Go(func() {
		<-start
		if err := store.Delete(ctx, s.Key); err != nil {
			t.Error(err)
		}
	})
	close(start)
	wg.Wait()
	if _, err := store.Use(ctx, s.Key, now, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("deleted record survived: %v", err)
	}
}
