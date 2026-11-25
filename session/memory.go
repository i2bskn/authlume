package session

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrCapacity indicates the in-memory store has reached its live session limit.
var ErrCapacity = errors.New("session: memory store is full")

const memoryCapacity = 4096

// MemoryStore is a process-local store for up to 4096 sessions. Expired
// records are reclaimed on access and when an insertion needs space.
// Its zero value is ready to use.
type MemoryStore struct {
	mu      sync.Mutex
	records map[Key]State
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func (s *MemoryStore) Replace(ctx context.Context, previous *Key, next State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := s.records[next.Key]; exists || (previous != nil && *previous == next.Key) {
		return ErrCollision
	}
	var replacing bool
	if previous != nil {
		_, replacing = s.records[*previous]
	}
	if !replacing && len(s.records) >= memoryCapacity {
		for key, record := range s.records {
			if record.Expired(next.AuthenticatedAt) {
				delete(s.records, key)
			}
		}
		if len(s.records) >= memoryCapacity {
			return ErrCapacity
		}
	}
	if s.records == nil {
		s.records = make(map[Key]State)
	}
	if replacing {
		delete(s.records, *previous)
	}
	s.records[next.Key] = next
	return nil
}

func (s *MemoryStore) Use(ctx context.Context, key Key, now time.Time, touch bool) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	record, exists := s.records[key]
	if !exists {
		return State{}, ErrInvalid
	}
	if record.Expired(now) {
		delete(s.records, key)
		return State{}, ErrInvalid
	}
	if touch && now.After(record.LastActivity) {
		record.LastActivity = now
		s.records[key] = record
	}
	return record, nil
}

func (s *MemoryStore) Delete(ctx context.Context, key Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	delete(s.records, key)
	return nil
}
