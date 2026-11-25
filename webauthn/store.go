package webauthn

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"
)

// Key is a digest that binds the origin and a secret browser handle.
// It is safe to use as a storage key.
type Key [32]byte

// CeremonyStore holds pending ceremonies. Operations on a key must be atomic,
// including across processes. Arrange physical cleanup of expired records.
// Return backend failures as errors distinct from ErrInvalid. Scope it to one
// origin.
//
// A record authorizes its subject: protect the store's integrity like the
// credential Store and keep records confidential, out of logs and inaccessible
// to the browser. Records use go-webauthn's session encoding; after a
// dependency upgrade, outstanding records may fail with ErrRecord.
//
// Serialize an application's subject-wide deletion with Create and Take for
// that subject; Take after deletion returns ErrInvalid. Deletion cannot stop a
// Finish whose Take already succeeded, so also enforce recovery state in the
// credential Store's Insert preconditions (in the same transaction).
//
// A passkey login ceremony is created with an empty subject, so subject-wide
// deletion does not remove it. Revocation after Begin takes effect when Finish
// reloads the credentials through Store.Load and when Update matches the version.
type CeremonyStore interface {
	// Create inserts without overwriting an existing live record. subject lets
	// the application revoke a subject's outstanding ceremonies, for example
	// during recovery or account suspension. It is empty for a passkey login.
	Create(ctx context.Context, key Key, subject string, record []byte, expiresAt time.Time) error
	// Take consumes a record exactly once. Return ErrInvalid for a missing or
	// expired record (now >= expiresAt). A failed retry cannot restore a record.
	Take(ctx context.Context, key Key, now time.Time) ([]byte, error)
}

type pendingCeremony struct {
	subject   string
	record    []byte
	expiresAt time.Time
}

// MemoryCeremonyStore holds at most 4096 outstanding ceremonies in one process.
// Use NewMemoryCeremonyStore to construct it.
//
// The limit is shared by every ceremony. Unlimited unauthenticated
// BeginPasskeyLogin calls fill it: ceremonies live for five minutes, so about
// 14 begins per second reach 4096 and second-factor begins then fail too.
// Limit such begins per client and overall. The application also owns the
// capacity design of a shared store.
type MemoryCeremonyStore struct {
	mu      sync.Mutex
	pending map[Key]pendingCeremony
}

// NewMemoryCeremonyStore returns an empty, bounded single-process ceremony store.
func NewMemoryCeremonyStore() *MemoryCeremonyStore {
	return &MemoryCeremonyStore{pending: make(map[Key]pendingCeremony)}
}

func (s *MemoryCeremonyStore) Create(_ context.Context, key Key, subject string, record []byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) >= 4096 {
		now := time.Now()
		for k, c := range s.pending {
			if !now.Before(c.expiresAt) {
				delete(s.pending, k)
			}
		}
		if len(s.pending) >= 4096 {
			return errors.New("webauthn: too many pending ceremonies")
		}
	}
	if _, ok := s.pending[key]; ok {
		return errors.New("webauthn: ceremony key collision")
	}
	s.pending[key] = pendingCeremony{subject: subject, record: bytes.Clone(record), expiresAt: expiresAt}
	return nil
}

func (s *MemoryCeremonyStore) Take(_ context.Context, key Key, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.pending[key]
	delete(s.pending, key)
	if !ok || !now.Before(c.expiresAt) {
		return nil, ErrInvalid
	}
	return c.record, nil
}

// Revoke deletes every outstanding ceremony of subject. An empty subject
// deletes nothing, which keeps the anonymous passkey login ceremonies.
func (s *MemoryCeremonyStore) Revoke(_ context.Context, subject string) error {
	if subject == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.pending {
		if c.subject == subject {
			delete(s.pending, k)
		}
	}
	return nil
}
