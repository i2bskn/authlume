// Package oidc authenticates a browser with a configured OpenID Connect issuer.
// It returns a verified external identity. The application owns account linking,
// enrollment, additional authentication and session issuance.
package oidc

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"
)

// ErrInvalid indicates that the login did not produce a verified identity.
var ErrInvalid = errors.New("oidc: invalid or incomplete login")

// Key binds the client configuration, secret browser cookie and public state.
// It is safe to use as a storage key.
type Key [32]byte

// Transaction contains server-side secrets. Keep it confidential, out of logs
// and inaccessible to the browser.
type Transaction struct {
	Nonce     string
	Verifier  string
	ExpiresAt time.Time
	StartedAt time.Time
	// MaxAgeSeconds is the requested freshness constraint. Persist nil distinctly from zero.
	MaxAgeSeconds *int64
	// AppData is the application's opaque value from AuthorizationOptions.
	// Persist it as is. Nil and empty are equivalent.
	AppData []byte
}

// Store operations on a key must be atomic, including across processes. Arrange
// physical cleanup of expired records. Return backend failures as distinct errors.
type Store interface {
	// Create inserts without overwriting an existing live record.
	Create(ctx context.Context, key Key, tx Transaction) error
	// Take consumes a record exactly once. Return ErrInvalid for a missing or
	// expired record (now >= ExpiresAt). A failed retry cannot restore a record.
	Take(ctx context.Context, key Key, now time.Time) (Transaction, error)
}

// MemoryStore holds at most 4096 outstanding logins in one process.
// Use NewMemoryStore to construct it.
type MemoryStore struct {
	mu      sync.Mutex
	pending map[Key]Transaction
}

// NewMemoryStore returns an empty, bounded single-process transaction store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{pending: make(map[Key]Transaction)}
}

func (s *MemoryStore) Create(_ context.Context, key Key, tx Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) >= 4096 {
		now := time.Now()
		for k, t := range s.pending {
			if !now.Before(t.ExpiresAt) {
				delete(s.pending, k)
			}
		}
		if len(s.pending) >= 4096 {
			return errors.New("oidc: too many pending logins")
		}
	}
	if _, ok := s.pending[key]; ok {
		return errors.New("oidc: transaction key collision")
	}
	tx.AppData = bytes.Clone(tx.AppData)
	s.pending[key] = tx
	return nil
}

func (s *MemoryStore) Take(_ context.Context, key Key, now time.Time) (Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.pending[key]
	delete(s.pending, key)
	if !ok || !now.Before(tx.ExpiresAt) {
		return Transaction{}, ErrInvalid
	}
	tx.AppData = bytes.Clone(tx.AppData)
	return tx, nil
}
