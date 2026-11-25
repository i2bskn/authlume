package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"sync"

	"github.com/i2bskn/authlume/webauthn"
)

// This demo allows exactly one first enrollment. The conditional insert
// enforces that policy even when two authorized registrations finish together.
type demoStore struct {
	mu      sync.Mutex
	id      []byte
	version string
	encoded []byte
}

func (s *demoStore) Load(ctx context.Context, subject string) ([]webauthn.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if subject != demoSubject || s.version == "" {
		return nil, nil
	}
	var key webauthn.Credential
	if err := json.Unmarshal(s.encoded, &key); err != nil {
		return nil, err
	}
	return []webauthn.Record{{Credential: key, Version: s.version}}, nil
}

func (s *demoStore) enrolled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version != ""
}

func (s *demoStore) Insert(ctx context.Context, subject string, key webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if subject != demoSubject || s.version != "" {
		return webauthn.ErrInvalid
	}
	return s.save(ctx, key)
}

func (s *demoStore) Update(ctx context.Context, subject, version string, key webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if subject != demoSubject || version == "" || version != s.version || !bytes.Equal(s.id, key.ID) {
		return webauthn.ErrInvalid
	}
	return s.save(ctx, key)
}

func (s *demoStore) save(ctx context.Context, key webauthn.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}
	s.id, s.version, s.encoded = bytes.Clone(key.ID), rand.Text(), data
	return nil
}
