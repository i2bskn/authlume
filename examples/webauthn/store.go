package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"sync"

	"github.com/i2bskn/authlume/webauthn"
)

type demoKey struct {
	id      []byte
	version string
	encoded []byte
	passkey bool
}

// This demo allows exactly one first enrollment as a second factor, then any
// number of passkeys. The conditional inserts enforce that policy even when
// two authorized registrations finish together.
type demoStore struct {
	mu   sync.Mutex
	keys []demoKey
}

func (s *demoStore) Load(ctx context.Context, subject string) ([]webauthn.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Passkey sign-in passes an unauthenticated subject. Match it exactly.
	if subject != demoSubject {
		return nil, nil
	}
	var records []webauthn.Record
	for _, k := range s.keys {
		var key webauthn.Credential
		if err := json.Unmarshal(k.encoded, &key); err != nil {
			return nil, err
		}
		records = append(records, webauthn.Record{Credential: key, Version: k.version, Passkey: k.passkey})
	}
	return records, nil
}

func (s *demoStore) enrolled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys) != 0
}

// Insert accepts a second-factor key only as the first credential, and a
// passkey only once a second-factor key exists.
func (s *demoStore) Insert(ctx context.Context, subject string, key webauthn.Credential, passkey bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secondFactor := false
	for _, k := range s.keys {
		if bytes.Equal(k.id, key.ID) {
			return webauthn.ErrInvalid
		}
		secondFactor = secondFactor || !k.passkey
	}
	allowed := len(s.keys) == 0
	if passkey {
		allowed = secondFactor
	}
	if subject != demoSubject || !allowed {
		return webauthn.ErrInvalid
	}
	saved, err := encode(ctx, key, passkey)
	if err != nil {
		return err
	}
	s.keys = append(s.keys, saved)
	return nil
}

// Update keeps the passkey marker set at insert.
func (s *demoStore) Update(ctx context.Context, subject, version string, key webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if subject != demoSubject || version == "" {
		return webauthn.ErrInvalid
	}
	for i, k := range s.keys {
		if bytes.Equal(k.id, key.ID) && k.version == version {
			saved, err := encode(ctx, key, k.passkey)
			if err != nil {
				return err
			}
			s.keys[i] = saved
			return nil
		}
	}
	return webauthn.ErrInvalid
}

func encode(ctx context.Context, key webauthn.Credential, passkey bool) (demoKey, error) {
	if err := ctx.Err(); err != nil {
		return demoKey{}, err
	}
	data, err := json.Marshal(key)
	if err != nil {
		return demoKey{}, err
	}
	return demoKey{id: bytes.Clone(key.ID), version: rand.Text(), encoded: data, passkey: passkey}, nil
}
