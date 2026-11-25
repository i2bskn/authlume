package webauthn

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

const testOrigin = "https://auth.example"

type testStore struct {
	sync.Mutex
	record  Record
	subject string
	fail    error
}

func (s *testStore) Load(_ context.Context, subject string) ([]Record, error) {
	s.Lock()
	defer s.Unlock()
	if subject != s.subject || s.record.Version == "" {
		return nil, nil
	}
	return []Record{s.record}, nil
}
func (s *testStore) Insert(_ context.Context, subject string, key Credential) error {
	s.Lock()
	defer s.Unlock()
	if s.fail != nil {
		return s.fail
	}
	if s.record.Version != "" {
		return ErrInvalid
	}
	s.record, s.subject = Record{key, rand.Text()}, subject
	return nil
}
func (s *testStore) Update(_ context.Context, subject, version string, key Credential) error {
	s.Lock()
	defer s.Unlock()
	if s.fail != nil {
		return s.fail
	}
	if s.subject != subject || s.record.Version != version || !bytes.Equal(s.record.Credential.ID, key.ID) {
		return ErrInvalid
	}
	s.record = Record{key, rand.Text()}
	return nil
}

// A presence-only Ed25519 test authenticator, with "none" attestation.
type testKey struct {
	id      []byte
	private ed25519.PrivateKey
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{[]byte(rand.Text()), private}
}

func asJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func asCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := webauthncbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func (k testKey) response(t *testing.T, fields map[string][]byte) []byte {
	id := base64.RawURLEncoding.EncodeToString(k.id)
	encoded := map[string]string{}
	for name, value := range fields {
		encoded[name] = base64.RawURLEncoding.EncodeToString(value)
	}
	return asJSON(t, map[string]any{"id": id, "rawId": id, "type": "public-key", "response": encoded})
}
func authData(rp string, flags byte, count uint32) []byte {
	hash := sha256.Sum256([]byte(rp))
	return binary.BigEndian.AppendUint32(append(hash[:], flags), count)
}
func (k testKey) registration(t *testing.T, challenge, origin string) []byte {
	key := asCBOR(t, map[int]any{1: 1, 3: -8, -1: 6, -2: []byte(k.private.Public().(ed25519.PublicKey))})
	data := authData("auth.example", byte(protocol.FlagUserPresent|protocol.FlagAttestedCredentialData), 0)
	data = append(data, make([]byte, 16)...) // AAGUID
	data = binary.BigEndian.AppendUint16(data, uint16(len(k.id)))
	data = append(data, k.id...)
	data = append(data, key...)
	attestation := asCBOR(t, map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
	client := asJSON(t, protocol.CollectedClientData{Type: protocol.CreateCeremony, Origin: origin, Challenge: challenge})
	return k.response(t, map[string][]byte{"clientDataJSON": client, "attestationObject": attestation})
}

type assertion struct {
	client     protocol.CollectedClientData
	rp, handle string
	present    bool
	count      uint32
}

func validAssertion(challenge string, count uint32) assertion {
	return assertion{protocol.CollectedClientData{Type: protocol.AssertCeremony, Origin: testOrigin, Challenge: challenge}, "auth.example", "alice", true, count}
}
func (k testKey) sign(t *testing.T, a assertion) []byte {
	client := asJSON(t, a.client)
	hash := sha256.Sum256(client)
	var flags byte
	if a.present {
		flags = byte(protocol.FlagUserPresent)
	}
	data := authData(a.rp, flags, a.count)
	sig := ed25519.Sign(k.private, append(bytes.Clone(data), hash[:]...))
	return k.response(t, map[string][]byte{"clientDataJSON": client, "authenticatorData": data, "signature": sig, "userHandle": []byte(a.handle)})
}

func setup(t *testing.T) (*Verifier, *testStore, testKey) {
	t.Helper()
	store := new(testStore)
	v, err := New(testOrigin, "Test", store)
	if err != nil {
		t.Fatal(err)
	}
	return v, store, newTestKey(t)
}
func register(t *testing.T, v *Verifier, k testKey, subject string) error {
	t.Helper()
	options, tx, err := v.BeginRegistration(t.Context(), subject, "Test account")
	if err != nil {
		t.Fatal(err)
	}
	return v.FinishRegistration(t.Context(), subject, tx, k.registration(t, options.Response.Challenge.String(), testOrigin))
}
func start(t *testing.T, v *Verifier) (string, *Ceremony) {
	t.Helper()
	options, tx, err := v.BeginVerification(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Response.AllowedCredentials) != 1 {
		t.Fatal("expected one allowed key")
	}
	return options.Response.Challenge.String(), tx
}
func TestRegisterAndVerify(t *testing.T) {
	v, store, k := setup(t)
	if _, _, err := v.BeginVerification(t.Context(), "alice"); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty allow list accepted")
	}
	if err := register(t, v, k, "alice"); err != nil {
		t.Fatal(err)
	}
	options, _, err := v.BeginRegistration(t.Context(), "alice", "Alice")
	if err != nil || len(options.Response.CredentialExcludeList) != 1 {
		t.Fatal("missing exclusion list", err)
	}
	selection := options.Response.AuthenticatorSelection
	if selection.AuthenticatorAttachment != "" || selection.ResidentKey != protocol.ResidentKeyRequirementPreferred || selection.UserVerification != protocol.VerificationPreferred {
		t.Fatalf("expected both platform passkeys and roaming presence-only keys: %+v", selection)
	}
	if err := register(t, v, k, "bob"); err == nil {
		t.Fatal("duplicate ID accepted across users")
	}
	if _, _, err := v.BeginVerification(t.Context(), "bob"); err == nil {
		t.Fatal("wrong account permitted")
	}
	for _, count := range []uint32{0, 0, 1} {
		challenge, tx := start(t, v)
		if err := v.FinishVerification(t.Context(), "alice", tx, k.sign(t, validAssertion(challenge, count))); err != nil {
			t.Fatal(err)
		}
	}
	if store.record.Credential.Authenticator.SignCount != 1 {
		t.Fatal("counter not persisted")
	}
	challenge, tx := start(t, v)
	if err := v.FinishVerification(t.Context(), "alice", tx, k.sign(t, validAssertion(challenge, 1))); !errors.Is(err, ErrInvalid) {
		t.Fatal("counter reuse", err)
	}
}
func TestAssertionRejection(t *testing.T) {
	v, _, key := setup(t)
	if err := register(t, v, key, "alice"); err != nil {
		t.Fatal(err)
	}
	other := newTestKey(t)
	for name, change := range map[string]func(*assertion, *testKey){
		"origin path":        func(a *assertion, _ *testKey) { a.client.Origin = testOrigin + "/path" },
		"origin":             func(a *assertion, _ *testKey) { a.client.Origin = "https://other.example" },
		"cross-origin":       func(a *assertion, _ *testKey) { a.client.CrossOrigin = true },
		"challenge":          func(a *assertion, _ *testKey) { a.client.Challenge = "wrong" },
		"type":               func(a *assertion, _ *testKey) { a.client.Type = protocol.CreateCeremony },
		"rp":                 func(a *assertion, _ *testKey) { a.rp = "other.example" },
		"presence":           func(a *assertion, _ *testKey) { a.present = false },
		"user handle":        func(a *assertion, _ *testKey) { a.handle = "bob" },
		"signature":          func(_ *assertion, k *testKey) { k.private = other.private },
		"unknown credential": func(_ *assertion, k *testKey) { *k = other },
	} {
		t.Run(name, func(t *testing.T) {
			challenge, tx := start(t, v)
			a, k := validAssertion(challenge, 1), key
			change(&a, &k)
			if err := v.FinishVerification(t.Context(), "alice", tx, k.sign(t, a)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
			if err := v.FinishVerification(t.Context(), "alice", tx, key.sign(t, validAssertion(challenge, 1))); !errors.Is(err, ErrInvalid) {
				t.Fatal("retry accepted")
			}
		})
	}
}
func TestCeremonyBinding(t *testing.T) {
	v, _, key := setup(t)
	other, _, _ := setup(t)
	for _, name := range []string{"subject", "purpose", "instance", "expiry", "response", "origin", "challenge"} {
		t.Run(name, func(t *testing.T) {
			options, tx, err := v.BeginRegistration(t.Context(), "alice", "Alice")
			if err != nil {
				t.Fatal(err)
			}
			response := key.registration(t, options.Response.Challenge.String(), testOrigin)
			switch name {
			case "origin":
				err = v.FinishRegistration(t.Context(), "alice", tx, key.registration(t, options.Response.Challenge.String(), testOrigin+"/path"))
			case "challenge":
				err = v.FinishRegistration(t.Context(), "alice", tx, key.registration(t, "wrong", testOrigin))
			case "subject":
				err = v.FinishRegistration(t.Context(), "bob", tx, response)
			case "purpose":
				err = v.FinishVerification(t.Context(), "alice", tx, response)
			case "instance":
				err = other.FinishRegistration(t.Context(), "alice", tx, response)
			case "expiry":
				tx.state.session.Expires = time.Now().Add(-time.Second)
				err = v.FinishRegistration(t.Context(), "alice", tx, response)
			case "response":
				err = v.FinishRegistration(t.Context(), "alice", tx, []byte("{}"))
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
			if err = v.FinishRegistration(t.Context(), "alice", tx, response); !errors.Is(err, ErrInvalid) {
				t.Fatal("retry accepted")
			}
		})
	}
}
func TestAtomicCompletion(t *testing.T) {
	v, store, k := setup(t)
	store.fail = errors.New("storage offline")
	if err := register(t, v, k, "alice"); !errors.Is(err, store.fail) {
		t.Fatal("insert failure", err)
	}
	store.fail = nil
	if err := register(t, v, k, "alice"); err != nil {
		t.Fatal(err)
	}
	challenge, tx := start(t, v)
	response := k.sign(t, validAssertion(challenge, 0))
	results := make(chan error, 2)
	// Copying the exported handle must still share its single use.
	for range 2 {
		copy := *tx
		go func() { results <- v.FinishVerification(t.Context(), "alice", &copy, response) }()
	}
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("want exactly one success: %v, %v", first, second)
	}
	for _, failure := range []string{"stale version", "revocation", "update error"} {
		t.Run(failure, func(t *testing.T) {
			old := store.record
			defer func() { store.record = old; store.fail = nil }()
			challenge, tx := start(t, v)
			switch failure {
			case "stale version":
				store.record.Version = rand.Text()
			case "revocation":
				store.record = Record{}
			case "update error":
				store.fail = errors.New("storage offline")
			}
			if err := v.FinishVerification(t.Context(), "alice", tx, k.sign(t, validAssertion(challenge, 1))); err == nil {
				t.Fatal("accepted without successful conditional write")
			}
		})
	}
}
func TestConfigurationAndSubject(t *testing.T) {
	v, s, _ := setup(t)
	for _, origin := range []string{"", "http://auth.example", "https://", "https://user@auth.example", "https://auth.example/path", "https://auth.example?x=1", "https://auth.example#here"} {
		if _, err := New(origin, "Test", s); err == nil {
			t.Errorf("accepted origin %q", origin)
		}
	}
	canonical, err := New("https://AUTH.EXAMPLE:443", "Test", s)
	if err != nil {
		t.Fatal(err)
	}
	if err := register(t, canonical, newTestKey(t), "alice"); err != nil {
		t.Fatal("canonical origin", err)
	}
	for _, subject := range []string{"", strings.Repeat("x", 65)} {
		if _, _, err := v.BeginRegistration(t.Context(), subject, "User"); err == nil {
			t.Fatal("accepted invalid subject")
		}
	}
}
