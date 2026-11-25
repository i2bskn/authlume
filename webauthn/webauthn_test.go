package webauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/i2bskn/authlume/internal/webauthntest"
)

const (
	testOrigin = "https://auth.example"
	testRPID   = "auth.example"
	present    = byte(protocol.FlagUserPresent)
)

type storedKey struct {
	subject string
	record  Record
}

// testStore holds credentials for any number of subjects, keyed by credential ID.
type testStore struct {
	mu            sync.Mutex
	keys          map[string]storedKey
	fail          error
	ignoreVersion bool
	updates       int
}

func newTestStore() *testStore { return &testStore{keys: map[string]storedKey{}} }

func (s *testStore) Load(_ context.Context, subject string) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var records []Record
	for _, k := range s.keys {
		if k.subject == subject {
			records = append(records, k.record)
		}
	}
	return records, nil
}
func (s *testStore) Insert(_ context.Context, subject string, key Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	if _, ok := s.keys[string(key.ID)]; ok {
		return ErrInvalid
	}
	s.keys[string(key.ID)] = storedKey{subject, Record{key, rand.Text()}}
	return nil
}
func (s *testStore) Update(_ context.Context, subject, version string, key Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	old, ok := s.keys[string(key.ID)]
	if !ok || old.subject != subject || (!s.ignoreVersion && old.record.Version != version) {
		return ErrInvalid
	}
	s.keys[string(key.ID)] = storedKey{subject, Record{key, rand.Text()}}
	s.updates++
	return nil
}
func (s *testStore) get(id []byte) Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[string(id)].record
}
func (s *testStore) set(id []byte, r Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.keys[string(id)]
	k.record = r
	s.keys[string(id)] = k
}
func (s *testStore) remove(id []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, string(id))
}

// testCeremonies records created ceremonies and can alter or fail Take.
type testCeremonies struct {
	*MemoryCeremonyStore
	mu        sync.Mutex
	createErr error
	takeErr   error
	mutate    func([]byte) []byte
	records   [][]byte
	takes     int
}

func newTestCeremonies() *testCeremonies {
	return &testCeremonies{MemoryCeremonyStore: NewMemoryCeremonyStore()}
}
func (c *testCeremonies) Create(ctx context.Context, key Key, subject string, record []byte, expiresAt time.Time) error {
	c.mu.Lock()
	if c.createErr != nil {
		c.mu.Unlock()
		return c.createErr
	}
	c.records = append(c.records, bytes.Clone(record))
	c.mu.Unlock()
	return c.MemoryCeremonyStore.Create(ctx, key, subject, record, expiresAt)
}
func (c *testCeremonies) Take(ctx context.Context, key Key, now time.Time) ([]byte, error) {
	c.mu.Lock()
	c.takes++
	takeErr, mutate := c.takeErr, c.mutate
	c.mu.Unlock()
	record, err := c.MemoryCeremonyStore.Take(ctx, key, now)
	if takeErr != nil {
		return nil, takeErr
	}
	if err != nil || mutate == nil {
		return record, err
	}
	return mutate(record), nil
}
func (c *testCeremonies) last(t *testing.T) ceremonyRecord {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var rec ceremonyRecord
	if err := json.Unmarshal(c.records[len(c.records)-1], &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func setup(t *testing.T) (*Verifier, *testStore, *testCeremonies, webauthntest.Key) {
	t.Helper()
	store, ceremonies := newTestStore(), newTestCeremonies()
	v, err := New(testOrigin, "Test", store, ceremonies)
	if err != nil {
		t.Fatal(err)
	}
	return v, store, ceremonies, webauthntest.New(t)
}

func creation(t *testing.T, options json.RawMessage) protocol.CredentialCreation {
	t.Helper()
	var c protocol.CredentialCreation
	if err := json.Unmarshal(options, &c); err != nil {
		t.Fatal(err)
	}
	return c
}
func assertionOptions(t *testing.T, options json.RawMessage) protocol.CredentialAssertion {
	t.Helper()
	var a protocol.CredentialAssertion
	if err := json.Unmarshal(options, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

// beginRegistration returns the challenge and handle of a new registration.
func beginRegistration(t *testing.T, v *Verifier, subject string) (string, string) {
	t.Helper()
	options, handle, err := v.BeginRegistration(t.Context(), subject, "Test account")
	if err != nil {
		t.Fatal(err)
	}
	return creation(t, options).Response.Challenge.String(), handle
}
func register(t *testing.T, v *Verifier, k webauthntest.Key, subject string) error {
	t.Helper()
	challenge, handle := beginRegistration(t, v, subject)
	got, err := v.FinishRegistration(t.Context(), handle, k.Registration(t, challenge, testOrigin, testRPID, present))
	if err == nil && got != subject {
		t.Fatalf("registered %q for %q", got, subject)
	}
	if err != nil && got != "" {
		t.Fatalf("returned subject %q with %v", got, err)
	}
	return err
}

// start returns the challenge and handle of a new verification.
func start(t *testing.T, v *Verifier, subject string) (string, string) {
	t.Helper()
	options, handle, err := v.BeginVerification(t.Context(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(assertionOptions(t, options).Response.AllowedCredentials) == 0 {
		t.Fatal("expected allowed keys")
	}
	return assertionOptions(t, options).Response.Challenge.String(), handle
}
func validAssertion(challenge, subject string, count uint32) webauthntest.Assertion {
	return webauthntest.Assertion{
		Client: protocol.CollectedClientData{Type: protocol.AssertCeremony, Origin: testOrigin, Challenge: challenge},
		RPID:   testRPID, UserHandle: subject, Flags: present, Count: count,
	}
}

// wantFailure checks that a failed finish returns no subject.
func wantFailure(t *testing.T, subject string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	if subject != "" {
		t.Fatalf("returned subject %q on failure", subject)
	}
}

func TestRegisterAndVerify(t *testing.T) {
	v, store, _, k := setup(t)
	if _, _, err := v.BeginVerification(t.Context(), "alice"); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty allow list accepted")
	}
	if err := register(t, v, k, "alice"); err != nil {
		t.Fatal(err)
	}
	options, _, err := v.BeginRegistration(t.Context(), "alice", "Alice")
	if err != nil || len(creation(t, options).Response.CredentialExcludeList) != 1 {
		t.Fatal("missing exclusion list", err)
	}
	selection := creation(t, options).Response.AuthenticatorSelection
	if selection.AuthenticatorAttachment != "" || selection.ResidentKey != protocol.ResidentKeyRequirementPreferred || selection.UserVerification != protocol.VerificationPreferred {
		t.Fatalf("expected both platform passkeys and roaming presence-only keys: %+v", selection)
	}
	if err := register(t, v, k, "bob"); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate ID accepted across users", err)
	}
	if _, _, err := v.BeginVerification(t.Context(), "bob"); err == nil {
		t.Fatal("wrong account permitted")
	}
	for _, count := range []uint32{0, 0, 1} {
		challenge, handle := start(t, v, "alice")
		subject, err := v.FinishVerification(t.Context(), handle, k.Sign(t, validAssertion(challenge, "alice", count)))
		if err != nil || subject != "alice" {
			t.Fatal(subject, err)
		}
	}
	if store.get(k.ID).Credential.Authenticator.SignCount != 1 {
		t.Fatal("counter not persisted")
	}
	for _, count := range []uint32{1, 0} {
		challenge, handle := start(t, v, "alice")
		subject, err := v.FinishVerification(t.Context(), handle, k.Sign(t, validAssertion(challenge, "alice", count)))
		wantFailure(t, subject, err, ErrCloned)
		if !errors.Is(err, ErrInvalid) {
			t.Fatal("ErrCloned must wrap ErrInvalid")
		}
	}
}

func TestSubjects(t *testing.T) {
	v, _, _, alice := setup(t)
	bob := webauthntest.New(t)
	if err := register(t, v, alice, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := register(t, v, bob, "bob"); err != nil {
		t.Fatal(err)
	}
	ac, ah := start(t, v, "alice")
	bc, bh := start(t, v, "bob")
	if subject, err := v.FinishVerification(t.Context(), bh, bob.Sign(t, validAssertion(bc, "bob", 1))); err != nil || subject != "bob" {
		t.Fatal(subject, err)
	}
	if subject, err := v.FinishVerification(t.Context(), ah, alice.Sign(t, validAssertion(ac, "alice", 1))); err != nil || subject != "alice" {
		t.Fatal(subject, err)
	}
}

func TestAssertionRejection(t *testing.T) {
	v, _, _, key := setup(t)
	if err := register(t, v, key, "alice"); err != nil {
		t.Fatal(err)
	}
	other := webauthntest.New(t)
	for name, change := range map[string]func(*webauthntest.Assertion, *webauthntest.Key){
		"origin path":        func(a *webauthntest.Assertion, _ *webauthntest.Key) { a.Client.Origin = testOrigin + "/path" },
		"origin":             func(a *webauthntest.Assertion, _ *webauthntest.Key) { a.Client.Origin = "https://other.example" },
		"cross-origin":       func(a *webauthntest.Assertion, _ *webauthntest.Key) { a.Client.CrossOrigin = true },
		"challenge":          func(a *webauthntest.Assertion, _ *webauthntest.Key) { a.Client.Challenge = "wrong" },
		"type":               func(a *webauthntest.Assertion, _ *webauthntest.Key) { a.Client.Type = protocol.CreateCeremony },
		"rp":                 func(a *webauthntest.Assertion, _ *webauthntest.Key) { a.RPID = "other.example" },
		"presence":           func(a *webauthntest.Assertion, _ *webauthntest.Key) { a.Flags = 0 },
		"backup eligibility": func(a *webauthntest.Assertion, _ *webauthntest.Key) { a.Flags |= byte(protocol.FlagBackupEligible) },
		"user handle":        func(a *webauthntest.Assertion, _ *webauthntest.Key) { a.UserHandle = "bob" },
		"signature":          func(_ *webauthntest.Assertion, k *webauthntest.Key) { k.Private = other.Private },
		"unknown credential": func(_ *webauthntest.Assertion, k *webauthntest.Key) { *k = other },
		"id and rawId": func(_ *webauthntest.Assertion, k *webauthntest.Key) {
			k.ResponseID = "Zm9v"
		},
		"empty response": nil,
	} {
		t.Run(name, func(t *testing.T) {
			challenge, handle := start(t, v, "alice")
			response := []byte("{}")
			if change != nil {
				a, k := validAssertion(challenge, "alice", 1), key
				change(&a, &k)
				response = k.Sign(t, a)
			}
			subject, err := v.FinishVerification(t.Context(), handle, response)
			wantFailure(t, subject, err, ErrInvalid)
			subject, err = v.FinishVerification(t.Context(), handle, key.Sign(t, validAssertion(challenge, "alice", 1)))
			wantFailure(t, subject, err, ErrInvalid)
		})
	}
}

func TestCeremonyBinding(t *testing.T) {
	v, store, ceremonies, key := setup(t)
	// Another RP shares the ceremony store and resolves the same handles to different keys.
	otherRP, err := New("https://other.example", "Other", store, ceremonies)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"purpose", "rp", "handle", "response", "origin", "challenge", "rp hash", "presence", "backup state", "id and rawId"} {
		t.Run(name, func(t *testing.T) {
			challenge, handle := beginRegistration(t, v, "alice")
			response := key.Registration(t, challenge, testOrigin, testRPID, present)
			var subject string
			switch name {
			case "purpose":
				subject, err = v.FinishVerification(t.Context(), handle, response)
			case "rp":
				subject, err = otherRP.FinishRegistration(t.Context(), handle, response)
				wantFailure(t, subject, err, ErrInvalid)
				// The other RP cannot consume this RP's ceremony. Discard it here.
				subject, err = v.FinishRegistration(t.Context(), handle, []byte("{}"))
			case "handle":
				before := ceremonies.takes
				for _, bad := range []string{"", "short", handle + "A", strings.Repeat("!", 43)} {
					subject, err = v.FinishRegistration(t.Context(), bad, response)
					wantFailure(t, subject, err, ErrInvalid)
				}
				if ceremonies.takes != before {
					t.Fatal("malformed handle reached the store")
				}
				subject, err = v.FinishRegistration(t.Context(), handle, []byte("{}"))
			case "response":
				subject, err = v.FinishRegistration(t.Context(), handle, []byte("{}"))
			case "origin":
				subject, err = v.FinishRegistration(t.Context(), handle, key.Registration(t, challenge, testOrigin+"/path", testRPID, present))
			case "challenge":
				subject, err = v.FinishRegistration(t.Context(), handle, key.Registration(t, "wrong", testOrigin, testRPID, present))
			case "rp hash":
				subject, err = v.FinishRegistration(t.Context(), handle, key.Registration(t, challenge, testOrigin, "other.example", present))
			case "presence":
				subject, err = v.FinishRegistration(t.Context(), handle, key.Registration(t, challenge, testOrigin, testRPID, 0))
			case "backup state":
				subject, err = v.FinishRegistration(t.Context(), handle, key.Registration(t, challenge, testOrigin, testRPID, present|byte(protocol.FlagBackupState)))
			case "id and rawId":
				k := key
				k.ResponseID, k.ResponseRawID = "Zm9v", []byte("foo")
				subject, err = v.FinishRegistration(t.Context(), handle, k.Registration(t, challenge, testOrigin, testRPID, present))
			}
			wantFailure(t, subject, err, ErrInvalid)
			subject, err = v.FinishRegistration(t.Context(), handle, response)
			wantFailure(t, subject, err, ErrInvalid)
		})
	}
	if len(store.keys) != 0 {
		t.Fatal("rejected registration stored a key")
	}
}

// edit rewrites the stored ceremony as Take returns it.
func edit(t *testing.T, change func(*ceremonyRecord)) func([]byte) []byte {
	return func(b []byte) []byte {
		var rec ceremonyRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Error(err)
		}
		change(&rec)
		out, err := json.Marshal(rec)
		if err != nil {
			t.Error(err)
		}
		return out
	}
}

func TestCeremonyRecord(t *testing.T) {
	v, _, ceremonies, key := setup(t)
	if err := register(t, v, key, "alice"); err != nil {
		t.Fatal(err)
	}
	offline := errors.New("ceremony store offline")
	for name, tc := range map[string]struct {
		mutate       func([]byte) []byte
		takeErr      error
		registration bool
		// blank signs the response for an empty challenge.
		blank bool
		want  error
	}{
		"json":            {mutate: func([]byte) []byte { return []byte("{") }, want: ErrRecord},
		"format":          {mutate: edit(t, func(r *ceremonyRecord) { r.Format = 2 }), want: ErrRecord},
		"take error":      {takeErr: offline, want: offline},
		"empty subject":   {mutate: edit(t, func(r *ceremonyRecord) { r.Subject, r.Session.UserID = "", nil }), registration: true, want: ErrInvalid},
		"long subject":    {mutate: edit(t, func(r *ceremonyRecord) { r.Subject = strings.Repeat("x", 65); r.Session.UserID = []byte(r.Subject) }), registration: true, want: ErrInvalid},
		"purpose":         {mutate: edit(t, func(r *ceremonyRecord) { r.Purpose = registration }), want: ErrInvalid},
		"user ID":         {mutate: edit(t, func(r *ceremonyRecord) { r.Session.UserID = []byte("bob") }), want: ErrInvalid},
		"no user ID":      {mutate: edit(t, func(r *ceremonyRecord) { r.Session.UserID = nil }), want: ErrInvalid},
		"no user ID reg":  {mutate: edit(t, func(r *ceremonyRecord) { r.Session.UserID = nil }), registration: true, want: ErrInvalid},
		"RP ID":           {mutate: edit(t, func(r *ceremonyRecord) { r.Session.RelyingPartyID = "other.example" }), want: ErrInvalid},
		"empty challenge": {mutate: edit(t, func(r *ceremonyRecord) { r.Session.Challenge = "" }), blank: true, want: ErrInvalid},
		"empty allow":     {mutate: edit(t, func(r *ceremonyRecord) { r.Session.AllowedCredentialIDs = nil }), want: ErrInvalid},
		"expired":         {mutate: edit(t, func(r *ceremonyRecord) { r.Session.Expires = time.Now().Add(-time.Second) }), want: ErrInvalid},
		"no expiry":       {mutate: edit(t, func(r *ceremonyRecord) { r.Session.Expires = time.Time{} }), want: ErrInvalid},
		"mediation":       {mutate: edit(t, func(r *ceremonyRecord) { r.Session.Mediation = protocol.MediationOptional }), want: ErrInvalid},
		"verification":    {mutate: edit(t, func(r *ceremonyRecord) { r.Session.UserVerification = protocol.VerificationDiscouraged }), want: ErrInvalid},
		"extensions":      {mutate: edit(t, func(r *ceremonyRecord) { r.Session.Extensions = protocol.AuthenticationExtensions{"x": true} }), want: ErrInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			ceremonies.mutate, ceremonies.takeErr = tc.mutate, tc.takeErr
			defer func() { ceremonies.mutate, ceremonies.takeErr = nil, nil }()
			var subject string
			var err error
			if tc.registration {
				challenge, handle := beginRegistration(t, v, "carol")
				if tc.blank {
					challenge = ""
				}
				subject, err = v.FinishRegistration(t.Context(), handle, webauthntest.New(t).Registration(t, challenge, testOrigin, testRPID, present))
			} else {
				challenge, handle := start(t, v, "alice")
				if tc.blank {
					challenge = ""
				}
				subject, err = v.FinishVerification(t.Context(), handle, key.Sign(t, validAssertion(challenge, "alice", 1)))
			}
			wantFailure(t, subject, err, tc.want)
			if tc.want != ErrInvalid && errors.Is(err, ErrInvalid) {
				t.Fatal("backend or record failure reported as ErrInvalid", err)
			}
		})
	}
}

func TestSessionEncoding(t *testing.T) {
	v, _, ceremonies, key := setup(t)
	if err := register(t, v, key, "alice"); err != nil {
		t.Fatal(err)
	}
	beginRegistration(t, v, "alice")
	reg := ceremonies.last(t)
	start(t, v, "alice")
	login := ceremonies.last(t)
	for _, rec := range []ceremonyRecord{reg, login} {
		first, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		var again ceremonyRecord
		if err := json.Unmarshal(first, &again); err != nil {
			t.Fatal(err)
		}
		second, err := json.Marshal(again)
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("session does not round-trip: %s\n%s", first, second)
		}
		s := rec.Session
		if s.Challenge == "" || s.RelyingPartyID != testRPID || string(s.UserID) != "alice" || s.Expires.IsZero() || s.UserVerification == "" {
			t.Fatalf("incomplete session: %+v", s)
		}
	}
	if reg.Purpose != registration || len(reg.Session.CredParams) == 0 {
		t.Fatalf("incomplete registration session: %+v", reg)
	}
	if login.Purpose != verification || len(login.Session.AllowedCredentialIDs) != 1 {
		t.Fatalf("incomplete verification session: %+v", login)
	}
}

func TestSharedStores(t *testing.T) {
	v, store, ceremonies, key := setup(t)
	other, err := New(testOrigin, "Test", store, ceremonies)
	if err != nil {
		t.Fatal(err)
	}
	challenge, handle := beginRegistration(t, v, "alice")
	if subject, err := other.FinishRegistration(t.Context(), handle, key.Registration(t, challenge, testOrigin, testRPID, present)); err != nil || subject != "alice" {
		t.Fatal(subject, err)
	}
	challenge, handle = start(t, other, "alice")
	if subject, err := v.FinishVerification(t.Context(), handle, key.Sign(t, validAssertion(challenge, "alice", 1))); err != nil || subject != "alice" {
		t.Fatal(subject, err)
	}
}

func TestRevoke(t *testing.T) {
	v, _, ceremonies, alice := setup(t)
	bob := webauthntest.New(t)
	for subject, k := range map[string]webauthntest.Key{"alice": alice, "bob": bob} {
		if err := register(t, v, k, subject); err != nil {
			t.Fatal(err)
		}
	}
	ac, ah := start(t, v, "alice")
	bc, bh := start(t, v, "bob")
	if err := ceremonies.Revoke(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	subject, err := v.FinishVerification(t.Context(), ah, alice.Sign(t, validAssertion(ac, "alice", 1)))
	wantFailure(t, subject, err, ErrInvalid)
	if subject, err := v.FinishVerification(t.Context(), bh, bob.Sign(t, validAssertion(bc, "bob", 1))); err != nil || subject != "bob" {
		t.Fatal(subject, err)
	}
}

func TestConcurrentCompletion(t *testing.T) {
	v, store, _, k := setup(t)
	if err := register(t, v, k, "alice"); err != nil {
		t.Fatal(err)
	}
	// Without the ceremony store, nothing else rejects the second completion.
	store.ignoreVersion = true
	challenge, handle := start(t, v, "alice")
	response := k.Sign(t, validAssertion(challenge, "alice", 0))
	ready := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-ready
			_, err := v.FinishVerification(context.Background(), handle, response)
			results <- err
		}()
	}
	close(ready)
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("want exactly one success: %v, %v", first, second)
	}
	if store.updates != 1 {
		t.Fatalf("got %d updates", store.updates)
	}
}

func TestCredentialWrites(t *testing.T) {
	v, store, _, k := setup(t)
	offline := errors.New("storage offline")
	store.fail = offline
	if err := register(t, v, k, "alice"); !errors.Is(err, offline) || errors.Is(err, ErrInvalid) {
		t.Fatal("insert failure", err)
	}
	store.fail = nil
	if err := register(t, v, k, "alice"); err != nil {
		t.Fatal(err)
	}
	t.Run("propagates the store's insert rejection", func(t *testing.T) {
		store.fail = ErrInvalid
		defer func() { store.fail = nil }()
		if err := register(t, v, webauthntest.New(t), "alice"); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	})
	t.Run("reloads credentials", func(t *testing.T) {
		challenge, handle := start(t, v, "alice")
		// Another login rotates the version after this ceremony began.
		r := store.get(k.ID)
		r.Version = rand.Text()
		store.set(k.ID, r)
		subject, err := v.FinishVerification(t.Context(), handle, k.Sign(t, validAssertion(challenge, "alice", 1)))
		if err != nil || subject != "alice" {
			t.Fatal(subject, err)
		}
	})
	for _, failure := range []string{"revocation", "update error", "update rejection"} {
		t.Run(failure, func(t *testing.T) {
			saved := store.keys[string(k.ID)]
			old := saved.record
			defer func() { store.keys[string(k.ID)] = saved; store.fail = nil }()
			challenge, handle := start(t, v, "alice")
			want := ErrInvalid
			switch failure {
			case "revocation":
				store.remove(k.ID)
			case "update error":
				store.fail = offline
				want = offline
			case "update rejection":
				store.fail = ErrInvalid
			}
			subject, err := v.FinishVerification(t.Context(), handle, k.Sign(t, validAssertion(challenge, "alice", old.Credential.Authenticator.SignCount+1)))
			wantFailure(t, subject, err, want)
		})
	}
}

// fixedStore returns fixed records or a load error.
type fixedStore struct {
	records []Record
	err     error
}

func (s fixedStore) Load(context.Context, string) ([]Record, error) { return s.records, s.err }
func (fixedStore) Insert(context.Context, string, Credential) error { return ErrInvalid }
func (fixedStore) Update(context.Context, string, string, Credential) error {
	return ErrInvalid
}

func TestLoad(t *testing.T) {
	valid := func(id string) Record {
		return Record{Credential: Credential{ID: []byte(id), PublicKey: []byte("key")}, Version: "1"}
	}
	for name, records := range map[string][]Record{
		"empty ID":       {{Credential: Credential{PublicKey: []byte("key")}, Version: "1"}},
		"empty version":  {{Credential: Credential{ID: []byte("a"), PublicKey: []byte("key")}}},
		"duplicate ID":   {valid("a"), valid("a")},
		"empty key":      {{Credential: Credential{ID: []byte("a")}, Version: "1"}},
		"one bad record": {valid("a"), {Credential: Credential{ID: []byte("b")}, Version: "1"}},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := New(testOrigin, "Test", fixedStore{records: records}, NewMemoryCeremonyStore())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := v.BeginVerification(t.Context(), "alice"); !errors.Is(err, ErrRecord) || errors.Is(err, ErrInvalid) {
				t.Fatal(err)
			}
			if _, _, err := v.BeginRegistration(t.Context(), "alice", "Alice"); !errors.Is(err, ErrRecord) {
				t.Fatal(err)
			}
		})
	}
	offline := errors.New("storage offline")
	v, err := New(testOrigin, "Test", fixedStore{err: offline}, NewMemoryCeremonyStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.BeginVerification(t.Context(), "alice"); !errors.Is(err, offline) || errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestBeginStoreFailure(t *testing.T) {
	v, _, ceremonies, k := setup(t)
	if err := register(t, v, k, "alice"); err != nil {
		t.Fatal(err)
	}
	offline := errors.New("ceremony store offline")
	ceremonies.createErr = offline
	options, handle, err := v.BeginRegistration(t.Context(), "alice", "Alice")
	if !errors.Is(err, offline) || options != nil || handle != "" {
		t.Fatal("registration", err)
	}
	options, handle, err = v.BeginVerification(t.Context(), "alice")
	if !errors.Is(err, offline) || options != nil || handle != "" {
		t.Fatal("verification", err)
	}
}

func TestConfigurationAndSubject(t *testing.T) {
	v, s, c, _ := setup(t)
	for _, origin := range []string{"", "http://auth.example", "https://", "https://user@auth.example", "https://auth.example/path", "https://auth.example?x=1", "https://auth.example#here"} {
		if _, err := New(origin, "Test", s, c); err == nil {
			t.Errorf("accepted origin %q", origin)
		}
	}
	if _, err := New(testOrigin, "Test", nil, c); err == nil {
		t.Error("accepted nil credential store")
	}
	if _, err := New(testOrigin, "Test", s, nil); err == nil {
		t.Error("accepted nil ceremony store")
	}
	if _, err := New(testOrigin, "", s, c); err == nil {
		t.Error("accepted empty display name")
	}
	canonical, err := New("https://AUTH.EXAMPLE:443", "Test", s, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := register(t, canonical, webauthntest.New(t), "alice"); err != nil {
		t.Fatal("canonical origin", err)
	}
	const portOrigin = "https://auth.example:8443"
	port, err := New(portOrigin, "Test", s, c)
	if err != nil {
		t.Fatal(err)
	}
	challenge, handle := beginRegistration(t, port, "bob")
	if subject, err := port.FinishRegistration(t.Context(), handle, webauthntest.New(t).Registration(t, challenge, portOrigin, testRPID, present)); err != nil || subject != "bob" {
		t.Fatal("nondefault port", subject, err)
	}
	for _, subject := range []string{"", strings.Repeat("x", 65)} {
		if _, _, err := v.BeginRegistration(t.Context(), subject, "User"); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted invalid subject")
		}
		if _, _, err := v.BeginVerification(t.Context(), subject); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted invalid subject")
		}
	}
	if _, _, err := v.BeginRegistration(t.Context(), "alice", ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted empty name")
	}
}
