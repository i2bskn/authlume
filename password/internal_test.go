package password

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
)

const (
	internalPBKDF2Record = "v1$pbkdf2-sha256$600000$AAECAwQFBgcICQoLDA0ODw$cjiPZp04h137x69SRDimhkI8gbfokyNy6XLl31C8qZw"
	internalArgon2Record = "v2$argon2id$m=19456,t=2,p=1$AAECAwQFBgcICQoLDA0ODw$LMxd0n0M/ff3/2OKNaK+14CbBpNJS2AlApE4UpwZ4ko"
)

func TestConfigurationErrors(t *testing.T) {
	lookup := func(context.Context, string) (Credential, error) { return Credential{}, ErrNotFound }
	for _, tc := range []struct {
		name string
		opts []Option
		want error
	}{
		{"zero algorithm", []Option{WithAlgorithm(0)}, errAlgorithm},
		{"unknown algorithm", []Option{WithAlgorithm(99)}, errAlgorithm},
		{"nil option", []Option{nil}, errOption},
		{"nil option after valid", []Option{WithAlgorithm(PBKDF2SHA256), nil}, errOption},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if auth, err := New(lookup, nil, tc.opts...); auth != nil || !errors.Is(err, tc.want) {
				t.Fatalf("auth %v, err %v", auth, err)
			}
		})
	}
	if auth, err := New(nil, nil); auth != nil || !errors.Is(err, errConfiguration) {
		t.Fatalf("missing lookup: auth %v, err %v", auth, err)
	}
	if record, err := (*Authenticator)(nil).Hash("a"); record != "" || !errors.Is(err, errConfiguration) {
		t.Fatalf("nil receiver: record %q, err %v", record, err)
	}
	if record, err := (&Authenticator{}).Hash("a"); record != "" || !errors.Is(err, errAlgorithm) {
		t.Fatalf("zero value Hash: record %q, err %v", record, err)
	}
	if _, err := (&Authenticator{}).Authenticate(t.Context(), "id", "a"); !errors.Is(err, errConfiguration) {
		t.Fatalf("zero value Authenticate: err %v", err)
	}
}

// TestDummyDerivation replaces the package variable deriveKey, which every
// Authenticate call in this test binary reads. Neither this test nor any other
// test in the package may use t.Parallel while this replacement is possible.
func TestDummyDerivation(t *testing.T) {
	original := deriveKey
	t.Cleanup(func() { deriveKey = original })
	var calls []Algorithm
	deriveKey = func(alg Algorithm, _ string, _ []byte) ([]byte, error) {
		calls = append(calls, alg)
		return make([]byte, keySize), nil
	}

	for _, cfg := range []struct {
		name    string
		opts    []Option
		want    Algorithm
		native  string
		foreign string
	}{
		{"default", nil, Argon2id, internalArgon2Record, internalPBKDF2Record},
		{"pbkdf2", []Option{WithAlgorithm(PBKDF2SHA256)}, PBKDF2SHA256, internalPBKDF2Record, internalArgon2Record},
	} {
		for _, tc := range []struct {
			name      string
			cred      Credential
			lookupErr error
			want      error
		}{
			{"unknown identifier", Credential{}, ErrNotFound, ErrCredentials},
			{"format mismatch", Credential{Subject: "demo-subject", Hash: cfg.foreign}, nil, ErrRecord},
			{"malformed record", Credential{Subject: "demo-subject", Hash: "malformed"}, nil, ErrRecord},
			{"empty subject", Credential{Hash: cfg.native}, nil, ErrRecord},
		} {
			t.Run(cfg.name+"/"+tc.name, func(t *testing.T) {
				calls = nil
				auth, err := New(func(context.Context, string) (Credential, error) {
					return tc.cred, tc.lookupErr
				}, func(context.Context, string) (Decision, error) {
					t.Fatal("policy ran after failed verification")
					return 0, nil
				}, cfg.opts...)
				if err != nil {
					t.Fatal(err)
				}
				result, err := auth.Authenticate(t.Context(), "id", "secret")
				if result != (Result{}) || !errors.Is(err, tc.want) {
					t.Fatalf("result %v, err %v", result, err)
				}
				if len(calls) != 1 || calls[0] != cfg.want {
					t.Fatalf("derivations %v, want exactly one with %v", calls, cfg.want)
				}
			})
		}
	}
}

func TestMigrationConfiguration(t *testing.T) {
	lookup := func(context.Context, string) (Credential, error) { return Credential{}, ErrNotFound }
	for _, tc := range []struct {
		name string
		opts []Option
		want error
	}{
		{"zero algorithm", []Option{WithMigrationFrom(0)}, errAlgorithm},
		{"unknown algorithm", []Option{WithMigrationFrom(99)}, errAlgorithm},
		{"repeated invalid algorithm", []Option{WithMigrationFrom(0, 0)}, errAlgorithm},
		{"invalid after valid", []Option{WithMigrationFrom(PBKDF2SHA256, 99)}, errAlgorithm},
		{"invalid with primary", []Option{WithMigrationFrom(Argon2id, 99)}, errAlgorithm},
		{"invalid primary", []Option{WithAlgorithm(0), WithMigrationFrom(PBKDF2SHA256)}, errAlgorithm},
		{"default primary", []Option{WithMigrationFrom(Argon2id)}, errOption},
		{"primary given first", []Option{WithAlgorithm(PBKDF2SHA256), WithMigrationFrom(PBKDF2SHA256)}, errOption},
		{"primary given last", []Option{WithMigrationFrom(PBKDF2SHA256), WithAlgorithm(PBKDF2SHA256)}, errOption},
		{"duplicate", []Option{WithMigrationFrom(PBKDF2SHA256, PBKDF2SHA256)}, errOption},
		{"valid then invalid", []Option{WithMigrationFrom(PBKDF2SHA256), WithMigrationFrom(99)}, errAlgorithm},
		{"no algorithms", []Option{WithMigrationFrom()}, nil},
		{"invalid then valid", []Option{WithMigrationFrom(99), WithMigrationFrom(PBKDF2SHA256)}, nil},
		{"either order", []Option{WithMigrationFrom(Argon2id), WithAlgorithm(PBKDF2SHA256)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := New(lookup, nil, tc.opts...)
			if tc.want == nil {
				if auth == nil || err != nil {
					t.Fatalf("auth %v, err %v", auth, err)
				}
				return
			}
			if auth != nil || !errors.Is(err, tc.want) {
				t.Fatalf("auth %v, err %v, want %v", auth, err, tc.want)
			}
		})
	}
}

// replaceDeriveKey replaces the package variable deriveKey until the test ends.
// Tests that call it must not use t.Parallel; see TestDummyDerivation.
func replaceDeriveKey(t *testing.T, replacement func(Algorithm, string, []byte) ([]byte, error)) {
	t.Helper()
	original := deriveKey
	t.Cleanup(func() { deriveKey = original })
	deriveKey = replacement
}

// acceptFixtures replaces deriveKey so that any password verifies against the
// two fixture records without running a KDF.
func acceptFixtures(t *testing.T) {
	t.Helper()
	keys := map[Algorithm][]byte{}
	var fixtureSalt []byte
	for alg, record := range map[Algorithm]string{Argon2id: internalArgon2Record, PBKDF2SHA256: internalPBKDF2Record} {
		salt, key, err := parseRecord(alg, record)
		if err != nil {
			t.Fatal(err)
		}
		fixtureSalt, keys[alg] = salt, key
	}
	replaceDeriveKey(t, func(alg Algorithm, _ string, salt []byte) ([]byte, error) {
		if bytes.Equal(salt, fixtureSalt) {
			return keys[alg], nil
		}
		return make([]byte, keySize), nil
	})
}

func fixtureLookup(record string) Lookup {
	return func(context.Context, string) (Credential, error) {
		return Credential{Subject: "demo-subject", Hash: record}, nil
	}
}

// TestMigrationDerivations checks that every path performs one derivation per
// accepted algorithm, in order, and that only the derivation for the record's
// own algorithm receives the record's salt. No KDF runs.
func TestMigrationDerivations(t *testing.T) {
	type call struct {
		alg  Algorithm
		salt []byte
	}
	zeroSalt := make([]byte, saltSize)
	argon2First := []Option{WithMigrationFrom(PBKDF2SHA256)}
	pbkdf2First := []Option{WithAlgorithm(PBKDF2SHA256), WithMigrationFrom(Argon2id)}
	for _, tc := range []struct {
		name      string
		opts      []Option
		sequence  []Algorithm
		cred      Credential
		lookupErr error
		// own is the algorithm of a record that reaches verification, or 0.
		own     Algorithm
		correct bool
		want    error
		rehash  bool
	}{
		{name: "unknown identifier", opts: argon2First, sequence: []Algorithm{Argon2id, PBKDF2SHA256},
			lookupErr: ErrNotFound, want: ErrCredentials},
		{name: "malformed record", opts: argon2First, sequence: []Algorithm{Argon2id, PBKDF2SHA256},
			cred: Credential{Subject: "demo-subject", Hash: "malformed"}, want: ErrRecord},
		{name: "pbkdf2 record with empty subject", opts: argon2First, sequence: []Algorithm{Argon2id, PBKDF2SHA256},
			cred: Credential{Hash: internalPBKDF2Record}, correct: true, want: ErrRecord},
		{name: "argon2id record with empty subject", opts: argon2First, sequence: []Algorithm{Argon2id, PBKDF2SHA256},
			cred: Credential{Hash: internalArgon2Record}, correct: true, want: ErrRecord},
		{name: "argon2id record with wrong password", opts: argon2First, sequence: []Algorithm{Argon2id, PBKDF2SHA256},
			cred: Credential{Subject: "demo-subject", Hash: internalArgon2Record}, own: Argon2id, want: ErrCredentials},
		{name: "pbkdf2 record with wrong password", opts: argon2First, sequence: []Algorithm{Argon2id, PBKDF2SHA256},
			cred: Credential{Subject: "demo-subject", Hash: internalPBKDF2Record}, own: PBKDF2SHA256, want: ErrCredentials},
		{name: "argon2id record with correct password", opts: argon2First, sequence: []Algorithm{Argon2id, PBKDF2SHA256},
			cred: Credential{Subject: "demo-subject", Hash: internalArgon2Record}, own: Argon2id, correct: true},
		{name: "pbkdf2 record with correct password", opts: argon2First, sequence: []Algorithm{Argon2id, PBKDF2SHA256},
			cred: Credential{Subject: "demo-subject", Hash: internalPBKDF2Record}, own: PBKDF2SHA256, correct: true, rehash: true},
		{name: "pbkdf2 primary with unknown identifier", opts: pbkdf2First, sequence: []Algorithm{PBKDF2SHA256, Argon2id},
			lookupErr: ErrNotFound, want: ErrCredentials},
		{name: "pbkdf2 primary with argon2id record", opts: pbkdf2First, sequence: []Algorithm{PBKDF2SHA256, Argon2id},
			cred: Credential{Subject: "demo-subject", Hash: internalArgon2Record}, own: Argon2id, correct: true, rehash: true},
		{name: "pbkdf2 primary with pbkdf2 record", opts: pbkdf2First, sequence: []Algorithm{PBKDF2SHA256, Argon2id},
			cred: Credential{Subject: "demo-subject", Hash: internalPBKDF2Record}, own: PBKDF2SHA256, correct: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var recordSalt, recordKey []byte
			for _, alg := range tc.sequence {
				if salt, key, err := parseRecord(alg, tc.cred.Hash); err == nil {
					recordSalt, recordKey = salt, key
				}
			}
			var calls []call
			replaceDeriveKey(t, func(alg Algorithm, _ string, salt []byte) ([]byte, error) {
				calls = append(calls, call{alg, bytes.Clone(salt)})
				if tc.correct && bytes.Equal(salt, recordSalt) {
					return recordKey, nil
				}
				return make([]byte, keySize), nil
			})
			policyCalls := 0
			auth, err := New(func(context.Context, string) (Credential, error) {
				return tc.cred, tc.lookupErr
			}, func(context.Context, string) (Decision, error) {
				policyCalls++
				return PasswordOnly, nil
			}, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			result, err := auth.Authenticate(t.Context(), "id", "any password")
			want := Result{}
			if tc.want == nil {
				want = Result{Subject: "demo-subject", Decision: PasswordOnly, Rehash: tc.rehash}
			}
			if result != want || !errors.Is(err, tc.want) {
				t.Fatalf("result %+v, err %v, want %+v, %v", result, err, want, tc.want)
			}
			if (policyCalls == 1) != (tc.want == nil) || policyCalls > 1 {
				t.Fatalf("policy ran %d times", policyCalls)
			}
			var sequence []Algorithm
			for _, c := range calls {
				sequence = append(sequence, c.alg)
				wantSalt := zeroSalt
				if c.alg == tc.own {
					wantSalt = recordSalt
				}
				if !bytes.Equal(c.salt, wantSalt) {
					t.Fatalf("derivation with %v received salt %x, want %x", c.alg, c.salt, wantSalt)
				}
			}
			if !slices.Equal(sequence, tc.sequence) {
				t.Fatalf("derivations %v, want %v", sequence, tc.sequence)
			}
		})
	}
}

func TestMigrationLookupFailureSkipsDerivation(t *testing.T) {
	calls := 0
	replaceDeriveKey(t, func(Algorithm, string, []byte) ([]byte, error) {
		calls++
		return make([]byte, keySize), nil
	})
	storeErr := errors.New("store unavailable")
	auth, err := New(func(context.Context, string) (Credential, error) {
		return Credential{}, storeErr
	}, nil, WithMigrationFrom(PBKDF2SHA256))
	if err != nil {
		t.Fatal(err)
	}
	result, err := auth.Authenticate(t.Context(), "id", "secret")
	if result != (Result{}) || !errors.Is(err, storeErr) || calls != 0 {
		t.Fatalf("result %+v, err %v, derivations %d", result, err, calls)
	}
}

func TestMigrationDerivationError(t *testing.T) {
	failed := errors.New("derivation failed")
	for _, failing := range []Algorithm{Argon2id, PBKDF2SHA256} {
		for _, tc := range []struct {
			name      string
			cred      Credential
			lookupErr error
		}{
			{"unknown identifier", Credential{}, ErrNotFound},
			{"malformed record", Credential{Subject: "demo-subject", Hash: "malformed"}, nil},
			{"pbkdf2 record", Credential{Subject: "demo-subject", Hash: internalPBKDF2Record}, nil},
		} {
			replaceDeriveKey(t, func(alg Algorithm, _ string, _ []byte) ([]byte, error) {
				if alg == failing {
					return nil, failed
				}
				return make([]byte, keySize), nil
			})
			auth, err := New(func(context.Context, string) (Credential, error) {
				return tc.cred, tc.lookupErr
			}, nil, WithMigrationFrom(PBKDF2SHA256))
			if err != nil {
				t.Fatal(err)
			}
			result, err := auth.Authenticate(t.Context(), "id", "secret")
			if result != (Result{}) || !errors.Is(err, failed) {
				t.Fatalf("%s, %v failing: result %+v, err %v", tc.name, failing, result, err)
			}
		}
	}
}

// TestDummyResultNeverAuthenticates hands the key stored in the record to the
// dummy derivations and a different key to the real one.
func TestDummyResultNeverAuthenticates(t *testing.T) {
	zeroSalt := make([]byte, saltSize)
	for _, tc := range []struct {
		name   string
		alg    Algorithm
		record string
	}{
		{"argon2id record", Argon2id, internalArgon2Record},
		{"pbkdf2 record", PBKDF2SHA256, internalPBKDF2Record},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stored, err := parseRecord(tc.alg, tc.record)
			if err != nil {
				t.Fatal(err)
			}
			dummyCalls := 0
			replaceDeriveKey(t, func(_ Algorithm, _ string, salt []byte) ([]byte, error) {
				if bytes.Equal(salt, zeroSalt) {
					dummyCalls++
					return stored, nil
				}
				return make([]byte, keySize), nil
			})
			auth, err := New(fixtureLookup(tc.record), func(context.Context, string) (Decision, error) {
				t.Fatal("policy ran after failed verification")
				return 0, nil
			}, WithMigrationFrom(PBKDF2SHA256))
			if err != nil {
				t.Fatal(err)
			}
			result, err := auth.Authenticate(t.Context(), "id", "secret")
			if result != (Result{}) || !errors.Is(err, ErrCredentials) || dummyCalls != 1 {
				t.Fatalf("result %+v, err %v, dummy derivations %d", result, err, dummyCalls)
			}
		})
	}
}

func TestMigrationPolicyFailure(t *testing.T) {
	acceptFixtures(t)
	failed := errors.New("policy unavailable")
	for _, tc := range []struct {
		decision Decision
		err      error
	}{{0, nil}, {99, nil}, {PasswordOnly, failed}} {
		auth, err := New(fixtureLookup(internalPBKDF2Record), func(context.Context, string) (Decision, error) {
			return tc.decision, tc.err
		}, WithMigrationFrom(PBKDF2SHA256))
		if err != nil {
			t.Fatal(err)
		}
		result, err := auth.Authenticate(t.Context(), "id", "secret")
		if result != (Result{}) || err == nil || (tc.err != nil && !errors.Is(err, tc.err)) {
			t.Fatalf("decision %v: result %+v, err %v", tc.decision, result, err)
		}
	}
}

func TestMigrationOptionSemantics(t *testing.T) {
	acceptFixtures(t)
	migrated := Result{Subject: "demo-subject", Decision: PasswordOnly, Rehash: true}
	authenticate := func(t *testing.T, auth *Authenticator) (Result, error) {
		t.Helper()
		return auth.Authenticate(t.Context(), "id", "secret")
	}

	t.Run("caller slice", func(t *testing.T) {
		algs := []Algorithm{PBKDF2SHA256}
		opt := WithMigrationFrom(algs...)
		algs[0] = Argon2id // would equal the primary algorithm
		auth, err := New(fixtureLookup(internalPBKDF2Record), nil, opt)
		if err != nil {
			t.Fatal(err)
		}
		algs[0] = 99
		if result, err := authenticate(t, auth); result != migrated || err != nil {
			t.Fatalf("result %+v, err %v", result, err)
		}
		if !auth.NeedsRehash(internalPBKDF2Record) {
			t.Fatal("NeedsRehash changed with the caller's slice")
		}
	})

	t.Run("empty call clears", func(t *testing.T) {
		auth, err := New(fixtureLookup(internalPBKDF2Record), nil, WithMigrationFrom(PBKDF2SHA256), WithMigrationFrom())
		if err != nil {
			t.Fatal(err)
		}
		if result, err := authenticate(t, auth); result != (Result{}) || !errors.Is(err, ErrRecord) {
			t.Fatalf("result %+v, err %v", result, err)
		}
		if auth.NeedsRehash(internalPBKDF2Record) {
			t.Fatal("NeedsRehash is true without a migration algorithm")
		}
	})

	t.Run("last call wins", func(t *testing.T) {
		auth, err := New(fixtureLookup(internalPBKDF2Record), nil, WithMigrationFrom(99), WithMigrationFrom(PBKDF2SHA256))
		if err != nil {
			t.Fatal(err)
		}
		if result, err := authenticate(t, auth); result != migrated || err != nil {
			t.Fatalf("result %+v, err %v", result, err)
		}
	})

	t.Run("reused option", func(t *testing.T) {
		opt := WithMigrationFrom(PBKDF2SHA256)
		for range 2 {
			auth, err := New(fixtureLookup(internalPBKDF2Record), nil, opt)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := authenticate(t, auth); result != migrated || err != nil {
				t.Fatalf("result %+v, err %v", result, err)
			}
		}
	})
}
