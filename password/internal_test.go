package password

import (
	"context"
	"errors"
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
