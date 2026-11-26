package password_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/i2bskn/authlume/password"
)

// Independent fixtures for fixturePassword, salt bytes 0..15.
const (
	fixturePassword = "example credential"
	// PBKDF2-HMAC-SHA256, 600,000 iterations.
	fixtureRecord = "v1$pbkdf2-sha256$600000$AAECAwQFBgcICQoLDA0ODw$cjiPZp04h137x69SRDimhkI8gbfokyNy6XLl31C8qZw"
	// Argon2id, m=19456 KiB, t=2, p=1, version 0x13.
	argon2Record = "v2$argon2id$m=19456,t=2,p=1$AAECAwQFBgcICQoLDA0ODw$LMxd0n0M/ff3/2OKNaK+14CbBpNJS2AlApE4UpwZ4ko"
)

func authenticator(t *testing.T, lookup password.Lookup, policy password.Policy, opts ...password.Option) *password.Authenticator {
	t.Helper()
	auth, err := password.New(lookup, policy, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func credential(record string) password.Lookup {
	return func(context.Context, string) (password.Credential, error) {
		return password.Credential{Subject: "demo-subject", Hash: record}, nil
	}
}

func TestAuthenticatePolicy(t *testing.T) {
	ctx := t.Context()
	for _, tc := range []struct {
		name     string
		record   string
		decision password.Decision
		opts     []password.Option
	}{
		{"argon2id password only", argon2Record, password.PasswordOnly, nil},
		{"argon2id require mfa", argon2Record, password.RequireMFA, nil},
		{"pbkdf2", fixtureRecord, password.PasswordOnly, []password.Option{password.WithAlgorithm(password.PBKDF2SHA256)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := authenticator(t, func(got context.Context, identifier string) (password.Credential, error) {
				if got != ctx || identifier != "Mixed.Case" {
					t.Fatal("lookup received different context or identifier")
				}
				return password.Credential{Subject: "demo-subject", Hash: tc.record}, nil
			}, func(got context.Context, subject string) (password.Decision, error) {
				if got != ctx || subject != "demo-subject" {
					t.Fatal("policy received different context or subject")
				}
				return tc.decision, nil
			}, tc.opts...)
			result, err := auth.Authenticate(ctx, "Mixed.Case", fixturePassword)
			if err != nil || result.Subject != "demo-subject" || result.Decision != tc.decision {
				t.Fatalf("decision %v: result %v, err %v", tc.decision, result, err)
			}
		})
	}
}

func TestHashRoundTrip(t *testing.T) {
	for _, secret := range []string{"a", strings.Repeat("\x00\xff", 512)} {
		record, err := password.Hash(secret)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(record, "v2$argon2id$m=19456,t=2,p=1$") {
			t.Fatalf("Hash used a different format: %q", record)
		}
		second, err := password.Hash(secret)
		if err != nil || record == second {
			t.Fatal("expected a freshly salted second record", err)
		}
		auth := authenticator(t, credential(record), nil)
		result, err := auth.Authenticate(t.Context(), "id", secret)
		if err != nil || result.Subject != "demo-subject" || result.Decision != password.PasswordOnly {
			t.Fatalf("default policy: result %v, err %v", result, err)
		}
	}
}

func TestAuthenticatorHashRoundTrip(t *testing.T) {
	var record string
	auth := authenticator(t, func(context.Context, string) (password.Credential, error) {
		return password.Credential{Subject: "demo-subject", Hash: record}, nil
	}, nil, password.WithAlgorithm(password.PBKDF2SHA256))
	record, err := auth.Hash("a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(record, "v1$pbkdf2-sha256$600000$") {
		t.Fatalf("Hash used a different format: %q", record)
	}
	result, err := auth.Authenticate(t.Context(), "id", "a")
	if err != nil || result.Subject != "demo-subject" || result.Decision != password.PasswordOnly {
		t.Fatalf("result %v, err %v", result, err)
	}
}

func TestConfiguration(t *testing.T) {
	lookup := credential(argon2Record)
	for _, tc := range []struct {
		name string
		opts []password.Option
	}{
		{"zero algorithm", []password.Option{password.WithAlgorithm(0)}},
		{"unknown algorithm", []password.Option{password.WithAlgorithm(99)}},
		{"nil option", []password.Option{nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if auth, err := password.New(lookup, nil, tc.opts...); auth != nil || err == nil {
				t.Fatalf("auth %v, err %v", auth, err)
			}
		})
	}
	t.Run("last option wins", func(t *testing.T) {
		auth := authenticator(t, lookup, nil,
			password.WithAlgorithm(password.PBKDF2SHA256), password.WithAlgorithm(password.Argon2id))
		record, err := auth.Hash("a")
		if err != nil || !strings.HasPrefix(record, "v2$argon2id$m=19456,t=2,p=1$") {
			t.Fatalf("record %q, err %v", record, err)
		}
	})
	t.Run("nil receiver hash", func(t *testing.T) {
		var auth *password.Authenticator
		if record, err := auth.Hash("a"); record != "" || err == nil {
			t.Fatalf("record %q, err %v", record, err)
		}
	})
	t.Run("zero value", func(t *testing.T) {
		auth := &password.Authenticator{}
		if record, err := auth.Hash("a"); record != "" || err == nil {
			t.Fatalf("Hash: record %q, err %v", record, err)
		}
		if result, err := auth.Authenticate(t.Context(), "id", "a"); result != (password.Result{}) || err == nil {
			t.Fatalf("Authenticate: result %v, err %v", result, err)
		}
	})
}

func TestPasswordLength(t *testing.T) {
	auth := authenticator(t, func(context.Context, string) (password.Credential, error) {
		t.Fatal("lookup received invalid input")
		return password.Credential{}, nil
	}, nil)
	for _, secret := range []string{"", strings.Repeat("a", 1025)} {
		if record, err := password.Hash(secret); err == nil || record != "" {
			t.Fatalf("Hash accepted a %d byte password", len(secret))
		}
		if record, err := auth.Hash(secret); err == nil || record != "" {
			t.Fatalf("Authenticator.Hash accepted a %d byte password", len(secret))
		}
		result, err := auth.Authenticate(t.Context(), "id", secret)
		if result != (password.Result{}) || !errors.Is(err, password.ErrCredentials) {
			t.Fatalf("Authenticate: result %v, err %v", result, err)
		}
	}
}

func TestLookupAndVerificationFailures(t *testing.T) {
	storeErr := errors.New("store unavailable")
	for _, tc := range []struct {
		name      string
		cred      password.Credential
		lookupErr error
		want      error
	}{
		{"unknown", password.Credential{}, fmt.Errorf("lookup: %w", password.ErrNotFound), password.ErrCredentials},
		{"wrong password", password.Credential{Subject: "demo-subject", Hash: argon2Record}, nil, password.ErrCredentials},
		{"store failure", password.Credential{}, storeErr, storeErr},
		{"empty subject", password.Credential{Hash: argon2Record}, nil, password.ErrRecord},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := authenticator(t, func(context.Context, string) (password.Credential, error) {
				return tc.cred, tc.lookupErr
			}, func(context.Context, string) (password.Decision, error) {
				t.Fatal("policy ran after failed verification")
				return 0, nil
			})
			result, err := auth.Authenticate(t.Context(), "id", "different password")
			if result != (password.Result{}) || !errors.Is(err, tc.want) {
				t.Fatalf("result %v, err %v", result, err)
			}
		})
	}
}

func TestInvalidRecord(t *testing.T) {
	pbkdf2 := []password.Option{password.WithAlgorithm(password.PBKDF2SHA256)}
	for _, tc := range []struct {
		name   string
		record string
		opts   []password.Option
	}{
		{"pbkdf2 empty", "", pbkdf2},
		{"pbkdf2 version", strings.Replace(fixtureRecord, "v1", "v2", 1), pbkdf2},
		{"pbkdf2 iterations", strings.Replace(fixtureRecord, "600000", "600001", 1), pbkdf2},
		{"pbkdf2 hash", strings.Replace(fixtureRecord, "pbkdf2-sha256", "pbkdf2-sha512", 1), pbkdf2},
		{"pbkdf2 noncanonical salt", strings.Replace(fixtureRecord, "ODw$", "ODx$", 1), pbkdf2},
		{"pbkdf2 noncanonical key", fixtureRecord[:len(fixtureRecord)-1] + "x", pbkdf2},
		{"pbkdf2 trailing padding", fixtureRecord + "=", pbkdf2},
		{"pbkdf2 truncated", fixtureRecord[:len(fixtureRecord)-1], pbkdf2},
		{"argon2id empty", "", nil},
		{"argon2id memory", strings.Replace(argon2Record, "m=19456", "m=19457", 1), nil},
		{"argon2id time", strings.Replace(argon2Record, "t=2", "t=3", 1), nil},
		{"argon2id threads", strings.Replace(argon2Record, "p=1", "p=2", 1), nil},
		{"argon2id variant", strings.Replace(argon2Record, "argon2id", "argon2i", 1), nil},
		{"argon2id noncanonical salt", strings.Replace(argon2Record, "ODw$", "ODx$", 1), nil},
		{"argon2id noncanonical key", argon2Record[:len(argon2Record)-1] + "p", nil},
		{"argon2id trailing padding", argon2Record + "=", nil},
		{"argon2id truncated", argon2Record[:len(argon2Record)-1], nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := authenticator(t, credential(tc.record), nil, tc.opts...)
			result, err := auth.Authenticate(t.Context(), "id", fixturePassword)
			if result != (password.Result{}) || !errors.Is(err, password.ErrRecord) {
				t.Fatalf("malformed record: result %v, err %v", result, err)
			}
		})
	}
}

func TestRecordFormatMismatch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record string
		opts   []password.Option
	}{
		{"pbkdf2 record with argon2id", fixtureRecord, nil},
		{"argon2id record with pbkdf2", argon2Record, []password.Option{password.WithAlgorithm(password.PBKDF2SHA256)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := authenticator(t, credential(tc.record), func(context.Context, string) (password.Decision, error) {
				t.Fatal("policy ran for a mismatched record")
				return 0, nil
			}, tc.opts...)
			result, err := auth.Authenticate(t.Context(), "id", fixturePassword)
			if result != (password.Result{}) || !errors.Is(err, password.ErrRecord) {
				t.Fatalf("result %v, err %v", result, err)
			}
		})
	}
}

func TestPolicyFailure(t *testing.T) {
	failed := errors.New("policy unavailable")
	for _, tc := range []struct {
		decision password.Decision
		err      error
	}{{0, nil}, {99, nil}, {password.PasswordOnly, failed}} {
		auth := authenticator(t, credential(argon2Record), func(context.Context, string) (password.Decision, error) {
			return tc.decision, tc.err
		})
		result, err := auth.Authenticate(t.Context(), "id", fixturePassword)
		if result != (password.Result{}) || err == nil || (tc.err != nil && !errors.Is(err, tc.err)) {
			t.Fatalf("policy failure: result %v, err %v", result, err)
		}
	}
}

func TestMissingLookup(t *testing.T) {
	if auth, err := password.New(nil, nil); auth != nil || err == nil {
		t.Fatal("expected configuration error")
	}
}

func TestMigrationAcceptance(t *testing.T) {
	fromPBKDF2 := []password.Option{password.WithMigrationFrom(password.PBKDF2SHA256)}
	fromArgon2id := []password.Option{
		password.WithAlgorithm(password.PBKDF2SHA256), password.WithMigrationFrom(password.Argon2id),
	}
	for _, tc := range []struct {
		name     string
		opts     []password.Option
		record   string
		secret   string
		decision password.Decision
		want     error
		rehash   bool
	}{
		{"argon2id primary, argon2id record", fromPBKDF2, argon2Record, fixturePassword, password.PasswordOnly, nil, false},
		{"argon2id primary, argon2id record, wrong password", fromPBKDF2, argon2Record, "different password", 0, password.ErrCredentials, false},
		{"argon2id primary, pbkdf2 record", fromPBKDF2, fixtureRecord, fixturePassword, password.PasswordOnly, nil, true},
		{"argon2id primary, pbkdf2 record, require mfa", fromPBKDF2, fixtureRecord, fixturePassword, password.RequireMFA, nil, true},
		{"argon2id primary, pbkdf2 record, wrong password", fromPBKDF2, fixtureRecord, "different password", 0, password.ErrCredentials, false},
		{"pbkdf2 primary, argon2id record", fromArgon2id, argon2Record, fixturePassword, password.PasswordOnly, nil, true},
		{"pbkdf2 primary, argon2id record, wrong password", fromArgon2id, argon2Record, "different password", 0, password.ErrCredentials, false},
		{"pbkdf2 primary, pbkdf2 record", fromArgon2id, fixtureRecord, fixturePassword, password.PasswordOnly, nil, false},
		{"pbkdf2 primary, pbkdf2 record, wrong password", fromArgon2id, fixtureRecord, "different password", 0, password.ErrCredentials, false},
		{"broken record", fromPBKDF2, "malformed", fixturePassword, 0, password.ErrRecord, false},
		{"broken record, wrong password", fromPBKDF2, "malformed", "different password", 0, password.ErrRecord, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := authenticator(t, credential(tc.record), func(context.Context, string) (password.Decision, error) {
				if tc.want != nil {
					t.Fatal("policy ran after failed verification")
				}
				return tc.decision, nil
			}, tc.opts...)
			result, err := auth.Authenticate(t.Context(), "id", tc.secret)
			want := password.Result{}
			if tc.want == nil {
				want = password.Result{Subject: "demo-subject", Decision: tc.decision, Rehash: tc.rehash}
			}
			if result != want || !errors.Is(err, tc.want) {
				t.Fatalf("result %+v, err %v, want %+v, %v", result, err, want, tc.want)
			}
		})
	}
}

func TestMigrationRoundTrip(t *testing.T) {
	record := fixtureRecord
	auth := authenticator(t, func(context.Context, string) (password.Credential, error) {
		return password.Credential{Subject: "demo-subject", Hash: record}, nil
	}, nil, password.WithMigrationFrom(password.PBKDF2SHA256))
	result, err := auth.Authenticate(t.Context(), "id", fixturePassword)
	if err != nil || !result.Rehash || !auth.NeedsRehash(record) {
		t.Fatalf("old record: result %+v, err %v, NeedsRehash %v", result, err, auth.NeedsRehash(record))
	}
	replacement, err := auth.Hash(fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(replacement, "v2$argon2id$m=19456,t=2,p=1$") {
		t.Fatalf("Hash used a different format: %q", replacement)
	}
	record = replacement
	result, err = auth.Authenticate(t.Context(), "id", fixturePassword)
	want := password.Result{Subject: "demo-subject", Decision: password.PasswordOnly}
	if err != nil || result != want || auth.NeedsRehash(record) {
		t.Fatalf("new record: result %+v, err %v, NeedsRehash %v", result, err, auth.NeedsRehash(record))
	}
}

func TestNeedsRehash(t *testing.T) {
	records := []string{argon2Record, fixtureRecord, "malformed", ""}
	for _, tc := range []struct {
		name string
		opts []password.Option
		want string // the only record that needs a rehash, if any
	}{
		{"no migration", nil, ""},
		{"argon2id primary", []password.Option{password.WithMigrationFrom(password.PBKDF2SHA256)}, fixtureRecord},
		{"pbkdf2 primary", []password.Option{
			password.WithAlgorithm(password.PBKDF2SHA256), password.WithMigrationFrom(password.Argon2id),
		}, argon2Record},
	} {
		auth := authenticator(t, credential(argon2Record), nil, tc.opts...)
		for _, record := range records {
			if got, want := auth.NeedsRehash(record), record != "" && record == tc.want; got != want {
				t.Fatalf("%s: NeedsRehash(%q) = %v, want %v", tc.name, record, got, want)
			}
		}
	}
	var missing *password.Authenticator
	for _, record := range records {
		if missing.NeedsRehash(record) || (&password.Authenticator{}).NeedsRehash(record) {
			t.Fatalf("NeedsRehash(%q) is true without configuration", record)
		}
	}
}
