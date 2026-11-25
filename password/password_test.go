package password_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/i2bskn/authlume/password"
)

// Independent PBKDF2-HMAC-SHA256 fixture, salt bytes 0..15.
const (
	fixturePassword = "example credential"
	fixtureRecord   = "v1$pbkdf2-sha256$600000$AAECAwQFBgcICQoLDA0ODw$cjiPZp04h137x69SRDimhkI8gbfokyNy6XLl31C8qZw"
)

func authenticator(t *testing.T, lookup password.Lookup, policy password.Policy) *password.Authenticator {
	t.Helper()
	auth, err := password.New(lookup, policy)
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
	for _, decision := range []password.Decision{password.PasswordOnly, password.RequireMFA} {
		auth := authenticator(t, func(got context.Context, identifier string) (password.Credential, error) {
			if got != ctx || identifier != "Mixed.Case" {
				t.Fatal("lookup received different context or identifier")
			}
			return password.Credential{Subject: "demo-subject", Hash: fixtureRecord}, nil
		}, func(got context.Context, subject string) (password.Decision, error) {
			if got != ctx || subject != "demo-subject" {
				t.Fatal("policy received different context or subject")
			}
			return decision, nil
		})
		result, err := auth.Authenticate(ctx, "Mixed.Case", fixturePassword)
		if err != nil || result.Subject != "demo-subject" || result.Decision != decision {
			t.Fatalf("decision %v: result %v, err %v", decision, result, err)
		}
	}
}

func TestHashRoundTrip(t *testing.T) {
	for _, secret := range []string{"a", strings.Repeat("\x00\xff", 512)} {
		record, err := password.Hash(secret)
		if err != nil {
			t.Fatal(err)
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

func TestPasswordLength(t *testing.T) {
	auth := authenticator(t, func(context.Context, string) (password.Credential, error) {
		t.Fatal("lookup received invalid input")
		return password.Credential{}, nil
	}, nil)
	for _, secret := range []string{"", strings.Repeat("a", 1025)} {
		if record, err := password.Hash(secret); err == nil || record != "" {
			t.Fatalf("Hash accepted a %d byte password", len(secret))
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
		{"wrong password", password.Credential{Subject: "demo-subject", Hash: fixtureRecord}, nil, password.ErrCredentials},
		{"store failure", password.Credential{}, storeErr, storeErr},
		{"empty subject", password.Credential{Hash: fixtureRecord}, nil, password.ErrRecord},
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
	for _, record := range []string{
		"", strings.Replace(fixtureRecord, "v1", "v2", 1),
		strings.Replace(fixtureRecord, "600000", "600001", 1),
		strings.Replace(fixtureRecord, "pbkdf2-sha256", "pbkdf2-sha512", 1),
		strings.Replace(fixtureRecord, "ODw$", "ODx$", 1), // noncanonical salt
		fixtureRecord[:len(fixtureRecord)-1] + "x",        // noncanonical derived key
		fixtureRecord + "=", fixtureRecord[:len(fixtureRecord)-1],
	} {
		auth := authenticator(t, credential(record), nil)
		result, err := auth.Authenticate(t.Context(), "id", fixturePassword)
		if result != (password.Result{}) || !errors.Is(err, password.ErrRecord) {
			t.Fatalf("malformed record: result %v, err %v", result, err)
		}
	}
}

func TestPolicyFailure(t *testing.T) {
	failed := errors.New("policy unavailable")
	for _, tc := range []struct {
		decision password.Decision
		err      error
	}{{0, nil}, {99, nil}, {password.PasswordOnly, failed}} {
		auth := authenticator(t, credential(fixtureRecord), func(context.Context, string) (password.Decision, error) {
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
