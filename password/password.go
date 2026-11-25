// Package password verifies application-owned password credentials and evaluates
// the application's policy for completing a login.
package password

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrNotFound is returned by Lookup when an identifier is unknown.
	ErrNotFound = errors.New("password: credential not found")
	// ErrCredentials reports an unknown identifier or invalid password.
	ErrCredentials = errors.New("password: invalid credentials")
	// ErrRecord reports invalid credential data from Lookup.
	ErrRecord        = errors.New("password: invalid credential record")
	errConfiguration = errors.New("password: credential lookup is required")
	errOption        = errors.New("password: invalid option")
	errAlgorithm     = errors.New("password: unsupported algorithm")
)

const (
	pbkdf2Prefix     = "v1$pbkdf2-sha256$600000$"
	pbkdf2Iterations = 600_000
	argon2Prefix     = "v2$argon2id$m=19456,t=2,p=1$"
	argon2Time       = 2
	argon2Memory     = 19_456 // KiB
	argon2Threads    = 1
	saltSize         = 16
	keySize          = 32
	maxPasswordBytes = 1024
)

var recordEncoding = base64.RawStdEncoding.Strict()

// deriveKey is the key derivation used for verification and dummy work. It is
// a variable only so that internal tests can observe the selected algorithm.
var deriveKey = derive

// Algorithm selects the key derivation function for password records.
type Algorithm uint8

const (
	// Argon2id derives keys with Argon2id (m=19456 KiB, t=2, p=1). It is the default.
	Argon2id Algorithm = iota + 1
	// PBKDF2SHA256 derives keys with PBKDF2-HMAC-SHA256 and 600,000 iterations.
	PBKDF2SHA256
)

func (alg Algorithm) valid() bool {
	return alg == Argon2id || alg == PBKDF2SHA256
}

// prefix returns the exact record prefix of alg, or "" for an invalid value.
func (alg Algorithm) prefix() string {
	switch alg {
	case Argon2id:
		return argon2Prefix
	case PBKDF2SHA256:
		return pbkdf2Prefix
	default:
		return ""
	}
}

type config struct {
	algorithm Algorithm
}

// Option configures an Authenticator.
type Option func(*config)

// WithAlgorithm selects the algorithm used by the Authenticator for new records
// from its Hash method, for the only record format accepted by Authenticate,
// and for the dummy work spent on unknown identifiers and invalid records.
// The package-level Hash function ignores this setting and always uses Argon2id.
func WithAlgorithm(alg Algorithm) Option {
	return func(c *config) { c.algorithm = alg }
}

// Credential contains the stable application subject and its encoded password hash.
type Credential struct {
	Subject string
	Hash    string
}

// Lookup retrieves a credential using application-specific identifier rules.
type Lookup func(ctx context.Context, identifier string) (Credential, error)

// Decision describes the application's requirements after password verification.
type Decision uint8

const (
	PasswordOnly Decision = iota + 1
	RequireMFA
)

// Policy evaluates the requirements for this verified subject. A policy error
// or any decision other than PasswordOnly or RequireMFA fails authentication.
type Policy func(ctx context.Context, subject string) (Decision, error)

// Result describes a verified password. RequireMFA means login is incomplete.
// The application must explicitly decide when to issue a session.
type Result struct {
	Subject  string
	Decision Decision
}

// Authenticator verifies credentials and applies the configured login policy.
type Authenticator struct {
	lookup    Lookup
	policy    Policy
	algorithm Algorithm
}

// New constructs an authenticator. A nil policy selects PasswordOnly.
// Applications requiring additional factors must supply their policy here.
// Without options the authenticator uses Argon2id. When the same option is
// given more than once, the last one wins.
func New(lookup Lookup, policy Policy, opts ...Option) (*Authenticator, error) {
	if lookup == nil {
		return nil, errConfiguration
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, errOption
		}
	}
	cfg := config{algorithm: Argon2id}
	for _, opt := range opts {
		opt(&cfg)
	}
	if !cfg.algorithm.valid() {
		return nil, errAlgorithm
	}
	if policy == nil {
		policy = func(context.Context, string) (Decision, error) { return PasswordOnly, nil }
	}
	return &Authenticator{lookup: lookup, policy: policy, algorithm: cfg.algorithm}, nil
}

// Hash encodes a new record with the authenticator's configured algorithm and
// a fresh random salt. The password must contain 1–1024 bytes. Its bytes are
// used exactly as supplied. Applications that use WithAlgorithm must create
// records with this method.
func (a *Authenticator) Hash(secret string) (string, error) {
	if a == nil {
		return "", errConfiguration
	}
	if !a.algorithm.valid() {
		return "", errAlgorithm
	}
	return hash(a.algorithm, secret)
}

// Hash encodes a new record with Argon2id, the default algorithm, and a fresh
// random salt. It matches (*Authenticator).Hash for an authenticator built
// without options. The password must contain 1–1024 bytes. Its bytes are used
// exactly as supplied.
func Hash(secret string) (string, error) {
	return hash(Argon2id, secret)
}

func hash(alg Algorithm, secret string) (string, error) {
	if len(secret) == 0 || len(secret) > maxPasswordBytes {
		return "", errors.New("password: password length must be 1–1024 bytes")
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}
	key, err := derive(alg, secret, salt)
	if err != nil {
		return "", err
	}
	return alg.prefix() + recordEncoding.EncodeToString(salt) + "$" + recordEncoding.EncodeToString(key), nil
}

func derive(alg Algorithm, secret string, salt []byte) ([]byte, error) {
	switch alg {
	case Argon2id:
		return argon2.IDKey([]byte(secret), salt, argon2Time, argon2Memory, argon2Threads, keySize), nil
	case PBKDF2SHA256:
		return pbkdf2.Key(sha256.New, secret, salt, pbkdf2Iterations, keySize)
	default:
		return nil, errAlgorithm
	}
}

// dummyDerive spends the same KDF cost as an ordinary verification without
// using any value from the stored record.
func (a *Authenticator) dummyDerive(secret string) error {
	_, err := deriveKey(a.algorithm, secret, make([]byte, saltSize))
	return err
}

// Authenticate verifies the password before evaluating policy. It accepts only
// records in the format of the configured algorithm; any other record returns
// ErrRecord. Lookup and policy errors are for internal handling and may contain
// application details.
func (a *Authenticator) Authenticate(ctx context.Context, identifier, secret string) (Result, error) {
	if a == nil || a.lookup == nil || a.policy == nil {
		return Result{}, errConfiguration
	}
	if !a.algorithm.valid() {
		return Result{}, errAlgorithm
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if len(secret) == 0 || len(secret) > maxPasswordBytes {
		return Result{}, ErrCredentials
	}
	cred, err := a.lookup(ctx, identifier)
	if errors.Is(err, ErrNotFound) {
		// Spend the same KDF cost as an ordinary unsuccessful verification.
		if err := a.dummyDerive(secret); err != nil {
			return Result{}, err
		}
		return Result{}, ErrCredentials
	}
	if err != nil {
		return Result{}, fmt.Errorf("password: lookup: %w", err)
	}
	salt, expected, err := parseRecord(a.algorithm, cred.Hash)
	if err != nil || cred.Subject == "" {
		// Keep invalid records indistinguishable in timing from unknown identifiers.
		if err := a.dummyDerive(secret); err != nil {
			return Result{}, err
		}
		return Result{}, ErrRecord
	}
	actual, err := deriveKey(a.algorithm, secret, salt)
	if err != nil {
		return Result{}, err
	}
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return Result{}, ErrCredentials
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	decision, err := a.policy(ctx, cred.Subject)
	if err != nil {
		return Result{}, fmt.Errorf("password: policy: %w", err)
	}
	if decision != PasswordOnly && decision != RequireMFA {
		return Result{}, errors.New("password: invalid policy decision")
	}
	return Result{Subject: cred.Subject, Decision: decision}, nil
}

// parseRecord accepts only the exact format of alg. Parameters are never read
// from the record.
func parseRecord(alg Algorithm, record string) (salt, key []byte, err error) {
	prefix := alg.prefix()
	saltChars := recordEncoding.EncodedLen(saltSize)
	keyChars := recordEncoding.EncodedLen(keySize)
	if prefix == "" || len(record) != len(prefix)+saltChars+1+keyChars || !strings.HasPrefix(record, prefix) {
		return nil, nil, ErrRecord
	}
	encodedSalt, encodedKey, ok := strings.Cut(record[len(prefix):], "$")
	if !ok || len(encodedSalt) != saltChars || len(encodedKey) != keyChars {
		return nil, nil, ErrRecord
	}
	salt, err = recordEncoding.DecodeString(encodedSalt)
	if err != nil || len(salt) != saltSize {
		return nil, nil, ErrRecord
	}
	key, err = recordEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != keySize {
		return nil, nil, ErrRecord
	}
	return salt, key, nil
}
