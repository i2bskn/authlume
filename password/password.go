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
	"slices"
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
	migration []Algorithm
}

// Option configures an Authenticator.
type Option func(*config)

// WithAlgorithm selects the primary algorithm of the Authenticator. It is used
// for new records from its Hash method, for the record format accepted by
// Authenticate, and for the dummy work spent on unknown identifiers and invalid
// records. Authenticate accepts no other format unless WithMigrationFrom names
// it. The package-level Hash function ignores this setting and always uses
// Argon2id.
func WithAlgorithm(alg Algorithm) Option {
	return func(c *config) { c.algorithm = alg }
}

// WithMigrationFrom makes Authenticate also accept records of the given
// algorithms. New records still use the algorithm selected with WithAlgorithm.
// A successful Authenticate for such a record sets Result.Rehash.
//
// The given algorithms must be supported, distinct and different from the
// algorithm selected with WithAlgorithm. The arguments are copied when
// WithMigrationFrom is called. A call without arguments accepts no additional
// algorithm.
//
// While the option is set, every Authenticate call that reaches a derivation
// performs one derivation per accepted algorithm: the real one for the
// algorithm of the stored record and a dummy one for each of the others, or
// only dummy ones for an unknown identifier or an invalid record. The response
// time of Authenticate therefore does not depend on whether the identifier
// exists or which accepted algorithm its record uses. In exchange every attempt
// costs the sum of the accepted algorithms, for example one Argon2id and one
// PBKDF2 derivation, and login throttling must allow for the added cost while
// the option is set.
//
// When Result.Rehash is true, replace the stored record. First compute the new
// record with the Authenticator's Hash method from the password that was just
// verified; the package-level Hash always writes Argon2id. Then, holding a lock
// on the stored record (a row lock, or the store's conditional write), read it
// again and write the new record only if NeedsRehash is still true for the
// stored one. Without the lock a concurrent password change can still be
// overwritten with the old password. Do the replacement synchronously. It may
// happen as soon as the password is verified, before MFA completes, because it
// only re-encodes the same password. A failed replacement need not fail the
// login: the old record still verifies and the next sign-in tries again. The
// replacement is the application's own work and adds time to a successful
// sign-in of a migrating record.
//
// NeedsRehash tells formats apart, not records. The check protects a concurrent
// password change only when that change wrote a record of the primary
// algorithm. Every writer of password records must therefore use the Hash
// method of an Authenticator with the same configuration. A writer that still
// produces the other algorithm, such as an instance not yet switched during a
// rollout or a tool calling the package-level Hash while the primary algorithm
// is PBKDF2, is not protected. An application that needs the stronger guarantee
// keeps the record its Lookup returned and writes only if the stored record
// still equals it.
//
// An instance without the option rejects records of the other algorithm. To
// roll out across several instances, first deploy every instance with the old
// algorithm as primary and the new one in WithMigrationFrom, then swap the two.
// To roll back, return to the first step. During the swap, instances on either
// side re-encode records toward their own primary algorithm, so a record can
// move back and forth until every instance is switched. Authentication keeps
// working throughout.
//
// Records of users who never sign in stay unmigrated and return ErrRecord once
// the option is removed. Before removing it, count them by calling NeedsRehash
// for each record, or by matching the record prefixes documented at
// https://docs.i2bskn.com/authlume/reference/design/ in a query, and decide what
// happens to them, for example a forced password reset.
func WithMigrationFrom(algs ...Algorithm) Option {
	migration := slices.Clone(algs)
	return func(c *config) { c.migration = migration }
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
	// Rehash reports that the verified record uses an algorithm accepted only
	// through WithMigrationFrom. Replace the record with the Authenticator's
	// Hash of the password that was just verified.
	Rehash bool
}

// Authenticator verifies credentials and applies the configured login policy.
type Authenticator struct {
	lookup    Lookup
	policy    Policy
	algorithm Algorithm
	migration []Algorithm
}

// New constructs an authenticator. A nil policy selects PasswordOnly.
// Applications requiring additional factors must supply their policy here.
// Without options the authenticator uses Argon2id and accepts no other
// algorithm. When the same option is given more than once, the last one wins.
// The options are checked together after all of them are applied, so their
// order does not matter.
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
	for _, alg := range cfg.migration {
		if !alg.valid() {
			return nil, errAlgorithm
		}
	}
	for i, alg := range cfg.migration {
		if alg == cfg.algorithm || slices.Contains(cfg.migration[:i], alg) {
			return nil, errOption
		}
	}
	if policy == nil {
		policy = func(context.Context, string) (Decision, error) { return PasswordOnly, nil }
	}
	return &Authenticator{
		lookup:    lookup,
		policy:    policy,
		algorithm: cfg.algorithm,
		migration: slices.Clone(cfg.migration),
	}, nil
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

// NeedsRehash reports whether record is a well-formed record of an algorithm
// accepted only through WithMigrationFrom. It performs no derivation.
func (a *Authenticator) NeedsRehash(record string) bool {
	if a == nil {
		return false
	}
	for _, alg := range a.migration {
		if _, _, err := parseRecord(alg, record); err == nil {
			return true
		}
	}
	return false
}

// accepted returns the configured algorithm followed by the algorithms from
// WithMigrationFrom in their given order.
func (a *Authenticator) accepted() []Algorithm {
	algs := make([]Algorithm, 0, 1+len(a.migration))
	return append(append(algs, a.algorithm), a.migration...)
}

// deriveAll performs one derivation per accepted algorithm, in the order of
// accepted. It returns the key derived with salt for the algorithm equal to
// record. Every other derivation is dummy work with a zero salt whose result is
// discarded. With record 0 all derivations are dummy work and the key is nil.
func (a *Authenticator) deriveAll(secret string, record Algorithm, salt []byte) ([]byte, error) {
	var actual []byte
	dummy := make([]byte, saltSize)
	for _, alg := range a.accepted() {
		if alg != record {
			if _, err := deriveKey(alg, secret, dummy); err != nil {
				return nil, err
			}
			continue
		}
		key, err := deriveKey(alg, secret, salt)
		if err != nil {
			return nil, err
		}
		actual = key
	}
	return actual, nil
}

// dummyDerive spends the same KDF cost as an ordinary verification, one
// derivation per accepted algorithm, without using any value from the stored
// record.
func (a *Authenticator) dummyDerive(secret string) error {
	_, err := a.deriveAll(secret, 0, nil)
	return err
}

// parse returns the accepted algorithm whose exact format record has, with the
// decoded salt and key. The configured algorithm is tried first, then the
// algorithms from WithMigrationFrom. The record prefixes differ, so at most one
// algorithm matches.
func (a *Authenticator) parse(record string) (alg Algorithm, salt, key []byte, err error) {
	for _, alg := range a.accepted() {
		if salt, key, err := parseRecord(alg, record); err == nil {
			return alg, salt, key, nil
		}
	}
	return 0, nil, nil, ErrRecord
}

// Authenticate verifies the password before evaluating policy. It accepts
// records in the format of the configured algorithm and, when WithMigrationFrom
// is set, of the algorithms named there; any other record returns ErrRecord. A
// success for a record accepted only through WithMigrationFrom sets
// Result.Rehash. Authenticate never changes the stored record. Lookup and policy
// errors are for internal handling and may contain application details.
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
		// Spend the same KDF cost as an ordinary unsuccessful verification:
		// one derivation per accepted algorithm.
		if err := a.dummyDerive(secret); err != nil {
			return Result{}, err
		}
		return Result{}, ErrCredentials
	}
	if err != nil {
		return Result{}, fmt.Errorf("password: lookup: %w", err)
	}
	alg, salt, expected, err := a.parse(cred.Hash)
	if err != nil || cred.Subject == "" {
		// Keep invalid records indistinguishable in timing from unknown identifiers.
		if err := a.dummyDerive(secret); err != nil {
			return Result{}, err
		}
		return Result{}, ErrRecord
	}
	// Only the derivation for the record's algorithm is compared. The dummy
	// derivations for the other accepted algorithms keep the work equal.
	actual, err := a.deriveAll(secret, alg, salt)
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
	return Result{Subject: cred.Subject, Decision: decision, Rehash: alg != a.algorithm}, nil
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
