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
)

var (
	// ErrNotFound is returned by Lookup when an identifier is unknown.
	ErrNotFound = errors.New("password: credential not found")
	// ErrCredentials reports an unknown identifier or invalid password.
	ErrCredentials = errors.New("password: invalid credentials")
	// ErrRecord reports invalid credential data from Lookup.
	ErrRecord        = errors.New("password: invalid credential record")
	errConfiguration = errors.New("password: credential lookup is required")
)

const (
	recordPrefix     = "v1$pbkdf2-sha256$600000$"
	iterations       = 600_000
	saltSize         = 16
	keySize          = 32
	maxPasswordBytes = 1024
)

var recordEncoding = base64.RawStdEncoding.Strict()

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
	lookup Lookup
	policy Policy
}

// New constructs an authenticator. A nil policy selects PasswordOnly.
// Applications requiring additional factors must supply their policy here.
func New(lookup Lookup, policy Policy) (*Authenticator, error) {
	if lookup == nil {
		return nil, errConfiguration
	}
	if policy == nil {
		policy = func(context.Context, string) (Decision, error) { return PasswordOnly, nil }
	}
	return &Authenticator{lookup: lookup, policy: policy}, nil
}

// Hash encodes a new password record using a fresh random salt. The password
// must contain 1–1024 bytes. Its bytes are used exactly as supplied.
func Hash(secret string) (string, error) {
	if len(secret) == 0 || len(secret) > maxPasswordBytes {
		return "", errors.New("password: password length must be 1–1024 bytes")
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}
	key, err := derive(secret, salt)
	if err != nil {
		return "", err
	}
	return recordPrefix + recordEncoding.EncodeToString(salt) + "$" + recordEncoding.EncodeToString(key), nil
}

func derive(secret string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, secret, salt, iterations, keySize)
}

// Authenticate verifies the password before evaluating policy. Lookup and
// policy errors are for internal handling and may contain application details.
func (a *Authenticator) Authenticate(ctx context.Context, identifier, secret string) (Result, error) {
	if a == nil || a.lookup == nil || a.policy == nil {
		return Result{}, errConfiguration
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
		if _, err := derive(secret, make([]byte, saltSize)); err != nil {
			return Result{}, err
		}
		return Result{}, ErrCredentials
	}
	if err != nil {
		return Result{}, fmt.Errorf("password: lookup: %w", err)
	}
	if cred.Subject == "" {
		return Result{}, ErrRecord
	}
	salt, expected, err := parseRecord(cred.Hash)
	if err != nil {
		return Result{}, err
	}
	actual, err := derive(secret, salt)
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

func parseRecord(record string) (salt, key []byte, err error) {
	saltChars := recordEncoding.EncodedLen(saltSize)
	keyChars := recordEncoding.EncodedLen(keySize)
	if len(record) != len(recordPrefix)+saltChars+1+keyChars || !strings.HasPrefix(record, recordPrefix) {
		return nil, nil, ErrRecord
	}
	encodedSalt, encodedKey, ok := strings.Cut(record[len(recordPrefix):], "$")
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
