// Package totp verifies enrolled RFC 6238 second factors for an application's
// already authenticated subject. The profile uses six digits, HMAC-SHA-1,
// a 30-second period and Unix epoch T0. By default, verification checks the
// server's current period and the preceding period to allow for entry delay.
// WithCurrentStepOnly limits it to the current period. If a fast device
// already shows the next period, that step is eligible only when the server
// reaches it. This profile requires HMAC-SHA-1 and is incompatible with Go's
// FIPS 140-only mode. Applications own enrollment, recovery, throttling and
// the decision to require this factor.
package totp

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrInvalid indicates an invalid code, missing/changed enrollment, or used step.
	ErrInvalid = errors.New("totp: invalid credentials")
	// ErrRecord indicates an invalid enrollment supplied by the store.
	ErrRecord = errors.New("totp: invalid enrollment")
	errOption = errors.New("totp: invalid option")
)

type config struct {
	currentOnly bool
}

// Option configures a Verifier.
type Option func(*config)

// WithCurrentStepOnly makes Verify accept only the server's current period.
// A code is then valid for at most 30 seconds, and a code entered near the
// end of its period fails once the next period begins. A device whose clock
// is slow enough to still show the preceding period always fails.
func WithCurrentStepOnly() Option {
	return func(c *config) { c.currentOnly = true }
}

// Credential is a consistent snapshot of an active enrollment. Each activation
// needs a fresh random secret of at least 20 bytes and a never-reused ID.
// Secret contains decoded bytes and its backing array must remain immutable.
// Verify returns ErrRecord for shorter secrets, including legacy 10-byte
// enrollments.
type Credential struct {
	ID     string
	Secret []byte
}

// Store holds one active TOTP enrollment per subject in an application namespace.
// Protect the secrets at rest. Backend errors must be distinct from ErrInvalid.
type Store interface {
	// Load returns the active credential for subject, or ErrInvalid if absent.
	Load(ctx context.Context, subject string) (Credential, error)
	// Consume atomically checks that id is still active for subject and that
	// step is newer than any step used for this enrollment. Persist the step
	// before reporting success. A failed condition returns ErrInvalid. These
	// checks must serialize with other consumes, rotations and revocations.
	Consume(ctx context.Context, subject, id string, step int64) error
}

// Verifier checks and consumes codes for the configured application.
type Verifier struct {
	store       Store
	now         func() time.Time
	currentOnly bool
}

// New creates a verifier. An optional concurrency-safe clock replaces time.Now.
// Options are optional. Without options Verify accepts the current and the
// preceding period. A nil option is an error.
func New(store Store, now func() time.Time, opts ...Option) (*Verifier, error) {
	if store == nil {
		return nil, errors.New("totp: store is required")
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, errOption
		}
	}
	if now == nil {
		now = time.Now
	}
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Verifier{store: store, now: now, currentOnly: cfg.currentOnly}, nil
}

// Verify completes the TOTP check for subject, as established by successful
// primary authentication. The code must be exactly six ASCII digits, including
// any leading zeros. Only nil means success. Callers must limit attempts
// across logins and may issue a session only after all policy checks succeed.
// A later session issuance failure does not undo consumption.
func (v *Verifier) Verify(ctx context.Context, subject, code string) error {
	if v == nil || v.store == nil {
		return errors.New("totp: uninitialized verifier")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if subject == "" || len(code) != 6 {
		return ErrInvalid
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return ErrInvalid
		}
	}
	cred, err := v.store.Load(ctx, subject)
	if err != nil {
		return fmt.Errorf("totp: load credential: %w", err)
	}
	if cred.ID == "" || len(cred.Secret) < 20 {
		return ErrRecord
	}
	seconds := v.now().Unix()
	if seconds < 0 {
		return ErrInvalid
	}
	current := seconds / 30
	first := current - 1
	if v.currentOnly {
		first = current
	}
	matched := int64(-1)
	for step := first; step <= current; step++ {
		if step >= 0 && subtle.ConstantTimeCompare([]byte(code), digits(cred.Secret, step)) == 1 {
			matched = step
		}
	}
	if matched < 0 {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := v.store.Consume(ctx, subject, cred.ID, matched); err != nil {
		return fmt.Errorf("totp: consume step: %w", err)
	}
	return nil
}

// digits applies the HOTP dynamic truncation from RFC 4226 to a time step.
func digits(secret []byte, step int64) []byte {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0xf
	value := binary.BigEndian.Uint32(sum[offset:]) & 0x7fffffff
	var code [6]byte
	for i := len(code) - 1; i >= 0; i-- {
		code[i] = '0' + byte(value%10)
		value /= 10
	}
	return code[:]
}
