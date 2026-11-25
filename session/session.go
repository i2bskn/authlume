// Package session manages server-backed web sessions independently of the
// authentication method. Applications call Issue only after completing their
// authentication policy, including any required additional factors.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	CookieName      = "__Host-authlume"
	DefaultIdle     = 24 * time.Hour
	DefaultAbsolute = 7 * 24 * time.Hour
)

var (
	// ErrInvalid indicates a missing, malformed, ambiguous, expired or revoked session.
	ErrInvalid = errors.New("session: invalid session")
	// ErrCookieWellFormed means reset found one syntactically valid cookie.
	// Use Logout to revoke the session and clear the cookie.
	ErrCookieWellFormed = errors.New("session: cookie is well formed")
	// ErrReauthenticationRequired indicates the session's authentication is too old.
	ErrReauthenticationRequired = errors.New("session: fresh authentication required")
	// ErrCollision indicates a new session key was already in use.
	ErrCollision = errors.New("session: session key collision")
)

// Key is the SHA-256 digest of the raw 32-byte cookie ID. It can be used to
// revoke a session, but cannot be presented as that session's bearer ID.
type Key [sha256.Size]byte

// State is a snapshot. Idle activity never changes AuthenticatedAt or AbsoluteExpiry.
type State struct {
	Key             Key
	Subject         string
	AuthenticatedAt time.Time
	LastActivity    time.Time
	AbsoluteExpiry  time.Time
	Idle            time.Duration
}

// Expired reports whether either deadline has been reached.
func (s State) Expired(now time.Time) bool {
	return !now.Before(s.AbsoluteExpiry) || !now.Before(s.LastActivity.Add(s.Idle))
}

// Store operations on overlapping keys must be linearizable. Implementations
// own physical cleanup of expired records. Backend errors must be distinct
// from ErrInvalid so the caller can report an unavailable service.
type Store interface {
	// Replace atomically inserts next and removes previous, if present. An
	// unknown previous key is allowed. A collision must leave previous intact.
	Replace(ctx context.Context, previous *Key, next State) error
	// Use atomically validates both deadlines and returns ErrInvalid if the
	// record is missing or expired. If touch, advance LastActivity to the
	// later of now and LastActivity. Never recreate a missing record.
	Use(ctx context.Context, key Key, now time.Time, touch bool) (State, error)
	// Delete is idempotent, including when the record is already gone.
	Delete(ctx context.Context, key Key) error
}

// Config selects the cookie name and server-side lifetimes. A zero duration selects the OSS
// default for that field. Now defaults to time.Now and must be concurrency-safe.
type Config struct {
	// CookieName defaults to __Host-authlume. A custom name must be a valid
	// __Host- cookie name and fit the 4096-byte name-plus-value limit.
	CookieName string
	Idle       time.Duration
	Absolute   time.Duration
	Now        func() time.Time
}

type Manager struct {
	store Store
	cfg   Config
}

func New(store Store, cfg Config) (*Manager, error) {
	if store == nil {
		return nil, errors.New("session: store is required")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = CookieName
	}
	const prefix = "__Host-"
	if !strings.HasPrefix(cfg.CookieName, prefix) || len(cfg.CookieName) == len(prefix) ||
		len(cfg.CookieName) > 4096-base64.RawURLEncoding.EncodedLen(32) ||
		(&http.Cookie{Name: cfg.CookieName}).Valid() != nil {
		return nil, errors.New("session: invalid cookie name")
	}
	if cfg.Idle == 0 {
		cfg.Idle = DefaultIdle
	}
	if cfg.Absolute == 0 {
		cfg.Absolute = DefaultAbsolute
	}
	if cfg.Idle <= 0 || cfg.Absolute <= 0 || cfg.Idle > cfg.Absolute {
		return nil, errors.New("session: require 0 < idle <= absolute lifetime")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Manager{store: store, cfg: cfg}, nil
}

// cookieKey inspects the wire values since net/http's cookie accessors skip
// malformed cookies and remove quotes. Only this manager's cookie is relevant.
func (m *Manager) cookieKey(r *http.Request) (*Key, error) {
	var key *Key
	for _, line := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(line, ";") {
			name, value, found := strings.Cut(strings.Trim(part, " \t"), "=")
			if strings.TrimSpace(name) != m.cfg.CookieName {
				continue
			}
			if key != nil || name != m.cfg.CookieName || !found || len(value) != base64.RawURLEncoding.EncodedLen(32) {
				return nil, ErrInvalid
			}
			var raw [32]byte
			n, err := base64.RawURLEncoding.Strict().Decode(raw[:], []byte(value))
			if err != nil || n != len(raw) {
				return nil, ErrInvalid
			}
			digest := Key(sha256.Sum256(raw[:]))
			key = &digest
		}
	}
	return key, nil
}

func (m *Manager) cookie(value string, expires time.Time) *http.Cookie {
	// HTTP dates only carry whole seconds. Round up so the browser retains
	// the cookie until the server's precise deadline, including subsecond TTLs.
	if ns := expires.Nanosecond(); ns != 0 {
		expires = expires.Add(time.Second - time.Duration(ns))
	}
	return &http.Cookie{
		Name: m.cfg.CookieName, Value: value, Expires: expires.UTC(), Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}

// Issue starts a new authentication lifetime and atomically replaces any
// presented session. Call before writing a response. For reauthentication,
// the application must first verify the intended subject under current policy.
func (m *Manager) Issue(w http.ResponseWriter, r *http.Request, subject string) error {
	previous, err := m.cookieKey(r)
	if err != nil {
		return err
	}
	if subject == "" {
		return errors.New("session: subject is required")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	now := m.cfg.Now()
	next := State{
		Key: Key(sha256.Sum256(raw[:])), Subject: subject, AuthenticatedAt: now,
		LastActivity: now, AbsoluteExpiry: now.Add(m.cfg.Absolute), Idle: m.cfg.Idle,
	}
	if previous != nil && *previous == next.Key {
		return ErrCollision
	}
	if err := m.store.Replace(r.Context(), previous, next); err != nil {
		return err
	}
	http.SetCookie(w, m.cookie(base64.RawURLEncoding.EncodeToString(raw[:]), next.AbsoluteExpiry))
	return nil
}

func (m *Manager) use(r *http.Request, now time.Time, touch bool) (State, error) {
	key, err := m.cookieKey(r)
	if err != nil || key == nil {
		return State{}, ErrInvalid
	}
	return m.store.Use(r.Context(), *key, now, touch)
}

// Read validates a session without extending its idle deadline.
func (m *Manager) Read(r *http.Request) (State, error) {
	return m.use(r, m.cfg.Now(), false)
}

// Touch validates and records an interactive action. Call only when the
// application has classified the activity as user-initiated.
func (m *Manager) Touch(r *http.Request) (State, error) {
	return m.use(r, m.cfg.Now(), true)
}

// RequireFresh passively validates a session and requires authentication
// within maxAge. At equality it requires reauthentication.
func (m *Manager) RequireFresh(r *http.Request, maxAge time.Duration) (State, error) {
	now := m.cfg.Now()
	state, err := m.use(r, now, false)
	if err != nil {
		return State{}, err
	}
	if maxAge <= 0 || now.Before(state.AuthenticatedAt) || !now.Before(state.AuthenticatedAt.Add(maxAge)) {
		return State{}, ErrReauthenticationRequired
	}
	return state, nil
}

// Logout revokes the session before instructing the browser to clear its cookie.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) error {
	key, err := m.cookieKey(r)
	if err != nil {
		return err
	}
	if key != nil {
		if err := m.Revoke(r.Context(), *key); err != nil {
			return err
		}
	}
	m.clearCookie(w)
	return nil
}

// ResetInvalidCookie clears a malformed or duplicate cookie for this manager
// without accessing the store. An absent cookie needs no action. A single
// well-formed cookie requires normal Logout, even if the record has expired.
// Protect this browser action against CSRF as for other state changes.
func (m *Manager) ResetInvalidCookie(w http.ResponseWriter, r *http.Request) error {
	key, err := m.cookieKey(r)
	if errors.Is(err, ErrInvalid) {
		m.clearCookie(w)
		return nil
	}
	if err != nil {
		return err
	}
	if key != nil {
		return ErrCookieWellFormed
	}
	return nil
}

func (m *Manager) clearCookie(w http.ResponseWriter) {
	expired := m.cookie("", time.Unix(1, 0))
	expired.MaxAge = -1
	http.SetCookie(w, expired)
}

// Revoke idempotently terminates a session by its stored digest.
func (m *Manager) Revoke(ctx context.Context, key Key) error {
	return m.store.Delete(ctx, key)
}
