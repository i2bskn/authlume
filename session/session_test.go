package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func manager(t *testing.T, store Store, cfg Config) *Manager {
	t.Helper()
	m, err := New(store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func request(cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", "https://example.org/", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

func issue(t *testing.T, m *Manager, r *http.Request) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	if err := m.Issue(w, r, "user"); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies()[0]
}

func TestConfigAndDefaults(t *testing.T) {
	for _, cfg := range []Config{{Idle: -1, Absolute: 1}, {Absolute: -1}, {Absolute: 1}, {Idle: 2, Absolute: 1}} {
		if _, err := New(NewMemoryStore(), cfg); err == nil {
			t.Fatalf("accepted config %+v", cfg)
		}
	}
	for _, tc := range []struct {
		cfg            Config
		idle, absolute time.Duration
	}{
		{Config{Idle: time.Hour}, time.Hour, DefaultAbsolute},
		{Config{Absolute: 30 * 24 * time.Hour}, DefaultIdle, 30 * 24 * time.Hour},
	} {
		m := manager(t, NewMemoryStore(), tc.cfg)
		s, err := m.Read(request(issue(t, m, request())))
		if err != nil || s.Idle != tc.idle || s.AbsoluteExpiry.Sub(s.AuthenticatedAt) != tc.absolute {
			t.Fatalf("single configured timeout: state %+v, err %v", s, err)
		}
	}
	if _, err := New(nil, Config{}); err == nil {
		t.Fatal("accepted nil store")
	}
	m := manager(t, NewMemoryStore(), Config{})
	w := httptest.NewRecorder()
	if err := m.Issue(w, request(), ""); err == nil || len(w.Header()) != 0 {
		t.Fatal("issued session for empty subject")
	}
	for _, op := range []func(*http.Request) (State, error){m.Read, m.Touch} {
		if _, err := op(request()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("missing cookie: %v", err)
		}
	}
	c := issue(t, m, request())
	if c.Name != CookieName || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Fatal("unexpected cookie attributes")
	}
	state, err := m.Read(request(c))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(c.Value)
	if err != nil || len(raw) != 32 || state.Key != Key(sha256.Sum256(raw)) {
		t.Fatal("invalid ID or digest")
	}
	if state.Subject != "user" || state.Idle != 24*time.Hour || state.AbsoluteExpiry.Sub(state.AuthenticatedAt) != 7*24*time.Hour || c.Expires.Before(state.AbsoluteExpiry) || c.Expires.Sub(state.AbsoluteExpiry) >= time.Second {
		t.Fatal("wrong default lifetimes or subject")
	}
}

func TestCookieExpiryRoundsUpWhileServerKeepsPreciseDeadline(t *testing.T) {
	base := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, ttl := range []time.Duration{100 * time.Millisecond, time.Second} {
		now := base
		m := manager(t, NewMemoryStore(), Config{Idle: ttl, Absolute: ttl, Now: func() time.Time { return now }})
		c := issue(t, m, request())
		if !c.Expires.Equal(base.Add(time.Second)) {
			t.Fatalf("ttl %v: browser expiry %s", ttl, c.Expires)
		}
		now = base.Add(ttl - time.Nanosecond)
		if _, err := m.Read(request(c)); err != nil {
			t.Fatalf("ttl %v: session expired early: %v", ttl, err)
		}
		now = base.Add(ttl)
		if _, err := m.Read(request(c)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ttl %v: server deadline not enforced: %v", ttl, err)
		}
	}
}

func TestDeadlinesAndFreshness(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Second)
	now := start
	m := manager(t, NewMemoryStore(), Config{Idle: time.Hour, Absolute: 2 * time.Hour, Now: func() time.Time { return now }})
	passive := request(issue(t, m, request()))
	active := request(issue(t, m, request()))
	now = start.Add(45 * time.Minute)
	if s, err := m.Read(passive); err != nil || s.LastActivity != start {
		t.Fatalf("passive read = %+v, %v", s, err)
	}
	if _, err := m.RequireFresh(active, time.Hour); err != nil {
		t.Fatal(err)
	}
	if s, err := m.Touch(active); err != nil || s.LastActivity != now {
		t.Fatal("interactive touch failed")
	}
	now = start.Add(40 * time.Minute)
	if s, err := m.Touch(active); err != nil || !s.LastActivity.Equal(start.Add(45*time.Minute)) {
		t.Fatal("last activity moved backwards")
	}
	now = start.Add(time.Hour)
	if _, err := m.Touch(passive); !errors.Is(err, ErrInvalid) {
		t.Fatalf("session at idle deadline: %v", err)
	}
	if _, err := m.RequireFresh(active, time.Hour); !errors.Is(err, ErrReauthenticationRequired) {
		t.Fatalf("authentication at max age: %v", err)
	}
	now = start.Add(90 * time.Minute)
	if _, err := m.Touch(active); err != nil {
		t.Fatal(err)
	}
	now = start.Add(2 * time.Hour)
	if _, err := m.Touch(active); !errors.Is(err, ErrInvalid) {
		t.Fatalf("session at absolute deadline: %v", err)
	}
	now = start
	if _, err := m.Read(active); !errors.Is(err, ErrInvalid) {
		t.Fatal("expired session reappeared")
	}
}

func TestRotationRevocationAndLogout(t *testing.T) {
	m := manager(t, NewMemoryStore(), Config{})
	first := issue(t, m, request())
	second := issue(t, m, request(first))
	if first.Value == second.Value {
		t.Fatal("session ID was reused")
	}
	if _, err := m.Read(request(first)); !errors.Is(err, ErrInvalid) {
		t.Fatal("old session survived rotation")
	}
	s, err := m.Read(request(second))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Revoke(context.Background(), s.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Touch(request(second)); !errors.Is(err, ErrInvalid) {
		t.Fatal("revoked session still active")
	}
	third := issue(t, m, request(second)) // Independently authenticated with a stale cookie.
	for _, r := range []*http.Request{request(third), request(third), request()} {
		w := httptest.NewRecorder()
		if err := m.Logout(w, r); err != nil {
			t.Fatal(err)
		}
		c := w.Result().Cookies()[0]
		if c.Name != CookieName || !c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.MaxAge >= 0 || c.Value != "" || !c.Expires.Before(time.Now()) {
			t.Fatal("incorrect logout cookie")
		}
	}
	if _, err := m.Read(request(third)); !errors.Is(err, ErrInvalid) {
		t.Fatal("logged-out session still active")
	}
}

func TestCookieValidation(t *testing.T) {
	m := manager(t, NewMemoryStore(), Config{})
	c := issue(t, m, request())
	valid := CookieName + "=" + c.Value
	for _, lines := range [][]string{
		{valid + "; " + valid}, {valid, valid}, {CookieName + "="},
		{CookieName + "=\"" + c.Value + "\""}, {valid + "="},
		{valid, CookieName + "=bad"}, {CookieName + " =" + c.Value},
		{CookieName + "=" + strings.Repeat("A", 42) + "B"}, // nonzero unused base64 bits
	} {
		r := request()
		for _, line := range lines {
			r.Header.Add("Cookie", line)
		}
		w := httptest.NewRecorder()
		for _, op := range []func() error{
			func() error { _, err := m.Read(r); return err },
			func() error { _, err := m.Touch(r); return err },
			func() error { return m.Issue(w, r, "user") },
			func() error { return m.Logout(w, r) },
		} {
			if err := op(); !errors.Is(err, ErrInvalid) || len(w.Header()) != 0 {
				t.Fatalf("cookie validation: %v", err)
			}
		}
		if _, err := m.Read(request(c)); err != nil {
			t.Fatal("cookie validation changed existing session")
		}
	}
}

func TestStorageErrors(t *testing.T) {
	m := manager(t, NewMemoryStore(), Config{})
	c := issue(t, m, request())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := request(c).WithContext(ctx)
	w := httptest.NewRecorder()
	for _, op := range []func() error{
		func() error { _, err := m.Read(r); return err },
		func() error { _, err := m.Touch(r); return err },
		func() error { return m.Issue(w, r, "user") },
		func() error { return m.Logout(w, r) },
	} {
		if err := op(); !errors.Is(err, context.Canceled) || len(w.Header()) != 0 {
			t.Fatalf("backend error: %v", err)
		}
	}
	if _, err := m.Read(request(c)); err != nil {
		t.Fatal("failed operations changed session")
	}
}
