package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2bskn/authlume/session"
)

// Run the same handler as the command, with a browser cookie jar and an
// adjustable server clock. Cookie transmission still uses real HTTPS.
type browser struct {
	server *httptest.Server
	client *http.Client
	start  time.Time
	offset atomic.Int64
}

func newBrowser(t *testing.T, store session.Store, requireMFA bool) *browser {
	t.Helper()
	b := &browser{start: time.Now()}
	sessions, err := session.New(store, session.Config{
		Idle: 2 * time.Hour, Absolute: 5 * time.Hour,
		Now: func() time.Time { return b.start.Add(time.Duration(b.offset.Load())) },
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := demoAuthenticator("test password", requireMFA)
	if err != nil {
		t.Fatal(err)
	}
	b.server = httptest.NewTLSServer(handler(auth, sessions))
	t.Cleanup(b.server.Close)
	b.client = b.server.Client()
	b.client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	b.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return b
}

func (b *browser) request(t *testing.T, method, path string, form url.Values, want int) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, b.server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", b.server.URL)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("%s %s: got %d, want %d", method, path, response.StatusCode, want)
	}
	return response
}

func (b *browser) login(t *testing.T, want int) *http.Response {
	t.Helper()
	return b.request(t, "POST", "/login", url.Values{"username": {"demo"}, "password": {"test password"}}, want)
}

func TestLoginRotateLogout(t *testing.T) {
	b := newBrowser(t, session.NewMemoryStore(), false)
	b.request(t, "GET", "/", nil, http.StatusOK)
	b.request(t, "GET", "/protected", nil, http.StatusUnauthorized)
	first := b.login(t, http.StatusSeeOther)
	if first.Header.Get("Location") != "/protected" || len(first.Cookies()) != 1 {
		t.Fatal("successful login must issue a cookie and redirect to the protected page")
	}
	b.request(t, "GET", "/protected", nil, http.StatusOK)
	second := b.login(t, http.StatusSeeOther)
	if len(second.Cookies()) != 1 || second.Cookies()[0].Value == first.Cookies()[0].Value {
		t.Fatal("login must rotate the session ID")
	}
	b.request(t, "POST", "/logout", nil, http.StatusSeeOther)
	b.request(t, "GET", "/protected", nil, http.StatusUnauthorized)
}

func TestPassiveTrafficAndExpiry(t *testing.T) {
	b := newBrowser(t, session.NewMemoryStore(), false)
	b.login(t, http.StatusSeeOther)
	b.offset.Store(int64(time.Hour))
	b.request(t, "GET", "/poll", nil, http.StatusNoContent)
	b.request(t, "GET", "/protected", nil, http.StatusOK)
	b.offset.Store(int64(2 * time.Hour))
	b.request(t, "GET", "/protected", nil, http.StatusUnauthorized)
}

func TestActivityAndAbsoluteExpiry(t *testing.T) {
	b := newBrowser(t, session.NewMemoryStore(), false)
	b.login(t, http.StatusSeeOther)
	for _, sinceLogin := range []time.Duration{90 * time.Minute, 3 * time.Hour, 270 * time.Minute} {
		b.offset.Store(int64(sinceLogin))
		b.request(t, "POST", "/activity", nil, http.StatusSeeOther)
		b.request(t, "GET", "/protected", nil, http.StatusOK)
	}
	b.offset.Store(int64(5 * time.Hour))
	b.request(t, "POST", "/activity", nil, http.StatusUnauthorized)
}

func TestRequiredMFALeavesLoginIncomplete(t *testing.T) {
	b := newBrowser(t, session.NewMemoryStore(), true)
	resp := b.login(t, http.StatusForbidden)
	if len(resp.Cookies()) != 0 {
		t.Fatal("incomplete MFA login issued a cookie")
	}
	b.request(t, "GET", "/protected", nil, http.StatusUnauthorized)
}

type unavailableDeletion struct{ *session.MemoryStore }

func (unavailableDeletion) Delete(context.Context, session.Key) error {
	return errors.New("backend unavailable")
}

func TestLogoutReportsStoreFailure(t *testing.T) {
	b := newBrowser(t, unavailableDeletion{session.NewMemoryStore()}, false)
	b.login(t, http.StatusSeeOther)
	resp := b.request(t, "POST", "/logout", nil, http.StatusServiceUnavailable)
	if len(resp.Cookies()) != 0 {
		t.Fatal("failed logout changed the cookie")
	}
	b.request(t, "GET", "/protected", nil, http.StatusOK)
}
