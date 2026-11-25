package main

import (
	"context"
	"errors"
	"io"
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

func newBrowser(t *testing.T, store session.Store, requireMFA bool, cookieName string) *browser {
	t.Helper()
	b := &browser{start: time.Now()}
	sessions, err := session.New(store, session.Config{
		Idle: 2 * time.Hour, Absolute: 5 * time.Hour, CookieName: cookieName,
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

type reply struct {
	*http.Response
	body string
}

func (b *browser) request(t *testing.T, method, path string, form url.Values, want int) reply {
	t.Helper()
	return b.requestFrom(t, method, path, form, b.server.URL, want)
}

func (b *browser) requestFrom(t *testing.T, method, path string, form url.Values, origin string, want int) reply {
	t.Helper()
	req, err := http.NewRequest(method, b.server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("%s %s: got %d, want %d", method, path, response.StatusCode, want)
	}
	return reply{Response: response, body: string(body)}
}

func (b *browser) login(t *testing.T, want int) reply {
	t.Helper()
	return b.request(t, "POST", "/login", url.Values{"username": {"demo"}, "password": {"test password"}}, want)
}

func TestLoginRotateLogout(t *testing.T) {
	b := newBrowser(t, session.NewMemoryStore(), false, "")
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
	b := newBrowser(t, session.NewMemoryStore(), false, "")
	b.login(t, http.StatusSeeOther)
	b.offset.Store(int64(time.Hour))
	b.request(t, "GET", "/poll", nil, http.StatusNoContent)
	b.request(t, "GET", "/protected", nil, http.StatusOK)
	b.offset.Store(int64(2 * time.Hour))
	b.request(t, "GET", "/protected", nil, http.StatusUnauthorized)
}

func TestActivityAndAbsoluteExpiry(t *testing.T) {
	b := newBrowser(t, session.NewMemoryStore(), false, "")
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
	b := newBrowser(t, session.NewMemoryStore(), true, "")
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
	b := newBrowser(t, unavailableDeletion{session.NewMemoryStore()}, false, "")
	b.login(t, http.StatusSeeOther)
	resp := b.request(t, "POST", "/logout", nil, http.StatusServiceUnavailable)
	if len(resp.Cookies()) != 0 {
		t.Fatal("failed logout changed the cookie")
	}
	b.request(t, "GET", "/protected", nil, http.StatusOK)
}

func TestBrowserCookieRecovery(t *testing.T) {
	const customName = "__Host-demo"
	app := newBrowser(t, session.NewMemoryStore(), false, customName)
	other := newBrowser(t, session.NewMemoryStore(), false, "")
	// Browsers share host cookies across ports. These apps use separate stores.
	other.client.Jar = app.client.Jar
	other.login(t, http.StatusSeeOther)
	appURL, err := url.Parse(app.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	app.client.Jar.SetCookies(appURL, []*http.Cookie{{
		Name: customName, Value: "old-format", Path: "/", Secure: true,
	}})

	checkRecoveryForm := func(resp reply) {
		t.Helper()
		if !strings.Contains(resp.body, `<form method="post" action="/reset-cookie">`) || len(resp.Cookies()) != 0 {
			t.Fatal("invalid cookie should offer an explicit reset without changing cookies")
		}
	}
	checkRecoveryForm(app.login(t, http.StatusUnauthorized))
	checkRecoveryForm(app.request(t, "POST", "/logout", nil, http.StatusUnauthorized))
	reset := app.request(t, "POST", "/reset-cookie", nil, http.StatusSeeOther)
	if reset.Header.Get("Location") != "/" {
		t.Fatal("reset should redirect to the login page")
	}
	if cookies := app.client.Jar.Cookies(appURL); len(cookies) != 1 || cookies[0].Name != session.CookieName {
		t.Fatal("expected only the other app's cookie after reset")
	}
	other.request(t, "GET", "/protected", nil, http.StatusOK)
	app.request(t, "GET", "/", nil, http.StatusOK)
	app.request(t, "GET", "/protected", nil, http.StatusUnauthorized)
	app.login(t, http.StatusSeeOther)
	refused := app.request(t, "POST", "/reset-cookie", nil, http.StatusConflict)
	if !strings.Contains(refused.body, `action="/logout"`) || len(refused.Cookies()) != 0 {
		t.Fatal("a well-formed cookie should offer normal logout and remain intact")
	}
	app.request(t, "GET", "/protected", nil, http.StatusOK)
	app.request(t, "POST", "/logout", nil, http.StatusSeeOther)
	app.request(t, "GET", "/protected", nil, http.StatusUnauthorized)
	other.request(t, "GET", "/protected", nil, http.StatusOK)
}

func TestMutationRoutePolicy(t *testing.T) {
	b := newBrowser(t, session.NewMemoryStore(), false, "")
	for _, path := range []string{"/login", "/activity", "/logout", "/reset-cookie"} {
		t.Run(path, func(t *testing.T) {
			b.request(t, "GET", path, nil, http.StatusMethodNotAllowed)
			b.requestFrom(t, "POST", path, nil, "https://other.example", http.StatusForbidden)
		})
	}
}
