package main

import (
	"encoding/base32"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

const demoPassword = "example-password"

func app(t *testing.T, require bool) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var clock atomic.Int64
	encoded := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	h, err := demo(demoPassword, encoded, require, func() time.Time { return time.Unix(clock.Load(), 0) })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	return server, &clock
}

func browser(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: server.Client().Transport, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func credentials(code string) url.Values {
	return url.Values{"username": {"demo"}, "password": {demoPassword}, "code": {code}}
}

func login(t *testing.T, client *http.Client, server *httptest.Server, input url.Values, want int) {
	t.Helper()
	response, err := client.PostForm(server.URL+"/login", input)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("login status %d, want %d", response.StatusCode, want)
	}
	if want != http.StatusSeeOther && len(response.Cookies()) != 0 {
		t.Fatal("cookie on failed login")
	}
}

func protected(t *testing.T, client *http.Client, server *httptest.Server, want int) {
	t.Helper()
	response, err := client.Get(server.URL + "/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("protected status %d, want %d", response.StatusCode, want)
	}
}

func TestHTTPSLogin(t *testing.T) {
	server, clock := app(t, true)
	client := browser(t, server)
	// Use a future RFC vector so the real browser jar retains the test cookie.
	clock.Store(20000000000)
	login(t, client, server, credentials(""), http.StatusUnauthorized)
	protected(t, client, server, http.StatusUnauthorized)
	input := credentials("353130")
	input.Set("password", "incorrect")
	login(t, client, server, input, http.StatusUnauthorized)
	login(t, client, server, credentials("353130"), http.StatusSeeOther)
	protected(t, client, server, http.StatusOK)
	other := browser(t, server)
	login(t, other, server, credentials("353130"), http.StatusUnauthorized)
	protected(t, other, server, http.StatusUnauthorized)
}

func TestPasswordOnly(t *testing.T) {
	server, clock := app(t, false)
	clock.Store(20000000000)
	client := browser(t, server)
	login(t, client, server, credentials(""), http.StatusSeeOther)
	protected(t, client, server, http.StatusOK)
}

func TestConcurrentLogins(t *testing.T) {
	server, clock := app(t, true)
	clock.Store(20000000000)
	status := make(chan int, 2)
	start := make(chan struct{})
	for range 2 {
		client := browser(t, server)
		go func() {
			<-start
			resp, err := client.PostForm(server.URL+"/login", credentials("353130"))
			if err != nil {
				t.Error(err)
				status <- 0
				return
			}
			resp.Body.Close()
			status <- resp.StatusCode
		}()
	}
	close(start)
	a, b := <-status, <-status
	if !(a == 303 && b == 401 || a == 401 && b == 303) {
		t.Errorf("statuses %d, %d", a, b)
	}
}

func TestStartupAndAttemptBudget(t *testing.T) {
	server, clock := app(t, true)
	client := browser(t, server)
	for range 5 {
		// The RFC 4226 counter-zero code is valid for the startup period.
		login(t, client, server, credentials("755224"), http.StatusUnauthorized)
	}
	clock.Store(59)
	login(t, client, server, credentials("287082"), http.StatusTooManyRequests)
	clock.Store(60)
	login(t, client, server, credentials("287082"), http.StatusSeeOther)
}
