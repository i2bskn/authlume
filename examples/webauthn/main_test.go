package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/i2bskn/authlume/internal/webauthntest"
	"github.com/i2bskn/authlume/webauthn"
)

const sessionCookie = "__Host-authlume-webauthn"

type client struct {
	t    *testing.T
	h    http.Handler
	code string
}

func newClient(t *testing.T) (*client, *demoStore) {
	t.Helper()
	code := base64.StdEncoding.EncodeToString(make([]byte, 32))
	store := new(demoStore)
	h, err := demo("demo password", code, store)
	if err != nil {
		t.Fatal(err)
	}
	return &client{t, h, code}, store
}

// post sends a POST and checks the status. It fails if a session cookie
// appears unless session is true, in which case it returns that cookie.
func (c *client) post(path, from string, body io.Reader, contentType string, cookie *http.Cookie, want int, session bool) *http.Response {
	c.t.Helper()
	r := httptest.NewRequest("POST", origin+path, body)
	if from != "" {
		r.Header.Set("Origin", from)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	res := w.Result()
	c.t.Cleanup(func() { res.Body.Close() })
	if res.StatusCode != want {
		c.t.Fatalf("%s: got %d want %d", path, res.StatusCode, want)
	}
	issued := false
	for _, ck := range res.Cookies() {
		issued = issued || (ck.Name == sessionCookie && ck.MaxAge >= 0 && ck.Value != "")
	}
	if issued != session {
		c.t.Fatalf("%s: session issued %v, want %v", path, issued, session)
	}
	return res
}

func (c *client) form(path, from string, values url.Values, want int) *http.Response {
	c.t.Helper()
	return c.post(path, from, strings.NewReader(values.Encode()), "application/x-www-form-urlencoded", nil, want, false)
}

func (c *client) finish(path string, cookie *http.Cookie, response []byte, want int, session bool) *http.Response {
	c.t.Helper()
	return c.post(path, origin, bytes.NewReader(response), "application/json", cookie, want, session)
}

func cookie(t *testing.T, res *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("missing cookie %s", name)
	return nil
}

func challenge(t *testing.T, res *http.Response) string {
	t.Helper()
	if res.Header.Get("Content-Type") != "application/json" {
		t.Fatal("options are not JSON")
	}
	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.NewDecoder(res.Body).Decode(&options); err != nil || options.PublicKey.Challenge == "" {
		t.Fatal("options", err)
	}
	return options.PublicKey.Challenge
}

func (c *client) credentials(withCode bool) url.Values {
	values := url.Values{"username": {"demo"}, "password": {"demo password"}}
	if withCode {
		values.Set("code", c.code)
	}
	return values
}

func TestBrowserFlow(t *testing.T) {
	c, _ := newClient(t)
	key := webauthntest.New(t)
	res := c.form("/register/begin", origin, c.credentials(true), 200)
	flow := cookie(t, res, flowCookie)
	if len(res.Cookies()) != 1 || !flow.HttpOnly || !flow.Secure || flow.SameSite != http.SameSiteStrictMode || flow.Path != "/" || flow.Domain != "" || flow.MaxAge != 300 {
		t.Fatal("invalid transaction cookie scope or lifetime")
	}
	res = c.finish("/register/finish", flow, key.Registration(t, challenge(t, res), origin, "localhost", byte(protocol.FlagUserPresent)), 204, false)
	if cookie(t, res, flowCookie).MaxAge >= 0 {
		t.Fatal("transaction cookie not cleared")
	}
	if res = c.form("/register/begin", origin, c.credentials(true), 401); len(res.Cookies()) != 0 {
		t.Fatal("issued another registration ceremony")
	}
	res = c.form("/login/begin", origin, c.credentials(false), 200)
	assertion := webauthntest.Assertion{
		Client: protocol.CollectedClientData{Type: protocol.AssertCeremony, Origin: origin, Challenge: challenge(t, res)},
		RPID:   "localhost", UserHandle: demoSubject, Flags: byte(protocol.FlagUserPresent), Count: 1,
	}
	res = c.finish("/login/finish", cookie(t, res, flowCookie), key.Sign(t, assertion), 204, true)
	r := httptest.NewRequest("GET", origin+"/protected", nil)
	r.AddCookie(cookie(t, res, sessionCookie))
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("protected returned %d", w.Code)
	}
}

func TestBrowserRejection(t *testing.T) {
	c, _ := newClient(t)
	c.form("/register/begin", "https://other.example", c.credentials(true), 403)
	c.form("/register/begin", "", c.credentials(true), 403)
	c.form("/register/begin", origin, c.credentials(false), 401)
	c.form("/login/begin", origin, c.credentials(false), 401) // no registered key
	wrong := c.credentials(true)
	wrong.Set("password", "wrong")
	c.form("/register/begin", origin, wrong, 401)
	res := c.form("/register/begin", origin, c.credentials(true), 200)
	flow := cookie(t, res, flowCookie)
	response := webauthntest.New(t).Registration(t, challenge(t, res), origin, "localhost", byte(protocol.FlagUserPresent))
	c.post("/register/finish", "https://other.example", bytes.NewReader(response), "application/json", flow, 403, false)
	c.finish("/register/finish", nil, response, 401, false)
	c.finish("/login/finish", flow, response, 401, false) // consumes the registration ceremony
	c.finish("/register/finish", flow, response, 401, false)
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, httptest.NewRequest("GET", origin+"/protected", nil))
	if w.Code != 401 {
		t.Errorf("protected returned %d", w.Code)
	}
}

func TestRateLimit(t *testing.T) {
	c, _ := newClient(t)
	wrong := c.credentials(true)
	wrong.Set("password", "wrong")
	for range 5 {
		c.form("/register/begin", origin, wrong, 401)
	}
	c.form("/login/begin", origin, c.credentials(false), 429)
}

func TestFirstEnrollmentAndConditionalUpdate(t *testing.T) {
	s := new(demoStore)
	if rows, err := s.Load(t.Context(), "unknown"); err != nil || rows != nil {
		t.Fatal("unknown subject", rows, err)
	}
	key := webauthn.Credential{ID: []byte("first"), PublicKey: []byte("test key")}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- s.Insert(t.Context(), demoSubject, key) }()
	}
	a, b := <-results, <-results
	if (a == nil) == (b == nil) {
		t.Fatal("expected exactly one bootstrap enrollment")
	}
	if !s.enrolled() {
		t.Fatal("enrollment not recorded")
	}
	rows, err := s.Load(t.Context(), demoSubject)
	if err != nil || len(rows) != 1 {
		t.Fatal("load", err)
	}
	old := rows[0]
	old.Credential.ID[0] = 'X'
	if err := s.Update(t.Context(), demoSubject, old.Version, old.Credential); err == nil {
		t.Fatal("changed credential ID accepted")
	}
	if err := s.Update(t.Context(), "other", old.Version, key); err == nil {
		t.Fatal("changed subject accepted")
	}
	if err := s.Update(t.Context(), demoSubject, rand.Text(), key); err == nil {
		t.Fatal("stale revision accepted")
	}
	if err := s.Update(t.Context(), demoSubject, old.Version, key); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(t.Context(), demoSubject, old.Version, key); err == nil {
		t.Fatal("revision reused")
	}
}
