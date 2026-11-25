package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/i2bskn/authlume/webauthn"
)

func TestBrowserTransaction(t *testing.T) {
	code := base64.StdEncoding.EncodeToString(make([]byte, 32))
	store := new(demoStore)
	h, err := demo("demo password", code, store)
	if err != nil {
		t.Fatal(err)
	}
	post := func(path, from string, values url.Values, cookie *http.Cookie, want int) *http.Response {
		t.Helper()
		r := httptest.NewRequest("POST", origin+path, strings.NewReader(values.Encode()))
		r.Header.Set("Origin", from)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		res := w.Result()
		t.Cleanup(func() { res.Body.Close() })
		if res.StatusCode != want {
			t.Fatalf("%s: got %d want %d", path, res.StatusCode, want)
		}
		for _, c := range res.Cookies() {
			if c.Name == "__Host-authlume-webauthn" {
				t.Fatalf("%s issued a login session", path)
			}
		}
		return res
	}

	form := url.Values{"username": {"demo"}, "password": {"demo password"}}
	post("/register/begin", "https://other.example", form, nil, 403)
	post("/register/begin", origin, form, nil, 401)
	post("/login/begin", origin, form, nil, 401)
	form.Set("code", code)
	form.Set("password", "wrong")
	post("/register/begin", origin, form, nil, 401)
	form.Set("password", "demo password")
	res := post("/register/begin", origin, form, nil, 200)
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatal("expected a single transaction cookie")
	}
	c := cookies[0]
	if c.Name != flowCookie || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 300 {
		t.Fatal("invalid transaction cookie scope or lifetime")
	}
	post("/register/finish", origin, nil, nil, 401)
	post("/login/finish", origin, nil, c, 401) // consumes the registration transaction
	post("/register/finish", origin, nil, c, 401)
	key := webauthn.Credential{ID: []byte("existing"), PublicKey: []byte("existing public key")}
	if err := store.Insert(t.Context(), demoSubject, key); err != nil {
		t.Fatal(err)
	}
	if res = post("/register/begin", origin, form, nil, 401); len(res.Cookies()) != 0 {
		t.Fatal("issued another registration ceremony")
	}
	post("/register/begin", origin, form, nil, 429)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", origin+"/protected", nil))
	if w.Code != 401 {
		t.Errorf("protected returned %d", w.Code)
	}
}

func TestFirstEnrollmentAndConditionalUpdate(t *testing.T) {
	s := new(demoStore)
	key := webauthn.Credential{ID: []byte("first"), PublicKey: []byte("test key")}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- s.Insert(t.Context(), demoSubject, key) }()
	}
	a, b := <-results, <-results
	if (a == nil) == (b == nil) {
		t.Fatal("expected exactly one bootstrap enrollment")
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
