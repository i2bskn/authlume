package oidc

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// loginWithAppData runs BeginWithOptions and CompleteWithAppData. issue
// receives the nonce of the authorization request and returns the ID token
// the issuer answers with.
func (idp *testIssuer) loginWithAppData(t *testing.T, c *Client, options AuthorizationOptions, issue func(nonce string) string) (Identity, []byte, error) {
	t.Helper()
	w := httptest.NewRecorder()
	if err := c.BeginWithOptions(w, httptest.NewRequest("POST", "https://app.example/login", nil), options); err != nil {
		t.Fatal(err)
	}
	loc, err := w.Result().Location()
	if err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("authorization request is incomplete")
	}
	idp.mu.Lock()
	idp.idToken = issue(loc.Query().Get("nonce"))
	idp.mu.Unlock()
	r := httptest.NewRequest("GET", "https://app.example/callback?code=sample&state="+url.QueryEscape(loc.Query().Get("state")), nil)
	r.AddCookie(cookies[0])
	return c.CompleteWithAppData(httptest.NewRecorder(), r)
}

func TestAppDataRoundTrip(t *testing.T) {
	idp := newTestIssuer(t)
	c := idp.client(t)
	valid := func(n string) string { return signToken(t, jose.RS256, idp.keys.rsa, "rsa", idp.payload(t, n, nil)) }
	for _, data := range [][]byte{
		[]byte("/oauth/authorize?client_id=x&state=y"),
		bytes.Repeat([]byte{0, 0xff}, MaxAppData/2),
		{},
		nil,
	} {
		sent := bytes.Clone(data)
		identity, got, err := idp.loginWithAppData(t, c, AuthorizationOptions{AppData: sent}, valid)
		if err != nil || identity.ID.Subject != "subject" {
			t.Fatalf("login with %d bytes of app data: %v", len(data), err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("got %d bytes of app data, want %d", len(got), len(data))
		}
	}
}

func TestAppDataIsSnapshotted(t *testing.T) {
	idp := newTestIssuer(t)
	c := idp.client(t)
	data := []byte("/settings")
	w := httptest.NewRecorder()
	if err := c.BeginWithOptions(w, httptest.NewRequest("POST", "https://app.example/login", nil), AuthorizationOptions{AppData: data}); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	loc, _ := w.Result().Location()
	tx, err := c.store.Take(t.Context(), c.key(loc.Query().Get("state"), w.Result().Cookies()[0].Value), time.Now())
	if err != nil || string(tx.AppData) != "/settings" {
		t.Fatalf("stored app data changed with the caller's slice: %q, %v", tx.AppData, err)
	}
}

func TestAppDataTooLarge(t *testing.T) {
	store := NewMemoryStore()
	c := &Client{store: store, cookieName: "__Host-test"}
	w := httptest.NewRecorder()
	err := c.BeginWithOptions(w, httptest.NewRequest("POST", "https://app.example/login", nil),
		AuthorizationOptions{AppData: make([]byte, MaxAppData+1)})
	if err == nil || len(store.pending) != 0 || len(w.Result().Cookies()) != 0 || w.Result().Header.Get("Location") != "" {
		t.Fatal("oversized app data started a login")
	}
}

func TestFailedLoginHasNoAppData(t *testing.T) {
	idp := newTestIssuer(t)
	c := idp.client(t)
	mismatch := func(string) string {
		return signToken(t, jose.RS256, idp.keys.rsa, "rsa", idp.payload(t, randomValue(), nil))
	}
	identity, data, err := idp.loginWithAppData(t, c, AuthorizationOptions{AppData: []byte("/settings")}, mismatch)
	if !errors.Is(err, ErrInvalid) || data != nil || identity.Claims != nil {
		t.Fatalf("failed login returned app data %q, %v", data, err)
	}

	// A callback without a pending transaction returns nothing either.
	r := httptest.NewRequest("GET", "https://app.example/callback?code=sample&state=unknown", nil)
	r.AddCookie(c.cookie(randomValue(), 600))
	if _, data, err := c.CompleteWithAppData(httptest.NewRecorder(), r); !errors.Is(err, ErrInvalid) || data != nil {
		t.Fatalf("unmatched callback returned app data %q, %v", data, err)
	}
}

func TestMemoryStoreCopiesAppData(t *testing.T) {
	var key Key
	s := NewMemoryStore()
	data := []byte("/settings")
	if err := s.Create(t.Context(), key, Transaction{ExpiresAt: time.Now().Add(time.Minute), AppData: data}); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	tx, err := s.Take(t.Context(), key, time.Now())
	if err != nil || string(tx.AppData) != "/settings" {
		t.Fatalf("memory store shared the caller's slice: %q, %v", tx.AppData, err)
	}
}
