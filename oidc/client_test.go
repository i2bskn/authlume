package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestBeginAndConsume(t *testing.T) {
	store := NewMemoryStore()
	c := &Client{
		cookieName: "__Host-test", issuer: "https://id.example",
		oauth: oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize"}},
		store: store,
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "https://app.example/login", nil)
	if err := c.Begin(w, req); err != nil {
		t.Fatal(err)
	}
	resp := w.Result()
	cookies := resp.Cookies()
	if resp.StatusCode != http.StatusSeeOther || len(cookies) != 1 {
		t.Fatal("expected a redirect and one transaction cookie")
	}
	browser := cookies[0]
	if !browser.Secure || !browser.HttpOnly || browser.SameSite != http.SameSiteLaxMode ||
		browser.Path != "/" || browser.Domain != "" || browser.MaxAge != 600 || !validValue(browser.Value) {
		t.Fatal("invalid cookie attributes")
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	state := loc.Query().Get("state")
	tx := store.pending[c.key(state, browser.Value)]
	if !validValue(state) || !validValue(tx.Nonce) || !validValue(tx.Verifier) ||
		state == browser.Value || loc.Query().Get("nonce") != tx.Nonce ||
		loc.Query().Get("code_challenge_method") != "S256" ||
		loc.Query().Get("code_challenge") != oauth2.S256ChallengeFromVerifier(tx.Verifier) {
		t.Fatal("authorization request does not match saved transaction")
	}
	for _, tt := range []struct{ name, cookie, query string }{
		{"absent browser", "", "state=" + state},
		{"different browser", browser.Name + "=" + randomValue(), "state=" + state},
		{"different state", browser.Name + "=" + browser.Value, "state=" + randomValue()},
		{"two states", browser.Name + "=" + browser.Value, "state=" + state + "&state=" + state},
		{"two cookies", browser.Name + "=" + browser.Value + "; " + browser.Name + "=invalid", "state=" + state},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://app.example/callback?"+tt.query, nil)
			r.Header.Set("Cookie", tt.cookie)
			w := httptest.NewRecorder()
			if _, err := c.Complete(w, r); !errors.Is(err, ErrInvalid) || len(w.Result().Cookies()) != 0 {
				t.Fatal("unmatched callback altered the browser transaction")
			}
		})
	}
	r := httptest.NewRequest("GET", "https://app.example/callback?state="+state+"&error=access_denied", nil)
	r.AddCookie(browser)
	w = httptest.NewRecorder()
	if _, err := c.Complete(w, r); !errors.Is(err, ErrInvalid) || len(store.pending) != 0 {
		t.Fatal("matched cancellation must consume the transaction")
	}
	if cs := w.Result().Cookies(); len(cs) != 1 || cs[0].MaxAge >= 0 {
		t.Fatal("matched cancellation must clear the cookie")
	}
}

func TestMemoryStore(t *testing.T) {
	var key Key
	ctx := context.Background()
	s := NewMemoryStore()
	now := time.Now()
	if err := s.Create(ctx, key, Transaction{ExpiresAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(ctx, key, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("expiry at equality")
	}
	if err := s.Create(ctx, key, Transaction{ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, key, Transaction{}); err == nil {
		t.Fatal("duplicate create succeeded")
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := s.Take(ctx, key, now); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrInvalid) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("consumed %d times", successes.Load())
	}
}

func TestDiscoveryValidation(t *testing.T) {
	for _, tt := range []struct{ name, issuer, auth, token, jwks string }{
		{"mismatched issuer", "https://elsewhere.example", "", "", ""},
		{"plaintext authorization", "", "http://elsewhere.example/auth", "", ""},
		{"plaintext token", "", "", "http://elsewhere.example/token", ""},
		{"plaintext keys", "", "", "", "http://elsewhere.example/keys"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				u := "https://" + r.Host
				choose := func(v, fallback string) string {
					if v != "" {
						return v
					}
					return fallback
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"issuer":"` + choose(tt.issuer, u) + `","authorization_endpoint":"` + choose(tt.auth, u+"/auth") +
					`","token_endpoint":"` + choose(tt.token, u+"/token") + `","jwks_uri":"` + choose(tt.jwks, u+"/keys") + `"}`))
			}))
			defer idp.Close()
			cfg := Config{Issuer: idp.URL, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app.example/callback", Transport: idp.Client().Transport}
			if _, err := New(t.Context(), cfg, NewMemoryStore()); err == nil {
				t.Fatal("accepted invalid provider metadata")
			}
		})
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, raw := range []string{"http://app.example", "https://user@app.example/a", "https://app.example/a#fragment", "https://app.example/a?x=1", "https://:443/a"} {
		cfg := Config{Issuer: "https://issuer.example", ClientID: "app", ClientSecret: "secret", RedirectURL: raw}
		if _, err := New(t.Context(), cfg, NewMemoryStore()); err == nil || !strings.Contains(err.Error(), "configuration") {
			t.Errorf("redirect %q: got %v", raw, err)
		}
	}
}

func TestMalformedMatchedCallback(t *testing.T) {
	for _, extra := range []string{"code=a&code=b", "code=a&iss=https%3A%2F%2Fother.example", "code=a&iss=x&iss=y", "code=a&error=denied", "code="} {
		s := NewMemoryStore()
		c := &Client{store: s, cookieName: "__Host-test", issuer: "https://id.example"}
		state, browser := randomValue(), randomValue()
		if err := s.Create(t.Context(), c.key(state, browser), Transaction{ExpiresAt: time.Now().Add(time.Minute), Nonce: "n", Verifier: "v"}); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "https://app.example/callback?state="+url.QueryEscape(state)+"&"+extra, nil)
		r.AddCookie(c.cookie(browser, 600))
		if _, err := c.Complete(httptest.NewRecorder(), r); !errors.Is(err, ErrInvalid) || len(s.pending) != 0 {
			t.Fatalf("accepted or retained transaction for %s", extra)
		}
	}
}

func TestAuthorizationOptions(t *testing.T) {
	age := int64(0)
	store := NewMemoryStore()
	c := &Client{oauth: oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize"}}, store: store, cookieName: "__Host-test"}
	w := httptest.NewRecorder()
	o := AuthorizationOptions{MaxAgeSeconds: &age, ACRValues: []string{"urn:example:strong", "urn:example:other"}, Prompt: "login"}
	if err := c.BeginWithOptions(w, httptest.NewRequest("POST", "https://app.example/login", nil), o); err != nil {
		t.Fatal(err)
	}
	loc, err := w.Result().Location()
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("max_age") != "0" || q.Get("prompt") != "login" || q.Get("acr_values") != "urn:example:strong urn:example:other" {
		t.Fatal("requested options not present")
	}
	age = 120
	tx, err := store.Take(t.Context(), c.key(q.Get("state"), w.Result().Cookies()[0].Value), time.Now())
	if err != nil || tx.MaxAgeSeconds == nil || *tx.MaxAgeSeconds != 0 || tx.StartedAt.IsZero() {
		t.Fatal("freshness requirement was not snapshotted")
	}

	negative := int64(-1)
	for _, bad := range []AuthorizationOptions{{MaxAgeSeconds: &negative}, {Prompt: "unsupported"}, {ACRValues: []string{"two words"}}, {ACRValues: []string{""}}} {
		w = httptest.NewRecorder()
		if err := c.BeginWithOptions(w, httptest.NewRequest("POST", "https://app.example/login", nil), bad); err == nil || len(store.pending) != 0 || len(w.Result().Cookies()) != 0 {
			t.Fatal("invalid option started a login")
		}
	}
}

func TestRequestedFreshness(t *testing.T) {
	start := time.Unix(1000, 500000000)
	now := start.Add(10 * time.Second)
	zero, five := int64(0), int64(5)
	for _, tc := range []struct {
		name string
		max  *int64
		at   time.Time
		want bool
	}{
		{"unrequested", nil, time.Time{}, true},
		{"missing", &five, time.Time{}, false},
		{"zero before start", &zero, time.Unix(999, 0), false},
		{"zero at start second", &zero, time.Unix(1000, 0), true},
		{"zero after start", &zero, time.Unix(1002, 0), true},
		{"positive exact age", &five, time.Unix(1005, 0), true},
		{"stale", &five, time.Unix(1004, 0), false},
		{"future", &five, time.Unix(1011, 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := Transaction{StartedAt: start, MaxAgeSeconds: tc.max}
			if tx.acceptsAuthTime(tc.at, now) != tc.want {
				t.Fatal("unexpected freshness decision")
			}
		})
	}
}

func TestCanceledCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s := NewMemoryStore()
	c := &Client{store: s, cookieName: "__Host-test", http: http.DefaultClient, oauth: oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: "https://id.example/token", AuthStyle: oauth2.AuthStyleInHeader}}}
	state, browser := randomValue(), randomValue()
	if err := s.Create(t.Context(), c.key(state, browser), Transaction{ExpiresAt: time.Now().Add(time.Minute), Nonce: randomValue(), Verifier: randomValue()}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(ctx, "GET", "https://app.example/callback?state="+state+"&code=sample", nil)
	r.AddCookie(c.cookie(browser, 60))
	if _, err := c.Complete(httptest.NewRecorder(), r); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
