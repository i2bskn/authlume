package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	provider "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
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

type signingKeys struct {
	rsa     *rsa.PrivateKey
	ec      *ecdsa.PrivateKey
	ed      ed25519.PrivateKey
	foreign *ecdsa.PrivateKey // P-256, never published
	p384    *ecdsa.PrivateKey // never published
}

func newSigningKeys(t *testing.T) signingKeys {
	t.Helper()
	var k signingKeys
	var err error
	if k.rsa, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if k.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if _, k.ed, err = ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if k.foreign, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if k.p384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	return k
}

func idTokenClaims(t *testing.T, issuer, audience string) []byte {
	t.Helper()
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "aud": audience, "sub": "subject",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func signToken(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, payload []byte) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// handBuiltToken assembles a compact JWS around the given signature bytes.
func handBuiltToken(t *testing.T, alg, kid string, payload, signature []byte) string {
	t.Helper()
	fields := map[string]string{"alg": alg}
	if kid != "" {
		fields["kid"] = kid
	}
	header, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString(signature)
}

func hmacToken(t *testing.T, kid string, payload, secret []byte) string {
	t.Helper()
	unsigned := handBuiltToken(t, "HS256", kid, payload, nil)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strings.TrimSuffix(unsigned, ".")))
	return unsigned + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func tokenSignature(t *testing.T, raw string) []byte {
	t.Helper()
	sig, err := base64.RawURLEncoding.DecodeString(raw[strings.LastIndex(raw, ".")+1:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestSigningAlgs(t *testing.T) {
	const issuer, clientID, secret = "https://id.example", "client", "secret"
	k := newSigningKeys(t)
	payload := idTokenClaims(t, issuer, clientID)
	pkix, err := x509.MarshalPKIXPublicKey(&k.rsa.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rs256 := signToken(t, jose.RS256, k.rsa, "", payload)
	es256 := signToken(t, jose.ES256, k.ec, "", payload)
	tokens := map[string]string{
		"RS256":                   rs256,
		"PS256":                   signToken(t, jose.PS256, k.rsa, "", payload),
		"ES256":                   es256,
		"EdDSA":                   signToken(t, jose.EdDSA, k.ed, "", payload),
		"RS384":                   signToken(t, jose.RS384, k.rsa, "", payload),
		"PS384":                   signToken(t, jose.PS384, k.rsa, "", payload),
		"ES384":                   signToken(t, jose.ES384, k.p384, "", payload),
		"ES256 unpublished key":   signToken(t, jose.ES256, k.foreign, "", payload),
		"none":                    handBuiltToken(t, "none", "", payload, nil),
		"HS256 client secret":     hmacToken(t, "", payload, []byte(secret)),
		"HS256 RSA public key":    hmacToken(t, "", payload, pkix),
		"ES256 header, RSA bytes": handBuiltToken(t, "ES256", "", payload, tokenSignature(t, rs256)),
		"RS256 header, EC bytes":  handBuiltToken(t, "RS256", "", payload, tokenSignature(t, es256)),
	}
	// Every published key is always present, so a listed algorithm is the
	// only thing standing between a well-signed token and acceptance.
	keys := &provider.StaticKeySet{PublicKeys: []crypto.PublicKey{&k.rsa.PublicKey, &k.ec.PublicKey, k.ed.Public()}}
	all := []string{"RS256", "PS256", "ES256", "EdDSA"}
	for _, tt := range []struct {
		name     string
		algs     []string
		accepted []string
		rejected []string
	}{
		{"unset", nil, []string{"RS256"}, []string{"PS256", "ES256", "EdDSA", "none", "HS256 client secret", "HS256 RSA public key"}},
		{"empty", []string{}, []string{"RS256"}, []string{"PS256", "ES256", "EdDSA"}},
		{"RS256", []string{"RS256"}, []string{"RS256"}, []string{"PS256", "ES256", "EdDSA"}},
		{"PS256", []string{"PS256"}, []string{"PS256"}, []string{"RS256", "ES256", "EdDSA"}},
		{"ES256", []string{"ES256"}, []string{"ES256"}, []string{"RS256", "PS256", "EdDSA", "ES256 unpublished key"}},
		{"EdDSA", []string{"EdDSA"}, []string{"EdDSA"}, []string{"RS256", "PS256", "ES256"}},
		{"ES256 and EdDSA", []string{"ES256", "EdDSA"}, []string{"ES256", "EdDSA"}, []string{"RS256", "PS256"}},
		{"RS256 and PS256", []string{"RS256", "PS256"}, []string{"RS256", "PS256"}, []string{"ES256", "EdDSA"}},
		{"RS256 and ES256", []string{"RS256", "ES256"}, []string{"RS256", "ES256"},
			[]string{"PS256", "EdDSA", "ES256 header, RSA bytes", "RS256 header, EC bytes"}},
		{"all four", all, all, []string{"RS384", "PS384", "ES384", "ES256 unpublished key", "none",
			"HS256 client secret", "HS256 RSA public key", "ES256 header, RSA bytes", "RS256 header, EC bytes"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{issuer: issuer, keys: keys, algs: tt.algs,
				oauth: oauth2.Config{ClientID: clientID, ClientSecret: secret}}
			for _, name := range tt.accepted {
				if _, err := c.verifyToken(t.Context(), tokens[name]); err != nil {
					t.Errorf("%s: got %v", name, err)
				}
			}
			for _, name := range tt.rejected {
				if _, err := c.verifyToken(t.Context(), tokens[name]); !errors.Is(err, ErrInvalid) {
					t.Errorf("%s: got %v, want ErrInvalid", name, err)
				}
			}
		})
	}
}

func TestSigningAlgsFromConfiguration(t *testing.T) {
	const clientID, secret = "client", "secret"
	k := newSigningKeys(t)
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/keys" {
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: &k.rsa.PublicKey, KeyID: "rsa", Use: "sig"},
				{Key: &k.ec.PublicKey, KeyID: "ec", Use: "sig"},
				{Key: k.ed.Public(), KeyID: "ed", Use: "sig"},
			}})
			return
		}
		w.Write([]byte(`{"issuer":"` + u + `","authorization_endpoint":"` + u + `/auth","token_endpoint":"` + u +
			`/token","jwks_uri":"` + u + `/keys"}`))
	}))
	defer idp.Close()
	payload := idTokenClaims(t, idp.URL, clientID)
	tokens := map[string]string{
		"RS256": signToken(t, jose.RS256, k.rsa, "rsa", payload),
		"PS256": signToken(t, jose.PS256, k.rsa, "rsa", payload),
		"ES256": signToken(t, jose.ES256, k.ec, "ec", payload),
		"EdDSA": signToken(t, jose.EdDSA, k.ed, "ed", payload),
		"none":  handBuiltToken(t, "none", "rsa", payload, nil),
		"HS256": hmacToken(t, "rsa", payload, []byte(secret)),
	}
	for _, tt := range []struct {
		name     string
		algs     []SigningAlg
		accepted []string
		rejected []string
	}{
		{"unset", nil, []string{"RS256"}, []string{"PS256", "ES256", "EdDSA"}},
		{"without RS256", []SigningAlg{PS256, ES256, EdDSA}, []string{"PS256", "ES256", "EdDSA"}, []string{"RS256"}},
		{"all four", []SigningAlg{RS256, PS256, ES256, EdDSA}, []string{"RS256", "PS256", "ES256", "EdDSA"}, []string{"none", "HS256"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Issuer: idp.URL, ClientID: clientID, ClientSecret: secret, RedirectURL: "https://app.example/callback",
				Transport: idp.Client().Transport, SigningAlgs: tt.algs}
			c, err := New(t.Context(), cfg, NewMemoryStore())
			if err != nil {
				t.Fatal(err)
			}
			check := func() {
				t.Helper()
				for _, name := range tt.accepted {
					if _, err := c.verifyToken(t.Context(), tokens[name]); err != nil {
						t.Errorf("%s: got %v", name, err)
					}
				}
				for _, name := range tt.rejected {
					if _, err := c.verifyToken(t.Context(), tokens[name]); !errors.Is(err, ErrInvalid) {
						t.Errorf("%s: got %v, want ErrInvalid", name, err)
					}
				}
			}
			check()
			if len(cfg.SigningAlgs) > 0 {
				// The caller's slice is not the client's configuration.
				cfg.SigningAlgs[0] = SigningAlg(tt.rejected[0])
				check()
			}
		})
	}
}

type countingTransport struct{ calls atomic.Int32 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return nil, errors.New("unexpected provider request")
}

func TestInvalidSigningAlgs(t *testing.T) {
	for _, algs := range [][]SigningAlg{
		{""}, {"none"}, {"HS256"}, {"RS384"}, {"rs256"},
		{"none", RS256}, {RS256, "none"}, {ES256, ES256}, {RS256, PS256, RS256},
	} {
		var transport countingTransport
		cfg := Config{Issuer: "https://issuer.example", ClientID: "app", ClientSecret: "secret",
			RedirectURL: "https://app.example/callback", Transport: &transport, SigningAlgs: algs}
		if _, err := New(t.Context(), cfg, NewMemoryStore()); err == nil || !strings.Contains(err.Error(), "configuration") {
			t.Errorf("algorithms %q: got %v", algs, err)
		}
		if transport.calls.Load() != 0 {
			t.Errorf("algorithms %q: contacted the provider", algs)
		}
	}
}
