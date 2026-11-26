package oidc

import (
	"bytes"
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
	"fmt"
	"log/slog"
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

func TestClaimsAccessors(t *testing.T) {
	claims := Claims{
		"null":           json.RawMessage(`null`),
		"padded null":    json.RawMessage(" null\n"),
		"text":           json.RawMessage(`"user@example.com"`),
		"padded text":    json.RawMessage(` "padded" `),
		"untrimmed":      json.RawMessage(`" Mixed Caseé "`),
		"empty text":     json.RawMessage(`""`),
		"true":           json.RawMessage(`true`),
		"false":          json.RawMessage(`false`),
		"padded true":    json.RawMessage("\ttrue "),
		"quoted true":    json.RawMessage(`"true"`),
		"one":            json.RawMessage(`1`),
		"object":         json.RawMessage(`{"a":true}`),
		"array":          json.RawMessage(`["a"]`),
		"empty raw":      json.RawMessage(``),
		"malformed":      json.RawMessage(`tru`),
		"Email_Verified": json.RawMessage(`true`),
		"Email":          json.RawMessage(`"user@example.com"`),
	}
	for _, tt := range []struct {
		name            string
		text            string
		isText          bool
		value, isBool   bool
		fromNilClaimSet bool
	}{
		{name: "absent"},
		{name: "null"},
		{name: "padded null"},
		{name: "text", text: "user@example.com", isText: true},
		{name: "padded text", text: "padded", isText: true},
		{name: "untrimmed", text: " Mixed Caseé ", isText: true},
		{name: "empty text", isText: true},
		{name: "true", value: true, isBool: true},
		{name: "false", isBool: true},
		{name: "padded true", value: true, isBool: true},
		{name: "quoted true", text: "true", isText: true},
		{name: "one"},
		{name: "object"},
		{name: "array"},
		{name: "empty raw"},
		{name: "malformed"},
		{name: "email_verified"},
		{name: "email"},
		{name: "Email_Verified", value: true, isBool: true},
		{name: "text", fromNilClaimSet: true},
		{name: "true", fromNilClaimSet: true},
	} {
		c := claims
		if tt.fromNilClaimSet {
			c = nil
		}
		if text, ok := c.Text(tt.name); text != tt.text || ok != tt.isText {
			t.Errorf("Text(%q) nil=%v: got %q, %v", tt.name, tt.fromNilClaimSet, text, ok)
		}
		if value, ok := c.Bool(tt.name); value != tt.value || ok != tt.isBool {
			t.Errorf("Bool(%q) nil=%v: got %v, %v", tt.name, tt.fromNilClaimSet, value, ok)
		}
	}
}

func TestClaimsAreNotLogged(t *testing.T) {
	const address = "user@example.com"
	identity := Identity{
		ID:     ExternalID{Issuer: "https://id.example", Subject: "subject"},
		Claims: Claims{"email": json.RawMessage(`"` + address + `"`), "sub": json.RawMessage(`"subject"`)},
	}
	const want = "oidc.Claims(2 claims)"
	for _, verb := range []string{"%v", "%+v", "%s", "%#v"} {
		for _, value := range []any{identity, &identity, identity.Claims} {
			if out := fmt.Sprintf(verb, value); strings.Contains(out, address) || !strings.Contains(out, want) {
				t.Errorf("%s of %T: got %s", verb, value, out)
			}
		}
	}
	var out bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&out, nil))
	logger.Info("login", "identity", identity, "pointer", &identity, "claims", identity.Claims)
	logger.Info("login", slog.Any("claims", identity.Claims), slog.Group("group", slog.Any("identity", identity)))
	if strings.Contains(out.String(), address) || strings.Count(out.String(), want) != 5 {
		t.Errorf("slog: got %s", out.String())
	}
	if got := (Claims)(nil).String(); got != "oidc.Claims(0 claims)" {
		t.Errorf("nil claims: got %s", got)
	}
}

// testIssuer serves discovery, keys and a token endpoint. The token endpoint
// answers with whatever ID token the test last stored.
type testIssuer struct {
	*httptest.Server
	keys    signingKeys
	mu      sync.Mutex
	idToken string
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	idp := &testIssuer{keys: newSigningKeys(t)}
	idp.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: &idp.keys.rsa.PublicKey, KeyID: "rsa", Use: "sig"},
				{Key: &idp.keys.ec.PublicKey, KeyID: "ec", Use: "sig"},
			}})
		case "/token":
			idp.mu.Lock()
			token := idp.idToken
			idp.mu.Unlock()
			if user, pass, ok := r.BasicAuth(); r.Method != http.MethodPost || !ok || user != "client" || pass != "secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			json.NewEncoder(w).Encode(map[string]string{"access_token": "fixture", "token_type": "Bearer", "id_token": token})
		default:
			w.Write([]byte(`{"issuer":"` + u + `","authorization_endpoint":"` + u + `/auth","token_endpoint":"` + u +
				`/token","jwks_uri":"` + u + `/keys"}`))
		}
	}))
	t.Cleanup(idp.Close)
	return idp
}

func (idp *testIssuer) client(t *testing.T, scopes ...string) *Client {
	t.Helper()
	c, err := New(t.Context(), idp.config(scopes...), NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (idp *testIssuer) config(scopes ...string) Config {
	return Config{Issuer: idp.URL, ClientID: "client", ClientSecret: "secret",
		RedirectURL: "https://app.example/callback", Transport: idp.Client().Transport, Scopes: scopes}
}

// payload returns ID token claims that pass every check, plus extra.
func (idp *testIssuer) payload(t *testing.T, nonce string, extra map[string]any) []byte {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": idp.URL, "aud": "client", "sub": "subject", "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	for name, value := range extra {
		claims[name] = value
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// login runs Begin and Complete. issue receives the nonce of the
// authorization request and returns the ID token the issuer answers with.
func (idp *testIssuer) login(t *testing.T, c *Client, options AuthorizationOptions, issue func(nonce string) string) (Identity, error) {
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
	if len(cookies) != 1 || loc.Query().Get("nonce") == "" || loc.Query().Get("state") == "" {
		t.Fatal("authorization request is incomplete")
	}
	token := issue(loc.Query().Get("nonce"))
	idp.mu.Lock()
	idp.idToken = token
	idp.mu.Unlock()
	r := httptest.NewRequest("GET", "https://app.example/callback?code=sample&state="+url.QueryEscape(loc.Query().Get("state")), nil)
	r.AddCookie(cookies[0])
	return c.Complete(httptest.NewRecorder(), r)
}

func requestedScope(t *testing.T, c *Client) string {
	t.Helper()
	w := httptest.NewRecorder()
	if err := c.Begin(w, httptest.NewRequest("POST", "https://app.example/login", nil)); err != nil {
		t.Fatal(err)
	}
	loc, err := w.Result().Location()
	if err != nil {
		t.Fatal(err)
	}
	if len(loc.Query()["scope"]) != 1 {
		t.Fatalf("scope parameters: got %q", loc.Query()["scope"])
	}
	return loc.Query().Get("scope")
}

func TestInvalidScopes(t *testing.T) {
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("scope%d", i)
	}
	for _, scopes := range [][]string{
		{""}, {" "}, {"two words"}, {"tab\t"}, {"line\n"}, {"delete\x7f"}, {"nul\x00"}, {`quo"te`}, {`back\slash`},
		{"café"}, {"high\xff"}, {"openid"}, {"offline_access"}, {"email", "openid"}, {"email", "offline_access"},
		{"email", "email"}, {"email", "profile", "email"}, {"email", ""}, {strings.Repeat("a", 256)}, many,
	} {
		var transport countingTransport
		cfg := Config{Issuer: "https://issuer.example", ClientID: "app", ClientSecret: "secret",
			RedirectURL: "https://app.example/callback", Transport: &transport, Scopes: scopes}
		if _, err := New(t.Context(), cfg, NewMemoryStore()); err == nil || !strings.Contains(err.Error(), "configuration") {
			t.Errorf("scopes %q: got %v", scopes, err)
		}
		if transport.calls.Load() != 0 {
			t.Errorf("scopes %q: contacted the provider", scopes)
		}
	}
}

func TestScopes(t *testing.T) {
	idp := newTestIssuer(t)
	many := make([]string, 32)
	for i := range many {
		many[i] = fmt.Sprintf("scope%d", i)
	}
	longest := strings.Repeat("a", 255)
	for _, tt := range []struct {
		name   string
		scopes []string
		want   string
	}{
		{"unset", nil, "openid"},
		{"empty", []string{}, "openid"},
		{"one", []string{"email"}, "openid email"},
		{"in the given order", []string{"profile", "email"}, "openid profile email"},
		{"scope URL", []string{"email", "profile", "https://example.com/scope"}, "openid email profile https://example.com/scope"},
		{"other case", []string{"OpenID", "Offline_Access"}, "openid OpenID Offline_Access"},
		{"every other printable byte", []string{"!#$%&'()*+,-./:;<=>?@[]^_`{|}~"}, "openid !#$%&'()*+,-./:;<=>?@[]^_`{|}~"},
		{"longest", []string{longest}, "openid " + longest},
		{"most", many, "openid " + strings.Join(many, " ")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idp.config(tt.scopes...)
			c, err := New(t.Context(), cfg, NewMemoryStore())
			if err != nil {
				t.Fatal(err)
			}
			if got := requestedScope(t, c); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			if len(cfg.Scopes) > 0 {
				// The caller's slice is not the client's configuration.
				cfg.Scopes[0] = "changed"
				if got := requestedScope(t, c); got != tt.want {
					t.Fatalf("after the caller's change: got %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestIdentityClaims(t *testing.T) {
	idp := newTestIssuer(t)
	authTime := time.Now().Add(-30 * time.Second).Unix()
	for _, scopes := range [][]string{nil, {"email", "profile"}} {
		c := idp.client(t, scopes...)
		var nonce string
		identity, err := idp.login(t, c, AuthorizationOptions{}, func(n string) string {
			nonce = n
			return signToken(t, jose.RS256, idp.keys.rsa, "rsa", idp.payload(t, n, map[string]any{
				"email": "User@Example.com", "email_verified": true, "hd": "example.com",
				"https://example.com/tenant": "tenant-1", "at_hash": "fixture",
				"acr": "urn:example:strong", "amr": []string{"pwd", "otp"}, "auth_time": authTime,
			}))
		})
		if err != nil {
			t.Fatalf("scopes %q: %v", scopes, err)
		}
		if identity.ID != (ExternalID{Issuer: idp.URL, Subject: "subject"}) {
			t.Errorf("scopes %q: got identifier %+v", scopes, identity.ID)
		}
		a := identity.Assurance
		if a.ACR != "urn:example:strong" || len(a.AMR) != 2 || a.AMR[0] != "pwd" || a.AMR[1] != "otp" || !a.AuthTime.Equal(time.Unix(authTime, 0)) {
			t.Errorf("scopes %q: got assurance %+v", scopes, a)
		}
		for name, want := range map[string]string{
			"email": "User@Example.com", "hd": "example.com", "https://example.com/tenant": "tenant-1",
			"iss": idp.URL, "sub": "subject", "nonce": nonce, "at_hash": "fixture", "aud": "client",
		} {
			if got, ok := identity.Claims.Text(name); !ok || got != want {
				t.Errorf("scopes %q: Text(%q): got %q, %v", scopes, name, got, ok)
			}
		}
		if verified, ok := identity.Claims.Bool("email_verified"); !ok || !verified {
			t.Errorf("scopes %q: Bool(email_verified): got %v, %v", scopes, verified, ok)
		}
		if _, ok := identity.Claims.Text("Email"); ok || len(identity.Claims) != 14 {
			t.Errorf("scopes %q: unexpected claims %q", scopes, identity.Claims)
		}
	}
}

func TestIdentityClaimTypes(t *testing.T) {
	idp := newTestIssuer(t)
	c := idp.client(t, "email")
	duplicate := func(first, second string) func(string) string {
		return func(nonce string) string {
			now := time.Now().Unix()
			payload := fmt.Sprintf(`{"iss":%q,"aud":"client","sub":"subject","nonce":%q,"iat":%d,"exp":%d,"email_verified":%s,"email_verified":%s}`,
				idp.URL, nonce, now, now+3600, first, second)
			return signToken(t, jose.RS256, idp.keys.rsa, "rsa", []byte(payload))
		}
	}
	with := func(extra map[string]any) func(string) string {
		return func(nonce string) string {
			return signToken(t, jose.RS256, idp.keys.rsa, "rsa", idp.payload(t, nonce, extra))
		}
	}
	for _, tt := range []struct {
		name          string
		issue         func(string) string
		present       bool
		value, isBool bool
	}{
		{"string true", with(map[string]any{"email_verified": "true"}), true, false, false},
		{"number", with(map[string]any{"email_verified": 1}), true, false, false},
		{"null", with(map[string]any{"email_verified": nil}), true, false, false},
		{"absent", with(nil), false, false, false},
		{"false", with(map[string]any{"email_verified": false}), true, false, true},
		{"false then true", duplicate("false", "true"), true, true, true},
		{"true then false", duplicate("true", "false"), true, false, true},
		{"true then string", duplicate("true", `"true"`), true, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := idp.login(t, c, AuthorizationOptions{}, tt.issue)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := identity.Claims["email_verified"]; present != tt.present {
				t.Errorf("presence: got %v", present)
			}
			if value, ok := identity.Claims.Bool("email_verified"); value != tt.value || ok != tt.isBool {
				t.Errorf("got %v, %v", value, ok)
			}
			if identity.ID.Subject != "subject" {
				t.Errorf("got identifier %+v", identity.ID)
			}
		})
	}
}

func TestFailedLoginHasNoClaims(t *testing.T) {
	idp := newTestIssuer(t)
	c := idp.client(t, "email")
	five := int64(5)
	personal := map[string]any{"email": "user@example.com", "email_verified": true, "acr": "urn:example:strong"}
	with := func(alg jose.SignatureAlgorithm, key any, kid string, extra map[string]any, fixedNonce string) func(string) string {
		return func(nonce string) string {
			if fixedNonce != "" {
				nonce = fixedNonce
			}
			claims := map[string]any{}
			for name, value := range personal {
				claims[name] = value
			}
			for name, value := range extra {
				claims[name] = value
			}
			return signToken(t, alg, key, kid, idp.payload(t, nonce, claims))
		}
	}
	for _, tt := range []struct {
		name    string
		options AuthorizationOptions
		issue   func(string) string
	}{
		{"nonce mismatch", AuthorizationOptions{}, with(jose.RS256, idp.keys.rsa, "rsa", nil, randomValue())},
		{"stale auth_time", AuthorizationOptions{MaxAgeSeconds: &five},
			with(jose.RS256, idp.keys.rsa, "rsa", map[string]any{"auth_time": time.Now().Add(-time.Hour).Unix()}, "")},
		{"amr of the wrong type", AuthorizationOptions{}, with(jose.RS256, idp.keys.rsa, "rsa", map[string]any{"amr": "pwd"}, "")},
		{"algorithm not accepted", AuthorizationOptions{}, with(jose.ES256, idp.keys.ec, "ec", nil, "")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := idp.login(t, c, tt.options, tt.issue)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
			if identity.Claims != nil || identity.ID != (ExternalID{}) || identity.Assurance.ACR != "" ||
				identity.Assurance.AMR != nil || !identity.Assurance.AuthTime.IsZero() {
				t.Fatalf("failed login returned %+v", identity)
			}
		})
	}
	// The same tokens are otherwise acceptable, so each case fails for its own reason.
	if identity, err := idp.login(t, c, AuthorizationOptions{}, with(jose.RS256, idp.keys.rsa, "rsa", nil, "")); err != nil || identity.Claims == nil {
		t.Fatalf("control login: got %v", err)
	}
}
