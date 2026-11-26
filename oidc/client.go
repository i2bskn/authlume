package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	provider "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ExternalID is an exact, case-sensitive pair. Subject is local to its issuer.
type ExternalID struct {
	Issuer  string
	Subject string
}

// Assurance contains signed provider claims. Missing claims have zero values.
// Only application policy can decide whether this issuer's assertions satisfy
// a local requirement for the linked account.
type Assurance struct {
	ACR      string
	AMR      []string
	AuthTime time.Time
}

// Identity contains a verified external identifier and the provider’s signed assurance.
type Identity struct {
	ID        ExternalID
	Assurance Assurance
}

// Config is trusted application configuration for one confidential client.
// RedirectURL must be a dedicated HTTPS callback with no query string. Use a
// distinct callback URI per issuer. The issuer must support client_secret_basic
// and S256, and must sign ID tokens with RS256 unless SigningAlgs says otherwise.
// Transport defaults to the standard HTTPS transport.
type Config struct {
	Issuer, ClientID, ClientSecret, RedirectURL string
	Transport                                   http.RoundTripper
	// SigningAlgs lists the signature algorithms accepted for ID tokens. When
	// it is empty only RS256 is accepted. An ID token signed with any other
	// algorithm is rejected, including RS256 when the list omits it.
	SigningAlgs []SigningAlg
}

// SigningAlg names a JWS signature algorithm for ID tokens.
type SigningAlg string

const (
	RS256 SigningAlg = "RS256" // RSASSA-PKCS1-v1_5 with SHA-256
	PS256 SigningAlg = "PS256" // RSASSA-PSS with SHA-256
	ES256 SigningAlg = "ES256" // ECDSA with P-256 and SHA-256
	EdDSA SigningAlg = "EdDSA" // Ed25519
)

// signingAlgs returns a private copy of the accepted algorithms, or RS256
// when none are listed. It reports false for an unknown or repeated entry.
func signingAlgs(list []SigningAlg) ([]string, bool) {
	if len(list) == 0 {
		return []string{string(RS256)}, true
	}
	algs := make([]string, 0, len(list))
	for _, alg := range list {
		switch alg {
		case RS256, PS256, ES256, EdDSA:
		default:
			return nil, false
		}
		if slices.Contains(algs, string(alg)) {
			return nil, false
		}
		algs = append(algs, string(alg))
	}
	return algs, true
}

// Client manages browser logins for one configured issuer and client registration.
type Client struct {
	issuer                string
	oauth                 oauth2.Config
	keys                  provider.KeySet
	algs                  []string
	http                  *http.Client
	store                 Store
	cookieName            string
	requireResponseIssuer bool
}

func httpsURL(raw string, allowQuery bool) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		!strings.Contains(raw, "#") && (allowQuery || u.RawQuery == "" && !u.ForceQuery)
}

// New discovers a fixed provider over HTTPS. Reuse the client across requests.
func New(ctx context.Context, cfg Config, store Store) (*Client, error) {
	algs, ok := signingAlgs(cfg.SigningAlgs)
	if store == nil || !httpsURL(cfg.Issuer, false) || !httpsURL(cfg.RedirectURL, false) ||
		cfg.ClientID == "" || cfg.ClientSecret == "" || !ok {
		return nil, errors.New("oidc: invalid client configuration")
	}
	transport := cfg.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	hc := &http.Client{
		Timeout: 10 * time.Second, Transport: providerTransport{base: transport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	p, err := provider.NewProvider(provider.ClientContext(ctx, hc), cfg.Issuer)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrProviderUnavailable
	}
	var meta struct {
		provider.ProviderConfig
		ResponseIssuer bool `json:"authorization_response_iss_parameter_supported"`
	}
	if err := p.Claims(&meta); err != nil || meta.IssuerURL != cfg.Issuer ||
		!httpsURL(meta.AuthURL, true) || !httpsURL(meta.TokenURL, true) || !httpsURL(meta.JWKSURL, true) {
		return nil, errors.New("oidc: invalid provider metadata")
	}
	endpoint := p.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	namespace, _ := json.Marshal([3]string{cfg.Issuer, cfg.ClientID, cfg.RedirectURL})
	sum := sha256.Sum256(namespace)
	return &Client{
		issuer: cfg.Issuer, http: hc, store: store, requireResponseIssuer: meta.ResponseIssuer, algs: algs,
		cookieName: "__Host-authlume-oidc-" + base64.RawURLEncoding.EncodeToString(sum[:]),
		oauth: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
			Endpoint: endpoint, Scopes: []string{provider.ScopeOpenID},
		},
		// Discovery honors ctx; the shared key cache outlives initialization.
		keys: provider.NewRemoteKeySet(provider.ClientContext(context.Background(), hc), meta.JWKSURL),
	}, nil
}

const lifetime = 10 * time.Minute

func randomValue() string {
	var raw [32]byte
	rand.Read(raw[:])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func validValue(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32
}

// Both inputs have a fixed validated length. The client namespace isolates
// multiple clients sharing a database or cookie host.
func (c *Client) key(state, cookie string) Key {
	return sha256.Sum256([]byte(c.cookieName + state + cookie))
}

func (c *Client) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: c.cookieName, Value: value, MaxAge: maxAge, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func privateResponse(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// Begin starts a login and sends a 303. Mount on a CSRF-protected POST route
// served over HTTPS. Starting again supersedes the prior browser attempt.
func (c *Client) Begin(w http.ResponseWriter, r *http.Request) error {
	return c.BeginWithOptions(w, r, AuthorizationOptions{})
}

// BeginWithOptions starts a login with application-selected authorization parameters.
func (c *Client) BeginWithOptions(w http.ResponseWriter, r *http.Request, options AuthorizationOptions) error {
	privateResponse(w)
	if r.Method != http.MethodPost {
		return ErrInvalid
	}
	params, err := options.parameters()
	if err != nil {
		return err
	}
	now := time.Now()
	state, browser := randomValue(), randomValue()
	tx := Transaction{Nonce: randomValue(), Verifier: oauth2.GenerateVerifier(), StartedAt: now, ExpiresAt: now.Add(lifetime)}
	if options.MaxAgeSeconds != nil {
		age := *options.MaxAgeSeconds
		tx.MaxAgeSeconds = &age
	}
	if err := c.store.Create(r.Context(), c.key(state, browser), tx); err != nil {
		return err
	}
	params = append(params, provider.Nonce(tx.Nonce), oauth2.S256ChallengeOption(tx.Verifier))
	dest := c.oauth.AuthCodeURL(state, params...)
	http.SetCookie(w, c.cookie(browser, int(lifetime.Seconds())))
	http.Redirect(w, r, dest, http.StatusSeeOther)
	return nil
}

// browserValue inspects raw Cookie fields because net/http skips malformed
// entries and normalizes quoted values, which can hide ambiguous credentials.
func (c *Client) browserValue(r *http.Request) (string, bool) {
	var value string
	for _, line := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(line, ";") {
			name, v, _ := strings.Cut(strings.Trim(part, " \t"), "=")
			if strings.TrimSpace(name) != c.cookieName {
				continue
			}
			if value != "" || name != c.cookieName || !validValue(v) {
				return "", false
			}
			value = v
		}
	}
	return value, value != ""
}

// Complete consumes the browser-bound transaction before exchanging the code.
// Mount only at the registered GET callback. A successful Identity must pass
// application linking and authentication policy before session issuance.
func (c *Client) Complete(w http.ResponseWriter, r *http.Request) (Identity, error) {
	privateResponse(w)
	q, err := url.ParseQuery(r.URL.RawQuery)
	browser, ok := c.browserValue(r)
	if r.Method != http.MethodGet || err != nil || !ok || len(q["state"]) != 1 || !validValue(q.Get("state")) {
		return Identity{}, ErrInvalid
	}
	// An unmatched or unavailable store may still hold the current browser's
	// pending login. Only clear the cookie after a confirmed consumption.
	tx, err := c.store.Take(r.Context(), c.key(q.Get("state"), browser), time.Now())
	if err != nil {
		return Identity{}, err
	}
	http.SetCookie(w, c.cookie("", -1))
	if !time.Now().Before(tx.ExpiresAt) || tx.Nonce == "" || tx.Verifier == "" || q.Has("error") ||
		len(q["code"]) != 1 || q.Get("code") == "" ||
		((c.requireResponseIssuer || q.Has("iss")) && (len(q["iss"]) != 1 || q.Get("iss") != c.issuer)) {
		return Identity{}, ErrInvalid
	}
	ctx := provider.ClientContext(r.Context(), c.http)
	t, err := c.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		return Identity{}, exchangeError(ctx, err)
	}
	raw, _ := t.Extra("id_token").(string)
	id, err := c.verifyToken(ctx, raw)
	if err != nil {
		return Identity{}, err
	}
	now := time.Now()
	identity, err := c.identity(id, tx.Nonce, now)
	if err != nil || !tx.acceptsAuthTime(identity.Assurance.AuthTime, now) {
		return Identity{}, ErrInvalid
	}
	return identity, nil
}

// Go struct unmarshalling folds case. Read the exact JWT claim names from the
// signed payload so provider-specific fields stay distinct from OIDC claims.
func readClaim(claims map[string]json.RawMessage, name string, dst any, required bool) bool {
	raw, ok := claims[name]
	if !ok {
		return !required
	}
	return string(raw) != "null" && json.Unmarshal(raw, dst) == nil
}

func singleAudience(claims map[string]json.RawMessage, client string) bool {
	var one string
	if readClaim(claims, "aud", &one, true) {
		return one == client
	}
	var many []string
	return readClaim(claims, "aud", &many, true) && len(many) == 1 && many[0] == client
}

func (c *Client) identity(token *provider.IDToken, nonce string, now time.Time) (Identity, error) {
	var claims map[string]json.RawMessage
	var id Identity
	var issued, expires, notBefore, authTime int64
	var gotNonce, authorizedParty string
	if token.Claims(&claims) != nil ||
		!readClaim(claims, "iss", &id.ID.Issuer, true) || id.ID.Issuer != c.issuer ||
		!readClaim(claims, "sub", &id.ID.Subject, true) || id.ID.Subject == "" ||
		!readClaim(claims, "nonce", &gotNonce, true) || gotNonce != nonce ||
		!singleAudience(claims, c.oauth.ClientID) ||
		!readClaim(claims, "azp", &authorizedParty, false) || (claims["azp"] != nil && authorizedParty != c.oauth.ClientID) {
		return Identity{}, ErrInvalid
	}
	if !readClaim(claims, "iat", &issued, true) || !readClaim(claims, "exp", &expires, true) ||
		!readClaim(claims, "nbf", &notBefore, false) || issued >= expires || now.Unix() >= expires ||
		issued > now.Add(time.Minute).Unix() || (claims["nbf"] != nil && now.Unix() < notBefore) {
		return Identity{}, ErrInvalid
	}
	if !readClaim(claims, "acr", &id.Assurance.ACR, false) || !readClaim(claims, "amr", &id.Assurance.AMR, false) ||
		slices.Contains(id.Assurance.AMR, "") || !readClaim(claims, "auth_time", &authTime, false) {
		return Identity{}, ErrInvalid
	}
	if claims["auth_time"] != nil {
		id.Assurance.AuthTime = time.Unix(authTime, 0)
		if id.Assurance.AuthTime.After(time.Unix(issued, 0).Add(time.Minute)) || id.Assurance.AuthTime.After(now.Add(time.Minute)) {
			return Identity{}, ErrInvalid
		}
	}
	return id, nil
}
