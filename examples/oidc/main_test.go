package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/i2bskn/authlume/oidc"
	"github.com/i2bskn/authlume/session"
	"golang.org/x/oauth2"
)

const localACR = "urn:example:assurance:two-factor"

type flowCase struct {
	name                string
	requireMFA          bool
	acceptACR           string
	claims              map[string]any
	differentSigningKey bool
	omitResponseIssuer  bool
	want                int
}

func TestHTTPSLogin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for _, tc := range []flowCase{
		{name: "approved pair and OIDC-only policy", want: 200},
		{name: "unknown subject with same verified email", claims: map[string]any{"sub": "other"}, want: 403},
		{name: "MFA required with signed MFA claims and no app acceptance", requireMFA: true, claims: map[string]any{"amr": []string{"mfa"}, "acr": localACR, "auth_time": now}, want: 403},
		{name: "MFA required with explicit fresh assurance", requireMFA: true, acceptACR: localACR, claims: map[string]any{"acr": localACR, "auth_time": now}, want: 200},
		{name: "MFA required with stale assurance", requireMFA: true, acceptACR: localACR, claims: map[string]any{"acr": localACR, "auth_time": now - 600}, want: 403},
		{name: "MFA required with absent authentication time", requireMFA: true, acceptACR: localACR, claims: map[string]any{"acr": localACR}, want: 403},
		{name: "MFA required with different assurance", requireMFA: true, acceptACR: localACR, claims: map[string]any{"acr": "other", "auth_time": now}, want: 403},
		{name: "provider-specific assurance name", requireMFA: true, acceptACR: localACR, claims: map[string]any{"ACR": localACR, "auth_time": now}, want: 403},
		{name: "missing exact subject name", claims: map[string]any{"sub": nil, "SUB": "approved"}, want: 401},
		{name: "explicit null authorized party", claims: map[string]any{"azp": json.RawMessage("null")}, want: 401},
		{name: "missing advertised callback issuer", omitResponseIssuer: true, want: 401},
		{name: "different issuer", claims: map[string]any{"iss": "https://different.example"}, want: 401},
		{name: "empty subject", claims: map[string]any{"sub": ""}, want: 401},
		{name: "different audience", claims: map[string]any{"aud": "another-client"}, want: 401},
		{name: "additional audience", claims: map[string]any{"aud": []string{"app", "other"}}, want: 401},
		{name: "different authorized party", claims: map[string]any{"azp": "another-client"}, want: 401},
		{name: "expired", claims: map[string]any{"exp": now - 1}, want: 401},
		{name: "before validity", claims: map[string]any{"nbf": now + 120}, want: 401},
		{name: "missing issuance time", claims: map[string]any{"iat": nil}, want: 401},
		{name: "future issuance time", claims: map[string]any{"iat": now + 180}, want: 401},
		{name: "different nonce", claims: map[string]any{"nonce": "unrelated"}, want: 401},
		{name: "unrecognized signature", differentSigningKey: true, want: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signingKey := key
			if tc.differentSigningKey {
				signingKey = otherKey
			}
			testHTTPSFlow(t, tc, signingKey, &key.PublicKey)
		})
	}
}

type authorization struct{ challenge, nonce string }

// testHTTPSFlow drives the same form, callback and protected handler as the
// executable. The issuer and RP use different HTTPS hostnames and a cookie jar.
func testHTTPSFlow(t *testing.T, tc flowCase, signingKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Start the listener first so its registered redirect URI is fixed before discovery.
	appMux := http.NewServeMux()
	app := httptest.NewTLSServer(appMux)
	defer app.Close()
	callback := app.URL + "/callback"
	pending := make(chan authorization, 1)
	idpMux := http.NewServeMux()
	idp := httptest.NewTLSServer(idpMux)
	defer idp.Close()
	issuer := strings.Replace(idp.URL, "127.0.0.1", "id.example.com", 1)
	idpMux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "authorization_response_iss_parameter_supported": true,
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	idpMux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: publicKey, Use: "sig", Algorithm: "RS256"}}})
	})
	idpMux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("redirect_uri") != callback || q.Get("client_id") != "app" || q.Get("response_type") != "code" ||
			q.Get("scope") != "openid" || q.Get("state") == "" || q.Get("nonce") == "" ||
			q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || len(r.Cookies()) != 0 {
			t.Error("unexpected authorization request")
			http.Error(w, "invalid request", 400)
			return
		}
		pending <- authorization{q.Get("code_challenge"), q.Get("nonce")}
		values := url.Values{"code": {"test-code"}, "state": {q.Get("state")}, "iss": {issuer}}
		if tc.omitResponseIssuer {
			values.Del("iss")
		}
		http.Redirect(w, r, callback+"?"+values.Encode(), http.StatusFound)
	})
	idpMux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		var auth authorization
		select {
		case auth = <-pending:
		default:
			http.Error(w, "no pending code", 400)
			return
		}
		client, secret, ok := r.BasicAuth()
		if !ok || client != "app" || secret != "test-secret" || r.PostFormValue("grant_type") != "authorization_code" ||
			r.PostFormValue("code") != "test-code" || r.PostFormValue("redirect_uri") != callback ||
			oauth2.S256ChallengeFromVerifier(r.PostFormValue("code_verifier")) != auth.challenge {
			t.Error("unexpected token request")
			http.Error(w, "invalid request", 400)
			return
		}
		now := time.Now()
		claims := map[string]any{"iss": issuer, "sub": "approved", "aud": "app", "azp": "app", "exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(), "nonce": auth.nonce, "email": "member@example.com", "email_verified": true}
		for k, v := range tc.claims {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Error(err)
			return
		}
		sig, err := signer.Sign(payload)
		if err != nil {
			t.Error(err)
			return
		}
		token, err := sig.CompactSerialize()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"access_token": "fixture", "token_type": "Bearer", "id_token": token})
	})
	transport := app.Client().Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.Proxy = nil
	dialer := new(net.Dialer)
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "id.example.com:") {
			addr = idp.Listener.Addr().String()
		}
		return dialer.DialContext(ctx, network, addr)
	}
	client, err := oidc.New(t.Context(), oidc.Config{Issuer: issuer, ClientID: "app", ClientSecret: "test-secret", RedirectURL: callback, Transport: transport}, oidc.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.New(session.NewMemoryStore(), session.Config{})
	if err != nil {
		t.Fatal(err)
	}
	appMux.Handle("/", routes(client, sessions, accountPolicy{
		external: oidc.ExternalID{Issuer: issuer, Subject: "approved"}, local: "local-account-7", requireMFA: tc.requireMFA, acceptedACR: tc.acceptACR,
	}))

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	var callbackURL, originalCookie string
	browser := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return http.ErrUseLastResponse
		}
		if strings.HasPrefix(r.URL.String(), callback+"?") {
			callbackURL = r.URL.String()
			for _, cookie := range jar.Cookies(r.URL) {
				if strings.HasPrefix(cookie.Name, "__Host-authlume-oidc-") {
					originalCookie = cookie.String()
				}
			}
		}
		return nil
	}}
	resp, err := browser.Get(app.URL)
	if err != nil {
		t.Fatal(err)
	}
	page, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !strings.Contains(string(page), `action="/login"`) {
		t.Fatal("missing sign-in form")
	}
	resp, err = browser.PostForm(app.URL+"/login", url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != tc.want {
		t.Fatalf("flow status %d, body %q", resp.StatusCode, body)
	}
	if callbackURL == "" || originalCookie == "" {
		t.Fatal("missing browser transaction")
	}
	resp, err = browser.Get(app.URL + "/account")
	if err != nil {
		t.Fatal(err)
	}
	account, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if tc.want == http.StatusOK {
		if resp.StatusCode != http.StatusOK || string(account) != "local-account-7\n" {
			t.Fatal("local session missing")
		}
	} else if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("incomplete login issued a session")
	}

	retry, err := http.NewRequest("GET", callbackURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	retry.Header.Set("Cookie", originalCookie)
	resp, err = (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(retry)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("consumed callback accepted")
	}
}
