package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2bskn/authlume/mcpoauth"
)

const (
	demoPassword = "example-password"
	redirectURI  = "https://client.example/callback?tenant=a"
	verifier     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	clientName   = `<script>alert(1)</script> & "Client"`
)

// site runs the command's handler over real HTTPS with an adjustable clock.
// The handler needs the server's URL, so it is installed after the listener
// starts.
type site struct {
	t       *testing.T
	server  *httptest.Server
	store   *mcpoauth.MemoryStore
	clock   atomic.Int64
	browser *http.Client // keeps the session cookie
	client  *http.Client // the MCP client: no cookies
}

func start(t *testing.T) *site {
	t.Helper()
	s := &site{t: t, store: mcpoauth.NewMemoryStore()}
	var handler atomic.Pointer[http.Handler]
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*handler.Load()).ServeHTTP(w, r)
	}))
	s.server.StartTLS()
	t.Cleanup(s.server.Close)
	h, err := demo(s.server.URL, demoPassword, mcpoauth.Client{
		ID: "demo-client", Name: clientName, RedirectURIs: []string{redirectURI, "http://127.0.0.1/callback"},
	}, s.store, s.now)
	if err != nil {
		t.Fatal(err)
	}
	handler.Store(&h)
	s.browser, s.client = s.agent(true), s.agent(false)
	return s
}

func (s *site) now() time.Time { return time.Unix(1_800_000_000+s.clock.Load(), 0) }

func (s *site) agent(cookies bool) *http.Client {
	s.t.Helper()
	c := &http.Client{Transport: s.server.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if cookies {
		jar, err := cookiejar.New(nil)
		if err != nil {
			s.t.Fatal(err)
		}
		c.Jar = jar
	}
	return c
}

type reply struct {
	*http.Response
	body string
}

func (r reply) location(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse(r.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// do sends a request and requires a status. A form makes it a POST, which
// carries the Origin a browser would send unless headers replace it.
func (s *site) do(c *http.Client, path string, form url.Values, want int, headers ...string) reply {
	s.t.Helper()
	method, body := http.MethodGet, io.Reader(nil)
	if form != nil {
		method, body = http.MethodPost, strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, s.server.URL+path, body)
	if err != nil {
		s.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if c.Jar != nil {
			req.Header.Set("Origin", s.server.URL)
		}
	}
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	response, err := c.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		s.t.Fatal(err)
	}
	if response.StatusCode != want {
		s.t.Fatalf("%s %s: status %d, want %d: %s", method, path, response.StatusCode, want, raw)
	}
	return reply{response, string(raw)}
}

func (s *site) login(c *http.Client, next string) reply {
	s.t.Helper()
	return s.do(c, "/login", url.Values{"username": {"demo"}, "password": {demoPassword}, "next": {next}}, http.StatusSeeOther)
}

func authorization(scope string) url.Values {
	digest := sha256.Sum256([]byte(verifier))
	v := url.Values{
		"response_type": {"code"}, "client_id": {"demo-client"}, "redirect_uri": {redirectURI}, "state": {"state value"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	if scope != "" {
		v.Set("scope", scope)
	}
	return v
}

var (
	hiddenQuery = regexp.MustCompile(`name="query" value="([^"]*)"`)
	hiddenNext  = regexp.MustCompile(`name="next" value="([^"]*)"`)
)

// consent opens the consent screen as the signed-in user and submits the
// decision with the query string the screen embedded.
func (s *site) consent(scope, decision string) *url.URL {
	s.t.Helper()
	query := authorization(scope).Encode()
	page := s.do(s.browser, "/authorize?"+query, nil, http.StatusOK)
	match := hiddenQuery.FindStringSubmatch(page.body)
	if match == nil || html.UnescapeString(match[1]) != query {
		s.t.Fatalf("consent form does not carry the request: %s", page.body)
	}
	r := s.do(s.browser, "/authorize", url.Values{"query": {html.UnescapeString(match[1])}, "decision": {decision}}, http.StatusSeeOther)
	if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Referrer-Policy") != "no-referrer" {
		s.t.Fatalf("redirect headers %v", r.Header)
	}
	u := r.location(s.t)
	if u.Scheme+"://"+u.Host+u.Path != "https://client.example/callback" || u.Query().Get("tenant") != "a" ||
		u.Query().Get("state") != "state value" || u.Query().Get("iss") != s.server.URL {
		s.t.Fatalf("redirect %s", u)
	}
	return u
}

type tokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Scope   string `json:"scope"`
	Expires int    `json:"expires_in"`
	Error   string `json:"error"`
}

func (s *site) token(form url.Values, want int) tokens {
	s.t.Helper()
	form.Set("client_id", "demo-client")
	r := s.do(s.client, "/token", form, want)
	var out tokens
	if err := json.Unmarshal([]byte(r.body), &out); err != nil || r.Header.Get("Cache-Control") != "no-store" {
		s.t.Fatalf("token response %q, header %v: %v", r.body, r.Header, err)
	}
	return out
}

// connect runs consent and the code exchange.
func (s *site) connect(scope string) tokens {
	s.t.Helper()
	code := s.consent(scope, "approve").Query().Get("code")
	return s.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {redirectURI}}, http.StatusOK)
}

func (s *site) refresh(token string, want int) tokens {
	s.t.Helper()
	return s.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}, want)
}

// mcp calls the protected endpoint and returns the challenge, if any.
func (s *site) mcp(method, token string, want int) reply {
	s.t.Helper()
	var form url.Values
	if method == http.MethodPost {
		form = url.Values{}
	}
	return s.do(s.client, "/mcp", form, want, "Authorization", "Bearer "+token)
}

func (s *site) ids(subject string) []string {
	s.t.Helper()
	conns, err := s.store.Connections(context.Background(), subject, s.now())
	if err != nil {
		s.t.Fatal(err)
	}
	var ids []string
	for _, conn := range conns {
		ids = append(ids, conn.ID)
	}
	return ids
}

func TestConnectRefreshAndDisconnect(t *testing.T) {
	s := start(t)
	query := authorization("mcp:read mcp:write").Encode()

	// An anonymous browser is sent to sign in and returns to the same request.
	r := s.do(s.browser, "/authorize?"+query, nil, http.StatusSeeOther)
	if got := r.location(t); got.Path != "/" || got.Query().Get("next") != "/authorize?"+query {
		t.Fatalf("sign-in redirect %s", got)
	}
	page := s.do(s.browser, r.Header.Get("Location"), nil, http.StatusOK)
	if match := hiddenNext.FindStringSubmatch(page.body); match == nil || html.UnescapeString(match[1]) != "/authorize?"+query {
		t.Fatalf("sign-in form lost the request: %s", page.body)
	}
	if r = s.login(s.browser, "/authorize?"+query); r.Header.Get("Location") != "/authorize?"+query {
		t.Fatalf("redirect after sign-in %q", r.Header.Get("Location"))
	}

	// The consent screen escapes the client's name and names its redirect host.
	page = s.do(s.browser, r.Header.Get("Location"), nil, http.StatusOK)
	if strings.Contains(page.body, "<script>") || !strings.Contains(page.body, "&lt;script&gt;alert(1)&lt;/script&gt; &amp; ") ||
		!strings.Contains(page.body, "<strong>client.example</strong>") || !strings.Contains(page.body, "<code>mcp:read</code>") ||
		!strings.Contains(page.body, "<code>mcp:write</code>") || strings.Contains(page.body, "on this computer") ||
		page.Header.Get("Content-Security-Policy") != "frame-ancestors 'none'" || page.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("consent page %s, header %v", page.body, page.Header)
	}
	loopback := authorization("")
	loopback.Set("redirect_uri", "http://127.0.0.1:51234/callback")
	if page = s.do(s.browser, "/authorize?"+loopback.Encode(), nil, http.StatusOK); !strings.Contains(page.body, "on this computer") ||
		!strings.Contains(page.body, "<strong>127.0.0.1:51234</strong>") {
		t.Fatalf("loopback consent page %s", page.body)
	}

	// Approval returns a code that the client exchanges for tokens.
	first := s.connect("mcp:read mcp:write")
	if first.Scope != "mcp:read mcp:write" || first.Expires != 3600 || first.Refresh == "" {
		t.Fatalf("tokens %+v", first)
	}
	var described struct {
		Subject  string   `json:"subject"`
		ClientID string   `json:"client_id"`
		Scopes   []string `json:"scopes"`
	}
	r = s.mcp(http.MethodGet, first.Access, http.StatusOK)
	if err := json.Unmarshal([]byte(r.body), &described); err != nil || described.Subject != demoSubject ||
		described.ClientID != "demo-client" || !slices.Equal(described.Scopes, []string{"mcp:read", "mcp:write"}) {
		t.Fatalf("mcp response %q: %v", r.body, err)
	}
	s.mcp(http.MethodPost, first.Access, http.StatusNoContent)

	// After an hour the access token expires and a refresh replaces it.
	s.clock.Add(3600)
	metadata := `resource_metadata="` + s.server.URL + `/.well-known/oauth-protected-resource/mcp"`
	r = s.mcp(http.MethodGet, first.Access, http.StatusUnauthorized)
	if got := r.Header.Get("WWW-Authenticate"); got != `Bearer error="invalid_token", `+metadata+`, scope="mcp:read"` {
		t.Fatalf("challenge %q", got)
	}
	second := s.refresh(first.Refresh, http.StatusOK)
	if second.Access == first.Access || second.Refresh == first.Refresh || second.Scope != first.Scope {
		t.Fatalf("refreshed tokens %+v", second)
	}
	s.mcp(http.MethodGet, second.Access, http.StatusOK)

	// Presenting the rotated refresh token again revokes the connection.
	if got := s.refresh(first.Refresh, http.StatusBadRequest); got.Error != "invalid_grant" {
		t.Fatalf("reuse %+v", got)
	}
	s.mcp(http.MethodGet, second.Access, http.StatusUnauthorized)
	if got := s.refresh(second.Refresh, http.StatusBadRequest); got.Error != "invalid_grant" || len(s.ids(demoSubject)) != 0 {
		t.Fatalf("refresh after reuse %+v, connections %v", got, s.ids(demoSubject))
	}

	// The user disconnects one of their own connections, and only those.
	third := s.connect("mcp:read")
	created := s.now()
	foreign := mcpoauth.Connection{ID: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Subject: "someone-else",
		ClientID: "demo-client", Scopes: []string{"mcp:read"}, CreatedAt: created, RefreshedAt: created,
		Selector: mcpoauth.Key{1}, Access: mcpoauth.Key{2}, AccessExpiry: created.Add(time.Hour),
		Refresh: mcpoauth.Key{3}, RefreshExpiry: created.Add(24 * time.Hour)}
	if err := s.store.Create(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	own := s.ids(demoSubject)
	page = s.do(s.browser, "/connections", nil, http.StatusOK)
	if len(own) != 1 || !strings.Contains(page.body, own[0]) || strings.Contains(page.body, foreign.ID) {
		t.Fatalf("connections %v, page %s", own, page.body)
	}
	for _, id := range []string{foreign.ID, "", "unknown"} {
		s.do(s.browser, "/connections/disconnect", url.Values{"id": {id}}, http.StatusNotFound)
	}
	if len(s.ids("someone-else")) != 1 || len(s.ids(demoSubject)) != 1 {
		t.Fatal("a connection of another user was disconnected")
	}
	s.do(s.agent(true), "/connections/disconnect", url.Values{"id": {own[0]}}, http.StatusUnauthorized,
		"Origin", s.server.URL)
	s.mcp(http.MethodGet, third.Access, http.StatusOK)
	if r = s.do(s.browser, "/connections/disconnect", url.Values{"id": {own[0]}}, http.StatusSeeOther); r.Header.Get("Location") != "/connections" {
		t.Fatalf("redirect %q", r.Header.Get("Location"))
	}
	s.mcp(http.MethodGet, third.Access, http.StatusUnauthorized)
	if got := s.refresh(third.Refresh, http.StatusBadRequest); got.Error != "invalid_grant" || len(s.ids("someone-else")) != 1 {
		t.Fatalf("refresh after disconnect %+v", got)
	}
}

func TestConsentDecisionsAndScopes(t *testing.T) {
	s := start(t)
	s.login(s.browser, "")

	// Denial reports access_denied and issues no code.
	denied := s.consent("mcp:read mcp:write", "deny").Query()
	if denied.Get("error") != "access_denied" || denied.Has("code") {
		t.Fatalf("denial %v", denied)
	}
	if other := s.consent("", "anything else").Query(); other.Get("error") != "access_denied" {
		t.Fatalf("unknown decision %v", other)
	}

	// Without a requested scope the connection can only read.
	reader := s.connect("")
	if reader.Scope != "mcp:read" {
		t.Fatalf("default scope %q", reader.Scope)
	}
	s.mcp(http.MethodGet, reader.Access, http.StatusOK)
	r := s.mcp(http.MethodPost, reader.Access, http.StatusForbidden)
	metadata := `resource_metadata="` + s.server.URL + `/.well-known/oauth-protected-resource/mcp"`
	if got := r.Header.Get("WWW-Authenticate"); got != `Bearer error="insufficient_scope", `+metadata+`, scope="mcp:write"` {
		t.Fatalf("challenge %q", got)
	}
	r = s.do(s.client, "/mcp", nil, http.StatusUnauthorized)
	if got := r.Header.Get("WWW-Authenticate"); got != "Bearer "+metadata+`, scope="mcp:read"` {
		t.Fatalf("challenge %q", got)
	}
	// The client revokes its own connection.
	s.do(s.client, "/revoke", url.Values{"client_id": {"demo-client"}, "token": {reader.Refresh}}, http.StatusOK)
	s.mcp(http.MethodGet, reader.Access, http.StatusUnauthorized)

	// A consent POST from another origin, or without a session, issues nothing.
	approve := url.Values{"query": {authorization("").Encode()}, "decision": {"approve"}}
	s.do(s.browser, "/authorize", approve, http.StatusForbidden, "Origin", "https://attacker.example")
	s.do(s.browser, "/authorize", approve, http.StatusForbidden, "Sec-Fetch-Site", "cross-site")
	s.do(s.agent(true), "/authorize", approve, http.StatusUnauthorized, "Origin", s.server.URL)
	if len(s.ids(demoSubject)) != 0 {
		t.Fatal("a rejected consent created a connection")
	}

	// Requests that cannot be attributed to the client are never forwarded;
	// those that can are reported to its redirect URI.
	for name, change := range map[string]func(url.Values){
		"unknown client":        func(v url.Values) { v.Set("client_id", "unknown") },
		"unregistered redirect": func(v url.Values) { v.Set("redirect_uri", "https://attacker.example/callback") },
	} {
		query := authorization("")
		change(query)
		if r := s.do(s.browser, "/authorize?"+query.Encode(), nil, http.StatusBadRequest); r.Header.Get("Location") != "" {
			t.Fatalf("%s: redirect %q", name, r.Header.Get("Location"))
		}
		approve := url.Values{"query": {query.Encode()}, "decision": {"approve"}}
		if r := s.do(s.browser, "/authorize", approve, http.StatusBadRequest); r.Header.Get("Location") != "" {
			t.Fatalf("%s: redirect %q", name, r.Header.Get("Location"))
		}
	}
	plain := authorization("")
	plain.Set("code_challenge_method", "plain")
	r = s.do(s.browser, "/authorize?"+plain.Encode(), nil, http.StatusSeeOther)
	if got := r.location(t); got.Host != "client.example" || got.Query().Get("error") != "invalid_request" ||
		got.Query().Get("iss") != s.server.URL || r.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("rejection redirect %s", got)
	}
}

func TestSignInNeverRedirectsElsewhere(t *testing.T) {
	s := start(t)
	s.do(s.browser, "/login", url.Values{"username": {"demo"}, "password": {"wrong"}, "next": {"/authorize?x"}}, http.StatusUnauthorized)
	for _, next := range []string{"https://attacker.example/authorize?x", "//attacker.example/authorize?x", "/authorize"} {
		if r := s.login(s.agent(true), next); r.Header.Get("Location") != "/connections" {
			t.Fatalf("next %q: redirect %q", next, r.Header.Get("Location"))
		}
	}
	// The sign-in form escapes the value it carries.
	page := s.do(s.browser, "/?next="+url.QueryEscape(`"><script>alert(1)</script>`), nil, http.StatusOK)
	if strings.Contains(page.body, "<script>") {
		t.Fatalf("sign-in page %s", page.body)
	}
	s.do(s.browser, "/connections", nil, http.StatusUnauthorized)
	s.login(s.browser, "")
	s.do(s.browser, "/connections", nil, http.StatusOK)
	if r := s.do(s.browser, "/logout", url.Values{}, http.StatusSeeOther); r.Header.Get("Location") != "/" {
		t.Fatalf("redirect %q", r.Header.Get("Location"))
	}
	s.do(s.browser, "/connections", nil, http.StatusUnauthorized)
}

func TestMetadata(t *testing.T) {
	s := start(t)
	for path, want := range map[string]map[string]string{
		"/.well-known/oauth-authorization-server": {
			"issuer": s.server.URL, "authorization_endpoint": s.server.URL + "/authorize",
			"token_endpoint": s.server.URL + "/token", "revocation_endpoint": s.server.URL + "/revoke",
		},
		"/.well-known/oauth-protected-resource/mcp": {"resource": s.server.URL + "/mcp"},
		"/.well-known/oauth-protected-resource":     {"resource": s.server.URL + "/mcp"},
	} {
		r := s.do(s.client, path, nil, http.StatusOK)
		var got map[string]any
		if err := json.Unmarshal([]byte(r.body), &got); err != nil || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("%s: %q, %v", path, r.body, err)
		}
		for name, value := range want {
			if got[name] != value {
				t.Fatalf("%s: %s is %v, want %s", path, name, got[name], value)
			}
		}
		if scopes, _ := got["scopes_supported"].([]any); len(scopes) != 2 {
			t.Fatalf("%s: scopes %v", path, got["scopes_supported"])
		}
		// A cross-origin fetch is not blocked: these routes carry no cookie.
		s.do(s.client, path, nil, http.StatusOK, "Origin", "https://attacker.example", "Sec-Fetch-Site", "cross-site")
		s.do(s.client, path, url.Values{}, http.StatusMethodNotAllowed)
	}
	// The token endpoint is reachable from another origin too.
	s.do(s.client, "/token", url.Values{"client_id": {"demo-client"}, "grant_type": {"refresh_token"}, "refresh_token": {"x"}},
		http.StatusBadRequest, "Origin", "https://attacker.example", "Sec-Fetch-Site", "cross-site")
}

func TestDemoConfiguration(t *testing.T) {
	store := mcpoauth.NewMemoryStore()
	valid := mcpoauth.Client{ID: "demo-client", RedirectURIs: []string{redirectURI}}
	for name, tc := range map[string]struct {
		password string
		client   mcpoauth.Client
	}{
		"empty password":      {"", valid},
		"missing client ID":   {demoPassword, mcpoauth.Client{RedirectURIs: []string{redirectURI}}},
		"missing redirect":    {demoPassword, mcpoauth.Client{ID: "demo-client", RedirectURIs: []string{""}}},
		"plain HTTP redirect": {demoPassword, mcpoauth.Client{ID: "demo-client", RedirectURIs: []string{"http://client.example/cb"}}},
	} {
		if _, err := demo("https://127.0.0.1:8446", tc.password, tc.client, store, time.Now); err == nil {
			t.Fatalf("%s: demo started", name)
		}
	}
	if _, err := demo("https://127.0.0.1:8446", demoPassword, valid, store, time.Now); err != nil {
		t.Fatal(err)
	}
}
