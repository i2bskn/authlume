package mcpoauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testIssuer   = "https://auth.example"
	testResource = "https://mcp.example/mcp"
	testVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	testSecret   = "correct horse battery staple"
	metadataURL  = "https://mcp.example/.well-known/oauth-protected-resource/mcp"
)

var testStart = time.Unix(1_800_000_000, 0).UTC()

func challengeOf(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// faultStore injects failures and altered records into a MemoryStore.
type faultStore struct {
	*MemoryStore
	mu    sync.Mutex
	fail  map[string]error
	calls map[string]int
	code  func(*Code)
	conn  func(*Connection)
}

func (s *faultStore) enter(method string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = make(map[string]int)
	}
	s.calls[method]++
	return s.fail[method]
}

func (s *faultStore) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for _, c := range s.calls {
		n += c
	}
	return n
}

func (s *faultStore) altered(conn Connection, err error) (Connection, error) {
	if err == nil && s.conn != nil {
		s.conn(&conn)
	}
	return conn, err
}

func (s *faultStore) CreateCode(ctx context.Context, key Key, code Code) error {
	if err := s.enter("CreateCode"); err != nil {
		return err
	}
	return s.MemoryStore.CreateCode(ctx, key, code)
}

func (s *faultStore) TakeCode(ctx context.Context, key Key, now time.Time) (Code, error) {
	if err := s.enter("TakeCode"); err != nil {
		return Code{}, err
	}
	code, err := s.MemoryStore.TakeCode(ctx, key, now)
	if err == nil && s.code != nil {
		s.code(&code)
	}
	return code, err
}

func (s *faultStore) Create(ctx context.Context, conn Connection) error {
	if err := s.enter("Create"); err != nil {
		return err
	}
	return s.MemoryStore.Create(ctx, conn)
}

func (s *faultStore) Rotate(ctx context.Context, selector, refresh Key, clientID string, now time.Time, next Rotation) (Connection, error) {
	if err := s.enter("Rotate"); err != nil {
		return Connection{}, err
	}
	conn, err := s.MemoryStore.Rotate(ctx, selector, refresh, clientID, now, next)
	return s.altered(conn, err)
}

func (s *faultStore) Lookup(ctx context.Context, selector Key, now time.Time) (Connection, error) {
	if err := s.enter("Lookup"); err != nil {
		return Connection{}, err
	}
	return s.altered(s.MemoryStore.Lookup(ctx, selector, now))
}

func (s *faultStore) Use(ctx context.Context, access Key, now time.Time) (Connection, error) {
	if err := s.enter("Use"); err != nil {
		return Connection{}, err
	}
	return s.altered(s.MemoryStore.Use(ctx, access, now))
}

func (s *faultStore) Revoke(ctx context.Context, id string) error {
	if err := s.enter("Revoke"); err != nil {
		return err
	}
	return s.MemoryStore.Revoke(ctx, id)
}

// fixture is a server with a fake clock, two registered clients and a store
// that can fail.
type fixture struct {
	*Server
	t         *testing.T
	store     *faultStore
	offset    atomic.Int64
	clients   map[string]Client
	lookupErr error
}

func testConfig() Config {
	return Config{
		Issuer: testIssuer, Resource: testResource,
		AuthorizationEndpoint: testIssuer + "/authorize", TokenEndpoint: testIssuer + "/token",
		RevocationEndpoint: testIssuer + "/revoke",
		Scopes:             []string{"read", "write", "admin"}, DefaultScopes: []string{"read"},
		AccessTTL: time.Hour, RefreshIdle: 2 * time.Hour,
	}
}

func newFixture(t *testing.T, change ...func(*Config)) *fixture {
	t.Helper()
	secret := sha256.Sum256([]byte(testSecret))
	f := &fixture{t: t, store: &faultStore{MemoryStore: NewMemoryStore(), fail: make(map[string]error)}}
	f.clients = map[string]Client{
		"public": {ID: "public", Name: "Public client", RedirectURIs: []string{
			"https://client.example/cb?keep=1&keep=2", "http://127.0.0.1/callback", "http://localhost/callback",
		}},
		"confidential": {ID: "confidential", Name: "Confidential client",
			RedirectURIs: []string{"https://app.example/cb"}, Secret: &secret},
		"id:colon": {ID: "id:colon", RedirectURIs: []string{"https://colon.example/cb"}, Secret: &secret},
	}
	f.Server = f.peer(change...)
	return f
}

// peer returns another server on the same store, clock and clients.
func (f *fixture) peer(change ...func(*Config)) *Server {
	f.t.Helper()
	cfg := testConfig()
	cfg.Now = func() time.Time { return testStart.Add(time.Duration(f.offset.Load())) }
	for _, c := range change {
		c(&cfg)
	}
	server, err := New(cfg, func(_ context.Context, id string) (Client, error) {
		if f.lookupErr != nil {
			return Client{}, f.lookupErr
		}
		client, ok := f.clients[id]
		if !ok {
			return Client{}, ErrNotFound
		}
		return client, nil
	}, f.store)
	if err != nil {
		f.t.Fatal(err)
	}
	return server
}

func (f *fixture) advance(d time.Duration) { f.offset.Add(int64(d)) }

func authParams() url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {"public"}, "redirect_uri": {"https://client.example/cb?keep=1&keep=2"},
		"scope": {"read write"}, "state": {"opaque state"}, "code_challenge": {challengeOf(testVerifier)},
		"code_challenge_method": {"S256"}, "resource": {testResource},
	}
}

// code approves an authorization request and returns the issued code.
func (f *fixture) code(params url.Values, subject string) string {
	f.t.Helper()
	_, redirect, err := f.Approve(f.t.Context(), params.Encode(), subject)
	if err != nil {
		f.t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil || !validValue(u.Query().Get("code")) {
		f.t.Fatalf("redirect %q: %v", redirect, err)
	}
	return u.Query().Get("code")
}

type reply struct {
	status int
	header http.Header
	body   string
	fields map[string]any
	event  Event
	err    error
}

func (r reply) field(name string) string {
	s, _ := r.fields[name].(string)
	return s
}

type handlerFunc func(http.ResponseWriter, *http.Request) (Event, error)

// post sends a form to a token or revocation endpoint.
func post(t *testing.T, handle handlerFunc, form url.Values, edit ...func(*http.Request)) reply {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, testIssuer+"/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, e := range edit {
		e(r)
	}
	w := httptest.NewRecorder()
	event, err := handle(w, r)
	out := reply{status: w.Code, header: w.Header(), body: w.Body.String(), event: event, err: err}
	if out.body != "" {
		if err := json.Unmarshal(w.Body.Bytes(), &out.fields); err != nil {
			t.Fatalf("body %q: %v", out.body, err)
		}
	}
	return out
}

// rejected requires an OAuth error response whose returned error wraps ErrInvalid.
func (r reply) rejected(t *testing.T, status int, code string) {
	t.Helper()
	if r.status != status || r.body != `{"error":"`+code+`"}` || !errors.Is(r.err, ErrInvalid) {
		t.Fatalf("status %d body %q err %v, want %d %s", r.status, r.body, r.err, status, code)
	}
}

// unavailable requires a 503 whose returned error is not a client failure.
func (r reply) unavailable(t *testing.T, cause error) {
	t.Helper()
	if r.status != http.StatusServiceUnavailable || r.body != `{"error":"temporarily_unavailable"}` ||
		errors.Is(r.err, ErrInvalid) || !errors.Is(r.err, cause) {
		t.Fatalf("status %d body %q err %v, want 503 caused by %v", r.status, r.body, r.err, cause)
	}
}

type grant struct{ access, refresh, id string }

func exchangeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {"public"}, "code": {code}, "code_verifier": {testVerifier}}
}

func refreshForm(token string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {"public"}, "refresh_token": {token}}
}

func granted(t *testing.T, r reply) grant {
	t.Helper()
	if r.status != http.StatusOK || r.err != nil {
		t.Fatalf("status %d body %q err %v", r.status, r.body, r.err)
	}
	g := grant{access: r.field("access_token"), refresh: r.field("refresh_token"), id: r.event.ConnectionID}
	if !validValue(g.access) || len(g.refresh) != 64 || !validValue(g.id) || r.field("token_type") != "Bearer" {
		t.Fatalf("token response %q, event %+v", r.body, r.event)
	}
	return g
}

// connect runs consent and code exchange for the public client.
func (f *fixture) connect(subject string) grant {
	f.t.Helper()
	return granted(f.t, post(f.t, f.Token, exchangeForm(f.code(authParams(), subject))))
}

func (f *fixture) refresh(token string) reply {
	f.t.Helper()
	return post(f.t, f.Token, refreshForm(token))
}

func bearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, testResource, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func (f *fixture) connections(subject string) []Connection {
	f.t.Helper()
	conns, err := f.store.Connections(context.Background(), subject, f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	return conns
}

func TestNew(t *testing.T) {
	lookup := func(context.Context, string) (Client, error) { return Client{}, ErrNotFound }
	store := NewMemoryStore()
	if _, err := New(testConfig(), nil, store); err == nil || err.Error() != "mcpoauth: client lookup and store are required" {
		t.Fatalf("nil lookup: %v", err)
	}
	if _, err := New(testConfig(), lookup, nil); err == nil || err.Error() != "mcpoauth: client lookup and store are required" {
		t.Fatalf("nil store: %v", err)
	}
	const (
		identifier = "mcpoauth: invalid issuer or resource"
		endpoint   = "mcpoauth: invalid endpoint"
		scopes     = "mcpoauth: invalid scopes"
		lifetimes  = "mcpoauth: invalid lifetimes"
		metadata   = "mcpoauth: invalid metadata"
	)
	many := make([]string, 65)
	for i := range many {
		many[i] = "s" + strings.Repeat("x", i)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"defaults", func(*Config) {}, ""},
		{"root issuer and resource", func(c *Config) { c.Issuer, c.Resource = "https://example.com", "https://example.com" }, ""},
		{"issuer with a path and port", func(c *Config) { c.Issuer = "https://example.com:8443/tenant/a" }, ""},
		{"empty issuer", func(c *Config) { c.Issuer = "" }, identifier},
		{"http issuer", func(c *Config) { c.Issuer = "http://auth.example" }, identifier},
		{"uppercase host", func(c *Config) { c.Issuer = "https://Auth.example" }, identifier},
		{"uppercase resource host", func(c *Config) { c.Resource = "https://MCP.example/mcp" }, identifier},
		{"missing host", func(c *Config) { c.Issuer = "https:///path" }, identifier},
		{"trailing slash", func(c *Config) { c.Resource = "https://mcp.example/mcp/" }, identifier},
		{"root slash", func(c *Config) { c.Issuer = "https://auth.example/" }, identifier},
		{"query", func(c *Config) { c.Resource = "https://mcp.example/mcp?x=1" }, identifier},
		{"empty query", func(c *Config) { c.Resource = "https://mcp.example/mcp?" }, identifier},
		{"fragment", func(c *Config) { c.Issuer = "https://auth.example#x" }, identifier},
		{"empty fragment", func(c *Config) { c.Issuer = "https://auth.example#" }, identifier},
		{"user information", func(c *Config) { c.Issuer = "https://user@auth.example" }, identifier},
		{"parent segment", func(c *Config) { c.Resource = "https://mcp.example/a/../mcp" }, identifier},
		{"empty segment", func(c *Config) { c.Resource = "https://mcp.example//mcp" }, identifier},
		{"percent-encoding", func(c *Config) { c.Resource = "https://mcp.example/m%63p" }, identifier},
		{"quote", func(c *Config) { c.Resource = `https://mcp.example/"mcp` }, identifier},
		{"missing endpoint", func(c *Config) { c.TokenEndpoint = "" }, endpoint},
		{"http endpoint", func(c *Config) { c.AuthorizationEndpoint = "http://auth.example/authorize" }, endpoint},
		{"endpoint with a query", func(c *Config) { c.RevocationEndpoint += "?x=1" }, endpoint},
		{"endpoint with a fragment", func(c *Config) { c.TokenEndpoint += "#x" }, endpoint},
		{"endpoint with user information", func(c *Config) { c.TokenEndpoint = "https://u@auth.example/token" }, endpoint},
		{"no scopes", func(c *Config) { c.Scopes = nil }, scopes},
		{"too many scopes", func(c *Config) { c.Scopes = many }, scopes},
		{"64 scopes", func(c *Config) { c.Scopes, c.DefaultScopes = many[:64], many[:1] }, ""},
		{"duplicate scope", func(c *Config) { c.Scopes = []string{"read", "read"} }, scopes},
		{"scope with a space", func(c *Config) { c.Scopes = []string{"read", "a b"} }, scopes},
		{"scope with a quote", func(c *Config) { c.Scopes = []string{"read", `a"b`} }, scopes},
		{"scope with a backslash", func(c *Config) { c.Scopes = []string{"read", `a\b`} }, scopes},
		{"empty scope", func(c *Config) { c.Scopes = []string{"read", ""} }, scopes},
		{"long scope", func(c *Config) { c.Scopes = []string{"read", strings.Repeat("x", 256)} }, scopes},
		{"no default scopes", func(c *Config) { c.DefaultScopes = nil }, scopes},
		{"unknown default scope", func(c *Config) { c.DefaultScopes = []string{"other"} }, scopes},
		{"duplicate default scope", func(c *Config) { c.DefaultScopes = []string{"read", "read"} }, scopes},
		{"negative access lifetime", func(c *Config) { c.AccessTTL = -1 }, lifetimes},
		{"negative refresh lifetime", func(c *Config) { c.RefreshIdle = -1 }, lifetimes},
		{"access longer than refresh", func(c *Config) { c.AccessTTL = 3 * time.Hour }, lifetimes},
		{"negative absolute lifetime", func(c *Config) { c.ConnectionAbsolute = -1 }, lifetimes},
		{"absolute shorter than access", func(c *Config) { c.ConnectionAbsolute = time.Minute }, lifetimes},
		{"absolute equal to access", func(c *Config) { c.ConnectionAbsolute = time.Hour }, ""},
		{"reserved metadata", func(c *Config) { c.Metadata = map[string]any{"issuer": "https://other.example"} }, metadata},
		{"reserved metadata list", func(c *Config) { c.Metadata = map[string]any{"scopes_supported": nil} }, metadata},
		{"metadata without a JSON form", func(c *Config) { c.Metadata = map[string]any{"x": func() {}} }, metadata},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			tc.change(&cfg)
			_, err := New(cfg, lookup, store)
			if (tc.want == "") != (err == nil) || (err != nil && err.Error() != tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}

	cfg := testConfig()
	cfg.AccessTTL, cfg.RefreshIdle = 0, 0
	s, err := New(cfg, lookup, store)
	if err != nil {
		t.Fatal(err)
	}
	if s.accessTTL != DefaultAccessTTL || s.refreshIdle != DefaultRefreshIdle || s.absolute != 0 || s.now == nil {
		t.Fatalf("defaults: %v %v %v", s.accessTTL, s.refreshIdle, s.absolute)
	}
	// The configuration's slices are copied.
	cfg.Scopes[0], cfg.DefaultScopes[0] = "changed", "changed"
	if s.scopes[0] != "read" || s.defaults[0] != "read" {
		t.Fatal("the server aliases the configured scopes")
	}
}

func TestMetadata(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.Metadata = map[string]any{"registration_endpoint": testIssuer + "/register", "client_id_metadata_document_supported": true}
	})
	get := func(handler http.HandlerFunc, method string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(method, testIssuer, nil))
		return w
	}
	methods := []any{"none", "client_secret_basic", "client_secret_post"}
	scopes := []any{"read", "write", "admin"}
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		want    map[string]any
	}{
		{"authorization server", f.Metadata, map[string]any{
			"issuer": testIssuer, "authorization_endpoint": testIssuer + "/authorize",
			"token_endpoint": testIssuer + "/token", "revocation_endpoint": testIssuer + "/revoke",
			"response_types_supported": []any{"code"}, "grant_types_supported": []any{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":           []any{"S256"},
			"token_endpoint_auth_methods_supported":      methods,
			"revocation_endpoint_auth_methods_supported": methods, "scopes_supported": scopes,
			"authorization_response_iss_parameter_supported": true,
			"registration_endpoint":                          testIssuer + "/register",
			"client_id_metadata_document_supported":          true,
		}},
		{"protected resource", f.ResourceMetadata, map[string]any{
			"resource": testResource, "authorization_servers": []any{testIssuer},
			"scopes_supported": scopes, "bearer_methods_supported": []any{"header"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				w := get(tc.handler, method)
				var got map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" ||
					w.Header().Get("Cache-Control") != "" || !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("%s: status %d header %v body %s", method, w.Code, w.Header(), w.Body)
				}
			}
			w := get(tc.handler, http.MethodPost)
			if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" || w.Body.Len() != 0 {
				t.Fatalf("POST: status %d header %v body %q", w.Code, w.Header(), w.Body)
			}
		})
	}

	if f.MetadataPath() != "/.well-known/oauth-authorization-server" ||
		f.ResourceMetadataPath() != "/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("paths %q %q", f.MetadataPath(), f.ResourceMetadataPath())
	}
	other := f.peer(func(c *Config) { c.Issuer, c.Resource = "https://auth.example/tenant/a", "https://mcp.example" })
	if other.MetadataPath() != "/.well-known/oauth-authorization-server/tenant/a" ||
		other.ResourceMetadataPath() != "/.well-known/oauth-protected-resource" {
		t.Fatalf("paths %q %q", other.MetadataPath(), other.ResourceMetadataPath())
	}
}

func TestUninitializedServer(t *testing.T) {
	const message = "mcpoauth: uninitialized server"
	for name, s := range map[string]*Server{"nil": nil, "zero value": {}} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			_, err := s.Authorize(ctx, authParams().Encode())
			_, _, errApprove := s.Approve(ctx, authParams().Encode(), "user")
			_, errDeny := s.Deny(ctx, authParams().Encode())
			_, errVerify := s.Verify(bearer(randomValue()))
			for _, err := range []error{err, errApprove, errDeny, errVerify, s.Disconnect(ctx, randomValue())} {
				if err == nil || err.Error() != message || errors.Is(err, ErrInvalid) {
					t.Fatalf("error %v", err)
				}
			}
			for _, handle := range []handlerFunc{s.Token, s.Revocation} {
				r := post(t, handle, refreshForm("x"))
				if r.status != http.StatusInternalServerError || r.body != "" || r.err == nil || r.err.Error() != message {
					t.Fatalf("status %d body %q err %v", r.status, r.body, r.err)
				}
			}
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("protected handler ran") })
			for name, handler := range map[string]http.HandlerFunc{
				"Metadata": s.Metadata, "ResourceMetadata": s.ResourceMetadata,
				"Challenge":         func(w http.ResponseWriter, r *http.Request) { s.Challenge(w, r, ErrInvalid, "read") },
				"InsufficientScope": func(w http.ResponseWriter, _ *http.Request) { s.InsufficientScope(w, "read") },
				"Protect":           s.Protect(next, "read").ServeHTTP,
			} {
				w := httptest.NewRecorder()
				handler(w, bearer(randomValue()))
				if w.Code != http.StatusInternalServerError || w.Body.Len() != 0 || w.Header().Get("WWW-Authenticate") != "" {
					t.Fatalf("%s: status %d header %v", name, w.Code, w.Header())
				}
			}
			if s.MetadataPath() != "" || s.ResourceMetadataPath() != "" {
				t.Fatal("path of an uninitialized server")
			}
		})
	}
}

func TestStoreFailures(t *testing.T) {
	down := errors.New("backend down")
	for _, cause := range []error{down, ErrCollision, ErrCapacity, context.DeadlineExceeded} {
		for _, method := range []string{"CreateCode", "TakeCode", "Create", "Rotate", "Use", "Lookup", "Revoke"} {
			t.Run(method+"/"+cause.Error(), func(t *testing.T) {
				f := newFixture(t)
				g := f.connect("user")
				code := f.code(authParams(), "user")
				f.store.fail[method] = cause
				switch method {
				case "CreateCode":
					_, redirect, err := f.Approve(t.Context(), authParams().Encode(), "user")
					if redirect != "" || !errors.Is(err, cause) || errors.Is(err, ErrInvalid) ||
						!strings.HasPrefix(err.Error(), "mcpoauth: store code: ") {
						t.Fatalf("redirect %q err %v", redirect, err)
					}
				case "TakeCode":
					post(t, f.Token, exchangeForm(code)).unavailable(t, cause)
				case "Create":
					r := post(t, f.Token, exchangeForm(code))
					r.unavailable(t, cause)
					if r.event.ConnectionID != "" || r.event.Grant != "authorization_code" || r.event.ClientID != "public" {
						t.Fatalf("event %+v", r.event)
					}
					// The code was consumed before the failure.
					delete(f.store.fail, method)
					post(t, f.Token, exchangeForm(code)).rejected(t, 400, "invalid_grant")
				case "Rotate":
					f.refresh(g.refresh).unavailable(t, cause)
					delete(f.store.fail, method)
					granted(t, f.refresh(g.refresh))
				case "Use":
					_, err := f.Verify(bearer(g.access))
					if !errors.Is(err, cause) || errors.Is(err, ErrInvalid) || !strings.HasPrefix(err.Error(), "mcpoauth: use access token: ") {
						t.Fatalf("verify: %v", err)
					}
					w := httptest.NewRecorder()
					f.Protect(http.NotFoundHandler(), "read").ServeHTTP(w, bearer(g.access))
					if w.Code != http.StatusServiceUnavailable || w.Header().Get("WWW-Authenticate") != "" ||
						w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() != 0 {
						t.Fatalf("status %d header %v", w.Code, w.Header())
					}
					post(t, f.Revocation, url.Values{"client_id": {"public"}, "token": {g.access}}).unavailable(t, cause)
				case "Lookup":
					post(t, f.Revocation, url.Values{"client_id": {"public"}, "token": {g.refresh}}).unavailable(t, cause)
				case "Revoke":
					post(t, f.Revocation, url.Values{"client_id": {"public"}, "token": {g.access}}).unavailable(t, cause)
					post(t, f.Revocation, url.Values{"client_id": {"public"}, "token": {g.refresh}}).unavailable(t, cause)
					err := f.Disconnect(t.Context(), g.id)
					if !errors.Is(err, cause) || errors.Is(err, ErrInvalid) || !strings.HasPrefix(err.Error(), "mcpoauth: revoke connection: ") {
						t.Fatalf("disconnect: %v", err)
					}
				}
				if method != "Rotate" && len(f.connections("user")) != 1 {
					t.Fatal("a failed call changed the connection")
				}
			})
		}
	}
}

func TestCanceledContext(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	code := f.code(authParams(), "user")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	canceled := func(r *http.Request) { *r = *r.WithContext(ctx) }
	before := f.store.total()

	_, err := f.Authorize(ctx, authParams().Encode())
	_, _, errApprove := f.Approve(ctx, authParams().Encode(), "user")
	_, errDeny := f.Deny(ctx, authParams().Encode())
	for _, err := range []error{err, errApprove, errDeny} {
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrInvalid) {
			t.Fatalf("authorization: %v", err)
		}
	}
	if f.store.total() != before {
		t.Fatal("a canceled authorization reached the store")
	}
	post(t, f.Token, exchangeForm(code), canceled).unavailable(t, context.Canceled)
	post(t, f.Token, refreshForm(g.refresh), canceled).unavailable(t, context.Canceled)
	post(t, f.Revocation, url.Values{"client_id": {"public"}, "token": {g.access}}, canceled).unavailable(t, context.Canceled)
	if err := f.Disconnect(ctx, g.id); !errors.Is(err, context.Canceled) || errors.Is(err, ErrInvalid) {
		t.Fatalf("disconnect: %v", err)
	}
	r := bearer(g.access)
	canceled(r)
	if _, err := f.Verify(r); !errors.Is(err, context.Canceled) || errors.Is(err, ErrInvalid) {
		t.Fatalf("verify: %v", err)
	}
	// Nothing was consumed or revoked.
	if _, err := f.Verify(bearer(g.access)); err != nil {
		t.Fatal(err)
	}
	granted(t, post(t, f.Token, exchangeForm(code)))
	granted(t, f.refresh(g.refresh))
}

func TestAudienceBinding(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	code := f.code(authParams(), "user")
	for name, other := range map[string]*Server{
		"resource": f.peer(func(c *Config) { c.Resource = "https://mcp.example/other" }),
		"issuer":   f.peer(func(c *Config) { c.Issuer = "https://other.example" }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := other.Verify(bearer(g.access)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("verify: %v", err)
			}
			post(t, other.Token, refreshForm(g.refresh)).rejected(t, 400, "invalid_grant")
			post(t, other.Token, exchangeForm(code)).rejected(t, 400, "invalid_grant")
			r := post(t, other.Revocation, url.Values{"client_id": {"public"}, "token": {g.access}})
			if r.status != http.StatusOK || r.err != nil || r.event.ConnectionID != "" {
				t.Fatalf("revocation: %+v", r)
			}
		})
	}
	// The issuing server still accepts all three.
	if _, err := f.Verify(bearer(g.access)); err != nil {
		t.Fatal(err)
	}
	granted(t, f.refresh(g.refresh))
	granted(t, post(t, f.Token, exchangeForm(code)))
}
