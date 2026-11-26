package mcpoauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNewDynamicClients(t *testing.T) {
	lookup := func(context.Context, string) (Client, error) { return Client{}, ErrNotFound }
	store := NewMemoryStore()
	docs := func(c *Config) { c.MetadataDocuments = &MetadataDocumentConfig{} }
	reg := func(c *Config) {
		c.Registration = &RegistrationConfig{Endpoint: testRegisterEndpoint, Store: NewMemoryClientStore()}
	}
	build := func(lookup ClientLookup, change ...func(*Config)) (*Server, error) {
		cfg := testConfig()
		for _, c := range change {
			c(&cfg)
		}
		return New(cfg, lookup, store)
	}
	// A nil lookup is accepted while either source is enabled.
	for _, change := range [][]func(*Config){{docs}, {reg}, {docs, reg}} {
		s, err := build(nil, change...)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Authorize(t.Context(), authParams().Encode()); err != ErrUnknownClient {
			t.Fatalf("nil lookup: %v", err)
		}
	}
	if _, err := build(nil); err == nil {
		t.Fatal("nil lookup without dynamic clients")
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"dynamic scopes without the restriction", func(c *Config) { c.DynamicScopes = []string{"read"} }, "mcpoauth: invalid scopes"},
		{"restriction without dynamic scopes", func(c *Config) { c.RestrictDynamicScopes = true }, "mcpoauth: invalid scopes"},
		{"undefined dynamic scope", func(c *Config) {
			c.RestrictDynamicScopes, c.DynamicScopes = true, []string{"read", "delete"}
		}, "mcpoauth: invalid scopes"},
		{"repeated dynamic scope", func(c *Config) {
			c.RestrictDynamicScopes, c.DynamicScopes = true, []string{"read", "read"}
		}, "mcpoauth: invalid scopes"},
		{"negative timeout", func(c *Config) { c.MetadataDocuments = &MetadataDocumentConfig{Timeout: -1} }, "mcpoauth: invalid metadata document configuration"},
		{"long timeout", func(c *Config) { c.MetadataDocuments = &MetadataDocumentConfig{Timeout: 31 * time.Second} }, "mcpoauth: invalid metadata document configuration"},
		{"large size", func(c *Config) { c.MetadataDocuments = &MetadataDocumentConfig{MaxSize: 64<<10 + 1} }, "mcpoauth: invalid metadata document configuration"},
		{"negative size", func(c *Config) { c.MetadataDocuments = &MetadataDocumentConfig{MaxSize: -1} }, "mcpoauth: invalid metadata document configuration"},
		{"minimum above the default maximum", func(c *Config) {
			c.MetadataDocuments = &MetadataDocumentConfig{MinCacheTTL: 48 * time.Hour}
		}, "mcpoauth: invalid metadata document configuration"},
		{"maximum below the default minimum", func(c *Config) {
			c.MetadataDocuments = &MetadataDocumentConfig{MaxCacheTTL: time.Minute}
		}, "mcpoauth: invalid metadata document configuration"},
		{"negative minimum", func(c *Config) {
			c.MetadataDocuments = &MetadataDocumentConfig{MinCacheTTL: -1}
		}, "mcpoauth: invalid metadata document configuration"},
		{"invalid allowed host", func(c *Config) {
			c.MetadataDocuments = &MetadataDocumentConfig{AllowedHosts: []string{"https://claude.ai"}}
		}, "mcpoauth: invalid allowed host"},
		{"registration without a store", func(c *Config) {
			c.Registration = &RegistrationConfig{Endpoint: testRegisterEndpoint}
		}, "mcpoauth: registration store is required"},
		{"plain HTTP registration endpoint", func(c *Config) {
			c.Registration = &RegistrationConfig{Endpoint: "http://auth.example/register", Store: NewMemoryClientStore()}
		}, "mcpoauth: invalid endpoint"},
		{"registration endpoint with a query", func(c *Config) {
			c.Registration = &RegistrationConfig{Endpoint: testRegisterEndpoint + "?x=1", Store: NewMemoryClientStore()}
		}, "mcpoauth: invalid endpoint"},
		{"short unused lifetime", func(c *Config) {
			c.Registration = &RegistrationConfig{Endpoint: testRegisterEndpoint, Store: NewMemoryClientStore(), UnusedTTL: 10*time.Minute - 1}
		}, "mcpoauth: invalid lifetimes"},
		{"reserved document member", func(c *Config) {
			docs(c)
			c.Metadata = map[string]any{"client_id_metadata_document_supported": false}
		}, "mcpoauth: invalid metadata"},
		{"reserved registration member", func(c *Config) {
			reg(c)
			c.Metadata = map[string]any{"registration_endpoint": "https://other.example/register"}
		}, "mcpoauth: invalid metadata"},
	} {
		if _, err := build(lookup, tc.change); err == nil || err.Error() != tc.want {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.want)
		}
	}
	// Accepted edges.
	for name, change := range map[string]func(*Config){
		"restricted dynamic scopes": func(c *Config) { c.RestrictDynamicScopes, c.DynamicScopes = true, []string{"read"} },
		"dynamic scopes without dynamic clients": func(c *Config) {
			c.RestrictDynamicScopes, c.DynamicScopes = true, []string{"admin"}
		},
		"limits": func(c *Config) {
			c.MetadataDocuments = &MetadataDocumentConfig{Timeout: 30 * time.Second, MaxSize: 64 << 10,
				MinCacheTTL: time.Second, MaxCacheTTL: time.Second}
		},
		"never expiring registrations": func(c *Config) {
			c.Registration = &RegistrationConfig{Endpoint: testRegisterEndpoint, Store: NewMemoryClientStore(), UnusedTTL: -1}
		},
		"shortest unused lifetime": func(c *Config) {
			c.Registration = &RegistrationConfig{Endpoint: testRegisterEndpoint, Store: NewMemoryClientStore(), UnusedTTL: 10 * time.Minute}
		},
	} {
		if _, err := build(lookup, change); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Zero values select the defaults.
	s, err := build(lookup, docs, reg)
	if err != nil {
		t.Fatal(err)
	}
	if s.docs.timeout != 5*time.Second || s.docs.maxSize != 5120 || s.docs.minTTL != 5*time.Minute ||
		s.docs.maxTTL != 24*time.Hour || s.registration.unusedTTL != 7*24*time.Hour {
		t.Fatalf("defaults %+v %+v", s.docs, s.registration)
	}
	for _, host := range []string{"auth.example", "mcp.example"} {
		if !s.docs.own[host] {
			t.Fatalf("own hosts %v", s.docs.own)
		}
	}
	// The configured slices are copied.
	cfg := testConfig()
	cfg.RestrictDynamicScopes, cfg.DynamicScopes = true, []string{"read"}
	cfg.MetadataDocuments = &MetadataDocumentConfig{AllowedHosts: []string{"claude.ai"}}
	s, err = New(cfg, lookup, store)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DynamicScopes[0], cfg.MetadataDocuments.AllowedHosts[0] = "admin", "evil.example"
	if s.dynamicScopes[0] != "read" || s.docs.allowed[0] != "claude.ai" {
		t.Fatal("the server aliases the configuration")
	}
}

func TestDynamicMetadata(t *testing.T) {
	get := func(s *Server) map[string]any {
		w := httptest.NewRecorder()
		s.Metadata(w, httptest.NewRequest(http.MethodGet, testIssuer, nil))
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	// With both disabled the document is byte for byte what it was.
	w := httptest.NewRecorder()
	newFixture(t).Metadata(w, httptest.NewRequest(http.MethodGet, testIssuer, nil))
	const want = `{"authorization_endpoint":"https://auth.example/authorize","authorization_response_iss_parameter_supported":true,` +
		`"code_challenge_methods_supported":["S256"],"grant_types_supported":["authorization_code","refresh_token"],` +
		`"issuer":"https://auth.example","response_types_supported":["code"],` +
		`"revocation_endpoint":"https://auth.example/revoke","revocation_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],` +
		`"scopes_supported":["read","write","admin"],"token_endpoint":"https://auth.example/token",` +
		`"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"]}`
	if w.Body.String() != want {
		t.Fatalf("metadata %s", w.Body)
	}
	f, _ := cimdFixture(t)
	if m := get(f.Server); m["client_id_metadata_document_supported"] != true || m["registration_endpoint"] != nil {
		t.Fatalf("metadata documents %v", m)
	}
	g, _ := dcrFixture(t)
	if m := get(g.Server); m["registration_endpoint"] != testRegisterEndpoint || m["client_id_metadata_document_supported"] != nil {
		t.Fatalf("registration %v", m)
	}
}

func TestClientSourceZero(t *testing.T) {
	var zero ClientSource
	for _, source := range []ClientSource{SourceLookup, SourceMetadata, SourceRegistration} {
		if source == zero {
			t.Fatalf("%d is the zero value", source)
		}
	}
}

func TestUnknownClient(t *testing.T) {
	f := newFixture(t)
	params := authParams()
	params.Set("client_id", "missing")
	if _, err := f.Authorize(t.Context(), params.Encode()); err != ErrUnknownClient || !errors.Is(err, ErrInvalid) {
		t.Fatalf("authorize: %v", err)
	}
	if _, _, err := f.Approve(t.Context(), params.Encode(), "alice"); err != ErrUnknownClient {
		t.Fatalf("approve: %v", err)
	}
	if _, err := f.Deny(t.Context(), params.Encode()); err != ErrUnknownClient {
		t.Fatalf("deny: %v", err)
	}
	params.Set("client_id", "bad id")
	if _, err := f.Authorize(t.Context(), params.Encode()); err != ErrInvalid {
		t.Fatalf("malformed id: %v", err)
	}
}

func TestDynamicScopes(t *testing.T) {
	restrict := func(c *Config) {
		c.RestrictDynamicScopes, c.DynamicScopes = true, []string{"read", "write"}
		c.DefaultScopes = []string{"admin", "read"}
	}
	f, docs := cimdFixture(t, restrict)
	docs.set(testDocID, docResponse{body: metadataDoc(testDocID, nil)})
	authorize := func(scope string) (Request, error) {
		params := cimdParams()
		if scope == "" {
			params.Del("scope")
		} else {
			params.Set("scope", scope)
		}
		return f.Authorize(t.Context(), params.Encode())
	}
	for scope, want := range map[string]string{
		"read write admin": "read write",
		"admin read":       "read",
		"admin admin read": "read",
		"":                 "read",
	} {
		req, err := authorize(scope)
		if err != nil || strings.Join(req.Scopes, " ") != want {
			t.Errorf("%q: %v %v, want %q", scope, req.Scopes, err, want)
		}
	}
	for _, scope := range []string{"admin", "read delete", "delete"} {
		var reject *RejectError
		if _, err := authorize(scope); !errors.As(err, &reject) || reject.Code != "invalid_scope" {
			t.Errorf("%q: %v", scope, err)
		}
	}
	// The narrowed scope is what the token carries.
	params := cimdParams()
	params.Set("scope", "read write admin")
	r := post(t, f.Token, cimdExchange(f.code(params, "alice")))
	granted(t, r)
	if r.field("scope") != "read write" {
		t.Fatalf("token scope %q", r.field("scope"))
	}
	// A pre-registered client is untouched: it may request admin.
	req, err := f.Authorize(t.Context(), authParams().Encode())
	if err != nil || strings.Join(req.Scopes, " ") != "read write" {
		t.Fatalf("pre-registered %v %v", req.Scopes, err)
	}
	params = authParams()
	params.Set("scope", "admin")
	if _, err := f.Authorize(t.Context(), params.Encode()); err != nil {
		t.Fatalf("pre-registered admin: %v", err)
	}
	// A pre-registered restricted client is still rejected, not narrowed.
	f.clients["limited"] = Client{ID: "limited", RedirectURIs: []string{"https://client.example/cb"}, RestrictScopes: true, Scopes: []string{"read"}}
	params.Set("client_id", "limited")
	params.Set("redirect_uri", "https://client.example/cb")
	params.Set("scope", "read admin")
	var reject *RejectError
	if _, err := f.Authorize(t.Context(), params.Encode()); !errors.As(err, &reject) || reject.Code != "invalid_scope" {
		t.Fatalf("pre-registered restricted: %v", err)
	}
	// Without the restriction a dynamic client may request every scope.
	open, openDocs := cimdFixture(t)
	openDocs.set(testDocID, docResponse{body: metadataDoc(testDocID, nil)})
	params = cimdParams()
	params.Set("scope", "read write admin")
	if req, err := open.Authorize(t.Context(), params.Encode()); err != nil || len(req.Scopes) != 3 {
		t.Fatalf("unrestricted %v %v", req.Scopes, err)
	}
	// A registered client is limited the same way.
	g, _ := dcrFixture(t, restrict)
	id := register(t, g.Server, registrationBody(nil)).reg.ID
	params = dcrParams(id)
	params.Set("scope", "admin write")
	if req, err := g.Authorize(t.Context(), params.Encode()); err != nil || !reflect.DeepEqual(req.Scopes, []string{"write"}) {
		t.Fatalf("registered %v %v", req.Scopes, err)
	}
}
