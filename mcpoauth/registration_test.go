package mcpoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const testRegisterEndpoint = testIssuer + "/register"

// faultClientStore injects failures into a MemoryClientStore.
type faultClientStore struct {
	*MemoryClientStore
	mu    sync.Mutex
	fail  map[string]error
	calls map[string]int
}

func (s *faultClientStore) enter(method string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = make(map[string]int)
	}
	s.calls[method]++
	return s.fail[method]
}

func (s *faultClientStore) count(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[method]
}

func (s *faultClientStore) CreateClient(ctx context.Context, reg Registration) error {
	if err := s.enter("CreateClient"); err != nil {
		return err
	}
	return s.MemoryClientStore.CreateClient(ctx, reg)
}

func (s *faultClientStore) Client(ctx context.Context, id string, now time.Time) (Registration, error) {
	if err := s.enter("Client"); err != nil {
		return Registration{}, err
	}
	return s.MemoryClientStore.Client(ctx, id, now)
}

func (s *faultClientStore) Activate(ctx context.Context, id string, now time.Time) error {
	if err := s.enter("Activate"); err != nil {
		return err
	}
	return s.MemoryClientStore.Activate(ctx, id, now)
}

func dcrFixture(t *testing.T, change ...func(*Config)) (*fixture, *faultClientStore) {
	t.Helper()
	store := &faultClientStore{MemoryClientStore: NewMemoryClientStore(), fail: make(map[string]error)}
	f := newFixture(t, append([]func(*Config){func(c *Config) {
		c.Registration = &RegistrationConfig{Endpoint: testRegisterEndpoint, Store: store}
	}}, change...)...)
	return f, store
}

type registered struct {
	status int
	header http.Header
	body   string
	fields map[string]any
	reg    Registration
	err    error
}

func register(t *testing.T, s *Server, body string, edit ...func(*http.Request)) registered {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, testRegisterEndpoint, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	for _, e := range edit {
		e(r)
	}
	w := httptest.NewRecorder()
	reg, err := s.Register(w, r)
	out := registered{status: w.Code, header: w.Header(), body: w.Body.String(), reg: reg, err: err}
	if out.body != "" {
		if err := json.Unmarshal(w.Body.Bytes(), &out.fields); err != nil {
			t.Fatalf("body %q: %v", out.body, err)
		}
	}
	return out
}

func (r registered) failed(t *testing.T, status int, code string) {
	t.Helper()
	want := ""
	if code != "" {
		want = `{"error":"` + code + `"}`
	}
	if r.status != status || r.body != want || !errors.Is(r.err, ErrInvalid) || r.reg.ID != "" {
		t.Fatalf("status %d body %q err %v, want %d %s", r.status, r.body, r.err, status, code)
	}
	if code != "" && r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("header %v", r.header)
	}
}

func registrationBody(extra map[string]any) string {
	body := map[string]any{
		"client_name":   "Inspector",
		"redirect_uris": []string{"http://localhost:6274/oauth/callback", "cursor://anysphere/cb", "https://app.example.com/cb"},
	}
	for k, v := range extra {
		if v == nil {
			delete(body, k)
			continue
		}
		body[k] = v
	}
	b, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func dcrExchange(code, id string) url.Values {
	form := exchangeForm(code)
	form.Set("client_id", id)
	return form
}

func dcrParams(id string) url.Values {
	params := authParams()
	params.Set("client_id", id)
	params.Set("redirect_uri", "https://app.example.com/cb")
	return params
}

func TestRegister(t *testing.T) {
	f, store := dcrFixture(t)
	r := register(t, f.Server, registrationBody(map[string]any{
		"token_endpoint_auth_method": "client_secret_basic", "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "scope": "admin", "logo_uri": "https://x.example/logo.png",
		"software_statement": "x.y.z", "client_secret": "mine",
	}))
	if r.status != http.StatusCreated || r.err != nil || r.header.Get("Cache-Control") != "no-store" ||
		r.header.Get("Content-Type") != "application/json" {
		t.Fatalf("status %d header %v body %s err %v", r.status, r.header, r.body, r.err)
	}
	id := r.reg.ID
	want := map[string]any{
		"client_id": id, "client_id_issued_at": float64(testStart.Unix()), "client_name": "Inspector",
		"redirect_uris":  []any{"http://localhost:6274/oauth/callback", "https://app.example.com/cb"},
		"grant_types":    []any{"authorization_code", "refresh_token"},
		"response_types": []any{"code"}, "token_endpoint_auth_method": "none",
	}
	if !validValue(id) || !reflect.DeepEqual(r.fields, want) {
		t.Fatalf("body %s", r.body)
	}
	stored, err := store.MemoryClientStore.Client(t.Context(), id, testStart)
	if err != nil || stored.Name != "Inspector" || !stored.CreatedAt.Equal(testStart) ||
		!stored.ExpiresAt.Equal(testStart.Add(7*24*time.Hour)) || !reflect.DeepEqual(stored, r.reg) {
		t.Fatalf("stored %+v %v, returned %+v", stored, err, r.reg)
	}
	// Without a name the member is left out.
	r = register(t, f.Server, registrationBody(map[string]any{"client_name": nil}))
	if r.status != http.StatusCreated || r.fields["client_name"] != nil || r.reg.Name != "" {
		t.Fatalf("no name: %s", r.body)
	}
	r = register(t, f.Server, `{"redirect_uris":["https://app.example.com/cb"],"client_name":null,"grant_types":null}`)
	if r.status != http.StatusCreated {
		t.Fatalf("null members: %s", r.body)
	}
	// The registration's lifetime and its activation by the first exchange.
	f.advance(7*24*time.Hour - time.Second)
	if _, err := f.Authorize(t.Context(), dcrParams(id).Encode()); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	f.advance(time.Second)
	if _, err := f.Authorize(t.Context(), dcrParams(id).Encode()); err != ErrUnknownClient {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestRegisterRejected(t *testing.T) {
	f, store := dcrFixture(t)
	many := func(n int, prefix string) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("%s%d", prefix, i))
		}
		return out
	}
	for _, tc := range []struct {
		name string
		body string
		edit func(*http.Request)
		code string
	}{
		{"form content type", registrationBody(nil), func(r *http.Request) {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}, "invalid_client_metadata"},
		{"no content type", registrationBody(nil), func(r *http.Request) { r.Header.Del("Content-Type") }, "invalid_client_metadata"},
		{"too large", registrationBody(map[string]any{"pad": strings.Repeat("a", 16<<10)}), nil, "invalid_client_metadata"},
		{"not JSON", "{", nil, "invalid_client_metadata"},
		{"array", "[" + registrationBody(nil) + "]", nil, "invalid_client_metadata"},
		{"trailing data", registrationBody(nil) + "{}", nil, "invalid_client_metadata"},
		{"repeated member", `{"redirect_uris":["https://a.example/cb"],"redirect_uris":["https://b.example/cb"]}`, nil, "invalid_client_metadata"},
		{"no redirect URIs", registrationBody(map[string]any{"redirect_uris": nil}), nil, "invalid_redirect_uri"},
		{"null redirect URIs", `{"redirect_uris":null}`, nil, "invalid_redirect_uri"},
		{"empty redirect URIs", registrationBody(map[string]any{"redirect_uris": []string{}}), nil, "invalid_redirect_uri"},
		{"string redirect URIs", registrationBody(map[string]any{"redirect_uris": "https://a.example/cb"}), nil, "invalid_redirect_uri"},
		{"non-string redirect URI", registrationBody(map[string]any{"redirect_uris": []any{"https://a.example/cb", 1}}), nil, "invalid_redirect_uri"},
		{"custom schemes only", registrationBody(map[string]any{"redirect_uris": []string{"cursor://anysphere/cb"}}), nil, "invalid_redirect_uri"},
		{"33 redirect URIs", registrationBody(map[string]any{"redirect_uris": many(33, "app:/cb")}), nil, "invalid_redirect_uri"},
		{"17 usable redirect URIs", registrationBody(map[string]any{"redirect_uris": many(17, "https://a.example/cb")}), nil, "invalid_redirect_uri"},
		{"long name", registrationBody(map[string]any{"client_name": strings.Repeat("a", 256)}), nil, "invalid_client_metadata"},
		{"control in name", registrationBody(map[string]any{"client_name": "a‮b"}), nil, "invalid_client_metadata"},
		{"numeric name", registrationBody(map[string]any{"client_name": 1}), nil, "invalid_client_metadata"},
		{"implicit grant", registrationBody(map[string]any{"grant_types": []string{"implicit"}}), nil, "invalid_client_metadata"},
		{"token response", registrationBody(map[string]any{"response_types": []string{"token"}}), nil, "invalid_client_metadata"},
		{"numeric method", registrationBody(map[string]any{"token_endpoint_auth_method": 1}), nil, "invalid_client_metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var edit []func(*http.Request)
			if tc.edit != nil {
				edit = append(edit, tc.edit)
			}
			register(t, f.Server, tc.body, edit...).failed(t, http.StatusBadRequest, tc.code)
		})
	}
	// 16 usable entries among 32 are kept.
	r := register(t, f.Server, registrationBody(map[string]any{
		"redirect_uris": append(many(16, "https://a.example/cb"), many(16, "app:/cb")...)}))
	if r.status != http.StatusCreated || len(r.reg.RedirectURIs) != 16 {
		t.Fatalf("32 entries: %d %s", r.status, r.body)
	}
	// Any method but POST.
	w := httptest.NewRecorder()
	reg, err := f.Register(w, httptest.NewRequest(http.MethodGet, testRegisterEndpoint, nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodPost || w.Body.Len() != 0 ||
		!errors.Is(err, ErrInvalid) || reg.ID != "" {
		t.Fatalf("GET: %d %v %v", w.Code, w.Header(), err)
	}
	// A store failure is a 503.
	store.fail["CreateClient"] = ErrCollision
	r = register(t, f.Server, registrationBody(nil))
	if r.status != http.StatusServiceUnavailable || r.body != `{"error":"temporarily_unavailable"}` ||
		errors.Is(r.err, ErrInvalid) || !errors.Is(r.err, ErrCollision) {
		t.Fatalf("store failure: %d %s %v", r.status, r.body, r.err)
	}
	// Registration disabled.
	disabled := newFixture(t)
	w = httptest.NewRecorder()
	if _, err := disabled.Register(w, httptest.NewRequest(http.MethodPost, testRegisterEndpoint, strings.NewReader(registrationBody(nil)))); w.Code != http.StatusNotFound || err == nil {
		t.Fatalf("disabled: %d %v", w.Code, err)
	}
}

func TestRegisterInitialAccessToken(t *testing.T) {
	backend := errors.New("token backend down")
	f, _ := dcrFixture(t, func(c *Config) {
		c.Registration.InitialAccessToken = func(_ context.Context, token string) error {
			switch token {
			case "good":
				return nil
			case "down":
				return backend
			}
			return fmt.Errorf("%w: unknown initial access token", ErrInvalid)
		}
	})
	header := func(values ...string) func(*http.Request) {
		return func(r *http.Request) {
			for _, v := range values {
				r.Header.Add("Authorization", v)
			}
		}
	}
	if r := register(t, f.Server, registrationBody(nil), header("Bearer good")); r.status != http.StatusCreated {
		t.Fatalf("good token: %d %s", r.status, r.body)
	}
	if r := register(t, f.Server, registrationBody(nil), header("bearer good")); r.status != http.StatusCreated {
		t.Fatalf("lowercase scheme: %d %s", r.status, r.body)
	}
	r := register(t, f.Server, registrationBody(nil))
	r.failed(t, http.StatusUnauthorized, "")
	if r.header.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("missing token: %v", r.header)
	}
	for _, values := range [][]string{{"Basic Z29vZA=="}, {"Bearer "}, {"Bearer"}, {"Bearer good", "Bearer good"}} {
		r := register(t, f.Server, registrationBody(nil), header(values...))
		r.failed(t, http.StatusBadRequest, "invalid_request")
		if r.header.Get("WWW-Authenticate") != `Bearer error="invalid_request"` {
			t.Fatalf("%q: %v", values, r.header)
		}
	}
	r = register(t, f.Server, registrationBody(nil), header("Bearer bad"))
	r.failed(t, http.StatusUnauthorized, "invalid_token")
	if r.header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("rejected token: %v", r.header)
	}
	r = register(t, f.Server, registrationBody(nil), header("Bearer down"))
	if r.status != http.StatusServiceUnavailable || errors.Is(r.err, ErrInvalid) || !errors.Is(r.err, backend) {
		t.Fatalf("backend failure: %d %v", r.status, r.err)
	}
	// Without a token check, an Authorization header is ignored.
	open, _ := dcrFixture(t)
	if r := register(t, open.Server, registrationBody(nil), header("Basic x", "Bearer y")); r.status != http.StatusCreated {
		t.Fatalf("ignored header: %d %s", r.status, r.body)
	}
}

func TestRegistrationUnusedTTL(t *testing.T) {
	forever, store := dcrFixture(t, func(c *Config) { c.Registration.UnusedTTL = -1 })
	r := register(t, forever.Server, registrationBody(nil))
	if r.status != http.StatusCreated || !r.reg.ExpiresAt.IsZero() {
		t.Fatalf("negative lifetime: %+v", r.reg)
	}
	forever.advance(1000 * 24 * time.Hour)
	if _, err := forever.Authorize(t.Context(), dcrParams(r.reg.ID).Encode()); err != nil {
		t.Fatal(err)
	}
	short, _ := dcrFixture(t, func(c *Config) { c.Registration.UnusedTTL = 10 * time.Minute })
	r = register(t, short.Server, registrationBody(nil))
	if !r.reg.ExpiresAt.Equal(testStart.Add(10 * time.Minute)) {
		t.Fatalf("10 minutes: %+v", r.reg)
	}
	// The server checks the deadline itself.
	lax := &laxClientStore{MemoryClientStore: store.MemoryClientStore}
	f, _ := dcrFixture(t, func(c *Config) { c.Registration.Store = lax })
	r = register(t, f.Server, registrationBody(nil))
	f.advance(7 * 24 * time.Hour)
	if _, err := f.Authorize(t.Context(), dcrParams(r.reg.ID).Encode()); err != ErrUnknownClient {
		t.Fatalf("expired registration from a lax store: %v", err)
	}
}

// laxClientStore ignores expiry.
type laxClientStore struct{ *MemoryClientStore }

func (s *laxClientStore) Client(ctx context.Context, id string, _ time.Time) (Registration, error) {
	return s.MemoryClientStore.Client(ctx, id, time.Time{})
}

func TestRegistrationFlow(t *testing.T) {
	f, store := dcrFixture(t, func(c *Config) { c.RefreshIdle = 30 * 24 * time.Hour })
	id := register(t, f.Server, registrationBody(nil)).reg.ID
	req, err := f.Authorize(t.Context(), dcrParams(id).Encode())
	if err != nil || req.ClientSource != SourceRegistration || req.ClientHost != "" || req.ClientName != "Inspector" {
		t.Fatalf("request %+v %v", req, err)
	}
	params := dcrParams(id)
	params.Set("redirect_uri", "cursor://anysphere/cb")
	if _, err := f.Authorize(t.Context(), params.Encode()); err != ErrInvalid {
		t.Fatalf("dropped custom scheme: %v", err)
	}
	params.Set("redirect_uri", "http://localhost:51000/oauth/callback")
	if _, err := f.Authorize(t.Context(), params.Encode()); err != nil {
		t.Fatalf("loopback on another port: %v", err)
	}

	// The secret a registered client believes it has is ignored, by Basic
	// or in the body; an assertion is refused.
	form := exchangeForm(f.code(dcrParams(id), "alice"))
	form.Del("client_id")
	r := post(t, f.Token, form, basicAuth(id, "ignored"))
	g := granted(t, r)
	if r.event.ClientID != id || store.count("Activate") != 1 {
		t.Fatalf("event %+v, %d activations", r.event, store.count("Activate"))
	}
	// Activation keeps the registration past its unused lifetime.
	f.advance(8 * 24 * time.Hour)
	refresh := refreshForm(g.refresh)
	refresh.Set("client_id", id)
	refresh.Set("client_secret", "ignored")
	g = granted(t, post(t, f.Token, refresh))
	for _, name := range []string{"client_assertion", "client_assertion_type"} {
		form := refreshForm(g.refresh)
		form.Set("client_id", id)
		form.Set(name, "")
		post(t, f.Token, form).rejected(t, http.StatusUnauthorized, "invalid_client")
	}
	if r := post(t, f.Revocation, url.Values{"client_id": {id}, "token": {g.access}}); r.status != http.StatusOK || r.event.ConnectionID == "" {
		t.Fatalf("revocation %d %+v", r.status, r.event)
	}

	// An activation the store refuses fails the exchange.
	id = register(t, f.Server, registrationBody(nil)).reg.ID
	store.fail["Activate"] = ErrNotFound
	post(t, f.Token, dcrExchange(f.code(dcrParams(id), "bob"), id)).rejected(t, http.StatusBadRequest, "invalid_grant")
	if store.count("Activate") != 2 {
		t.Fatalf("%d activations", store.count("Activate"))
	}
	backend := errors.New("activation backend down")
	store.fail["Activate"] = backend
	post(t, f.Token, dcrExchange(f.code(dcrParams(id), "bob"), id)).unavailable(t, backend)
	if len(f.connections("bob")) != 0 {
		t.Fatal("a connection was created without activation")
	}
	delete(store.fail, "Activate")
	// A registration that expired before the exchange is unknown.
	code := f.code(dcrParams(id), "bob")
	f.advance(7 * 24 * time.Hour)
	post(t, f.Token, dcrExchange(code, id)).rejected(t, http.StatusUnauthorized, "invalid_client")
}

func TestRegistrationResolution(t *testing.T) {
	f, store := dcrFixture(t)
	id := register(t, f.Server, registrationBody(nil)).reg.ID
	// An identifier that is not a registration's format is not looked up.
	for _, other := range []string{"unknown", id + "x", strings.ToUpper(id[:1]) + "!" + id[2:]} {
		before := store.count("Client")
		if _, err := f.Authorize(t.Context(), dcrParams(other).Encode()); err != ErrUnknownClient || store.count("Client") != before {
			t.Fatalf("%q: %v", other, err)
		}
	}
	// A lookup failure never falls through to the registrations.
	f.lookupErr = errors.New("backend down")
	before := store.count("Client")
	if _, err := f.Authorize(t.Context(), dcrParams(id).Encode()); !errors.Is(err, f.lookupErr) || store.count("Client") != before {
		t.Fatalf("lookup failure: %v", err)
	}
	f.lookupErr = nil
	// A pre-registered client with the same identifier wins.
	f.clients[id] = Client{ID: id, Name: "Registered", RedirectURIs: []string{"https://app.example.com/cb"}}
	if req, err := f.Authorize(t.Context(), dcrParams(id).Encode()); err != nil || req.ClientSource != SourceLookup {
		t.Fatalf("pre-registered: %+v %v", req, err)
	}
	delete(f.clients, id)
	// A store failure is not an unknown client.
	backend := errors.New("store down")
	store.fail["Client"] = backend
	if _, err := f.Authorize(t.Context(), dcrParams(id).Encode()); !errors.Is(err, backend) || errors.Is(err, ErrInvalid) {
		t.Fatalf("store failure: %v", err)
	}
	delete(store.fail, "Client")
	// A record that does not match is invalid.
	odd := &oddClientStore{MemoryClientStore: NewMemoryClientStore()}
	g, _ := dcrFixture(t, func(c *Config) { c.Registration.Store = odd })
	id = register(t, g.Server, registrationBody(nil)).reg.ID
	if _, err := g.Authorize(t.Context(), dcrParams(id).Encode()); !errors.Is(err, ErrRecord) {
		t.Fatalf("mismatched record: %v", err)
	}
}

// oddClientStore returns records for another ID.
type oddClientStore struct{ *MemoryClientStore }

func (s *oddClientStore) Client(ctx context.Context, id string, now time.Time) (Registration, error) {
	reg, err := s.MemoryClientStore.Client(ctx, id, now)
	reg.ID += "x"
	return reg, err
}

func TestMemoryClientStoreCapacity(t *testing.T) {
	ctx := t.Context()
	s := NewMemoryClientStore()
	far := time.Now().Add(time.Hour)
	for i := range memoryClientCapacity {
		reg := Registration{ID: fmt.Sprintf("r%04d", i), RedirectURIs: []string{"https://a.example/cb"},
			CreatedAt: testStart.Add(time.Duration(i) * time.Second)}
		if i%2 == 0 {
			reg.ExpiresAt = far
		}
		if i == 10 {
			reg.ExpiresAt = time.Now().Add(-time.Second)
		}
		if err := s.CreateClient(ctx, reg); err != nil {
			t.Fatal(err)
		}
	}
	add := func(id string) error {
		return s.CreateClient(ctx, Registration{ID: id, RedirectURIs: []string{"https://a.example/cb"},
			CreatedAt: testStart.Add(10 * time.Hour), ExpiresAt: far})
	}
	// An expired registration goes first.
	if err := add("new-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Client(ctx, "r0010", testStart); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired registration kept: %v", err)
	}
	// Then the oldest that was never activated.
	if err := add("new-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Client(ctx, "r0000", testStart); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest unactivated registration kept: %v", err)
	}
	if _, err := s.Client(ctx, "r0001", testStart); err != nil {
		t.Fatalf("activated registration removed: %v", err)
	}
	// With only activated registrations the store is full.
	regs, err := s.Clients(ctx)
	if err != nil || len(regs) != memoryClientCapacity {
		t.Fatalf("%d registrations: %v", len(regs), err)
	}
	for _, reg := range regs {
		if err := s.Activate(ctx, reg.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := add("new-3"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("full store: %v", err)
	}
	if err := s.DeleteClient(ctx, "r0001"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteClient(ctx, "r0001"); err != nil {
		t.Fatal(err)
	}
	if err := add("new-3"); err != nil {
		t.Fatalf("after deletion: %v", err)
	}
	// Clients is ordered by CreatedAt and then ID.
	regs, _ = s.Clients(ctx)
	n := len(regs)
	if regs[0].ID != "r0002" || regs[1].ID != "r0003" || regs[n-3].ID != "new-1" || regs[n-2].ID != "new-2" || regs[n-1].ID != "new-3" {
		t.Fatalf("order %s %s ... %s %s %s", regs[0].ID, regs[1].ID, regs[n-3].ID, regs[n-2].ID, regs[n-1].ID)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Clients(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.DeleteClient(canceled, "new-1"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var zero MemoryClientStore
	if err := zero.CreateClient(ctx, Registration{ID: "z"}); err != nil {
		t.Fatal(err)
	}
}
