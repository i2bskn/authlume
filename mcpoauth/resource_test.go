package mcpoauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	access, err := f.Verify(bearer(g.access))
	if err != nil {
		t.Fatal(err)
	}
	if access.ConnectionID != g.id || access.Subject != "user" || access.ClientID != "public" ||
		!slices.Equal(access.Scopes, []string{"read", "write"}) || !access.ExpiresAt.Equal(testStart.Add(time.Hour)) {
		t.Fatalf("access %+v", access)
	}
	if !access.Has() || !access.Has("read") || !access.Has("write", "read") || access.Has("admin") || access.Has("read", "admin") {
		t.Fatal("scope check")
	}

	header := func(values ...string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, testResource, nil)
		for _, value := range values {
			r.Header.Add("Authorization", value)
		}
		return r
	}
	before := f.store.calls["Use"]
	for name, r := range map[string]*http.Request{
		"no header":            header(),
		"empty header":         header(""),
		"scheme only":          header("Bearer"),
		"scheme and space":     header("Bearer "),
		"token only":           header(g.access),
		"Basic scheme":         header("Basic " + g.access),
		"two spaces":           header("Bearer  " + g.access),
		"tab":                  header("Bearer\t" + g.access),
		"trailing space":       header("Bearer " + g.access + " "),
		"trailing parameter":   header("Bearer " + g.access + ", x=1"),
		"truncated token":      header("Bearer " + g.access[:42]),
		"padded token":         header("Bearer " + g.access + "="),
		"trailing bits":        header("Bearer " + strings.Repeat("A", 42) + "B"),
		"standard alphabet":    header("Bearer " + strings.Repeat("+", 42) + "A"),
		"refresh token":        header("Bearer " + g.refresh),
		"repeated header":      header("Bearer "+g.access, "Bearer "+g.access),
		"token in the URL":     httptest.NewRequest(http.MethodGet, testResource+"?access_token="+g.access, nil),
		"token in a form body": httptest.NewRequest(http.MethodPost, testResource, strings.NewReader("access_token="+g.access)),
	} {
		if _, err := f.Verify(r); err != ErrInvalid || f.store.calls["Use"] != before {
			t.Fatalf("%s: %v, store calls %d", name, err, f.store.calls["Use"]-before)
		}
	}
	for name, r := range map[string]*http.Request{
		"unknown token":  bearer(randomValue()),
		"connection ID":  bearer(g.id),
		"code as token":  bearer(f.code(authParams(), "user")),
		"lowercase":      header("bearer " + g.access),
		"uppercase":      header("BEARER " + g.access),
		"with a URL too": httptest.NewRequest(http.MethodGet, testResource+"?access_token=x", nil),
	} {
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+g.access)
		}
		_, err := f.Verify(r)
		if valid := strings.Contains(name, "case") || strings.Contains(name, "URL"); (err == nil) != valid || (err != nil && err != ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// Verification never extends a deadline.
	f.advance(time.Hour - time.Nanosecond)
	if !f.valid(g.access) {
		t.Fatal("the access token expired early")
	}
	f.advance(time.Nanosecond)
	if f.valid(g.access) {
		t.Fatal("verification extended the access token")
	}
	if conn, err := f.stored(g.refresh); err != nil || !conn.AccessExpiry.Equal(testStart.Add(time.Hour)) || !conn.RefreshedAt.Equal(testStart) {
		t.Fatalf("verification changed the connection: %+v, %v", conn, err)
	}
}

func TestVerifyStoredRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Connection)
		want   error
		scopes []string
	}{
		{name: "intact", change: func(*Connection) {}, scopes: []string{"read", "write"}},
		{name: "empty client", change: func(c *Connection) { c.ClientID = "" }, scopes: []string{"read", "write"}},
		{name: "scope removed from the configuration", change: func(c *Connection) { c.Scopes = []string{"gone", "write"} }, scopes: []string{"write"}},
		{name: "other access digest", change: func(c *Connection) { c.Access[0] ^= 1 }, want: ErrRecord},
		{name: "empty ID", change: func(c *Connection) { c.ID = "" }, want: ErrRecord},
		{name: "empty subject", change: func(c *Connection) { c.Subject = "" }, want: ErrRecord},
		{name: "expired access token", change: func(c *Connection) { c.AccessExpiry = testStart }, want: ErrInvalid},
		{name: "expired connection", change: func(c *Connection) { c.AbsoluteExpiry = testStart }, want: ErrInvalid},
		{name: "no remaining scope", change: func(c *Connection) { c.Scopes = []string{"gone"} }, want: ErrInvalid},
		{name: "no scope", change: func(c *Connection) { c.Scopes = nil }, want: ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			g := f.connect("user")
			f.store.conn = tc.change
			access, err := f.Verify(bearer(g.access))
			if err != tc.want || !slices.Equal(access.Scopes, tc.scopes) || (err != nil && access.Subject != "") {
				t.Fatalf("access %+v, %v", access, err)
			}
			if errors.Is(tc.want, ErrRecord) && errors.Is(err, ErrInvalid) {
				t.Fatal("an invalid record is reported as an invalid token")
			}
		})
	}

	// A server that no longer defines a scope stops granting it.
	f := newFixture(t)
	g := f.connect("user")
	narrowed := f.peer(func(c *Config) { c.Scopes = []string{"write", "admin"}; c.DefaultScopes = []string{"admin"} })
	access, err := narrowed.Verify(bearer(g.access))
	if err != nil || !slices.Equal(access.Scopes, []string{"write"}) || access.Has("read") {
		t.Fatalf("access %+v, %v", access, err)
	}
	removed := f.peer(func(c *Config) { c.Scopes = []string{"admin"}; c.DefaultScopes = []string{"admin"} })
	if _, err := removed.Verify(bearer(g.access)); err != ErrInvalid {
		t.Fatalf("no remaining scope: %v", err)
	}
	// The earlier of the two deadlines is reported.
	absolute := newFixture(t, func(c *Config) { c.ConnectionAbsolute = 90 * time.Minute })
	g = absolute.connect("user")
	absolute.advance(45 * time.Minute)
	g = granted(t, absolute.refresh(g.refresh))
	if access, err := absolute.Verify(bearer(g.access)); err != nil || !access.ExpiresAt.Equal(testStart.Add(90*time.Minute)) {
		t.Fatalf("access %+v, %v", access, err)
	}
}

func TestChallenge(t *testing.T) {
	f := newFixture(t)
	const metadata = `resource_metadata="` + metadataURL + `"`
	anonymous := httptest.NewRequest(http.MethodGet, testResource, nil)
	for _, tc := range []struct {
		name   string
		r      *http.Request
		err    error
		scopes []string
		status int
		want   string
	}{
		{"no credentials", anonymous, ErrInvalid, nil, 401, "Bearer " + metadata},
		{"no credentials with scopes", anonymous, ErrInvalid, []string{"read", "write"}, 401, "Bearer " + metadata + `, scope="read write"`},
		{"invalid token", bearer("x"), ErrInvalid, nil, 401, `Bearer error="invalid_token", ` + metadata},
		{"invalid token with a scope", bearer("x"), ErrInvalid, []string{"read"}, 401, `Bearer error="invalid_token", ` + metadata + `, scope="read"`},
		{"wrapped error", bearer("x"), ErrReused, nil, 401, `Bearer error="invalid_token", ` + metadata},
		{"other scheme", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, testResource, nil)
			r.SetBasicAuth("user", "password")
			return r
		}(), ErrInvalid, nil, 401, `Bearer error="invalid_token", ` + metadata},
		{"unsafe scopes", anonymous, ErrInvalid, []string{`a"b`, "read", "has space", "", `back\slash`, "café", "write"}, 401, "Bearer " + metadata + `, scope="read write"`},
		{"only unsafe scopes", anonymous, ErrInvalid, []string{`", error="x`}, 401, "Bearer " + metadata},
		{"undefined scope", anonymous, ErrInvalid, []string{"other"}, 401, "Bearer " + metadata + `, scope="other"`},
		{"backend failure", bearer("x"), errors.New("backend down"), []string{"read"}, 503, ""},
		{"invalid record", bearer("x"), ErrRecord, nil, 503, ""},
		{"canceled", bearer("x"), context.Canceled, nil, 503, ""},
		{"nil error", bearer("x"), nil, nil, 503, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			f.Challenge(w, tc.r, tc.err, tc.scopes...)
			if w.Code != tc.status || w.Header().Get("WWW-Authenticate") != tc.want ||
				w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() != 0 {
				t.Fatalf("status %d header %v body %q", w.Code, w.Header(), w.Body)
			}
		})
	}

	for _, tc := range []struct {
		required []string
		want     string
	}{
		{nil, `Bearer error="insufficient_scope", ` + metadata},
		{[]string{"write"}, `Bearer error="insufficient_scope", ` + metadata + `, scope="write"`},
		{[]string{"read", `a"b`, "write"}, `Bearer error="insufficient_scope", ` + metadata + `, scope="read write"`},
	} {
		w := httptest.NewRecorder()
		f.InsufficientScope(w, tc.required...)
		if w.Code != http.StatusForbidden || w.Header().Get("WWW-Authenticate") != tc.want ||
			w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() != 0 {
			t.Fatalf("status %d header %v body %q", w.Code, w.Header(), w.Body)
		}
	}

	// The metadata URL of a resource without a path.
	root := f.peer(func(c *Config) { c.Resource = "https://mcp.example:8443" })
	w := httptest.NewRecorder()
	root.Challenge(w, anonymous, ErrInvalid)
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer resource_metadata="https://mcp.example:8443/.well-known/oauth-protected-resource"` {
		t.Fatalf("challenge %q", got)
	}
}

func TestProtect(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	params := authParams()
	params.Del("scope")
	reader := granted(t, post(t, f.Token, exchangeForm(f.code(params, "reader"))))
	const metadata = `resource_metadata="` + metadataURL + `"`

	var seen []Access
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, ok := FromContext(r.Context())
		if !ok {
			t.Error("no access in the request context")
		}
		seen = append(seen, access)
		w.WriteHeader(http.StatusNoContent)
	})
	for _, tc := range []struct {
		name     string
		r        *http.Request
		required []string
		status   int
		want     string
	}{
		{"granted", bearer(g.access), []string{"read", "write"}, 204, ""},
		{"no required scope", bearer(reader.access), nil, 204, ""},
		{"default scope", bearer(reader.access), []string{"read"}, 204, ""},
		{"insufficient scope", bearer(reader.access), []string{"read", "write"}, 403,
			`Bearer error="insufficient_scope", ` + metadata + `, scope="read write"`},
		{"scope defined but not granted", bearer(g.access), []string{"admin"}, 403,
			`Bearer error="insufficient_scope", ` + metadata + `, scope="admin"`},
		{"undefined required scope", bearer(g.access), []string{"read", "other"}, 403,
			`Bearer error="insufficient_scope", ` + metadata + `, scope="read other"`},
		{"no token", httptest.NewRequest(http.MethodGet, testResource, nil), []string{"write"}, 401,
			"Bearer " + metadata + `, scope="write"`},
		{"unknown token", bearer(randomValue()), []string{"write"}, 401,
			`Bearer error="invalid_token", ` + metadata + `, scope="write"`},
		{"malformed token", bearer("x"), nil, 401, `Bearer error="invalid_token", ` + metadata},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen = nil
			w := httptest.NewRecorder()
			f.Protect(next, tc.required...).ServeHTTP(w, tc.r)
			if w.Code != tc.status || w.Header().Get("WWW-Authenticate") != tc.want || (tc.status == 204) != (len(seen) == 1) {
				t.Fatalf("status %d header %v, handler calls %d", w.Code, w.Header(), len(seen))
			}
			if tc.status != 204 && (w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() != 0) {
				t.Fatalf("header %v body %q", w.Header(), w.Body)
			}
		})
	}

	seen = nil
	f.Protect(next, "read").ServeHTTP(httptest.NewRecorder(), bearer(g.access))
	if len(seen) != 1 || seen[0].ConnectionID != g.id || seen[0].Subject != "user" || seen[0].ClientID != "public" ||
		!slices.Equal(seen[0].Scopes, []string{"read", "write"}) {
		t.Fatalf("access %+v", seen)
	}
	// The required scopes are copied when the handler is built.
	required := []string{"read"}
	protected := f.Protect(next, required...)
	required[0] = "admin"
	w := httptest.NewRecorder()
	protected.ServeHTTP(w, bearer(reader.access))
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d", w.Code)
	}
	if _, ok := FromContext(t.Context()); ok {
		t.Fatal("access in an unrelated context")
	}
}
