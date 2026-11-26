package mcpoauth

import (
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAuthorize(t *testing.T) {
	f := newFixture(t)
	got, err := f.Authorize(t.Context(), authParams().Encode()+"&unknown=1&unknown=2")
	if err != nil {
		t.Fatal(err)
	}
	want := Request{ClientID: "public", ClientName: "Public client", RedirectURI: "https://client.example/cb?keep=1&keep=2",
		Scopes: []string{"read", "write"}, State: "opaque state"}
	if got.ClientID != want.ClientID || got.ClientName != want.ClientName || got.RedirectURI != want.RedirectURI ||
		!slices.Equal(got.Scopes, want.Scopes) || got.State != want.State {
		t.Fatalf("request %+v", got)
	}
	if f.store.total() != 0 {
		t.Fatal("validation reached the store")
	}

	for _, tc := range []struct {
		name   string
		change func(url.Values)
		want   []string
	}{
		{"omitted scope", func(v url.Values) { v.Del("scope") }, []string{"read"}},
		{"empty scope", func(v url.Values) { v.Set("scope", "") }, []string{"read"}},
		{"only spaces", func(v url.Values) { v.Set("scope", "  ") }, []string{"read"}},
		{"order and duplicates", func(v url.Values) { v.Set("scope", " write  read write admin ") }, []string{"write", "read", "admin"}},
		{"omitted resource", func(v url.Values) { v.Del("resource") }, []string{"read", "write"}},
		{"empty resource", func(v url.Values) { v.Set("resource", "") }, []string{"read", "write"}},
		{"resource with a trailing slash", func(v url.Values) { v.Set("resource", testResource+"/") }, []string{"read", "write"}},
		{"resource with an uppercase host", func(v url.Values) { v.Set("resource", "HTTPS://MCP.Example/mcp") }, []string{"read", "write"}},
		{"omitted state", func(v url.Values) { v.Del("state") }, []string{"read", "write"}},
		{"longest state", func(v url.Values) { v.Set("state", strings.Repeat("s", 1024)) }, []string{"read", "write"}},
		{"loopback with a port", func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:51234/callback") }, []string{"read", "write"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := authParams()
			tc.change(params)
			got, err := f.Authorize(t.Context(), params.Encode())
			if err != nil || !slices.Equal(got.Scopes, tc.want) || got.RedirectURI != params.Get("redirect_uri") {
				t.Fatalf("request %+v, %v", got, err)
			}
		})
	}
	// The default scopes are copied for each request.
	params := authParams()
	params.Del("scope")
	first, _ := f.Authorize(t.Context(), params.Encode())
	first.Scopes[0] = "changed"
	if second, _ := f.Authorize(t.Context(), params.Encode()); second.Scopes[0] != "read" {
		t.Fatal("a request aliases the default scopes")
	}
}

// Failures before the client and redirect URI are verified never produce a
// redirect, whatever else is wrong with the request.
func TestAuthorizeUnverifiedClient(t *testing.T) {
	f := newFixture(t)
	f.clients["invalid"] = Client{ID: "invalid", RedirectURIs: []string{"app://callback"}}
	f.clients["renamed"] = Client{ID: "other", RedirectURIs: []string{"https://client.example/cb"}}
	raw := func(change func(url.Values)) string {
		params := authParams()
		// Every case also carries failures that would otherwise be reported.
		params.Set("response_type", "token")
		params.Del("code_challenge")
		change(params)
		return params.Encode()
	}
	for _, tc := range []struct {
		name  string
		query string
		want  error
	}{
		{"empty query", "", ErrInvalid},
		{"long query", raw(func(v url.Values) { v.Set("unknown", strings.Repeat("x", 8192)) }), ErrInvalid},
		{"semicolon", raw(func(url.Values) {}) + ";scope=admin", ErrInvalid},
		{"invalid percent-encoding", raw(func(url.Values) {}) + "&scope=%zz", ErrInvalid},
		{"invalid percent-encoding of an unknown parameter", raw(func(url.Values) {}) + "&unknown=%", ErrInvalid},
		{"repeated client_id", raw(func(v url.Values) { v.Add("client_id", "public") }), ErrInvalid},
		{"repeated redirect_uri", raw(func(v url.Values) { v.Add("redirect_uri", "https://client.example/cb?keep=1&keep=2") }), ErrInvalid},
		{"repeated response_type", raw(func(v url.Values) { v.Add("response_type", "code") }), ErrInvalid},
		{"repeated scope", raw(func(v url.Values) { v.Add("scope", "read") }), ErrInvalid},
		{"repeated state", raw(func(v url.Values) { v.Add("state", "") }), ErrInvalid},
		{"repeated code_challenge", raw(func(v url.Values) { v["code_challenge"] = []string{"a", "b"} }), ErrInvalid},
		{"repeated code_challenge_method", raw(func(v url.Values) { v.Add("code_challenge_method", "S256") }), ErrInvalid},
		{"repeated resource", raw(func(v url.Values) { v.Add("resource", testResource) }), ErrInvalid},
		{"missing client_id", raw(func(v url.Values) { v.Del("client_id") }), ErrInvalid},
		{"malformed client_id", raw(func(v url.Values) { v.Set("client_id", "pub lic") }), ErrInvalid},
		{"unknown client", raw(func(v url.Values) { v.Set("client_id", "unknown") }), ErrInvalid},
		{"invalid client record", raw(func(v url.Values) { v.Set("client_id", "invalid"); v.Set("redirect_uri", "app://callback") }), ErrRecord},
		{"client record with another ID", raw(func(v url.Values) { v.Set("client_id", "renamed") }), ErrRecord},
		{"missing redirect_uri", raw(func(v url.Values) { v.Del("redirect_uri") }), ErrInvalid},
		{"empty redirect_uri", raw(func(v url.Values) { v.Set("redirect_uri", "") }), ErrInvalid},
		{"unregistered redirect_uri", raw(func(v url.Values) { v.Set("redirect_uri", "https://attacker.example/cb") }), ErrInvalid},
		{"redirect_uri without its query", raw(func(v url.Values) { v.Set("redirect_uri", "https://client.example/cb") }), ErrInvalid},
		{"redirect_uri of another client", raw(func(v url.Values) { v.Set("redirect_uri", "https://app.example/cb") }), ErrInvalid},
		{"loopback path", raw(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:51234/other") }), ErrInvalid},
		{"long state", raw(func(v url.Values) { v.Set("state", strings.Repeat("s", 1025)) }), ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.Authorize(t.Context(), tc.query)
			_, redirect, errApprove := f.Approve(t.Context(), tc.query, "user")
			denied, errDeny := f.Deny(t.Context(), tc.query)
			for _, err := range []error{err, errApprove, errDeny} {
				var reject *RejectError
				if !errors.Is(err, tc.want) || errors.As(err, &reject) || errors.Is(tc.want, ErrRecord) && errors.Is(err, ErrInvalid) {
					t.Fatalf("error %v, want %v", err, tc.want)
				}
			}
			if redirect != "" || denied != "" || f.store.total() != 0 {
				t.Fatalf("redirect %q %q, store calls %d", redirect, denied, f.store.total())
			}
		})
	}

	down := errors.New("directory down")
	f.lookupErr = down
	_, err := f.Authorize(t.Context(), authParams().Encode())
	if !errors.Is(err, down) || errors.Is(err, ErrInvalid) || !strings.HasPrefix(err.Error(), "mcpoauth: lookup client: ") {
		t.Fatalf("lookup failure: %v", err)
	}
}

func TestAuthorizeRejected(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name   string
		change func(url.Values)
		want   string
	}{
		{"omitted response_type", func(v url.Values) { v.Del("response_type") }, "invalid_request"},
		{"empty response_type", func(v url.Values) { v.Set("response_type", "") }, "invalid_request"},
		{"token response_type", func(v url.Values) { v.Set("response_type", "token") }, "unsupported_response_type"},
		{"omitted method", func(v url.Values) { v.Del("code_challenge_method") }, "invalid_request"},
		{"plain method", func(v url.Values) { v.Set("code_challenge_method", "plain") }, "invalid_request"},
		{"lowercase method", func(v url.Values) { v.Set("code_challenge_method", "s256") }, "invalid_request"},
		{"omitted challenge", func(v url.Values) { v.Del("code_challenge") }, "invalid_request"},
		{"short challenge", func(v url.Values) { v.Set("code_challenge", challengeOf(testVerifier)[:42]) }, "invalid_request"},
		{"padded challenge", func(v url.Values) { v.Set("code_challenge", challengeOf(testVerifier)+"=") }, "invalid_request"},
		{"challenge with trailing bits", func(v url.Values) { v.Set("code_challenge", challengeOf(testVerifier)[:42]+"B") }, "invalid_request"},
		{"challenge in the standard alphabet", func(v url.Values) { v.Set("code_challenge", strings.Repeat("+", 42)+"A") }, "invalid_request"},
		{"other resource path", func(v url.Values) { v.Set("resource", "https://mcp.example/other") }, "invalid_target"},
		{"resource of the issuer", func(v url.Values) { v.Set("resource", testIssuer) }, "invalid_target"},
		{"resource root", func(v url.Values) { v.Set("resource", "https://mcp.example") }, "invalid_target"},
		{"resource with a query", func(v url.Values) { v.Set("resource", testResource+"?x=1") }, "invalid_target"},
		{"resource with an empty query", func(v url.Values) { v.Set("resource", testResource+"?") }, "invalid_target"},
		{"resource with a fragment", func(v url.Values) { v.Set("resource", testResource+"#x") }, "invalid_target"},
		{"resource with two trailing slashes", func(v url.Values) { v.Set("resource", testResource+"//") }, "invalid_target"},
		{"resource with user information", func(v url.Values) { v.Set("resource", "https://u@mcp.example/mcp") }, "invalid_target"},
		{"http resource", func(v url.Values) { v.Set("resource", "http://mcp.example/mcp") }, "invalid_target"},
		{"unknown scope", func(v url.Values) { v.Set("scope", "read other") }, "invalid_scope"},
		{"scope separated by a tab", func(v url.Values) { v.Set("scope", "read\twrite") }, "invalid_scope"},
		// Evaluation order.
		{"response_type before PKCE", func(v url.Values) { v.Set("response_type", "token"); v.Del("code_challenge_method") }, "unsupported_response_type"},
		{"PKCE before resource", func(v url.Values) { v.Set("code_challenge_method", "plain"); v.Set("resource", testIssuer) }, "invalid_request"},
		{"resource before scope", func(v url.Values) { v.Set("resource", testIssuer); v.Set("scope", "other") }, "invalid_target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := authParams()
			tc.change(params)
			_, err := f.Authorize(t.Context(), params.Encode())
			_, redirect, errApprove := f.Approve(t.Context(), params.Encode(), "user")
			denied, errDeny := f.Deny(t.Context(), params.Encode())
			for _, err := range []error{err, errApprove, errDeny} {
				var reject *RejectError
				if !errors.As(err, &reject) || !errors.Is(err, ErrInvalid) || reject.Code != tc.want ||
					err.Error() != "mcpoauth: authorization rejected: "+tc.want {
					t.Fatalf("error %v, want %s", err, tc.want)
				}
				u, err := url.Parse(reject.RedirectURL)
				if err != nil {
					t.Fatal(err)
				}
				query := u.Query()
				if u.Scheme+"://"+u.Host+u.Path != "https://client.example/cb" || !slices.Equal(query["keep"], []string{"1", "2"}) ||
					query.Get("error") != tc.want || query.Get("state") != "opaque state" || query.Get("iss") != testIssuer ||
					query.Has("code") || len(query) != 4 {
					t.Fatalf("redirect %q", reject.RedirectURL)
				}
				want := Request{ClientID: "public", ClientName: "Public client", RedirectURI: "https://client.example/cb?keep=1&keep=2", State: "opaque state"}
				if got := reject.Request; got.ClientID != want.ClientID || got.ClientName != want.ClientName ||
					got.RedirectURI != want.RedirectURI || got.State != want.State || got.Scopes != nil {
					t.Fatalf("request %+v", got)
				}
			}
			if redirect != "" || denied != "" || f.store.total() != 0 {
				t.Fatalf("redirect %q %q, store calls %d", redirect, denied, f.store.total())
			}
		})
	}
}

func TestApproveAndDeny(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, redirectURI, state, base string
	}{
		{"registered query", "https://client.example/cb?keep=1&keep=2", "opaque state", "https://client.example/cb"},
		{"loopback port", "http://127.0.0.1:51234/callback", "", "http://127.0.0.1:51234/callback"},
		{"localhost port", "http://localhost:8080/callback", "s", "http://localhost:8080/callback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := authParams()
			params.Set("redirect_uri", tc.redirectURI)
			params.Set("state", tc.state)
			check := func(redirect, name string) url.Values {
				t.Helper()
				u, err := url.Parse(redirect)
				if err != nil {
					t.Fatal(err)
				}
				query, other := u.Query(), map[string]string{"code": "error", "error": "code"}[name]
				if u.Scheme+"://"+u.Host+u.Path != tc.base || query.Get("iss") != testIssuer || query.Get("state") != tc.state ||
					query.Has("state") != (tc.state != "") || !query.Has(name) || query.Has(other) || u.Fragment != "" {
					t.Fatalf("redirect %q", redirect)
				}
				return query
			}
			before := f.store.total()
			denied, err := f.Deny(t.Context(), params.Encode())
			if err != nil || check(denied, "error").Get("error") != "access_denied" || f.store.total() != before {
				t.Fatalf("deny %q, %v", denied, err)
			}
			request, redirect, err := f.Approve(t.Context(), params.Encode(), "user")
			if err != nil {
				t.Fatal(err)
			}
			if request.ClientID != "public" || request.RedirectURI != tc.redirectURI || request.State != tc.state ||
				!slices.Equal(request.Scopes, []string{"read", "write"}) {
				t.Fatalf("request %+v", request)
			}
			code := check(redirect, "code").Get("code")
			record, _, err := f.store.MemoryStore.TakeCode(t.Context(), f.key("code", code), f.now())
			if err != nil {
				t.Fatal(err)
			}
			if record.ClientID != "public" || record.RedirectURI != tc.redirectURI || record.Subject != "user" ||
				!slices.Equal(record.Scopes, []string{"read", "write"}) || record.Challenge != challengeOf(testVerifier) ||
				!record.ExpiresAt.Equal(f.now().Add(time.Minute)) {
				t.Fatalf("record %+v", record)
			}
		})
	}

	before := f.store.total()
	if _, redirect, err := f.Approve(t.Context(), authParams().Encode(), ""); err == nil ||
		err.Error() != "mcpoauth: subject is required" || redirect != "" || f.store.total() != before {
		t.Fatalf("empty subject: %q, %v", redirect, err)
	}
	// The subject is checked before the request.
	if _, _, err := f.Approve(t.Context(), "", ""); err == nil || errors.Is(err, ErrInvalid) {
		t.Fatalf("empty subject with an invalid request: %v", err)
	}
	// Two approvals of one request issue independent codes.
	if a, b := f.code(authParams(), "user"), f.code(authParams(), "user"); a == b {
		t.Fatal("repeated code")
	}
}

// restrict replaces the public client's record with one limited to scopes.
func (f *fixture) restrict(scopes ...string) {
	client := f.clients["public"]
	client.RestrictScopes, client.Scopes = true, scopes
	f.clients["public"] = client
}

func TestAuthorizeClientScopes(t *testing.T) {
	const rejected = "invalid_scope"
	twoDefaults := func(c *Config) { c.DefaultScopes = []string{"read", "write"} }
	for _, tc := range []struct {
		name   string
		config []func(*Config)
		list   []string
		scope  string // "-" omits the parameter
		want   string // the granted scopes, or rejected
	}{
		{name: "listed scopes", list: []string{"write", "read"}, scope: "write read", want: "write read"},
		{name: "one listed scope", list: []string{"write", "read"}, scope: "read", want: "read"},
		{name: "scope outside the list", list: []string{"write", "read"}, scope: "read admin", want: rejected},
		{name: "only a scope outside the list", list: []string{"write", "read"}, scope: "admin", want: rejected},
		{name: "unknown scope", list: []string{"write", "read", "other"}, scope: "read other", want: rejected},
		{name: "omitted scope in the default order", config: []func(*Config){twoDefaults}, list: []string{"write", "read"}, scope: "-", want: "read write"},
		{name: "empty scope in the default order", config: []func(*Config){twoDefaults}, list: []string{"admin", "write", "read"}, scope: " ", want: "read write"},
		{name: "omitted scope with part of the defaults", config: []func(*Config){twoDefaults}, list: []string{"admin", "write"}, scope: "-", want: "write"},
		{name: "omitted scope without a listed default", list: []string{"admin", "write"}, scope: "-", want: rejected},
		{name: "named scope without a listed default", list: []string{"admin", "write"}, scope: "write admin", want: "write admin"},
		{name: "list outside the configuration", list: []string{"other"}, scope: "-", want: rejected},
		{name: "list outside the configuration with a known scope", list: []string{"other"}, scope: "read", want: rejected},
		{name: "list outside the configuration with its own scope", list: []string{"other"}, scope: "other", want: rejected},
		{name: "nil list", list: nil, scope: "-", want: rejected},
		{name: "nil list with a scope", list: nil, scope: "read", want: rejected},
		{name: "nil list with every scope", list: nil, scope: "read write admin", want: rejected},
		{name: "empty list", list: []string{}, scope: "-", want: rejected},
		{name: "empty list with a scope", list: []string{}, scope: "read", want: rejected},
		{name: "empty list with every scope", list: []string{}, scope: "read write admin", want: rejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.config...)
			f.restrict(tc.list...)
			params := authParams()
			if tc.scope == "-" {
				params.Del("scope")
			} else {
				params.Set("scope", tc.scope)
			}
			request, err := f.Authorize(t.Context(), params.Encode())
			denied, errDeny := f.Deny(t.Context(), params.Encode())
			if tc.want != rejected {
				if err != nil || errDeny != nil || denied == "" || strings.Join(request.Scopes, " ") != tc.want {
					t.Fatalf("request %+v, %v, deny %q, %v", request, err, denied, errDeny)
				}
				approved, redirect, err := f.Approve(t.Context(), params.Encode(), "user")
				if err != nil || strings.Join(approved.Scopes, " ") != tc.want {
					t.Fatalf("approved %+v, %v", approved, err)
				}
				u, err := url.Parse(redirect)
				if err != nil {
					t.Fatal(err)
				}
				record, _, err := f.store.MemoryStore.TakeCode(t.Context(), f.key("code", u.Query().Get("code")), f.now())
				if err != nil || strings.Join(record.Scopes, " ") != tc.want {
					t.Fatalf("record %+v, %v", record, err)
				}
				return
			}
			_, redirect, errApprove := f.Approve(t.Context(), params.Encode(), "user")
			for name, err := range map[string]error{"authorize": err, "approve": errApprove, "deny": errDeny} {
				var reject *RejectError
				if !errors.As(err, &reject) || reject.Code != rejected || reject.Request.Scopes != nil ||
					reject.Request.ClientID != "public" {
					t.Fatalf("%s: error %v", name, err)
				}
				u, err := url.Parse(reject.RedirectURL)
				if err != nil || u.Query().Get("error") != rejected || u.Query().Has("code") {
					t.Fatalf("%s: redirect %q, %v", name, reject.RedirectURL, err)
				}
			}
			if request.Scopes != nil || redirect != "" || denied != "" || f.store.total() != 0 {
				t.Fatalf("request %+v, redirect %q %q, store calls %d", request, redirect, denied, f.store.total())
			}
		})
	}

	// A list on an unrestricted client is an invalid record, not a limit.
	f := newFixture(t)
	client := f.clients["public"]
	client.Scopes = []string{"read"}
	f.clients["public"] = client
	_, err := f.Authorize(t.Context(), authParams().Encode())
	var reject *RejectError
	if !errors.Is(err, ErrRecord) || errors.Is(err, ErrInvalid) || errors.As(err, &reject) {
		t.Fatalf("invalid scope list: %v", err)
	}
}
