package mcpoauth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func basicAuth(user, password string) func(*http.Request) {
	return func(r *http.Request) { r.SetBasicAuth(user, password) }
}

// stored returns the connection of a refresh token, whatever its deadlines.
func (f *fixture) stored(refresh string) (Connection, error) {
	encoded, _ := refreshSelector(refresh)
	return f.store.MemoryStore.Lookup(f.t.Context(), f.key("selector", encoded), testStart.Add(-time.Hour))
}

func (f *fixture) valid(access string) bool {
	f.t.Helper()
	_, err := f.Verify(bearer(access))
	if err != nil && !errors.Is(err, ErrInvalid) {
		f.t.Fatal(err)
	}
	return err == nil
}

func TestTokenExchange(t *testing.T) {
	f := newFixture(t)
	f.advance(1500 * time.Millisecond)
	r := post(t, f.Token, exchangeForm(f.code(authParams(), "user")))
	g := granted(t, r)
	if !strings.HasPrefix(r.body, `{"access_token":"`) || r.fields["expires_in"] != float64(3600) || r.field("scope") != "read write" ||
		len(r.fields) != 5 || r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" ||
		r.header.Get("Content-Type") != "application/json" {
		t.Fatalf("response %q, header %v", r.body, r.header)
	}
	if want := (Event{Grant: "authorization_code", ClientID: "public", ConnectionID: g.id, Subject: "user"}); r.event != want {
		t.Fatalf("event %+v", r.event)
	}
	conn, err := f.stored(g.refresh)
	if err != nil {
		t.Fatal(err)
	}
	now := f.now()
	if conn.ID != g.id || conn.Subject != "user" || conn.ClientID != "public" || strings.Join(conn.Scopes, " ") != "read write" ||
		!conn.CreatedAt.Equal(now) || !conn.RefreshedAt.Equal(now) || !conn.AbsoluteExpiry.IsZero() ||
		!conn.AccessExpiry.Equal(now.Add(time.Hour)) || !conn.RefreshExpiry.Equal(now.Add(2*time.Hour)) ||
		conn.Access != f.key("access", g.access) || conn.Refresh != f.key("refresh", g.refresh) {
		t.Fatalf("connection %+v", conn)
	}
	// The connection ID is independent of the token values.
	if strings.Contains(g.refresh, g.id) || g.id == g.access {
		t.Fatal("connection ID derived from a token")
	}

	// A confidential client and a second consent by the same user and client.
	params := authParams()
	params.Set("client_id", "confidential")
	params.Set("redirect_uri", "https://app.example/cb")
	params.Del("scope")
	form := exchangeForm(f.code(params, "user"))
	form.Del("client_id")
	r = post(t, f.Token, form, basicAuth("confidential", testSecret))
	other := granted(t, r)
	if r.field("scope") != "read" || r.event.ClientID != "confidential" || other.id == g.id {
		t.Fatalf("response %q, event %+v", r.body, r.event)
	}
	again := f.connect("user")
	if len(f.connections("user")) != 3 || !f.valid(g.access) || !f.valid(again.access) {
		t.Fatal("a repeated consent replaced a connection")
	}

	// A code issued without an absolute lifetime keeps the configured one.
	absolute := newFixture(t, func(c *Config) { c.ConnectionAbsolute = 3 * time.Hour })
	g = absolute.connect("user")
	if conn, _ := absolute.stored(g.refresh); !conn.AbsoluteExpiry.Equal(testStart.Add(3 * time.Hour)) {
		t.Fatalf("absolute deadline %v", conn.AbsoluteExpiry)
	}
}

func TestTokenExchangeRejected(t *testing.T) {
	loopback := authParams()
	loopback.Set("redirect_uri", "http://127.0.0.1:51234/callback")
	for _, tc := range []struct {
		name   string
		params url.Values
		change func(url.Values)
		edit   func(*http.Request)
		status int
		want   string // empty for success
		reach  bool   // the store consumed the code
	}{
		{name: "matching redirect_uri", change: func(v url.Values) { v.Set("redirect_uri", "https://client.example/cb?keep=1&keep=2") }, reach: true},
		{name: "empty redirect_uri", change: func(v url.Values) { v.Set("redirect_uri", "") }, reach: true},
		{name: "matching resource", change: func(v url.Values) { v.Set("resource", testResource+"/") }, reach: true},
		{name: "empty resource and scope", change: func(v url.Values) { v.Set("resource", ""); v.Set("scope", "") }, reach: true},
		{name: "longest verifier", params: func() url.Values {
			v := authParams()
			v.Set("code_challenge", challengeOf(strings.Repeat("v", 128)))
			return v
		}(), change: func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 128)) }, reach: true},
		{name: "loopback redirect_uri with the same port", params: loopback,
			change: func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:51234/callback") }, reach: true},
		{name: "loopback redirect_uri with another port", params: loopback,
			change: func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:51235/callback") }, status: 400, want: "invalid_grant", reach: true},
		{name: "other redirect_uri", change: func(v url.Values) { v.Set("redirect_uri", "https://client.example/cb") }, status: 400, want: "invalid_grant", reach: true},
		{name: "reordered redirect_uri query", change: func(v url.Values) { v.Set("redirect_uri", "https://client.example/cb?keep=2&keep=1") }, status: 400, want: "invalid_grant", reach: true},
		{name: "other verifier", change: func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 43)) }, status: 400, want: "invalid_grant", reach: true},
		{name: "challenge as verifier", change: func(v url.Values) { v.Set("code_verifier", challengeOf(testVerifier)) }, status: 400, want: "invalid_grant", reach: true},
		{name: "other client", change: func(v url.Values) { v.Set("client_id", "confidential"); v.Set("client_secret", testSecret) }, status: 400, want: "invalid_grant", reach: true},
		{name: "missing code", change: func(v url.Values) { v.Del("code") }, status: 400, want: "invalid_request"},
		{name: "missing verifier", change: func(v url.Values) { v.Del("code_verifier") }, status: 400, want: "invalid_request"},
		{name: "empty verifier", change: func(v url.Values) { v.Set("code_verifier", "") }, status: 400, want: "invalid_request"},
		{name: "missing grant_type", change: func(v url.Values) { v.Del("grant_type") }, status: 400, want: "invalid_request"},
		{name: "unknown grant_type", change: func(v url.Values) { v.Set("grant_type", "client_credentials") }, status: 400, want: "unsupported_grant_type"},
		{name: "other resource", change: func(v url.Values) { v.Set("resource", testIssuer) }, status: 400, want: "invalid_target"},
		{name: "short verifier", change: func(v url.Values) { v.Set("code_verifier", testVerifier[:42]) }, status: 400, want: "invalid_grant"},
		{name: "long verifier", change: func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 129)) }, status: 400, want: "invalid_grant"},
		{name: "verifier outside the alphabet", change: func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 42)+"+") }, status: 400, want: "invalid_grant"},
		{name: "truncated code", change: func(v url.Values) { v.Set("code", v.Get("code")[:42]) }, status: 400, want: "invalid_grant"},
		{name: "padded code", change: func(v url.Values) { v.Set("code", v.Get("code")+"=") }, status: 400, want: "invalid_grant"},
		{name: "code with trailing bits", change: func(v url.Values) { v.Set("code", strings.Repeat("A", 42)+"B") }, status: 400, want: "invalid_grant"},
		{name: "unauthenticated client", change: func(v url.Values) { v.Set("client_id", "unknown") }, status: 401, want: "invalid_client"},
		{name: "unknown code", change: func(v url.Values) { v.Set("code", randomValue()) }, status: 400, want: "invalid_grant"},
		{name: "access token as code", change: func(v url.Values) { v.Set("code", "access") }, status: 400, want: "invalid_grant"},
		{name: "parameters in the URL", change: func(v url.Values) { v.Del("code") },
			edit: func(r *http.Request) { r.URL.RawQuery = "code=" + randomValue() }, status: 400, want: "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			existing := f.connect("user")
			if tc.params == nil {
				tc.params = authParams()
			}
			form := exchangeForm(f.code(tc.params, "user"))
			correct := url.Values{}
			for k, v := range form {
				correct[k] = v
			}
			if tc.params.Get("code_challenge") != challengeOf(testVerifier) {
				correct.Set("code_verifier", strings.Repeat("v", 128))
			}
			tc.change(form)
			if form.Get("code") == "access" {
				form.Set("code", existing.access)
			}
			before := f.store.calls["TakeCode"]
			var edit []func(*http.Request)
			if tc.edit != nil {
				edit = append(edit, tc.edit)
			}
			r := post(t, f.Token, form, edit...)
			if tc.want == "" {
				granted(t, r)
			} else {
				r.rejected(t, tc.status, tc.want)
				if r.event.ConnectionID != "" || r.event.Subject != "" || len(f.connections("user")) != 1 {
					t.Fatalf("event %+v", r.event)
				}
			}
			unknown := form.Get("code") != correct.Get("code") && validValue(form.Get("code"))
			if reached := f.store.calls["TakeCode"] > before; reached != (tc.reach || unknown) {
				t.Fatalf("store reached: %v", reached)
			}
			// A code is consumed by its first lookup, successful or not, and
			// presenting it again is reuse. Only a successful first exchange
			// left a connection to revoke.
			again := post(t, f.Token, correct)
			if tc.reach {
				again.rejected(t, 400, "invalid_grant")
				revoked := again.event.ConnectionID != ""
				if again.err != ErrReused || revoked != (tc.want == "") || (again.event.Subject != "") != revoked ||
					(revoked && again.event.ConnectionID != r.event.ConnectionID) || len(f.connections("user")) != 1 {
					t.Fatalf("second exchange: err %v, event %+v", again.err, again.event)
				}
			} else {
				granted(t, again)
			}
			if !f.valid(existing.access) {
				t.Fatal("an earlier connection was revoked")
			}
		})
	}
}

func TestTokenCodeLifetime(t *testing.T) {
	f := newFixture(t)
	early, late := f.code(authParams(), "user"), f.code(authParams(), "user")
	f.advance(60*time.Second - time.Nanosecond)
	granted(t, post(t, f.Token, exchangeForm(early)))
	f.advance(time.Nanosecond)
	// The expired code is deleted and never works on an earlier clock.
	for range 2 {
		r := post(t, f.Token, exchangeForm(late))
		r.rejected(t, 400, "invalid_grant")
		if errors.Is(r.err, ErrReused) {
			t.Fatalf("expired code: %v", r.err)
		}
		f.advance(-time.Minute)
	}
}

func TestTokenConcurrentExchange(t *testing.T) {
	f := newFixture(t)
	sibling := f.connect("user")
	code := f.code(authParams(), "user")
	var mu sync.Mutex
	var winners []string
	var wg sync.WaitGroup
	begin := make(chan struct{})
	for range 16 {
		wg.Go(func() {
			<-begin
			r := post(t, f.Token, exchangeForm(code))
			if r.status == http.StatusOK {
				mu.Lock()
				defer mu.Unlock()
				winners = append(winners, r.field("access_token"))
			} else if r.status != http.StatusBadRequest || r.body != `{"error":"invalid_grant"}` || r.err != ErrReused {
				t.Errorf("status %d body %q err %v", r.status, r.body, r.err)
			}
		})
	}
	close(begin)
	wg.Wait()
	// Every losing request presented a consumed code. That revokes the
	// winner's connection, or refuses it before it is created.
	if len(winners) > 1 || len(f.connections("user")) != 1 {
		t.Fatalf("%d exchanges succeeded, %d connections", len(winners), len(f.connections("user")))
	}
	for _, access := range winners {
		if f.valid(access) {
			t.Fatal("an access token survived concurrent exchanges")
		}
	}
	if !f.valid(sibling.access) {
		t.Fatal("concurrent exchanges revoked another connection")
	}
}

func TestCodeReuse(t *testing.T) {
	confidential := func(v url.Values) { v.Set("client_id", "confidential"); v.Set("client_secret", testSecret) }
	for _, tc := range []struct {
		name   string
		change func(url.Values)
		client string
	}{
		{"same client", func(url.Values) {}, "public"},
		{"another client", confidential, "confidential"},
		{"another verifier", func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 43)) }, "public"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			sibling, stranger := f.connect("user"), f.connect("other")
			code := f.code(authParams(), "user")
			g := granted(t, post(t, f.Token, exchangeForm(code)))
			if conn, err := f.stored(g.refresh); err != nil || conn.Code != f.key("code", code) {
				t.Fatalf("connection %+v, %v", conn, err)
			}
			f.advance(codeTTL - time.Nanosecond)

			form := exchangeForm(code)
			tc.change(form)
			r := post(t, f.Token, form)
			r.rejected(t, 400, "invalid_grant")
			if r.err != ErrReused || r.event != (Event{Grant: "authorization_code", ClientID: tc.client, ConnectionID: g.id, Subject: "user"}) {
				t.Fatalf("err %v, event %+v", r.err, r.event)
			}
			if f.valid(g.access) {
				t.Fatal("the access token survived reuse detection")
			}
			if _, err := f.stored(g.refresh); !errors.Is(err, ErrInvalid) {
				t.Fatalf("the connection survived reuse detection: %v", err)
			}
			refreshed := f.refresh(g.refresh)
			refreshed.rejected(t, 400, "invalid_grant")
			if errors.Is(refreshed.err, ErrReused) || refreshed.event.ConnectionID != "" {
				t.Fatalf("refresh after code reuse: err %v, event %+v", refreshed.err, refreshed.event)
			}
			// Later attempts are still reuse, with no connection left.
			r = post(t, f.Token, exchangeForm(code))
			r.rejected(t, 400, "invalid_grant")
			if r.err != ErrReused || r.event != (Event{Grant: "authorization_code", ClientID: "public"}) {
				t.Fatalf("err %v, event %+v", r.err, r.event)
			}
			if !f.valid(sibling.access) || !f.valid(stranger.access) || len(f.connections("user")) != 1 || len(f.connections("other")) != 1 {
				t.Fatal("code reuse revoked another connection")
			}
			granted(t, f.refresh(sibling.refresh))
		})
	}

	// A rotation keeps the link to the code.
	t.Run("after a refresh", func(t *testing.T) {
		f := newFixture(t)
		code := f.code(authParams(), "user")
		g := granted(t, post(t, f.Token, exchangeForm(code)))
		rotated := granted(t, f.refresh(g.refresh))
		r := post(t, f.Token, exchangeForm(code))
		r.rejected(t, 400, "invalid_grant")
		if r.err != ErrReused || r.event.ConnectionID != g.id || f.valid(rotated.access) || len(f.connections("user")) != 0 {
			t.Fatalf("err %v, event %+v", r.err, r.event)
		}
		f.refresh(rotated.refresh).rejected(t, 400, "invalid_grant")
	})

	// A first exchange that failed after consuming the code left no connection.
	t.Run("after a failed exchange", func(t *testing.T) {
		f := newFixture(t)
		code := f.code(authParams(), "user")
		form := exchangeForm(code)
		form.Set("code_verifier", strings.Repeat("v", 43))
		r := post(t, f.Token, form)
		r.rejected(t, 400, "invalid_grant")
		if errors.Is(r.err, ErrReused) {
			t.Fatalf("first exchange: %v", r.err)
		}
		r = post(t, f.Token, exchangeForm(code))
		r.rejected(t, 400, "invalid_grant")
		if r.err != ErrReused || r.event != (Event{Grant: "authorization_code", ClientID: "public"}) || f.store.calls["Create"] != 0 {
			t.Fatalf("err %v, event %+v", r.err, r.event)
		}
	})

	// From its deadline on the code is only invalid and revokes nothing.
	t.Run("after expiry", func(t *testing.T) {
		f := newFixture(t)
		code := f.code(authParams(), "user")
		g := granted(t, post(t, f.Token, exchangeForm(code)))
		f.advance(codeTTL)
		for range 2 {
			r := post(t, f.Token, exchangeForm(code))
			r.rejected(t, 400, "invalid_grant")
			if errors.Is(r.err, ErrReused) || r.event.ConnectionID != "" || r.event.Subject != "" {
				t.Fatalf("err %v, event %+v", r.err, r.event)
			}
			// The record is deleted, so an earlier clock changes nothing.
			f.advance(-time.Minute)
		}
		if !f.valid(g.access) {
			t.Fatal("an expired code revoked the connection")
		}
		granted(t, f.refresh(g.refresh))
	})

	// A request that fails before the store is reached revokes nothing.
	t.Run("rejected before the store", func(t *testing.T) {
		f := newFixture(t)
		code := f.code(authParams(), "user")
		g := granted(t, post(t, f.Token, exchangeForm(code)))
		before := f.store.calls["TakeCode"]
		for name, tc := range map[string]struct {
			change func(url.Values)
			status int
			want   string
		}{
			"unauthenticated client": {func(v url.Values) { v.Set("client_id", "confidential") }, 401, "invalid_client"},
			"missing verifier":       {func(v url.Values) { v.Del("code_verifier") }, 400, "invalid_request"},
			"malformed verifier":     {func(v url.Values) { v.Set("code_verifier", "short") }, 400, "invalid_grant"},
			"malformed code":         {func(v url.Values) { v.Set("code", v.Get("code")+"=") }, 400, "invalid_grant"},
			"other resource":         {func(v url.Values) { v.Set("resource", testIssuer) }, 400, "invalid_target"},
		} {
			form := exchangeForm(code)
			tc.change(form)
			r := post(t, f.Token, form)
			r.rejected(t, tc.status, tc.want)
			if errors.Is(r.err, ErrReused) || r.event.ConnectionID != "" || f.store.calls["TakeCode"] != before {
				t.Fatalf("%s: err %v, event %+v", name, r.err, r.event)
			}
		}
		if !f.valid(g.access) {
			t.Fatal("a rejected request revoked the connection")
		}
		granted(t, f.refresh(g.refresh))
	})
}

// TestCodeReuseBeforeCreate covers what reaches the store between the
// consumption of a code and the creation of its connection.
func TestCodeReuseBeforeCreate(t *testing.T) {
	t.Run("code presented again", func(t *testing.T) {
		f := newFixture(t)
		code := f.code(authParams(), "user")
		f.store.hook = map[string]func(){"Create": func() {
			r := post(t, f.Token, exchangeForm(code))
			r.rejected(t, 400, "invalid_grant")
			if r.err != ErrReused || r.event != (Event{Grant: "authorization_code", ClientID: "public"}) {
				t.Errorf("second exchange: err %v, event %+v", r.err, r.event)
			}
		}}
		r := post(t, f.Token, exchangeForm(code))
		r.rejected(t, 400, "invalid_grant")
		if r.err != ErrReused || r.event != (Event{Grant: "authorization_code", ClientID: "public", Subject: "user"}) {
			t.Fatalf("first exchange: err %v, event %+v", r.err, r.event)
		}
		if f.store.calls["Create"] != 1 || len(f.connections("user")) != 0 {
			t.Fatalf("%d creations, %d connections", f.store.calls["Create"], len(f.connections("user")))
		}
	})

	t.Run("record deleted", func(t *testing.T) {
		f := newFixture(t)
		existing := f.connect("user")
		code := f.code(authParams(), "user")
		f.store.hook = map[string]func(){"Create": func() {
			if err := f.store.RevokeSubject(t.Context(), "user"); err != nil {
				t.Error(err)
			}
		}}
		r := post(t, f.Token, exchangeForm(code))
		r.rejected(t, 400, "invalid_grant")
		if errors.Is(r.err, ErrReused) || r.event.ConnectionID != "" {
			t.Fatalf("err %v, event %+v", r.err, r.event)
		}
		if f.store.calls["Create"] != 2 || len(f.connections("user")) != 0 || f.valid(existing.access) {
			t.Fatalf("%d creations, %d connections", f.store.calls["Create"], len(f.connections("user")))
		}
		// With the record gone a retry is a plain failure.
		r = post(t, f.Token, exchangeForm(code))
		r.rejected(t, 400, "invalid_grant")
		if errors.Is(r.err, ErrReused) {
			t.Fatalf("retry: %v", r.err)
		}
	})
}

func TestClientAuthentication(t *testing.T) {
	raw := func(value string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", value) }
	}
	basic := func(user, password string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	}
	body := func(pairs ...string) url.Values {
		v := url.Values{}
		for i := 0; i < len(pairs); i += 2 {
			v.Set(pairs[i], pairs[i+1])
		}
		return v
	}
	const (
		pass      = "invalid_grant" // authenticated; the refresh token is unknown
		challenge = `Basic realm="mcpoauth"`
	)
	for _, tc := range []struct {
		name   string
		form   url.Values
		edit   func(*http.Request)
		status int
		want   string
		header string
		client string
	}{
		{name: "public", form: body("client_id", "public"), status: 400, want: pass, client: "public"},
		{name: "public with an ignored secret", form: body("client_id", "public", "client_secret", "anything"), status: 400, want: pass, client: "public"},
		{name: "public with an empty secret", form: body("client_id", "public", "client_secret", ""), status: 400, want: pass, client: "public"},
		{name: "public by Basic", edit: basicAuth("public", ""), status: 400, want: pass, client: "public"},
		{name: "public by Basic with an ignored password", edit: basicAuth("public", "anything"), status: 400, want: pass, client: "public"},
		{name: "confidential by post", form: body("client_id", "confidential", "client_secret", testSecret), status: 400, want: pass, client: "confidential"},
		{name: "confidential by Basic", edit: basicAuth("confidential", url.QueryEscape(testSecret)), status: 400, want: pass, client: "confidential"},
		{name: "lowercase scheme", edit: raw("basic " + basic("confidential", url.QueryEscape(testSecret))[6:]), status: 400, want: pass, client: "confidential"},
		{name: "form-encoded Basic ID", edit: basicAuth("id%3Acolon", url.QueryEscape(testSecret)), status: 400, want: pass, client: "id:colon"},
		{name: "Basic with the same body ID", form: body("client_id", "confidential"), edit: basicAuth("confidential", url.QueryEscape(testSecret)), status: 400, want: pass, client: "confidential"},
		{name: "Basic with empty body values", form: body("client_id", "", "client_secret", ""), edit: basicAuth("confidential", url.QueryEscape(testSecret)), status: 400, want: pass, client: "confidential"},
		{name: "wrong secret by post", form: body("client_id", "confidential", "client_secret", "wrong"), status: 401, want: "invalid_client"},
		{name: "wrong secret by Basic", edit: basicAuth("confidential", "wrong"), status: 401, want: "invalid_client", header: challenge},
		{name: "unencoded secret by Basic", edit: basicAuth("confidential", testSecret+"%zz"), status: 401, want: "invalid_client", header: challenge},
		{name: "missing secret", form: body("client_id", "confidential"), status: 401, want: "invalid_client"},
		{name: "empty secret", form: body("client_id", "confidential", "client_secret", ""), status: 401, want: "invalid_client"},
		{name: "empty Basic password", edit: basicAuth("confidential", ""), status: 401, want: "invalid_client", header: challenge},
		{name: "secret digest as secret", form: body("client_id", "confidential", "client_secret", "digest"), status: 401, want: "invalid_client"},
		{name: "missing client", form: body(), status: 401, want: "invalid_client"},
		{name: "empty client", form: body("client_id", ""), status: 401, want: "invalid_client"},
		{name: "unknown client", form: body("client_id", "unknown"), status: 401, want: "invalid_client"},
		{name: "malformed client", form: body("client_id", "pub lic"), status: 401, want: "invalid_client"},
		{name: "unknown client by Basic", edit: basicAuth("unknown", "x"), status: 401, want: "invalid_client", header: challenge},
		{name: "empty Basic ID", edit: basicAuth("", "x"), status: 401, want: "invalid_client", header: challenge},
		{name: "Bearer scheme", form: body("client_id", "public"), edit: raw("Bearer " + randomValue()), status: 401, want: "invalid_client", header: challenge},
		{name: "scheme only", form: body("client_id", "public"), edit: raw("Basic"), status: 401, want: "invalid_client", header: challenge},
		{name: "Basic without base64", form: body("client_id", "public"), edit: raw("Basic !!!"), status: 401, want: "invalid_client", header: challenge},
		{name: "Basic without a colon", form: body("client_id", "public"), edit: raw("Basic " + base64.StdEncoding.EncodeToString([]byte("public"))), status: 401, want: "invalid_client", header: challenge},
		{name: "Basic ID with invalid encoding", edit: basicAuth("%zz", "x"), status: 401, want: "invalid_client", header: challenge},
		{name: "two Authorization headers", edit: func(r *http.Request) {
			r.Header.Add("Authorization", basic("public", ""))
			r.Header.Add("Authorization", basic("public", ""))
		}, status: 400, want: "invalid_request"},
		{name: "Basic with a body secret", form: body("client_secret", testSecret), edit: basicAuth("confidential", url.QueryEscape(testSecret)), status: 400, want: "invalid_request"},
		{name: "Basic with another body ID", form: body("client_id", "public"), edit: basicAuth("confidential", url.QueryEscape(testSecret)), status: 400, want: "invalid_request"},
	} {
		for name, handle := range map[string]func(*fixture) handlerFunc{
			"token":      func(f *fixture) handlerFunc { return f.Token },
			"revocation": func(f *fixture) handlerFunc { return f.Revocation },
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				f := newFixture(t)
				form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken(make([]byte, 16))}, "token": {"unknown"}}
				for k, v := range tc.form {
					form[k] = v
				}
				if form.Get("client_secret") == "digest" {
					form.Set("client_secret", string(f.clients["confidential"].Secret[:]))
				}
				var edit []func(*http.Request)
				if tc.edit != nil {
					edit = append(edit, tc.edit)
				}
				r := post(t, handle(f), form, edit...)
				if r.header.Get("WWW-Authenticate") != tc.header || r.event.ClientID != tc.client {
					t.Fatalf("challenge %q, event %+v", r.header.Get("WWW-Authenticate"), r.event)
				}
				if tc.want == pass && name == "revocation" {
					if r.status != http.StatusOK || r.err != nil {
						t.Fatalf("status %d err %v", r.status, r.err)
					}
					return
				}
				r.rejected(t, tc.status, tc.want)
				if errors.Is(r.err, ErrClient) != (tc.status == 401) || r.header.Get("Cache-Control") != "no-store" ||
					r.header.Get("Pragma") != "no-cache" || r.header.Get("Content-Type") != "application/json" {
					t.Fatalf("err %v, header %v", r.err, r.header)
				}
				if tc.status == 400 && tc.want == "invalid_request" && r.err.Error() != ErrInvalid.Error()+": invalid_request" {
					t.Fatalf("err %v", r.err)
				}
			})
		}
	}

	t.Run("lookup failure", func(t *testing.T) {
		f := newFixture(t)
		down := errors.New("directory down")
		f.lookupErr = down
		f.refresh("x").unavailable(t, down)
		post(t, f.Revocation, url.Values{"client_id": {"public"}, "token": {"x"}}).unavailable(t, down)
	})
	t.Run("invalid client record", func(t *testing.T) {
		f := newFixture(t)
		f.clients["public"] = Client{ID: "public", RedirectURIs: []string{"app://callback"}}
		f.refresh("x").unavailable(t, ErrRecord)
		f.clients["public"] = Client{ID: "other", RedirectURIs: []string{"https://client.example/cb"}}
		f.refresh("x").unavailable(t, ErrRecord)
	})
}

func TestTokenRequestFormat(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	for _, handle := range []handlerFunc{f.Token, f.Revocation} {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodHead} {
			r := post(t, handle, refreshForm(g.refresh), func(r *http.Request) { r.Method = method })
			if r.status != http.StatusMethodNotAllowed || r.header.Get("Allow") != "POST" || r.body != "" ||
				r.header.Get("Cache-Control") != "" || !errors.Is(r.err, ErrInvalid) || !strings.HasSuffix(r.err.Error(), ": method not allowed") {
				t.Fatalf("%s: status %d header %v err %v", method, r.status, r.header, r.err)
			}
		}
	}
	contentType := func(value string) func(string) func(*http.Request) {
		return func(string) func(*http.Request) {
			return func(r *http.Request) {
				r.Header.Del("Content-Type")
				if value != "" {
					r.Header.Set("Content-Type", value)
				}
			}
		}
	}
	body := func(build func(encoded string) string) func(string) func(*http.Request) {
		return func(encoded string) func(*http.Request) {
			return func(r *http.Request) { r.Body = readCloser{strings.NewReader(build(encoded))} }
		}
	}
	pad := func(size int) func(string) string {
		return func(encoded string) string {
			return encoded + "&pad=" + strings.Repeat("x", size-len(encoded)-len("&pad="))
		}
	}
	for _, tc := range []struct {
		name string
		edit func(encoded string) func(*http.Request)
		ok   bool
	}{
		{"media type parameters and case", contentType("Application/X-WWW-Form-Urlencoded; charset=UTF-8"), true},
		{"body at the limit", body(pad(16 << 10)), true},
		{"body over the limit", body(pad(16<<10 + 1)), false},
		{"missing content type", contentType(""), false},
		{"JSON content type", contentType("application/json"), false},
		{"multipart content type", contentType("multipart/form-data; boundary=x"), false},
		{"malformed content type", contentType("application/x-www-form-urlencoded; charset"), false},
		{"semicolon separator", body(func(encoded string) string { return encoded + ";scope=read" }), false},
		{"invalid percent-encoding", body(func(encoded string) string { return encoded + "&unknown=%zz" }), false},
		{"grant parameters only in the URL", func(encoded string) func(*http.Request) {
			return func(r *http.Request) {
				r.URL.RawQuery = encoded
				r.Body = readCloser{strings.NewReader("client_id=public")}
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			g := f.connect("user")
			r := post(t, f.Token, refreshForm(g.refresh), tc.edit(refreshForm(g.refresh).Encode()))
			if tc.ok {
				granted(t, r)
				return
			}
			r.rejected(t, 400, "invalid_request")
			if _, err := f.stored(g.refresh); err != nil || !f.valid(g.access) || f.store.calls["Rotate"] != 0 {
				t.Fatal("a malformed request reached the connection")
			}
		})
	}

	for _, name := range []string{"grant_type", "code", "redirect_uri", "code_verifier", "client_id", "client_secret", "refresh_token", "scope", "resource"} {
		form := refreshForm(g.refresh)
		form[name] = []string{form.Get(name), form.Get(name)}
		post(t, f.Token, form).rejected(t, 400, "invalid_request")
	}
	for _, name := range []string{"token", "token_type_hint", "client_id", "client_secret"} {
		form := url.Values{"client_id": {"public"}, "token": {g.access}}
		form[name] = []string{form.Get(name), form.Get(name)}
		post(t, f.Revocation, form).rejected(t, 400, "invalid_request")
	}
	if !f.valid(g.access) {
		t.Fatal("a repeated parameter was accepted")
	}
	// A repeated unknown parameter is ignored.
	form := refreshForm(g.refresh)
	form["unknown"] = []string{"1", "2"}
	granted(t, post(t, f.Token, form))
}

type readCloser struct{ *strings.Reader }

func (readCloser) Close() error { return nil }

func TestTokenInvalidRecords(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Code)
		status int
		want   string
		scope  string
	}{
		{name: "intact", change: func(*Code) {}, scope: "read write"},
		{name: "scope removed from the configuration", change: func(c *Code) { c.Scopes = []string{"gone", "write", "read"} }, scope: "write read"},
		{name: "expired code", change: func(c *Code) { c.ExpiresAt = testStart }, status: 400, want: "invalid_grant"},
		{name: "no remaining scope", change: func(c *Code) { c.Scopes = []string{"gone"} }, status: 400, want: "invalid_grant"},
		{name: "other client", change: func(c *Code) { c.ClientID = "confidential" }, status: 400, want: "invalid_grant"},
		{name: "empty challenge", change: func(c *Code) { c.Challenge = "" }, status: 400, want: "invalid_grant"},
		{name: "empty subject", change: func(c *Code) { c.Subject = "" }, status: 503},
		{name: "no scope", change: func(c *Code) { c.Scopes = nil }, status: 503},
	} {
		t.Run("code/"+tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.store.code = tc.change
			r := post(t, f.Token, exchangeForm(f.code(authParams(), "user")))
			switch tc.status {
			case 0:
				granted(t, r)
				if conn, _ := f.stored(r.field("refresh_token")); r.field("scope") != tc.scope || strings.Join(conn.Scopes, " ") != tc.scope {
					t.Fatalf("scope %q, stored %v", r.field("scope"), conn.Scopes)
				}
			case 503:
				r.unavailable(t, ErrRecord)
			default:
				r.rejected(t, tc.status, tc.want)
			}
			if tc.status != 0 && (f.store.calls["Create"] != 0 || r.event.ConnectionID != "") {
				t.Fatalf("an invalid code created a connection: %+v", r.event)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		change func(*Connection)
	}{
		{"empty ID", func(c *Connection) { c.ID = "" }},
		{"empty subject", func(c *Connection) { c.Subject = "" }},
		{"no scope", func(c *Connection) { c.Scopes = nil }},
		{"other client", func(c *Connection) { c.ClientID = "confidential" }},
		{"other selector", func(c *Connection) { c.Selector[0] ^= 1 }},
		{"other access digest", func(c *Connection) { c.Access[0] ^= 1 }},
		{"other refresh digest", func(c *Connection) { c.Refresh[0] ^= 1 }},
	} {
		t.Run("connection/"+tc.name, func(t *testing.T) {
			f := newFixture(t)
			g := f.connect("user")
			f.store.conn = tc.change
			f.refresh(g.refresh).unavailable(t, ErrRecord)
		})
	}
}

func TestRefresh(t *testing.T) {
	f := newFixture(t)
	first := f.connect("user")
	f.advance(10*time.Minute + 300*time.Millisecond)
	r := f.refresh(first.refresh)
	second := granted(t, r)
	if want := (Event{Grant: "refresh_token", ClientID: "public", ConnectionID: first.id, Subject: "user"}); r.event != want {
		t.Fatalf("event %+v", r.event)
	}
	if r.fields["expires_in"] != float64(3600) || r.field("scope") != "read write" || len(r.fields) != 5 ||
		r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" {
		t.Fatalf("response %q, header %v", r.body, r.header)
	}
	oldSelector, _ := refreshSelector(first.refresh)
	newSelector, _ := refreshSelector(second.refresh)
	if second.access == first.access || second.refresh == first.refresh || oldSelector != newSelector {
		t.Fatal("rotation kept a token or changed the selector")
	}
	if f.valid(first.access) || !f.valid(second.access) {
		t.Fatal("rotation did not replace the access token")
	}
	conn, err := f.stored(second.refresh)
	now := f.now()
	if err != nil || conn.ID != first.id || !conn.CreatedAt.Equal(testStart) || !conn.RefreshedAt.Equal(now) ||
		!conn.AccessExpiry.Equal(now.Add(time.Hour)) || !conn.RefreshExpiry.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("connection %+v, %v", conn, err)
	}
	// A second rotation continues from the new token.
	third := granted(t, f.refresh(second.refresh))
	if f.valid(second.access) || !f.valid(third.access) || len(f.connections("user")) != 1 {
		t.Fatal("second rotation")
	}
}

func TestRefreshRejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(url.Values)
		want   string
		reach  bool
	}{
		{name: "missing token", change: func(v url.Values) { v.Del("refresh_token") }, want: "invalid_request"},
		{name: "other resource", change: func(v url.Values) { v.Set("resource", "https://mcp.example/other") }, want: "invalid_target"},
		{name: "unknown scope", change: func(v url.Values) { v.Set("scope", "read other") }, want: "invalid_scope"},
		{name: "short token", change: func(v url.Values) { v.Set("refresh_token", v.Get("refresh_token")[:63]) }, want: "invalid_grant"},
		{name: "long token", change: func(v url.Values) { v.Set("refresh_token", v.Get("refresh_token")+"AAAA") }, want: "invalid_grant"},
		{name: "token outside the alphabet", change: func(v url.Values) { v.Set("refresh_token", v.Get("refresh_token")[:63]+"+") }, want: "invalid_grant"},
		{name: "access token", change: func(v url.Values) { v.Set("refresh_token", "access") }, want: "invalid_grant"},
		{name: "unknown token", change: func(v url.Values) { v.Set("refresh_token", refreshToken(make([]byte, 16))) }, want: "invalid_grant", reach: true},
		{name: "other client", change: func(v url.Values) { v.Set("client_id", "confidential"); v.Set("client_secret", testSecret) }, want: "invalid_grant", reach: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			g := f.connect("user")
			form := refreshForm(g.refresh)
			tc.change(form)
			if form.Get("refresh_token") == "access" {
				form.Set("refresh_token", g.access)
			}
			r := post(t, f.Token, form)
			r.rejected(t, 400, tc.want)
			if errors.Is(r.err, ErrReused) || r.event.ConnectionID != "" || (f.store.calls["Rotate"] != 0) != tc.reach {
				t.Fatalf("err %v, event %+v, rotations %d", r.err, r.event, f.store.calls["Rotate"])
			}
			// The connection is unchanged: both tokens still work.
			if !f.valid(g.access) {
				t.Fatal("the access token was revoked")
			}
			granted(t, f.refresh(g.refresh))
		})
	}
}

func TestRefreshScope(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	for _, scope := range []string{"read", "admin", "read write admin", "", "  "} {
		form := refreshForm(g.refresh)
		form.Set("scope", scope)
		r := post(t, f.Token, form)
		g = granted(t, r)
		if r.field("scope") != "read write" {
			t.Fatalf("scope %q for request %q", r.field("scope"), scope)
		}
		if access, err := f.Verify(bearer(g.access)); err != nil || strings.Join(access.Scopes, " ") != "read write" {
			t.Fatalf("access %+v, %v", access, err)
		}
	}

	// A server whose configuration dropped scopes issues what remains.
	narrowed := f.peer(func(c *Config) { c.Scopes = []string{"admin", "write"}; c.DefaultScopes = []string{"admin"} })
	r := post(t, narrowed.Token, refreshForm(g.refresh))
	g = granted(t, r)
	if r.field("scope") != "write" {
		t.Fatalf("scope %q", r.field("scope"))
	}
	removed := f.peer(func(c *Config) { c.Scopes = []string{"admin"}; c.DefaultScopes = []string{"admin"} })
	r = post(t, removed.Token, refreshForm(g.refresh))
	r.rejected(t, 400, "invalid_grant")
	if _, err := f.stored(g.refresh); !errors.Is(err, ErrInvalid) || r.event.ConnectionID != g.id || errors.Is(r.err, ErrReused) {
		t.Fatalf("a connection without a remaining scope survived: %v, %+v", err, r.event)
	}
}

func TestRefreshReuse(t *testing.T) {
	f := newFixture(t)
	reused, sibling, stranger := f.connect("user"), f.connect("user"), f.connect("other")
	rotated := granted(t, f.refresh(reused.refresh))

	r := f.refresh(reused.refresh)
	r.rejected(t, 400, "invalid_grant")
	if r.err != ErrReused || r.event != (Event{Grant: "refresh_token", ClientID: "public", ConnectionID: reused.id, Subject: "user"}) {
		t.Fatalf("err %v, event %+v", r.err, r.event)
	}
	if f.valid(rotated.access) {
		t.Fatal("the access token survived reuse detection")
	}
	// Later attempts find no connection and are plain failures.
	for _, token := range []string{rotated.refresh, reused.refresh} {
		r = f.refresh(token)
		r.rejected(t, 400, "invalid_grant")
		if errors.Is(r.err, ErrReused) || r.event.ConnectionID != "" {
			t.Fatalf("err %v, event %+v", r.err, r.event)
		}
	}
	if !f.valid(sibling.access) || !f.valid(stranger.access) || len(f.connections("user")) != 1 || len(f.connections("other")) != 1 {
		t.Fatal("reuse revoked another connection")
	}
	granted(t, f.refresh(sibling.refresh))
	granted(t, f.refresh(stranger.refresh))
}

func TestRefreshOtherClient(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	rotated := granted(t, f.refresh(g.refresh))
	// Neither the current nor a rotated refresh token of another client's
	// connection changes it, so a client cannot revoke connections it does
	// not own by refreshing. A consumed authorization code is different: it
	// revokes the connection whichever client presents it.
	for _, token := range []string{rotated.refresh, g.refresh} {
		form := refreshForm(token)
		form.Del("client_id")
		r := post(t, f.Token, form, basicAuth("confidential", url.QueryEscape(testSecret)))
		r.rejected(t, 400, "invalid_grant")
		if errors.Is(r.err, ErrReused) || r.event.ConnectionID != "" || r.event.ClientID != "confidential" {
			t.Fatalf("err %v, event %+v", r.err, r.event)
		}
	}
	if !f.valid(rotated.access) {
		t.Fatal("another client revoked the connection")
	}
	granted(t, f.refresh(rotated.refresh))
}

func TestRefreshIdleLifetime(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	// Each refresh just before the deadline extends it by the idle lifetime.
	for range 3 {
		f.advance(2*time.Hour - time.Nanosecond)
		if f.valid(g.access) {
			t.Fatal("the access token outlived its lifetime")
		}
		g = granted(t, f.refresh(g.refresh))
	}
	f.advance(2 * time.Hour)
	r := f.refresh(g.refresh)
	r.rejected(t, 400, "invalid_grant")
	if errors.Is(r.err, ErrReused) {
		t.Fatalf("err %v", r.err)
	}
	if _, err := f.stored(g.refresh); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an expired connection was kept: %v", err)
	}
}

func TestRefreshAbsoluteLifetime(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.ConnectionAbsolute = 3 * time.Hour })
	g := f.connect("user")
	f.advance(90 * time.Minute)
	r := f.refresh(g.refresh)
	g = granted(t, r)
	if r.fields["expires_in"] != float64(3600) {
		t.Fatalf("expires_in %v", r.fields["expires_in"])
	}
	// 29 minutes 59.5 seconds remain: expires_in is truncated to the
	// absolute deadline and rounded down.
	f.advance(time.Hour + 500*time.Millisecond)
	r = f.refresh(g.refresh)
	g = granted(t, r)
	if r.fields["expires_in"] != float64(1799) {
		t.Fatalf("expires_in %v", r.fields["expires_in"])
	}
	access, err := f.Verify(bearer(g.access))
	if err != nil || !access.ExpiresAt.Equal(testStart.Add(3*time.Hour)) {
		t.Fatalf("access %+v, %v", access, err)
	}
	if conn, _ := f.stored(g.refresh); !conn.AbsoluteExpiry.Equal(testStart.Add(3*time.Hour)) || !conn.CreatedAt.Equal(testStart) {
		t.Fatalf("a rotation moved the absolute deadline: %+v", conn)
	}
	f.advance(30*time.Minute - 500*time.Millisecond - time.Nanosecond)
	if !f.valid(g.access) {
		t.Fatal("the access token expired before the absolute deadline")
	}
	f.advance(time.Nanosecond)
	if f.valid(g.access) {
		t.Fatal("the access token outlived the absolute deadline")
	}
	f.refresh(g.refresh).rejected(t, 400, "invalid_grant")
	if _, err := f.stored(g.refresh); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an expired connection was kept: %v", err)
	}
}

func TestRefreshConcurrent(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	sibling := f.connect("user")
	var mu sync.Mutex
	var winners []grant
	var reused int
	var wg sync.WaitGroup
	begin := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-begin
			r := f.refresh(g.refresh)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case r.status == http.StatusOK:
				winners = append(winners, grant{access: r.field("access_token"), refresh: r.field("refresh_token")})
			case r.status != http.StatusBadRequest || r.body != `{"error":"invalid_grant"}`:
				t.Errorf("status %d body %q", r.status, r.body)
			case errors.Is(r.err, ErrReused):
				reused++
			}
		})
	}
	close(begin)
	wg.Wait()
	if len(winners) != 1 || reused != 1 {
		t.Fatalf("%d refreshes succeeded and %d detected reuse, want 1 and 1", len(winners), reused)
	}
	// The losing request reused the token, so the winner's tokens are dead too.
	if _, err := f.stored(g.refresh); !errors.Is(err, ErrInvalid) || f.valid(winners[0].access) {
		t.Fatalf("the connection survived concurrent refreshes: %v", err)
	}
	f.refresh(winners[0].refresh).rejected(t, 400, "invalid_grant")
	if !f.valid(sibling.access) {
		t.Fatal("concurrent refreshes revoked another connection")
	}
}

func TestRefreshAfterExpiredAccessToken(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	f.advance(time.Hour - time.Nanosecond)
	if !f.valid(g.access) {
		t.Fatal("the access token expired early")
	}
	f.advance(time.Nanosecond)
	for range 2 {
		if f.valid(g.access) {
			t.Fatal("the access token outlived its lifetime")
		}
	}
	next := granted(t, f.refresh(g.refresh))
	if !f.valid(next.access) {
		t.Fatal("refresh after an expired access token")
	}
}

func TestRevocation(t *testing.T) {
	revoke := func(f *fixture, token string, edit ...func(*http.Request)) reply {
		t.Helper()
		form := url.Values{"token": {token}, "token_type_hint": {"unknown_hint"}}
		if len(edit) == 0 {
			form.Set("client_id", "public")
		}
		r := post(t, f.Revocation, form, edit...)
		if r.status != http.StatusOK || r.err != nil || r.body != "" || r.header.Get("Content-Type") != "" ||
			r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" || r.event.Grant != "" {
			t.Fatalf("status %d header %v body %q err %v", r.status, r.header, r.body, r.err)
		}
		return r
	}
	for _, kind := range []string{"access", "refresh"} {
		t.Run(kind+" token", func(t *testing.T) {
			f := newFixture(t)
			g, sibling := f.connect("user"), f.connect("user")
			token := map[string]string{"access": g.access, "refresh": g.refresh}[kind]
			r := revoke(f, token)
			if want := (Event{ClientID: "public", ConnectionID: g.id, Subject: "user"}); r.event != want {
				t.Fatalf("event %+v", r.event)
			}
			if _, err := f.stored(g.refresh); !errors.Is(err, ErrInvalid) || f.valid(g.access) {
				t.Fatalf("the connection survived: %v", err)
			}
			f.refresh(g.refresh).rejected(t, 400, "invalid_grant")
			// Revoking again is not an error and reports no connection.
			if r := revoke(f, token); r.event.ConnectionID != "" {
				t.Fatalf("event %+v", r.event)
			}
			if !f.valid(sibling.access) || len(f.connections("user")) != 1 {
				t.Fatal("revocation removed another connection")
			}
		})
	}

	t.Run("ignored tokens", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.ConnectionAbsolute = 5 * time.Hour })
		old := f.connect("user")
		g := granted(t, f.refresh(old.refresh))
		confidential := basicAuth("confidential", url.QueryEscape(testSecret))
		for name, r := range map[string]reply{
			"another client's access token":  revoke(f, g.access, confidential),
			"another client's refresh token": revoke(f, g.refresh, confidential),
			"rotated refresh token":          revoke(f, old.refresh),
			"rotated access token":           revoke(f, old.access),
			"unknown access token":           revoke(f, randomValue()),
			"unknown refresh token":          revoke(f, refreshToken(make([]byte, 16))),
			"malformed token":                revoke(f, "not a token"),
			"connection ID":                  revoke(f, g.id),
		} {
			if r.event.ConnectionID != "" || r.event.Subject != "" || f.store.calls["Revoke"] != 0 {
				t.Fatalf("%s: event %+v, revocations %d", name, r.event, f.store.calls["Revoke"])
			}
		}
		if !f.valid(g.access) {
			t.Fatal("an ignored token revoked the connection")
		}
		// An expired access token does not revoke; its refresh token does.
		f.advance(time.Hour)
		if r := revoke(f, g.access); r.event.ConnectionID != "" || f.store.calls["Revoke"] != 0 {
			t.Fatalf("expired access token: %+v", r.event)
		}
		if r := revoke(f, g.refresh); r.event.ConnectionID != g.id {
			t.Fatalf("refresh token after the access token expired: %+v", r.event)
		}
	})

	t.Run("expired refresh token", func(t *testing.T) {
		f := newFixture(t)
		g := f.connect("user")
		f.advance(2 * time.Hour)
		if r := revoke(f, g.refresh); r.event.ConnectionID != "" || f.store.calls["Revoke"] != 0 {
			t.Fatalf("event %+v", r.event)
		}
	})

	t.Run("invalid records", func(t *testing.T) {
		for name, change := range map[string]func(*Connection){
			"empty ID":            func(c *Connection) { c.ID = "" },
			"other access digest": func(c *Connection) { c.Access[0] ^= 1; c.Selector[0] ^= 1 },
		} {
			f := newFixture(t)
			g := f.connect("user")
			f.store.conn = change
			for _, token := range []string{g.access, g.refresh} {
				post(t, f.Revocation, url.Values{"client_id": {"public"}, "token": {token}}).unavailable(t, ErrRecord)
			}
			if f.store.calls["Revoke"] != 0 {
				t.Fatalf("%s: an invalid record was revoked", name)
			}
		}
		// A record the store should have reported as expired, or whose refresh
		// digest differs, is ignored.
		for name, change := range map[string]func(*Connection){
			"expired":              func(c *Connection) { c.AccessExpiry, c.RefreshExpiry = testStart, testStart },
			"other refresh digest": func(c *Connection) { c.Refresh[0] ^= 1; c.AccessExpiry = testStart },
		} {
			f := newFixture(t)
			g := f.connect("user")
			f.store.conn = change
			for _, token := range []string{g.access, g.refresh} {
				if r := revoke(f, token); r.event.ConnectionID != "" || f.store.calls["Revoke"] != 0 {
					t.Fatalf("%s: event %+v", name, r.event)
				}
			}
		}
	})

	t.Run("rejected requests", func(t *testing.T) {
		f := newFixture(t)
		g := f.connect("user")
		post(t, f.Revocation, url.Values{"client_id": {"public"}}).rejected(t, 400, "invalid_request")
		post(t, f.Revocation, url.Values{"client_id": {"public"}, "token": {""}}).rejected(t, 400, "invalid_request")
		r := post(t, f.Revocation, url.Values{"client_id": {"confidential"}, "token": {g.access}})
		r.rejected(t, 401, "invalid_client")
		if r.err != ErrClient || !f.valid(g.access) {
			t.Fatalf("err %v", r.err)
		}
		// The token is read from the body only.
		r = post(t, f.Revocation, url.Values{"client_id": {"public"}}, func(r *http.Request) { r.URL.RawQuery = "token=" + g.access })
		r.rejected(t, 400, "invalid_request")
		if !f.valid(g.access) {
			t.Fatal("a token in the URL was revoked")
		}
	})
}

func TestDisconnect(t *testing.T) {
	f := newFixture(t)
	g, sibling := f.connect("user"), f.connect("user")
	for _, id := range []string{"", "x", g.id[:42], g.id + "=", g.id[:42] + "+", g.refresh, strings.Repeat("A", 42) + "B"} {
		if err := f.Disconnect(t.Context(), id); err != ErrInvalid || f.store.calls["Revoke"] != 0 {
			t.Fatalf("id %q: %v", id, err)
		}
	}
	if err := f.Disconnect(t.Context(), randomValue()); err != nil {
		t.Fatalf("unknown connection: %v", err)
	}
	for range 2 {
		if err := f.Disconnect(t.Context(), g.id); err != nil {
			t.Fatal(err)
		}
	}
	if f.valid(g.access) || !f.valid(sibling.access) {
		t.Fatal("disconnect revoked the wrong access token")
	}
	r := f.refresh(g.refresh)
	r.rejected(t, 400, "invalid_grant")
	if errors.Is(r.err, ErrReused) {
		t.Fatalf("err %v", r.err)
	}
	granted(t, f.refresh(sibling.refresh))
}

// TestExchangeClientScopes narrows the client's scope list between consent
// and the code exchange.
func TestExchangeClientScopes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope string
		list  []string
		want  string // empty when nothing remains
	}{
		{name: "every scope listed", scope: "read write", list: []string{"write", "read"}, want: "read write"},
		{name: "one scope listed", scope: "read write", list: []string{"write"}, want: "write"},
		{name: "the code's order is kept", scope: "write read admin", list: []string{"admin", "read"}, want: "read admin"},
		{name: "reversed list", scope: "write admin read", list: []string{"read", "admin", "write"}, want: "write admin read"},
		{name: "no scope listed", scope: "read write", list: []string{"admin"}},
		{name: "list outside the configuration", scope: "read write", list: []string{"other"}},
		{name: "nil list", scope: "read write", list: nil},
		{name: "empty list", scope: "read write", list: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			params := authParams()
			params.Set("scope", tc.scope)
			code := f.code(params, "user")
			f.restrict(tc.list...)
			r := post(t, f.Token, exchangeForm(code))
			if tc.want == "" {
				r.rejected(t, 400, "invalid_grant")
				if errors.Is(r.err, ErrReused) || r.event.ConnectionID != "" || r.event.Subject != "" ||
					f.store.calls["Create"] != 0 || len(f.connections("user")) != 0 {
					t.Fatalf("err %v, event %+v, creations %d", r.err, r.event, f.store.calls["Create"])
				}
				// The code stays consumed after the list is restored.
				f.restrict("read", "write", "admin")
				again := post(t, f.Token, exchangeForm(code))
				again.rejected(t, 400, "invalid_grant")
				if again.err != ErrReused {
					t.Fatalf("second exchange: %v", again.err)
				}
				return
			}
			g := granted(t, r)
			access, err := f.Verify(bearer(g.access))
			conn, errStored := f.stored(g.refresh)
			if r.field("scope") != tc.want || err != nil || strings.Join(access.Scopes, " ") != tc.want ||
				errStored != nil || strings.Join(conn.Scopes, " ") != tc.want {
				t.Fatalf("scope %q, access %+v, %v, stored %v, %v", r.field("scope"), access, err, conn.Scopes, errStored)
			}
			// The narrowed connection is within the list, so it refreshes.
			if next := f.refresh(g.refresh); granted(t, next).id != g.id || next.field("scope") != tc.want {
				t.Fatalf("refreshed scope %q", next.field("scope"))
			}
		})
	}
}

// TestRefreshClientScopes changes the client's scope list after a connection
// with the scopes read and write was created.
func TestRefreshClientScopes(t *testing.T) {
	for _, tc := range []struct {
		name string
		list []string
	}{
		{"one scope removed", []string{"read"}},
		{"other scope removed", []string{"admin", "write"}},
		{"every scope removed", []string{"admin"}},
		{"list outside the configuration", []string{"other"}},
		{"nil list", nil},
		{"empty list", []string{}},
	} {
		t.Run("revoked/"+tc.name, func(t *testing.T) {
			f := newFixture(t)
			g, sibling := f.connect("user"), f.connect("other")
			unrestricted := f.clients["public"]
			f.restrict(tc.list...)
			r := f.refresh(g.refresh)
			r.rejected(t, 400, "invalid_grant")
			if _, err := f.stored(g.refresh); !errors.Is(err, ErrInvalid) {
				t.Fatalf("a connection beyond the client's scopes survived: %v", err)
			}
			if want := (Event{Grant: "refresh_token", ClientID: "public", ConnectionID: g.id, Subject: "user"}); r.event != want ||
				errors.Is(r.err, ErrReused) || f.store.calls["Revoke"] != 1 {
				t.Fatalf("err %v, event %+v, revocations %d", r.err, r.event, f.store.calls["Revoke"])
			}
			if f.valid(g.access) || len(f.connections("user")) != 0 {
				t.Fatal("the access token survived")
			}
			// Restoring the list does not restore the connection.
			f.clients["public"] = unrestricted
			again := f.refresh(g.refresh)
			again.rejected(t, 400, "invalid_grant")
			if errors.Is(again.err, ErrReused) || again.event.ConnectionID != "" {
				t.Fatalf("refresh after restoring the list: err %v, event %+v", again.err, again.event)
			}
			// Another user's connection of the same client is judged on its own
			// refresh, with the list of that moment.
			if !f.valid(sibling.access) {
				t.Fatal("another connection was revoked")
			}
			granted(t, f.refresh(sibling.refresh))
		})
	}

	for _, tc := range []struct {
		name  string
		list  []string
		scope string
	}{
		{"exact list", []string{"read", "write"}, ""},
		{"reversed wider list", []string{"admin", "write", "read"}, ""},
		{"requested scope outside the list", []string{"write", "read"}, "admin"},
		{"requested scopes inside and outside the list", []string{"write", "read"}, "read admin"},
	} {
		t.Run("kept/"+tc.name, func(t *testing.T) {
			f := newFixture(t)
			g := f.connect("user")
			f.restrict(tc.list...)
			form := refreshForm(g.refresh)
			if tc.scope != "" {
				form.Set("scope", tc.scope)
			}
			r := post(t, f.Token, form)
			next := granted(t, r)
			access, err := f.Verify(bearer(next.access))
			if next.id != g.id || r.field("scope") != "read write" || err != nil || strings.Join(access.Scopes, " ") != "read write" ||
				f.store.calls["Revoke"] != 0 {
				t.Fatalf("scope %q, access %+v, %v", r.field("scope"), access, err)
			}
		})
	}

	t.Run("revocation failure", func(t *testing.T) {
		f := newFixture(t)
		g := f.connect("user")
		f.restrict("read")
		down := errors.New("backend down")
		f.store.fail["Revoke"] = down
		r := f.refresh(g.refresh)
		r.unavailable(t, down)
		if !strings.HasPrefix(r.err.Error(), "mcpoauth: revoke connection: ") || r.event.ConnectionID != g.id || r.event.Subject != "user" {
			t.Fatalf("err %v, event %+v", r.err, r.event)
		}
	})
}

// A scope list on a client that does not restrict scopes is an invalid record
// at every endpoint that resolves the client.
func TestClientScopesInvalidRecord(t *testing.T) {
	f := newFixture(t)
	g := f.connect("user")
	code := f.code(authParams(), "user")
	client := f.clients["public"]
	client.Scopes = []string{"read", "write"}
	f.clients["public"] = client
	for _, token := range []string{g.access, g.refresh} {
		r := post(t, f.Revocation, url.Values{"client_id": {"public"}, "token": {token}})
		r.unavailable(t, ErrRecord)
		if r.event != (Event{}) {
			t.Fatalf("event %+v", r.event)
		}
	}
	f.refresh(g.refresh).unavailable(t, ErrRecord)
	post(t, f.Token, exchangeForm(code)).unavailable(t, ErrRecord)
	if f.store.calls["Revoke"] != 0 || f.store.calls["Rotate"] != 0 || f.store.calls["TakeCode"] != 1 || !f.valid(g.access) {
		t.Fatalf("an invalid client record reached the store: %v", f.store.calls)
	}
	// The same list is valid once the record restricts scopes.
	f.restrict("read", "write")
	granted(t, f.refresh(g.refresh))
}
