// Command mcp runs an OAuth authorization server and a protected MCP endpoint
// for one pre-registered client and one demo user on loopback HTTPS.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/i2bskn/authlume/mcpoauth"
	"github.com/i2bskn/authlume/password"
	"github.com/i2bskn/authlume/session"
)

const demoSubject = "local-demo-user"

func main() {
	cert := flag.String("cert", "", "localhost TLS certificate")
	key := flag.String("key", "", "localhost TLS private key")
	flag.Parse()
	client := mcpoauth.Client{ID: os.Getenv("MCP_CLIENT_ID"), Name: "Demo MCP client",
		RedirectURIs: []string{os.Getenv("MCP_REDIRECT_URI")}}
	if secret := os.Getenv("MCP_CLIENT_SECRET"); secret != "" {
		digest := sha256.Sum256([]byte(secret))
		client.Secret = &digest
	}
	h, err := demo("https://127.0.0.1:8446", os.Getenv("AUTHLUME_PASSWORD"), client, mcpoauth.NewMemoryStore(), time.Now)
	if err != nil {
		log.Fatal(err)
	}
	srv := http.Server{Addr: "127.0.0.1:8446", Handler: h, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

// demo serves the authorization server at origin and the MCP endpoint at
// origin + "/mcp". The store's subject listing backs the connections page.
func demo(origin, secret string, client mcpoauth.Client, store *mcpoauth.MemoryStore, now func() time.Time) (http.Handler, error) {
	if store == nil || client.Validate() != nil {
		return nil, errors.New("set MCP_CLIENT_ID and MCP_REDIRECT_URI to a client ID and an HTTPS or loopback HTTP redirect URI")
	}
	hash, err := password.Hash(secret)
	if err != nil {
		return nil, errors.New("set AUTHLUME_PASSWORD to a demo password of 1–1024 bytes")
	}
	auth, err := password.New(func(_ context.Context, username string) (password.Credential, error) {
		if username != "demo" {
			return password.Credential{}, password.ErrNotFound
		}
		return password.Credential{Subject: demoSubject, Hash: hash}, nil
	}, nil)
	if err != nil {
		return nil, err
	}
	sessions, err := session.New(session.NewMemoryStore(), session.Config{CookieName: "__Host-authlume-mcp", Now: now})
	if err != nil {
		return nil, err
	}
	oauth, err := mcpoauth.New(mcpoauth.Config{
		Issuer: origin, Resource: origin + "/mcp",
		AuthorizationEndpoint: origin + "/authorize", TokenEndpoint: origin + "/token", RevocationEndpoint: origin + "/revoke",
		Scopes: []string{"mcp:read", "mcp:write"}, DefaultScopes: []string{"mcp:read"}, Now: now,
	}, func(_ context.Context, id string) (mcpoauth.Client, error) {
		if id != client.ID {
			return mcpoauth.Client{}, mcpoauth.ErrNotFound
		}
		return client, nil
	}, store)
	if err != nil {
		return nil, err
	}
	a := &app{auth: auth, sessions: sessions, oauth: oauth, store: store, now: now}

	// Browser routes carry the session cookie and need CSRF protection.
	browser := http.NewServeMux()
	browser.HandleFunc("GET /{$}", a.loginPage)
	browser.HandleFunc("POST /login", a.login)
	browser.HandleFunc("POST /logout", a.logout)
	browser.HandleFunc("GET /authorize", a.consentPage)
	browser.HandleFunc("POST /authorize", a.consent)
	browser.HandleFunc("GET /connections", a.connections)
	browser.HandleFunc("POST /connections/disconnect", a.disconnect)
	protected := http.NewCrossOriginProtection().Handler(browser)

	// OAuth clients and MCP requests authenticate without the cookie and are
	// not browser navigations, so they stay outside cross-origin protection.
	api := http.NewServeMux()
	api.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) { record("token", oauth.Token, w, r) })
	api.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) { record("revoke", oauth.Revocation, w, r) })
	api.HandleFunc("GET "+oauth.MetadataPath(), oauth.Metadata)
	api.HandleFunc("GET "+oauth.ResourceMetadataPath(), oauth.ResourceMetadata)
	// Some clients look for the resource metadata at the root.
	api.HandleFunc("GET /.well-known/oauth-protected-resource", oauth.ResourceMetadata)
	api.Handle("GET /mcp", oauth.Protect(http.HandlerFunc(a.describe), "mcp:read"))
	api.Handle("POST /mcp", oauth.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "mcp:write"))

	root := http.NewServeMux()
	for _, prefix := range []string{"/token", "/revoke", "/mcp", "/.well-known/"} {
		root.Handle(prefix, api)
	}
	root.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		protected.ServeHTTP(w, r)
	}))
	return root, nil
}

// record logs a failed token or revocation request without any token value.
func record(name string, handle func(http.ResponseWriter, *http.Request) (mcpoauth.Event, error), w http.ResponseWriter, r *http.Request) {
	event, err := handle(w, r)
	switch {
	case errors.Is(err, mcpoauth.ErrReused):
		log.Printf("%s: refresh token reuse revoked connection %s", name, event.ConnectionID)
	case err != nil:
		log.Printf("%s: client %q: %v", name, event.ClientID, err)
	}
}

type app struct {
	auth     *password.Authenticator
	sessions *session.Manager
	oauth    *mcpoauth.Server
	store    *mcpoauth.MemoryStore
	now      func() time.Time
}

var pages = template.Must(template.New("").Parse(`
{{define "login"}}<!doctype html><html lang="en"><meta charset="utf-8"><title>Demo sign-in</title>
<h1>Sign in</h1><form method="post" action="/login"><input type="hidden" name="next" value="{{.}}">
<p><label>Username <input name="username" autocomplete="username" required></label></p>
<p><label>Password <input type="password" name="password" autocomplete="current-password" required></label></p>
<button>Sign in</button></form></html>{{end}}

{{define "consent"}}<!doctype html><html lang="en"><meta charset="utf-8"><title>Connect an MCP client</title>
<h1>Connect {{.Request.ClientName}}?</h1>
<p>Client <code>{{.Request.ClientID}}</code> will receive the response at <strong>{{.Host}}</strong>.</p>
{{if .Loopback}}<p><strong>This client receives the response on this computer. Continue only if you started it yourself.</strong></p>{{end}}
<p>It asks for:</p><ul>{{range .Request.Scopes}}<li><code>{{.}}</code></li>{{end}}</ul>
<form method="post" action="/authorize"><input type="hidden" name="query" value="{{.Query}}">
<button name="decision" value="approve">Allow</button> <button name="decision" value="deny">Deny</button></form></html>{{end}}

{{define "connections"}}<!doctype html><html lang="en"><meta charset="utf-8"><title>MCP connections</title>
<h1>MCP connections</h1>{{range .}}
<form method="post" action="/connections/disconnect"><input type="hidden" name="id" value="{{.ID}}">
<p><code>{{.ClientID}}</code> with {{range .Scopes}}<code>{{.}}</code> {{end}}since {{.CreatedAt.Format "2006-01-02 15:04 MST"}}
<button>Disconnect</button></p></form>{{else}}<p>No client is connected.</p>{{end}}
<form method="post" action="/logout"><button>Sign out</button></form></html>{{end}}
`))

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

func sessionError(w http.ResponseWriter, err error) {
	if errors.Is(err, session.ErrInvalid) {
		http.Error(w, "Sign in to continue.", http.StatusUnauthorized)
		return
	}
	http.Error(w, "Session service unavailable.", http.StatusServiceUnavailable)
}

// leave sends the browser to the client's redirect URI, which carries a code
// or an error. The response must not be cached or leak through a referrer.
func leave(w http.ResponseWriter, r *http.Request, target string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// authorizationError forwards a rejection to the client. This demo has one
// pre-registered client. An application with open registration shows an error
// page instead, so that it cannot be used as an open redirector.
func authorizationError(w http.ResponseWriter, r *http.Request, err error) {
	var reject *mcpoauth.RejectError
	switch {
	case errors.As(err, &reject):
		leave(w, r, reject.RedirectURL)
	case errors.Is(err, mcpoauth.ErrInvalid):
		http.Error(w, "Invalid authorization request.", http.StatusBadRequest)
	default:
		http.Error(w, "Authorization unavailable.", http.StatusServiceUnavailable)
	}
}

func (a *app) loginPage(w http.ResponseWriter, r *http.Request) {
	render(w, "login", r.URL.Query().Get("next"))
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form.", http.StatusBadRequest)
		return
	}
	result, err := a.auth.Authenticate(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"))
	if errors.Is(err, password.ErrCredentials) {
		http.Error(w, "Invalid credentials.", http.StatusUnauthorized)
		return
	}
	if err != nil || result.Decision != password.PasswordOnly {
		http.Error(w, "Sign-in unavailable.", http.StatusServiceUnavailable)
		return
	}
	if err := a.sessions.Issue(w, r, result.Subject); err != nil {
		http.Error(w, "Session could not be issued.", http.StatusServiceUnavailable)
		return
	}
	// Only return to this server's own authorization endpoint.
	target := "/connections"
	if next := r.PostForm.Get("next"); strings.HasPrefix(next, "/authorize?") {
		target = next
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if err := a.sessions.Logout(w, r); err != nil {
		sessionError(w, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) consentPage(w http.ResponseWriter, r *http.Request) {
	request, err := a.oauth.Authorize(r.Context(), r.URL.RawQuery)
	if err != nil {
		authorizationError(w, r, err)
		return
	}
	if _, err := a.sessions.Read(r); errors.Is(err, session.ErrInvalid) {
		http.Redirect(w, r, "/?next="+url.QueryEscape("/authorize?"+r.URL.RawQuery), http.StatusSeeOther)
		return
	} else if err != nil {
		sessionError(w, err)
		return
	}
	redirect, err := url.Parse(request.RedirectURI)
	if err != nil {
		http.Error(w, "Invalid authorization request.", http.StatusBadRequest)
		return
	}
	// The same query string returns in the form, so the request approved by
	// the POST is the one displayed here.
	render(w, "consent", struct {
		Request  mcpoauth.Request
		Host     string
		Loopback bool
		Query    string
	}{request, redirect.Host, redirect.Scheme == "http", r.URL.RawQuery})
}

func (a *app) consent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form.", http.StatusBadRequest)
		return
	}
	state, err := a.sessions.Touch(r)
	if err != nil {
		sessionError(w, err)
		return
	}
	query := r.PostForm.Get("query")
	var target string
	if r.PostForm.Get("decision") == "approve" {
		_, target, err = a.oauth.Approve(r.Context(), query, state.Subject)
	} else {
		target, err = a.oauth.Deny(r.Context(), query)
	}
	if err != nil {
		authorizationError(w, r, err)
		return
	}
	leave(w, r, target)
}

func (a *app) connections(w http.ResponseWriter, r *http.Request) {
	state, err := a.sessions.Read(r)
	if err != nil {
		sessionError(w, err)
		return
	}
	conns, err := a.store.Connections(r.Context(), state.Subject, a.now())
	if err != nil {
		http.Error(w, "Connections unavailable.", http.StatusServiceUnavailable)
		return
	}
	render(w, "connections", conns)
}

func (a *app) disconnect(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form.", http.StatusBadRequest)
		return
	}
	state, err := a.sessions.Touch(r)
	if err != nil {
		sessionError(w, err)
		return
	}
	// Disconnect takes any connection ID: confirm it is the user's own first.
	conns, err := a.store.Connections(r.Context(), state.Subject, a.now())
	if err != nil {
		http.Error(w, "Connections unavailable.", http.StatusServiceUnavailable)
		return
	}
	id := r.PostForm.Get("id")
	for _, conn := range conns {
		if conn.ID != id {
			continue
		}
		if err := a.oauth.Disconnect(r.Context(), id); err != nil {
			http.Error(w, "Connections unavailable.", http.StatusServiceUnavailable)
			return
		}
		http.Redirect(w, r, "/connections", http.StatusSeeOther)
		return
	}
	http.NotFound(w, r)
}

// describe stands in for an MCP method: it reports who the token acts for.
// A real server also checks the user's current state and permissions.
func (a *app) describe(w http.ResponseWriter, r *http.Request) {
	access, ok := mcpoauth.FromContext(r.Context())
	if !ok {
		http.Error(w, "Access unavailable.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"subject": access.Subject, "client_id": access.ClientID, "scopes": access.Scopes,
	}); err != nil {
		log.Printf("mcp: %v", err)
	}
}
