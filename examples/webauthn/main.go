// Command webauthn serves a single-account, single-process HTTPS demonstration.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/i2bskn/authlume/password"
	"github.com/i2bskn/authlume/session"
	"github.com/i2bskn/authlume/webauthn"
)

const (
	origin      = "https://localhost:8445"
	demoSubject = "local-demo-user"
	flowCookie  = "__Host-authlume-webauthn-flow"
)

//go:embed index.html
var page string

func main() {
	cert := flag.String("cert", "", "localhost TLS certificate")
	key := flag.String("key", "", "localhost TLS private key")
	flag.Parse()
	h, err := demo(os.Getenv("AUTHLUME_PASSWORD"), os.Getenv("AUTHLUME_ENROLLMENT_CODE"), new(demoStore))
	if err != nil {
		log.Fatal(err)
	}
	srv := http.Server{Addr: "127.0.0.1:8445", Handler: h, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

type transaction struct {
	subject  string
	ceremony *webauthn.Ceremony
	expires  time.Time
}

type app struct {
	auth     *password.Authenticator
	keys     *webauthn.Verifier
	sessions *session.Manager
	code     string
	mu       sync.Mutex
	pending  map[string]transaction
	reset    time.Time
	attempts int
}

func demo(secret, code string, store *demoStore) (http.Handler, error) {
	hash, err := password.Hash(secret)
	if err != nil {
		return nil, errors.New("set AUTHLUME_PASSWORD to a demo password of 1–1024 bytes")
	}
	if b, err := base64.StdEncoding.Strict().DecodeString(code); err != nil || len(b) != 32 {
		return nil, errors.New("set AUTHLUME_ENROLLMENT_CODE using openssl rand -base64 32")
	}
	auth, err := password.New(func(_ context.Context, username string) (password.Credential, error) {
		if username != "demo" {
			return password.Credential{}, password.ErrNotFound
		}
		return password.Credential{Subject: demoSubject, Hash: hash}, nil
	}, func(context.Context, string) (password.Decision, error) { return password.RequireMFA, nil })
	if err != nil {
		return nil, err
	}
	keys, err := webauthn.New(origin, "Authlume demo", store)
	if err != nil {
		return nil, err
	}
	sessions, err := session.New(session.NewMemoryStore(), session.Config{CookieName: "__Host-authlume-webauthn"})
	if err != nil {
		return nil, err
	}
	a := &app{auth: auth, keys: keys, sessions: sessions, code: code, pending: make(map[string]transaction)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, page)
	})
	for _, action := range []string{"register", "login"} {
		mux.HandleFunc("POST /"+action+"/begin", func(w http.ResponseWriter, r *http.Request) { a.begin(w, r, action) })
		mux.HandleFunc("POST /"+action+"/finish", func(w http.ResponseWriter, r *http.Request) { a.finish(w, r, action) })
	}
	mux.HandleFunc("GET /protected", func(w http.ResponseWriter, r *http.Request) {
		if _, err := sessions.Read(r); err != nil {
			deny(w)
			return
		}
		io.WriteString(w, "You are signed in.\n")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		if r.Method == http.MethodPost && r.Header.Get("Origin") != origin {
			http.Error(w, "Invalid origin.", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
}

func deny(w http.ResponseWriter) { http.Error(w, "Authentication failed.", http.StatusUnauthorized) }

func (a *app) allow(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, tx := range a.pending {
		if !now.Before(tx.expires) {
			delete(a.pending, id)
		}
	}
	if !now.Before(a.reset) {
		a.reset = now.Add(time.Minute)
		a.attempts = 0
	}
	if a.attempts >= 5 {
		return false
	}
	a.attempts++
	return true
}

func (a *app) begin(w http.ResponseWriter, r *http.Request, action string) {
	if !a.allow(time.Now()) {
		http.Error(w, "Try again later.", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		deny(w)
		return
	}
	user, err := a.auth.Authenticate(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"))
	if err != nil || user.Decision != password.RequireMFA {
		deny(w)
		return
	}
	var options any
	var ceremony *webauthn.Ceremony
	if action == "register" {
		if subtle.ConstantTimeCompare([]byte(a.code), []byte(r.PostForm.Get("code"))) != 1 {
			deny(w)
			return
		}
		creation, pending, beginErr := a.keys.BeginRegistration(r.Context(), user.Subject, "demo")
		if beginErr != nil || len(creation.Response.CredentialExcludeList) != 0 {
			deny(w)
			return
		}
		options, ceremony = creation, pending
	} else {
		options, ceremony, err = a.keys.BeginVerification(r.Context(), user.Subject)
	}
	if err != nil {
		deny(w)
		return
	}
	id := rand.Text()
	a.mu.Lock()
	// A new begin supersedes the previous transaction in this browser.
	for _, old := range r.CookiesNamed(flowCookie) {
		delete(a.pending, old.Value)
	}
	a.pending[id] = transaction{user.Subject, ceremony, time.Now().Add(5 * time.Minute)}
	a.mu.Unlock()
	setFlowCookie(w, id, 300)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func setFlowCookie(w http.ResponseWriter, id string, age int) {
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: id, Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: age})
}

func (a *app) finish(w http.ResponseWriter, r *http.Request, action string) {
	cookies := r.CookiesNamed(flowCookie)
	if len(cookies) != 1 {
		deny(w)
		return
	}
	a.mu.Lock()
	tx, ok := a.pending[cookies[0].Value]
	delete(a.pending, cookies[0].Value)
	a.mu.Unlock()
	setFlowCookie(w, "", -1)
	if !ok || !time.Now().Before(tx.expires) {
		deny(w)
		return
	}
	response, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	if err != nil {
		deny(w)
		return
	}
	if action == "register" {
		if err := a.keys.FinishRegistration(r.Context(), tx.subject, tx.ceremony, response); err != nil {
			deny(w)
			return
		}
	} else {
		if err := a.keys.FinishVerification(r.Context(), tx.subject, tx.ceremony, response); err != nil {
			deny(w)
			return
		}
		if err := a.sessions.Issue(w, r, tx.subject); err != nil {
			http.Error(w, "Session unavailable.", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
