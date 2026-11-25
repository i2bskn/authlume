// Command web runs a single-account, loopback-only HTTPS example.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/i2bskn/authlume/password"
	"github.com/i2bskn/authlume/session"
)

func main() {
	cert := flag.String("cert", "", "TLS certificate PEM file")
	key := flag.String("key", "", "TLS private key PEM file")
	requireMFA := flag.Bool("require-mfa", false, "require another authentication factor for the demo account")
	idle := flag.Duration("idle", session.DefaultIdle, "session idle timeout")
	absolute := flag.Duration("absolute", session.DefaultAbsolute, "absolute session lifetime")
	flag.Parse()
	if *cert == "" || *key == "" {
		log.Fatal("supply -cert and -key for the local HTTPS server")
	}
	auth, err := demoAuthenticator(os.Getenv("AUTHLUME_PASSWORD"), *requireMFA)
	if err != nil {
		log.Fatal(err)
	}
	sessions, err := session.New(session.NewMemoryStore(), session.Config{Idle: *idle, Absolute: *absolute})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              "127.0.0.1:8443",
		Handler:           handler(auth, sessions),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       time.Minute,
	}
	log.Printf("Sign in as demo at https://%s/", server.Addr)
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}

func demoAuthenticator(secret string, requireMFA bool) (*password.Authenticator, error) {
	if secret == "" {
		return nil, errors.New("set AUTHLUME_PASSWORD to the demo account password")
	}
	hash, err := password.Hash(secret)
	if err != nil {
		return nil, fmt.Errorf("initialize demo password: %w", err)
	}
	lookup := func(_ context.Context, name string) (password.Credential, error) {
		if name != "demo" {
			return password.Credential{}, password.ErrNotFound
		}
		return password.Credential{Subject: "demo", Hash: hash}, nil
	}
	if requireMFA {
		return password.New(lookup, func(context.Context, string) (password.Decision, error) {
			return password.RequireMFA, nil
		})
	}
	return password.New(lookup, nil)
}

const loginPage = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign in</title>
<h1>Sign in</h1><form action="/login" method="post">
<p><label>Username <input name="username" value="demo" required autocomplete="username"></label></p>
<p><label>Password <input type="password" name="password" required autocomplete="current-password"></label></p>
<button>Sign in</button></form></html>`

const protectedPage = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Protected page</title>
<h1>Protected page</h1><p>You are signed in.</p>
<form method="post" action="/activity"><button>Record my activity</button></form>
<form method="post" action="/logout"><button>Sign out</button></form></html>`

func writePage(w http.ResponseWriter, page string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, page)
}

func sessionError(w http.ResponseWriter, err error) {
	if errors.Is(err, session.ErrInvalid) {
		http.Error(w, "Sign in to continue.", http.StatusUnauthorized)
		return
	}
	http.Error(w, "Session service unavailable.", http.StatusServiceUnavailable)
}

func handler(auth *password.Authenticator, sessions *session.Manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		writePage(w, loginPage)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form.", http.StatusBadRequest)
			return
		}
		result, err := auth.Authenticate(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"))
		if errors.Is(err, password.ErrCredentials) {
			http.Error(w, "Invalid credentials.", http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, "Sign-in service unavailable.", http.StatusServiceUnavailable)
			return
		}
		switch result.Decision {
		case password.PasswordOnly:
			if err := sessions.Issue(w, r, result.Subject); err != nil {
				sessionError(w, err)
				return
			}
			http.Redirect(w, r, "/protected", http.StatusSeeOther)
		case password.RequireMFA:
			http.Error(w, "Another factor is required to finish signing in.", http.StatusForbidden)
		default:
			http.Error(w, "Sign-in policy unavailable.", http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc("GET /protected", func(w http.ResponseWriter, r *http.Request) {
		if _, err := sessions.Read(r); err != nil {
			sessionError(w, err)
			return
		}
		writePage(w, protectedPage)
	})
	mux.HandleFunc("GET /poll", func(w http.ResponseWriter, r *http.Request) {
		if _, err := sessions.Read(r); err != nil {
			sessionError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /activity", func(w http.ResponseWriter, r *http.Request) {
		if _, err := sessions.Touch(r); err != nil {
			sessionError(w, err)
			return
		}
		http.Redirect(w, r, "/protected", http.StatusSeeOther)
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		if err := sessions.Logout(w, r); err != nil {
			sessionError(w, err)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	protected := http.NewCrossOriginProtection().Handler(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		protected.ServeHTTP(w, r)
	})
}
