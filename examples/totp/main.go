// Command totp runs a single-account HTTPS sign-in example on loopback.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/i2bskn/authlume/password"
	"github.com/i2bskn/authlume/session"
	"github.com/i2bskn/authlume/totp"
)

const demoSubject = "local-demo-user"

func main() {
	cert := flag.String("cert", "", "localhost TLS certificate")
	key := flag.String("key", "", "localhost TLS private key")
	require := flag.Bool("require-mfa", false, "require the demo user's enrolled TOTP")
	flag.Parse()
	h, err := demo(os.Getenv("AUTHLUME_PASSWORD"), os.Getenv("AUTHLUME_TOTP_SECRET"), *require, time.Now)
	if err != nil {
		log.Fatal(err)
	}
	srv := http.Server{Addr: "127.0.0.1:8444", Handler: h, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

// enrollment is a single-process store for this demo's one pre-enrolled user.
type enrollment struct {
	credential totp.Credential
	mu         sync.Mutex
	lastStep   int64
}

func (s *enrollment) Load(_ context.Context, subject string) (totp.Credential, error) {
	if subject != demoSubject {
		return totp.Credential{}, totp.ErrInvalid
	}
	return s.credential, nil
}

func (s *enrollment) Consume(ctx context.Context, subject, id string, step int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if subject != demoSubject || id != s.credential.ID || step <= s.lastStep {
		return totp.ErrInvalid
	}
	s.lastStep = step
	return nil
}

// All sign-in attempts share a bounded budget for this single-account demo.
type attempts struct {
	mu    sync.Mutex
	reset time.Time
	count int
}

func (a *attempts) allow(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !now.Before(a.reset) {
		a.reset = now.Add(time.Minute)
		a.count = 0
	}
	if a.count >= 5 {
		return false
	}
	a.count++
	return true
}

func demo(secret, encoded string, require bool, now func() time.Time) (http.Handler, error) {
	hash, err := password.Hash(secret)
	if err != nil {
		return nil, errors.New("set AUTHLUME_PASSWORD to a demo password of 1–1024 bytes")
	}
	var policy password.Policy
	var verifier *totp.Verifier
	if require {
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encoded))
		if err != nil || len(raw) < 20 {
			return nil, errors.New("set AUTHLUME_TOTP_SECRET to an unpadded Base32 seed of at least 20 decoded bytes")
		}
		store := &enrollment{credential: totp.Credential{ID: rand.Text(), Secret: raw},
			lastStep: now().Unix() / 30} // Restart: exclude every step already eligible before startup.
		verifier, err = totp.New(store, now)
		if err != nil {
			return nil, err
		}
		policy = func(context.Context, string) (password.Decision, error) { return password.RequireMFA, nil }
	}
	auth, err := password.New(func(_ context.Context, username string) (password.Credential, error) {
		if username != "demo" {
			return password.Credential{}, password.ErrNotFound
		}
		return password.Credential{Subject: demoSubject, Hash: hash}, nil
	}, policy)
	if err != nil {
		return nil, err
	}
	sessions, err := session.New(session.NewMemoryStore(), session.Config{CookieName: "__Host-authlume-totp", Now: now})
	if err != nil {
		return nil, err
	}
	return handler(auth, verifier, sessions, now), nil
}

const form = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Demo sign-in</title>
<h1>Sign in</h1><form method="post" action="/login">
<p><label>Username <input name="username" autocomplete="username" required></label></p>
<p><label>Password <input type="password" name="password" autocomplete="current-password" required></label></p>
<p><label>Authenticator code (when required) <input name="code" autocomplete="one-time-code" inputmode="numeric"></label></p>
<button>Sign in</button></form></html>`

func handler(auth *password.Authenticator, verifier *totp.Verifier, sessions *session.Manager, now func() time.Time) http.Handler {
	var budget attempts
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, form)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form.", http.StatusBadRequest)
			return
		}
		if !budget.allow(now()) {
			http.Error(w, "Try again later.", http.StatusTooManyRequests)
			return
		}
		result, err := auth.Authenticate(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"))
		if err == nil {
			switch result.Decision {
			case password.RequireMFA:
				code := r.PostForm.Get("code")
				// Some authenticators display two groups of three digits.
				if len(code) == 7 && code[3] == ' ' {
					code = code[:3] + code[4:]
				}
				err = verifier.Verify(r.Context(), result.Subject, code)
			case password.PasswordOnly:
				// The application policy is already complete.
			default:
				err = errors.New("unknown login policy")
			}
		}
		if errors.Is(err, password.ErrCredentials) || errors.Is(err, totp.ErrInvalid) {
			http.Error(w, "Invalid credentials.", http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, "Sign-in unavailable.", http.StatusServiceUnavailable)
			return
		}
		if err := sessions.Issue(w, r, result.Subject); err != nil {
			http.Error(w, "Session could not be issued.", http.StatusServiceUnavailable)
			return
		}
		http.Redirect(w, r, "/protected", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /protected", func(w http.ResponseWriter, r *http.Request) {
		if _, err := sessions.Read(r); err != nil {
			http.Error(w, "Sign in to continue.", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "You are signed in.\n")
	})
	protected := http.NewCrossOriginProtection().Handler(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		protected.ServeHTTP(w, r)
	})
}
