// Command oidc runs a loopback HTTPS relying party with one preauthorized link.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/i2bskn/authlume/oidc"
	"github.com/i2bskn/authlume/session"
)

type accountPolicy struct {
	external    oidc.ExternalID
	local       string
	requireMFA  bool
	acceptedACR string
}

func (p accountPolicy) acceptsAssurance(id oidc.Identity, now time.Time) bool {
	if !p.requireMFA {
		return true
	}
	// This value is an explicit agreement with this particular issuer.
	// The sample also requires authentication within the past five minutes.
	at := id.Assurance.AuthTime
	return id.ID.Issuer == p.external.Issuer && p.acceptedACR != "" && id.Assurance.ACR == p.acceptedACR &&
		!at.IsZero() && !at.After(now) && now.Sub(at) < 5*time.Minute
}

// This loopback, single-account example shares one start budget across callers.
type startBudget struct {
	mu    sync.Mutex
	used  int
	reset time.Time
}

func (b *startBudget) retryAfter(now time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !now.Before(b.reset) {
		b.used = 0
		b.reset = now.Add(time.Minute)
	}
	if b.used >= 5 {
		return int((b.reset.Sub(now) + time.Second - 1) / time.Second)
	}
	b.used++
	return 0
}

func (b *startBudget) limit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if seconds := b.retryAfter(time.Now()); seconds > 0 {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			http.Error(w, "Try sign-in again later", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func (p accountPolicy) authorizationOptions() oidc.AuthorizationOptions {
	if !p.requireMFA || p.acceptedACR == "" {
		return oidc.AuthorizationOptions{}
	}
	age := int64(300)
	return oidc.AuthorizationOptions{MaxAgeSeconds: &age, ACRValues: []string{p.acceptedACR}}
}

func routes(client *oidc.Client, sessions *session.Manager, policy accountPolicy) http.Handler {
	mux := http.NewServeMux()
	var budget startBudget
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<form method="post" action="/login"><button>Sign in with OpenID Connect</button></form>`)
	})
	mux.HandleFunc("POST /login", budget.limit(func(w http.ResponseWriter, r *http.Request) {
		if err := client.BeginWithOptions(w, r, policy.authorizationOptions()); err != nil {
			http.Error(w, "Unable to start sign-in", http.StatusServiceUnavailable)
		}
	}))
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		id, err := client.Complete(w, r)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, oidc.ErrInvalid) {
				status = http.StatusUnauthorized
			}
			http.Error(w, "Unable to complete sign-in", status)
			return
		}
		// The operator preauthorized exactly one external identity for this
		// local account. Unknown identities require a separate enrollment flow.
		if id.ID != policy.external || policy.local == "" {
			http.Error(w, "Account linking required", http.StatusForbidden)
			return
		}
		if !policy.acceptsAssurance(id, time.Now()) {
			// An integrating app can begin its own subject-bound MFA flow here.
			http.Error(w, "Additional authentication required", http.StatusForbidden)
			return
		}
		if err := sessions.Issue(w, r, policy.local); err != nil {
			if errors.Is(err, session.ErrInvalid) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `<p>The session cookie could not be read.</p><form method="post" action="/reset-cookie"><button>Reset cookie and sign in again</button></form>`)
			} else {
				http.Error(w, "Unable to start session", http.StatusServiceUnavailable)
			}
			return
		}
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	})
	mux.HandleFunc("POST /reset-cookie", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		err := sessions.ResetInvalidCookie(w, r)
		if errors.Is(err, session.ErrCookieWellFormed) {
			http.Error(w, "Cookie is readable; start sign-in again", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, "Unable to reset cookie", http.StatusServiceUnavailable)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		state, err := sessions.Read(r)
		if err != nil {
			if errors.Is(err, session.ErrInvalid) {
				http.Error(w, "Sign-in required", http.StatusUnauthorized)
			} else {
				http.Error(w, "Session unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, state.Subject)
	})
	return http.NewCrossOriginProtection().Handler(mux)
}

func main() {
	cert := flag.String("cert", "", "TLS certificate for 127.0.0.1")
	key := flag.String("key", "", "TLS private key")
	requireMFA := flag.Bool("require-mfa", true, "require recent provider MFA or additional authentication")
	flag.Parse()
	cfg := oidc.Config{
		Issuer: os.Getenv("OIDC_ISSUER"), ClientID: os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"), RedirectURL: "https://127.0.0.1:8443/callback",
	}
	policy := accountPolicy{
		external: oidc.ExternalID{Issuer: cfg.Issuer, Subject: os.Getenv("OIDC_SUBJECT")},
		local:    os.Getenv("LOCAL_ACCOUNT"), requireMFA: *requireMFA, acceptedACR: os.Getenv("OIDC_ACCEPTED_ACR"),
	}
	if *cert == "" || *key == "" || policy.local == "" || policy.external.Subject == "" {
		log.Fatal("configure -cert, -key, LOCAL_ACCOUNT and OIDC_SUBJECT")
	}
	client, err := oidc.New(context.Background(), cfg, oidc.NewMemoryStore())
	if err != nil {
		log.Fatal(err)
	}
	sessions, err := session.New(session.NewMemoryStore(), session.Config{CookieName: "__Host-authlume-oidc-demo-session"})
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: "127.0.0.1:8443", Handler: routes(client, sessions, policy), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}
