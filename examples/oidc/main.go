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

func routes(client *oidc.Client, sessions *session.Manager, policy accountPolicy) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<form method="post" action="/login"><button>Sign in with OpenID Connect</button></form>`)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if err := client.Begin(w, r); err != nil {
			http.Error(w, "Unable to start sign-in", http.StatusServiceUnavailable)
		}
	})
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
			http.Error(w, "Unable to start session", http.StatusConflict)
			return
		}
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		state, err := sessions.Read(r)
		if err != nil {
			http.Error(w, "Sign-in required", http.StatusUnauthorized)
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
	srv := &http.Server{Addr: "127.0.0.1:8443", Handler: routes(client, sessions, policy), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}
