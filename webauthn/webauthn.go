// Package webauthn verifies WebAuthn as a second factor for an already identified
// application subject. The caller authorizes enrollment and owns MFA policy,
// browser binding, recovery, rate limits and issuance of application sessions.
package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

// ErrInvalid means the ceremony cannot complete. Start again with a fresh first factor.
var ErrInvalid = errors.New("webauthn: invalid ceremony or response")

// Credential is the public WebAuthn credential record. Persist the whole record.
type Credential = wa.Credential

// Record identifies the exact active revision of a credential.
type Record struct {
	Credential Credential
	Version    string
}

// Store is scoped to a relying party. Load returns an isolated snapshot of the
// active credentials for subject. Insert atomically enforces credential ID
// uniqueness across subjects and any application enrollment preconditions.
// Update atomically matches subject, credential ID and the expected active
// version before replacing the record. Both writes assign a fresh, never-reused
// version. A conflict or revocation must return an error, including for keys
// without a signature counter.
type Store interface {
	Load(ctx context.Context, subject string) ([]Record, error)
	Insert(ctx context.Context, subject string, credential Credential) error
	Update(ctx context.Context, subject, version string, credential Credential) error
}

// Verifier is configured once for the application's trusted origin.
type Verifier struct {
	origin string
	rp     *wa.WebAuthn
	store  Store
}

// New pins a single HTTPS origin (scheme and host, optionally a port) and
// uses its hostname as the RP ID. Supply trusted configuration at startup.
func New(origin, displayName string, store Store) (*Verifier, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || origin != "https://"+u.Host || displayName == "" || store == nil {
		return nil, errors.New("webauthn: expected an HTTPS origin, display name and store")
	}
	// Match the browser's serialized origin, including any nondefault port.
	origin = "https://" + strings.TrimSuffix(strings.ToLower(u.Host), ":443")
	timeout := wa.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute}
	rp, err := wa.New(&wa.Config{
		RPID: strings.ToLower(u.Hostname()), RPDisplayName: displayName, RPOrigins: []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts:              wa.TimeoutsConfig{Registration: timeout, Login: timeout},
	})
	if err != nil {
		return nil, err
	}
	return &Verifier{origin: origin, rp: rp, store: store}, nil
}

type account struct {
	subject, name string
	keys          wa.Credentials
	versions      map[string]string
}

func (a account) WebAuthnID() []byte                { return []byte(a.subject) }
func (a account) WebAuthnName() string              { return a.name }
func (a account) WebAuthnDisplayName() string       { return a.name }
func (a account) WebAuthnCredentials() []Credential { return a.keys }

func (v *Verifier) load(ctx context.Context, subject, name string) (account, error) {
	if len(subject) == 0 || len(subject) > 64 {
		return account{}, ErrInvalid
	}
	records, err := v.store.Load(ctx, subject)
	if err != nil {
		return account{}, err
	}
	a := account{subject: subject, name: name, versions: make(map[string]string, len(records))}
	for _, r := range records {
		id := string(r.Credential.ID)
		if id == "" || r.Version == "" || a.versions[id] != "" || len(r.Credential.PublicKey) == 0 {
			return account{}, errors.New("webauthn: invalid credential record")
		}
		a.keys = append(a.keys, r.Credential)
		a.versions[id] = r.Version
	}
	return a, nil
}

// Ceremony holds five minutes of single-use server-side state. Keep it in the
// initiating browser's server-side transaction, on the instance that created it.
type Ceremony struct{ state *pending }

type pending struct {
	used    atomic.Bool
	owner   *Verifier
	purpose protocol.CeremonyType
	user    account
	session *wa.SessionData
}

func (v *Verifier) take(c *Ceremony, subject string, purpose protocol.CeremonyType) (*pending, error) {
	if c == nil || c.state == nil {
		return nil, ErrInvalid
	}
	p := c.state
	if p.used.Swap(true) || p.owner != v || p.purpose != purpose || p.user.subject != subject || !time.Now().Before(p.session.Expires) {
		return nil, ErrInvalid
	}
	return p, nil
}

// BeginRegistration requires a freshly authorized enrollment for subject, a
// stable opaque handle of 1–64 bytes. name is a human-readable account label.
func (v *Verifier) BeginRegistration(ctx context.Context, subject, name string) (*protocol.CredentialCreation, *Ceremony, error) {
	if name == "" {
		return nil, nil, ErrInvalid
	}
	a, err := v.load(ctx, subject, name)
	if err != nil {
		return nil, nil, err
	}
	options, session, err := v.rp.BeginRegistration(a, wa.WithExclusions(a.keys.CredentialDescriptors()))
	if err != nil {
		return nil, nil, err
	}
	return options, &Ceremony{&pending{owner: v, purpose: protocol.CreateCeremony, user: a, session: session}}, nil
}

// FinishRegistration consumes the ceremony and inserts the verified key.
// response is the browser credential JSON. Limit its size before reading it.
func (v *Verifier) FinishRegistration(ctx context.Context, subject string, c *Ceremony, response []byte) error {
	p, err := v.take(c, subject, protocol.CreateCeremony)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if parsed.Response.CollectedClientData.Origin != v.origin {
		return ErrInvalid
	}
	key, err := v.rp.CreateCredential(p.user, *p.session, parsed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(key.ID) == 0 || parsed.ID != base64.RawURLEncoding.EncodeToString(key.ID) || !bytes.Equal(parsed.RawID, key.ID) {
		return ErrInvalid
	}
	return v.store.Insert(ctx, subject, *key)
}

// BeginVerification starts an assertion restricted to the verified first-factor
// subject's active credentials. An account with no credentials cannot proceed.
func (v *Verifier) BeginVerification(ctx context.Context, subject string) (*protocol.CredentialAssertion, *Ceremony, error) {
	a, err := v.load(ctx, subject, "")
	if err != nil {
		return nil, nil, err
	}
	if len(a.keys) == 0 {
		return nil, nil, ErrInvalid
	}
	options, session, err := v.rp.BeginLogin(a)
	if err != nil {
		return nil, nil, err
	}
	return options, &Ceremony{&pending{owner: v, purpose: protocol.AssertCeremony, user: a, session: session}}, nil
}

// FinishVerification consumes the ceremony. Only nil authorizes the caller to
// count the second factor as verified for subject.
func (v *Verifier) FinishVerification(ctx context.Context, subject string, c *Ceremony, response []byte) error {
	p, err := v.take(c, subject, protocol.AssertCeremony)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if parsed.Response.CollectedClientData.Origin != v.origin || parsed.ID != base64.RawURLEncoding.EncodeToString(parsed.RawID) {
		return ErrInvalid
	}
	key, err := v.rp.ValidateLogin(p.user, *p.session, parsed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if key.Authenticator.CloneWarning {
		return ErrInvalid
	}
	return v.store.Update(ctx, subject, p.user.versions[string(key.ID)], *key)
}
