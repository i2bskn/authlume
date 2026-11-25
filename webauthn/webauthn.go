// Package webauthn verifies WebAuthn as a second factor for an already identified
// application subject. The caller authorizes enrollment and owns MFA policy,
// browser binding, recovery, rate limits and issuance of application sessions.
package webauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

var (
	// ErrInvalid means the ceremony cannot complete. Start again with a fresh first factor.
	ErrInvalid = errors.New("webauthn: invalid ceremony or response")
	// ErrRecord means the credential or ceremony store returned an invalid record.
	ErrRecord = errors.New("webauthn: invalid stored record")
	// ErrCloned wraps ErrInvalid. The signature counter did not increase.
	ErrCloned = fmt.Errorf("%w: signature counter did not increase", ErrInvalid)
)

// Credential is the public WebAuthn credential record. Persist the whole record.
// Its persisted form is go-webauthn's JSON encoding. Check compatibility when
// upgrading that dependency.
type Credential = wa.Credential

// Record identifies the exact active revision of a credential.
type Record struct {
	Credential Credential
	Version    string
}

// Store is scoped to a relying party.
type Store interface {
	// Load returns an isolated snapshot of the active credentials for subject.
	// Return an empty list for a subject without credentials. Return backend
	// failures as errors distinct from ErrInvalid.
	Load(ctx context.Context, subject string) ([]Record, error)
	// Insert atomically enforces credential ID uniqueness across subjects and any
	// application enrollment preconditions, and assigns a fresh, never-reused
	// version. Return ErrInvalid when a uniqueness or precondition check fails.
	Insert(ctx context.Context, subject string, credential Credential) error
	// Update atomically matches subject, credential ID and the expected active
	// version, replaces the record and assigns a fresh, never-reused version.
	// Return ErrInvalid for a mismatch, conflict or revocation, including for
	// keys without a signature counter.
	Update(ctx context.Context, subject, version string, credential Credential) error
}

// Verifier is configured once for the application's trusted origin.
type Verifier struct {
	origin      string
	rpID        string
	rp          *wa.WebAuthn
	credentials Store
	ceremonies  CeremonyStore
}

// New pins a single HTTPS origin (scheme and host, optionally a port) and
// uses its hostname as the RP ID. Supply trusted configuration at startup.
// Verifiers for the same origin may share both stores across processes.
func New(origin, displayName string, credentials Store, ceremonies CeremonyStore) (*Verifier, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || origin != "https://"+u.Host || displayName == "" ||
		credentials == nil || ceremonies == nil {
		return nil, errors.New("webauthn: expected an HTTPS origin, display name and stores")
	}
	// Match the browser's serialized origin, including any nondefault port.
	origin = "https://" + strings.TrimSuffix(strings.ToLower(u.Host), ":443")
	rpID := strings.ToLower(u.Hostname())
	timeout := wa.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute}
	rp, err := wa.New(&wa.Config{
		RPID: rpID, RPDisplayName: displayName, RPOrigins: []string{origin},
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
	return &Verifier{origin: origin, rpID: rpID, rp: rp, credentials: credentials, ceremonies: ceremonies}, nil
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

func validSubject(subject string) bool { return len(subject) > 0 && len(subject) <= 64 }

func (v *Verifier) load(ctx context.Context, subject, name string) (account, error) {
	if !validSubject(subject) {
		return account{}, ErrInvalid
	}
	records, err := v.credentials.Load(ctx, subject)
	if err != nil {
		return account{}, fmt.Errorf("webauthn: load credentials: %w", err)
	}
	a := account{subject: subject, name: name, versions: make(map[string]string, len(records))}
	for _, r := range records {
		id := string(r.Credential.ID)
		if id == "" || r.Version == "" || a.versions[id] != "" || len(r.Credential.PublicKey) == 0 {
			return account{}, ErrRecord
		}
		a.keys = append(a.keys, r.Credential)
		a.versions[id] = r.Version
	}
	return a, nil
}

const (
	registration = "registration"
	verification = "verification"
)

// ceremonyRecord is the opaque value kept in the CeremonyStore. Keep it
// confidential, out of logs and inaccessible to the browser.
type ceremonyRecord struct {
	Format  int            `json:"v"`
	Purpose string         `json:"purpose"`
	Subject string         `json:"subject"`
	Session wa.SessionData `json:"session"`
}

func randomHandle() string {
	var raw [32]byte
	rand.Read(raw[:])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func validHandle(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32
}

// The origin namespace isolates verifiers sharing a ceremony store.
func (v *Verifier) key(handle string) Key {
	return sha256.Sum256([]byte("authlume-webauthn\x00" + v.origin + "\x00" + handle))
}

func (v *Verifier) start(ctx context.Context, purpose, subject string, options any, session *wa.SessionData) (json.RawMessage, string, error) {
	if session == nil || session.Expires.IsZero() {
		return nil, "", errors.New("webauthn: begin: session without expiry")
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin: %w", err)
	}
	record, err := json.Marshal(ceremonyRecord{Format: 1, Purpose: purpose, Subject: subject, Session: *session})
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin: %w", err)
	}
	handle := randomHandle()
	if err := v.ceremonies.Create(ctx, v.key(handle), subject, record, session.Expires); err != nil {
		return nil, "", fmt.Errorf("webauthn: store ceremony: %w", err)
	}
	return encoded, handle, nil
}

// take consumes the ceremony for handle and checks that it is intact and
// matches purpose. The checks guard against corruption and mix-ups. The
// record's authenticity relies on the integrity of the CeremonyStore.
func (v *Verifier) take(ctx context.Context, handle, purpose string) (ceremonyRecord, error) {
	if !validHandle(handle) {
		return ceremonyRecord{}, ErrInvalid
	}
	data, err := v.ceremonies.Take(ctx, v.key(handle), time.Now())
	if errors.Is(err, ErrInvalid) {
		return ceremonyRecord{}, err
	}
	if err != nil {
		return ceremonyRecord{}, fmt.Errorf("webauthn: take ceremony: %w", err)
	}
	var rec ceremonyRecord
	if err := json.Unmarshal(data, &rec); err != nil || rec.Format != 1 {
		return ceremonyRecord{}, ErrRecord
	}
	s := rec.Session
	if rec.Purpose != purpose || !validSubject(rec.Subject) || rec.Subject != string(s.UserID) ||
		s.RelyingPartyID != v.rpID || s.Challenge == "" || s.Expires.IsZero() || !time.Now().Before(s.Expires) ||
		(purpose == verification && len(s.AllowedCredentialIDs) == 0) ||
		s.Mediation != "" || s.UserVerification != protocol.VerificationPreferred || len(s.Extensions) != 0 {
		return ceremonyRecord{}, ErrInvalid
	}
	return rec, nil
}

// BeginRegistration requires a freshly authorized enrollment for subject, a
// stable opaque handle of 1–64 bytes. name is a human-readable account label.
// It returns the browser options as JSON and a secret handle for the pending
// ceremony. Keep the handle in a Secure, HttpOnly, SameSite and host-only cookie.
func (v *Verifier) BeginRegistration(ctx context.Context, subject, name string) (options json.RawMessage, handle string, err error) {
	if name == "" {
		return nil, "", ErrInvalid
	}
	a, err := v.load(ctx, subject, name)
	if err != nil {
		return nil, "", err
	}
	creation, session, err := v.rp.BeginRegistration(a, wa.WithExclusions(a.keys.CredentialDescriptors()))
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin: %w", err)
	}
	return v.start(ctx, registration, subject, creation, session)
}

// FinishRegistration consumes the ceremony for handle and inserts the verified
// key. response is the browser credential JSON. Limit its size before reading
// it. Only a nil error authorizes the caller to count the factor for the
// returned subject.
func (v *Verifier) FinishRegistration(ctx context.Context, handle string, response []byte) (subject string, err error) {
	rec, err := v.take(ctx, handle, registration)
	if err != nil {
		return "", err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if parsed.Response.CollectedClientData.Origin != v.origin {
		return "", ErrInvalid
	}
	flags := parsed.Response.AttestationObject.AuthData.Flags
	if !flags.HasBackupEligible() && flags.HasBackupState() {
		return "", ErrInvalid
	}
	key, err := v.rp.CreateCredential(account{subject: rec.Subject}, rec.Session, parsed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(key.ID) == 0 || parsed.ID != base64.RawURLEncoding.EncodeToString(key.ID) || !bytes.Equal(parsed.RawID, key.ID) {
		return "", ErrInvalid
	}
	if err := v.credentials.Insert(ctx, rec.Subject, *key); err != nil {
		return "", fmt.Errorf("webauthn: insert credential: %w", err)
	}
	return rec.Subject, nil
}

// BeginVerification starts an assertion restricted to the verified first-factor
// subject's active credentials. An account with no credentials cannot proceed.
// It returns the browser options as JSON and a secret handle for the pending
// ceremony. Keep the handle in a Secure, HttpOnly, SameSite and host-only cookie.
func (v *Verifier) BeginVerification(ctx context.Context, subject string) (options json.RawMessage, handle string, err error) {
	a, err := v.load(ctx, subject, "")
	if err != nil {
		return nil, "", err
	}
	if len(a.keys) == 0 {
		return nil, "", ErrInvalid
	}
	assertion, session, err := v.rp.BeginLogin(a)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin: %w", err)
	}
	return v.start(ctx, verification, subject, assertion, session)
}

// FinishVerification consumes the ceremony for handle and records the new
// signature counter. It reloads the subject's active credentials. Only a nil
// error authorizes the caller to count the factor for the returned subject.
// ErrCloned reports a counter that did not increase.
func (v *Verifier) FinishVerification(ctx context.Context, handle string, response []byte) (subject string, err error) {
	rec, err := v.take(ctx, handle, verification)
	if err != nil {
		return "", err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if parsed.Response.CollectedClientData.Origin != v.origin || parsed.ID != base64.RawURLEncoding.EncodeToString(parsed.RawID) {
		return "", ErrInvalid
	}
	a, err := v.load(ctx, rec.Subject, "")
	if err != nil {
		return "", err
	}
	key, err := v.rp.ValidateLogin(a, rec.Session, parsed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if key.Authenticator.CloneWarning {
		return "", ErrCloned
	}
	if err := v.credentials.Update(ctx, rec.Subject, a.versions[string(key.ID)], *key); err != nil {
		return "", fmt.Errorf("webauthn: update credential: %w", err)
	}
	return rec.Subject, nil
}
