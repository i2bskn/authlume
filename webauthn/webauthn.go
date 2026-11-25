// Package webauthn verifies WebAuthn as a second factor for an already identified
// application subject and, when the application opts in, as a standalone
// passkey sign-in without a username. The caller authorizes enrollment and owns
// MFA policy, account state, browser binding, recovery, rate limits and issuance
// of application sessions.
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
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

var (
	// ErrInvalid means the ceremony cannot complete. Start the sign-in or
	// enrollment again from its first step.
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
	// Passkey reports that the credential was enrolled for standalone sign-in
	// through FinishPasskeyRegistration. It is set at insert and never changes.
	Passkey bool
}

// Store is scoped to a relying party. Treat rows stored before Passkey existed
// as Passkey false.
type Store interface {
	// Load returns an isolated snapshot of the active credentials for subject,
	// including Passkey. Return an empty list for a subject without credentials.
	// Return backend failures as errors distinct from ErrInvalid.
	//
	// Match subject byte for byte. Passkey sign-in passes an unauthenticated
	// value, so return an empty list for an unknown one and never fold case or
	// whitespace when comparing.
	Load(ctx context.Context, subject string) ([]Record, error)
	// Insert atomically enforces credential ID uniqueness across subjects and any
	// application enrollment preconditions, persists passkey and assigns a fresh,
	// never-reused version. Return ErrInvalid when a uniqueness or precondition
	// check fails.
	Insert(ctx context.Context, subject string, credential Credential, passkey bool) error
	// Update atomically matches subject, credential ID and the expected active
	// version, replaces the record and assigns a fresh, never-reused version.
	// It keeps the stored Passkey value. Return ErrInvalid for a mismatch,
	// conflict or revocation, including for keys without a signature counter.
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

// load validates every record. With passkeysOnly it then keeps only the
// credentials enrolled for standalone sign-in.
func (v *Verifier) load(ctx context.Context, subject, name string, passkeysOnly bool) (account, error) {
	if !validSubject(subject) {
		return account{}, ErrInvalid
	}
	records, err := v.credentials.Load(ctx, subject)
	if err != nil {
		return account{}, fmt.Errorf("webauthn: load credentials: %w", err)
	}
	a := account{subject: subject, name: name, versions: make(map[string]string, len(records))}
	seen := make(map[string]bool, len(records))
	for _, r := range records {
		id := string(r.Credential.ID)
		if id == "" || r.Version == "" || seen[id] || len(r.Credential.PublicKey) == 0 {
			return account{}, ErrRecord
		}
		seen[id] = true
		if passkeysOnly && !r.Passkey {
			continue
		}
		a.keys = append(a.keys, r.Credential)
		a.versions[id] = r.Version
	}
	return a, nil
}

const (
	registration        = "registration"
	verification        = "verification"
	passkeyRegistration = "passkey-registration"
	passkeyLogin        = "passkey-login"
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
//
// A passkey ceremony requires user verification. A passkey login is anonymous:
// it has no subject, no user ID and no allowed credentials. Every other
// ceremony is bound to its subject.
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
	bound := validSubject(rec.Subject) && rec.Subject == string(s.UserID)
	uv := protocol.VerificationPreferred
	switch purpose {
	case verification:
		bound = bound && len(s.AllowedCredentialIDs) != 0
	case passkeyRegistration:
		uv = protocol.VerificationRequired
	case passkeyLogin:
		bound = rec.Subject == "" && len(s.UserID) == 0 && len(s.AllowedCredentialIDs) == 0
		uv = protocol.VerificationRequired
	}
	if rec.Purpose != purpose || !bound ||
		s.RelyingPartyID != v.rpID || s.Challenge == "" || s.Expires.IsZero() || !time.Now().Before(s.Expires) ||
		s.Mediation != "" || s.UserVerification != uv || len(s.Extensions) != 0 {
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
	a, err := v.load(ctx, subject, name, false)
	if err != nil {
		return nil, "", err
	}
	creation, session, err := v.rp.BeginRegistration(a, wa.WithExclusions(a.keys.CredentialDescriptors()))
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin: %w", err)
	}
	return v.start(ctx, registration, subject, creation, session)
}

// BeginPasskeyRegistration starts enrollment of a passkey for standalone
// sign-in. The caller must have reauthenticated subject recently and authorized
// adding a passkey. subject must also be valid UTF-8. The options require a
// discoverable credential and user verification, on a built-in or a roaming
// authenticator, and exclude the subject's existing credentials. Handle the
// result as for BeginRegistration.
func (v *Verifier) BeginPasskeyRegistration(ctx context.Context, subject, name string) (options json.RawMessage, handle string, err error) {
	if name == "" || !utf8.ValidString(subject) {
		return nil, "", ErrInvalid
	}
	a, err := v.load(ctx, subject, name, false)
	if err != nil {
		return nil, "", err
	}
	creation, session, err := v.rp.BeginRegistration(a, wa.WithExclusions(a.keys.CredentialDescriptors()),
		wa.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		}))
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin: %w", err)
	}
	return v.start(ctx, passkeyRegistration, subject, creation, session)
}

// FinishRegistration consumes the ceremony for handle and inserts the verified
// key. response is the browser credential JSON. Limit its size before reading
// it. Only a nil error authorizes the caller to count the factor for the
// returned subject.
func (v *Verifier) FinishRegistration(ctx context.Context, handle string, response []byte) (subject string, err error) {
	return v.finishRegistration(ctx, handle, response, registration, false)
}

// FinishPasskeyRegistration consumes the ceremony for handle and inserts the
// verified key as a passkey. It rejects a response without user verification.
// Only a nil error authorizes the caller to count the passkey for the returned
// subject. Check that subject against the session that authorized the enrollment.
//
// An authenticator may still create a non-discoverable key. Such a key cannot
// sign in on its own, so complete one passkey sign-in before counting it as a
// usable sign-in method.
func (v *Verifier) FinishPasskeyRegistration(ctx context.Context, handle string, response []byte) (subject string, err error) {
	return v.finishRegistration(ctx, handle, response, passkeyRegistration, true)
}

func (v *Verifier) finishRegistration(ctx context.Context, handle string, response []byte, purpose string, passkey bool) (string, error) {
	rec, err := v.take(ctx, handle, purpose)
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
	if err := v.credentials.Insert(ctx, rec.Subject, *key, passkey); err != nil {
		return "", fmt.Errorf("webauthn: insert credential: %w", err)
	}
	return rec.Subject, nil
}

// BeginVerification starts an assertion restricted to the verified first-factor
// subject's active credentials. An account with no credentials cannot proceed.
// It returns the browser options as JSON and a secret handle for the pending
// ceremony. Keep the handle in a Secure, HttpOnly, SameSite and host-only cookie.
func (v *Verifier) BeginVerification(ctx context.Context, subject string) (options json.RawMessage, handle string, err error) {
	a, err := v.load(ctx, subject, "", false)
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
	a, err := v.load(ctx, rec.Subject, "", false)
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

// BeginPasskeyLogin starts a sign-in that names no subject: the browser offers
// the user's discoverable credentials and the assertion must include user
// verification. It returns the browser options as JSON and a secret handle for
// the pending ceremony. Keep the handle in a Secure, HttpOnly, SameSite and
// host-only cookie.
//
// Anyone can reach this entry point before authenticating, so limit it per
// client and also cap unauthenticated begins overall. Ceremonies live for five
// minutes: about 14 begins per second fill the 4096 entries of a
// MemoryCeremonyStore, and second-factor begins sharing that store then fail too.
func (v *Verifier) BeginPasskeyLogin(ctx context.Context) (options json.RawMessage, handle string, err error) {
	assertion, session, err := v.rp.BeginDiscoverableLogin(wa.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin: %w", err)
	}
	return v.start(ctx, passkeyLogin, "", assertion, session)
}

// FinishPasskeyLogin consumes the ceremony for handle, takes the subject from
// the response's user handle and reloads that subject's active credentials. It
// accepts only a credential enrolled through FinishPasskeyRegistration, so a
// key registered as a second factor never signs in on its own, and it requires
// user verification. It records the new signature counter. Only a nil error
// means the returned subject proved both possession and user verification.
// ErrCloned reports a counter that did not increase.
//
// This sign-in has no first-factor step. Stopping a suspended or locked account
// is the caller's responsibility: check the returned subject's account state
// before issuing a session, or have Store.Load return an empty list for a
// subject that may not sign in. The caller decides whether to issue a session.
func (v *Verifier) FinishPasskeyLogin(ctx context.Context, handle string, response []byte) (subject string, err error) {
	rec, err := v.take(ctx, handle, passkeyLogin)
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
	// The user handle is unauthenticated until the signature verifies.
	subject = string(parsed.Response.UserHandle)
	if !validSubject(subject) || !utf8.ValidString(subject) {
		return "", ErrInvalid
	}
	a, err := v.load(ctx, subject, "", true)
	if err != nil {
		return "", err
	}
	if a.versions[string(parsed.RawID)] == "" {
		return "", ErrInvalid
	}
	_, key, err := v.rp.ValidatePasskeyLogin(func(_, _ []byte) (wa.User, error) { return a, nil }, rec.Session, parsed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if key.Authenticator.CloneWarning {
		return "", ErrCloned
	}
	if err := v.credentials.Update(ctx, subject, a.versions[string(key.ID)], *key); err != nil {
		return "", fmt.Errorf("webauthn: update credential: %w", err)
	}
	return subject, nil
}
