// Package webauthntest provides a software authenticator for tests.
package webauthntest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// Key is an Ed25519 test authenticator with "none" attestation.
type Key struct {
	ID      []byte
	Private ed25519.PrivateKey
	// ResponseID and ResponseRawID replace the id and rawId members when set.
	ResponseID    string
	ResponseRawID []byte
}

// New returns a key with a random credential ID.
func New(t testing.TB) Key {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Key{ID: []byte(rand.Text()), Private: private}
}

// Assertion describes the signed content of an assertion response.
type Assertion struct {
	Client     protocol.CollectedClientData
	RPID       string
	UserHandle string
	Flags      byte
	Count      uint32
}

// Registration returns a credential creation response. The attested
// credential data flag is always added to flags.
func (k Key) Registration(t testing.TB, challenge, origin, rpID string, flags byte) []byte {
	t.Helper()
	key := asCBOR(t, map[int]any{1: 1, 3: -8, -1: 6, -2: []byte(k.Private.Public().(ed25519.PublicKey))})
	data := authData(rpID, flags|byte(protocol.FlagAttestedCredentialData), 0)
	data = append(data, make([]byte, 16)...) // AAGUID
	data = binary.BigEndian.AppendUint16(data, uint16(len(k.ID)))
	data = append(data, k.ID...)
	data = append(data, key...)
	attestation := asCBOR(t, map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
	client := asJSON(t, protocol.CollectedClientData{Type: protocol.CreateCeremony, Origin: origin, Challenge: challenge})
	return k.response(t, map[string][]byte{"clientDataJSON": client, "attestationObject": attestation})
}

// Sign returns an assertion response.
func (k Key) Sign(t testing.TB, a Assertion) []byte {
	t.Helper()
	client := asJSON(t, a.Client)
	hash := sha256.Sum256(client)
	data := authData(a.RPID, a.Flags, a.Count)
	sig := ed25519.Sign(k.Private, append(bytes.Clone(data), hash[:]...))
	return k.response(t, map[string][]byte{"clientDataJSON": client, "authenticatorData": data, "signature": sig, "userHandle": []byte(a.UserHandle)})
}

func (k Key) response(t testing.TB, fields map[string][]byte) []byte {
	id, raw := base64.RawURLEncoding.EncodeToString(k.ID), base64.RawURLEncoding.EncodeToString(k.ID)
	if k.ResponseID != "" {
		id = k.ResponseID
	}
	if k.ResponseRawID != nil {
		raw = base64.RawURLEncoding.EncodeToString(k.ResponseRawID)
	}
	encoded := map[string]string{}
	for name, value := range fields {
		encoded[name] = base64.RawURLEncoding.EncodeToString(value)
	}
	return asJSON(t, map[string]any{"id": id, "rawId": raw, "type": "public-key", "response": encoded})
}

func authData(rpID string, flags byte, count uint32) []byte {
	hash := sha256.Sum256([]byte(rpID))
	return binary.BigEndian.AppendUint32(append(hash[:], flags), count)
}

func asJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func asCBOR(t testing.TB, v any) []byte {
	t.Helper()
	b, err := webauthncbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
