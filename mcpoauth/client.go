package mcpoauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Client is a registered OAuth client as resolved by the application.
//
// A redirect URI is either an HTTPS URL, or an HTTP URL whose host is exactly
// 127.0.0.1, ::1 or localhost. A loopback URI matches a request on any port.
// Every other URI must match a request's redirect_uri exactly.
type Client struct {
	ID   string
	Name string
	// RedirectURIs holds 1 to 16 entries.
	RedirectURIs []string
	// Secret is nil for a public client. For a confidential client it is the
	// SHA-256 digest of a random secret with at least 256 bits of entropy.
	Secret *[sha256.Size]byte
	// RestrictScopes limits the scopes this client may be granted to Scopes.
	// When it is false the client may be granted every scope of Config.Scopes
	// and Scopes must be empty. Narrowing the list revokes each affected
	// connection at its next refresh.
	RestrictScopes bool
	// Scopes holds at most 64 distinct scope tokens and is used only with
	// RestrictScopes. An empty list grants nothing. An entry that
	// Config.Scopes does not define grants nothing.
	Scopes []string
}

// ClientLookup resolves a client by its exact identifier. Return ErrNotFound
// for an unregistered client and a distinct error for a backend failure. The
// result must satisfy Client.Validate and carry the requested ID.
type ClientLookup func(ctx context.Context, clientID string) (Client, error)

const (
	maxClientID     = 2048
	maxClientName   = 255
	maxRedirectURI  = 2048
	maxRedirectURIs = 16
	maxClientScopes = 64
)

// validClientID accepts 1 to 2048 bytes of printable ASCII without spaces.
func validClientID(id string) bool {
	if id == "" || len(id) > maxClientID {
		return false
	}
	for i := range len(id) {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return true
}

// allows reports whether the client may be granted scope. It does not check
// that the configuration defines the scope.
func (c Client) allows(scope string) bool {
	return !c.RestrictScopes || slices.Contains(c.Scopes, scope)
}

func loopback(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// Validate reports whether the record satisfies this package's constraints
// and returns ErrRecord otherwise. Applications can call it at registration.
// The server applies it to every ClientLookup result.
func (c Client) Validate() error {
	if !validClientID(c.ID) || len(c.Name) > maxClientName ||
		len(c.RedirectURIs) == 0 || len(c.RedirectURIs) > maxRedirectURIs {
		return ErrRecord
	}
	if len(c.Scopes) > maxClientScopes || (!c.RestrictScopes && len(c.Scopes) > 0) {
		return ErrRecord
	}
	for i, scope := range c.Scopes {
		if !scopeToken(scope) || slices.Contains(c.Scopes[:i], scope) {
			return ErrRecord
		}
	}
	for _, raw := range c.RedirectURIs {
		if !validRedirectURI(raw) {
			return ErrRecord
		}
	}
	return nil
}

// validRedirectURI applies the redirect URI rules of Client.Validate to one
// URI.
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > maxRedirectURI || u.User != nil || strings.Contains(raw, "#") {
		return false
	}
	switch u.Scheme {
	case "https":
		if u.Hostname() == "" {
			return false
		}
	case "http":
		if !loopback(u.Hostname()) {
			return false
		}
	default:
		return false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}
	for _, reserved := range []string{"code", "state", "iss", "error"} {
		if query.Has(reserved) {
			return false
		}
	}
	return true
}

// matchRedirect compares a presented redirect_uri with one registered URI.
// For a registered loopback URI the port is ignored (RFC 8252 section 7.3);
// localhost and 127.0.0.1 never match each other.
func matchRedirect(registered, presented string) bool {
	want, err := url.Parse(registered)
	if err != nil || want.Scheme != "http" {
		return registered == presented
	}
	if len(presented) > maxRedirectURI || strings.Contains(presented, "#") {
		return false
	}
	got, err := url.Parse(presented)
	return err == nil && got.Scheme == "http" && got.User == nil &&
		got.Hostname() == want.Hostname() && got.EscapedPath() == want.EscapedPath() &&
		got.RawQuery == want.RawQuery && got.ForceQuery == want.ForceQuery
}

// ClientSource tells where the server resolved a client from. The zero value
// is unknown and matches no constant.
type ClientSource int

const (
	// SourceLookup is a client that the ClientLookup returned.
	SourceLookup ClientSource = iota + 1
	// SourceMetadata is a client built from a Client ID Metadata Document.
	SourceMetadata
	// SourceRegistration is a client registered through Server.Register.
	SourceRegistration
)

// resolved is a client with where it came from. host is the authority of a
// metadata document's client_id and empty otherwise.
type resolved struct {
	Client
	source ClientSource
	host   string
}

// purpose selects how a metadata document may be served from the cache.
type purpose int

const (
	// forAuthorization uses an entry fetched within the last 30 seconds and,
	// when a fetch fails temporarily, a fresh one.
	forAuthorization purpose = iota
	// forToken uses a fresh entry and, when a fetch fails temporarily, a
	// stale one.
	forToken
)

// errCredentials is returned by a resolve guard that refuses a dynamic client
// before any fetch.
var errCredentials = errors.New("mcpoauth: credentials for a client without a secret")

// resolve finds a client in the order ClientLookup, metadata document, then
// registration. It returns ErrNotFound for an unknown client, a
// *MetadataError for a document that cannot be used and any other error for
// a backend or temporary failure. guard, when set, runs once a dynamic source
// is chosen and before it is consulted; its error is returned as is.
func (s *Server) resolve(ctx context.Context, id string, use purpose, guard func(ClientSource) error) (resolved, error) {
	client, err := s.clients(ctx, id)
	if err == nil {
		if client.Validate() != nil || client.ID != id {
			return resolved{}, ErrRecord
		}
		return resolved{Client: client, source: SourceLookup}, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return resolved{}, fmt.Errorf("mcpoauth: lookup client: %w", err)
	}
	var source ClientSource
	switch {
	case strings.HasPrefix(id, "https://"):
		if s.docs == nil {
			return resolved{}, ErrNotFound
		}
		source = SourceMetadata
	case s.registration != nil && validValue(id):
		source = SourceRegistration
	default:
		return resolved{}, ErrNotFound
	}
	if guard != nil {
		if err := guard(source); err != nil {
			return resolved{}, err
		}
	}
	if source == SourceMetadata {
		return s.metadataClient(ctx, id, use)
	}
	return s.registeredClient(ctx, id)
}

// dynamicClient builds the record of a client resolved from a metadata
// document or a registration.
func (s *Server) dynamicClient(id, name string, redirectURIs []string) Client {
	return Client{
		ID: id, Name: name, RedirectURIs: redirectURIs,
		RestrictScopes: s.restrictDynamic, Scopes: s.dynamicScopes,
	}
}
