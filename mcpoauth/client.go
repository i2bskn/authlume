package mcpoauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
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
	for _, raw := range c.RedirectURIs {
		u, err := url.Parse(raw)
		if err != nil || len(raw) > maxRedirectURI || u.User != nil || strings.Contains(raw, "#") {
			return ErrRecord
		}
		switch u.Scheme {
		case "https":
			if u.Hostname() == "" {
				return ErrRecord
			}
		case "http":
			if !loopback(u.Hostname()) {
				return ErrRecord
			}
		default:
			return ErrRecord
		}
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return ErrRecord
		}
		for _, reserved := range []string{"code", "state", "iss", "error"} {
			if query.Has(reserved) {
				return ErrRecord
			}
		}
	}
	return nil
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

// client resolves and checks a client record. It returns ErrNotFound as is.
func (s *Server) client(ctx context.Context, id string) (Client, error) {
	client, err := s.clients(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, fmt.Errorf("mcpoauth: lookup client: %w", err)
	}
	if client.Validate() != nil || client.ID != id {
		return Client{}, ErrRecord
	}
	return client, nil
}
