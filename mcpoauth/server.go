// Package mcpoauth provides an OAuth 2.1 authorization server and bearer token
// verification for one MCP server. It validates authorization requests, issues
// authorization codes bound to PKCE, exchanges and rotates tokens, revokes
// connections and verifies access tokens on the protected resource.
//
// The application owns user authentication, the consent screen, client
// registration, rate limits, CORS and audit storage. Clients are resolved
// through a ClientLookup, so an application keeps its own registration
// process. The package depends on the standard library only.
//
// Tokens are opaque random values. Access tokens live for one hour by default
// and are renewed with a rotating refresh token. A rotated refresh token that
// is presented again revokes that connection only, without a grace period.
//
// Deviations and extensions that an integrator should know:
//
//   - redirect_uri is always required in an authorization request, even when
//     the client registered a single URI. This is stricter than OAuth 2.1.
//   - The port of a loopback redirect URI is ignored for the IP literals of
//     RFC 8252 section 7.3 and also for localhost, which matches deployed
//     clients although RFC 8252 section 8.3 discourages localhost.
//   - A refresh request's scope is checked for syntax only. A request beyond
//     the connection's scope is not an error: the issued scope always stays
//     that of the connection and the response's scope member reports it. This
//     differs from RFC 6749 section 6 but never widens access.
//   - A client record that fails Client.Validate, such as a custom scheme
//     redirect URI or more than 16 URIs, yields ErrRecord and a 503 from the
//     token endpoint. Reject such clients with Validate at registration.
package mcpoauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"
)

const (
	DefaultAccessTTL   = time.Hour
	DefaultRefreshIdle = 90 * 24 * time.Hour

	// codeTTL is fixed: an authorization code is short-lived by design.
	codeTTL = 60 * time.Second
)

var (
	// ErrInvalid indicates an invalid, expired, consumed or revoked request,
	// code or token.
	ErrInvalid = errors.New("mcpoauth: invalid request, code or token")
	// ErrClient wraps ErrInvalid and reports failed client authentication.
	ErrClient = fmt.Errorf("%w: client authentication failed", ErrInvalid)
	// ErrReused wraps ErrInvalid. A rotated refresh token was presented and
	// its connection has been revoked.
	ErrReused = fmt.Errorf("%w: refresh token reuse", ErrInvalid)
	// ErrNotFound is returned by ClientLookup for an unregistered client.
	ErrNotFound = errors.New("mcpoauth: client not found")
	// ErrRecord reports an invalid record from the Store or ClientLookup.
	ErrRecord = errors.New("mcpoauth: invalid stored record")
	// ErrCollision indicates a new key was already in use.
	ErrCollision = errors.New("mcpoauth: key collision")
	// ErrCapacity indicates the in-memory store has reached its limit.
	ErrCapacity = errors.New("mcpoauth: memory store is full")

	errUninitialized = errors.New("mcpoauth: uninitialized server")
)

// Config is trusted application configuration for one authorization server
// and the single MCP server it protects.
//
// Issuer and Resource are HTTPS URLs with a lowercase host and no query,
// fragment, user information, trailing slash or percent-encoding. Both enter
// the key derivation of every code and token: changing either spelling
// invalidates all outstanding codes and tokens. The three endpoints are
// required HTTPS URLs without a query or fragment.
//
// A zero AccessTTL or RefreshIdle selects its default. RefreshIdle counts from
// the last refresh, or from issuance. A zero ConnectionAbsolute sets no
// absolute deadline for a connection. Now defaults to time.Now and must be
// concurrency-safe.
type Config struct {
	Issuer   string
	Resource string

	AuthorizationEndpoint string
	TokenEndpoint         string
	RevocationEndpoint    string

	// Scopes is every scope the application defines. DefaultScopes is the
	// nonempty subset granted when an authorization request omits scope.
	Scopes        []string
	DefaultScopes []string

	AccessTTL          time.Duration
	RefreshIdle        time.Duration
	ConnectionAbsolute time.Duration

	// Metadata adds members to the authorization server metadata, such as
	// registration_endpoint for an application with its own registration. It
	// cannot replace a member this package emits and must encode as JSON.
	Metadata map[string]any

	Now func() time.Time
}

// Server is safe for concurrent use. Construct it with New.
type Server struct {
	clients ClientLookup
	store   Store

	issuer, resource           string
	resourceHost, resourcePath string

	scopes   []string
	defaults []string
	known    map[string]struct{}

	accessTTL, refreshIdle, absolute time.Duration
	now                              func() time.Time

	metadata, resourceMetadata         []byte
	metadataPath, resourceMetadataPath string
	resourceMetadataURL                string
}

// identifier parses an issuer or resource identifier in its canonical form.
func identifier(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Host != strings.ToLower(u.Host) ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.ContainsAny(raw, "#\"\\") {
		return nil, false
	}
	if p := u.Path; p != "" && (p[0] != '/' || p == "/" || path.Clean(p) != p || u.EscapedPath() != p) {
		return nil, false
	}
	return u, true
}

func endpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		u.RawQuery == "" && !u.ForceQuery && !strings.Contains(raw, "#")
}

// scopeToken reports whether s is an RFC 6749 scope-token of 1 to 255 bytes.
func scopeToken(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// New validates the configuration. Reuse the server across requests.
func New(cfg Config, clients ClientLookup, store Store) (*Server, error) {
	if clients == nil || store == nil {
		return nil, errors.New("mcpoauth: client lookup and store are required")
	}
	issuer, validIssuer := identifier(cfg.Issuer)
	resource, validResource := identifier(cfg.Resource)
	if !validIssuer || !validResource {
		return nil, errors.New("mcpoauth: invalid issuer or resource")
	}
	if !endpoint(cfg.AuthorizationEndpoint) || !endpoint(cfg.TokenEndpoint) || !endpoint(cfg.RevocationEndpoint) {
		return nil, errors.New("mcpoauth: invalid endpoint")
	}
	errScopes := errors.New("mcpoauth: invalid scopes")
	if len(cfg.Scopes) == 0 || len(cfg.Scopes) > 64 || len(cfg.DefaultScopes) == 0 {
		return nil, errScopes
	}
	known := make(map[string]struct{}, len(cfg.Scopes))
	for _, scope := range cfg.Scopes {
		if _, duplicate := known[scope]; duplicate || !scopeToken(scope) {
			return nil, errScopes
		}
		known[scope] = struct{}{}
	}
	defaults := make(map[string]struct{}, len(cfg.DefaultScopes))
	for _, scope := range cfg.DefaultScopes {
		_, defined := known[scope]
		if _, duplicate := defaults[scope]; duplicate || !defined {
			return nil, errScopes
		}
		defaults[scope] = struct{}{}
	}
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = DefaultAccessTTL
	}
	if cfg.RefreshIdle == 0 {
		cfg.RefreshIdle = DefaultRefreshIdle
	}
	if cfg.AccessTTL <= 0 || cfg.RefreshIdle <= 0 || cfg.AccessTTL > cfg.RefreshIdle ||
		cfg.ConnectionAbsolute < 0 || (cfg.ConnectionAbsolute != 0 && cfg.ConnectionAbsolute < cfg.AccessTTL) {
		return nil, errors.New("mcpoauth: invalid lifetimes")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{
		clients: clients, store: store,
		issuer: cfg.Issuer, resource: cfg.Resource,
		resourceHost: resource.Host, resourcePath: resource.Path,
		scopes: slices.Clone(cfg.Scopes), defaults: slices.Clone(cfg.DefaultScopes), known: known,
		accessTTL: cfg.AccessTTL, refreshIdle: cfg.RefreshIdle, absolute: cfg.ConnectionAbsolute,
		now:                  cfg.Now,
		metadataPath:         "/.well-known/oauth-authorization-server" + issuer.Path,
		resourceMetadataPath: "/.well-known/oauth-protected-resource" + resource.Path,
	}
	s.resourceMetadataURL = "https://" + resource.Host + s.resourceMetadataPath

	methods := []string{"none", "client_secret_basic", "client_secret_post"}
	metadata := map[string]any{
		"issuer":                                         cfg.Issuer,
		"authorization_endpoint":                         cfg.AuthorizationEndpoint,
		"token_endpoint":                                 cfg.TokenEndpoint,
		"revocation_endpoint":                            cfg.RevocationEndpoint,
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          methods,
		"revocation_endpoint_auth_methods_supported":     methods,
		"scopes_supported":                               s.scopes,
		"authorization_response_iss_parameter_supported": true,
	}
	errMetadata := errors.New("mcpoauth: invalid metadata")
	for name, value := range cfg.Metadata {
		if _, reserved := metadata[name]; reserved {
			return nil, errMetadata
		}
		metadata[name] = value
	}
	var err error
	if s.metadata, err = json.Marshal(metadata); err != nil {
		return nil, errMetadata
	}
	s.resourceMetadata, err = json.Marshal(map[string]any{
		"resource":                 cfg.Resource,
		"authorization_servers":    []string{cfg.Issuer},
		"scopes_supported":         s.scopes,
		"bearer_methods_supported": []string{"header"},
	})
	if err != nil {
		return nil, errMetadata
	}
	return s, nil
}

func (s *Server) uninitialized() bool { return s == nil || s.store == nil }

// Key is a domain-separated SHA-256 digest. It is safe to use as a storage
// key and cannot be presented as the code or token it was derived from.
type Key [sha256.Size]byte

// key separates the purposes "code", "access", "selector" and "refresh". The
// issuer and resource bind every code and token to this server's audience: a
// server configured with another issuer or resource cannot find them.
func (s *Server) key(purpose, value string) Key {
	return sha256.Sum256([]byte("authlume-mcpoauth\x00" + purpose + "\x00" + s.issuer + "\x00" + s.resource + "\x00" + value))
}

const (
	selectorSize = 16
	refreshSize  = selectorSize + 32
)

// randomValue returns 32 random bytes as 43 base64url characters. It is used
// for authorization codes, access tokens and connection IDs.
func randomValue() string {
	var raw [32]byte
	rand.Read(raw[:])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func validValue(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32
}

// refreshToken joins a connection's fixed selector with a fresh verifier.
func refreshToken(selector []byte) string {
	var raw [refreshSize]byte
	copy(raw[:], selector)
	rand.Read(raw[selectorSize:])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

// refreshSelector returns the encoded selector of a well-formed refresh token.
func refreshSelector(token string) (string, bool) {
	if len(token) != base64.RawURLEncoding.EncodedLen(refreshSize) {
		return "", false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != refreshSize {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(raw[:selectorSize]), true
}

// granted keeps the scopes that the current configuration still defines.
func (s *Server) granted(scopes []string) []string {
	kept := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if _, ok := s.known[scope]; ok {
			kept = append(kept, scope)
		}
	}
	return kept
}

// matchResource compares a presented resource indicator with the configured
// resource, ignoring the case of the scheme and host and one trailing slash.
func (s *Server) matchResource(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && strings.ToLower(u.Host) == s.resourceHost &&
		strings.TrimSuffix(u.EscapedPath(), "/") == s.resourcePath && u.User == nil &&
		u.RawQuery == "" && !u.ForceQuery && !strings.Contains(raw, "#")
}

// MetadataPath is where the application mounts Metadata: the RFC 8414
// well-known prefix followed by the issuer's path.
func (s *Server) MetadataPath() string {
	if s.uninitialized() {
		return ""
	}
	return s.metadataPath
}

// ResourceMetadataPath is where the application mounts ResourceMetadata: the
// RFC 9728 well-known prefix followed by the resource's path. Some clients
// fall back to the root /.well-known/oauth-protected-resource, so a resource
// with a path can mount the same handler at both.
func (s *Server) ResourceMetadataPath() string {
	if s.uninitialized() {
		return ""
	}
	return s.resourceMetadataPath
}

// Metadata serves the RFC 8414 authorization server metadata. It sets no CORS
// headers; a browser-based client needs them from the application.
func (s *Server) Metadata(w http.ResponseWriter, r *http.Request) {
	if s.uninitialized() {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	document(w, r, s.metadata)
}

// ResourceMetadata serves the RFC 9728 protected resource metadata. It sets
// no CORS headers.
func (s *Server) ResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if s.uninitialized() {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	document(w, r, s.resourceMetadata)
}

func document(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
