package mcpoauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Access is the content of a verified access token.
//
// Allow an operation only when both Scopes and the user's current permissions
// cover it. Reload the user's current state, such as suspension and roles,
// from Subject. Never widen the scope of an existing connection.
type Access struct {
	ConnectionID string
	Subject      string
	ClientID     string
	// Scopes is the connection's scopes that the configuration still defines.
	Scopes []string
	// ExpiresAt is the earlier of the access token's and the connection's
	// absolute deadline.
	ExpiresAt time.Time
}

// Has reports whether the access covers every one of scopes.
func (a Access) Has(scopes ...string) bool {
	for _, scope := range scopes {
		if !slices.Contains(a.Scopes, scope) {
			return false
		}
	}
	return true
}

// Verify validates the bearer token in the Authorization header. It reads no
// token from the URL or the body and never extends a deadline. ErrInvalid
// reports a missing, malformed, unknown, expired or revoked token; any other
// error is a backend failure. Pass the error to Challenge.
//
// Only tokens issued for this server's issuer and resource are accepted.
func (s *Server) Verify(r *http.Request) (Access, error) {
	if s.uninitialized() {
		return Access{}, errUninitialized
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return Access{}, ErrInvalid
	}
	scheme, token, _ := strings.Cut(headers[0], " ")
	if !strings.EqualFold(scheme, "Bearer") || !validValue(token) {
		return Access{}, ErrInvalid
	}
	now, key := s.now(), s.key("access", token)
	conn, err := s.store.Use(r.Context(), key, now)
	if errors.Is(err, ErrInvalid) {
		return Access{}, err
	}
	if err != nil {
		return Access{}, fmt.Errorf("mcpoauth: use access token: %w", err)
	}
	if conn.Access != key || conn.ID == "" || conn.Subject == "" {
		return Access{}, ErrRecord
	}
	scopes := s.granted(conn.Scopes)
	if conn.AccessExpired(now) || len(scopes) == 0 {
		return Access{}, ErrInvalid
	}
	expiry := conn.AccessExpiry
	if !conn.AbsoluteExpiry.IsZero() && conn.AbsoluteExpiry.Before(expiry) {
		expiry = conn.AbsoluteExpiry
	}
	return Access{ConnectionID: conn.ID, Subject: conn.Subject, ClientID: conn.ClientID, Scopes: scopes, ExpiresAt: expiry}, nil
}

// challenge formats a Bearer challenge. Values that are not scope tokens are
// dropped, so nothing needs quoting.
func (s *Server) challenge(code string, scopes []string) string {
	var params []string
	if code != "" {
		params = append(params, `error="`+code+`"`)
	}
	params = append(params, `resource_metadata="`+s.resourceMetadataURL+`"`)
	var valid []string
	for _, scope := range scopes {
		if scopeToken(scope) {
			valid = append(valid, scope)
		}
	}
	if len(valid) != 0 {
		params = append(params, `scope="`+strings.Join(valid, " ")+`"`)
	}
	return "Bearer " + strings.Join(params, ", ")
}

// Challenge turns an error from Verify into a response with an empty body.
// ErrInvalid becomes 401 with a Bearer challenge that names the protected
// resource metadata and, when given, the scopes the request needs. A request
// that carried an Authorization header also gets error="invalid_token", even
// when the header was malformed. Any other error, including nil, becomes 503.
func (s *Server) Challenge(w http.ResponseWriter, r *http.Request, err error, scopes ...string) {
	if s.uninitialized() {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !errors.Is(err, ErrInvalid) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var code string
	if r != nil && len(r.Header.Values("Authorization")) != 0 {
		code = "invalid_token"
	}
	w.Header().Set("WWW-Authenticate", s.challenge(code, scopes))
	w.WriteHeader(http.StatusUnauthorized)
}

// InsufficientScope writes a 403 whose Bearer challenge names the required
// scopes. The body is empty.
func (s *Server) InsufficientScope(w http.ResponseWriter, required ...string) {
	if s.uninitialized() {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("WWW-Authenticate", s.challenge("insufficient_scope", required))
	w.WriteHeader(http.StatusForbidden)
}

type accessKey struct{}

// Protect verifies the bearer token, requires every one of the required
// scopes and calls next with the Access in the request context. A scope the
// configuration does not define can never be satisfied and always yields 403.
//
// Calling Verify, Challenge and InsufficientScope directly is equivalent, for
// example where an endpoint also accepts another kind of credential.
func (s *Server) Protect(next http.Handler, required ...string) http.Handler {
	required = slices.Clone(required)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, err := s.Verify(r)
		if err != nil {
			s.Challenge(w, r, err, required...)
			return
		}
		if !access.Has(required...) {
			s.InsufficientScope(w, required...)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), accessKey{}, access)))
	})
}

// FromContext returns the Access that Protect stored in ctx.
func FromContext(ctx context.Context) (Access, bool) {
	access, ok := ctx.Value(accessKey{}).(Access)
	return access, ok
}
