package mcpoauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Event describes a token or revocation request for the application's audit
// record. Only the members that became known are set. It never contains a
// code or token value.
type Event struct {
	// Grant is "authorization_code", "refresh_token" or empty.
	Grant string
	// ClientID is the authenticated client.
	ClientID string
	// ConnectionID is the connection that was issued, refreshed or revoked.
	ConnectionID string
	Subject      string
}

const maxBody = 16 << 10

// failure is an error response of the token or revocation endpoint.
type failure struct {
	status int
	code   string
	basic  bool // challenge with WWW-Authenticate: Basic
	err    error
}

func badRequest(code string) *failure {
	return &failure{status: http.StatusBadRequest, code: code, err: fmt.Errorf("%w: %s", ErrInvalid, code)}
}

func unauthorized(basic bool) *failure {
	return &failure{status: http.StatusUnauthorized, code: "invalid_client", basic: basic, err: ErrClient}
}

// unavailable reports a backend failure. RFC 6749 section 5.2 does not define
// temporarily_unavailable for this endpoint; it tells the client to retry.
func unavailable(err error) *failure {
	return &failure{status: http.StatusServiceUnavailable, code: "temporarily_unavailable", err: err}
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (f *failure) write(w http.ResponseWriter) {
	if f.status == http.StatusMethodNotAllowed {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(f.status)
		return
	}
	noStore(w)
	if f.basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="mcpoauth"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	io.WriteString(w, `{"error":"`+f.code+`"}`)
}

// form reads a bounded form body. It never reads the URL's query, and rejects
// a repeated occurrence of any of the named parameters.
func form(w http.ResponseWriter, r *http.Request, names ...string) (url.Values, *failure) {
	if r.Method != http.MethodPost {
		return nil, &failure{status: http.StatusMethodNotAllowed, err: fmt.Errorf("%w: method not allowed", ErrInvalid)}
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		return nil, badRequest("invalid_request")
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil || strings.Contains(string(raw), ";") {
		return nil, badRequest("invalid_request")
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil || !single(values, names...) {
		return nil, badRequest("invalid_request")
	}
	return values, nil
}

// authenticate identifies the client by HTTP Basic or by body parameters. A
// public client is identified only; a secret it presents is ignored.
func (s *Server) authenticate(r *http.Request, values url.Values) (Client, *failure) {
	headers := r.Header.Values("Authorization")
	if len(headers) > 1 {
		return Client{}, badRequest("invalid_request")
	}
	basic := len(headers) == 1
	var id, secret string
	if basic {
		scheme, _, _ := strings.Cut(headers[0], " ")
		user, pass, ok := r.BasicAuth()
		if !strings.EqualFold(scheme, "Basic") || !ok {
			return Client{}, unauthorized(true)
		}
		// RFC 6749 section 2.3.1 form-encodes both values before Basic encoding.
		var errID, errSecret error
		id, errID = url.QueryUnescape(user)
		secret, errSecret = url.QueryUnescape(pass)
		if errID != nil || errSecret != nil {
			return Client{}, unauthorized(true)
		}
		if values.Get("client_secret") != "" {
			return Client{}, badRequest("invalid_request")
		}
		if bodyID := values.Get("client_id"); bodyID != "" && bodyID != id {
			return Client{}, badRequest("invalid_request")
		}
	} else {
		id, secret = values.Get("client_id"), values.Get("client_secret")
	}
	if !validClientID(id) {
		return Client{}, unauthorized(basic)
	}
	client, err := s.client(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		return Client{}, unauthorized(basic)
	}
	if err != nil {
		return Client{}, unavailable(err)
	}
	if client.Secret != nil {
		digest := sha256.Sum256([]byte(secret))
		if secret == "" || subtle.ConstantTimeCompare(digest[:], client.Secret[:]) != 1 {
			return Client{}, unauthorized(basic)
		}
	}
	return client, nil
}

// Token serves the token endpoint for the authorization_code and
// refresh_token grants. It always writes the response. The returned values
// are for the application's records: err is nil on success, wraps ErrInvalid
// for a failure caused by the client (ErrClient for failed client
// authentication, ErrReused for a detected refresh token reuse) and is any
// other error for a backend failure, which is answered with 503.
//
// A refresh rotates the access and refresh tokens atomically. Presenting a
// rotated refresh token revokes that connection, so a client that retries a
// refresh whose response it lost must be authorized again.
func (s *Server) Token(w http.ResponseWriter, r *http.Request) (Event, error) {
	if s.uninitialized() {
		w.WriteHeader(http.StatusInternalServerError)
		return Event{}, errUninitialized
	}
	var event Event
	body, f := s.token(w, r, &event)
	if f != nil {
		f.write(w)
		return event, f.err
	}
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
	return event, nil
}

func (s *Server) token(w http.ResponseWriter, r *http.Request, event *Event) ([]byte, *failure) {
	values, f := form(w, r, "grant_type", "code", "redirect_uri", "code_verifier", "client_id",
		"client_secret", "refresh_token", "scope", "resource")
	if f != nil {
		return nil, f
	}
	client, f := s.authenticate(r, values)
	if f != nil {
		return nil, f
	}
	event.ClientID = client.ID
	switch grant := values.Get("grant_type"); grant {
	case "":
		return nil, badRequest("invalid_request")
	case "authorization_code":
		event.Grant = grant
		return s.exchange(r.Context(), client, values, event)
	case "refresh_token":
		event.Grant = grant
		return s.refresh(r.Context(), client, values, event)
	default:
		return nil, badRequest("unsupported_grant_type")
	}
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := range len(v) {
		c := v[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') &&
			c != '.' && c != '_' && c != '~' && c != '-' {
			return false
		}
	}
	return true
}

// exchange redeems an authorization code for a new connection.
func (s *Server) exchange(ctx context.Context, client Client, values url.Values, event *Event) ([]byte, *failure) {
	code, verifier := values.Get("code"), values.Get("code_verifier")
	if code == "" || verifier == "" {
		return nil, badRequest("invalid_request")
	}
	if resource := values.Get("resource"); resource != "" && !s.matchResource(resource) {
		return nil, badRequest("invalid_target")
	}
	if !validValue(code) || !validVerifier(verifier) {
		return nil, badRequest("invalid_grant")
	}
	now := s.now()
	record, err := s.store.TakeCode(ctx, s.key("code", code), now)
	if errors.Is(err, ErrInvalid) {
		return nil, badRequest("invalid_grant")
	}
	if err != nil {
		return nil, unavailable(fmt.Errorf("mcpoauth: take code: %w", err))
	}
	// The code is consumed. No failure below restores it. The store's own
	// expiry check is repeated rather than trusted.
	if !now.Before(record.ExpiresAt) {
		return nil, badRequest("invalid_grant")
	}
	if record.Subject == "" || len(record.Scopes) == 0 {
		return nil, unavailable(ErrRecord)
	}
	scopes := s.granted(record.Scopes)
	if len(scopes) == 0 || record.ClientID != client.ID {
		return nil, badRequest("invalid_grant")
	}
	if redirectURI := values.Get("redirect_uri"); redirectURI != "" && redirectURI != record.RedirectURI {
		return nil, badRequest("invalid_grant")
	}
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(challenge), []byte(record.Challenge)) != 1 {
		return nil, badRequest("invalid_grant")
	}

	var selector [selectorSize]byte
	rand.Read(selector[:])
	access, refresh := randomValue(), refreshToken(selector[:])
	conn := Connection{
		ID:       randomValue(),
		Selector: s.key("selector", base64.RawURLEncoding.EncodeToString(selector[:])),
		Subject:  record.Subject, ClientID: client.ID, Scopes: scopes,
		CreatedAt: now, RefreshedAt: now,
		Access: s.key("access", access), AccessExpiry: now.Add(s.accessTTL),
		Refresh: s.key("refresh", refresh), RefreshExpiry: now.Add(s.refreshIdle),
	}
	if s.absolute != 0 {
		conn.AbsoluteExpiry = now.Add(s.absolute)
	}
	if err := s.store.Create(ctx, conn); err != nil {
		return nil, unavailable(fmt.Errorf("mcpoauth: create connection: %w", err))
	}
	event.ConnectionID, event.Subject = conn.ID, conn.Subject
	return s.grant(access, refresh, now, conn.AbsoluteExpiry, scopes)
}

// refresh rotates a connection's tokens. The issued scope is always that of
// the connection; a requested scope is only checked for known values.
func (s *Server) refresh(ctx context.Context, client Client, values url.Values, event *Event) ([]byte, *failure) {
	token := values.Get("refresh_token")
	if token == "" {
		return nil, badRequest("invalid_request")
	}
	if resource := values.Get("resource"); resource != "" && !s.matchResource(resource) {
		return nil, badRequest("invalid_target")
	}
	for scope := range strings.SplitSeq(values.Get("scope"), " ") {
		if _, ok := s.known[scope]; scope != "" && !ok {
			return nil, badRequest("invalid_scope")
		}
	}
	encoded, ok := refreshSelector(token)
	if !ok {
		return nil, badRequest("invalid_grant")
	}
	selector, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, badRequest("invalid_grant")
	}
	now := s.now()
	access, next := randomValue(), refreshToken(selector)
	selectorKey := s.key("selector", encoded)
	rotation := Rotation{
		Access: s.key("access", access), AccessExpiry: now.Add(s.accessTTL),
		Refresh: s.key("refresh", next), RefreshExpiry: now.Add(s.refreshIdle),
	}
	conn, err := s.store.Rotate(ctx, selectorKey, s.key("refresh", token), client.ID, now, rotation)
	if errors.Is(err, ErrReused) {
		event.ConnectionID, event.Subject = conn.ID, conn.Subject
		return nil, &failure{status: http.StatusBadRequest, code: "invalid_grant", err: ErrReused}
	}
	if errors.Is(err, ErrInvalid) {
		return nil, badRequest("invalid_grant")
	}
	if err != nil {
		return nil, unavailable(fmt.Errorf("mcpoauth: rotate connection: %w", err))
	}
	if conn.ID == "" || conn.Subject == "" || len(conn.Scopes) == 0 || conn.ClientID != client.ID ||
		conn.Selector != selectorKey || conn.Access != rotation.Access || conn.Refresh != rotation.Refresh {
		return nil, unavailable(ErrRecord)
	}
	event.ConnectionID, event.Subject = conn.ID, conn.Subject
	scopes := s.granted(conn.Scopes)
	// A connection without a remaining scope, or one the store rotated past
	// its absolute deadline, must not keep working tokens.
	if len(scopes) == 0 || conn.absoluteExpired(now) {
		if err := s.store.Revoke(ctx, conn.ID); err != nil {
			return nil, unavailable(fmt.Errorf("mcpoauth: revoke connection: %w", err))
		}
		return nil, badRequest("invalid_grant")
	}
	return s.grant(access, next, now, conn.AbsoluteExpiry, scopes)
}

// grant encodes a successful token response. expires_in is computed from this
// server's clock and lifetime, not from the stored deadline, so a store that
// truncates times cannot skew it.
func (s *Server) grant(access, refresh string, now, absolute time.Time, scopes []string) ([]byte, *failure) {
	expiry := now.Add(s.accessTTL)
	if !absolute.IsZero() && absolute.Before(expiry) {
		expiry = absolute
	}
	body, err := json.Marshal(struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}{access, "Bearer", int64(expiry.Sub(now) / time.Second), refresh, strings.Join(scopes, " ")})
	if err != nil {
		return nil, unavailable(err)
	}
	return body, nil
}

// Revocation serves RFC 7009 token revocation. It always writes the response
// and returns values with the same meaning as Token. Revoking either token of
// a connection removes the connection, and so both tokens. An unknown token,
// another client's token or a rotated refresh token is answered with 200 and
// changes nothing. token_type_hint is ignored.
func (s *Server) Revocation(w http.ResponseWriter, r *http.Request) (Event, error) {
	if s.uninitialized() {
		w.WriteHeader(http.StatusInternalServerError)
		return Event{}, errUninitialized
	}
	var event Event
	if f := s.revocation(w, r, &event); f != nil {
		f.write(w)
		return event, f.err
	}
	noStore(w)
	w.WriteHeader(http.StatusOK)
	return event, nil
}

func (s *Server) revocation(w http.ResponseWriter, r *http.Request, event *Event) *failure {
	values, f := form(w, r, "token", "token_type_hint", "client_id", "client_secret")
	if f != nil {
		return f
	}
	client, f := s.authenticate(r, values)
	if f != nil {
		return f
	}
	event.ClientID = client.ID
	token := values.Get("token")
	if token == "" {
		return badRequest("invalid_request")
	}
	ctx, now := r.Context(), s.now()
	var conn Connection
	var err error
	if validValue(token) {
		access := s.key("access", token)
		conn, err = s.store.Use(ctx, access, now)
		if err == nil && (conn.ID == "" || conn.Access != access) {
			return unavailable(ErrRecord)
		}
		if err == nil && conn.AccessExpired(now) {
			return nil
		}
	} else if encoded, ok := refreshSelector(token); ok {
		selector, refresh := s.key("selector", encoded), s.key("refresh", token)
		conn, err = s.store.Lookup(ctx, selector, now)
		if err == nil && (conn.ID == "" || conn.Selector != selector) {
			return unavailable(ErrRecord)
		}
		if err == nil && (conn.RefreshExpired(now) || subtle.ConstantTimeCompare(conn.Refresh[:], refresh[:]) != 1) {
			return nil
		}
	} else {
		return nil
	}
	if errors.Is(err, ErrInvalid) {
		return nil
	}
	if err != nil {
		return unavailable(fmt.Errorf("mcpoauth: find connection: %w", err))
	}
	if conn.ClientID != client.ID {
		return nil
	}
	if err := s.store.Revoke(ctx, conn.ID); err != nil {
		return unavailable(fmt.Errorf("mcpoauth: revoke connection: %w", err))
	}
	event.ConnectionID, event.Subject = conn.ID, conn.Subject
	return nil
}

// Disconnect revokes a connection by its ID, which invalidates its access and
// refresh tokens together. It is idempotent. The caller must first confirm in
// its own store that the connection belongs to the acting user.
func (s *Server) Disconnect(ctx context.Context, connectionID string) error {
	if s.uninitialized() {
		return errUninitialized
	}
	if !validValue(connectionID) {
		return ErrInvalid
	}
	if err := s.store.Revoke(ctx, connectionID); err != nil {
		return fmt.Errorf("mcpoauth: revoke connection: %w", err)
	}
	return nil
}
