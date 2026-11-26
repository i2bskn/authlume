package mcpoauth

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// RegistrationConfig enables RFC 7591 dynamic client registration. Every
// registered client is public: it authenticates with no secret.
type RegistrationConfig struct {
	// Endpoint is the HTTPS URL, without a query or fragment, where the
	// application mounts Server.Register. It is published as
	// registration_endpoint.
	Endpoint string
	// Store keeps the registrations.
	Store ClientStore
	// InitialAccessToken, when set, requires a registration request to carry
	// Authorization: Bearer with a token that this function accepts by
	// returning nil. An error wrapping ErrInvalid rejects the token and any
	// other error is answered with 503. When it is nil, an Authorization
	// header is ignored.
	InitialAccessToken func(ctx context.Context, token string) error
	// UnusedTTL is how long a registration that has never been used for a
	// connection stays valid, counted from its registration. Zero selects 7
	// days and a negative value keeps every registration. A positive value
	// must be at least 10 minutes. A client that keeps its client_id and is
	// not used within this time must register again, so keep it generous.
	UnusedTTL time.Duration
}

const (
	defaultUnusedTTL = 7 * 24 * time.Hour
	minUnusedTTL     = 10 * time.Minute
)

// ErrUnknownClient wraps ErrInvalid. No ClientLookup entry, metadata document
// or registration matched the client_id, or its registration has expired.
// Authorize, Approve and Deny return it; the user can be told to connect
// again from the client.
var ErrUnknownClient = fmt.Errorf("%w: unknown client", ErrInvalid)

var errRegistrationDisabled = errors.New("mcpoauth: dynamic client registration is disabled")

// Registration is a client registered through Server.Register.
type Registration struct {
	ID           string
	Name         string
	RedirectURIs []string
	CreatedAt    time.Time
	// ExpiresAt is the deadline of a registration that has never been used
	// for a connection. Zero means no deadline. The first code exchange
	// clears it through ClientStore.Activate.
	ExpiresAt time.Time
}

func (r Registration) expired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt)
}

// ClientStore keeps dynamically registered clients.
//
// Every method returns ctx.Err(), in a form errors.Is can identify, without
// changing state when ctx is already done. Return backend failures as errors
// distinct from ErrNotFound and ErrCollision. Preserve the order of
// RedirectURIs and at least whole seconds of every time; the location and
// monotonic reading may be dropped. Arrange physical cleanup of expired
// registrations, and remove activated registrations whose connections are
// all gone: a client may register again every time it connects.
type ClientStore interface {
	// CreateClient inserts without overwriting. Return ErrCollision when a
	// registration with the same ID is stored. Expired registrations may be
	// swept first.
	CreateClient(ctx context.Context, reg Registration) error
	// Client returns the registration with this ID. Return ErrNotFound when
	// there is none or when ExpiresAt is nonzero and now >= ExpiresAt. It
	// changes no registration, though it may remove an expired one.
	Client(ctx context.Context, id string, now time.Time) (Registration, error)
	// Activate clears ExpiresAt. Return ErrNotFound when there is no
	// registration with this ID or it has expired at now. The check and the
	// change are one atomic operation. It is idempotent.
	Activate(ctx context.Context, id string, now time.Time) error
}

type registration struct {
	store     ClientStore
	token     func(context.Context, string) error
	unusedTTL time.Duration // negative keeps registrations
}

func newRegistration(cfg RegistrationConfig) (*registration, error) {
	if !endpoint(cfg.Endpoint) {
		return nil, errors.New("mcpoauth: invalid endpoint")
	}
	if cfg.Store == nil {
		return nil, errors.New("mcpoauth: registration store is required")
	}
	if cfg.UnusedTTL == 0 {
		cfg.UnusedTTL = defaultUnusedTTL
	}
	if cfg.UnusedTTL > 0 && cfg.UnusedTTL < minUnusedTTL {
		return nil, errors.New("mcpoauth: invalid lifetimes")
	}
	return &registration{store: cfg.Store, token: cfg.InitialAccessToken, unusedTTL: cfg.UnusedTTL}, nil
}

// registeredClient resolves a client from its registration.
func (s *Server) registeredClient(ctx context.Context, id string) (resolved, error) {
	now := s.now()
	reg, err := s.registration.store.Client(ctx, id, now)
	if errors.Is(err, ErrNotFound) {
		return resolved{}, ErrNotFound
	}
	if err != nil {
		return resolved{}, fmt.Errorf("mcpoauth: lookup registration: %w", err)
	}
	if reg.ID != id {
		return resolved{}, ErrRecord
	}
	// The store's own expiry check is repeated rather than trusted.
	if reg.expired(now) {
		return resolved{}, ErrNotFound
	}
	client := s.dynamicClient(reg.ID, reg.Name, reg.RedirectURIs)
	if client.Validate() != nil {
		return resolved{}, ErrRecord
	}
	return resolved{Client: client, source: SourceRegistration}, nil
}

// Register serves the RFC 7591 registration endpoint. It always writes the
// response. When registration is disabled it answers 404 and returns an
// error. On success it returns the stored Registration for the
// application's records and a nil error; a failure caused by the client
// wraps ErrInvalid and any other error is a backend failure answered with
// 503.
//
// The registered client is public whatever authentication method it asks
// for. Redirect URIs that Client.Validate would refuse, such as custom
// schemes, are dropped. Only redirect_uris, client_name, grant_types,
// response_types and token_endpoint_auth_method are read; the other members
// are ignored. Rate limits, CORS and the OPTIONS preflight are the
// application's: anyone can register.
func (s *Server) Register(w http.ResponseWriter, r *http.Request) (Registration, error) {
	if s.uninitialized() {
		w.WriteHeader(http.StatusInternalServerError)
		return Registration{}, errUninitialized
	}
	if s.registration == nil {
		w.WriteHeader(http.StatusNotFound)
		return Registration{}, errRegistrationDisabled
	}
	reg, f := s.register(w, r)
	if f != nil {
		f.write(w)
		return Registration{}, f.err
	}
	body, err := json.Marshal(struct {
		ClientID                string   `json:"client_id"`
		ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
		ClientName              string   `json:"client_name,omitempty"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}{reg.ID, reg.CreatedAt.Unix(), reg.Name, reg.RedirectURIs,
		[]string{"authorization_code", "refresh_token"}, []string{"code"}, "none"})
	if err != nil {
		unavailable(err).write(w)
		return Registration{}, err
	}
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(body)
	return reg, nil
}

func metadataFailure(code, reason string) *failure {
	return &failure{status: http.StatusBadRequest, code: code, err: fmt.Errorf("%w: %s: %s", ErrInvalid, code, reason)}
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) (Registration, *failure) {
	if r.Method != http.MethodPost {
		return Registration{}, &failure{status: http.StatusMethodNotAllowed, err: fmt.Errorf("%w: method not allowed", ErrInvalid)}
	}
	if check := s.registration.token; check != nil {
		headers := r.Header.Values("Authorization")
		if len(headers) == 0 {
			return Registration{}, &failure{status: http.StatusUnauthorized, challenge: "Bearer",
				err: fmt.Errorf("%w: missing initial access token", ErrInvalid)}
		}
		scheme, token, _ := strings.Cut(headers[0], " ")
		if len(headers) > 1 || !strings.EqualFold(scheme, "Bearer") || token == "" {
			return Registration{}, &failure{status: http.StatusBadRequest, code: "invalid_request",
				challenge: `Bearer error="invalid_request"`, err: fmt.Errorf("%w: invalid_request", ErrInvalid)}
		}
		if err := check(r.Context(), token); errors.Is(err, ErrInvalid) {
			return Registration{}, &failure{status: http.StatusUnauthorized, code: "invalid_token",
				challenge: `Bearer error="invalid_token"`, err: fmt.Errorf("mcpoauth: initial access token: %w", err)}
		} else if err != nil {
			return Registration{}, unavailable(fmt.Errorf("mcpoauth: initial access token: %w", err))
		}
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return Registration{}, metadataFailure("invalid_client_metadata", "content type")
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		return Registration{}, metadataFailure("invalid_client_metadata", "body")
	}
	m, err := members(raw)
	if err != nil {
		return Registration{}, metadataFailure("invalid_client_metadata", err.Error())
	}
	uris, reason := redirectURIs(m)
	if reason != "" {
		return Registration{}, metadataFailure("invalid_redirect_uri", reason)
	}
	name, reason := clientName(m)
	if reason == "" {
		reason = grantAndResponseTypes(m)
	}
	if method, ok := present(m, "token_endpoint_auth_method"); ok && reason == "" {
		if _, ok := jsonString(method); !ok {
			reason = "invalid token_endpoint_auth_method"
		}
	}
	if reason != "" {
		return Registration{}, metadataFailure("invalid_client_metadata", reason)
	}
	now := s.now()
	reg := Registration{ID: randomValue(), Name: name, RedirectURIs: uris, CreatedAt: now}
	if s.registration.unusedTTL > 0 {
		reg.ExpiresAt = now.Add(s.registration.unusedTTL)
	}
	if err := s.registration.store.CreateClient(r.Context(), reg); err != nil {
		return Registration{}, unavailable(fmt.Errorf("mcpoauth: store registration: %w", err))
	}
	return reg, nil
}

const memoryClientCapacity = 4096

// MemoryClientStore is a process-local ClientStore for up to 4096
// registrations. Its zero value is ready to use. It suits development and a
// single process; registrations are lost on restart.
//
// When full, an insertion first removes expired registrations, then the
// oldest registration not yet activated, and fails with ErrCapacity when
// every registration has been activated. Remove registrations whose
// connections are gone with Clients and DeleteClient.
type MemoryClientStore struct {
	mu   sync.Mutex
	regs map[string]Registration
}

// NewMemoryClientStore returns an empty, bounded single-process store.
func NewMemoryClientStore() *MemoryClientStore { return &MemoryClientStore{} }

func cloneRegistration(reg Registration) Registration {
	reg.RedirectURIs = slices.Clone(reg.RedirectURIs)
	return reg
}

func (s *MemoryClientStore) CreateClient(ctx context.Context, reg Registration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := s.regs[reg.ID]; exists {
		return ErrCollision
	}
	if len(s.regs) >= memoryClientCapacity {
		now := time.Now()
		for id, r := range s.regs {
			if r.expired(now) {
				delete(s.regs, id)
			}
		}
	}
	if len(s.regs) >= memoryClientCapacity {
		var oldest *Registration
		for _, r := range s.regs {
			if r.ExpiresAt.IsZero() {
				continue
			}
			if oldest == nil || r.CreatedAt.Before(oldest.CreatedAt) ||
				(r.CreatedAt.Equal(oldest.CreatedAt) && r.ID < oldest.ID) {
				oldest = &r
			}
		}
		if oldest == nil {
			return ErrCapacity
		}
		delete(s.regs, oldest.ID)
	}
	if s.regs == nil {
		s.regs = make(map[string]Registration)
	}
	s.regs[reg.ID] = cloneRegistration(reg)
	return nil
}

func (s *MemoryClientStore) Client(ctx context.Context, id string, now time.Time) (Registration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Registration{}, err
	}
	reg, ok := s.regs[id]
	if !ok || reg.expired(now) {
		return Registration{}, ErrNotFound
	}
	return cloneRegistration(reg), nil
}

func (s *MemoryClientStore) Activate(ctx context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	reg, ok := s.regs[id]
	if !ok || reg.expired(now) {
		return ErrNotFound
	}
	reg.ExpiresAt = time.Time{}
	s.regs[id] = reg
	return nil
}

// Clients returns every stored registration, expired ones included, ordered
// by CreatedAt and then by ID.
func (s *MemoryClientStore) Clients(ctx context.Context) ([]Registration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	regs := make([]Registration, 0, len(s.regs))
	for _, reg := range s.regs {
		regs = append(regs, cloneRegistration(reg))
	}
	slices.SortFunc(regs, func(a, b Registration) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.ID, b.ID))
	})
	return regs, nil
}

// DeleteClient removes a registration. It is idempotent. Revoke the
// connections of the client separately.
func (s *MemoryClientStore) DeleteClient(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	delete(s.regs, id)
	return nil
}
