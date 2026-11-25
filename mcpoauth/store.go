package mcpoauth

import (
	"cmp"
	"context"
	"crypto/subtle"
	"slices"
	"sync"
	"time"
)

// Code is the server-side record of an authorization code. Keep it
// confidential and out of logs.
type Code struct {
	ClientID string
	// RedirectURI is the value presented in the authorization request.
	RedirectURI string
	Subject     string
	Scopes      []string
	// Challenge is the PKCE S256 code_challenge.
	Challenge string
	ExpiresAt time.Time
}

// Connection is a snapshot of one MCP connection, the result of one consent.
// ID is not a secret: it can be shown to the user and names the connection to
// disconnect. Selector, Access and Refresh are digests of the token values.
type Connection struct {
	ID        string
	Selector  Key
	Subject   string
	ClientID  string
	Scopes    []string
	CreatedAt time.Time
	// RefreshedAt equals CreatedAt until the first rotation.
	RefreshedAt time.Time
	// AbsoluteExpiry is zero when the connection has no absolute deadline.
	AbsoluteExpiry time.Time
	Access         Key
	AccessExpiry   time.Time
	Refresh        Key
	RefreshExpiry  time.Time
}

func (c Connection) absoluteExpired(now time.Time) bool {
	return !c.AbsoluteExpiry.IsZero() && !now.Before(c.AbsoluteExpiry)
}

// AccessExpired reports whether the access token or the connection has
// reached its deadline. A deadline equal to now has been reached.
func (c Connection) AccessExpired(now time.Time) bool {
	return !now.Before(c.AccessExpiry) || c.absoluteExpired(now)
}

// RefreshExpired reports whether the refresh token or the connection has
// reached its deadline. A deadline equal to now has been reached.
func (c Connection) RefreshExpired(now time.Time) bool {
	return !now.Before(c.RefreshExpiry) || c.absoluteExpired(now)
}

// Rotation holds the token digests and deadlines that replace a connection's
// current ones.
type Rotation struct {
	Access        Key
	AccessExpiry  time.Time
	Refresh       Key
	RefreshExpiry time.Time
}

// Store holds authorization codes and connections.
//
// Operations on the same code or connection must be linearizable, including
// across processes. Dedicate a store to one Server configuration (one issuer
// and resource pair): the key namespace is defense in depth, and Revoke and
// subject-wide operations are not separated by it. Arrange physical cleanup
// of expired records. Return backend failures as errors distinct from
// ErrInvalid. Treat records as secrets and keep them out of logs. Preserve the
// order of Scopes and at least whole seconds of every time; the location and
// monotonic reading may be dropped.
//
// Every method returns ctx.Err(), in a form errors.Is can identify, without
// changing state when ctx is already done. The uniqueness of ID, Selector and
// Access holds across the whole store.
//
// An operation that changes state while returning an error (the consumption
// in TakeCode, the deletions in steps 3 and 4 of Rotate) must commit the
// change before returning. Never roll a transaction back because of that
// error. If the deletion cannot be committed, return the backend's error
// instead of ErrInvalid or ErrReused.
//
// Listing and revoking by subject belong to the application's store:
//
//   - When revoking every connection of a subject, for account recovery or a
//     takeover response, delete that subject's unconsumed codes in the same
//     operation. A Create that follows a successful TakeCode cannot be
//     stopped, so also check the subject's state as a precondition of Create.
//   - Revoke the connections of a client whose registration is withdrawn. Use
//     does not consult the client registration.
//   - A repeated consent by the same subject and client adds a connection. It
//     does not replace the earlier one.
type Store interface {
	// CreateCode inserts without overwriting. Return ErrCollision when a
	// record with the same key is stored. Expired records may be swept first.
	CreateCode(ctx context.Context, key Key, code Code) error
	// TakeCode consumes a record exactly once. Return ErrInvalid for a
	// missing or expired record (now >= ExpiresAt). An expired record is
	// consumed too. A failed retry cannot restore a record.
	TakeCode(ctx context.Context, key Key, now time.Time) (Code, error)
	// Create inserts a new connection. If its ID, Selector or Access equals
	// that of a stored connection, change nothing and return ErrCollision.
	Create(ctx context.Context, conn Connection) error
	// Rotate evaluates the following in order as one atomic operation.
	//
	//  1. Without a connection for selector, return ErrInvalid.
	//  2. If its ClientID differs from clientID, change nothing and return
	//     ErrInvalid.
	//  3. If RefreshExpired(now), delete the connection and return ErrInvalid.
	//  4. If its Refresh differs from refresh, delete the connection and
	//     return ErrReused together with the snapshot before deletion.
	//  5. If next.Access equals the Access of another connection, change
	//     nothing and return ErrCollision.
	//  6. Replace Access, AccessExpiry, Refresh and RefreshExpiry with those
	//     of next, set RefreshedAt to now and return the updated connection.
	//
	// Of concurrent calls with the same refresh, exactly one reaches step 6.
	Rotate(ctx context.Context, selector, refresh Key, clientID string, now time.Time, next Rotation) (Connection, error)
	// Lookup returns the connection for selector. Return ErrInvalid when it
	// is missing or RefreshExpired(now). It changes no state.
	Lookup(ctx context.Context, selector Key, now time.Time) (Connection, error)
	// Use returns the connection whose current access token digest is
	// access. Return ErrInvalid when it is missing or AccessExpired(now). It
	// changes no state: an expired access token never deletes the
	// connection, whose refresh token may still be valid.
	Use(ctx context.Context, access Key, now time.Time) (Connection, error)
	// Revoke deletes the connection with this ID, which invalidates its
	// access and refresh tokens together. It is idempotent.
	Revoke(ctx context.Context, id string) error
}

const memoryCapacity = 4096

// MemoryStore is a process-local Store for up to 4096 authorization codes and
// 4096 connections. Its zero value is ready to use.
//
// When a limit is reached, an insertion first reclaims expired records and
// fails with ErrCapacity if none can be reclaimed. Codes live for 60 seconds,
// so about 68 approvals per second fill the code limit. A connection occupies
// its slot until it is revoked or its refresh deadline passes, which can take
// the whole refresh idle lifetime, and every repeated consent adds one more.
// All records are lost on restart.
type MemoryStore struct {
	mu        sync.Mutex
	codes     map[Key]Code
	conns     map[string]Connection
	selectors map[Key]string
	accesses  map[Key]string
}

// NewMemoryStore returns an empty, bounded single-process store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func snapshot(conn Connection) Connection {
	conn.Scopes = slices.Clone(conn.Scopes)
	return conn
}

// remove deletes a connection and its indexes. The caller holds the lock.
func (s *MemoryStore) remove(conn Connection) {
	delete(s.conns, conn.ID)
	delete(s.selectors, conn.Selector)
	delete(s.accesses, conn.Access)
}

func (s *MemoryStore) CreateCode(ctx context.Context, key Key, code Code) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := s.codes[key]; exists {
		return ErrCollision
	}
	if len(s.codes) >= memoryCapacity {
		now := time.Now()
		for k, c := range s.codes {
			if !now.Before(c.ExpiresAt) {
				delete(s.codes, k)
			}
		}
		if len(s.codes) >= memoryCapacity {
			return ErrCapacity
		}
	}
	if s.codes == nil {
		s.codes = make(map[Key]Code)
	}
	code.Scopes = slices.Clone(code.Scopes)
	s.codes[key] = code
	return nil
}

func (s *MemoryStore) TakeCode(ctx context.Context, key Key, now time.Time) (Code, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Code{}, err
	}
	code, ok := s.codes[key]
	delete(s.codes, key)
	if !ok || !now.Before(code.ExpiresAt) {
		return Code{}, ErrInvalid
	}
	return code, nil
}

func (s *MemoryStore) Create(ctx context.Context, conn Connection) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	_, id := s.conns[conn.ID]
	_, selector := s.selectors[conn.Selector]
	_, access := s.accesses[conn.Access]
	if id || selector || access {
		return ErrCollision
	}
	if len(s.conns) >= memoryCapacity {
		for _, c := range s.conns {
			if c.RefreshExpired(conn.CreatedAt) {
				s.remove(c)
			}
		}
		if len(s.conns) >= memoryCapacity {
			return ErrCapacity
		}
	}
	if s.conns == nil {
		s.conns = make(map[string]Connection)
		s.selectors = make(map[Key]string)
		s.accesses = make(map[Key]string)
	}
	s.conns[conn.ID] = snapshot(conn)
	s.selectors[conn.Selector] = conn.ID
	s.accesses[conn.Access] = conn.ID
	return nil
}

func (s *MemoryStore) Rotate(ctx context.Context, selector, refresh Key, clientID string, now time.Time, next Rotation) (Connection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Connection{}, err
	}
	id, ok := s.selectors[selector]
	if !ok {
		return Connection{}, ErrInvalid
	}
	conn := s.conns[id]
	if conn.ClientID != clientID {
		return Connection{}, ErrInvalid
	}
	if conn.RefreshExpired(now) {
		s.remove(conn)
		return Connection{}, ErrInvalid
	}
	if subtle.ConstantTimeCompare(conn.Refresh[:], refresh[:]) != 1 {
		s.remove(conn)
		return snapshot(conn), ErrReused
	}
	if other, taken := s.accesses[next.Access]; taken && other != id {
		return Connection{}, ErrCollision
	}
	delete(s.accesses, conn.Access)
	conn.Access, conn.AccessExpiry = next.Access, next.AccessExpiry
	conn.Refresh, conn.RefreshExpiry = next.Refresh, next.RefreshExpiry
	conn.RefreshedAt = now
	s.conns[id] = conn
	s.accesses[conn.Access] = id
	return snapshot(conn), nil
}

func (s *MemoryStore) Lookup(ctx context.Context, selector Key, now time.Time) (Connection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Connection{}, err
	}
	id, ok := s.selectors[selector]
	if !ok || s.conns[id].RefreshExpired(now) {
		return Connection{}, ErrInvalid
	}
	return snapshot(s.conns[id]), nil
}

func (s *MemoryStore) Use(ctx context.Context, access Key, now time.Time) (Connection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Connection{}, err
	}
	id, ok := s.accesses[access]
	if !ok || s.conns[id].AccessExpired(now) {
		return Connection{}, ErrInvalid
	}
	return snapshot(s.conns[id]), nil
}

func (s *MemoryStore) Revoke(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if conn, ok := s.conns[id]; ok {
		s.remove(conn)
	}
	return nil
}

// Connections returns subject's connections whose refresh deadline has not
// been reached at now, ordered by CreatedAt and then by ID.
func (s *MemoryStore) Connections(ctx context.Context, subject string, now time.Time) ([]Connection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var conns []Connection
	for _, conn := range s.conns {
		if conn.Subject == subject && !conn.RefreshExpired(now) {
			conns = append(conns, snapshot(conn))
		}
	}
	slices.SortFunc(conns, func(a, b Connection) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.ID, b.ID))
	})
	return conns, nil
}

// RevokeSubject deletes every connection and every unconsumed authorization
// code of subject in one operation.
func (s *MemoryStore) RevokeSubject(ctx context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, conn := range s.conns {
		if conn.Subject == subject {
			s.remove(conn)
		}
	}
	for key, code := range s.codes {
		if code.Subject == subject {
			delete(s.codes, key)
		}
	}
	return nil
}
