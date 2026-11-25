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
	// Code is the digest of the authorization code that created the connection.
	// The zero Key means no code is linked. Rotate never changes it.
	Code Key
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
// across processes. A code and the connection created from it are operated on
// together: the code record check, the uniqueness check and the insertion in
// Create must be serialized with every TakeCode of the same conn.Code. Keep
// codes and connections in one backend that can change both atomically.
// Dedicate a store to one Server configuration (one issuer and resource
// pair): the key namespace is defense in depth, and Revoke and subject-wide
// operations are not separated by it. Arrange physical cleanup of expired
// records. Return backend failures as errors distinct from ErrInvalid. Treat
// records as secrets and keep them out of logs. Preserve the order of Scopes
// and at least whole seconds of every time; the location and monotonic
// reading may be dropped.
//
// Every method returns ctx.Err(), in a form errors.Is can identify, without
// changing state when ctx is already done. The uniqueness of ID, Selector,
// Access and a nonzero Code holds across the whole store. The snapshots that
// Rotate, Lookup and Use return keep Code.
//
// An operation that changes state while returning an error (the deletion in
// step 2 of TakeCode, the reuse mark and the deletion in its step 3, the
// deletions in steps 3 and 4 of Rotate) must commit the change before
// returning. Never roll a transaction back because of that error. If the
// change cannot be committed, return the backend's error instead of
// ErrInvalid or ErrReused.
//
// Listing and revoking by subject belong to the application's store:
//
//   - When revoking every connection of a subject, for account recovery or a
//     takeover response, delete every code record of that subject, consumed
//     ones included, in the same operation. Deleting a consumed record also
//     stops an exchange in progress: its Create finds no record and returns
//     ErrInvalid. Checking the subject's state as a precondition of Create
//     adds a second barrier.
//   - Revoke the connections of a client whose registration is withdrawn. Use
//     does not consult the client registration.
//   - A repeated consent by the same subject and client adds a connection. It
//     does not replace the earlier one.
type Store interface {
	// CreateCode inserts without overwriting. Return ErrCollision when a
	// record with the same key is stored. Expired records may be swept first.
	CreateCode(ctx context.Context, key Key, code Code) error
	// TakeCode evaluates the following in order as one atomic operation.
	//
	//  1. Without a record for key, return ErrInvalid.
	//  2. If now >= ExpiresAt, delete the record and return ErrInvalid,
	//     whether or not it was consumed or marked. Change no connection.
	//  3. If the record is consumed, mark it as reused, delete the connection
	//     whose Code equals key, if any, and return ErrReused together with
	//     the snapshot before deletion, or with the zero Connection when
	//     there was none. The mark stays until the record is deleted. A
	//     connection with the zero Code never matches.
	//  4. Mark the record as consumed and return its Code. Keep the record:
	//     it stays until its deadline so that a replay is detected.
	//
	// Of concurrent calls with the same key, exactly one reaches step 4. The
	// Code is nonzero only from step 4 and the Connection only when step 3
	// deleted one.
	TakeCode(ctx context.Context, key Key, now time.Time) (Code, Connection, error)
	// Create inserts a new connection. It takes no time and evaluates no
	// deadline. It checks the following in order.
	//
	//  1. With a nonzero conn.Code: without a record for that key, or with
	//     an unconsumed one, change nothing and return ErrInvalid. With a
	//     record marked as reused, change nothing and return ErrReused. A
	//     zero conn.Code skips this step.
	//  2. If its ID, Selector or Access, or its nonzero Code, equals that of
	//     a stored connection, change nothing and return ErrCollision.
	//  3. Insert the connection.
	//
	// Only the presence and state of the record decide step 1, so a record
	// removed by expiry cleanup or by a subject-wide revocation refuses the
	// connection.
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
	//     Every other member, Code included, is kept.
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
// fails with ErrCapacity if none can be reclaimed. A code record occupies its
// slot until its deadline, exchanged or not. Codes live for 60 seconds, so
// about 68 approvals per second fill the code limit. A connection occupies
// its slot until it is revoked or its refresh deadline passes, which can take
// the whole refresh idle lifetime, and every repeated consent adds one more.
// All records are lost on restart.
type MemoryStore struct {
	mu        sync.Mutex
	codes     map[Key]codeRecord
	conns     map[string]Connection
	selectors map[Key]string
	accesses  map[Key]string
	linked    map[Key]string // nonzero Connection.Code to connection ID
}

// codeRecord is a stored code. A consumed record stays until its deadline.
type codeRecord struct {
	Code
	consumed bool
	reused   bool
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
	if conn.Code != (Key{}) {
		delete(s.linked, conn.Code)
	}
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
		s.codes = make(map[Key]codeRecord)
	}
	code.Scopes = slices.Clone(code.Scopes)
	s.codes[key] = codeRecord{Code: code}
	return nil
}

func (s *MemoryStore) TakeCode(ctx context.Context, key Key, now time.Time) (Code, Connection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Code{}, Connection{}, err
	}
	record, ok := s.codes[key]
	if !ok {
		return Code{}, Connection{}, ErrInvalid
	}
	if !now.Before(record.ExpiresAt) {
		delete(s.codes, key)
		return Code{}, Connection{}, ErrInvalid
	}
	if record.consumed {
		record.reused = true
		s.codes[key] = record
		id, ok := s.linked[key]
		if !ok {
			return Code{}, Connection{}, ErrReused
		}
		conn := s.conns[id]
		s.remove(conn)
		return Code{}, snapshot(conn), ErrReused
	}
	record.consumed = true
	s.codes[key] = record
	code := record.Code
	code.Scopes = slices.Clone(code.Scopes)
	return code, Connection{}, nil
}

func (s *MemoryStore) Create(ctx context.Context, conn Connection) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	coded := conn.Code != (Key{})
	if coded {
		record, ok := s.codes[conn.Code]
		if !ok || !record.consumed {
			return ErrInvalid
		}
		if record.reused {
			return ErrReused
		}
	}
	_, id := s.conns[conn.ID]
	_, selector := s.selectors[conn.Selector]
	_, access := s.accesses[conn.Access]
	_, code := s.linked[conn.Code]
	if id || selector || access || (coded && code) {
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
		s.linked = make(map[Key]string)
	}
	s.conns[conn.ID] = snapshot(conn)
	s.selectors[conn.Selector] = conn.ID
	s.accesses[conn.Access] = conn.ID
	if coded {
		s.linked[conn.Code] = conn.ID
	}
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

// RevokeSubject deletes every connection and every code record of subject,
// consumed ones included, in one operation.
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
