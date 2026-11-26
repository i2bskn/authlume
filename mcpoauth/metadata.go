package mcpoauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// MetadataDocumentConfig enables Client ID Metadata Documents
// (draft-ietf-oauth-client-id-metadata-document). A zero Timeout, MaxSize,
// MinCacheTTL or MaxCacheTTL selects its default before the ranges are
// checked.
type MetadataDocumentConfig struct {
	// AllowedHosts limits the hosts a client_id may name. Empty accepts
	// every host. An entry is a lowercase host name such as "claude.ai",
	// which matches that host only, or "*." and a host name, such as
	// "*.example.com", which matches every longer host ending in
	// ".example.com" but not example.com itself. Ports are not written and
	// not compared.
	AllowedHosts []string
	// Timeout bounds one fetch: name resolution, connection, TLS and the
	// body. It defaults to 5 seconds and is at most 30 seconds.
	Timeout time.Duration
	// MaxSize is the largest document in bytes. It defaults to 5120 and is
	// at most 65536.
	MaxSize int
	// MinCacheTTL and MaxCacheTTL bound how long a document stays fresh,
	// whatever its Cache-Control says. They default to 5 minutes and 24
	// hours, and 0 < MinCacheTTL <= MaxCacheTTL.
	MinCacheTTL, MaxCacheTTL time.Duration
}

const (
	defaultMetadataTimeout = 5 * time.Second
	maxMetadataTimeout     = 30 * time.Second
	defaultMetadataSize    = 5120
	maxMetadataSize        = 64 << 10
	defaultMinCacheTTL     = 5 * time.Minute
	defaultMaxCacheTTL     = 24 * time.Hour

	metadataCacheSize    = 1024
	maxFetches           = 16
	maxFetchesPerHost    = 4
	maxResponseHeader    = 64 << 10
	authorizationRecheck = 30 * time.Second
	metadataUserAgent    = "authlume-mcpoauth"
)

// ErrMetadata wraps ErrInvalid. A client_id URL or its metadata document
// cannot be used: the URL or document is invalid, its host is not allowed or
// the fetch failed in a way that retrying does not fix. The error is a
// *MetadataError.
var ErrMetadata = fmt.Errorf("%w: invalid client metadata document", ErrInvalid)

// MetadataError describes a client_id URL or metadata document that cannot be
// used. errors.Is reports it as ErrMetadata and ErrInvalid.
type MetadataError struct {
	// ClientID is the presented client_id. It is not authenticated. An
	// application can use it to revoke the connections of a client whose
	// document has become invalid.
	ClientID string
	// Reason is a human-readable explanation, such as "status 404".
	Reason string
	// Mismatch reports that the fetched document named another client_id.
	// The draft says the server should then revoke the client's refresh
	// tokens at once.
	Mismatch bool
}

func (e *MetadataError) Error() string { return ErrMetadata.Error() + ": " + e.Reason }

func (e *MetadataError) Unwrap() error { return ErrMetadata }

// errFetch wraps a temporary failure to fetch a metadata document. It does
// not wrap ErrInvalid.
var errFetch = errors.New("mcpoauth: client metadata document unavailable")

// errBlocked is returned by the dial control for an address that is not
// allowed.
var errBlocked = errors.New("mcpoauth: address not allowed")

// metadataDocs fetches, validates and caches metadata documents.
type metadataDocs struct {
	allowed        []string
	own            map[string]bool
	timeout        time.Duration
	maxSize        int
	minTTL, maxTTL time.Duration
	now            func() time.Time

	// test is set only by tests in this package. Production configuration
	// cannot reach it.
	test *metadataTestHooks

	mu      sync.Mutex
	cache   map[string]*metadataEntry
	flights map[string]*metadataFlight
	active  int
	perHost map[string]int
}

// metadataTestHooks let tests fetch from a local server. address rewrites the
// dialed host and port, permit replaces the address check and tls replaces
// the TLS configuration.
type metadataTestHooks struct {
	address func(string) string
	permit  func(netip.Addr) bool
	tls     *tls.Config
}

type metadataEntry struct {
	client     Client
	fetched    time.Time
	freshUntil time.Time
	keepUntil  time.Time
	used       time.Time
}

type metadataFlight struct {
	done    chan struct{}
	waiters int // callers that started or joined it, for tests
	entry   metadataEntry
	err     error
}

func newMetadataDocs(cfg MetadataDocumentConfig, own []string, now func() time.Time) (*metadataDocs, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultMetadataTimeout
	}
	if cfg.MaxSize == 0 {
		cfg.MaxSize = defaultMetadataSize
	}
	if cfg.MinCacheTTL == 0 {
		cfg.MinCacheTTL = defaultMinCacheTTL
	}
	if cfg.MaxCacheTTL == 0 {
		cfg.MaxCacheTTL = defaultMaxCacheTTL
	}
	if cfg.Timeout < 0 || cfg.Timeout > maxMetadataTimeout || cfg.MaxSize < 0 || cfg.MaxSize > maxMetadataSize ||
		cfg.MinCacheTTL < 0 || cfg.MinCacheTTL > cfg.MaxCacheTTL {
		return nil, errors.New("mcpoauth: invalid metadata document configuration")
	}
	for _, host := range cfg.AllowedHosts {
		if !hostName(strings.TrimPrefix(host, "*.")) {
			return nil, errors.New("mcpoauth: invalid allowed host")
		}
	}
	d := &metadataDocs{
		allowed: slices.Clone(cfg.AllowedHosts), own: make(map[string]bool),
		timeout: cfg.Timeout, maxSize: cfg.MaxSize, minTTL: cfg.MinCacheTTL, maxTTL: cfg.MaxCacheTTL, now: now,
		cache: make(map[string]*metadataEntry), flights: make(map[string]*metadataFlight), perHost: make(map[string]int),
	}
	for _, raw := range own {
		if u, err := url.Parse(raw); err == nil {
			d.own[strings.ToLower(u.Hostname())] = true
		}
	}
	return d, nil
}

// hostName reports whether host is a lowercase DNS name of two or more
// labels whose last label is not numeric.
func hostName(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			if c := label[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// checkID applies the rules for a client_id URL before any fetch and returns
// its authority and host name.
func (d *metadataDocs) checkID(id string) (authority, host string, err error) {
	invalid := func(reason string) (string, string, error) {
		return "", "", &MetadataError{ClientID: id, Reason: reason}
	}
	if !strings.HasPrefix(id, "https://") || strings.ContainsAny(id, "#?") {
		return invalid("invalid client_id URL")
	}
	authority, rest, found := strings.Cut(id[len("https://"):], "/")
	if !found || rest == "" {
		return invalid("client_id URL without a path")
	}
	host, port, hasPort := strings.Cut(authority, ":")
	if !hostName(host) {
		return invalid("invalid client_id host")
	}
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || len(port) > 5 || strings.Trim(port, "0123456789") != "" || n < 1 || n > 65535 {
			return invalid("invalid client_id port")
		}
	}
	for segment := range strings.SplitSeq(rest, "/") {
		decoded := strings.ReplaceAll(strings.ToLower(segment), "%2e", ".")
		if decoded == "." || decoded == ".." {
			return invalid("client_id URL with a dot segment")
		}
	}
	u, err := url.Parse(id)
	if err != nil || u.Host != authority {
		return invalid("invalid client_id URL")
	}
	if d.own[host] {
		return invalid("client_id on this server's host")
	}
	if len(d.allowed) > 0 && !slices.ContainsFunc(d.allowed, func(entry string) bool {
		if suffix, wildcard := strings.CutPrefix(entry, "*"); wildcard {
			return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
		}
		return host == entry
	}) {
		return invalid("client_id host not allowed")
	}
	return authority, host, nil
}

var (
	blockedIPv4 = prefixes("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")
	blockedIPv6 = prefixes("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20")
	globalIPv6  = netip.MustParsePrefix("2000::/3")
	nat64       = netip.MustParsePrefix("64:ff9b::/96")
)

func prefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, p := range list {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// publicAddr reports whether a metadata document may be fetched from addr.
// It allows global unicast addresses only. An address in the well-known
// NAT64 prefix is judged by the IPv4 address it embeds.
func publicAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return !slices.ContainsFunc(blockedIPv4, func(p netip.Prefix) bool { return p.Contains(addr) })
	}
	if nat64.Contains(addr) {
		b := addr.As16()
		return publicAddr(netip.AddrFrom4([4]byte(b[12:])))
	}
	return globalIPv6.Contains(addr) &&
		!slices.ContainsFunc(blockedIPv6, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// cacheTTL reads the freshness lifetime from Cache-Control's max-age less the
// Age header. no-store, no-cache, a missing max-age or an invalid value give
// 0. Expires is ignored.
func cacheTTL(h http.Header) time.Duration {
	maxAge := int64(-1)
	for _, line := range h.Values("Cache-Control") {
		for directive := range strings.SplitSeq(line, ",") {
			name, value, hasValue := strings.Cut(strings.TrimSpace(directive), "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "no-store", "no-cache":
				return 0
			case "max-age":
				value = strings.TrimSpace(value)
				if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
					value = value[1 : len(value)-1]
				}
				n, ok := deltaSeconds(value)
				if !hasValue || !ok || maxAge >= 0 {
					return 0
				}
				maxAge = n
			}
		}
	}
	if maxAge < 0 {
		return 0
	}
	if age, ok := deltaSeconds(strings.TrimSpace(h.Get("Age"))); ok {
		maxAge = max(maxAge-age, 0)
	}
	return time.Duration(maxAge) * time.Second
}

// deltaSeconds parses a non-negative decimal number of seconds, capping a
// value too large to represent at 2^31 as RFC 9111 section 1.2.2 allows.
func deltaSeconds(s string) (int64, bool) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > 1<<31 {
		n = 1 << 31
	}
	return n, true
}

// metadataClient resolves a client from its metadata document, from the
// cache or by fetching it.
func (s *Server) metadataClient(ctx context.Context, id string, use purpose) (resolved, error) {
	d := s.docs
	authority, host, err := d.checkID(id)
	if err != nil {
		return resolved{}, err
	}
	found := func(c Client) (resolved, error) {
		client := s.dynamicClient(c.ID, c.Name, c.RedirectURIs)
		if client.Validate() != nil {
			return resolved{}, ErrRecord
		}
		return resolved{Client: client, source: SourceMetadata, host: authority}, nil
	}
	if client, ok := d.cached(id, func(e *metadataEntry, now time.Time) bool {
		if use == forToken {
			return now.Before(e.freshUntil)
		}
		return now.Sub(e.fetched) < authorizationRecheck
	}); ok {
		return found(client)
	}
	entry, err := d.fetch(ctx, id, host)
	if err == nil {
		return found(entry.client)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return resolved{}, ctxErr
	}
	if errors.Is(err, ErrMetadata) {
		return resolved{}, err
	}
	// A temporary failure falls back to a fresh entry when authorizing and
	// to any entry still kept when serving a token request.
	if client, ok := d.cached(id, func(e *metadataEntry, now time.Time) bool {
		if use == forToken {
			return true
		}
		return now.Before(e.freshUntil)
	}); ok {
		return found(client)
	}
	return resolved{}, err
}

// cached returns the cached client for id when usable accepts its entry. An
// entry past its keep deadline is removed.
func (d *metadataDocs) cached(id string, usable func(*metadataEntry, time.Time) bool) (Client, bool) {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.cache[id]
	if !ok {
		return Client{}, false
	}
	if !now.Before(e.keepUntil) {
		delete(d.cache, id)
		return Client{}, false
	}
	if !usable(e, now) {
		return Client{}, false
	}
	e.used = now
	return e.client, true
}

// fetch fetches id, sharing a fetch already in progress for the same id. The
// fetch itself runs detached from ctx with its own timeout, so one caller
// leaving does not fail the others; each caller waits on its own ctx.
func (d *metadataDocs) fetch(ctx context.Context, id, host string) (metadataEntry, error) {
	d.mu.Lock()
	flight, joined := d.flights[id]
	if !joined {
		// A caller that has already left starts no fetch.
		if err := ctx.Err(); err != nil {
			d.mu.Unlock()
			return metadataEntry{}, err
		}
		if d.active >= maxFetches || d.perHost[host] >= maxFetchesPerHost {
			d.mu.Unlock()
			return metadataEntry{}, fmt.Errorf("%w: too many concurrent fetches", errFetch)
		}
		d.active++
		d.perHost[host]++
		flight = &metadataFlight{done: make(chan struct{})}
		d.flights[id] = flight
		go d.run(context.WithoutCancel(ctx), id, host, flight)
	}
	flight.waiters++
	d.mu.Unlock()
	select {
	case <-flight.done:
		return flight.entry, flight.err
	case <-ctx.Done():
		return metadataEntry{}, ctx.Err()
	}
}

func (d *metadataDocs) run(ctx context.Context, id, host string, flight *metadataFlight) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	client, ttl, err := d.get(ctx, id)
	now := d.now()
	d.mu.Lock()
	defer close(flight.done)
	defer d.mu.Unlock()
	d.active--
	if d.perHost[host]--; d.perHost[host] <= 0 {
		delete(d.perHost, host)
	}
	delete(d.flights, id)
	flight.err = err
	switch {
	case err == nil:
		fresh := now.Add(min(max(ttl, d.minTTL), d.maxTTL))
		entry := &metadataEntry{client: client, fetched: now, freshUntil: fresh, keepUntil: fresh.Add(d.maxTTL), used: now}
		d.insert(id, entry, now)
		flight.entry = *entry
	case errors.Is(err, ErrMetadata):
		delete(d.cache, id)
	}
}

// insert stores an entry, removing entries past their keep deadline and then
// the least recently used one when the cache is full. The caller holds the
// lock.
func (d *metadataDocs) insert(id string, entry *metadataEntry, now time.Time) {
	if _, ok := d.cache[id]; !ok && len(d.cache) >= metadataCacheSize {
		for k, e := range d.cache {
			if !now.Before(e.keepUntil) {
				delete(d.cache, k)
			}
		}
		if len(d.cache) >= metadataCacheSize {
			var oldest string
			for k, e := range d.cache {
				if oldest == "" || e.used.Before(d.cache[oldest].used) {
					oldest = k
				}
			}
			delete(d.cache, oldest)
		}
	}
	d.cache[id] = entry
}

// dialCount counts the addresses one fetch dialed and how many of them the
// address check refused. It belongs to one fetch, so concurrent fetches never
// share it.
type dialCount struct{ attempts, refused atomic.Int64 }

// allRefused reports whether the fetch dialed at least one address and the
// check refused every one. Then the failure is permanent; a fetch where some
// address was allowed and then failed is temporary.
func (c *dialCount) allRefused() bool {
	n := c.attempts.Load()
	return n > 0 && c.refused.Load() == n
}

// control checks each address actually dialed, after name resolution, so
// DNS rebinding and multiple records are both covered.
func (d *metadataDocs) control(count *dialCount) func(string, string, syscall.RawConn) error {
	permit := publicAddr
	if d.test != nil && d.test.permit != nil {
		permit = d.test.permit
	}
	return func(_, address string, _ syscall.RawConn) error {
		count.attempts.Add(1)
		host, _, err := net.SplitHostPort(address)
		addr, parseErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil || !permit(addr) {
			count.refused.Add(1)
			return errBlocked
		}
		return nil
	}
}

// transport builds the dedicated transport of one fetch. It never uses a
// proxy, keeps no connection and does not decompress, so MaxSize counts the
// bytes transferred.
func (d *metadataDocs) transport(count *dialCount) *http.Transport {
	dialer := &net.Dialer{Timeout: d.timeout, Control: d.control(count)}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if d.test != nil && d.test.address != nil {
				address = d.test.address(address)
			}
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    d.timeout,
		ResponseHeaderTimeout:  d.timeout,
		MaxResponseHeaderBytes: maxResponseHeader,
	}
	if d.test != nil && d.test.tls != nil {
		transport.TLSClientConfig = d.test.tls.Clone()
	}
	return transport
}

// get performs one fetch and validates the document. It returns a
// *MetadataError for a failure that retrying does not fix and an error
// wrapping errFetch otherwise.
func (d *metadataDocs) get(ctx context.Context, id string) (Client, time.Duration, error) {
	permanent := func(reason string) (Client, time.Duration, error) {
		return Client{}, 0, &MetadataError{ClientID: id, Reason: reason}
	}
	temporary := func(reason string, err error) (Client, time.Duration, error) {
		if err != nil {
			return Client{}, 0, fmt.Errorf("%w: %s: %w", errFetch, reason, err)
		}
		return Client{}, 0, fmt.Errorf("%w: %s", errFetch, reason)
	}
	var count dialCount
	transport := d.transport(&count)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: d.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return permanent("invalid client_id URL")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", metadataUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		if count.allRefused() {
			return permanent("blocked address")
		}
		return temporary("request failed", err)
	}
	defer resp.Body.Close()
	switch status := resp.StatusCode; {
	case status == http.StatusOK:
	case status >= 300 && status < 400:
		return permanent("redirect status " + strconv.Itoa(status))
	case status == http.StatusNotFound || status == http.StatusGone:
		return permanent("status " + strconv.Itoa(status))
	case status >= 400:
		return temporary("status "+strconv.Itoa(status), nil)
	default:
		return permanent("status " + strconv.Itoa(status))
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (media != "application/json" &&
		!(strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json"))) {
		return permanent("content type " + strconv.Quote(resp.Header.Get("Content-Type")))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(d.maxSize)+1))
	if err != nil {
		return temporary("reading the body failed", err)
	}
	if len(body) > d.maxSize {
		return permanent("document larger than " + strconv.Itoa(d.maxSize) + " bytes")
	}
	doc, merr := parseMetadataDocument(id, body)
	if merr != nil {
		return Client{}, 0, merr
	}
	return doc, cacheTTL(resp.Header), nil
}

// members reads exactly one JSON object and returns its top-level members by
// exact name. A repeated top-level name, a byte order mark or trailing data
// is an error.
func members(body []byte) (map[string]json.RawMessage, error) {
	errObject := errors.New("not a single JSON object")
	if bytes.HasPrefix(body, []byte("\xef\xbb\xbf")) {
		return nil, errObject
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errObject
	}
	out := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		name, ok := tok.(string)
		if err != nil || !ok {
			return nil, errObject
		}
		if _, repeated := out[name]; repeated {
			return nil, errors.New("repeated member " + strconv.Quote(name))
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, errObject
		}
		out[name] = raw
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errObject
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errObject
	}
	return out, nil
}

// present returns a member's value unless it is absent or null.
func present(m map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	raw, ok := m[name]
	if !ok || string(raw) == "null" {
		return nil, false
	}
	return raw, true
}

func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func jsonStrings(raw json.RawMessage) ([]string, bool) {
	var items []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := jsonString(item)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// maxPresentedRedirectURIs bounds redirect_uris before unusable entries are
// removed.
const maxPresentedRedirectURIs = 32

// redirectURIs reads redirect_uris, drops entries that Client.Validate would
// refuse, such as custom schemes, and duplicates, and returns the rest. It
// returns a reason when the member is missing, malformed or leaves no usable
// or too many URIs.
func redirectURIs(m map[string]json.RawMessage) ([]string, string) {
	raw, ok := present(m, "redirect_uris")
	if !ok {
		return nil, "missing redirect_uris"
	}
	list, ok := jsonStrings(raw)
	if !ok || len(list) == 0 || len(list) > maxPresentedRedirectURIs {
		return nil, "invalid redirect_uris"
	}
	var kept []string
	for _, uri := range list {
		if validRedirectURI(uri) && !slices.Contains(kept, uri) {
			kept = append(kept, uri)
		}
	}
	if len(kept) == 0 || len(kept) > maxRedirectURIs {
		return nil, "no usable redirect_uris or too many"
	}
	return kept, ""
}

// clientName reads client_name, which must be printable UTF-8 of at most 255
// bytes without control or bidirectional formatting characters.
func clientName(m map[string]json.RawMessage) (string, string) {
	raw, ok := present(m, "client_name")
	if !ok {
		return "", ""
	}
	name, ok := jsonString(raw)
	if !ok || !utf8.Valid(raw) || len(name) > maxClientName || !utf8.ValidString(name) {
		return "", "invalid client_name"
	}
	for _, r := range name {
		if unicode.Is(unicode.Cc, r) || r == '\u200e' || r == '\u200f' ||
			(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') {
			return "", "invalid client_name"
		}
	}
	return name, ""
}

// grantAndResponseTypes checks that grant_types and response_types, when
// present, include the authorization code flow.
func grantAndResponseTypes(m map[string]json.RawMessage) string {
	if raw, ok := present(m, "grant_types"); ok {
		if list, ok := jsonStrings(raw); !ok || !slices.Contains(list, "authorization_code") {
			return "invalid grant_types"
		}
	}
	if raw, ok := present(m, "response_types"); ok {
		if list, ok := jsonStrings(raw); !ok || !slices.Contains(list, "code") {
			return "invalid response_types"
		}
	}
	return ""
}

var sharedSecretMethods = []string{"client_secret_basic", "client_secret_post", "client_secret_jwt"}

// authMethods checks that the document allows the none method and declares
// no shared secret method.
func authMethods(m map[string]json.RawMessage) string {
	const reason = "token endpoint authentication method other than none"
	var single string
	var plural []string
	rawSingle, hasSingle := present(m, "token_endpoint_auth_method")
	rawPlural, hasPlural := present(m, "token_endpoint_auth_methods_supported")
	var ok bool
	if hasSingle {
		if single, ok = jsonString(rawSingle); !ok {
			return "invalid token_endpoint_auth_method"
		}
	}
	if hasPlural {
		if plural, ok = jsonStrings(rawPlural); !ok {
			return "invalid token_endpoint_auth_methods_supported"
		}
	}
	if slices.Contains(sharedSecretMethods, single) ||
		slices.ContainsFunc(plural, func(method string) bool { return slices.Contains(sharedSecretMethods, method) }) {
		return "shared secret authentication method"
	}
	if hasSingle && hasPlural && !slices.Contains(plural, single) {
		return "inconsistent token endpoint authentication methods"
	}
	methods := []string{"none"}
	switch {
	case hasPlural:
		methods = plural
	case hasSingle:
		methods = []string{single}
	}
	if !slices.Contains(methods, "none") {
		return reason
	}
	return ""
}

// parseMetadataDocument validates a fetched document for client_id id.
func parseMetadataDocument(id string, body []byte) (Client, *MetadataError) {
	invalid := func(reason string) (Client, *MetadataError) {
		return Client{}, &MetadataError{ClientID: id, Reason: reason}
	}
	m, err := members(body)
	if err != nil {
		return invalid(err.Error())
	}
	raw, ok := present(m, "client_id")
	if !ok {
		return invalid("missing client_id")
	}
	documentID, ok := jsonString(raw)
	if !ok {
		return invalid("invalid client_id")
	}
	if documentID != id {
		return Client{}, &MetadataError{ClientID: id, Reason: "client_id does not match the URL", Mismatch: true}
	}
	if _, ok := m["client_secret"]; ok {
		return invalid("client_secret in the document")
	}
	if _, ok := m["client_secret_expires_at"]; ok {
		return invalid("client_secret_expires_at in the document")
	}
	_, jwks := present(m, "jwks")
	_, jwksURI := present(m, "jwks_uri")
	if jwks && jwksURI {
		return invalid("both jwks and jwks_uri")
	}
	if reason := authMethods(m); reason != "" {
		return invalid(reason)
	}
	uris, reason := redirectURIs(m)
	if reason != "" {
		return invalid(reason)
	}
	if reason := grantAndResponseTypes(m); reason != "" {
		return invalid(reason)
	}
	name, reason := clientName(m)
	if reason != "" {
		return invalid(reason)
	}
	return Client{ID: id, Name: name, RedirectURIs: uris}, nil
}
