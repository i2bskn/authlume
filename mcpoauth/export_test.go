package mcpoauth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
)

// This file holds the only way to fetch metadata documents from a local
// server: tests set the unexported hooks of metadataDocs, which production
// configuration cannot reach.

// docResponse is what the document server answers for one URL.
type docResponse struct {
	status      int
	contentType string
	header      map[string]string
	body        string
	// wait, when set, delays the response until it is closed.
	wait chan struct{}
}

// docServer serves metadata documents by client_id URL, for any host name.
type docServer struct {
	*httptest.Server
	mu        sync.Mutex
	responses map[string]docResponse
	hits      map[string]int
	requests  []*http.Request
	arrived   chan string
}

func newDocServer(t *testing.T) *docServer {
	t.Helper()
	d := &docServer{responses: make(map[string]docResponse), hits: make(map[string]int), arrived: make(chan string, 1024)}
	d.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := "https://" + r.Host + r.URL.Path
		d.mu.Lock()
		d.hits[id]++
		d.requests = append(d.requests, r)
		resp, ok := d.responses[id]
		d.mu.Unlock()
		select {
		case d.arrived <- id:
		default:
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		if resp.wait != nil {
			select {
			case <-resp.wait:
			case <-r.Context().Done():
				return
			}
		}
		contentType := resp.contentType
		if contentType == "" {
			contentType = "application/json"
		}
		w.Header().Set("Content-Type", contentType)
		for k, v := range resp.header {
			w.Header().Set(k, v)
		}
		status := resp.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		w.Write([]byte(resp.body))
	}))
	t.Cleanup(d.Close)
	return d
}

func (d *docServer) set(id string, resp docResponse) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.responses[id] = resp
}

func (d *docServer) count(id string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hits[id]
}

func (d *docServer) last() *http.Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.requests[len(d.requests)-1]
}

// hooks route every fetch to the server, permit loopback addresses and trust
// the server's certificate for any host name.
func (d *docServer) hooks() *metadataTestHooks {
	pool := x509.NewCertPool()
	pool.AddCert(d.Certificate())
	addr := d.Listener.Addr().String()
	return &metadataTestHooks{
		address: func(string) string { return addr },
		permit:  func(a netip.Addr) bool { return a.IsLoopback() },
		tls:     &tls.Config{RootCAs: pool, ServerName: "example.com"},
	}
}

// fetchFrom lets s fetch metadata documents from d.
func (s *Server) fetchFrom(d *docServer) { s.docs.test = d.hooks() }

const (
	testDocID       = "https://app.example.com/client.json"
	testDocRedirect = "https://app.example.com/cb"
)

// metadataDoc returns a valid document for id with extra members merged in.
// A nil value removes a member.
func metadataDoc(id string, extra map[string]any) string {
	doc := map[string]any{
		"client_id": id, "client_name": "Doc client",
		"redirect_uris":              []string{testDocRedirect, "http://127.0.0.1/callback", "cursor://anysphere/cb"},
		"token_endpoint_auth_method": "none",
	}
	for k, v := range extra {
		if v == nil {
			delete(doc, k)
			continue
		}
		doc[k] = v
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return string(b)
}
