package mcpoauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func cimdFixture(t *testing.T, change ...func(*Config)) (*fixture, *docServer) {
	t.Helper()
	docs := newDocServer(t)
	f := newFixture(t, append([]func(*Config){func(c *Config) {
		c.MetadataDocuments = &MetadataDocumentConfig{}
	}}, change...)...)
	f.fetchFrom(docs)
	return f, docs
}

func cimdParams() url.Values {
	params := authParams()
	params.Set("client_id", testDocID)
	params.Set("redirect_uri", testDocRedirect)
	return params
}

func cimdExchange(code string) url.Values {
	form := exchangeForm(code)
	form.Set("client_id", testDocID)
	return form
}

func TestMetadataClientID(t *testing.T) {
	d, err := newMetadataDocs(MetadataDocumentConfig{}, []string{testIssuer, testResource, "https://login.example.org/token"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id        string
		authority string // empty when rejected
	}{
		{"https://app.example.com/client.json", "app.example.com"},
		{"https://app.example.com:8443/c", "app.example.com:8443"},
		{"https://a-b.c.example/x/y/z", "a-b.c.example"},
		{"https://app.example.com/a%2fb", "app.example.com"},
		{"https://app.example.com/.well-known/client", "app.example.com"},
		{"https://app.example.com//double", "app.example.com"},
		{"https://app.example.com", ""},
		{"https://app.example.com/", ""},
		{"https://App.example.com/c", ""},
		{"https://app.example.com./c", ""},
		{"https://xn--4ca.example/c", "xn--4ca.example"},
		{"https://%C3%A4.example/c", ""},
		{"https://ä.example/c", ""},
		{"https://127.0.0.1/c", ""},
		{"https://1.2.3.4/c", ""},
		{"https://[::1]/c", ""},
		{"https://localhost/c", ""},
		{"https://intranet/c", ""},
		{"https://user@app.example.com/c", ""},
		{"https://user:pass@app.example.com/c", ""},
		{"https://app.example.com:0/c", ""},
		{"https://app.example.com:65536/c", ""},
		{"https://app.example.com:/c", ""},
		{"https://app.example.com:+80/c", ""},
		{"https://app.example.com/c?x=1", ""},
		{"https://app.example.com/c?", ""},
		{"https://app.example.com/c#f", ""},
		{"https://app.example.com/./c", ""},
		{"https://app.example.com/a/../c", ""},
		{"https://app.example.com/a/..", ""},
		{"https://app.example.com/%2e/c", ""},
		{"https://app.example.com/%2E%2e/c", ""},
		{"https://app.example.com/.%2E/c", ""},
		{"https://app.example.com/-a.example/c", "app.example.com"},
		{"https://-app.example.com/c", ""},
		{"https://app-.example.com/c", ""},
		{"https://app..example.com/c", ""},
		{"https://" + strings.Repeat("a", 64) + ".example/c", ""},
		{"https://" + strings.Repeat("a", 63) + ".example/c", strings.Repeat("a", 63) + ".example"},
		{"https://app.123/c", ""},
		{"https://app.example1/c", "app.example1"},
		{"https://auth.example/client.json", ""},
		{"https://mcp.example/client.json", ""},
		{"https://mcp.example:8443/client.json", ""},
		{"https://login.example.org/client.json", ""},
		{"http://app.example.com/c", ""},
	} {
		authority, _, err := d.checkID(tc.id)
		if authority != tc.authority {
			t.Errorf("%q: authority %q, want %q (%v)", tc.id, authority, tc.authority, err)
		}
		var merr *MetadataError
		if tc.authority == "" && (!errors.As(err, &merr) || merr.ClientID != tc.id || !errors.Is(err, ErrMetadata) ||
			!errors.Is(err, ErrInvalid) || merr.Mismatch) {
			t.Errorf("%q: error %v", tc.id, err)
		}
	}
}

func TestMetadataAllowedHosts(t *testing.T) {
	d, err := newMetadataDocs(MetadataDocumentConfig{AllowedHosts: []string{"claude.ai", "*.example.com", "claude.ai"}}, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for host, allowed := range map[string]bool{
		"claude.ai": true, "claude.ai:443": true, "a.claude.ai": false,
		"a.example.com": true, "a.b.example.com": true, "a.example.com:8443": true,
		"example.com": false, "evilexample.com": false, "example.com.evil.com": false, "xexample.com": false,
	} {
		_, _, err := d.checkID("https://" + host + "/client")
		if (err == nil) != allowed {
			t.Errorf("%s: %v", host, err)
		}
	}
	for _, bad := range []string{"", "*", "*.", "*.com", "Claude.ai", "claude.ai:443", "**.example.com", "*example.com", "a.*.com", "127.0.0.1"} {
		if _, err := newMetadataDocs(MetadataDocumentConfig{AllowedHosts: []string{bad}}, nil, time.Now); err == nil {
			t.Errorf("allowed host %q was accepted", bad)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	for addr, public := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "203.0.114.1": true, "100.63.255.255": true, "100.128.0.1": true,
		"0.1.2.3": false, "10.1.2.3": false, "100.64.0.1": false, "127.0.0.1": false, "169.254.169.254": false,
		"172.16.0.1": false, "172.31.255.255": false, "172.32.0.1": true, "192.0.0.1": false, "192.0.2.1": false,
		"192.88.99.1": false, "192.168.1.1": false, "198.18.0.1": false, "198.19.255.255": false,
		"198.51.100.1": false, "203.0.113.1": false, "224.0.0.1": false, "239.255.255.255": false,
		"240.0.0.1": false, "255.255.255.255": false,
		"::ffff:8.8.8.8": true, "::ffff:127.0.0.1": false, "::ffff:169.254.169.254": false,
		"2606:4700::1111": true, "2001:4860:4860::8888": true,
		"::1": false, "::": false, "::127.0.0.1": false, "fc00::1": false, "fd00::1": false, "fe80::1": false,
		"ff02::1": false, "2001::1": false, "2001:1ff::1": false, "2001:200::1": true, "2001:db8::1": false,
		"2002:c000:201::1": false, "3fff::1": false, "3fff:fff::1": false, "3fff:1000::1": true, "4000::1": false,
		"64:ff9b::808:808": true, "64:ff9b::a00:1": false, "64:ff9b::7f00:1": false, "64:ff9b::a9fe:a9fe": false,
		"64:ff9b:1::808:808": false, "fe80::1%eth0": false, "2606:4700::1111%eth0": false,
	} {
		if got := publicAddr(netip.MustParseAddr(addr)); got != public {
			t.Errorf("%s: %v, want %v", addr, got, public)
		}
	}
	if publicAddr(netip.Addr{}) {
		t.Error("the zero address is public")
	}
}

func TestCacheTTL(t *testing.T) {
	for _, tc := range []struct {
		cacheControl []string
		age          string
		want         time.Duration
	}{
		{nil, "", 0},
		{[]string{"max-age=300"}, "", 300 * time.Second},
		{[]string{"public, max-age=300"}, "", 300 * time.Second},
		{[]string{"Max-Age=300"}, "", 300 * time.Second},
		{[]string{`max-age="300"`}, "", 300 * time.Second},
		{[]string{"max-age=300"}, "100", 200 * time.Second},
		{[]string{"max-age=300"}, "400", 0},
		{[]string{"max-age=300"}, "x", 300 * time.Second},
		{[]string{"max-age=300, no-cache"}, "", 0},
		{[]string{"no-store", "max-age=300"}, "", 0},
		{[]string{`no-cache="Set-Cookie", max-age=300`}, "", 0},
		{[]string{"max-age"}, "", 0},
		{[]string{"max-age="}, "", 0},
		{[]string{"max-age=-1"}, "", 0},
		{[]string{"max-age=1.5"}, "", 0},
		{[]string{"max-age=300", "max-age=600"}, "", 0},
		{[]string{"s-maxage=300"}, "", 0},
		{[]string{"max-age=99999999999999999999999"}, "", time.Duration(1<<31) * time.Second},
	} {
		h := http.Header{}
		for _, v := range tc.cacheControl {
			h.Add("Cache-Control", v)
		}
		if tc.age != "" {
			h.Set("Age", tc.age)
		}
		h.Set("Expires", "Thu, 01 Jan 2099 00:00:00 GMT")
		if got := cacheTTL(h); got != tc.want {
			t.Errorf("%q age %q: %v, want %v", tc.cacheControl, tc.age, got, tc.want)
		}
	}
}

func TestParseMetadataDocument(t *testing.T) {
	const id = testDocID
	valid := func(body string) {
		t.Helper()
		client, err := parseMetadataDocument(id, []byte(body))
		if err != nil || client.ID != id || client.Validate() != nil {
			t.Errorf("%s: %+v %v", body, client, err)
		}
	}
	invalid := func(body string, mismatch bool) {
		t.Helper()
		_, err := parseMetadataDocument(id, []byte(body))
		if err == nil || err.ClientID != id || err.Mismatch != mismatch || !errors.Is(err, ErrMetadata) {
			t.Errorf("%s: %v", body, err)
		}
	}
	client, err := parseMetadataDocument(id, []byte(metadataDoc(id, nil)))
	if err != nil || client.Name != "Doc client" ||
		strings.Join(client.RedirectURIs, " ") != testDocRedirect+" http://127.0.0.1/callback" {
		t.Fatalf("document: %+v %v", client, err)
	}

	// Members are matched by exact name; unknown ones are ignored.
	valid(metadataDoc(id, map[string]any{"client_name": nil, "Client_Secret": "x", "logo_uri": "https://x.example/l.png"}))
	valid(metadataDoc(id, map[string]any{"client_name": nil, "token_endpoint_auth_method": nil}))
	valid(metadataDoc(id, map[string]any{"client_name": nil, "Client_ID": "other"}))
	valid(`{"client_id":"` + id + `","redirect_uris":["` + testDocRedirect + `"],"nested":{"a":1,"a":2}}`)
	valid("  \n" + metadataDoc(id, nil) + "\n\t ")
	invalid(`{"client_id":"`+id+`","client_id":"`+id+`","redirect_uris":["`+testDocRedirect+`"]}`, false)
	invalid("\xef\xbb\xbf"+metadataDoc(id, nil), false)
	invalid(metadataDoc(id, nil)+"{}", false)
	invalid(metadataDoc(id, nil)+"x", false)
	invalid(`[`+metadataDoc(id, nil)+`]`, false)
	invalid(`"x"`, false)
	invalid(``, false)
	invalid(`{"client_id":"`+id+`",`, false)

	// client_id.
	invalid(metadataDoc(id, map[string]any{"client_id": nil}), false)
	invalid(`{"client_id":null,"redirect_uris":["`+testDocRedirect+`"]}`, false)
	invalid(metadataDoc(id, map[string]any{"client_id": 1}), false)
	invalid(metadataDoc(id, map[string]any{"client_id": id + "/"}), true)
	invalid(metadataDoc(id, map[string]any{"client_id": strings.ToUpper(id)}), true)
	invalid(metadataDoc(id, map[string]any{"client_id": "https://APP.example.com/client.json"}), true)

	// Secrets and keys.
	invalid(metadataDoc(id, map[string]any{"client_secret": "s"}), false)
	invalid(`{"client_id":"`+id+`","redirect_uris":["`+testDocRedirect+`"],"client_secret":null}`, false)
	invalid(`{"client_id":"`+id+`","redirect_uris":["`+testDocRedirect+`"],"client_secret_expires_at":null}`, false)
	invalid(metadataDoc(id, map[string]any{"jwks": map[string]any{}, "jwks_uri": "https://app.example.com/jwks"}), false)
	valid(metadataDoc(id, map[string]any{"jwks_uri": "https://app.example.com/jwks"}))
	valid(`{"client_id":"` + id + `","redirect_uris":["` + testDocRedirect + `"],"jwks":null,"jwks_uri":"x"}`)

	// Authentication methods.
	for _, tc := range []struct {
		single any
		plural any
		ok     bool
	}{
		{nil, nil, true},
		{"none", nil, true},
		{nil, []string{"none"}, true},
		{nil, []string{"private_key_jwt", "none"}, true},
		{"private_key_jwt", []string{"none", "private_key_jwt"}, true},
		{"none", []string{"private_key_jwt"}, false},
		{"private_key_jwt", nil, false},
		{nil, []string{"private_key_jwt"}, false},
		{nil, []string{}, false},
		{"client_secret_basic", nil, false},
		{"client_secret_post", []string{"none", "client_secret_post"}, false},
		{nil, []string{"none", "client_secret_jwt"}, false},
		{1, nil, false},
		{nil, "none", false},
		{nil, []any{"none", 1}, false},
	} {
		body := metadataDoc(id, map[string]any{"token_endpoint_auth_method": tc.single, "token_endpoint_auth_methods_supported": tc.plural})
		if tc.ok {
			valid(body)
		} else {
			invalid(body, false)
		}
	}

	// Redirect URIs.
	uris := func(list any) string { return metadataDoc(id, map[string]any{"redirect_uris": list}) }
	invalid(uris([]string{}), false)
	invalid(uris("https://app.example.com/cb"), false)
	invalid(uris([]any{testDocRedirect, nil}), false)
	invalid(uris([]any{testDocRedirect, 1}), false)
	invalid(uris([]string{"cursor://anysphere/cb"}), false)
	invalid(uris([]string{"http://app.example.com/cb", "https://app.example.com/cb#f", "https://app.example.com/cb?code=1"}), false)
	invalid(`{"client_id":"`+id+`","redirect_uris":null}`, false)
	many := func(n int, prefix string) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("%s%d", prefix, i))
		}
		return out
	}
	valid(uris(many(16, testDocRedirect+"/")))
	invalid(uris(many(17, testDocRedirect+"/")), false)
	valid(uris(append(many(16, testDocRedirect+"/"), many(16, "app:/cb")...)))
	invalid(uris(append(many(16, testDocRedirect+"/"), many(17, "app:/cb")...)), false)
	client, err = parseMetadataDocument(id, []byte(uris([]string{"app:/x", testDocRedirect, testDocRedirect, "http://localhost/cb"})))
	if err != nil || strings.Join(client.RedirectURIs, " ") != testDocRedirect+" http://localhost/cb" {
		t.Fatalf("filtered redirect URIs %q %v", client.RedirectURIs, err)
	}

	// Grant and response types.
	valid(metadataDoc(id, map[string]any{"grant_types": []string{"authorization_code"}}))
	valid(metadataDoc(id, map[string]any{"grant_types": []string{"refresh_token", "authorization_code", "urn:x"}}))
	invalid(metadataDoc(id, map[string]any{"grant_types": []string{"refresh_token"}}), false)
	invalid(metadataDoc(id, map[string]any{"grant_types": "authorization_code"}), false)
	valid(metadataDoc(id, map[string]any{"response_types": []string{"code"}}))
	invalid(metadataDoc(id, map[string]any{"response_types": []string{"token"}}), false)

	// Client name.
	valid(metadataDoc(id, map[string]any{"client_name": "Claude 日本語"}))
	valid(metadataDoc(id, map[string]any{"client_name": strings.Repeat("a", 255)}))
	invalid(metadataDoc(id, map[string]any{"client_name": strings.Repeat("a", 256)}), false)
	invalid(metadataDoc(id, map[string]any{"client_name": 1}), false)
	for _, bad := range []string{"a\nb", "a\x00b", "a‮b", "a⁦b", "a‏b", "a\x7fb"} {
		invalid(metadataDoc(id, map[string]any{"client_name": bad}), false)
	}
	invalid(`{"client_id":"`+id+`","redirect_uris":["`+testDocRedirect+`"],"client_name":"a`+"\xff"+`"}`, false)
}

func TestMetadataCacheLRU(t *testing.T) {
	d, err := newMetadataDocs(MetadataDocumentConfig{}, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	now := testStart
	for i := range metadataCacheSize {
		d.insert(fmt.Sprint(i), &metadataEntry{used: now.Add(time.Duration(i) * time.Second), keepUntil: now.Add(time.Hour)}, now)
	}
	d.cache["5"].used = now.Add(-time.Second)
	d.insert("new", &metadataEntry{used: now, keepUntil: now.Add(time.Hour)}, now)
	if _, ok := d.cache["5"]; ok || len(d.cache) != metadataCacheSize {
		t.Fatalf("least recently used entry kept, %d entries", len(d.cache))
	}
	d.cache["7"].keepUntil = now
	d.cache["8"].keepUntil = now
	d.insert("newer", &metadataEntry{used: now, keepUntil: now.Add(time.Hour)}, now)
	if _, ok := d.cache["0"]; !ok || len(d.cache) != metadataCacheSize-1 {
		t.Fatalf("expired entries not swept first, %d entries", len(d.cache))
	}
}

func TestMetadataAuthorize(t *testing.T) {
	f, docs := cimdFixture(t)
	docs.set(testDocID, docResponse{body: metadataDoc(testDocID, nil), header: map[string]string{"Set-Cookie": "a=b"}})
	req, err := f.Authorize(t.Context(), cimdParams().Encode())
	if err != nil {
		t.Fatal(err)
	}
	if req.ClientID != testDocID || req.ClientName != "Doc client" || req.ClientSource != SourceMetadata ||
		req.ClientHost != "app.example.com" || strings.Join(req.Scopes, " ") != "read write" {
		t.Fatalf("request %+v", req)
	}
	r := docs.last()
	if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" || r.Header.Get("User-Agent") != "authlume-mcpoauth" ||
		r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Accept-Encoding") != "" {
		t.Fatalf("fetch headers %v", r.Header)
	}
	// The loopback redirect URI of the document matches on any port; the
	// custom scheme was dropped.
	params := cimdParams()
	params.Set("redirect_uri", "http://127.0.0.1:49152/callback")
	if _, err := f.Authorize(t.Context(), params.Encode()); err != nil {
		t.Fatal(err)
	}
	params.Set("redirect_uri", "cursor://anysphere/cb")
	if _, err := f.Authorize(t.Context(), params.Encode()); !errors.Is(err, ErrInvalid) || errors.Is(err, ErrMetadata) {
		t.Fatalf("custom scheme: %v", err)
	}
	// A rejection reports the source and host.
	params = cimdParams()
	params.Set("response_type", "token")
	_, err = f.Authorize(t.Context(), params.Encode())
	var reject *RejectError
	if !errors.As(err, &reject) || reject.Request.ClientSource != SourceMetadata || reject.Request.ClientHost != "app.example.com" {
		t.Fatalf("rejection %v", err)
	}
	// A pre-registered client keeps SourceLookup and no host.
	req, err = f.Authorize(t.Context(), authParams().Encode())
	if err != nil || req.ClientSource != SourceLookup || req.ClientHost != "" {
		t.Fatalf("pre-registered %+v %v", req, err)
	}
	// A port is part of the host.
	const ported = "https://app.example.com:8443/client.json"
	docs.set(ported, docResponse{body: metadataDoc(ported, nil)})
	params = cimdParams()
	params.Set("client_id", ported)
	req, err = f.Authorize(t.Context(), params.Encode())
	if err != nil || req.ClientHost != "app.example.com:8443" {
		t.Fatalf("ported %+v %v", req, err)
	}
}

func TestMetadataPrecedence(t *testing.T) {
	f, docs := cimdFixture(t)
	docs.set(testDocID, docResponse{body: metadataDoc(testDocID, nil)})
	// A pre-registered client with an https identifier wins.
	f.clients[testDocID] = Client{ID: testDocID, Name: "Registered", RedirectURIs: []string{testDocRedirect}}
	req, err := f.Authorize(t.Context(), cimdParams().Encode())
	if err != nil || req.ClientSource != SourceLookup || req.ClientName != "Registered" || docs.count(testDocID) != 0 {
		t.Fatalf("pre-registered https client %+v %v, %d fetches", req, err, docs.count(testDocID))
	}
	delete(f.clients, testDocID)
	// A lookup failure never falls through.
	f.lookupErr = errors.New("backend down")
	if _, err := f.Authorize(t.Context(), cimdParams().Encode()); !errors.Is(err, f.lookupErr) || errors.Is(err, ErrInvalid) {
		t.Fatalf("lookup failure: %v", err)
	}
	if r := post(t, f.Token, cimdExchange("x")); r.status != http.StatusServiceUnavailable || docs.count(testDocID) != 0 {
		t.Fatalf("lookup failure at the token endpoint: %d, %d fetches", r.status, docs.count(testDocID))
	}
	f.lookupErr = nil
	// A request that fails anyway fetches nothing.
	for _, edit := range []func(url.Values){
		func(p url.Values) { p.Del("redirect_uri") },
		func(p url.Values) { p.Set("redirect_uri", testDocRedirect+"/"+strings.Repeat("a", 2048)) },
		func(p url.Values) { p["client_id"] = []string{testDocID, testDocID} },
	} {
		params := cimdParams()
		edit(params)
		if _, err := f.Authorize(t.Context(), params.Encode()); err != ErrInvalid || docs.count(testDocID) != 0 {
			t.Fatalf("%v: %v, %d fetches", params, err, docs.count(testDocID))
		}
	}
	// With metadata documents disabled an https identifier is unknown.
	disabled := newFixture(t)
	if _, err := disabled.Authorize(t.Context(), cimdParams().Encode()); err != ErrUnknownClient {
		t.Fatalf("disabled: %v", err)
	}
}

func TestMetadataFetchFailures(t *testing.T) {
	doc := metadataDoc(testDocID, nil)
	for _, tc := range []struct {
		name      string
		resp      docResponse
		permanent bool
		mismatch  bool
	}{
		{"not found", docResponse{status: http.StatusNotFound, body: doc}, true, false},
		{"gone", docResponse{status: http.StatusGone, body: doc}, true, false},
		{"redirect", docResponse{status: http.StatusFound, body: doc, header: map[string]string{"Location": testDocID + "2"}}, true, false},
		{"permanent redirect", docResponse{status: http.StatusPermanentRedirect, body: doc, header: map[string]string{"Location": "/x"}}, true, false},
		{"created", docResponse{status: http.StatusCreated, body: doc}, true, false},
		{"no content", docResponse{status: http.StatusNoContent}, true, false},
		{"forbidden", docResponse{status: http.StatusForbidden, body: doc}, false, false},
		{"unauthorized", docResponse{status: http.StatusUnauthorized, body: doc}, false, false},
		{"timeout status", docResponse{status: http.StatusRequestTimeout, body: doc}, false, false},
		{"too many requests", docResponse{status: http.StatusTooManyRequests, body: doc}, false, false},
		{"server error", docResponse{status: http.StatusInternalServerError, body: doc}, false, false},
		{"bad gateway", docResponse{status: http.StatusBadGateway, body: doc}, false, false},
		{"text", docResponse{contentType: "text/plain", body: doc}, true, false},
		{"no content type", docResponse{contentType: "application/octet-stream", body: doc}, true, false},
		{"bad content type", docResponse{contentType: "application/json; charset", body: doc}, true, false},
		{"json suffix trick", docResponse{contentType: "text/x+json", body: doc}, true, false},
		{"too large", docResponse{body: metadataDoc(testDocID, map[string]any{"pad": strings.Repeat("a", 5120)})}, true, false},
		{"invalid", docResponse{body: "{"}, true, false},
		{"mismatch", docResponse{body: metadataDoc("https://other.example.com/client.json", nil)}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, docs := cimdFixture(t)
			docs.set(testDocID, tc.resp)
			_, err := f.Authorize(t.Context(), cimdParams().Encode())
			var merr *MetadataError
			if tc.permanent {
				if !errors.As(err, &merr) || merr.ClientID != testDocID || merr.Mismatch != tc.mismatch || !errors.Is(err, ErrInvalid) {
					t.Fatalf("permanent failure: %v", err)
				}
			} else if err == nil || errors.Is(err, ErrInvalid) || !errors.Is(err, errFetch) {
				t.Fatalf("temporary failure: %v", err)
			}
			if docs.count(testDocID) != 1 || docs.count(testDocID+"2") != 0 {
				t.Fatalf("%d fetches", docs.count(testDocID))
			}
		})
	}
	t.Run("accepted variants", func(t *testing.T) {
		for _, resp := range []docResponse{
			{contentType: "application/json; charset=utf-8", body: doc},
			{contentType: "Application/JSON", body: doc},
			{contentType: "application/oauth-client+json", body: doc},
			{body: metadataDoc(testDocID, map[string]any{"pad": strings.Repeat("a", 4800)})},
			{body: doc, header: map[string]string{"X-Large": strings.Repeat("a", 16<<10)}},
		} {
			f, docs := cimdFixture(t)
			docs.set(testDocID, resp)
			if _, err := f.Authorize(t.Context(), cimdParams().Encode()); err != nil {
				t.Fatalf("%v: %v", resp.contentType, err)
			}
		}
	})
	t.Run("larger configured size", func(t *testing.T) {
		f, docs := cimdFixture(t, func(c *Config) { c.MetadataDocuments.MaxSize = 16 << 10 })
		docs.set(testDocID, docResponse{body: metadataDoc(testDocID, map[string]any{"pad": strings.Repeat("a", 8000)})})
		if _, err := f.Authorize(t.Context(), cimdParams().Encode()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		f, docs := cimdFixture(t)
		hooks := docs.hooks()
		hooks.address = func(string) string { return "127.0.0.1:1" }
		f.docs.test = hooks
		if _, err := f.Authorize(t.Context(), cimdParams().Encode()); err == nil || errors.Is(err, ErrInvalid) {
			t.Fatalf("refused connection: %v", err)
		}
	})
	t.Run("untrusted certificate", func(t *testing.T) {
		f, docs := cimdFixture(t)
		docs.set(testDocID, docResponse{body: doc})
		hooks := docs.hooks()
		hooks.tls = nil
		f.docs.test = hooks
		if _, err := f.Authorize(t.Context(), cimdParams().Encode()); err == nil || errors.Is(err, ErrInvalid) {
			t.Fatalf("untrusted certificate: %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f, docs := cimdFixture(t, func(c *Config) { c.MetadataDocuments.Timeout = 200 * time.Millisecond })
		wait := make(chan struct{})
		defer close(wait)
		docs.set(testDocID, docResponse{body: doc, wait: wait})
		if _, err := f.Authorize(t.Context(), cimdParams().Encode()); err == nil || errors.Is(err, ErrInvalid) || !errors.Is(err, errFetch) {
			t.Fatalf("timeout: %v", err)
		}
	})
	t.Run("caller context", func(t *testing.T) {
		f, docs := cimdFixture(t)
		wait := make(chan struct{})
		docs.set(testDocID, docResponse{body: doc, wait: wait})
		ctx, cancel := context.WithCancel(t.Context())
		go func() { <-docs.arrived; cancel() }()
		if _, err := f.Authorize(ctx, cimdParams().Encode()); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled: %v", err)
		}
		close(wait)
		// The detached fetch still completes and fills the cache.
		deadline := time.Now().Add(5 * time.Second)
		for {
			f.docs.mu.Lock()
			_, cached := f.docs.cache[testDocID]
			f.docs.mu.Unlock()
			if cached {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the detached fetch did not fill the cache")
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func TestMetadataAddressCheck(t *testing.T) {
	f, docs := cimdFixture(t)
	docs.set(testDocID, docResponse{body: metadataDoc(testDocID, nil)})
	hooks := docs.hooks()
	hooks.permit = nil // the production check refuses the loopback test server
	f.docs.test = hooks
	_, err := f.Authorize(t.Context(), cimdParams().Encode())
	var merr *MetadataError
	if !errors.As(err, &merr) || merr.Reason != "blocked address" || docs.count(testDocID) != 0 {
		t.Fatalf("loopback: %v, %d fetches", err, docs.count(testDocID))
	}
	// The proxy environment is not used.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	f.fetchFrom(docs)
	if _, err := f.Authorize(t.Context(), cimdParams().Encode()); err != nil {
		t.Fatalf("with a proxy environment: %v", err)
	}
}

func TestMetadataCache(t *testing.T) {
	// The document stays fresh for 10 minutes and is kept for 24 hours more.
	f, docs := cimdFixture(t, func(c *Config) {
		c.MetadataDocuments.MinCacheTTL, c.MetadataDocuments.MaxCacheTTL = 10*time.Minute, 24*time.Hour
	})
	good := docResponse{body: metadataDoc(testDocID, nil), header: map[string]string{"Cache-Control": "max-age=60"}}
	down := docResponse{status: http.StatusServiceUnavailable}
	docs.set(testDocID, good)
	authorize := func() error {
		_, err := f.Authorize(t.Context(), cimdParams().Encode())
		return err
	}
	revoke := func() reply {
		return post(t, f.Revocation, url.Values{"client_id": {testDocID}, "token": {"unknown"}})
	}
	if err := authorize(); err != nil || docs.count(testDocID) != 1 {
		t.Fatalf("first: %v, %d fetches", err, docs.count(testDocID))
	}
	// Authorization within 30 seconds of the fetch uses the entry.
	f.advance(29 * time.Second)
	if err := authorize(); err != nil || docs.count(testDocID) != 1 {
		t.Fatalf("within 30 seconds: %v, %d fetches", err, docs.count(testDocID))
	}
	// Later it fetches again, and on a temporary failure uses the fresh entry.
	f.advance(time.Second)
	docs.set(testDocID, down)
	if err := authorize(); err != nil || docs.count(testDocID) != 2 {
		t.Fatalf("fallback to a fresh entry: %v, %d fetches", err, docs.count(testDocID))
	}
	// The token endpoint uses the fresh entry without fetching.
	if r := revoke(); r.status != http.StatusOK || docs.count(testDocID) != 2 {
		t.Fatalf("fresh entry at the token endpoint: %d, %d fetches", r.status, docs.count(testDocID))
	}
	// Past freshness, authorization refuses the stale entry but the token
	// endpoint falls back to it.
	f.advance(10 * time.Minute)
	if err := authorize(); err == nil || errors.Is(err, ErrInvalid) {
		t.Fatalf("stale entry at authorization: %v", err)
	}
	if r := revoke(); r.status != http.StatusOK || docs.count(testDocID) != 4 {
		t.Fatalf("stale entry at the token endpoint: %d %s, %d fetches", r.status, r.body, docs.count(testDocID))
	}
	// Past the keep deadline there is nothing to fall back to.
	f.advance(24 * time.Hour)
	revoke().unavailable(t, errFetch)
	// A success refreshes the entry; a permanent failure removes it.
	docs.set(testDocID, good)
	if r := revoke(); r.status != http.StatusOK {
		t.Fatalf("refetch: %d", r.status)
	}
	f.advance(10 * time.Minute)
	docs.set(testDocID, docResponse{status: http.StatusNotFound})
	r := revoke()
	r.rejected(t, http.StatusUnauthorized, "invalid_client")
	var merr *MetadataError
	if !errors.Is(r.err, ErrClient) || !errors.As(r.err, &merr) || merr.ClientID != testDocID || r.event.ClientID != "" {
		t.Fatalf("permanent failure: %v %+v", r.err, r.event)
	}
	docs.set(testDocID, down)
	revoke().unavailable(t, errFetch)
}

func TestMetadataApproveRecheck(t *testing.T) {
	f, docs := cimdFixture(t)
	docs.set(testDocID, docResponse{body: metadataDoc(testDocID, nil), header: map[string]string{"Cache-Control": "max-age=86400"}})
	if _, err := f.Authorize(t.Context(), cimdParams().Encode()); err != nil {
		t.Fatal(err)
	}
	f.advance(31 * time.Second)
	docs.set(testDocID, docResponse{body: metadataDoc(testDocID, map[string]any{"redirect_uris": []string{"https://app.example.com/other"}})})
	if _, _, err := f.Approve(t.Context(), cimdParams().Encode(), "alice"); !errors.Is(err, ErrInvalid) || docs.count(testDocID) != 2 {
		t.Fatalf("approval after the document changed: %v, %d fetches", err, docs.count(testDocID))
	}
	if _, err := f.Deny(t.Context(), cimdParams().Encode()); !errors.Is(err, ErrInvalid) || docs.count(testDocID) != 2 {
		t.Fatalf("denial within 30 seconds: %v, %d fetches", err, docs.count(testDocID))
	}
}

func TestMetadataSharedFetch(t *testing.T) {
	f, docs := cimdFixture(t)
	wait := make(chan struct{})
	docs.set(testDocID, docResponse{body: metadataDoc(testDocID, nil), wait: wait})
	first, cancel := context.WithCancel(t.Context())
	errs := make(chan error, 2)
	go func() {
		_, err := f.Authorize(first, cimdParams().Encode())
		errs <- err
	}()
	<-docs.arrived
	go func() {
		_, err := f.Authorize(t.Context(), cimdParams().Encode())
		errs <- err
	}()
	// The second caller joins the fetch in progress.
	for {
		f.docs.mu.Lock()
		joined := len(f.docs.flights) == 1
		f.docs.mu.Unlock()
		if joined {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-errs; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller: %v", err)
	}
	close(wait)
	if err := <-errs; err != nil {
		t.Fatalf("waiting caller: %v", err)
	}
	if docs.count(testDocID) != 1 {
		t.Fatalf("%d fetches", docs.count(testDocID))
	}
}

func TestMetadataConcurrencyLimits(t *testing.T) {
	f, docs := cimdFixture(t)
	wait := make(chan struct{})
	ids := func(host string, n int) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("https://%s/client-%d.json", host, i))
		}
		return out
	}
	var all []string
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"} {
		all = append(all, ids(host, 5)...)
	}
	for _, id := range all {
		docs.set(id, docResponse{body: metadataDoc(id, nil), wait: wait})
	}
	authorize := func(ctx context.Context, id string) error {
		params := cimdParams()
		params.Set("client_id", id)
		_, err := f.Authorize(ctx, params.Encode())
		return err
	}
	var wg sync.WaitGroup
	started := 0
	for _, id := range all {
		if strings.HasSuffix(id, "-4.json") {
			continue
		}
		started++
		wg.Go(func() {
			if err := authorize(t.Context(), id); err != nil {
				t.Errorf("%s: %v", id, err)
			}
		})
	}
	for range started {
		<-docs.arrived
	}
	// Four per host are in flight, which is also the global limit of 16.
	if err := authorize(t.Context(), "https://a.example.com/client-4.json"); err == nil || errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "too many concurrent fetches") {
		t.Fatalf("over the host limit: %v", err)
	}
	const other = "https://e.example.com/client.json"
	docs.set(other, docResponse{body: metadataDoc(other, nil)})
	if err := authorize(t.Context(), other); err == nil || errors.Is(err, ErrInvalid) {
		t.Fatalf("over the global limit: %v", err)
	}
	close(wait)
	wg.Wait()
	if err := authorize(t.Context(), other); err != nil {
		t.Fatalf("after the fetches: %v", err)
	}
	f.docs.mu.Lock()
	defer f.docs.mu.Unlock()
	if f.docs.active != 0 || len(f.docs.perHost) != 0 || len(f.docs.flights) != 0 {
		t.Fatalf("counters %d %v %v", f.docs.active, f.docs.perHost, f.docs.flights)
	}
}

func TestMetadataToken(t *testing.T) {
	f, docs := cimdFixture(t)
	docs.set(testDocID, docResponse{body: metadataDoc(testDocID, map[string]any{"grant_types": []string{"authorization_code"}})})
	code := f.code(cimdParams(), "alice")
	r := post(t, f.Token, cimdExchange(code))
	g := granted(t, r)
	if r.event.ClientID != testDocID || r.event.Subject != "alice" {
		t.Fatalf("event %+v", r.event)
	}
	refresh := refreshForm(g.refresh)
	refresh.Set("client_id", testDocID)
	g2 := granted(t, post(t, f.Token, refresh))
	if r := post(t, f.Revocation, url.Values{"client_id": {testDocID}, "token": {g2.refresh}}); r.status != http.StatusOK || r.event.ConnectionID != g.id {
		t.Fatalf("revocation %d %+v", r.status, r.event)
	}
	if len(f.connections("alice")) != 0 {
		t.Fatal("connection kept")
	}

	// Any credential is refused before fetching.
	before := docs.count(testDocID)
	f.advance(48 * time.Hour)
	for name, edit := range map[string]func(url.Values){
		"basic":                 nil,
		"secret":                func(v url.Values) { v.Set("client_secret", "s") },
		"empty secret":          func(v url.Values) { v.Set("client_secret", "") },
		"assertion":             func(v url.Values) { v.Set("client_assertion", "a.b.c") },
		"empty assertion type":  func(v url.Values) { v.Set("client_assertion_type", "") },
		"assertion with secret": func(v url.Values) { v.Set("client_assertion", "x"); v.Set("client_secret", "y") },
	} {
		form := refreshForm(g2.refresh)
		form.Set("client_id", testDocID)
		var r reply
		if edit == nil {
			form.Del("client_id")
			r = post(t, f.Token, form, basicAuth(url.QueryEscape(testDocID), ""))
		} else {
			edit(form)
			r = post(t, f.Token, form)
		}
		r.rejected(t, http.StatusUnauthorized, "invalid_client")
		if (r.header.Get("WWW-Authenticate") != "") != (name == "basic") || docs.count(testDocID) != before {
			t.Fatalf("%s: header %v, %d fetches", name, r.header, docs.count(testDocID))
		}
	}
	// A repeated assertion parameter is a malformed request.
	for _, handle := range []handlerFunc{f.Token, f.Revocation} {
		form := url.Values{"client_id": {testDocID}, "grant_type": {"refresh_token"}, "refresh_token": {g2.refresh},
			"token": {g2.refresh}, "client_assertion_type": {"a", "b"}}
		post(t, handle, form).rejected(t, http.StatusBadRequest, "invalid_request")
		form.Del("client_assertion_type")
		form["client_assertion"] = []string{"a", "b"}
		post(t, handle, form).rejected(t, http.StatusBadRequest, "invalid_request")
	}
}

func TestMetadataTokenFailures(t *testing.T) {
	f, docs := cimdFixture(t)
	docs.set(testDocID, docResponse{body: metadataDoc(testDocID, nil)})
	code := f.code(cimdParams(), "alice")
	// A document that now names another client fails the exchange.
	f.advance(time.Hour)
	docs.set(testDocID, docResponse{body: metadataDoc("https://app.example.com/other.json", nil)})
	r := post(t, f.Token, cimdExchange(code))
	r.rejected(t, http.StatusUnauthorized, "invalid_client")
	var merr *MetadataError
	if !errors.As(r.err, &merr) || !merr.Mismatch || r.event.ClientID != "" || r.event.Grant != "" {
		t.Fatalf("mismatch: %v %+v", r.err, r.event)
	}
	// A temporary failure without any entry is a 503.
	docs.set(testDocID, docResponse{status: http.StatusInternalServerError})
	post(t, f.Token, cimdExchange(code)).unavailable(t, errFetch)
}
