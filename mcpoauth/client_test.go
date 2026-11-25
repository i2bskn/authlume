package mcpoauth

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestClientValidate(t *testing.T) {
	valid := func() Client {
		return Client{ID: "client", Name: "Client", RedirectURIs: []string{"https://client.example/cb"}}
	}
	uri := func(raw string) func(*Client) {
		return func(c *Client) { c.RedirectURIs = []string{"https://client.example/cb", raw} }
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = fmt.Sprintf("https://client.example/cb/%d", i)
	}
	for _, tc := range []struct {
		name   string
		change func(*Client)
		ok     bool
	}{
		{"minimal", func(*Client) {}, true},
		{"empty name", func(c *Client) { c.Name = "" }, true},
		{"longest ID", func(c *Client) { c.ID = strings.Repeat("x", 2048) }, true},
		{"URL as ID", func(c *Client) { c.ID = "https://client.example/metadata.json" }, true},
		{"empty ID", func(c *Client) { c.ID = "" }, false},
		{"long ID", func(c *Client) { c.ID = strings.Repeat("x", 2049) }, false},
		{"ID with a space", func(c *Client) { c.ID = "a b" }, false},
		{"ID with a control character", func(c *Client) { c.ID = "a\x7f" }, false},
		{"ID outside ASCII", func(c *Client) { c.ID = "é" }, false},
		{"longest name", func(c *Client) { c.Name = strings.Repeat("x", 255) }, true},
		{"long name", func(c *Client) { c.Name = strings.Repeat("x", 256) }, false},
		{"no redirect URI", func(c *Client) { c.RedirectURIs = nil }, false},
		{"16 redirect URIs", func(c *Client) { c.RedirectURIs = many[:16] }, true},
		{"17 redirect URIs", func(c *Client) { c.RedirectURIs = many }, false},
		{"query", uri("https://client.example/cb?tenant=a&x"), true},
		{"port", uri("https://client.example:8443/cb"), true},
		{"loopback IPv4", uri("http://127.0.0.1/cb"), true},
		{"loopback IPv4 with a port", uri("http://127.0.0.1:8080/cb"), true},
		{"loopback IPv6", uri("http://[::1]/cb"), true},
		{"localhost", uri("http://localhost/cb"), true},
		{"longest URI", uri("https://client.example/" + strings.Repeat("x", 2048-len("https://client.example/"))), true},
		{"long URI", uri("https://client.example/" + strings.Repeat("x", 2049-len("https://client.example/"))), false},
		{"empty URI", uri(""), false},
		{"unparsable URI", uri("https://client.example/%zz"), false},
		{"https without a host", uri("https:///cb"), false},
		{"plain http", uri("http://client.example/cb"), false},
		{"other loopback address", uri("http://127.0.0.2/cb"), false},
		{"uppercase localhost", uri("http://LOCALHOST/cb"), false},
		{"localhost subdomain", uri("http://app.localhost/cb"), false},
		{"custom scheme", uri("com.example.app:/cb"), false},
		{"fragment", uri("https://client.example/cb#x"), false},
		{"empty fragment", uri("https://client.example/cb#"), false},
		{"loopback fragment", uri("http://127.0.0.1/cb#x"), false},
		{"user information", uri("https://user@client.example/cb"), false},
		{"loopback user information", uri("http://user@127.0.0.1/cb"), false},
		{"reserved code", uri("https://client.example/cb?code=x"), false},
		{"reserved state", uri("https://client.example/cb?a=1&state="), false},
		{"reserved iss", uri("https://client.example/cb?iss"), false},
		{"reserved error", uri("http://localhost/cb?error=x"), false},
		{"unparsable query", uri("https://client.example/cb?a=%zz"), false},
		{"semicolon in the query", uri("https://client.example/cb?a=1;b=2"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.change(&c)
			if err := c.Validate(); (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrRecord)) {
				t.Fatalf("validate: %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestMatchRedirect(t *testing.T) {
	for _, tc := range []struct {
		name, registered, presented string
		want                        bool
	}{
		{"https exact", "https://client.example/cb?a=1", "https://client.example/cb?a=1", true},
		{"https trailing slash", "https://client.example/cb", "https://client.example/cb/", false},
		{"https query", "https://client.example/cb?a=1", "https://client.example/cb?a=2", false},
		{"https added query", "https://client.example/cb", "https://client.example/cb?a=1", false},
		{"https port", "https://client.example/cb", "https://client.example:8443/cb", false},
		{"https default port", "https://client.example/cb", "https://client.example:443/cb", false},
		{"https host case", "https://client.example/cb", "https://CLIENT.example/cb", false},
		{"https to http", "https://client.example/cb", "http://client.example/cb", false},
		{"https loopback port", "https://127.0.0.1/cb", "https://127.0.0.1:8443/cb", false},
		{"loopback exact", "http://127.0.0.1/cb", "http://127.0.0.1/cb", true},
		{"loopback other port", "http://127.0.0.1/cb", "http://127.0.0.1:51234/cb", true},
		{"loopback registered port", "http://127.0.0.1:8080/cb", "http://127.0.0.1:51234/cb", true},
		{"loopback IPv6 port", "http://[::1]/cb", "http://[::1]:51234/cb", true},
		{"localhost port", "http://localhost/cb", "http://localhost:51234/cb", true},
		{"loopback query", "http://127.0.0.1/cb?a=1", "http://127.0.0.1:51234/cb?a=1", true},
		{"localhost for 127.0.0.1", "http://127.0.0.1/cb", "http://localhost:51234/cb", false},
		{"127.0.0.1 for localhost", "http://localhost/cb", "http://127.0.0.1:51234/cb", false},
		{"IPv6 for IPv4", "http://127.0.0.1/cb", "http://[::1]:51234/cb", false},
		{"loopback path", "http://127.0.0.1/cb", "http://127.0.0.1:51234/other", false},
		{"loopback trailing slash", "http://127.0.0.1/cb", "http://127.0.0.1:51234/cb/", false},
		{"loopback encoded path", "http://127.0.0.1/cb", "http://127.0.0.1:51234/%63b", false},
		{"loopback query differs", "http://127.0.0.1/cb?a=1", "http://127.0.0.1:51234/cb?a=2", false},
		{"loopback added query", "http://127.0.0.1/cb", "http://127.0.0.1:51234/cb?a=1", false},
		{"loopback empty query", "http://127.0.0.1/cb", "http://127.0.0.1:51234/cb?", false},
		{"loopback https", "http://127.0.0.1/cb", "https://127.0.0.1:51234/cb", false},
		{"loopback fragment", "http://127.0.0.1/cb", "http://127.0.0.1:51234/cb#x", false},
		{"loopback user information", "http://127.0.0.1/cb", "http://user@127.0.0.1:51234/cb", false},
		{"loopback host suffix", "http://127.0.0.1/cb", "http://127.0.0.1.example:51234/cb", false},
		{"loopback bad port", "http://127.0.0.1/cb", "http://127.0.0.1:x/cb", false},
		{"loopback too long", "http://127.0.0.1/cb", "http://127.0.0.1:" + strings.Repeat("0", 2048) + "1/cb", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchRedirect(tc.registered, tc.presented); got != tc.want {
				t.Fatalf("match %q with %q: %v", tc.registered, tc.presented, got)
			}
		})
	}
}
