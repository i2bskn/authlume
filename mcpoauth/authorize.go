package mcpoauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Request is a validated authorization request.
type Request struct {
	ClientID   string
	ClientName string
	// RedirectURI is the presented value, unchanged.
	RedirectURI string
	// Scopes keeps the requested order without duplicates. When the request
	// omitted scope it holds the configured default scopes that the client
	// may be granted.
	Scopes []string
	State  string
}

// RejectError is a failure that may be reported to the client, whose identity
// and redirect URI have been verified. errors.Is(err, ErrInvalid) is true.
//
// The package never redirects. Whether to send the browser to RedirectURL is
// the application's decision: where anyone can register a client, automatic
// forwarding makes the authorization endpoint an open redirector (RFC 9700
// section 4.11.2), so show an error page or require a user action instead.
type RejectError struct {
	// Code is the OAuth error code.
	Code string
	// RedirectURL is the client's redirect URI with error, state and iss.
	RedirectURL string
	// Request carries ClientID, ClientName, RedirectURI and State for an
	// error page. Scopes is nil.
	Request Request
}

func (e *RejectError) Error() string { return "mcpoauth: authorization rejected: " + e.Code }

func (e *RejectError) Is(target error) bool { return target == ErrInvalid }

const (
	maxQuery = 8192
	maxState = 1024
)

// single reports whether none of the named parameters is repeated.
func single(values url.Values, names ...string) bool {
	for _, name := range names {
		if len(values[name]) > 1 {
			return false
		}
	}
	return true
}

type authorization struct {
	request   Request
	challenge string
	redirect  *url.URL
	query     url.Values
}

// redirectURL adds one response parameter, state and iss to the client's
// redirect URI, keeping the values of its registered query.
func (a *authorization) redirectURL(issuer, name, value string) string {
	query := make(url.Values, len(a.query)+3)
	for k, v := range a.query {
		query[k] = slices.Clone(v)
	}
	query.Set(name, value)
	if a.request.State != "" {
		query.Set("state", a.request.State)
	}
	query.Set("iss", issuer)
	u := *a.redirect
	u.RawQuery = query.Encode()
	return u.String()
}

// authorize validates an authorization request. Failures that must not reach
// the client return ErrInvalid before any that return a *RejectError.
func (s *Server) authorize(ctx context.Context, rawQuery string) (*authorization, error) {
	if len(rawQuery) > maxQuery || strings.Contains(rawQuery, ";") {
		return nil, ErrInvalid
	}
	params, err := url.ParseQuery(rawQuery)
	if err != nil || !single(params, "client_id", "redirect_uri", "response_type", "scope", "state",
		"code_challenge", "code_challenge_method", "resource") {
		return nil, ErrInvalid
	}
	clientID := params.Get("client_id")
	if !validClientID(clientID) {
		return nil, ErrInvalid
	}
	client, err := s.client(ctx, clientID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	redirectURI, state := params.Get("redirect_uri"), params.Get("state")
	if redirectURI == "" || !slices.ContainsFunc(client.RedirectURIs, func(registered string) bool {
		return matchRedirect(registered, redirectURI)
	}) || len(state) > maxState {
		return nil, ErrInvalid
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return nil, ErrInvalid
	}
	query, err := url.ParseQuery(redirect.RawQuery)
	if err != nil {
		return nil, ErrInvalid
	}
	a := &authorization{
		request:  Request{ClientID: client.ID, ClientName: client.Name, RedirectURI: redirectURI, State: state},
		redirect: redirect, query: query,
	}
	reject := func(code string) (*authorization, error) {
		return nil, &RejectError{Code: code, RedirectURL: a.redirectURL(s.issuer, "error", code), Request: a.request}
	}

	switch params.Get("response_type") {
	case "code":
	case "":
		return reject("invalid_request")
	default:
		return reject("unsupported_response_type")
	}
	a.challenge = params.Get("code_challenge")
	if params.Get("code_challenge_method") != "S256" || !validValue(a.challenge) {
		return reject("invalid_request")
	}
	if resource := params.Get("resource"); resource != "" && !s.matchResource(resource) {
		return reject("invalid_target")
	}
	var scopes []string
	for scope := range strings.SplitSeq(params.Get("scope"), " ") {
		if scope == "" || slices.Contains(scopes, scope) {
			continue
		}
		if _, ok := s.known[scope]; !ok || !client.allows(scope) {
			return reject("invalid_scope")
		}
		scopes = append(scopes, scope)
	}
	if len(scopes) == 0 {
		for _, scope := range s.defaults {
			if client.allows(scope) {
				scopes = append(scopes, scope)
			}
		}
		// A restricted client without a default scope must name its scopes.
		if len(scopes) == 0 {
			return reject("invalid_scope")
		}
	}
	a.request.Scopes = scopes
	return a, nil
}

// Authorize validates the authorization request in rawQuery, the raw query
// string the authorization endpoint received (r.URL.RawQuery). It keeps no
// server-side state. Show the consent screen for the returned Request.
//
// A *RejectError may be reported to the client. Any other error must not
// redirect the browser: the client or its redirect URI is unverified.
//
// The consent screen names the client, the redirect URI's host and the scopes.
// Warn the user when Request.RedirectURI is a loopback address, since any
// local program can then receive the response. Forbid framing of the screen.
func (s *Server) Authorize(ctx context.Context, rawQuery string) (Request, error) {
	if s.uninitialized() {
		return Request{}, errUninitialized
	}
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	a, err := s.authorize(ctx, rawQuery)
	if err != nil {
		return Request{}, err
	}
	return a.request, nil
}

// Approve validates the request again, records subject's consent as a
// single-use authorization code and returns the approved Request with the
// client's redirect URL.
//
// Before calling it, authenticate the user and confirm that the call results
// from the user's explicit consent action. Protect the consent POST against
// CSRF. Binding the displayed request to the approved one is the
// application's duty: pass the same query string to Authorize on the GET and
// to Approve on the POST, and compare the returned Request with what was
// shown when it matters. When sending the browser to the redirect URL, set
// Cache-Control: no-store and Referrer-Policy: no-referrer.
func (s *Server) Approve(ctx context.Context, rawQuery, subject string) (Request, string, error) {
	if s.uninitialized() {
		return Request{}, "", errUninitialized
	}
	if err := ctx.Err(); err != nil {
		return Request{}, "", err
	}
	if subject == "" {
		return Request{}, "", errors.New("mcpoauth: subject is required")
	}
	a, err := s.authorize(ctx, rawQuery)
	if err != nil {
		return Request{}, "", err
	}
	code := randomValue()
	err = s.store.CreateCode(ctx, s.key("code", code), Code{
		ClientID: a.request.ClientID, RedirectURI: a.request.RedirectURI, Subject: subject,
		Scopes: slices.Clone(a.request.Scopes), Challenge: a.challenge, ExpiresAt: s.now().Add(codeTTL),
	})
	if err != nil {
		return Request{}, "", fmt.Errorf("mcpoauth: store code: %w", err)
	}
	return a.request, a.redirectURL(s.issuer, "code", code), nil
}

// Deny validates the request again and returns the client's redirect URL
// carrying error=access_denied.
func (s *Server) Deny(ctx context.Context, rawQuery string) (string, error) {
	if s.uninitialized() {
		return "", errUninitialized
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	a, err := s.authorize(ctx, rawQuery)
	if err != nil {
		return "", err
	}
	return a.redirectURL(s.issuer, "error", "access_denied"), nil
}
