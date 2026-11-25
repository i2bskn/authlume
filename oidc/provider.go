package oidc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	provider "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrProviderUnavailable indicates an operational failure contacting the
// provider or exchanging a code. The error excludes response bodies and tokens.
var ErrProviderUnavailable = errors.New("oidc: provider unavailable")

// go-oidc stringifies non-200 responses and mid-stream body errors when it
// reads metadata and JWKS. Finish these small GETs at the HTTP boundary so
// transport failures retain their category. OAuth token POSTs pass through.
type providerTransport struct{ base http.RoundTripper }

const maxMetadataBytes = 1 << 20

func (t providerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil || r.Method != http.MethodGet {
		return resp, err
	}
	if resp.Body == nil {
		return nil, ErrProviderUnavailable
	}
	body := resp.Body
	defer body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > maxMetadataBytes {
		return nil, ErrProviderUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(body, maxMetadataBytes+1))
	if err != nil || len(data) > maxMetadataBytes {
		return nil, ErrProviderUnavailable
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return resp, nil
}

func exchangeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var oauthErr *oauth2.RetrieveError
	if errors.As(err, &oauthErr) && oauthErr.ErrorCode == "invalid_grant" &&
		oauthErr.Response.StatusCode == http.StatusBadRequest {
		return ErrInvalid
	}
	return ErrProviderUnavailable
}

// The upstream verifier stringifies KeySet errors. Capture a safe category
// per verification while all requests continue to use the same JWKS cache.
type verificationKeys struct {
	keys        provider.KeySet
	unavailable bool
}

func (k *verificationKeys) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	payload, err := k.keys.VerifySignature(ctx, raw)
	var network *url.Error
	k.unavailable = errors.As(err, &network) || errors.Is(err, ErrProviderUnavailable)
	return payload, err
}

func (c *Client) verifyToken(ctx context.Context, raw string) (*provider.IDToken, error) {
	keys := &verificationKeys{keys: c.keys}
	v := provider.NewVerifier(c.issuer, keys, &provider.Config{
		ClientID: c.oauth.ClientID, SupportedSigningAlgs: []string{provider.RS256},
	})
	token, err := v.Verify(ctx, raw)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if keys.unavailable {
		return nil, ErrProviderUnavailable
	}
	if err != nil {
		return nil, ErrInvalid
	}
	return token, nil
}
