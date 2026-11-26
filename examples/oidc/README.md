# Sign in with OpenID Connect

This HTTPS example links one operator-approved external identity to a local account. To run it, register a confidential web client with the exact callback `https://127.0.0.1:8443/callback`. Use a provider on a separate trusted HTTPS host that supports discovery, RS256 ID tokens, the authorization code flow, client_secret_basic and S256 PKCE. RS256 is the default. Set `oidc.Config.SigningAlgs` to choose among RS256, PS256, ES256 and EdDSA; an ID token signed with an algorithm left off the list is rejected.

The client accepts ID tokens with one audience (the registered client ID) and integer Unix timestamps. If discovery advertises an authorization response issuer parameter, the callback must include it.

Set `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` from your registration. Set `OIDC_SUBJECT` to the exact subject assigned by that issuer for this client, and `LOCAL_ACCOUNT` to the corresponding opaque local account ID. Keep the client secret server-side. For a local test certificate and key, run the following from the repository root.

```sh
certdir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "$certdir/key.pem" -out "$certdir/cert.pem"
go run ./examples/oidc -cert "$certdir/cert.pem" -key "$certdir/key.pem"
```

Trust the local test certificate and open <https://127.0.0.1:8443/>. Sign in with the provider. The sample requires MFA by default and displays “Additional authentication required” after account resolution. To explicitly trust a provider guarantee, set `OIDC_ACCEPTED_ACR` to the exact authentication class your configured issuer defines as sufficient. The sample also requires a signed `auth_time` less than five minutes old. With required MFA and an accepted ACR configured, the example sends `acr_values` and `max_age=300` to the provider. A missing or stale signed `auth_time` fails the protocol check. The application then checks the actual ACR before issuing a session. It requests only the `openid` scope. To exercise a policy that permits this account to log in with OIDC alone, run with `-require-mfa=false`. A completed login redirects to the account page.

Run `go test -race ./oidc ./examples/oidc` to drive the HTTPS flow with a local signed test issuer.

## Integrate with an application

See the [documentation](https://docs.i2bskn.com/authlume/guides/oidc/).
