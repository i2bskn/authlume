# MCP OAuth over HTTPS

This loopback example is an OAuth 2.1 authorization server and a protected MCP endpoint for one demo user and one pre-registered client. It signs the user in with the `password` and `session` packages and uses `github.com/i2bskn/authlume/mcpoauth` for consent, tokens and bearer verification. The `/mcp` route answers just enough of the MCP protocol for a client to connect and call two tools: `initialize`, `ping`, `tools/list` and `tools/call`. It keeps no MCP session and opens no event stream.

## Run

Use Go 1.25 or later, Bash and OpenSSL. Generate a certificate for the loopback address, set a demo password and register the client's ID and redirect URI.

```bash
certdir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "$certdir/key.pem" -out "$certdir/cert.pem"
read -rs -p 'Demo password: ' AUTHLUME_PASSWORD
echo
export AUTHLUME_PASSWORD
export MCP_CLIENT_ID=demo-client
export MCP_REDIRECT_URI=http://127.0.0.1/callback
go run ./examples/mcp -cert "$certdir/cert.pem" -key "$certdir/key.pem"
```

The redirect URI is an HTTPS URL, or an HTTP URL on `127.0.0.1`, `[::1]` or `localhost`. A loopback URI is registered without a port and matches any port the client listens on. Set `MCP_CLIENT_SECRET` to a random value with at least 256 bits of entropy to make the client confidential. Without it the client is public and identified by its ID alone.

Create a PKCE pair and open the authorization request in a browser that trusts the temporary certificate.

```bash
verifier=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')
challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')
echo "https://127.0.0.1:8446/authorize?response_type=code&client_id=$MCP_CLIENT_ID&redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback&code_challenge=$challenge&code_challenge_method=S256&scope=mcp%3Aread%20mcp%3Awrite&state=demo"
```

Sign in as `demo`, then choose **Allow**. The browser is sent to the redirect URI with `code`, `state` and `iss`. Nothing needs to listen there: copy the code from the address bar and exchange it within 60 seconds.

```bash
code=PASTE_THE_CODE
curl --cacert "$certdir/cert.pem" https://127.0.0.1:8446/token \
  -d grant_type=authorization_code -d client_id="$MCP_CLIENT_ID" \
  -d code="$code" -d code_verifier="$verifier"
```

Call a tool with the access token and renew it with the refresh token.

```bash
curl --cacert "$certdir/cert.pem" -H "Authorization: Bearer $access_token" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}' https://127.0.0.1:8446/mcp
curl --cacert "$certdir/cert.pem" https://127.0.0.1:8446/token \
  -d grant_type=refresh_token -d client_id="$MCP_CLIENT_ID" -d refresh_token="$refresh_token"
```

Every request to `/mcp` needs `mcp:read`. The `whoami` tool reports who the token acts for. The `echo` tool also needs `mcp:write` and answers 403 with an `insufficient_scope` challenge without it. A request that omits `scope` receives `mcp:read` only. Each refresh returns a new access token and a new refresh token. Sending an earlier refresh token again revokes that connection. The signed-in user lists and disconnects connections at <https://127.0.0.1:8446/connections>. The client can revoke its own connection by posting either token to `/revoke`. The metadata documents are at `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource/mcp`. The second one is also served at `/.well-known/oauth-protected-resource` for clients that look at the root.

## Integrate with an application

See the [documentation](https://docs.i2bskn.com/authlume/guides/mcp-oauth/).
