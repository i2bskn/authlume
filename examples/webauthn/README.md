# Password and WebAuthn over HTTPS

This standard `net/http` example requires a password and a registered platform passkey or roaming security key (such as a WebAuthn-capable YubiKey) for its single demo account. The independent `github.com/i2bskn/authlume/webauthn` package can also verify a second factor after another primary method has identified a local application subject. The example then adds a passkey to the signed-in account and signs in with that passkey alone, without a username.

## Run locally

Use Go 1.26 or later, OpenSSL, a WebAuthn authenticator and a browser supporting the WebAuthn JSON conversion methods. Generate a localhost certificate, a demo password and a separate random first-enrollment code. Use the code only for this run.

```bash
certdir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout "$certdir/key.pem" -out "$certdir/cert.pem"
read -rs -p 'Demo password: ' AUTHLUME_PASSWORD
echo
export AUTHLUME_PASSWORD
export AUTHLUME_ENROLLMENT_CODE=$(openssl rand -base64 32)
# Copy this one-time setup value for the registration form.
printf '%s\n' "$AUTHLUME_ENROLLMENT_CODE"
go run ./examples/webauthn -cert "$certdir/cert.pem" -key "$certdir/key.pem"
```

Trust the demo certificate locally and open <https://localhost:8445/>. Use the hostname exactly as shown. With username `demo`, your password and the value of `AUTHLUME_ENROLLMENT_CODE`, choose **Register first key** and complete the browser prompt. Registration leaves you signed out. Enter the username and password again, choose **Sign in** and use the registered key. Success opens `/protected`.

To try passkey sign-in without a username:

1. Within five minutes of signing in, return to <https://localhost:8445/> and choose **Add a passkey**. Use a different authenticator or passkey provider from the first key, because the browser excludes an authenticator that is already registered. The authenticator must verify you with a PIN or biometric check.
2. Choose **Sign out**.
3. Choose **Sign in with a passkey** and pick the new passkey. Success opens `/protected`.

Five begin requests per minute share one budget for the demo account, including unauthenticated passkey sign-in. Adding a passkey is authorized by the fresh session and does not consume the budget. Do not copy this limit to production; limit per account and per client instead. Pending transactions expire after five minutes. Each finish consumes one transaction. Restarting this in-memory demo discards credentials, transactions and sessions and reopens first enrollment. Use a new code on restart. A production account needs durable enrollment state, even when its last key is lost or revoked.

## Integrate with an application

See the [documentation](https://docs.i2bskn.com/authlume/guides/webauthn/).
