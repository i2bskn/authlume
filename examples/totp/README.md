# Password and TOTP over HTTPS

This loopback example signs in one pre-enrolled user. With `-require-mfa`, submit the password and current authenticator code in the same form. The handler takes the subject from the successful password check, verifies and consumes a code for that subject, then issues a normal session. The redirect to `/protected` reads that session. Omit the flag to try the application's password-only policy.

## Run the example

Use Go 1.25 or later, Bash, OpenSSL, and a local authenticator app. Generate a localhost certificate and a fresh demo seed.

```bash
certdir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "$certdir/key.pem" -out "$certdir/cert.pem"
read -rs -p 'Demo password: ' AUTHLUME_PASSWORD
echo
export AUTHLUME_PASSWORD
export AUTHLUME_TOTP_SECRET=$(openssl rand 20 | base32)
```

Import the value of `AUTHLUME_TOTP_SECRET` into your authenticator using manual setup. Select time-based codes, SHA-1, six digits and a 30-second period. Keep the seed private. From the repository root, run

```bash
go run ./examples/totp -require-mfa -cert "$certdir/cert.pem" -key "$certdir/key.pem"
```

Open <https://127.0.0.1:8444/> with the temporary certificate trusted for this demo. Wait for the first new authenticator code after server startup, then sign in as `demo`. The form accepts six digits as `012345` or `012 345` with one ordinary space between the groups. Keep any leading zero. The server allows five submissions per minute across this single demo account.

Authlume checks the server's current 30-second step and the immediately preceding step. The matched step must be newer than the last one consumed for that enrollment. If a device clock is ahead but still in the same step, its code can succeed. If the device already shows the next step, the server will first check that step when it begins. Keep the device and server clocks synchronized. The sample holds replay state in one process and excludes the startup step and earlier steps after each restart.

## Migrating an existing enrollment

Authlume requires at least 20 decoded bytes per TOTP secret. A legacy 16-character Base32 secret decodes to 10 bytes (80 bits), so verification returns `totp.ErrRecord` for that enrollment. Before switching the account to Authlume, use the application's verified enrollment or recovery flow to register and confirm a fresh random secret of at least 20 bytes with the user's authenticator.

## Use TOTP with another primary method

Import `github.com/i2bskn/authlume/totp` and implement its `Store` for your own verified application subjects. For multiple instances, share durable replay state. An implementation can consume a code with one conditional database update matching the subject and active enrollment ID and requiring a null or smaller last-used time step. Exactly one changed row means success. Protect seeds at rest, return a stable snapshot from `Load`, and give each new enrollment a fresh cryptographically random secret and unique activation ID. The application owns enrollment confirmation, recovery, credential changes and rate limits that span login attempts.

After primary authentication, apply the application's MFA policy. If TOTP is required, pass the verified subject and submitted code to `verifier.Verify(ctx, subject, code)`. Only a successful verification permits that policy path to call `sessions.Issue`. If session issuance fails, start a fresh login with a newer code. For a flow spanning multiple requests, retain the verified subject and purpose in an expiring, browser-bound, single-use server-side login transaction. For OIDC, accepting upstream MFA assurance requires an explicit application policy over verified evidence. The presence of a claim alone leaves the additional factor pending.

WebAuthn second factors use a separate public-key ceremony. Username-less passkey sign-in also needs a distinct application setting, discoverable credentials and required user verification. Both flows are reserved for follow-up changes.
