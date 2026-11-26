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

By default, Authlume checks the server's current 30-second step and the immediately preceding step. The matched step must be newer than the last one consumed for that enrollment. If a device clock is ahead but still in the same step, its code can succeed. If the device already shows the next step, the server will first check that step when it begins. Keep the device and server clocks synchronized. To accept only the current step, create the verifier with `totp.New(store, nil, totp.WithCurrentStepOnly())`. A code entered near the end of its step then fails once the next step begins, and a device whose clock is slow enough to still show the preceding step always fails. The sample runs with the default. It holds replay state in one process and excludes the startup step and earlier steps after each restart.

## Integrate with an application

See the [documentation](https://docs.i2bskn.com/authlume/guides/totp/).
