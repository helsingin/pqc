# Daemon, HTTP API, And Transport

`pqcd` is the optional daemon mode for centralized key operations. In remote
mode the CLI sends key operations to the daemon, and the daemon remains the only
process that opens the key store.

## Start The Daemon

Start the optional daemon:

```sh
pqcd --addr 127.0.0.1:8080
```

For a practical local encrypted setup:

```sh
export PQC_AGE_PASSPHRASE='use a real secret here'
export PQC_API_TOKEN='change-me'

pqcd \
  --addr 127.0.0.1:8080 \
  --store ./server-keys \
  --store-type age \
  --audit ./audit.jsonl
```

Then use the CLI as a remote client:

```sh
pqc keys list --remote http://127.0.0.1:8080 --token "$PQC_API_TOKEN"
```

## HTTPS

Run the daemon with HTTPS:

```sh
pqcd \
  --addr 127.0.0.1:8443 \
  --tls-cert ./server.crt \
  --tls-key ./server.key \
  --store-type age \
  --audit ./audit.jsonl
```

Generate a quick self-signed certificate for local testing:

```sh
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout server.key \
  -out server.crt \
  -days 30 \
  -subj '/CN=127.0.0.1' \
  -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost'
```

Then trust that certificate from the CLI:

```sh
pqc keys list --remote https://127.0.0.1:8443 --token "$PQC_API_TOKEN" --tls-ca ./server.crt
```

## Store Encryption

Use the age-encrypted store with the daemon:

```sh
PQC_AGE_PASSPHRASE='use a real secret here' pqcd --store-type age
```

## Bearer Auth

Require bearer-token auth:

```sh
PQC_API_TOKEN='change-me' pqcd --addr 127.0.0.1:8080
curl -H 'Authorization: Bearer change-me' http://127.0.0.1:8080/v1/keys
```

## Audit

Append daemon audit events:

```sh
pqcd --audit ./audit.jsonl
```

## TLS Flags

Daemon TLS flags:

- `--tls-cert FILE`: server certificate PEM.
- `--tls-key FILE`: server private key PEM.
- `--tls-client-ca FILE`: CA used to verify client certificates.
- `--tls-require-client-cert`: require mTLS client certificates.
- `--tls-pqc`: prefer TLS 1.3 hybrid post-quantum key exchange groups.

The CLI supports matching remote TLS flags:

- `--tls-ca FILE`: CA bundle for the HTTPS server.
- `--tls-server-name NAME`: override HTTPS server-name verification.
- `--tls-client-cert FILE`: client certificate for mTLS.
- `--tls-client-key FILE`: client private key for mTLS.
- `--tls-insecure-skip-verify`: testing only.
- `--tls-pqc`: prefer TLS 1.3 hybrid post-quantum key exchange groups.

## Client Certificate Authentication

Run the daemon with required client certificate authentication:

```sh
pqcd \
  --addr 127.0.0.1:8443 \
  --tls-cert ./server.crt \
  --tls-key ./server.key \
  --tls-client-ca ./client-ca.crt \
  --tls-require-client-cert
```

Connect with a client certificate:

```sh
pqc \
  keys list \
  --remote https://127.0.0.1:8443 \
  --tls-ca ./server-ca.crt \
  --tls-client-cert ./client.crt \
  --tls-client-key ./client.key
```

Client certificate flags can also be set with `PQC_TLS_CLIENT_CERT` and
`PQC_TLS_CLIENT_KEY`.

## Authorization Policy

Authorization policy:

```json
{
  "default_action": "deny",
  "rules": [
    {
      "identity": "cn:ops-reader",
      "allow": ["key.list", "key.get", "encrypt", "verify"]
    },
    {
      "identity": "cn:ops-admin",
      "allow": ["*"]
    }
  ]
}
```

Run the daemon with a policy:

```sh
pqcd --auth-policy ./auth-policy.json
```

Recognized operation names:

- `key.list`
- `key.create`
- `key.get`
- `key.rotate`
- `encrypt`
- `decrypt`
- `sign`
- `verify`

Recognized identity forms:

- `cn:NAME` from an mTLS client certificate common name.
- `dns:NAME`, `email:ADDR`, `uri:URI` from mTLS SANs.
- `x509-fingerprint:sha256:HEX` from an mTLS client certificate.
- `bearer` for a valid bearer token.

## Endpoints

- `GET /v1/keys`
- `POST /v1/keys`
- `GET /v1/keys/{id}`
- `POST /v1/keys/{id}/rotate`
- `POST /v1/encrypt`
- `POST /v1/decrypt`
- `POST /v1/sign`
- `POST /v1/verify`

Example key creation:

```sh
curl -s http://127.0.0.1:8080/v1/keys \
  -H 'content-type: application/json' \
  -d '{"id":"service-a","algorithm":"ml-kem-768"}'
```

JSON byte fields are base64 encoded by Go's `encoding/json`.

## Configuration

Common CLI and daemon configuration can be supplied through flags or
environment variables:

- `PQC_STORE_DIR`: default key store directory.
- `PQC_STORE_TYPE`: `file` or `age`.
- `PQC_AGE_PASSPHRASE`: passphrase for the age-backed local store.
- `PQC_AGE_PASSPHRASE_FILE`: file containing the age store passphrase.
- `PQC_REMOTE`: remote `pqcd` URL for CLI commands.
- `PQC_API_TOKEN`: bearer token for remote CLI or daemon auth.
- `PQC_AUDIT_LOG`: audit JSONL path for CLI or daemon audit events.
- `PQC_TLS_CA`: CA bundle for HTTPS remote verification.
- `PQC_TLS_SERVER_NAME`: override HTTPS server-name verification.
- `PQC_TLS_CLIENT_CERT`: client certificate for remote mTLS.
- `PQC_TLS_CLIENT_KEY`: client private key for remote mTLS.
- `PQC_TLS_INSECURE_SKIP_VERIFY`: skip HTTPS certificate verification for remote CLI testing.
- `PQC_TLS_CERT`: daemon TLS server certificate.
- `PQC_TLS_KEY`: daemon TLS server private key.
- `PQC_TLS_CLIENT_CA`: daemon client-certificate CA bundle.
- `PQC_TLS_REQUIRE_CLIENT_CERT`: require daemon mTLS client certificates.
- `PQC_TLS_PQC`: prefer TLS 1.3 hybrid post-quantum key exchange groups.
- `PQC_AUTH_POLICY`: daemon authorization policy file.

Command-line flags take precedence where both forms are supported. Prefer
environment variables or files for secrets; avoid putting passphrases and bearer
tokens in shell history.

## PQC Transport

When `pqcd` is started with `--tls-cert` and `--tls-key`, it serves HTTPS with
TLS 1.3. By default, both `pqcd` and remote CLI commands prefer Go's
hybrid post-quantum TLS key exchange groups, including `X25519MLKEM768`,
`SecP256r1MLKEM768`, and `SecP384r1MLKEM1024`.

That means the client and server can negotiate a hybrid classical/PQC key
exchange for the transport channel. This protects the session key agreement
with ML-KEM while retaining a classical component.

Important boundary: TLS server and client certificates are normal X.509. This
is hybrid PQC key exchange, not PQC-signed X.509 certificate authentication.
The project does not implement a custom application-level PQC certificate or
per-request ML-DSA authentication layer.

Remote `decrypt` and `sign` still send operation inputs to the daemon over TLS
because the daemon owns the private keys by design.
