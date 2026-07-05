# pqc: Post-Quantum Cryptography Toolkit

**Operational post-quantum cryptography: key management, encryption, signatures,
TLS inspection, and signed migration evidence.**

`pqc` helps teams turn a post-quantum cryptography migration plan into working
systems. It provides a command-line interface, Go library, and optional local
daemon for generating keys, rotating versions, encrypting data, signing
artifacts, inspecting TLS endpoints, and preserving evidence of migration work.

The toolkit is built for the practical work behind post-quantum cryptography
readiness: reducing "harvest now, decrypt later" risk, testing NIST-standard
algorithms, building crypto-agility into systems, and producing repeatable
records for engineering, vendor, and compliance reviews.

## What You Can Do

| Area | Capabilities |
| --- | --- |
| Key management | Generate, rotate, list, inspect, and export versioned `ML-KEM-768`, `ML-DSA-65`, and `ML-DSA-87` keys. |
| Data protection | Encrypt and decrypt envelopes with ML-KEM, HKDF-SHA-256, and AES-256-GCM; sign and verify artifacts with ML-DSA. |
| Stores and daemon | Use a plain local file store, a passphrase-encrypted age store, or the optional `pqcd` daemon for remote key operations. |
| TLS inspection | Inspect endpoints for TLS facts, hybrid post-quantum cryptography key exchange, certificate chain size, and certificate lifecycle risk. |
| Evidence | Emit metadata-only audit logs, signed Merkle checkpoints, transparency bundles, revocation manifests, inventory reports, and readiness scores. |
| Artifact profiles | Experiment with Merkle Tree Certificates, ML-DSA in X.509, Composite X.509, and FN-DSA behind isolated profile boundaries. |

## Quick Start

Install the command-line tool:

```sh
go install github.com/helsingin/pqc/cmd/pqc@latest
```

Create a key for encryption and a key for signing:

```sh
pqc keys create --type ml-kem-768 --id service-a
pqc keys create --type ml-dsa-65 --id signer-a
```

Encrypt, decrypt, sign, and verify:

```sh
pqc encrypt --key service-a < message.json > message.pqc
pqc decrypt < message.pqc > message.out

pqc sign --key signer-a artifact.tar > artifact.sig
pqc verify --key signer-a artifact.tar artifact.sig
```

Inspect a TLS endpoint and produce a readiness report:

```sh
pqc tls readiness cloudflare.com:443
pqc readiness scan --target cloudflare.com:443
```

Build from a local checkout:

```sh
make build
```

The binaries are written to:

```text
bin/pqc
bin/pqcd
```

## Common Workflows

### Prototype Post-Quantum Cryptography Key Operations

Use the library or command-line interface to create ML-KEM and ML-DSA keys,
rotate versions, encrypt and decrypt payloads, sign artifacts, and keep older
versions available for decrypt and verify operations during a migration.

### Run Inventory And Readiness Checks

Scan local key stores and TLS endpoints to produce repeatable reports for
migration planning, certificate lifecycle readiness, and operational risk
review.

```sh
pqc inventory scan --store ./dev-keys --target example.com:443
pqc readiness scan --store ./dev-keys --target example.com:443
```

### Produce Signed Evidence

Create metadata-only audit logs, sign Merkle checkpoints over those logs, and
build transparency bundles over key inventory, TLS endpoint facts, and optional
revocation manifests.

```sh
pqc audit checkpoint --audit ./audit.jsonl --sign-key audit-signer
pqc transparency checkpoint --sign-key org-root --target example.com:443
```

### Run A Local Key Service

Run `pqcd` when command-line users or test applications should call a local
service instead of opening the key store directly. The daemon supports bearer
tokens, HTTPS, mutual TLS, and authorization policy for test environments.

```sh
pqcd --addr 127.0.0.1:8080
pqc keys list --remote http://127.0.0.1:8080 --token "$PQC_API_TOKEN"
```

### Explore Certificate And Signature Profiles

Use artifact profiles to issue, inspect, estimate, and verify signed JSON
artifacts for post-quantum cryptography certificate and signature experiments.

```sh
pqc profiles list
pqc profiles show x509-ml-dsa
pqc issue --profile mtc --sign-key org-root --subject example.com --dns example.com
pqc verify-artifact artifact.json
```

## Documentation

The detailed reference material lives in `docs/`:

- [Command-Line Reference](docs/cli.md): key operations, stores, remote mode,
  audit checkpoints, transparency bundles, TLS inspection, readiness scoring,
  Merkle Tree Certificate utilities, and profile commands.
- [Artifact Profiles](docs/artifact-profiles.md): Merkle Tree Certificates,
  ML-DSA in X.509, Composite X.509, and FN-DSA profile versions, inputs,
  issue/verify flows, estimates, and smoke tests.
- [Daemon, HTTP Service, And Transport](docs/daemon-api.md): `pqcd` endpoints,
  bearer auth, HTTPS, mutual TLS, authorization policy, environment variables,
  and hybrid post-quantum cryptography transport boundaries.

## Security Boundaries

`pqc` is an early open source toolkit for migration design, integration testing,
and operational evidence. Treat the current stores and daemon as development
and private-environment building blocks unless you have reviewed and hardened
the full deployment path.

Important boundaries:

- The plain `file` store writes private key material to local JSON files with
  filesystem permissions only.
- The `age` store encrypts local key files with a passphrase, but passphrase
  handling still matters.
- Remote `decrypt` and `sign` send operation inputs to `pqcd`; this is by
  design because the daemon owns the private keys.
- TLS transport can negotiate hybrid post-quantum cryptography key exchange,
  but the X.509 certificates used for TLS authentication are classical
  certificates.
- Artifact profile documents are application-level signed JSON artifacts, not
  browser-trusted public web certificates.
- Audit logs intentionally exclude private keys, public key bytes, plaintext,
  ciphertext, signatures, shared secrets, and request bodies.
- Merkle Tree Certificate commands model log/checkpoint/proof mechanics for
  development and testing; they do not create browser-trusted public web
  certificates.
- Readiness scores are operational guidance based on observed facts, not a
  cryptographic proof that an endpoint or organization is quantum-safe.

For production-facing work, use this repository as a migration and integration
toolkit alongside hardened private-key custody, access control, incident
response, key management services, hardware security modules, cloud secret
stores, or platform secret managers.

## Project Status

The first supported primitives are:

- `ML-KEM-768` for envelope encryption.
- `ML-DSA-65` for signatures.
- `ML-DSA-87` for signatures.

The implementation uses Cloudflare CIRCL for post-quantum cryptography
primitives and the Go standard library for HKDF and AES-GCM.

Remote TLS behavior depends on the Go version used to build the binaries,
because hybrid post-quantum cryptography TLS group support is provided by the Go
standard library.

Run the test suite:

```sh
make test
```

## License

Apache-2.0. See [LICENSE](LICENSE).
