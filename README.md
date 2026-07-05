# pqc: Post-Quantum Cryptography Toolkit

Post-quantum cryptography readiness is how organizations protect sensitive data
from "harvest now, decrypt later" attacks: encrypted traffic and stored secrets
captured today that could be decrypted later once quantum computers can break RSA
and ECC.

`pqc` turns that readiness work into concrete evidence. It helps teams identify
cryptographic assets, test post-quantum cryptography encryption and signing
workflows, inspect TLS endpoints, track key rotation, and produce signed records
of what was checked.

Use it to move from a high-level post-quantum cryptography strategy to
repeatable migration tests, readiness reports, audit records, and
crypto-agility exercises based on NIST-standard post-quantum cryptography
algorithms such as ML-KEM and ML-DSA.

## At A Glance

`pqc` is for post-quantum cryptography readiness work that needs to be tested,
reported, and repeated:

- Inventory cryptographic assets and local key stores.
- Test ML-KEM envelope encryption and ML-DSA signing workflows.
- Inspect TLS endpoints for hybrid post-quantum cryptography key exchange and
  certificate lifecycle risk.
- Generate readiness reports for migration planning, vendor reviews, and
  compliance evidence.
- Create signed audit and transparency checkpoints over key inventory and
  endpoint facts.

The first supported primitives are:

- `ML-KEM-768` for envelope encryption.
- `ML-DSA-65` for signatures.
- `ML-DSA-87` for signatures.

The implementation uses Cloudflare CIRCL for post-quantum cryptography
primitives and the Go standard library for HKDF and AES-GCM.

The project is designed for teams that need to prototype crypto-agility and
post-quantum cryptography migration workflows before committing to a production
KMS, HSM, Vault, cloud secret manager, or public key infrastructure platform.

## Quick Start

Fastest path from install to useful output:

```sh
go install github.com/helsingin/pqc/cmd/pqc@latest
pqc tls readiness cloudflare.com:443
pqc readiness scan --target cloudflare.com:443
```

Example output from `pqc tls readiness cloudflare.com:443` on June 29, 2026:

```text
target: cloudflare.com:443
policy: public-web-2029
ready_for_47_day_certs: false
certificate_validity_days: 91
days_until_expiry: 41
renewal_window_risk: low
recommended_renewal_cadence_days: 30
recommended_renewal_lead_time_days: 17
san_count: 5
san_dcv_reuse_risk: low
certificate_chain_bytes: 2591
certificate_count: 3
leaf_signature_algorithm: ECDSA-SHA256
leaf_public_key_algorithm: ECDSA
hybrid_pqc_key_exchange: true
verified: true
verification_mode: system
warning: certificate_validity: leaf certificate validity exceeds the public-web-2029 target
```

The companion `pqc readiness scan --target cloudflare.com:443` command emits a
JSON readiness report. For the same scan it produced:

```json
{
  "score": 75,
  "level": "watch",
  "summary": "watch readiness with risks: automation-risk"
}
```

Live endpoint results will change as certificates rotate and TLS deployments
change.

Build the CLI and daemon:

```sh
make build
```

The binaries are written to:

```text
bin/pqc
bin/pqcd
```

Create a KEM key and a signing key:

```sh
bin/pqc keys create --type ml-kem-768 --id service-a
bin/pqc keys create --type ml-dsa-65 --id signer-a
```

Encrypt, decrypt, sign, and verify:

```sh
bin/pqc encrypt --key service-a < message.json > message.pqc
bin/pqc decrypt < message.pqc > message.out

bin/pqc sign --key signer-a artifact.tar > artifact.sig
bin/pqc verify --key signer-a artifact.tar artifact.sig
```

Run the Go test suite:

```sh
make test
```

Install from the local checkout:

```sh
go install ./cmd/pqc
go install ./cmd/pqcd
```

## Documentation

The README is the publishing overview. Detailed usage lives in `docs/`:

- [CLI Reference](docs/cli.md): local and remote key operations, age store,
  audit checkpoints, transparency bundles, TLS readiness, readiness scoring,
  Merkle Tree Certificate log/proof modeling, and treehead cache commands.
- [Artifact Profiles](docs/artifact-profiles.md): `mtc`, `x509-ml-dsa`,
  `composite-x509`, and `fndsa` profile versions, inputs, issue/verify flows,
  estimates, and smoke tests.
- [Daemon, HTTP API, And Transport](docs/daemon-api.md): `pqcd`, HTTP
  endpoints, bearer auth, HTTPS, mTLS, authorization policy, environment
  variables, and hybrid post-quantum cryptography TLS transport boundaries.

## What It Does

`pqc` handles common post-quantum cryptography key-management and migration
workflows:

- Generates versioned `ML-KEM-768`, `ML-DSA-65`, and `ML-DSA-87` keys.
- Encrypts and decrypts envelopes using ML-KEM, HKDF-SHA-256, and AES-256-GCM.
- Signs and verifies payloads with ML-DSA.
- Rotates keys while preserving old decrypt and verify versions.
- Stores key metadata and public fingerprints for inventory and transparency.
- Supports a plain local file store and a passphrase-encrypted age file store.
- Runs as a local CLI or as a remote CLI talking to `pqcd`.
- Serves an optional HTTP API for centralized key operations.
- Supports bearer-token auth, HTTPS, mTLS, and mTLS identity authorization
  policy for the daemon.
- Prefers TLS 1.3 hybrid post-quantum cryptography key exchange groups for
  remote CLI transport.
- Emits metadata-only JSONL audit events.
- Builds signed Merkle checkpoints for audit logs.
- Builds signed transparency bundles over key inventory, TLS endpoint facts, and
  optional revocation manifests.
- Maintains experimental Merkle Tree Certificate log, checkpoint, proof,
  revocation, and treehead cache utilities.
- Scans TLS endpoints for post-quantum cryptography or hybrid key exchange,
  certificate chain facts, and public-web 2029 lifecycle readiness.
- Produces an opinionated readiness score across local keys and TLS targets.
- Isolates post-quantum cryptography certificate and signature approaches
  behind artifact profiles:
  `mtc`, `x509-ml-dsa`, `composite-x509`, and `fndsa`.

## Post-Quantum Cryptography Context

The project currently focuses on three practical migration tracks:

- Operational key management: generate, rotate, store, encrypt, decrypt, sign,
  verify, and audit post-quantum cryptography key usage.
- TLS and certificate readiness: inspect current TLS endpoints, detect hybrid
  post-quantum cryptography key exchange, measure chain size, and model CA/B
  Forum 47-day certificate lifecycle pressure.
- Certificate/signature experiments: keep Merkle Tree Certificate, ML-DSA in
  X.509, Composite X.509, and FN-DSA logic behind artifact profile boundaries
  so draft updates stay localized.

It intentionally separates hybrid post-quantum cryptography transport from
certificates signed with post-quantum cryptography algorithms. `pqcd` can
negotiate hybrid post-quantum cryptography TLS key exchange, but its server and
client certificates are normal X.509 certificates.

## Typical Pattern

```text
local CLI
   |
   | local store mode
   v
 file or age key store

remote CLI
   |
   | HTTP or HTTPS JSON API
   v
 pqcd daemon
   |
   +-- file or age key store
   +-- audit JSONL
   +-- optional mTLS identity policy
```

For migration and readiness work:

```text
pqc inventory/readiness scan
   |
   +-- local or remote key inventory
   +-- TLS endpoint inspection
   +-- public-web-2029 lifecycle policy
   +-- signed transparency checkpoint
   +-- optional revocation manifest
```

For certificate/signature experiments:

```text
pqc profiles
   |
   +-- mtc
   +-- x509-ml-dsa
   +-- composite-x509
   +-- fndsa
```

Each profile owns its draft-specific inputs, metadata, estimates, and
verification behavior.

## Status

This is an early open source scaffold. The default local file store writes
private key material to JSON files with `0600` permissions under
`$PQC_STORE_DIR` or `~/.pqc/keys`. The age-backed file store encrypts key files
with passphrase-based age encryption. Production deployments should still prefer
careful secret management, Vault-backed stores, HSM-backed stores, cloud secret
stores, or platform secret managers.

## CLI

The CLI command groups are:

- `keys`: create, rotate, list, show, and export public keys.
- `encrypt` / `decrypt`: ML-KEM envelope encryption.
- `sign` / `verify`: ML-DSA signatures.
- `audit`: tamper-evident Merkle checkpoints for JSONL audit logs.
- `transparency`: signed inventory checkpoints and revocation manifests.
- `inventory`: crypto-agility inventory reports for stores and TLS endpoints.
- `tls`: TLS and post-quantum cryptography readiness inspection.
- `readiness`: opinionated readiness scoring over stores and TLS targets.
- `mtc`: experimental Merkle Tree Certificate log/proof simulator.
- `profiles`: post-quantum cryptography certificate and signature artifact
  profile discovery, inspection, and sizing.
- `issue` / `verify-artifact`: issue and verify signed artifact profile
  documents.

Key-manager commands can operate locally against a store or remotely through
`pqcd`. In remote mode only the daemon opens the key store. Commands that read
keys accept manager access flags like `--store`, `--remote`, `--token`, and
remote TLS options.

Create keys:

```sh
pqc keys create --type ml-kem-768 --id service-a
pqc keys create --type ml-dsa-65 --id signer-a
```

Run with a remote daemon:

```sh
pqc keys list --remote http://127.0.0.1:8080 --token change-me
pqc encrypt --remote http://127.0.0.1:8080 --token change-me --key service-a < message.json > message.pqc
```

Inspect TLS readiness and generate a combined readiness score:

```sh
pqc tls readiness --json example.com:443
pqc readiness scan --store ./dev-keys --target example.com:443 > readiness.json
```

Run the experimental Merkle Tree Certificate log/proof flow:

```sh
pqc mtc log init --log mtc-log.json
pqc mtc issue --log mtc-log.json --subject example.com --public-key org-root.public.json
pqc mtc checkpoint --store ./mtc-keys --log mtc-log.json --sign-key org-root > mtc-checkpoint.json
pqc mtc prove --log mtc-log.json --leaf 0 > mtc-proof.json
pqc mtc verify --store ./mtc-keys --proof mtc-proof.json --checkpoint mtc-checkpoint.json
```

Detailed command flows are in [CLI Reference](docs/cli.md). Artifact profile
versions and issue/verify smoke tests are in
[Artifact Profiles](docs/artifact-profiles.md).

## What You Can Build With It

### Post-Quantum Cryptography Key-Management Prototype

Use the core library or command-line interface to generate ML-KEM and ML-DSA
keys, rotate versions, encrypt and decrypt envelopes, sign artifacts, and verify
old versions while a service migration is underway.

### Crypto-Agility Inventory Job

Run `pqc inventory scan` and `pqc readiness scan` against local key stores and
TLS endpoints to produce repeatable reports for migration planning, public-web
certificate lifecycle readiness, and chain-size risk.

### Signed Transparency Bundle

Build signed transparency checkpoints over key inventory, TLS target state, and
optional revocation manifests. This gives teams a portable record of what keys
and public fingerprints existed at a point in time.

### Merkle Tree Certificate Experiment Harness

Use the experimental Merkle Tree Certificate log, checkpoint, proof, revocation,
and treehead cache commands to model Merkle Tree Certificate workflows without
depending on browser public key infrastructure.

### Post-Quantum Cryptography Certificate Profile Lab

Use artifact profiles to issue and verify signed JSON artifacts for Merkle Tree
Certificate, ML-DSA-in-X.509, Composite X.509, and FN-DSA experiments. The
profile boundary keeps draft-specific behavior isolated.

### Remote Key Service

Run `pqcd` as a local or private-network daemon so CLI users do not open the key
store directly. Add bearer-token auth, HTTPS, mTLS, and mTLS authorization
policy as needed for the test environment.

## What an Integration Needs

An integration normally chooses:

- Store mode: local `file`, local `age`, or remote `pqcd`.
- Key IDs and rotation policy for KEM and signing keys.
- Audit location if operation metadata should be checkpointed later.
- TLS trust configuration for remote `pqcd` access.
- Whether private operations are local-only or sent to a daemon.
- Whether inventory and readiness reports are target-only, store-only, or both.
- Which artifact profiles are allowed in the project, especially for draft
  formats.
- Where transparency bundles, revocation manifests, and Merkle Tree Certificate
  treehead caches are stored.

For production-facing work, treat this repository as a migration and integration
toolkit rather than a replacement for a hardened KMS or HSM deployment.

## What It Is Not

`pqc` is not:

- A production HSM, Vault, or cloud KMS replacement.
- A browser-trusted WebPKI CA.
- A full ACME CA or certificate issuance authority.
- An X.509 implementation signed with post-quantum cryptography algorithms for
  the public WebPKI.
- An implementation of browser Merkle Tree Certificate validation.
- An OpenSSL trust store generator.
- A guarantee that observed TLS endpoints are quantum-safe.
- A substitute for private-key custody, access-control, and incident-response
  design.

The project does implement useful pieces for experimentation: key operations,
hybrid post-quantum cryptography transport preference, signed artifacts,
transparency checkpoints, revocation manifests, Merkle Tree Certificate
log/proof modeling, treehead cache utilities, TLS readiness facts, and
opinionated readiness scoring.

## Library

```go
store, err := file.New("./keys")
if err != nil {
    panic(err)
}
manager := pqc.NewManager(store)

_, err = manager.Generate(context.Background(), pqc.GenerateRequest{
    ID:        "service-a",
    Algorithm: pqc.AlgorithmMLKEM768,
})
if err != nil {
    panic(err)
}

env, err := manager.Encrypt(context.Background(), "service-a", []byte("hello"), pqc.EncryptOptions{})
if err != nil {
    panic(err)
}

plaintext, err := manager.Decrypt(context.Background(), env, pqc.EncryptOptions{})
if err != nil {
    panic(err)
}
_ = plaintext
```

## HTTP API And Remote Mode

Start the optional daemon:

```sh
pqcd --addr 127.0.0.1:8080
```

Use it from the CLI:

```sh
pqc keys list --remote http://127.0.0.1:8080 --token "$PQC_API_TOKEN"
```

The daemon supports bearer-token auth, HTTPS, mTLS client certificates, and
mTLS identity authorization policy. Its HTTP API exposes key inventory,
create/rotate, encrypt/decrypt, and sign/verify operations.

Full daemon setup, endpoint list, TLS flags, authorization policy format,
environment variables, and transport boundaries are documented in
[Daemon, HTTP API, And Transport](docs/daemon-api.md).

## Audit And Transparency

CLI operation audit is opt-in through `--audit-log FILE` or `PQC_AUDIT_LOG`.
Daemon audit is opt-in through `pqcd --audit FILE` or `PQC_AUDIT_LOG`. Events
are JSONL records with operation metadata only:

```json
{
  "time": "2026-06-28T20:00:00Z",
  "operation": "key.generate",
  "key_id": "service-a",
  "algorithm": "ML-KEM-768",
  "key_version": 1,
  "success": true
}
```

Audit records intentionally exclude private keys, public key bytes, plaintext,
ciphertext, signatures, shared secrets, and request bodies.

When using `--remote`, audit belongs on `pqcd`; remote CLI commands reject
`--audit-log`.

Audit checkpoints make a JSONL audit file tamper-evident. The checkpoint stores
the SHA-256 Merkle root, line count, audit digest, and an ML-DSA signature from
the configured signing key:

```sh
pqc audit checkpoint --audit ./audit.jsonl --sign-key audit-signer > audit-checkpoint.json
pqc audit verify --audit ./audit.jsonl --checkpoint audit-checkpoint.json
```

Transparency bundles checkpoint the current key inventory and optional TLS
targets. The bundle contains the normalized inventory and a signed Merkle root:

```sh
pqc transparency checkpoint --sign-key org-root --target example.com:443 > transparency.json
pqc transparency verify transparency.json
```

Revocation events are recorded in a JSON revocation manifest and can be folded
into the transparency bundle:

```sh
pqc transparency revoke --key service-a --reason key-compromise --revocations ./revocations.json
pqc transparency checkpoint \
  --sign-key org-root \
  --target example.com:443 \
  --include-revocations \
  --revocations ./revocations.json \
  > transparency.json
pqc transparency verify transparency.json
```

The checkpoint commits to `revocation_count`, `revocation_root`, and
`revocation_digest`. Verification recomputes those fields from the embedded
manifest, so removing or editing a revocation event breaks the signed bundle.

## Store Encryption

Two local stores are available:

- `file`: plain JSON keysets protected only by filesystem permissions.
- `age`: binary `.age` keysets encrypted with passphrase-based age encryption.

`age` is a small modern file-encryption tool and Go library. This project uses
its scrypt passphrase mode for the first encrypted local backend, which avoids
inventing a custom password-based encryption format.

Age store filenames are derived from SHA-256 of the key ID, so directory
listings do not directly reveal key names.

Prefer `PQC_AGE_PASSPHRASE` or `--age-passphrase-file` over
`--age-passphrase`, because command-line arguments can be visible in shell
history and process listings.

## Envelope Design

`ML-KEM-768` is used as a KEM, not as direct encryption:

1. Encapsulate with the recipient public key.
2. Derive a 256-bit AEAD key with `HKDF-SHA256`.
3. Encrypt the payload with `AES-256-GCM`.
4. Store metadata, key version, salt, KEM ciphertext, nonce, and AEAD ciphertext
   in a JSON envelope.

## Main Files

- `manager.go`: core key generation, rotation, encryption, decryption, signing,
  verification, and public-key export.
- `envelope.go`: ML-KEM/HKDF/AES-GCM envelope structure.
- `algorithm.go`: supported algorithm names and aliases.
- `checkpoint.go`: audit checkpoints, inventory reports, transparency bundles,
  and Merkle helpers.
- `revocation.go`: revocation manifest model and validation.
- `readiness.go`: opinionated readiness scoring over inventory and TLS facts.
- `tlsinspect.go`: TLS endpoint inspection and hybrid post-quantum cryptography
  key exchange detection.
- `tlsreadiness.go`: public-web 2029 certificate lifecycle readiness policy.
- `mtclog.go`: experimental Merkle Tree Certificate log, checkpoint, proof, and
  verification model.
- `mtctreeheads.go`: experimental Merkle Tree Certificate treehead cache
  parsing, verification, and export model.
- `profile/`: stable artifact profile plugin interfaces and shared artifact
  signing helpers.
- `profiles/`: built-in artifact profiles for Merkle Tree Certificate, ML-DSA
  in X.509, Composite X.509, and FN-DSA.
- `store/file/`: plain local JSON key store.
- `store/agefile/`: passphrase-encrypted age local key store.
- `cmd/pqc/`: CLI commands.
- `cmd/pqcd/`: optional HTTP API daemon.

## Verification

```sh
make test
make build
```

Build outputs:

```text
bin/pqc
bin/pqcd
```

Additional useful checks before publishing changes:

```sh
gofmt -w .
git diff --check
go test ./...
make build
```

## Tested Environments

The codebase is currently developed and tested with the Go toolchain available
in this repository's local environment. The project uses Go's standard TLS
stack for hybrid post-quantum cryptography key exchange groups and Cloudflare
CIRCL for ML-KEM and ML-DSA primitives.

Remote TLS behavior depends on the Go version used to build the binaries,
because hybrid post-quantum cryptography TLS group support is provided by the Go
standard library.

## Security

This is an early open source scaffold and should be treated as a migration and
integration toolkit.

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
  browser-trusted certificates.
- Audit logs intentionally exclude private keys, public key bytes, plaintext,
  ciphertext, signatures, shared secrets, and request bodies.
- Merkle Tree Certificate commands model log/checkpoint/proof mechanics for
  development and testing; they do not create browser-trusted WebPKI
  certificates.
- Readiness scores are operational guidance based on observed facts, not a
  cryptographic proof that an endpoint or organization is quantum-safe.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Summary

`pqc` is a practical post-quantum cryptography key-management and migration
sandbox. It combines ML-KEM and ML-DSA key operations, local and remote
key-store modes, audit and transparency checkpoints, TLS lifecycle readiness,
Merkle Tree Certificate modeling, and isolated post-quantum cryptography
certificate and signature artifact profiles. The goal is to make
post-quantum cryptography migration workflows concrete and testable while
keeping experimental certificate formats behind clear boundaries.
