# CLI Reference

The root README gives the publishing overview. This file keeps the detailed CLI
flows for local stores, remote stores, audit checkpoints, transparency bundles,
TLS readiness, MTC log modeling, and MTC treehead caches.

The CLI command groups are:

- `keys`: create, rotate, list, show, and export public keys.
- `encrypt` / `decrypt`: ML-KEM envelope encryption.
- `sign` / `verify`: ML-DSA signatures.
- `audit`: tamper-evident Merkle checkpoints for JSONL audit logs.
- `transparency`: signed inventory checkpoints.
- `inventory`: crypto-agility inventory reports for stores and TLS endpoints.
- `tls`: TLS/PQC readiness inspection.
- `mtc`: experimental Merkle Tree Certificate log/proof simulator.
- `profiles`: PQ certificate/signature artifact profile discovery, inspection, and sizing.
- `issue` / `verify-artifact`: issue and verify signed artifact profile documents.

Key-manager commands can operate locally against a store or remotely through
`pqcd`. In remote mode only the daemon opens the key store.

Commands that read keys accept manager access flags like `--store`, `--remote`,
`--token`, and remote TLS options. Operational key/encrypt/decrypt/sign/verify
commands also accept `--audit-log`; checkpoint and inventory commands do not
write audit events.

## Key Operations

Create keys:

```sh
pqc keys create --type ml-kem-768 --id service-a
pqc keys create --type ml-dsa-65 --id signer-a
```

Encrypt and decrypt:

```sh
pqc encrypt --key service-a < message.json > message.pqc
pqc decrypt < message.pqc > message.out
```

Sign and verify:

```sh
pqc sign --key signer-a artifact.tar > artifact.sig
pqc verify --key signer-a artifact.tar artifact.sig
```

Rotate a key:

```sh
pqc keys rotate --id service-a
```

Existing envelopes and signatures remain tied to their original key version.

Use a custom store directory:

```sh
pqc keys list --store ./dev-keys
```

## Age Store

Use the age-encrypted file store:

```sh
export PQC_AGE_PASSPHRASE='use a real secret here'
pqc keys create --store-type age --type ml-kem-768 --id service-a
pqc encrypt --store-type age --key service-a < message.json > message.pqc
pqc decrypt --store-type age < message.pqc
```

Or read the passphrase from a file:

```sh
pqc keys list --store-type age --age-passphrase-file ./pqc.pass
```

## Audit Events

Append metadata-only audit events:

```sh
pqc keys create --audit-log ./audit.jsonl --type ml-kem-768 --id service-a
```

## Remote Mode

Use a remote daemon:

```sh
pqc keys list --remote http://127.0.0.1:8080 --token change-me
pqc keys create --remote http://127.0.0.1:8080 --token change-me --type ml-kem-768 --id service-a
pqc encrypt --remote http://127.0.0.1:8080 --token change-me --key service-a < message.json > message.pqc
pqc decrypt --remote http://127.0.0.1:8080 --token change-me < message.pqc > message.out
pqc sign --remote http://127.0.0.1:8080 --token change-me --key signer-a artifact.tar > artifact.sig
pqc verify --remote http://127.0.0.1:8080 --token change-me --key signer-a artifact.tar artifact.sig
```

Use a remote daemon over HTTPS:

```sh
pqc \
  keys list \
  --remote https://127.0.0.1:8443 \
  --token change-me \
  --tls-ca ./server-ca.pem
```

For local testing only, certificate verification can be disabled:

```sh
pqc keys list --remote https://127.0.0.1:8443 --token change-me --tls-insecure-skip-verify
```

## Audit Checkpoints

Create a signed Merkle checkpoint for audit events:

```sh
pqc keys create --type ml-dsa-65 --id audit-signer
pqc audit checkpoint --audit ./audit.jsonl --sign-key audit-signer > audit-checkpoint.json
pqc audit verify --audit ./audit.jsonl --checkpoint audit-checkpoint.json
```

## Transparency Bundles

Create a signed transparency bundle over the current key inventory:

```sh
pqc keys create --type ml-dsa-65 --id org-root
pqc keys create --type ml-kem-768 --id service-a
pqc transparency revoke --key service-a --reason key-compromise --revocations ./revocations.json
pqc transparency checkpoint \
  --sign-key org-root \
  --include-revocations \
  --revocations ./revocations.json \
  > transparency.json
pqc transparency verify transparency.json
```

Without revocations:

```sh
pqc transparency checkpoint --sign-key org-root > transparency.json
pqc transparency verify transparency.json
```

## Inventory, TLS Readiness, And Scoring

Scan local keys and TLS endpoints:

```sh
pqc inventory scan --store ./dev-keys --target example.com:443 > inventory.json
pqc tls inspect --json example.com:443
pqc tls readiness --json example.com:443
pqc inventory scan --store ./dev-keys --target example.com:443 --policy public-web-2029
pqc readiness scan --store ./dev-keys --target example.com:443 > readiness.json
```

The `public-web-2029` readiness policy models CA/B Forum Ballot SC-081v3's
2029 public-web target: 47-day maximum certificate validity and 10-day maximum
domain validation data reuse. Readiness output includes certificate validity
length, days until expiry, renewal-window risk, chain size, key/signature
algorithms, SAN/DCV automation risk, 47-day readiness, and recommended renewal
cadence. SAN/DCV risk is inferred from the visible DNS SAN count because TLS
does not expose the CA's actual domain validation reuse state.
`ready_for_47_day_certs` reports whether the observed leaf certificate is
verified, unexpired, and no longer than 47 days; renewal-window urgency is
reported separately.

`pqc readiness scan` wraps the inventory and TLS lifecycle facts in an
opinionated score from `0` to `100`, plus a `coverage` object that says whether
the score is based on targets only, a key store only, private/custom-CA targets,
or fuller coverage. The score includes category verdicts for `classical-only`,
`hybrid-kex-ready`, `pq-signature-experimental`, `webpki-mtc-candidate`,
`private-pki-pq-x509-candidate`, `automation-risk`, and `chain-size-risk`.

Use `--target-ca FILE` when scanning private TLS endpoints through inventory:

```sh
pqc inventory scan \
  --store ./dev-keys \
  --target internal.example.com:443 \
  --target-ca ./internal-ca.pem \
  --policy public-web-2029
```

## MTC Log And Proof Model

Run the experimental MTC log/proof flow:

```sh
pqc keys create --store ./mtc-keys --type ml-dsa-65 --id org-root
pqc keys public --store ./mtc-keys --id org-root > org-root.public.json

pqc mtc log init --log mtc-log.json
pqc mtc issue --log mtc-log.json --subject example.com --public-key org-root.public.json
pqc mtc revoke --log mtc-log.json --index 0 --reason key-compromise --revocations mtc-revocations.json
pqc mtc checkpoint --store ./mtc-keys --log mtc-log.json --sign-key org-root > mtc-checkpoint.json
pqc mtc prove --log mtc-log.json --leaf 0 > mtc-proof.json
pqc mtc verify --store ./mtc-keys --proof mtc-proof.json --checkpoint mtc-checkpoint.json
```

This creates a local append-only-style JSON log, hashes each issued subject into
a Merkle tree, signs the tree-head checkpoint with ML-DSA, produces inclusion
proofs, and verifies proofs against the signed checkpoint. It is an experimental
MTC model for development and testing; it is not a browser-trusted WebPKI
certificate format. `pqc mtc verify` requires a signed checkpoint; an unsigned
checkpoint is not accepted as a transparency proof.

`pqc mtc revoke` records a canonical revocation event for an MTC leaf index in
a revocation manifest. The manifest is separate from the MTC issuance log for
now; include it in transparency checkpoints with `--include-revocations` when
you want the revocation state committed into a signed transparency bundle.

## MTC Treehead Cache

Maintain a treehead cache for non-browser clients:

```sh
pqc mtc treeheads fetch --source https://mtc.example.test/treeheads.json --out ./treeheads
pqc mtc treeheads verify ./treeheads
pqc mtc treeheads export --format openssl-dir --cache ./treeheads --out ./openssl-treeheads
```

The source URL can serve a `pqc.mtc-treehead-cache.v1` document containing
signed checkpoints and signer public keys. For local experiments it can also
serve a single `pqc.mtc-checkpoint.v1` checkpoint if the signer key is supplied:

```sh
pqc mtc treeheads fetch \
  --source https://mtc.example.test/checkpoint.json \
  --public-key org-root.public.json \
  --log-id test-log \
  --out ./treeheads
```

The `openssl-dir` export is an experimental `/etc/ssl`-style directory layout
for clients that want cached treehead JSON and signer public keys on disk. It is
not an OpenSSL trust store and does not make OpenSSL validate MTCs by itself.

For artifact profile discovery, issue, verify, and smoke-test flows, see
[Artifact Profiles](artifact-profiles.md).
