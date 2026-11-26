# SLH-DSA artifact and checkpoint signing

`pqc` supports two explicit SHA-2 parameter sets from
[NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), implemented by
[Cloudflare CIRCL v1.6.5](https://github.com/cloudflare/circl/releases/tag/v1.6.5).
They provide a hash-based signature alternative to lattice-based ML-DSA.
They do not provide encryption or a guarantee against future cryptanalysis.

| Algorithm | NIST category | Public key | Private key | Signature |
|---|---:|---:|---:|---:|
| SLH-DSA-SHA2-192s | 3 | 48 bytes | 96 bytes | 16,224 bytes |
| SLH-DSA-SHA2-256s | 5 | 64 bytes | 128 bytes | 29,792 bytes |

The `s` variants favor smaller signatures over signing speed. This makes them
useful for release manifests, migration evidence and occasional signed
checkpoints. ML-DSA remains available for frequent signing. No existing key
or deployment automatically changes algorithm.

## Use

Available since v0.2.0. Build from a checkout with `make build`, or install with
`go install github.com/helsingin/pqc/cmd/pqc@v0.2.0`. For example, from a checkout:

```sh
bin/pqc keys create --store ./slh-keys --type slh-dsa-sha2-192s --id evidence-root
bin/pqc sign --store ./slh-keys --key evidence-root --context release.v1 manifest.json > manifest.sig
bin/pqc verify --store ./slh-keys manifest.json manifest.sig
bin/pqc transparency checkpoint --store ./slh-keys --sign-key evidence-root > transparency.json
bin/pqc transparency verify --store ./slh-keys transparency.json
```

Use `slh-dsa-sha2-256s` for the Category 5 signature option. The Go constants are
`pqc.AlgorithmSLHDSASHA2192s` and `pqc.AlgorithmSLHDSASHA2256s`.
Both work through `Manager.Generate`, `Sign`, `Verify`, `ExportPublic`,
`Rotate`, `VerifyWithPublicKey`, the file and age-encrypted stores, and `pqcd`.
Existing `audit checkpoint`, `transparency checkpoint`, `mtc checkpoint` and
`issue` commands accept these signing keys.

This is pure SLH-DSA: the complete message and optional context are passed to
the FIPS 205 message interface. The context limit is 255 bytes. Signing is
deterministic by default; `--randomized` or `SignOptions.Randomized` uses fresh
entropy. A failed entropy read fails key generation or randomized signing.
`WithRand` supplies the entropy reader for these SLH-DSA operations.

## Compatibility and boundaries

- Signature JSON remains `pqc.signature.v1`, containing one explicitly named
  algorithm and one signature. Existing ML-DSA signatures and ML-KEM envelopes
  remain readable in both directions with the pre-change binary.
- Older binaries reject SLH-DSA as an unsupported algorithm. Upgrade every
  verifier that must consume SLH-DSA evidence. Keep SLH-DSA keys in a separate
  store while older clients still need to list shared key stores.
- Rotation creates a new version of the same algorithm. To migrate algorithms,
  create a new key ID and distribute its verification key through an
  authenticated trust process. A supported algorithm name alone is not a trust
  decision; consumers must enforce their accepted keys and algorithms.
- This milestone does not add dual signatures, HashSLH-DSA/prehash mode,
  SLH-DSA X.509/TLS encoding or SLH-DSA PKCS#11 custody. A profile artifact is
  a signed JSON document, not a browser-trusted certificate.
- Audit, transparency and MTC hashes remain SHA-256. Selecting a Category 3 or
  Category 5 signer does not establish that security category for the entire
  checkpoint/proof system. The existing hash construction must be evaluated
  separately before making an end-to-end strength claim.
- MBGW's Category 3 profile remains ML-KEM-768 / ML-DSA-65; Category 5 remains
  ML-KEM-1024 / ML-DSA-87. This work changes neither those profiles nor deployed
  gateways. `pqc` itself still implements only ML-KEM-768 envelope encryption.

## Validation

Tests cover deterministic and randomized external pure-mode ACVP fixtures,
both stores, rotation and historical verification, wrong messages/keys/contexts,
malformed key/signature lengths, unsupported algorithms, CLI workflows and
HTTP handlers. Fixture provenance is recorded in
[testdata](../internal/core/testdata/README.md). These tests are not NIST module
validation or an independent cryptographic audit.

Reproduce the checks:

```sh
make test build
go test -race ./...
go vet ./...
scripts/test-backward-compat.sh /path/to/previous/pqc
scripts/test-keyman-interop.sh
```

All of these checks passed for the milestone on 26 November 2026. The full
local test suite and binary builds used Go 1.26.4 on macOS/arm64; the race
detector and `go vet` reported no issues.

The compatibility check uses temporary generated keys. The initial run compared
this implementation with a binary built from commit `35ef725` (CIRCL v1.6.4).
It checks both directions for ML-DSA-65, ML-DSA-87 and ML-KEM-768, and explicit
old-client rejection of both SLH-DSA parameter sets.

The Keyman script mounts sibling checkouts read-only and runs a disposable
container from `keyman-softhsm:latest`, using the updated local `pqc` through a
temporary module replacement. It does not mount or modify fleet tokens. Set
`KEYMAN_DIR`, `CONTAINER_RUNTIME` or `KEYMAN_INTEROP_IMAGE` to override defaults.
The image can be built from Keyman's `build/Dockerfile.softhsm` (SoftHSM with
ML-DSA enabled). The Keyman test covers both ML-DSA-65 and ML-DSA-87: token-created
keys, token signatures over nonempty and empty messages, verification by `pqc`,
and rejection of changed messages, wrong contexts and truncated signatures.

The 26 November 2026 run passed on Linux/arm64, Go 1.26.11, CIRCL v1.6.5,
using image digest prefix `7fa30da3fb5c`. This demonstrates SoftHSM-to-CIRCL
interoperability, not SLH-DSA token support or certification of a hardware HSM.

## Measured costs

Measured on 26 November 2026, Apple M4 Max, macOS/arm64, Go 1.26.4 and CIRCL
v1.6.5. Each operation used a 1 KiB message, deterministic signing, an in-memory
store and context `pqc.benchmark.v1`. Times are the medians of three runs of
five operations; they are a small local comparison, not a capacity estimate.
Key generation measures the primitive; signing and verification include the
manager. JSON serialization is excluded from operation timings.

| Algorithm | Key generation | Sign | Verify | Raw signature | JSON envelope in this run |
|---|---:|---:|---:|---:|---:|
| ML-DSA-65 | 0.185 ms | 0.199 ms | 0.138 ms | 3,309 B | 4,593 B |
| ML-DSA-87 | 0.220 ms | 0.533 ms | 0.181 ms | 4,627 B | 6,353 B |
| SLH-DSA-SHA2-192s | 22.155 ms | 233.113 ms | 0.204 ms | 16,224 B | 21,821 B |
| SLH-DSA-SHA2-256s | 14.857 ms | 216.117 ms | 0.293 ms | 29,792 B | 39,913 B |

Envelope size includes base64, context and metadata and varies with those
fields. Category alone does not determine speed: these parameter sets have
different tree structures. Reproduce with:

```sh
go test ./internal/core -run '^$' -bench BenchmarkSignatureProfiles -benchtime=5x -count=3
```
