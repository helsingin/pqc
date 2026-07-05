# Post-Quantum Cryptography Toolkit

![Editorial image of a secure operations environment with post-quantum cryptography infrastructure](docs/assets/pqc-hero.jpg)

`pqc` lets you:

- Manage post-quantum cryptography keys.
- Encrypt data with ML-KEM envelopes.
- Sign artifacts with ML-DSA.
- Inspect TLS endpoints for hybrid post-quantum cryptography.
- Score migration readiness.
- Produce signed audit and transparency evidence.
- Run local or remote key operations through `pqcd`.
- Experiment with post-quantum cryptography certificate and signature profiles.

Use it to turn a post-quantum cryptography migration plan into working systems:
generate keys, rotate versions, protect data, inspect real endpoints, and
preserve repeatable evidence for engineering, vendor, and compliance reviews.

## Install

```sh
go install github.com/helsingin/pqc/cmd/pqc@latest
go install github.com/helsingin/pqc/cmd/pqcd@latest
```

From a local checkout:

```sh
make build
```

## Manage Keys

```sh
pqc keys create --type ml-kem-768 --id service-a
pqc keys create --type ml-dsa-65 --id signer-a
pqc keys rotate --id service-a
pqc keys list
pqc keys public --id signer-a
```

## Encrypt Data

```sh
pqc encrypt --key service-a < message.json > message.pqc
pqc decrypt < message.pqc > message.out
```

## Sign Artifacts

```sh
pqc sign --key signer-a artifact.tar > artifact.sig
pqc verify --key signer-a artifact.tar artifact.sig
```

## Inspect TLS

```sh
pqc tls inspect example.com:443
pqc tls readiness example.com:443
```

## Score Readiness

```sh
pqc inventory scan --store ./dev-keys --target example.com:443
pqc readiness scan --store ./dev-keys --target example.com:443
```

## Produce Evidence

```sh
pqc keys create --type ml-dsa-65 --id audit-signer --audit-log ./audit.jsonl
pqc audit checkpoint --audit ./audit.jsonl --sign-key audit-signer
pqc transparency checkpoint --sign-key audit-signer --target example.com:443
```

## Run A Key Service

```sh
pqcd --addr 127.0.0.1:8080 --token "$PQC_API_TOKEN"
pqc keys list --remote http://127.0.0.1:8080 --token "$PQC_API_TOKEN"
```

## Experiment With Certificate And Signature Profiles

```sh
pqc profiles list
pqc profiles show x509-ml-dsa
pqc issue --profile mtc --sign-key signer-a --subject example.com --dns example.com
pqc verify-artifact artifact.json
```

## Documentation

- [Command-Line Reference](docs/cli.md)
- [Artifact Profiles](docs/artifact-profiles.md)
- [Daemon, HTTP Service, And Transport](docs/daemon-api.md)

## Notes

- Current post-quantum cryptography primitives: `ML-KEM-768`, `ML-DSA-65`, and
  `ML-DSA-87`.
- The implementation uses Cloudflare CIRCL for post-quantum cryptography
  primitives and the Go standard library for HKDF and AES-GCM.
- Treat this as a migration and integration toolkit, not a replacement for
  hardened production key custody, access control, or incident response design.

## License

Apache-2.0. See [LICENSE](LICENSE).
