# Artifact Profiles

Artifact profiles isolate PQ certificate/signature approaches behind plugin
boundaries. Each profile owns its draft-specific inputs, metadata, estimates,
and verification behavior so changing drafts do not spread through the key
manager.

In `pqc`, a profile means an artifact profile: a named plugin boundary for one
PQC certificate/signature artifact family. It is broader than a traditional CA
certificate issuance profile, though a profile may eventually contain one.

## Commands

```sh
pqc profiles list
pqc profiles show mtc
pqc profiles help mtc
pqc profiles estimate mtc
```

Built-in artifact profiles:

- `mtc`: Merkle Tree Certificates.
- `x509-ml-dsa`: finalized FIPS 204 / RFC 9881 ML-DSA signatures in X.509 artifacts.
- `composite-x509`: LAMPS Composite ML-DSA X.509 artifacts.
- `fndsa`: FN-DSA certificate artifacts.

## Supported Versions

The `mtc` artifact profile currently supports
`draft-ietf-plants-merkle-tree-certs-04`, dated `2026-05-24` and expiring
`2026-11-25`. The supported draft appears in `pqc profiles help mtc`,
`pqc profiles show mtc`, estimates, and issued artifact metadata.

The `x509-ml-dsa` artifact profile supports finalized `NIST FIPS 204`, dated
`2024-08-13`, and `IETF RFC 9881`, published `2025-10`, for ML-DSA algorithm
identifiers in X.509 certificates and CRLs. It is drop-in compatible with
X.509 encoding, but the default ML-DSA-44 full-chain TLS authentication
estimate is `14724` bytes, so the profile marks public web TLS viability as
`false`.

The `composite-x509` artifact profile supports the generated LAMPS Composite
ML-DSA Internet-Draft source snapshot
`draft-ietf-lamps-pq-composite-sigs-latest@2026-06-15`, published
`2026-06-15` and expiring `2026-12-17`:
<https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html>.
The profile pins that source snapshot by date instead of treating `latest` as a
floating target.
It is X.509/PKIX protocol-compatible for upgraded systems, but still marks
public web TLS viability as `false` because the full-chain TLS authentication
overhead is in the `17000`-`20000` byte class.

The `fndsa` artifact profile supports the LAMPS FN-DSA X.509 certificate draft
`draft-ietf-lamps-fn-dsa-certificates-00@2026-05-20`, dated `2026-05-20` and
expiring `2026-11-21`: <https://www.ietf.org/archive/id/draft-ietf-lamps-fn-dsa-certificates-00.html>.
The draft references `NIST FIPS 206` as forthcoming; the profile therefore
does not claim a finalized FIPS 206 publication. It models pure FN-DSA only,
rejects HashFN-DSA/pre-hash inputs, and marks X.509 OID assignments as `tbd`
because the draft has not assigned final OIDs yet.

## Issue And Verify

Issue a signed artifact profile document:

```sh
pqc keys create --store ./dev-keys --type ml-dsa-65 --id org-root

cat > mtc-input.json <<'JSON'
{
  "certificate_type": "landmark",
  "tree_size": 4400000,
  "hash_algorithm": "sha256",
  "checkpoint": "dev"
}
JSON

pqc issue \
  --store ./dev-keys \
  --profile mtc \
  --sign-key org-root \
  --subject example.com \
  --dns example.com \
  --input mtc-input.json \
  > example.mtc.json
```

Estimate the MTC TLS authentication overhead for that tree size:

```sh
pqc profiles estimate mtc --input mtc-input.json
```

Verify a profile artifact from the store:

```sh
pqc verify-artifact --store ./dev-keys example.mtc.json
```

Or verify from an exported public key without opening a store:

```sh
pqc keys public --store ./dev-keys --id org-root > org-root.public.json
pqc verify-artifact --public-key org-root.public.json example.mtc.json
```

`pqc issue` works with `--remote` as well. In that mode the CLI sends the
artifact signing operation to `pqcd`, and the daemon remains the only process
that opens the key store.

Artifact profile documents are JSON documents with `schema`, `profile`, `type`,
`subject`, validity timestamps, profile-owned `inputs`, metadata, and an ML-DSA
signature. The stable Go boundary is `profile.Plugin` plus optional
`Issuer`, `Verifier`, `Inspector`, and `Estimator` capabilities; built-ins live
under `profiles/<id>` so draft changes stay inside the relevant artifact
profile.

## ML-DSA In X.509

Inspect and estimate finalized ML-DSA in X.509:

```sh
pqc profiles help x509-ml-dsa

cat > x509-ml-dsa-input.json <<'JSON'
{
  "signature_algorithm": "ml-dsa-44",
  "subject_public_key_algorithm": "ml-dsa-44",
  "certificate_role": "leaf",
  "chain_signature_count": 5,
  "chain_public_key_count": 2,
  "subject": "example.com",
  "dns_names": ["example.com"]
}
JSON

pqc profiles estimate x509-ml-dsa --input x509-ml-dsa-input.json

pqc issue \
  --store ./dev-keys \
  --profile x509-ml-dsa \
  --sign-key org-root \
  --subject example.com \
  --dns example.com \
  --input x509-ml-dsa-input.json \
  > example.x509-ml-dsa.json

pqc verify-artifact --store ./dev-keys example.x509-ml-dsa.json
```

## Composite ML-DSA In X.509

Inspect and estimate Composite ML-DSA in X.509:

```sh
pqc profiles help composite-x509

cat > composite-x509-input.json <<'JSON'
{
  "composite_algorithm": "id-MLDSA44-RSA2048-PSS-SHA256",
  "certificate_role": "leaf",
  "chain_signature_count": 5,
  "chain_public_key_count": 2,
  "subject": "example.com",
  "dns_names": ["example.com"]
}
JSON

pqc profiles estimate composite-x509 --input composite-x509-input.json
```

## FN-DSA In X.509

Inspect and estimate FN-DSA in X.509:

```sh
pqc profiles help fndsa

cat > fndsa-input.json <<'JSON'
{
  "parameter_set": "fn-dsa-512",
  "certificate_role": "intermediate",
  "chain_signature_count": 5,
  "chain_public_key_count": 2,
  "subject": "Example Intermediate CA",
  "key_usage": ["keyCertSign", "cRLSign"]
}
JSON

pqc profiles estimate fndsa --input fndsa-input.json
```

## Complete MTC Smoke Test

```sh
mkdir -p ./dev-keys

pqc keys create --store ./dev-keys --type ml-dsa-65 --id org-root

cat > mtc-input.json <<'JSON'
{
  "certificate_type": "landmark",
  "tree_size": 4400000,
  "hash_algorithm": "sha256",
  "checkpoint": "dev"
}
JSON

pqc profiles help mtc
pqc profiles estimate mtc --input mtc-input.json

pqc issue \
  --store ./dev-keys \
  --profile mtc \
  --sign-key org-root \
  --subject example.com \
  --dns example.com \
  --input mtc-input.json \
  > example.mtc.json

pqc verify-artifact --store ./dev-keys example.mtc.json

pqc keys public --store ./dev-keys --id org-root > org-root.public.json
pqc verify-artifact --public-key org-root.public.json example.mtc.json
```

## Complete ML-DSA In X.509 Smoke Test

```sh
mkdir -p ./x509-ml-dsa-dev-keys

pqc keys create --store ./x509-ml-dsa-dev-keys --type ml-dsa-65 --id org-root

cat > x509-ml-dsa-input.json <<'JSON'
{
  "signature_algorithm": "ml-dsa-44",
  "subject_public_key_algorithm": "ml-dsa-44",
  "certificate_role": "leaf",
  "chain_signature_count": 5,
  "chain_public_key_count": 2,
  "subject": "example.com",
  "dns_names": ["example.com"]
}
JSON

pqc profiles help x509-ml-dsa
pqc profiles estimate x509-ml-dsa --input x509-ml-dsa-input.json

pqc issue \
  --store ./x509-ml-dsa-dev-keys \
  --profile x509-ml-dsa \
  --sign-key org-root \
  --subject example.com \
  --dns example.com \
  --input x509-ml-dsa-input.json \
  > example.x509-ml-dsa.json

pqc verify-artifact --store ./x509-ml-dsa-dev-keys example.x509-ml-dsa.json

pqc keys public --store ./x509-ml-dsa-dev-keys --id org-root > org-root.x509-ml-dsa.public.json
pqc verify-artifact --public-key org-root.x509-ml-dsa.public.json example.x509-ml-dsa.json
```

## Complete Composite ML-DSA X.509 Smoke Test

```sh
mkdir -p ./composite-x509-dev-keys

pqc keys create --store ./composite-x509-dev-keys --type ml-dsa-65 --id org-root

cat > composite-x509-input.json <<'JSON'
{
  "composite_algorithm": "id-MLDSA44-RSA2048-PSS-SHA256",
  "certificate_role": "leaf",
  "chain_signature_count": 5,
  "chain_public_key_count": 2,
  "subject": "example.com",
  "dns_names": ["example.com"]
}
JSON

pqc profiles help composite-x509
pqc profiles estimate composite-x509 --input composite-x509-input.json

pqc issue \
  --store ./composite-x509-dev-keys \
  --profile composite-x509 \
  --sign-key org-root \
  --subject example.com \
  --dns example.com \
  --input composite-x509-input.json \
  > example.composite-x509.json

pqc verify-artifact --store ./composite-x509-dev-keys example.composite-x509.json

pqc keys public --store ./composite-x509-dev-keys --id org-root > org-root.composite-x509.public.json
pqc verify-artifact --public-key org-root.composite-x509.public.json example.composite-x509.json
```

## Complete FN-DSA X.509 Smoke Test

```sh
mkdir -p ./fndsa-dev-keys

pqc keys create --store ./fndsa-dev-keys --type ml-dsa-65 --id org-root

cat > fndsa-input.json <<'JSON'
{
  "parameter_set": "fn-dsa-512",
  "certificate_role": "intermediate",
  "chain_signature_count": 5,
  "chain_public_key_count": 2,
  "subject": "Example Intermediate CA",
  "key_usage": ["keyCertSign", "cRLSign"]
}
JSON

pqc profiles help fndsa
pqc profiles estimate fndsa --input fndsa-input.json

pqc issue \
  --store ./fndsa-dev-keys \
  --profile fndsa \
  --sign-key org-root \
  --subject "Example Intermediate CA" \
  --input fndsa-input.json \
  > example.fndsa.json

pqc verify-artifact --store ./fndsa-dev-keys example.fndsa.json

pqc keys public --store ./fndsa-dev-keys --id org-root > org-root.fndsa.public.json
pqc verify-artifact --public-key org-root.fndsa.public.json example.fndsa.json
```
