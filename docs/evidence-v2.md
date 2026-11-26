# Evidence v2 contract

This format authenticates a payload commitment, its purpose and application
context, metadata, a claimed time, and the complete verification policy. It is
separate from `pqc.signature.v1` and existing artifact/checkpoint formats. Those
formats keep their existing interpretation; wrapping their exact bytes in v2
adds a new, independently verifiable statement rather than upgrading old claims.

## Trust and multiple signatures

A verifier supplies the expected policy, trusted public keys, and current time.
The embedded policy must match that expected policy exactly. Possession of a
public key in a document never establishes trust.

The policy identifies an ordered, nonempty set of required signers (maximum 8).
Each entry binds key ID, version, exact algorithm, and SHA-512 public-key digest.
**All listed signatures are required.** Every signer signs the same complete
statement, including that signer set and policy identity/version. There is no
automatic fallback to one signature, a weaker algorithm, or an older policy.
Removing, duplicating, reordering or replacing a signature fails verification.
For algorithm diversity, configure distinct families, for example ML-DSA and
SLH-DSA. Two keys of one family are not described as algorithm diversity.

Recovery is never inferred from a missing or invalid signature. A recovery
authority must provision a separate trusted policy with an explicit identity,
version, signer set and validity interval, and arrange fresh signatures under
that policy. Old signatures cannot be transplanted into it. Policy publication,
authorization and revocation distribution belong to the application; accepting
an attacker-provided recovery policy defeats verification.

## Data model

The JSON document has `schema`, `statement`, and `signatures` fields. Schema is
`pqc.evidence.v2`. The statement contains:

- `policy`: schema `pqc.evidence-policy.v1`, `id`, positive `version`, `purpose`,
  `context`, integer `not_before`/`not_after`, and ordered `signers`.
- `payload`: algorithm `SHA-512`, lowercase hexadecimal `digest`, byte `length`
  and `media_type`. The payload is supplied separately to verification.
- `claimed_at`: integer Unix seconds, signed as a claim by the signers.
- `metadata`: string key/value pairs. Keys are unique and serialized in UTF-8
  byte order; no Unicode normalization is performed.

Each signature entry has an integer `signer` index and base64 `value`.
Entries appear exactly once in policy order. Signer entries contain `key_id`,
`key_version`, `algorithm`, and `public_key_digest` (lowercase SHA-512 hex).
Key and policy versions are positive 32-bit integers. Lengths and timestamps
are bounded to exact JSON integers; negative values and unknown algorithms,
schemas or fields are rejected. Duplicate JSON object members are rejected.

Times are UTC Unix seconds in [0, 253402300799]. The verifier requires a supplied
nonzero clock value. The trusted policy interval is half-open:
`not_before <= now < not_after`. The signed claimed time must fall in that
interval and must not be in the verifier's future. It remains a claim, not
proof of historical existence. There are no trusted timestamps in this format.
An expired policy cannot be revived by presenting an old claimed time.

Inspection is explicit and does not authenticate anything. Verification always
requires the expected policy, trusted keys, payload and every required signature.
Unsigned documents can be inspected but never pass strict verification.

## Exact signing bytes

JSON is the transport encoding, not the signing encoding. Canonical bytes are
the following concatenation, with no padding or terminator beyond those stated:

1. ASCII `pqc.evidence.v2` followed by one NUL byte.
2. String: document schema.
3. String: policy schema; string: policy ID; uint64: policy version.
4. String: purpose; string: context.
5. uint64: not-before; uint64: not-after.
6. uint64: signer count. For each signer in order: string key ID, uint64 key
   version, string algorithm, string public-key digest.
7. String: payload hash algorithm; string: digest; uint64: payload length;
   string: media type.
8. uint64: claimed time.
9. uint64: metadata count. For each entry sorted by UTF-8 key bytes: string key,
   string value.

A uint64 is eight bytes, unsigned big-endian. A string is its UTF-8 byte length
as uint64 followed by those bytes. Invalid UTF-8 is rejected. Digests are encoded
as lowercase hexadecimal strings, not decoded binary. Signature bytes and JSON
whitespace are not part of this encoding. The pure ML-DSA/SLH-DSA operation uses
the fixed FIPS signing context `pqc.evidence.v2`. No prehash-signature mode is used;
the payload commitment is a field of the signed statement.

Limits: policy/key IDs, purpose, context and media type at most 1024 UTF-8 bytes;
at most 64 metadata entries, keys at most 256 bytes, values at most 4096 bytes;
JSON document at most 1 MiB; payload length at most 2^53-1 bytes. Limits apply to
both construction and decoding. No signature is accepted from an algorithm
outside ML-DSA-65/87 and SLH-DSA-SHA2-192s/256s.

## Audit failures and retry contract

Configured auditing must never silently discard write failures. A manager
operation can succeed before its audit record fails: a returned audit error must
retain the original operation outcome and any result. Callers must inspect that
outcome rather than blindly repeating generation, rotation or randomized signing.
An error from a store write can mean the write committed but acknowledgement
failed; this is reported as unknown, not as proof that nothing changed.

Audit receipts carry a stable event ID. Retry persists that same event; it does
not invoke the cryptographic operation again. A durable file auditor deduplicates
matching IDs, rejects conflicting reuse, serializes writers, repairs an incomplete
final line, and syncs writes before acknowledging them. An append that succeeded
before acknowledgement failed must remain a single event after retry/reopening.
Malformed complete records fail closed rather than being silently discarded.

This is idempotent audit persistence, not a distributed exactly-once operation
protocol. A process dying before it can return a receipt leaves an uncertain
operation outcome; reconcile stored key identity/version before deciding what
to do. Observed cancellation and sync failures are returned. An I/O operation
already in progress may complete even if the caller cancels concurrently.
Underlying durable storage and exclusive ownership of log lifecycle/rotation
remain deployment requirements. Legacy audit records without event IDs remain
readable and keep their original bytes and checkpoint interpretation.

File auditing is validated on Linux and macOS and uses OS advisory locks on
supported Unix platforms. Other platforms fail explicitly and need another
`Auditor` implementation. Each write scans the log to reconcile IDs; use a
database-backed auditor for high-volume workloads. External rotation or
replacement of an active log is not supported by this locking contract.

## Go API and migration

Import `github.com/helsingin/pqc/evidence`. The package works with the software
manager and optional Keyman provider. Keyman v0.6.1 already supplies the required
operations; no Keyman upgrade is introduced by this milestone.

`KeyReference` derives a reference from public key bytes. Establish that key's
trust separately, then place its reference into your configured policy. Never
select the trusted policy from the document being verified.

```go
statement, err := evidence.NewStatement(
    trustedPolicy, payload, "application/octet-stream", time.Now().UTC(),
    []evidence.Field{{Key: "record-type", Value: "engineering-report"}},
)
if err != nil {
    return nil, err
}
document, signingErr := evidence.Sign(ctx, statement, providers, false)
if document == nil {
    return nil, signingErr
}
if err := evidence.Verify(document, payload, trustedPolicy, trustedKeys, time.Now()); err != nil {
    return nil, errors.Join(signingErr, err)
}
// Retain the complete document even when signingErr reports audit failures.
return document, signingErr
```

Providers and trusted keys are supplied in policy order. A changed key version
or public key fails rather than silently updating the policy. `false` requests
deterministic signing; `true` requests randomized signing. Neither changes the
fixed signing context. Signing failures return no partial evidence document.

If every signature succeeds but audit persistence fails, `Sign` returns the
complete document plus `*evidence.SigningAuditError`. Its `Receipts` retain all
underlying `*pqc.AuditFailure` values. Retry each with `pqc.RetryAudit` and the
auditor that originally owned it. If a later signer fails, no complete document
is returned, but earlier audit receipts remain available through the error chain.

For direct manager operations, use `errors.As(err, &auditFailure)` to inspect
`Event.Outcome` and retain any accompanying result. `succeeded` means the original
operation completed, `failed` means it returned an operation failure, and
`unknown` means a store write was attempted but needs reconciliation.
`*pqc.UncertainOperationError` identifies the key/version to reconcile, including
when auditing itself succeeded. Error chains preserve underlying causes.

This intentionally changes failure behaviour when auditing is configured:
failures previously ignored now produce errors. Calls without an auditor keep
their ordinary behaviour, apart from explicit uncertainty on store write errors.
There is no automatic operation retry. File audit receipts have durable
deduplication across reopening and processes; custom auditors must implement
the same ID contract.

The daemon returns HTTP 500 with `audit_failure` and, for a completed operation,
`result`. The remote client retains both the decoded result and typed audit error.
The error body's result is as sensitive as an ordinary successful response;
do not copy it into logs. No public audit-retry endpoint is exposed: reconciliation
and audit replay are trusted administrative/application operations.

To wrap an existing artifact or checkpoint, serialize the exact v1 document as
the payload and choose an explicit purpose/media type in the trusted v2 policy.
Keep the v1 bytes for historical verification. A v2 wrapper does not establish
when old evidence first existed or restore authenticity after an algorithm fails.

## Reproducible checks

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 go test ./...
python3 scripts/check-evidence-vectors.py
KEYMAN_INTEROP_IMAGE=keyman-softhsm:latest scripts/test-keyman-provider.sh
scripts/test-backward-compat.sh /path/to/pqc-v0.2.1 bin/pqc --old-with-slh
```

The static public-only fixture covers all four signature algorithms. A separate
Python standard-library encoder checks the exact signing bytes, payload hash and
public-key commitments; Go verifies its signatures. The token suite independently
checks the Keyman/SoftHSM path, including ML-DSA + SLH-DSA pairs at Categories 3
and 5, stripping/downgrade rejection and private-object protections. Python needs
no additional packages. Fixture regeneration is explicit:

```sh
PQC_UPDATE_EVIDENCE_VECTOR=1 go test ./evidence -run '^TestWritePublicVector$'
python3 scripts/check-evidence-vectors.py --write
```

Only public keys, payload, signatures and canonical vectors are saved. Temporary
private test keys are removed by the Go test harness. Review regenerated vectors
as new fixtures; do not regenerate them merely to make a failing check pass.

Validated on 27 November 2026 with Go 1.26.4 on macOS arm64, container Go
1.26.11 on Linux arm64, CIRCL v1.6.5 and released Keyman v0.6.1. Full tests,
race checks, vet, software-only tests, both command builds, independent Python
vectors and the disposable SoftHSM suite passed. Decoder fuzzing completed
47,748 executions without a failure. All four signature algorithms and ML-KEM
interoperated in both directions with the v0.2.1 CLI. Hardware-token support
requires separate validation; no hardware certification is implied by SoftHSM.
