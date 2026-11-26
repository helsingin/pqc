# Architecture and scope

Applications choose a custody provider and own authorization, operational audit,
reconciliation and deployment. The libraries do not introduce a second central
key-management platform.

| Responsibility | Owner |
|---|---|
| Central authentication, authorization, secrets, certificate issuance and service audit | OpenBao |
| PKCS#11 provisioning and private-key operations | Keyman and the token provider |
| Cryptographic encoding, strict evidence verification, assessment and evidence renewal primitives | pqc |
| Inventory graphs, failure scenarios, storage, scheduling and recovery approvals | Application |

OpenBao already supports [external keys](https://openbao.org/docs/concepts/external-keys/)
and a [PKCS#11 plugin](https://openbao.org/docs/api/system/external-keys/plugins/pkcs11/).
Keyman-provisioned objects can serve that integration. Registering an external key
and its permitted operations belongs to deployment configuration. A new adapter
must be justified by an application requirement and verified against the exact
OpenBao/plugin versions; support in Keyman alone does not establish OpenBao support.

## Signing and evidence

`SigningProvider` is a small contract for a signing operation and public-key
access. `Manager` implements it for local software keys. There is no bundled
Keyman or OpenBao adapter. The interface does not implement authentication,
issuance policies, key custody, service auditing or retry orchestration.

An application integration must preserve the exact evidence bytes, signing
context, algorithm and key version. A changed key or unsupported signing mode
must produce an error. In particular, a generic context/derivation field in a
remote API must not be assumed to mean the ML-DSA/SLH-DSA signing context.

The evidence package supplies policy-bound signatures and public verification.
Its required signer list is an evidence acceptance policy, separate from the
service's policy controlling permission to invoke a key. Offline verification
requires no local private keys and does not justify a second signing backend.

## Existing local tools

The software store, CLI and `pqcd` predate this roadmap. They remain available
for development and local cryptographic use. Expanding them into central secrets,
identity, certificate or key-management services is outside the roadmap.

Local audit callbacks return failures and retain completed manager results.
The file auditor is a single-writer append log, without replay, deduplication,
multi-process coordination or crash-repair guarantees. Applications own failure
handling. OpenBao audit records cover OpenBao operations; they do not cover
operations performed directly by a separate process.

## Withdrawn milestone releases

The GitHub releases and tags for pqc v0.2.1/v0.2.2 and Keyman v0.6.1 were removed
on 27 November 2026 after review of the overlapping milestone scope. The direct
Keyman adapter and durable audit-retry subsystem were withdrawn. The independent
evidence format and verifier remain under development. Original commits remain
in history. Previously published version numbers must not be reused: external
Go module caches may still contain their original contents.

The cleanup was checked with Go 1.26.4 on macOS arm64: both repositories' unit
tests and vet checks, pqc software-only tests, focused race checks for evidence,
core and both command packages, independent Python evidence vectors, and command
builds. The disposable SoftHSM interoperability test used Go 1.26.11
on Linux arm64 and verified Keyman's ML-DSA-65/87 and SLH-DSA-SHA2-192s/256s
signatures with the local pqc checkout. This establishes primitive compatibility,
not an OpenBao adapter or hardware-HSM certification.
