# Protected signing with Keyman

`pqc` v0.2.1 adds a Go signing-provider boundary and an optional Keyman adapter.
It uses released Keyman v0.6.1. Keyman has no runtime dependency on `pqc`; its
cross-library verification tests live in a separate module.

The adapter supports ML-DSA-65, ML-DSA-87, SLH-DSA-SHA2-192s and
SLH-DSA-SHA2-256s. It signs existing profile artifacts and audit, transparency
and MTC checkpoints. Their v1 wire formats and public-only verification APIs
are unchanged. This release adds a Go API; it does not add token configuration
flags to `pqc` or `pqcd`.

## Provider contract

`pqc.Signer` has `Sign`; `pqc.SigningProvider` adds `ExportPublic`. Both the
software manager and the Keyman adapter implement the latter. A provider
receives the original message and `SignOptions`, and returns a signature
envelope naming the key identity, version and algorithm actually used.
Private-key retrieval is not part of either interface.

Import `github.com/helsingin/pqc/provider/keyman` only where token signing is
needed. This package requires CGO and a suitable PKCS#11 module. The root
library and existing commands still build and test with `CGO_ENABLED=0`.
The caller owns the Keyman manager, token credentials and key lifecycle.

This function signs an artifact with an existing token key. Serialize rotation
with the export/sign pair shown here, or maintain a registry of public keys by
identity and version and select the key named by the returned signature.

```go
package evidence

import (
    "context"
    "fmt"

    "github.com/helsingin/keyman/pkcs11"
    "github.com/helsingin/pqc"
    "github.com/helsingin/pqc/profile"
    keymanprovider "github.com/helsingin/pqc/provider/keyman"
)

func Sign(ctx context.Context, manager *pkcs11.Manager, keyID string,
    artifact *profile.IssuedArtifact) (*pqc.PublicKey, error) {
    provider, err := keymanprovider.New(manager)
    if err != nil {
        return nil, err
    }
    public, err := provider.ExportPublic(ctx, keyID)
    if err != nil {
        return nil, err
    }
    if err := profile.SignArtifact(ctx, provider, keyID, artifact); err != nil {
        return nil, err
    }
    if artifact.Signature.KeyVersion != public.Version {
        return nil, fmt.Errorf("key rotated: retrieve public version %d", artifact.Signature.KeyVersion)
    }
    if err := profile.VerifyArtifactSignature(artifact, public); err != nil {
        return nil, err
    }
    return public, nil
}
```

Pass the same provider to `pqc.SignAuditCheckpoint`,
`pqc.SignTransparencyCheckpoint` or `pqc.SignMTCCheckpoint`. These callers
already supply their signing contexts. Save the public key with the evidence;
verification needs neither the token nor an open Keyman manager.

## Contexts, modes and rotation

- Contexts are byte strings up to 255 bytes. The adapter passes them unchanged
  into the token operation and copies them into the signature envelope.
- `SignOptions.Randomized == false` requires deterministic signing; `true`
  requires token-generated randomness. The adapter never weakens either mode.
- Unsupported algorithms, contexts or modes return errors. Use `errors.Is`
  with Keyman's `ErrUnsupportedPQOperation` or `keyring.ErrUnsupportedKeyType`
  as appropriate. Underlying token errors remain wrapped; there is no software
  fallback and no returned signature on failure.
- Each call binds one token handle and its metadata before signing. If rotation
  overlaps signing, the signature still names that handle's actual version.
  `ExportPublic` selects the current version; retain historical public keys
  before rotating or deleting keys. It is not a historical-key lookup API.
- Cancellation is checked before the token operation. An already running token
  call cannot be interrupted through this API.

`manager.PQCapabilities` reports mechanisms advertised by the token. It does
not certify parameter-set, context or randomness-mode support. Test the exact
operation on the intended hardware. SoftHSM is a software token used here for
integration testing, not evidence of hardware protection or certification.

The adapter does not produce an attestation that a token created a signature.
Envelope creation times are local timestamps, not trusted timestamps. Existing
artifact/checkpoint verification semantics are unchanged; archival evidence
renewal, dual signatures and stricter verification policies are separate work.

## Validation

Build the pinned disposable SoftHSM image in Keyman, then run:

```sh
# In the Keyman repository:
CONTAINER_RUNTIME=container KEYMAN_TEST_IMAGE=keyman-softhsm-m1:test make test-integration

# In the pqc repository:
KEYMAN_INTEROP_IMAGE=keyman-softhsm-m1:test scripts/test-keyman-provider.sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 go test ./...
make build
scripts/test-backward-compat.sh /path/to/pqc-v0.2.0 bin/pqc --old-with-slh
```

The provider script uses the released Keyman dependency with `GOWORK=off`,
checks for local replacements, and runs with a disposable token. It covers all
four algorithms across artifact and checkpoint signing, software-provider
equivalence, context/mode handling, concurrent rotation, private-key protection
and public-only verification after key deletion and session closure.
Keyman's integration suite additionally injects unsupported mechanisms,
rejected contexts and failed metadata writes/retirement to check cleanup.

Validated on 27 November 2026: the commands above passed with host Go 1.26.4
on macOS arm64 and container Go 1.26.11 on Linux arm64, CIRCL v1.6.5 and
released Keyman v0.6.1. All four signature algorithms and ML-KEM envelopes
interoperated in both directions with the v0.2.0 command binary. No serialized
format or MBGW security-profile changes were required.
