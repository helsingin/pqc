#!/usr/bin/env bash
# Run against this checkout, with a disposable SoftHSM token and no fleet mounts.
set -euo pipefail
pqc_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
keyman_dir=$(cd "${KEYMAN_DIR:-$pqc_dir/../keyman}" && pwd)
runtime=${CONTAINER_RUNTIME:-container}
image=${KEYMAN_INTEROP_IMAGE:-keyman-softhsm:latest}

"$runtime" run --rm --name "pqc-keyman-interop-$$" \
  --cpus 2 --memory 2G \
  --volume "$pqc_dir:/sources/pqc:ro" \
  --volume "$keyman_dir:/sources/keyman:ro" \
  --entrypoint sh "$image" -ec '
    export GOWORK=off
    mkdir -p /tmp/keyman/pkcs11 /tmp/keyman/tests/pqc
    cp /sources/keyman/go.mod /sources/keyman/go.sum /sources/keyman/*.go /tmp/keyman/
    cp /sources/keyman/pkcs11/*.go /tmp/keyman/pkcs11/
    cp /sources/keyman/tests/pqc/go.mod /sources/keyman/tests/pqc/go.sum /sources/keyman/tests/pqc/*.go /tmp/keyman/tests/pqc/
    cd /tmp/keyman/tests/pqc
    go mod edit -replace github.com/helsingin/pqc=/sources/pqc
    go mod tidy
    go version
    go list -m github.com/helsingin/keyman github.com/helsingin/pqc github.com/cloudflare/circl
    go test -count=1 -v ./...
  '
