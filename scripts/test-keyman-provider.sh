#!/usr/bin/env bash
# Exercise this checkout against the RELEASED Keyman dependency, using an
# isolated software token. The host repository is mounted read-only.
set -euo pipefail
pqc_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runtime=${CONTAINER_RUNTIME:-container}
image=${KEYMAN_INTEROP_IMAGE:-keyman-softhsm:latest}

"$runtime" run --rm --name "pqc-keyman-provider-$$" \
  --cpus 2 --memory 2G \
  --volume "$pqc_dir:/sources/pqc:ro" \
  --entrypoint sh "$image" -ec '
    export GOWORK=off
    mkdir -p /tmp/pqc
    cp /sources/pqc/go.mod /sources/pqc/go.sum /sources/pqc/pqc.go /tmp/pqc/
    cp -R /sources/pqc/internal /sources/pqc/profile /sources/pqc/profiles /sources/pqc/store /sources/pqc/provider /tmp/pqc/
    cd /tmp/pqc
    go version
    go list -m github.com/helsingin/keyman github.com/cloudflare/circl
    test -z "$(go list -m -f "{{if .Replace}}replaced{{end}}" github.com/helsingin/keyman)"
    go test -mod=readonly -race -count=1 -v ./provider/keyman
  '
