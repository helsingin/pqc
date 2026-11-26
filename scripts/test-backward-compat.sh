#!/usr/bin/env bash
# Supply the previous-release binary; all generated keys are temporary.
set -euo pipefail
old=${1:?Usage: test-backward-compat.sh OLD_PQC [NEW_PQC] [--old-with-slh]}
pqc_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
new=${2:-$pqc_dir/bin/pqc}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf 'Existing PQC compatibility fixture\n' > "$work/message"

algorithms=(ml-dsa-65 ml-dsa-87)
if [[ "${3:-}" == --old-with-slh ]]; then
  algorithms+=(slh-dsa-sha2-192s slh-dsa-sha2-256s)
elif [[ -n "${3:-}" ]]; then
  printf 'Unknown option: %s\n' "$3" >&2
  exit 2
fi
for algorithm in "${algorithms[@]}"; do
  "$old" keys create --store "$work/keys" --type "$algorithm" --id "$algorithm" >/dev/null
  "$old" sign --store "$work/keys" --key "$algorithm" --context compatibility "$work/message" > "$work/old.sig"
  "$new" verify --store "$work/keys" "$work/message" "$work/old.sig"
  "$new" sign --store "$work/keys" --key "$algorithm" --context compatibility "$work/message" > "$work/new.sig"
  "$old" verify --store "$work/keys" "$work/message" "$work/new.sig"
done

"$old" keys create --store "$work/keys" --type ml-kem-768 --id kem >/dev/null
"$old" encrypt --store "$work/keys" --key kem "$work/message" > "$work/old.enc"
"$new" decrypt --store "$work/keys" "$work/old.enc" > "$work/plain"
cmp "$work/message" "$work/plain"
"$new" encrypt --store "$work/keys" --key kem "$work/message" > "$work/new.enc"
"$old" decrypt --store "$work/keys" "$work/new.enc" > "$work/plain"
cmp "$work/message" "$work/plain"

if [[ "${3:-}" == --old-with-slh ]]; then
  printf 'PASS: all four signature algorithms and ML-KEM interoperate in both directions.\n'
  exit 0
fi
for algorithm in slh-dsa-sha2-192s slh-dsa-sha2-256s; do
  "$new" keys create --store "$work/slh" --type "$algorithm" --id "$algorithm" >/dev/null
  "$new" sign --store "$work/slh" --key "$algorithm" "$work/message" > "$work/slh.sig"
  if "$old" verify --store "$work/slh" "$work/message" "$work/slh.sig" > "$work/rejected" 2>&1; then
    printf 'FAIL: old client accepted %s\n' "$algorithm" >&2
    exit 1
  fi
  if ! grep -qi 'unsupported algorithm' "$work/rejected"; then
    cat "$work/rejected" >&2
    exit 1
  fi
done
printf 'PASS: existing ML-DSA/ML-KEM interoperate in both directions; old client rejects SLH-DSA explicitly.\n'
