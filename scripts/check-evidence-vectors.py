#!/usr/bin/env python3
"""Independent stdlib encoder for docs/evidence-v2.md; does not call Go code.

Checks canonical bytes and payload/key commitments. PQ signature verification
is performed by the Go public-vector test and the independent token interop suite.
--write is for explicit fixture maintenance after TestWritePublicVector.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct


def encode(statement):
    result = bytearray(b"pqc.evidence.v2\0")

    def number(value):
        assert isinstance(value, int) and not isinstance(value, bool)
        result.extend(struct.pack(">Q", value))

    def string(value):
        encoded = value.encode("utf-8", errors="strict")
        number(len(encoded))
        result.extend(encoded)

    string("pqc.evidence.v2")
    policy = statement["policy"]
    string(policy["schema"])
    string(policy["id"])
    number(policy["version"])
    string(policy["purpose"])
    string(policy["context"])
    number(policy["not_before"])
    number(policy["not_after"])
    number(len(policy["signers"]))
    for signer in policy["signers"]:
        string(signer["key_id"])
        number(signer["key_version"])
        string(signer["algorithm"])
        string(signer["public_key_digest"])
    payload = statement["payload"]
    string(payload["hash"])
    string(payload["digest"])
    number(payload["length"])
    string(payload["media_type"])
    number(statement["claimed_at"])
    fields = sorted(statement["metadata"], key=lambda field: field["key"].encode("utf-8"))
    assert len({field["key"] for field in fields}) == len(fields)
    number(len(fields))
    for field in fields:
        string(field["key"])
        string(field["value"])
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).resolve().parent.parent / "evidence/testdata/evidence-v2.json"
    vector = json.loads(path.read_text(encoding="utf-8"))
    statement = vector["document"]["statement"]
    payload = base64.b64decode(vector["payload"], validate=True)
    assert len(payload) == statement["payload"]["length"]
    assert hashlib.sha512(payload).hexdigest() == statement["payload"]["digest"]
    assert len(statement["policy"]["signers"]) == len(vector["keys"])
    for signer, key in zip(statement["policy"]["signers"], vector["keys"]):
        assert signer["key_id"] == key["id"]
        assert signer["key_version"] == key["version"]
        assert signer["algorithm"] == key["algorithm"]
        assert signer["public_key_digest"] == hashlib.sha512(base64.b64decode(key["public_key"], validate=True)).hexdigest()
    canonical = encode(statement)
    digest = hashlib.sha512(canonical).hexdigest()
    if args.write:
        vector["signing_bytes_hex"] = canonical.hex()
        vector["signing_sha512"] = digest
        path.write_text(json.dumps(vector, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        assert vector["signing_bytes_hex"] == canonical.hex(), "canonical byte mismatch"
        assert vector["signing_sha512"] == digest, "canonical digest mismatch"
    print(f"PASS: independent Python encoding ({len(canonical)} bytes), payload and four key commitments")


if __name__ == "__main__":
    main()
