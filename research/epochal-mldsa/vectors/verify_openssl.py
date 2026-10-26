# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A third verifier, outside Rust: OpenSSL's ML-DSA-87 (through the
`cryptography` package) checks the public cases tests/proofs.rs exports.

    cargo test --release --test proofs     # writes target/evidence/public-cases.json
    python3 vectors/verify_openssl.py [path]

Public data only: verification keys, contexts, messages, signatures and
the expected outcome. No seed or signing key is read or needed. Exit 0 only
if every case comes out as expected.
"""
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric import mldsa

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(HERE, "..", "target", "evidence", "public-cases.json")


def verifies(case):
    pk = mldsa.MLDSA87PublicKey.from_public_bytes(bytes.fromhex(case["pk"]))
    try:
        pk.verify(bytes.fromhex(case["signature"]), bytes.fromhex(case["message"]),
                  context=bytes.fromhex(case["context"]))
        return True
    except InvalidSignature:
        return False


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    cases = json.load(open(path))["cases"]
    print("verifier: %s" % backend.openssl_version_text())
    bad = 0
    for c in cases:
        got = verifies(c)
        ok = got == c["expected"]
        bad += not ok
        print("%-4s %-6s %s" % ("ok" if ok else "FAIL", "valid" if got else "reject", c["label"]))
    print("%d/%d as expected" % (len(cases) - bad, len(cases)))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
