# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Extract the ML-DSA-87 cases the prototype is checked against from NIST's
ACVP-Server vectors, at a pinned commit, so anyone can regenerate
acvp-mldsa87.json and compare it byte for byte.

    python3 vectors/extract_acvp.py            # downloads, checks, writes
    python3 vectors/extract_acvp.py DIR        # uses DIR/<name>.json instead

Kept (all cases of each group):
  keyGen  ML-DSA-87                         seed -> pk, sk  (SHA3-256 of each)
  sigGen  ML-DSA-87 hedged, external, pure  sk, message, context, rnd -> sig
  sigVer  ML-DSA-87 external, pure          pk, message, context, sig -> pass?
The prototype signs exactly as the sigGen group does (FIPS 204 Algorithm 2
with a context and a fresh rnd), so these are its signing path's vectors.
"""
import hashlib
import json
import os
import sys
import urllib.request

COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
BASE = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/%s/gen-val/json-files/"
        "%%s/internalProjection.json" % COMMIT)
SOURCES = {
    "ML-DSA-keyGen-FIPS204": "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf",
    "ML-DSA-sigGen-FIPS204": "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22",
    "ML-DSA-sigVer-FIPS204": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "acvp-mldsa87.json")


def load(name, local_dir):
    if local_dir:
        raw = open(os.path.join(local_dir, name + ".json"), "rb").read()
    else:
        raw = urllib.request.urlopen(BASE % name, timeout=60).read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SOURCES[name]:
        sys.exit("%s: sha256 %s, expected %s" % (name, digest, SOURCES[name]))
    return json.loads(raw)


def sha3(hexstr):
    return hashlib.sha3_256(bytes.fromhex(hexstr)).hexdigest()


def group(doc, **want):
    found = [g for g in doc["testGroups"] if all(g.get(k) == v for k, v in want.items())]
    assert len(found) == 1, want
    return found[0]


def main():
    local = sys.argv[1] if len(sys.argv) > 1 else None
    kg = load("ML-DSA-keyGen-FIPS204", local)
    sg = load("ML-DSA-sigGen-FIPS204", local)
    sv = load("ML-DSA-sigVer-FIPS204", local)
    g_kg = group(kg, parameterSet="ML-DSA-87")
    g_sg = group(sg, parameterSet="ML-DSA-87", deterministic=False, signatureInterface="external",
                 preHash="pure", externalMu=False)
    g_sv = group(sv, parameterSet="ML-DSA-87", signatureInterface="external", preHash="pure",
                 externalMu=False)
    out = {
        "source": {"repository": "https://github.com/usnistgov/ACVP-Server", "commit": COMMIT,
                   "files": {n + "/internalProjection.json": h for n, h in SOURCES.items()}},
        "keyGen": {"tgId": g_kg["tgId"], "tests": [
            {"tcId": t["tcId"], "seed": t["seed"], "pk_sha3": sha3(t["pk"]), "sk_sha3": sha3(t["sk"])}
            for t in g_kg["tests"]]},
        "sigGen": {"tgId": g_sg["tgId"], "tests": [
            {"tcId": t["tcId"], "sk": t["sk"], "message": t["message"], "context": t["context"],
             "rnd": t["rnd"], "signature_sha3": sha3(t["signature"])}
            for t in g_sg["tests"]]},
        "sigVer": {"tgId": g_sv["tgId"], "tests": [
            {"tcId": t["tcId"], "pk": t["pk"], "message": t["message"], "context": t["context"],
             "signature": t["signature"], "testPassed": t["testPassed"], "reason": t["reason"]}
            for t in g_sv["tests"]]},
    }
    with open(OUT, "w") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote %s: keyGen %d, sigGen %d, sigVer %d" % (
        OUT, len(out["keyGen"]["tests"]), len(out["sigGen"]["tests"]), len(out["sigVer"]["tests"])))


if __name__ == "__main__":
    main()
