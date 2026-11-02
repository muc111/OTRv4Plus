# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Extract the ML-KEM-1024 and ML-DSA-87 cases the SHIPPING crates (ml-kem /
ml-dsa, the versions Rust/Cargo.lock pins) are checked against, from NIST's
ACVP-Server vectors at a pinned commit, so anyone can regenerate the two
vendored files and compare them byte for byte.

    python3 vectors/extract_acvp.py            # downloads, checks, writes
    python3 vectors/extract_acvp.py DIR        # uses DIR/<name>.json instead

Every source file must match its pinned SHA-256 or nothing is written.
Inputs are kept in full; large expected outputs are kept as SHA3-256 digests
(the tests hash what the crate produces and compare).

Kept (all cases of each group):
  ML-KEM-1024  keyGen                 d, z -> ek, dk
               encapsulation          ek, m -> c, k
               decapsulation          dk, c -> k   (incl. implicit rejection)
               encapsulationKeyCheck  ek -> valid?  (FIPS 203 s7.2)
               decapsulationKeyCheck  dk -> valid?  (FIPS 203 s7.3)
  ML-DSA-87    keyGen                 seed -> pk, sk
               sigGen  deterministic, external, pure   sk, message, context -> sig
               sigVer  external, pure                  pk, message, context, sig -> pass?
These are the groups whose code paths shipping uses (deterministic signing;
expanded dk / sk encodings). The commit is the one research/epochal-mldsa
already pins; the three ML-DSA files hash identically there.
"""
import hashlib
import json
import os
import sys
import urllib.request

COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
REPO = "https://github.com/usnistgov/ACVP-Server"
BASE = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/%s/gen-val/json-files/"
        "%%s/internalProjection.json" % COMMIT)
SOURCES = {
    "ML-KEM-keyGen-FIPS203": "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b",
    "ML-KEM-encapDecap-FIPS203": "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f",
    "ML-DSA-keyGen-FIPS204": "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf",
    "ML-DSA-sigGen-FIPS204": "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22",
    "ML-DSA-sigVer-FIPS204": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
}
HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, local_dir):
    if local_dir:
        raw = open(os.path.join(local_dir, name + ".json"), "rb").read()
    else:
        raw = urllib.request.urlopen(BASE % name, timeout=120).read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SOURCES[name]:
        sys.exit("%s: sha256 %s, expected %s" % (name, digest, SOURCES[name]))
    return json.loads(raw)


def sha3(hexstr):
    return hashlib.sha3_256(bytes.fromhex(hexstr)).hexdigest()


def group(doc, **want):
    found = [g for g in doc["testGroups"] if all(g.get(k) == v for k, v in want.items())]
    assert len(found) == 1, want
    g = found[0]
    assert not any(t.get("deferred") for t in g["tests"]), ("deferred cases", want)
    return g


def source(names):
    return {"repository": REPO, "commit": COMMIT,
            "files": {n + "/internalProjection.json": SOURCES[n] for n in names}}


def write(path, out, counts):
    with open(path, "w") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote %s (%d bytes): %s" % (os.path.basename(path), os.path.getsize(path), counts))


def main():
    local = sys.argv[1] if len(sys.argv) > 1 else None

    kg = load("ML-KEM-keyGen-FIPS203", local)
    ed = load("ML-KEM-encapDecap-FIPS203", local)
    p = "ML-KEM-1024"
    g_kg = group(kg, parameterSet=p)
    g_en = group(ed, parameterSet=p, function="encapsulation")
    g_de = group(ed, parameterSet=p, function="decapsulation")
    g_ek = group(ed, parameterSet=p, function="encapsulationKeyCheck")
    g_dk = group(ed, parameterSet=p, function="decapsulationKeyCheck")
    kem = {
        "source": source(["ML-KEM-keyGen-FIPS203", "ML-KEM-encapDecap-FIPS203"]),
        "keyGen": {"tgId": g_kg["tgId"], "tests": [
            {"tcId": t["tcId"], "d": t["d"], "z": t["z"],
             "ek_sha3": sha3(t["ek"]), "dk_sha3": sha3(t["dk"])} for t in g_kg["tests"]]},
        "encapsulation": {"tgId": g_en["tgId"], "tests": [
            {"tcId": t["tcId"], "ek": t["ek"], "m": t["m"], "c_sha3": sha3(t["c"]), "k": t["k"]}
            for t in g_en["tests"]]},
        "decapsulation": {"tgId": g_de["tgId"], "tests": [
            {"tcId": t["tcId"], "dk": t["dk"], "c": t["c"], "k": t["k"], "reason": t["reason"]}
            for t in g_de["tests"]]},
        "encapsulationKeyCheck": {"tgId": g_ek["tgId"], "tests": [
            {"tcId": t["tcId"], "ek": t["ek"], "testPassed": t["testPassed"], "reason": t["reason"]}
            for t in g_ek["tests"]]},
        "decapsulationKeyCheck": {"tgId": g_dk["tgId"], "tests": [
            {"tcId": t["tcId"], "dk": t["dk"], "testPassed": t["testPassed"], "reason": t["reason"]}
            for t in g_dk["tests"]]},
    }
    write(os.path.join(HERE, "acvp-mlkem1024.json"), kem,
          {k: len(v["tests"]) for k, v in kem.items() if k != "source"})

    dkg = load("ML-DSA-keyGen-FIPS204", local)
    dsg = load("ML-DSA-sigGen-FIPS204", local)
    dsv = load("ML-DSA-sigVer-FIPS204", local)
    p = "ML-DSA-87"
    g_kg = group(dkg, parameterSet=p)
    g_sg = group(dsg, parameterSet=p, deterministic=True, signatureInterface="external",
                 preHash="pure", externalMu=False)
    g_sv = group(dsv, parameterSet=p, signatureInterface="external", preHash="pure",
                 externalMu=False)
    dsa = {
        "source": source(["ML-DSA-keyGen-FIPS204", "ML-DSA-sigGen-FIPS204",
                          "ML-DSA-sigVer-FIPS204"]),
        "keyGen": {"tgId": g_kg["tgId"], "tests": [
            {"tcId": t["tcId"], "seed": t["seed"],
             "pk_sha3": sha3(t["pk"]), "sk_sha3": sha3(t["sk"])} for t in g_kg["tests"]]},
        "sigGen": {"tgId": g_sg["tgId"], "tests": [
            {"tcId": t["tcId"], "sk": t["sk"], "message": t["message"],
             "context": t["context"], "signature_sha3": sha3(t["signature"])}
            for t in g_sg["tests"]]},
        "sigVer": {"tgId": g_sv["tgId"], "tests": [
            {"tcId": t["tcId"], "pk": t["pk"], "message": t["message"], "context": t["context"],
             "signature": t["signature"], "testPassed": t["testPassed"], "reason": t["reason"]}
            for t in g_sv["tests"]]},
    }
    write(os.path.join(HERE, "acvp-mldsa87.json"), dsa,
          {k: len(v["tests"]) for k, v in dsa.items() if k != "source"})


if __name__ == "__main__":
    main()
