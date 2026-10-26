# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Mutation checks: the tests are not vacuous. Each mutant breaks one rule
of the claim in a copy of the crate; the test suite must then fail. A
mutant the suite does not catch is printed as SURVIVED and makes the run
fail, so a gate that tests nothing cannot hide.

    python3 tools/mutants.py           # from research/epochal-mldsa
"""
import os
import shutil
import subprocess
import sys
import tempfile

CRATE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (name, rule it breaks, old text in src/lib.rs, replacement)
MUTANTS = [
    ("ctx-no-epoch", "C3 boundary: the context names the epoch",
     "    ctx.extend_from_slice(&epoch_id.to_be_bytes());\n", ""),
    ("release-open-epoch", "C1: only a closed epoch is released",
     "if epoch_id + 1 >= self.next_epoch {", "if epoch_id >= self.next_epoch {"),
    ("chain-stalls", "C3: the chain steps forward",
     'let next = h(&[b"chain", &self.chain]);', "let next = self.chain;"),
    ("binding-no-member", "binding: the tag covers the member",
     "&epoch_id.to_be_bytes(), member, &pk_hash])", "&epoch_id.to_be_bytes(), &pk_hash])"),
    ("binding-no-epoch", "binding: only to its own epoch",
     "    group.epoch_id == pk.epoch_id\n        && group.group_hash()",
     "    group.group_hash()"),
    ("release-wrong-seed", "C2: the release is the key",
     "seed.copy_from_slice(key.seed.as_slice());",
     "seed.copy_from_slice(key.seed.as_slice()); seed[0] ^= 1;"),
    ("prehash-domain", "FIPS 204: pure signing, domain byte 0",
     "sk.sign_internal(&[&[0u8], &[ctx.len() as u8], ctx, message], &rnd)",
     "sk.sign_internal(&[&[1u8], &[ctx.len() as u8], ctx, message], &rnd)"),
    ("receiver-ignores-releases", "boundary rule: refuse released epochs",
     "!board.is_released(&pk.member, pk.epoch_id) && verify_bound",
     "verify_bound"),
    ("keygen-goes-back", "C3: keys only go forward",
     "if epoch_id < self.next_epoch || group.epoch_id != epoch_id {",
     "if group.epoch_id != epoch_id {"),
    ("release-keeps-key", "erasure: a released key leaves the signer",
     "let key = self.keys.remove(&epoch_id).ok_or(ReleaseError::Unknown)?;",
     "let key = self.keys.remove(&epoch_id).ok_or(ReleaseError::Unknown)?;\n"
     "        self.keys.insert(epoch_id, SecretKey { group_hash: key.group_hash, epoch_id,"
     " seed: key.seed.clone(), sk: key_from_seed(&key.seed) });"),
    ("verify-ignores-epoch-label", "the signature's declared epoch must match the key's",
     "    sig.epoch_id == pk.epoch_id\n        && fips204_verify",
     "    fips204_verify"),
]


def main():
    src = open(os.path.join(CRATE, "src", "lib.rs")).read()
    work = tempfile.mkdtemp(prefix="epochal-mutants-")
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(CRATE, "target", "mutants"))
    survived = 0
    try:
        for name in ("src", "tests", "vectors", "examples"):
            shutil.copytree(os.path.join(CRATE, name), os.path.join(work, name))
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copy(os.path.join(CRATE, name), work)
        print("| Mutant | Rule it breaks | Result | First failing test |")
        print("|---|---|---|---|")
        for name, rule, old, new in MUTANTS:
            assert src.count(old) == 1, "mutation point not unique: %s" % name
            open(os.path.join(work, "src", "lib.rs"), "w").write(src.replace(old, new))
            p = subprocess.run(["cargo", "test", "--offline", "--release", "--no-fail-fast", "-q"],
                               cwd=work, env=env, capture_output=True, text=True)
            out = p.stdout + p.stderr
            if "error[" in out and "could not compile" in out:
                result, first = "ERROR (did not compile)", ""
                survived += 1
            elif p.returncode != 0:
                # Each test binary ends with "failures:" and then the names,
                # one per line, indented; the earlier "failures:" holds output.
                failed = []
                for block in out.split("\nfailures:\n")[1:]:
                    names = []
                    for line in block.splitlines():
                        if not line.startswith("    "):
                            break
                        names.append(line.strip())
                    if names and all(n.replace("_", "").isalnum() for n in names):
                        failed += names
                result = "killed (%d test%s failed)" % (len(failed), "" if len(failed) == 1 else "s")
                first = failed[0] if failed else "?"
            else:
                result, first = "SURVIVED", ""
                survived += 1
            print("| `%s` | %s | %s | `%s` |" % (name, rule, result, first))
            sys.stdout.flush()
    finally:
        shutil.rmtree(work)
    print()
    print("%d/%d mutants killed" % (len(MUTANTS) - survived, len(MUTANTS)))
    sys.exit(1 if survived else 0)


if __name__ == "__main__":
    main()
