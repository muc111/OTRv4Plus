#!/usr/bin/env python3
"""Where each KDF actually lives, pinned against the documentation.

FEATURES.md and README.md both claimed an "Argon2id KDF protecting the SMP
vault" inside the Rust core. All three parts were wrong: `argon2` is not a
dependency of the crate, no Rust source mentions it, and `smp_vault.rs` is an
in-memory zeroizing secret store with no key derivation in it whatsoever. The
claim survived a documentation-synchronisation pass because the table was read
and not checked.

A wrong KDF claim is worse than a missing one -- it invites a reader to assume
a passphrase is protected by a memory-hard function when it is not.

v10.13.0 then made the claim true, in the one place it actually mattered: SMP
wire version 0x03 derives the secret scalar with Argon2id, salted with the
session id and both fingerprints.  The guards below were written to fire on
exactly that change, and they did; they now pin the new shape instead.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
otr = pytest.importorskip("otrv4_")


def _rust_sources():
    d = os.path.join(ROOT, "Rust", "src")
    return {f: open(os.path.join(d, f), encoding="utf-8").read()
            for f in os.listdir(d) if f.endswith(".rs")}


class TestArgon2IsInTheRustCore:

    def test_it_is_a_crate_dependency(self):
        cargo = open(os.path.join(ROOT, "Rust", "Cargo.toml"),
                     encoding="utf-8").read()
        assert re.search(r"(?m)^\s*argon2\s+=", cargo), (
            "argon2 is no longer a Rust dependency -- SMP 0x03 cannot work "
            "without it, and it must not silently fall back to 0x02")

    def test_it_is_used_by_smp_and_not_by_the_vault(self):
        # smp.rs for the 0x03 wire stretch; at_rest.rs only to read store
        # files written by the retired Python argon2-cffi code.
        users = sorted(f for f, src in _rust_sources().items()
                       if "argon2" in src.lower())
        assert users == ["at_rest.rs", "smp.rs"], (
            "argon2 should appear in smp.rs and at_rest.rs only; found %s" % users)
        assert "argon2" not in _rust_sources()["smp_vault.rs"].lower()

    def test_the_low_level_api_is_used_not_the_phc_string(self):
        """A wire protocol needs raw bytes both peers agree on.

        `hash_password` returns a PHC string carrying its own encoded salt and
        parameters; two peers formatting it differently would derive different
        scalars.  `hash_password_into` writes the raw output.
        """
        smp = _rust_sources()["smp.rs"]
        assert "hash_password_into" in smp
        assert "PasswordHasher" not in smp

    def test_the_vault_has_no_kdf(self):
        src = _rust_sources()["smp_vault.rs"].lower()
        for kdf in ("argon2", "scrypt", "pbkdf"):
            assert kdf not in src, (
                "smp_vault.rs mentions %s; it is documented as a store, not a "
                "deriver" % kdf)


class TestTheDocumentationSaysSo:

    def _doc(self, name):
        return open(os.path.join(ROOT, name), encoding="utf-8").read()

    def test_features_no_longer_puts_argon2_in_the_vault(self):
        rows = [l for l in self._doc("FEATURES.md").split("\n")
                if l.startswith("| Argon2id")]
        assert rows, "the Argon2 rows vanished; they should say where it IS used"
        for row in rows:
            assert "smp_vault.rs`. |" not in row, (
                "FEATURES.md still credits src/smp_vault.rs with an Argon2 KDF")

    def test_features_separates_the_smp_and_at_rest_uses(self):
        """Two different KDFs doing two different jobs; conflating them is how
        the false claim got written in the first place."""
        rows = [l for l in self._doc("FEATURES.md").split("\n")
                if l.startswith("| Argon2id")]
        joined = "\n".join(rows)
        assert "Argon2id (SMP)" in joined and "0x03" in joined
        assert "Argon2id (at rest)" in joined

    def test_readme_no_longer_claims_it_runs_in_the_rust_core(self):
        doc = self._doc("README.md")
        i = doc.index("One cryptographic surface for chat.")
        para = doc[i:i + 1400]
        assert "Argon2id-class KDF protecting the SMP vault — runs inside" not in para

    def test_the_scrypt_fallback_is_recorded_as_removed(self):
        row = [l for l in self._doc("FEATURES.md").split("\n")
               if l.startswith("| Argon2id (at rest)")][0]
        assert "scrypt" in row and "removed" in row, (
            "the at-rest row must say the Python scrypt fallback is gone")


class TestWhereTheKdfsReallyAre:

    def test_at_rest_key_handling_is_in_rust(self):
        src = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
        for gone in ("def _derive_key(", "hashlib.scrypt", "import argon2",
                     "hash_secret_raw", "class SecureKeyStorage"):
            assert gone not in src, gone
        assert "SmpSecretStore" in src

    def test_the_smp_passphrase_derivation_is_memory_hard_under_0x03(self):
        smp = open(os.path.join(ROOT, "Rust", "src", "smp.rs"),
                   encoding="utf-8").read()
        assert "fn stretch_argon2id(" in smp
        assert "Algorithm::Argon2id" in smp

    def test_the_legacy_shake_stretch_is_still_available_for_0x02_peers(self):
        smp = open(os.path.join(ROOT, "Rust", "src", "smp.rs"),
                   encoding="utf-8").read()
        assert "fn stretch_shake_legacy(" in smp
        m = re.search(r"const KDF_ROUNDS:\s*u32\s*=\s*([0-9_]+);", smp)
        assert m, "KDF_ROUNDS is gone; 0x02 peers can no longer be talked to"
        assert int(m.group(1).replace("_", "")) == 50_000

    def test_the_argon2_cost_is_the_same_as_the_at_rest_cost(self):
        """Two cost profiles in one codebase is one more thing to get wrong."""
        smp = open(os.path.join(ROOT, "Rust", "src", "smp.rs"),
                   encoding="utf-8").read()
        assert "const ARGON2_M_COST_KIB: u32 = 65_536;" in smp
        assert "const ARGON2_T_COST:     u32 = 3;" in smp
        assert "const ARGON2_P_COST:     u32 = 4;" in smp

        # The legacy reader must derive exactly what argon2-cffi derived
        # (memory_cost=65536, time_cost=3, parallelism=4), or old stores
        # stop opening.
        at_rest = _rust_sources()["at_rest.rs"]
        assert "Params::new(65536, 3, 4, Some(KEY_LEN))" in at_rest
        assert "Algorithm::Argon2id, Version::V0x13" in at_rest

    def test_the_spec_documents_the_derivation_that_is_implemented(self):
        spec = open(os.path.join(ROOT, "SPEC.md"), encoding="utf-8").read()
        i = spec.index("### 6.4 Secret Derivation")
        section = spec[i:i + 4000]
        assert "Argon2id" in section
        assert "0x03" in section
        # The 0x02 derivation must stay documented for as long as the code can
        # still speak it.
        assert "50,000" in section and "SHAKE-256" in section


class TestThereIsNoDowngrade:
    """The Python at-rest KDF could silently fall to scrypt. It is gone; what
    replaces the warning is that an unreadable store is never dropped."""

    def test_no_python_kdf_or_scrypt(self):
        src = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
        assert "hashlib.scrypt" not in src
        assert "_warn_kdf_downgrade" not in src
        assert "def kdf_backend(" not in src

    def test_an_unreadable_store_is_moved_aside_and_reported(self):
        import tempfile
        core = pytest.importorskip("otrv4_core")
        d = tempfile.mkdtemp()
        path = os.path.join(d, "smp_secrets.json")
        with open(os.path.join(d, ".smp_seed"), "wb") as f:
            f.write(os.urandom(32))
        with open(path, "wb") as f:
            f.write(os.urandom(200))                      # not decryptable
        store = core.SmpSecretStore(path)
        assert store.legacy_unreadable, "an unreadable store was dropped silently"
        assert os.path.exists(store.legacy_unreadable)
        assert not os.path.exists(path)

    def test_the_engine_says_so(self):
        src = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
        assert "were moved aside to" in src


class TestTheSmpStretchIsSalted:
    """0x03 puts the session and the peer pair inside the expensive part.

    Under 0x02 the 50,000 SHAKE-256 rounds hashed the passphrase alone, so
    ``stretch(candidate)`` was computed once and reused against every user and
    every session; the session and fingerprint binding that followed was a
    single HMAC.  Under 0x03 the session id and both fingerprints are in the
    Argon2id salt, so no precomputation survives.

    These tests pin the shape of the construction, because any of it moving is
    a wire break: it needs a new version byte, both peers updated together,
    and SPEC 6.4 rewritten.
    """

    def _smp(self):
        return open(os.path.join(ROOT, "Rust", "src", "smp.rs"),
                    encoding="utf-8").read()

    def _set_secret(self):
        src = self._smp()
        body = src.split("pub fn set_secret(", 1)[1]
        return body.split("\n    pub fn ", 1)[0]

    def _argon2_fn(self):
        """Just stretch_argon2id -- it is the last helper before set_secret,
        so splitting only on "\n    fn " runs straight into it."""
        body = self._smp().split("fn stretch_argon2id(", 1)[1]
        return re.split(r"\n    (?:pub )?fn ", body, maxsplit=1)[0]

    def test_the_session_and_peers_reach_the_expensive_part(self):
        fn = self._argon2_fn()
        salt = fn.split("let mut salt", 1)[1].split("let params", 1)[0]
        for user_specific in ("session_id", "first_fp", "second_fp"):
            assert user_specific in salt, (
                "%s no longer reaches the Argon2 salt -- precomputation is "
                "back, and this is a wire change either way" % user_specific)

    def test_the_salt_is_length_prefixed(self):
        """Otherwise ("ab","c") and ("a","bc") collide into one salt."""
        fn = self._argon2_fn()
        assert "(field.len() as u64).to_be_bytes()" in fn

    def test_the_salt_is_deterministic_not_random(self):
        """Both peers must land on the same scalar with no salt on the wire."""
        fn = self._argon2_fn()
        for rng in ("OsRng", "rand::", "SaltString::generate", "random"):
            assert rng not in fn, (
                "%s in the salt derivation would make SMP fail outright, not "
                "merely differ" % rng)

    def test_argon2_failure_does_not_fall_back_to_the_weaker_stretch(self):
        """Failing open here would be worse than the problem 0x03 fixes."""
        fn = self._argon2_fn()
        assert "stretch_shake_legacy" not in fn
        assert "unwrap_or" not in fn and "ok()" not in fn

    def test_the_cost_is_still_the_documented_50k(self):
        assert "const KDF_ROUNDS:           u32   = 50_000;" in self._smp(), (
            "KDF_ROUNDS changed; both peers must agree or SMP fails, and "
            "SPEC 6.4 quotes this number")
