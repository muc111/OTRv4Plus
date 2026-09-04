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
        users = sorted(f for f, src in _rust_sources().items()
                       if "argon2" in src.lower())
        assert users == ["smp.rs"], (
            "argon2 should appear in smp.rs and nowhere else; found %s" % users)

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

    def test_the_scrypt_fallback_is_disclosed(self):
        assert "scrypt" in self._doc("FEATURES.md"), (
            "the at-rest KDF silently degrades to scrypt when argon2-cffi is "
            "missing, and that must be written down somewhere a reader looks")


class TestWhereTheKdfsReallyAre:

    def test_at_rest_uses_argon2_when_available(self):
        import inspect
        src = inspect.getsource(otr._derive_key)
        assert "hash_secret_raw" in src and "Type as _ArgonType" in src
        assert "scrypt" in src, "the documented fallback is gone"

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

        import inspect
        at_rest = inspect.getsource(otr._derive_key)
        assert "memory_cost=65536" in at_rest
        assert "time_cost=3" in at_rest
        assert "parallelism=4" in at_rest

    def test_the_spec_documents_the_derivation_that_is_implemented(self):
        spec = open(os.path.join(ROOT, "SPEC.md"), encoding="utf-8").read()
        i = spec.index("### 6.4 Secret Derivation")
        section = spec[i:i + 4000]
        assert "Argon2id" in section
        assert "0x03" in section
        # The 0x02 derivation must stay documented for as long as the code can
        # still speak it.
        assert "50,000" in section and "SHAKE-256" in section


class TestTheDowngradeIsNotSilent:
    """If at-rest storage stops being memory-hard, you should be told."""

    def _src(self):
        return open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()

    def test_argon2_failure_is_no_longer_swallowed(self):
        src = self._src()
        assert "except Exception:\n            pass\n\n    return hashlib.scrypt" not in src, (
            "an argon2 failure silently degraded to scrypt with no warning")
        assert "_warn_kdf_downgrade" in src

    def test_both_downgrade_paths_warn(self):
        """Missing argon2-cffi AND a raising argon2 must each warn."""
        src = self._src()
        body = src.split("def _derive_key(", 1)[1].split("\nclass ", 1)[0]
        assert body.count("_warn_kdf_downgrade(") == 2, (
            "one of the two ways to end up on scrypt does not warn")

    def test_the_backend_actually_used_is_reportable(self):
        src = self._src()
        assert "def kdf_backend(" in src
        assert '_KDF_LAST_BACKEND = "argon2id"' in src
        assert '_KDF_LAST_BACKEND = "scrypt"' in src

    def test_derive_key_docstring_does_not_claim_argon2_protects_smp_wire(self):
        """The at-rest KDF must not be confused with the protocol KDF."""
        src = self._src()
        doc = src.split("def _derive_key(", 1)[1].split('"""', 2)[1]
        assert "AT-REST" in doc
        assert "50,000" in doc and "SHAKE-256" in doc, (
            "the docstring should name the protocol KDF it is NOT")

    def test_warning_names_a_remedy(self):
        src = self._src()
        assert "pip install argon2-cffi" in src


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
