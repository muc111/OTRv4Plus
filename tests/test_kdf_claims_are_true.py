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


class TestArgon2IsNotInTheRustCore:

    def test_it_is_not_a_crate_dependency(self):
        cargo = open(os.path.join(ROOT, "Rust", "Cargo.toml"),
                     encoding="utf-8").read()
        assert not re.search(r"(?m)^\s*argon2\s*=", cargo), (
            "argon2 is now a Rust dependency; the documentation that says it "
            "is not needs updating with it")

    def test_no_rust_source_uses_it(self):
        users = [f for f, src in _rust_sources().items()
                 if "argon2" in src.lower()]
        assert users == [], "argon2 appears in %s" % users

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
        line = [l for l in self._doc("FEATURES.md").split("\n")
                if l.startswith("| Argon2id ")]
        assert line, "the Argon2 row vanished; it should say where it IS used"
        assert "smp_vault.rs`. |" not in line[0], (
            "FEATURES.md still credits src/smp_vault.rs with an Argon2 KDF")
        assert "At-rest" in line[0]

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

    def test_the_smp_passphrase_derivation_is_iterated_shake_not_memory_hard(self):
        """The thing a memory-hard KDF would actually be for.

        SMP transcripts permit an offline dictionary attack on the shared
        passphrase, and 50,000 rounds of SHAKE-256 is CPU-only work that
        parallelises freely. This test does not claim that is wrong -- it
        pins what it IS, so a change to it is deliberate and versioned.
        """
        smp = open(os.path.join(ROOT, "Rust", "src", "smp.rs"),
                   encoding="utf-8").read()
        m = re.search(r"const KDF_ROUNDS:\s*u32\s*=\s*([0-9_]+);", smp)
        assert m, "KDF_ROUNDS is gone; the derivation changed"
        assert int(m.group(1).replace("_", "")) == 50_000
        assert "argon2" not in smp.lower(), (
            "smp.rs now uses argon2 -- this is a WIRE CHANGE and needs a new "
            "SMP version byte, both peers updated, and SPEC 6.4 rewritten")

    def test_the_spec_documents_the_derivation_that_is_implemented(self):
        spec = open(os.path.join(ROOT, "SPEC.md"), encoding="utf-8").read()
        i = spec.index("### 6.4 Secret Derivation")
        section = spec[i:i + 1200]
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


class TestTheSmpStretchIsUnsalted:
    """The 50k-round stretch buys less than it looks like it buys.

    ``set_secret`` stretches ``"OTRv4+SMP-v2\\0" || raw_secret`` for 50,000
    rounds of SHAKE-256 and only THEN binds in the session id and both
    fingerprints, with a single HMAC.  Nothing user-specific enters the
    expensive part, so an attacker builds ``stretch(candidate)`` once and
    reuses it against every OTRv4Plus user and every session forever; testing
    a candidate against a captured transcript then costs one HMAC.

    These tests do not assert that this is fine.  They pin the shape of the
    construction so that if someone fixes it -- or makes it worse -- the
    change is deliberate and the docs move with it.
    """

    def _smp(self):
        return open(os.path.join(ROOT, "Rust", "src", "smp.rs"),
                    encoding="utf-8").read()

    def _set_secret(self):
        src = self._smp()
        body = src.split("pub fn set_secret(", 1)[1]
        return body.split("\n    pub fn ", 1)[0]

    def test_the_stretch_input_is_only_the_domain_tag_and_the_secret(self):
        body = self._set_secret()
        stretch = body.split("Step 1", 1)[1].split("Step 2", 1)[0]
        for user_specific in ("session_id", "our_fp", "peer_fp"):
            assert user_specific not in stretch, (
                "%s now enters the 50k-round stretch -- good, but that is a "
                "WIRE CHANGE: it needs a new SMP version byte, both peers "
                "updated together, and SPEC 6.4 rewritten" % user_specific)

    def test_the_binding_happens_after_the_stretch(self):
        body = self._set_secret()
        assert body.index("KDF_ROUNDS") < body.index("Hmac::<Sha3_512>"), (
            "binding moved ahead of the stretch -- that changes the derived "
            "scalar and is a wire break")

    def test_the_cost_is_still_the_documented_50k(self):
        assert "const KDF_ROUNDS:           u32   = 50_000;" in self._smp(), (
            "KDF_ROUNDS changed; both peers must agree or SMP fails, and "
            "SPEC 6.4 quotes this number")
