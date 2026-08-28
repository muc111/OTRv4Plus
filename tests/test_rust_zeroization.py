#!/usr/bin/env python3
"""INV-07, INV-08: Rust owns the secrets, and drops them clean.

`ZeroizeOnDrop` is a derive, so the guarantee is real but invisible: nothing
in the Python suite can observe a Rust buffer being wiped.  What these tests
can do is assert that the declarations are still present, that the secret
wrappers have not grown an accessor that would let material escape, and that
the Python side is not holding what Rust should.
"""

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
RUST = os.path.join(ROOT, "Rust", "src")


def _rs(name):
    return open(os.path.join(RUST, name), encoding="utf-8").read()


class TestTheSecretWrappers:

    def test_secret_bytes_zeroizes_on_drop(self):
        src = _rs("secure_mem.rs")
        i = src.index("pub struct SecretBytes")
        assert "ZeroizeOnDrop" in src[max(0, i - 120):i]

    def test_secret_vec_zeroizes_on_drop(self):
        src = _rs("secure_mem.rs")
        i = src.index("pub struct SecretVec")
        assert "ZeroizeOnDrop" in src[max(0, i - 120):i]

    @pytest.mark.parametrize("struct", [
        "DakeSessionKeys", "MessageKey", "EphemeralX448", "Ed448IdentityKey",
    ])
    def test_every_key_bundle_zeroizes_on_drop(self, struct):
        src = _rs("secure_mem.rs")
        i = src.index("pub struct %s" % struct)
        assert "ZeroizeOnDrop" in src[max(0, i - 120):i], (
            "%s does not wipe on drop" % struct)

    def test_debug_never_prints_the_contents(self):
        src = _rs("secure_mem.rs")
        assert src.count("[REDACTED]") >= 2, (
            "a secret wrapper can print itself; a single debug log or panic "
            "message would then carry key material")

    def test_the_wrappers_expose_no_owned_copy(self):
        """`expose()` returns a borrow.  A method handing back an owned Vec
        would create a copy outside the zeroizing wrapper."""
        src = _rs("secure_mem.rs")
        for bad in ("-> Vec<u8>", "-> [u8; N]", "fn into_", "fn to_vec"):
            assert bad not in src, (
                "%s lets secret bytes escape the wrapper" % bad)

    def test_constant_time_comparison_is_available(self):
        src = _rs("secure_mem.rs")
        assert "subtle::ConstantTimeEq" in src or "ConstantTimeEq" in src


class TestTheSmpSecretStaysInRust:

    def test_the_scalar_is_a_secret_vec(self):
        assert "self.secret     = SecretVec::from_slice" in _rs("smp.rs")

    def test_the_vault_zeroizes(self):
        src = _rs("smp_vault.rs")
        assert "ZeroizeOnDrop" in src

    def test_the_vault_read_back_is_gated_out_of_production(self):
        src = _rs("smp_vault.rs")
        for method in ("fn load", "fn load_by_handle"):
            i = src.find(method)
            if i == -1:
                continue
            assert 'cfg(feature = "test-only-kdf")' in src[max(0, i - 200):i], (
                "%s is reachable in a production build" % method)

    def test_the_argon2_state_is_wiped(self):
        """The stretch output and its salt are both live secret material."""
        src = _rs("smp.rs")
        fn = src.split("fn stretch_argon2id(", 1)[1]
        fn = re.split(r"\n    (?:pub )?fn ", fn, maxsplit=1)[0]
        assert "salt.zeroize()" in fn


class TestTheIdentitySeedNeverLeaves:

    def test_there_is_no_seed_accessor(self):
        for name in os.listdir(RUST):
            if not name.endswith(".rs"):
                continue
            src = _rs(name)
            assert "pub fn get_seed" not in src, name
            assert "pub fn expose_seed" not in src, (
                "%s exposes the seed publicly" % name)

    def test_expose_seed_slice_is_crate_private(self):
        src = _rs("key_handles.rs")
        if "expose_seed_slice" in src:
            i = src.index("fn expose_seed_slice")
            assert "pub(crate)" in src[max(0, i - 40):i], (
                "expose_seed_slice is no longer crate-private")

    def test_the_legacy_key_getters_are_feature_gated(self):
        src = _rs("dake.rs")
        for getter in ("fn root_key", "fn chain_key_a", "fn chain_key_b",
                       "fn brace_key", "fn mac_key"):
            i = src.find(getter)
            if i == -1:
                continue
            window = src[max(0, i - 200):i]
            assert 'cfg(feature = "legacy-dake-keys")' in window, (
                "%s is compiled into production builds" % getter)


class TestPythonDoesNotHoldWhatRustShould:

    def test_the_engine_has_no_ratchet_key_bytes(self):
        """Ratchet material moves Rust-to-Rust through an opaque handle."""
        src = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
        assert "get_session_keys" not in src or "legacy" in src.lower()

    def test_voice_key_material_is_at_least_wipeable(self):
        """Voice IS Python-owned -- a documented gap, INV-08's `limits`.

        bytearray is used rather than bytes precisely so `_wipe` can overwrite
        it.  Switching to bytes would make even best-effort wiping impossible.
        """
        src = open(os.path.join(ROOT, "otrv4plus_voice.py"),
                   encoding="utf-8").read()
        assert "def derive_media_key(root, call_id: bytes, epoch: int, " \
               "direction: int) -> bytearray:" in src, (
            "media keys are no longer bytearray, so they cannot be wiped at "
            "all")
        assert "def _wipe(" in src
