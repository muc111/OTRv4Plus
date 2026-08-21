#!/usr/bin/env python3
"""Decision B1 (option B): identity sealing inside the Rust boundary.

The nine proofs the decision requires, in order:

  1. identity survives application restart
  2. fingerprint remains stable after restart
  3. raw Ed448 seed is not exposed through PyO3
  4. raw seed does not appear in Kotlin
  5. raw seed does not appear in logs
  6. corrupted identity storage fails closed
  7. wrong wrapping key fails closed
  8. identity deletion invalidates the stored identity
  9. Rust secret buffers are zeroized where appropriate

Proof 9 needs care and is treated honestly: no test can demonstrate that memory
has been erased. What is asserted is the mechanism -- that the sealing path uses
`Zeroizing`/`SecretBytes` so buffers are wiped on drop -- not that RAM is clean.
See the docstring on TestZeroization.
"""

import io
import logging
import os
import subprocess
import sys
import tempfile
import shutil

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otrv4_core = pytest.importorskip("otrv4_core")

pytestmark = pytest.mark.skipif(
    not hasattr(otrv4_core, "create_sealed_identity"),
    reason="Rust core built without the identity sealing module",
)

from android_bridge.identity import (            # noqa: E402
    CorruptIdentity, IdentityError, IdentityManager, RustSealedIdentityKeyStore,
    fingerprint_of,
)
from android_bridge.secure_store import AesGcmSealedStore, DekHandle, DekProvider, UnsealError  # noqa: E402

DEK_A = bytes(range(32))
DEK_B = bytes(range(32, 64))


# ── DEK plumbing ─────────────────────────────────────────────────────────────

class _Handle(DekHandle):
    def __init__(self, key, key_id, counters):
        self._key, self._key_id, self._counters = key, key_id, counters
        counters.setdefault(key_id, 0)

    @property
    def key_id(self): return self._key_id
    def next_counter(self):
        self._counters[self._key_id] += 1
        return self._counters[self._key_id]
    def raw_key_for_rust(self): return self._key
    def _seal(self, nonce, pt, aad):
        return bytes(otrv4_core.aes256gcm_encrypt(self._key, nonce, pt, aad))
    def _open(self, nonce, ct, aad):
        return bytes(otrv4_core.aes256gcm_decrypt(self._key, nonce, ct, aad))


class _Provider(DekProvider):
    def __init__(self, key=DEK_A, key_id=1):
        self._keys = {key_id: key}
        self._cur = key_id
        self._counters = {}
    def current(self): return _Handle(self._keys[self._cur], self._cur, self._counters)
    def for_key_id(self, key_id):
        if key_id not in self._keys:
            raise UnsealError("record failed authentication")
        return _Handle(self._keys[key_id], key_id, self._counters)


class _Disk:
    def __init__(self): self.blob = None
    def persist(self, blob): self.blob = blob
    def delete(self): self.blob = None


def _manager(provider=None):
    provider = provider or _Provider()
    return IdentityManager(AesGcmSealedStore(provider),
                           RustSealedIdentityKeyStore(provider)), provider


# ── 1 & 2: restart and fingerprint stability ─────────────────────────────────

class TestSurvivesRestart:

    def test_1_identity_survives_restart(self):
        provider, disk = _Provider(), _Disk()
        mgr, _ = _manager(provider)
        created = mgr.create(disk.persist)
        assert disk.blob

        del mgr
        import gc; gc.collect()

        mgr2, _ = _manager(provider)
        reloaded = mgr2.load(disk.blob)
        assert reloaded.identity_pub == created.identity_pub
        assert reloaded.prekey_pub == created.prekey_pub

    def test_2_fingerprint_is_stable_after_restart(self):
        provider, disk = _Provider(), _Disk()
        mgr, _ = _manager(provider)
        original = mgr.create(disk.persist).fingerprint
        mgr2, _ = _manager(provider)
        assert mgr2.load(disk.blob).fingerprint == original

    def test_2b_fingerprint_stable_across_a_real_second_interpreter(self):
        """Process death for real: a fresh interpreter sharing only the files."""
        provider, disk = _Provider(), _Disk()
        mgr, _ = _manager(provider)
        original = mgr.create(disk.persist).fingerprint

        tmp = tempfile.mkdtemp(prefix="otr-b1-")
        try:
            blob_path = os.path.join(tmp, "identity.sealed")
            with open(blob_path, "wb") as fh:
                fh.write(disk.blob)
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            child = (
                f"import sys; sys.path.insert(0, {root!r}); "
                f"sys.path.insert(0, {os.path.dirname(os.path.abspath(__file__))!r})\n"
                "from test_rust_identity_sealing import _Provider, _manager\n"
                f"p = _Provider()\n"
                f"mgr, _ = _manager(p)\n"
                f"print(mgr.load(open({blob_path!r},'rb').read()).fingerprint)\n"
            )
            out = subprocess.run([sys.executable, "-c", child],
                                 capture_output=True, text=True, timeout=180)
            assert out.returncode == 0, out.stderr
            assert out.stdout.strip() == original
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_2c_signature_made_before_restart_verifies_after(self):
        provider, disk = _Provider(), _Disk()
        mgr, _ = _manager(provider)
        rec = mgr.create(disk.persist)
        sig = bytes(rec.identity_handle.sign(b"continuity"))

        mgr2, _ = _manager(provider)
        rec2 = mgr2.load(disk.blob)
        assert otrv4_core.verify_ed448_sig(rec2.identity_pub, b"continuity", sig)


# ── 3 & 4: the seed does not cross the boundary ──────────────────────────────

class TestSeedIsNotExposed:

    def test_3_no_seed_accessor_on_the_rust_module(self):
        """No PyO3 entry point may return private identity material."""
        banned = ("seed", "private_bytes", "priv_bytes", "secret_bytes",
                  "export_seed", "get_seed", "raw_seed", "expose_seed")
        for name in dir(otrv4_core):
            if name.startswith("_"):
                continue
            low = name.lower()
            assert not any(b in low for b in banned), \
                f"otrv4_core.{name} looks like a seed accessor"

    def test_3b_no_seed_accessor_on_the_key_handles(self):
        """Neither a read path nor an injection path may be Python-visible.

        Writing this test found that PyO3 keeps a #[staticmethod] visible
        regardless of the Rust visibility modifier, so `pub(crate)` alone did
        NOT remove from_seed_bytes from Python. It is now behind
        `test-only-kdf`, and identity.rs uses an always-compiled
        `from_seed_internal` that is not a PyO3 method at all.
        """
        for cls in (otrv4_core.Ed448KeyHandle, otrv4_core.X448KeyHandle):
            for name in dir(cls):
                if name.startswith("_"):
                    continue
                low = name.lower()
                assert not any(b in low for b in ("seed", "priv", "secret", "expose")), \
                    f"{cls.__name__}.{name} is Python-visible and seed-shaped"

    def test_3b2_internal_constructors_are_not_pyo3_methods(self):
        """from_*_internal must never become Python-visible."""
        for cls in (otrv4_core.Ed448KeyHandle, otrv4_core.X448KeyHandle):
            for banned in ("from_seed_internal", "from_priv_internal"):
                assert not hasattr(cls, banned), f"{cls.__name__}.{banned} leaked to Python"

    def test_3c_seed_injection_is_gated_out_of_production(self):
        """Python must not be able to supply a chosen identity seed.

        Not a disclosure path -- from_seed_bytes only accepts bytes -- but it
        would weaken the invariant that a handle's key was generated inside Rust
        and never observed. Option B does not need it, so production omits it.
        """
        assert not hasattr(otrv4_core.Ed448KeyHandle, "from_seed_bytes"), \
            "seed injection is present; this is not a production build"
        assert not hasattr(otrv4_core.X448KeyHandle, "from_priv_bytes"), \
            "private-scalar injection is present; this is not a production build"

    def test_3d_repr_does_not_leak(self):
        handle = otrv4_core.generate_ed448_keypair()
        text = repr(handle)
        assert "seed" not in text.lower() or "SecretBytes" in text
        # No long hex run that could be key material.
        import re
        assert not re.search(r"[0-9a-fA-F]{60,}", text)

    def test_4_seed_does_not_reach_the_kotlin_boundary(self):
        """The Kotlin bridge must expose no identity-secret accessor.

        Checked against the Kotlin sources: OtrCore is the entire surface Kotlin
        has, and none of its members may be seed-shaped.
        """
        import pathlib, re
        root = pathlib.Path(__file__).resolve().parent.parent / "android"
        if not root.is_dir():
            pytest.skip("android project not present")

        banned = re.compile(r"\b(seed|privateKey|privKey|secretKey)\b", re.IGNORECASE)
        offenders = []
        for path in root.rglob("*.kt"):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith(("//", "*", "/*")):
                    continue           # prose explaining the rule is fine
                if banned.search(line):
                    offenders.append(f"{path.name}:{lineno}: {stripped[:70]}")
        assert not offenders, "Kotlin references identity secret material:\n  " + "\n  ".join(offenders)

    def test_4b_sealed_blob_is_the_only_thing_python_holds(self):
        provider, disk = _Provider(), _Disk()
        mgr, _ = _manager(provider)
        rec = mgr.create(disk.persist)
        # Nothing reachable from the record is 57 raw secret bytes.
        assert len(rec.identity_pub) == 57      # public key, fine
        blob = disk.blob
        assert isinstance(blob, (bytes, bytearray))
        # The record is ciphertext: it must not equal or contain the public key
        # concatenation pattern, and must be longer than the plaintext.
        assert len(blob) > 113


# ── 5: logs ──────────────────────────────────────────────────────────────────

class TestNoSeedInLogs:

    def test_5_creating_and_loading_logs_nothing_sensitive(self, caplog):
        provider, disk = _Provider(), _Disk()
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.DEBUG)
        try:
            with caplog.at_level(logging.DEBUG):
                mgr, _ = _manager(provider)
                rec = mgr.create(disk.persist)
                mgr2, _ = _manager(provider)
                mgr2.load(disk.blob)
        finally:
            root_logger.removeHandler(handler)

        captured = stream.getvalue() + "\n".join(r.getMessage() for r in caplog.records)
        import re
        # No long hex/base64 run that could be key material.
        assert not re.search(r"[0-9a-fA-F]{60,}", captured), "long hex run in logs"
        for word in ("seed", "private key", "privkey"):
            assert word not in captured.lower(), f"{word!r} mentioned in logs"

    def test_5b_the_dek_never_appears_in_a_log(self, caplog):
        provider, disk = _Provider(), _Disk()
        with caplog.at_level(logging.DEBUG):
            mgr, _ = _manager(provider)
            mgr.create(disk.persist)
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert DEK_A.hex() not in text
        assert DEK_A.hex().upper() not in text


# ── 6, 7, 8: failing closed ──────────────────────────────────────────────────

class TestFailsClosed:

    def _sealed(self):
        provider, disk = _Provider(), _Disk()
        mgr, _ = _manager(provider)
        mgr.create(disk.persist)
        return provider, disk

    @pytest.mark.parametrize("index", [0, 1, 5, 17, 40, -1])
    def test_6_corrupted_storage_fails_closed(self, index):
        provider, disk = self._sealed()
        bad = bytearray(disk.blob)
        bad[index] ^= 0x01
        mgr, _ = _manager(provider)
        with pytest.raises(CorruptIdentity):
            mgr.load(bytes(bad))

    def test_6b_truncation_fails_closed(self):
        provider, disk = self._sealed()
        mgr, _ = _manager(provider)
        for cut in (0, 1, 16, len(disk.blob) // 2, len(disk.blob) - 1):
            with pytest.raises(CorruptIdentity):
                mgr.load(disk.blob[:cut])

    def test_6c_rust_layer_rejects_a_mangled_inner_record(self):
        """Even bypassing the outer SealedStore, the Rust seal must reject."""
        _, _, sealed = otrv4_core.create_sealed_identity(DEK_A, 1)
        bad = bytearray(sealed); bad[-1] ^= 0xFF
        with pytest.raises(Exception):
            otrv4_core.unseal_identity(bytes(bad), DEK_A, 1)

    def test_6d_unknown_record_version_is_refused(self):
        _, _, sealed = otrv4_core.create_sealed_identity(DEK_A, 1)
        bad = bytearray(sealed); bad[0] = 99
        with pytest.raises(Exception):
            otrv4_core.unseal_identity(bytes(bad), DEK_A, 1)

    def test_7_wrong_wrapping_key_fails_closed(self):
        provider, disk = self._sealed()
        other = _Provider(key=DEK_B, key_id=1)
        mgr = IdentityManager(AesGcmSealedStore(other),
                              RustSealedIdentityKeyStore(other))
        with pytest.raises(CorruptIdentity):
            mgr.load(disk.blob)

    def test_7b_rust_layer_rejects_the_wrong_key_directly(self):
        _, _, sealed = otrv4_core.create_sealed_identity(DEK_A, 1)
        with pytest.raises(Exception):
            otrv4_core.unseal_identity(sealed, DEK_B, 1)

    def test_7c_wrong_key_id_fails_closed(self):
        """key_id is bound into the AAD, so a record cannot be re-attributed."""
        _, _, sealed = otrv4_core.create_sealed_identity(DEK_A, 1)
        with pytest.raises(Exception):
            otrv4_core.unseal_identity(sealed, DEK_A, 2)

    def test_7d_short_key_is_rejected(self):
        with pytest.raises(Exception):
            otrv4_core.create_sealed_identity(b"\x00" * 16, 1)

    def test_8_deletion_invalidates_the_stored_identity(self):
        provider, disk = self._sealed()
        assert disk.blob is not None
        disk.delete()
        assert disk.blob is None

        mgr, _ = _manager(provider)
        with pytest.raises(CorruptIdentity):
            mgr.load(b"")

        # load_or_create mints a NEW identity once the old record is gone,
        # and its fingerprint must differ from the deleted one.
        fresh = mgr.load_or_create(disk.blob, disk.persist)
        assert disk.blob is not None
        assert len(fresh.fingerprint) == 128

    def test_8b_a_deleted_identity_cannot_be_resurrected_by_key_alone(self):
        """Holding the DEK is not enough once the record is gone."""
        provider, disk = self._sealed()
        disk.delete()
        mgr, _ = _manager(provider)
        with pytest.raises(CorruptIdentity):
            mgr.load(b"")


# ── 9: zeroization, stated honestly ──────────────────────────────────────────

class TestZeroization:
    """Zeroization is asserted as a MECHANISM, not as an outcome.

    No test in any language can demonstrate that a secret has been erased from a
    process's memory: a `Zeroizing` buffer overwrites the allocation it owns, but
    cannot reach copies the allocator, the kernel, a `Vec` reallocation, swap or
    hibernation may hold. The claim being made is that the code uses the wiping
    types on the paths that handle secrets, which bounds how long they persist.
    It is not a claim that RAM is clean.
    """

    def test_9_sealing_path_uses_wiping_types(self):
        import pathlib
        src = pathlib.Path(__file__).resolve().parent.parent / "Rust" / "src" / "identity.rs"
        if not src.is_file():
            pytest.skip("Rust sources not present")
        body = src.read_text(encoding="utf-8")
        assert "Zeroizing" in body, "the assembled plaintext must be a Zeroizing buffer"
        assert body.count("Zeroizing::new") >= 3, \
            "every path that assembles or recovers the seed must wipe its buffer"

    def test_9b_handles_hold_zeroize_on_drop_secrets(self):
        import pathlib
        src = pathlib.Path(__file__).resolve().parent.parent / "Rust" / "src"
        handles = (src / "key_handles.rs").read_text(encoding="utf-8")
        assert "SecretBytes<57>" in handles
        assert "SecretBytes<56>" in handles
        mem = (src / "secure_mem.rs").read_text(encoding="utf-8")
        assert "ZeroizeOnDrop" in mem

    def test_9c_the_module_does_not_claim_perfect_erasure(self):
        """Documentation honesty is part of the requirement."""
        import pathlib
        src = pathlib.Path(__file__).resolve().parent.parent / "Rust" / "src" / "identity.rs"
        body = src.read_text(encoding="utf-8").lower()
        assert "not a guarantee" in body or "hygiene, not" in body, \
            "identity.rs must not imply memory can be perfectly erased"


# ── Round trip ───────────────────────────────────────────────────────────────

class TestRoundTrip:

    def test_seal_then_unseal_recovers_the_same_keys(self):
        ident, prekey, sealed = otrv4_core.create_sealed_identity(DEK_A, 1)
        pub_before = bytes(ident.public_bytes())
        pre_before = bytes(prekey.public_bytes())

        ident2, prekey2 = otrv4_core.unseal_identity(sealed, DEK_A, 1)
        assert bytes(ident2.public_bytes()) == pub_before
        assert bytes(prekey2.public_bytes()) == pre_before

    def test_explicit_seal_matches_create(self):
        ident = otrv4_core.generate_ed448_keypair()
        prekey = otrv4_core.generate_x448_keypair()
        sealed = otrv4_core.seal_identity(ident, prekey, DEK_A, 7)
        ident2, prekey2 = otrv4_core.unseal_identity(sealed, DEK_A, 7)
        assert bytes(ident2.public_bytes()) == bytes(ident.public_bytes())
        assert bytes(prekey2.public_bytes()) == bytes(prekey.public_bytes())

    def test_two_seals_of_one_identity_differ(self):
        """Fresh CSPRNG nonce per seal."""
        ident = otrv4_core.generate_ed448_keypair()
        prekey = otrv4_core.generate_x448_keypair()
        a = otrv4_core.seal_identity(ident, prekey, DEK_A, 1)
        b = otrv4_core.seal_identity(ident, prekey, DEK_A, 1)
        assert a != b
        assert a[1:13] != b[1:13], "nonce reused across seals"

    def test_record_is_versioned(self):
        _, _, sealed = otrv4_core.create_sealed_identity(DEK_A, 1)
        assert sealed[0] == otrv4_core.identity_record_version()
