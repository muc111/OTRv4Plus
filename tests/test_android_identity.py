#!/usr/bin/env python3
"""Persistent-identity tests for the Android bridge (Phase 2).

Covers the Phase 2 identity requirements: generation, persistence, fingerprint
stability across a simulated process restart, reload, and corrupt-record
rejection -- plus the at-rest properties the sealed-store interface promises
(no plaintext seed on disk, unique nonces, AAD binding, key rotation).

The doubles below live in the test suite ON PURPOSE.  `android_bridge` ships no
concrete DekProvider and no concrete IdentityKeyStore, because key custody is
Phase 4 (Android Keystore/StrongBox) and the seed-custody question is an open
security decision.  Putting the doubles here keeps them out of any production
import path while still allowing the lifecycle to be tested end to end now.
"""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otrv4_core = pytest.importorskip("otrv4_core")

# The double below rebuilds handles from a raw seed. Decision B1 (option B)
# gated Ed448KeyHandle.from_seed_bytes out of production builds, because it lets
# Python inject a chosen identity. These tests therefore run only on a
# test-only-kdf wheel; tests/test_rust_identity_sealing.py covers the same
# lifecycle against the production build, sealing inside Rust.
pytestmark = pytest.mark.skipif(
    not hasattr(otrv4_core.Ed448KeyHandle, "from_seed_bytes"),
    reason="seed injection is gated out of production builds (decision B1)",
)

from android_bridge.secure_store import (          # noqa: E402
    AesGcmSealedStore, DekHandle, DekProvider, SealError, UnsealError,
    KeyRotationRequired, MAX_RECORDS_PER_KEY, RECORD_VERSION,
)
from android_bridge.identity import (              # noqa: E402
    IdentityManager, IdentityKeyStore, CorruptIdentity, IdentityError,
    fingerprint_of, IDENTITY_RECORD_TYPE, IDENTITY_SCHEMA_VERSION,
)

ED448_SEED_LEN = 57
X448_PRIV_LEN = 56


# ── Test doubles ──────────────────────────────────────────────────────────────

class _MemoryDekHandle(DekHandle):
    """A DEK held in memory, using the real Rust AES-256-GCM.

    Stands in for the Phase 4 handle whose key is unwrapped from Android
    Keystore.  The AEAD calls are the production ones; only custody is faked.
    """

    def __init__(self, key: bytes, key_id: int, counters: dict):
        self._key = key
        self._key_id = key_id
        self._counters = counters
        self._counters.setdefault(key_id, 0)

    @property
    def key_id(self) -> int:
        return self._key_id

    def next_counter(self) -> int:
        self._counters[self._key_id] += 1
        return self._counters[self._key_id]

    def _seal(self, nonce, plaintext, aad):
        return bytes(otrv4_core.aes256gcm_encrypt(self._key, nonce, plaintext, aad))

    def _open(self, nonce, ciphertext_and_tag, aad):
        return bytes(otrv4_core.aes256gcm_decrypt(self._key, nonce, ciphertext_and_tag, aad))


class _MemoryDekProvider(DekProvider):
    """Keeps every key generation so old records stay readable after rotation."""

    def __init__(self):
        self._keys = {1: os.urandom(32)}
        self._current_id = 1
        self._counters = {}

    def current(self):
        return _MemoryDekHandle(self._keys[self._current_id], self._current_id, self._counters)

    def for_key_id(self, key_id):
        if key_id not in self._keys:
            raise UnsealError("record failed authentication")
        return _MemoryDekHandle(self._keys[key_id], key_id, self._counters)

    def rotate(self):
        self._current_id += 1
        self._keys[self._current_id] = os.urandom(32)
        return self._current_id


class _PythonSeedIdentityKeyStore(IdentityKeyStore):
    """Resolution A: seed generated in Python, handles rebuilt via from_seed_bytes.

    DEVELOPMENT/TEST ONLY.  This is the implementation whose security cost is
    described in android_bridge/identity.py -- the seed exists as a Python object
    at create and at every restore.  It is used here so the identity lifecycle
    can be tested end to end; adopting it in production requires the explicit
    decision recorded in ANDROID_PHASE2_REPORT.md.
    """

    def create(self):
        seed = os.urandom(ED448_SEED_LEN)
        priv = os.urandom(X448_PRIV_LEN)
        ident = otrv4_core.Ed448KeyHandle.from_seed_bytes(seed)
        prekey = otrv4_core.X448KeyHandle.from_priv_bytes(priv)
        return ident, prekey, seed + priv

    def restore(self, serialized):
        if len(serialized) != ED448_SEED_LEN + X448_PRIV_LEN:
            raise CorruptIdentity("identity payload wrong length")
        seed = serialized[:ED448_SEED_LEN]
        priv = serialized[ED448_SEED_LEN:]
        return (otrv4_core.Ed448KeyHandle.from_seed_bytes(seed),
                otrv4_core.X448KeyHandle.from_priv_bytes(priv))


class _Disk:
    """Stands in for Android app-private storage."""

    def __init__(self):
        self.blob = None

    def persist(self, blob):
        self.blob = blob


def _manager(provider=None, key_store=None):
    provider = provider or _MemoryDekProvider()
    store = AesGcmSealedStore(provider)
    return IdentityManager(store, key_store or _PythonSeedIdentityKeyStore()), provider


# ── Identity generation and persistence ───────────────────────────────────────

class TestIdentityGeneration:

    def test_create_produces_usable_handles_and_fingerprint(self):
        mgr, _ = _manager()
        disk = _Disk()
        rec = mgr.create(disk.persist)

        assert len(rec.identity_pub) == 57
        assert len(rec.prekey_pub) == 56
        assert len(rec.fingerprint) == 128          # SHA3-512 hex
        assert rec.fingerprint == fingerprint_of(rec.identity_pub)
        # the handle must actually work
        sig = bytes(rec.identity_handle.sign(b"probe"))
        assert len(sig) == 114
        assert otrv4_core.verify_ed448_sig(rec.identity_pub, b"probe", sig)

    def test_two_identities_differ(self):
        mgr_a, _ = _manager()
        mgr_b, _ = _manager()
        fp_a = mgr_a.create(_Disk().persist).fingerprint
        fp_b = mgr_b.create(_Disk().persist).fingerprint
        assert fp_a != fp_b


class TestFingerprintStability:
    """The Phase 2 requirement: same fingerprint after a process restart."""

    def test_fingerprint_survives_simulated_process_restart(self):
        provider = _MemoryDekProvider()
        disk = _Disk()

        # ── run 1: first launch ──
        mgr1, _ = _manager(provider)
        original = mgr1.create(disk.persist).fingerprint
        assert disk.blob, "identity must have been persisted"

        # ── process death: drop every object from run 1 ──
        del mgr1
        import gc; gc.collect()

        # ── run 2: fresh objects, same stored blob and same key custody ──
        mgr2, _ = _manager(provider)
        reloaded = mgr2.load(disk.blob)

        assert reloaded.fingerprint == original, "fingerprint must be stable across restart"

    def test_reloaded_identity_signs_verifiably(self):
        provider = _MemoryDekProvider()
        disk = _Disk()
        mgr1, _ = _manager(provider)
        rec1 = mgr1.create(disk.persist)
        msg = b"identity continuity"
        sig1 = bytes(rec1.identity_handle.sign(msg))

        mgr2, _ = _manager(provider)
        rec2 = mgr2.load(disk.blob)

        # Same private key restored: a signature made before the restart
        # verifies against the public key recovered after it.
        assert otrv4_core.verify_ed448_sig(rec2.identity_pub, msg, sig1)
        assert rec2.identity_pub == rec1.identity_pub
        assert rec2.prekey_pub == rec1.prekey_pub

    def test_repeated_restarts_keep_one_identity(self):
        provider = _MemoryDekProvider()
        disk = _Disk()
        mgr, _ = _manager(provider)
        first = mgr.create(disk.persist).fingerprint
        for _ in range(5):
            mgr_n, _ = _manager(provider)
            assert mgr_n.load_or_create(disk.blob, disk.persist).fingerprint == first

    def test_created_at_is_preserved(self):
        provider = _MemoryDekProvider()
        disk = _Disk()
        mgr1, _ = _manager(provider)
        mgr1.create(disk.persist, now=1_700_000_000)
        mgr2, _ = _manager(provider)
        assert mgr2.load(disk.blob).created_at == 1_700_000_000


class TestProcessDeath:
    """A real second process, not just fresh objects in this one.

    The in-process test above drops the Python objects but keeps the
    interpreter, so it cannot prove that nothing is being carried in module
    state, a cache, or a live Rust handle.  This one re-derives the identity in
    a separate interpreter that shares nothing but the two files on disk --
    which is what Android process death actually looks like.
    """

    def test_fingerprint_identical_in_a_fresh_interpreter(self):
        import subprocess, textwrap, tempfile, shutil, pathlib
        # NB: not pytest's tmp_path -- conftest.py stubs the `pwd` module, which
        # breaks the getpass.getuser() call that fixture makes.
        tmp_path = pathlib.Path(tempfile.mkdtemp(prefix='otr-identity-'))
        self.addCleanup_dir = tmp_path

        provider = _MemoryDekProvider()
        disk = _Disk()
        mgr, _ = _manager(provider)
        original = mgr.create(disk.persist).fingerprint

        blob_path = tmp_path / "identity.sealed"
        key_path = tmp_path / "dek.bin"
        blob_path.write_bytes(disk.blob)
        # Test-only: hand the DEK over as a file so the child has the same key
        # custody.  On Android this is the Keystore-held key and never leaves the
        # device -- see android_bridge/secure_store.py.
        key_path.write_bytes(provider._keys[1])

        child = textwrap.dedent(f"""
            import sys, os
            sys.path.insert(0, {str(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))!r})
            sys.path.insert(0, {str(os.path.dirname(os.path.abspath(__file__)))!r})
            import otrv4_core
            from android_bridge.secure_store import AesGcmSealedStore
            from android_bridge.identity import IdentityManager
            from test_android_identity import _MemoryDekProvider, _PythonSeedIdentityKeyStore

            provider = _MemoryDekProvider()
            provider._keys[1] = open({str(key_path)!r}, "rb").read()
            mgr = IdentityManager(AesGcmSealedStore(provider), _PythonSeedIdentityKeyStore())
            rec = mgr.load(open({str(blob_path)!r}, "rb").read())
            print(rec.fingerprint)
        """)
        out = subprocess.run([sys.executable, "-c", child],
                             capture_output=True, text=True, timeout=120)
        try:
            assert out.returncode == 0 and out.stdout.strip() == original, \
                "fingerprint changed across process death"
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)


class TestFirstRunFlow:

    def test_load_or_create_creates_then_loads(self):
        provider = _MemoryDekProvider()
        disk = _Disk()
        mgr1, _ = _manager(provider)
        created = mgr1.load_or_create(None, disk.persist).fingerprint

        mgr2, _ = _manager(provider)
        assert mgr2.load_or_create(disk.blob, disk.persist).fingerprint == created


# ── Rejection of unusable records ─────────────────────────────────────────────

class TestCorruptIdentityRejection:

    def _sealed(self):
        provider = _MemoryDekProvider()
        disk = _Disk()
        mgr, _ = _manager(provider)
        mgr.create(disk.persist)
        return provider, disk.blob

    @pytest.mark.parametrize("index", [0, 1, 6, 20, -1])
    def test_single_bit_flip_is_rejected(self, index):
        provider, blob = self._sealed()
        bad = bytearray(blob)
        bad[index] ^= 0x01
        mgr, _ = _manager(provider)
        with pytest.raises(CorruptIdentity):
            mgr.load(bytes(bad))

    def test_truncation_is_rejected(self):
        provider, blob = self._sealed()
        mgr, _ = _manager(provider)
        for cut in (0, 1, 8, len(blob) // 2, len(blob) - 1):
            with pytest.raises(CorruptIdentity):
                mgr.load(blob[:cut])

    def test_empty_record_is_rejected(self):
        provider, _ = self._sealed()
        mgr, _ = _manager(provider)
        with pytest.raises(CorruptIdentity):
            mgr.load(b"")

    def test_record_from_a_different_key_is_rejected(self):
        _, blob = self._sealed()
        other, _ = _manager()                      # unrelated key custody
        with pytest.raises(CorruptIdentity):
            other.load(blob)

    def test_record_id_is_bound(self):
        """A record sealed as 'primary' must not open as another identity slot."""
        provider = _MemoryDekProvider()
        disk = _Disk()
        store = AesGcmSealedStore(provider)
        IdentityManager(store, _PythonSeedIdentityKeyStore(), record_id="primary") \
            .create(disk.persist)

        impostor = IdentityManager(AesGcmSealedStore(provider),
                                   _PythonSeedIdentityKeyStore(), record_id="secondary")
        with pytest.raises(CorruptIdentity):
            impostor.load(disk.blob)

    def test_load_or_create_does_not_silently_replace_a_bad_record(self):
        """Tampering must surface, not quietly mint a new identity."""
        provider, blob = self._sealed()
        bad = bytearray(blob); bad[-1] ^= 0xFF
        mgr, _ = _manager(provider)
        with pytest.raises(CorruptIdentity):
            mgr.load_or_create(bytes(bad), _Disk().persist)


# ── At-rest properties ────────────────────────────────────────────────────────

class TestAtRestProperties:

    def test_seed_never_appears_in_the_sealed_record(self):
        """The strongest available check that nothing is stored in the clear."""
        provider = _MemoryDekProvider()
        store = AesGcmSealedStore(provider)

        captured = {}
        class _CapturingKeyStore(_PythonSeedIdentityKeyStore):
            def create(self):
                ident, prekey, serialized = super().create()
                captured["serialized"] = serialized
                return ident, prekey, serialized

        disk = _Disk()
        IdentityManager(store, _CapturingKeyStore()).create(disk.persist)

        seed = captured["serialized"]
        assert seed not in disk.blob, "serialized private material found verbatim on disk"
        # and no substantial run of it either
        for start in range(0, len(seed) - 8):
            assert seed[start:start + 8] not in disk.blob, "private material leaked into record"

    def test_record_is_versioned_and_carries_key_id(self):
        provider = _MemoryDekProvider()
        disk = _Disk()
        mgr, _ = _manager(provider)
        mgr.create(disk.persist)
        assert disk.blob[0] == RECORD_VERSION
        assert struct.unpack(">I", disk.blob[1:5])[0] == 1     # first key generation

    def test_nonces_are_unique_across_many_records(self):
        provider = _MemoryDekProvider()
        store = AesGcmSealedStore(provider)
        nonces = set()
        for i in range(2000):
            blob = store.seal("t", f"r{i}", 1, b"payload")
            nonces.add(blob[5:17])
        assert len(nonces) == 2000, "nonce reuse detected"

    def test_nonce_is_random_not_sequential(self):
        """The spec requires a CSPRNG nonce per operation, not a counter.

        A counter-derived nonce would show as a monotonic low-order run and as
        a mostly-constant high half; random ones do neither.
        """
        provider = _MemoryDekProvider()
        store = AesGcmSealedStore(provider)
        nonces = [store.seal("t", f"r{i}", 1, b"x")[5:17] for i in range(64)]

        as_ints = [int.from_bytes(n, "big") for n in nonces]
        assert as_ints != sorted(as_ints), "nonces look sequential"
        # A counter nonce keeps the leading bytes fixed; random nonces vary.
        assert len({n[:4] for n in nonces}) > 32, "nonce high bytes look fixed"

    def test_identical_plaintext_seals_differently(self):
        """Same key, same plaintext, same AAD must still give distinct records."""
        store = AesGcmSealedStore(_MemoryDekProvider())
        a = store.seal("t", "r", 1, b"identical payload")
        b = store.seal("t", "r", 1, b"identical payload")
        assert a != b
        assert a[5:17] != b[5:17], "nonce reused for identical input"
        assert store.unseal("t", "r", 1, a) == store.unseal("t", "r", 1, b)

    def test_rotation_bound_matches_the_nist_random_nonce_limit(self):
        assert MAX_RECORDS_PER_KEY == 2 ** 32

    def test_seal_refuses_past_the_rotation_bound(self):
        """Reaching the analysed bound must be loud, not a silent continuation."""
        provider = _MemoryDekProvider()
        store = AesGcmSealedStore(provider)
        # Fast-forward the usage meter rather than sealing 2^32 records.
        provider._counters[1] = MAX_RECORDS_PER_KEY
        with pytest.raises(KeyRotationRequired):
            store.seal("t", "r", 1, b"one too many")

        # Rotating clears the condition and old records stay readable.
        provider.rotate()
        fresh = store.seal("t", "r", 1, b"after rotation")
        assert store.unseal("t", "r", 1, fresh) == b"after rotation"

    def test_aad_binds_record_type_and_id(self):
        provider = _MemoryDekProvider()
        store = AesGcmSealedStore(provider)
        blob = store.seal("type.a", "id.a", 1, b"secret payload")

        assert store.unseal("type.a", "id.a", 1, blob) == b"secret payload"
        for args in (("type.b", "id.a", 1), ("type.a", "id.b", 1), ("type.a", "id.a", 2)):
            with pytest.raises(UnsealError):
                store.unseal(*args, blob)

    def test_aad_field_boundaries_cannot_be_shifted(self):
        """('ab','c') and ('a','bc') must not produce interchangeable records."""
        provider = _MemoryDekProvider()
        store = AesGcmSealedStore(provider)
        blob = store.seal("ab", "c", 1, b"x")
        with pytest.raises(UnsealError):
            store.unseal("a", "bc", 1, blob)

    def test_rotated_key_still_reads_old_records(self):
        provider = _MemoryDekProvider()
        store = AesGcmSealedStore(provider)
        old = store.seal("t", "r", 1, b"before rotation")

        new_id = provider.rotate()
        fresh = store.seal("t", "r", 1, b"after rotation")

        assert struct.unpack(">I", fresh[1:5])[0] == new_id
        assert store.unseal("t", "r", 1, old) == b"before rotation"
        assert store.unseal("t", "r", 1, fresh) == b"after rotation"

    def test_unknown_record_version_is_refused(self):
        provider = _MemoryDekProvider()
        store = AesGcmSealedStore(provider)
        blob = bytearray(store.seal("t", "r", 1, b"x"))
        blob[0] = 99
        with pytest.raises(UnsealError):
            store.unseal("t", "r", 1, bytes(blob))


# ── Fail-closed wiring ────────────────────────────────────────────────────────

class TestNoInsecureDefaults:

    def test_sealed_store_requires_a_dek_provider(self):
        with pytest.raises(SealError):
            AesGcmSealedStore(None)

    def test_identity_manager_requires_a_store(self):
        with pytest.raises(IdentityError):
            IdentityManager(None, _PythonSeedIdentityKeyStore())

    def test_identity_manager_requires_a_key_store(self):
        with pytest.raises(IdentityError):
            IdentityManager(AesGcmSealedStore(_MemoryDekProvider()), None)

    def test_package_ships_no_concrete_key_custody(self):
        """Key CUSTODY must still come from the platform, not this package.

        Narrowed since decision B1: `RustSealedIdentityKeyStore` is now the
        approved production IdentityKeyStore and legitimately lives here, so the
        rule applies to DekProvider only. Producing the data-encryption key --
        unwrapping it from an Android Keystore key after an Argon2id-derived KEK
        opens it -- is Phase 4 and must not acquire a convenience default that
        happens to work.
        """
        import android_bridge.secure_store as ss
        import inspect

        for name, obj in vars(ss).items():
            if not inspect.isclass(obj) or obj is ss.DekProvider:
                continue
            if issubclass(obj, ss.DekProvider) and not inspect.isabstract(obj):
                pytest.fail(
                    f"android_bridge.secure_store.{name} is a concrete "
                    f"DekProvider; key custody must come from the platform"
                )

    def test_the_production_key_store_still_fails_closed(self):
        """RustSealedIdentityKeyStore must refuse to invent a key."""
        from android_bridge.identity import RustSealedIdentityKeyStore
        with pytest.raises(IdentityError):
            RustSealedIdentityKeyStore(None)


class TestFingerprintDerivation:

    def test_rejects_wrong_length_public_key(self):
        for bad in (b"", b"\x00" * 56, b"\x00" * 58):
            with pytest.raises(IdentityError):
                fingerprint_of(bad)

    def test_is_deterministic_and_public_only(self):
        pub = bytes(otrv4_core.generate_ed448_keypair().public_bytes())
        assert fingerprint_of(pub) == fingerprint_of(pub)
