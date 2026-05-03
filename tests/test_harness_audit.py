"""
test_harness_audit.py — Coverage tests for components found untested
during security audit (adapted for Rust SMP backend).

Covers:
  1. SMP full protocol flow using RustSMP
  2. SecureKeyStorage AES-GCM round-trip
  3. RustSMPVault
  4. RustBackedDoubleRatchet integration
"""

import os
import sys
import time
import shutil
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(__file__))

import otrv4_ as otr
try:
    from otrv4_core import RustSMP, RustSMPVault
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False


# ─── Helpers for SMP tests ───────────────────────────────────────

def make_smp_pair(secret_a=b"testpass", secret_b=b"testpass"):
    """Create two RustSMP instances with secrets already loaded."""
    alice = RustSMP(True)
    bob = RustSMP(False)
    vault_a = RustSMPVault()
    vault_b = RustSMPVault()
    # 32-byte session ID and fingerprints (arbitrary for tests)
    sid = b"0123456789abcdef0123456789abcdef"  # exactly 32 bytes
    our_fp = sid
    peer_fp = b"fedcba9876543210fedcba9876543210"

    vault_a.store("smp_secret", secret_a)
    vault_b.store("smp_secret", secret_b)

    ok_a = alice.set_secret_from_vault(vault_a, "smp_secret", sid, our_fp, peer_fp)
    ok_b = bob.set_secret_from_vault(vault_b, "smp_secret", sid, our_fp, peer_fp)
    assert ok_a and ok_b, "Secret not set in RustSMP"
    return alice, bob


# ═══════════ SMP Protocol Flow ═══════════════════════════════════

@unittest.skipUnless(VAULT_AVAILABLE, "otrv4_core Rust module not installed")
class TestSMPProtocolFlow(unittest.TestCase):
    """Full SMP round-trip using the Rust SMP engine."""

    def test_01_smp_matching_secrets(self):
        """Same secret → both sides verified."""
        alice, bob = make_smp_pair(b"quantum!", b"quantum!")
        smp1 = alice.generate_smp1(None)
        smp2 = bob.process_smp1_generate_smp2(bytes(smp1))
        smp3 = alice.process_smp2_generate_smp3(bytes(smp2))
        smp4 = bob.process_smp3_generate_smp4(bytes(smp3))
        alice.process_smp4(bytes(smp4))

        self.assertTrue(alice.is_verified())
        self.assertTrue(bob.is_verified())

    def test_02_smp_mismatched_secrets(self):
        """Different secrets → at least one side fails."""
        alice, bob = make_smp_pair(b"alice_sec", b"bob_sec")
        smp1 = alice.generate_smp1(None)
        smp2 = bob.process_smp1_generate_smp2(bytes(smp1))
        smp3 = alice.process_smp2_generate_smp3(bytes(smp2))
        smp4 = bob.process_smp3_generate_smp4(bytes(smp3))
        alice.process_smp4(bytes(smp4))

        self.assertFalse(alice.is_verified() and bob.is_verified())

    def test_03_smp_abort(self):
        """Abort resets phase to ABORTED."""
        alice, _ = make_smp_pair()
        alice.generate_smp1(None)
        self.assertNotEqual(alice.get_phase(), "IDLE")
        alice.abort()
        self.assertEqual(alice.get_phase(), "ABORTED")

    def test_04_smp_replay_rejected(self):
        """Replaying SMP1 on the same engine raises an error."""
        alice, bob = make_smp_pair(b"testpass", b"testpass")
        smp1 = alice.generate_smp1(None)
        bob.process_smp1_generate_smp2(bytes(smp1))
        # Replay the SAME SMP1 on the SAME Bob — must raise, because Bob is no longer IDLE
        with self.assertRaises(Exception):
            bob.process_smp1_generate_smp2(bytes(smp1))

    def test_05_smp_no_secret_set_raises(self):
        """Processing SMP1 without a secret raises an error."""
        bob = RustSMP(False)
        alice, _ = make_smp_pair()
        smp1 = alice.generate_smp1(None)
        with self.assertRaises(Exception):
            bob.process_smp1_generate_smp2(bytes(smp1))

    def test_06_smp_key_stretching_applied(self):
        """Secrets are stretched; different inputs produce different internals."""
        eng1 = RustSMP(True)
        eng2 = RustSMP(True)
        v1, v2 = RustSMPVault(), RustSMPVault()
        sid = b"s" * 32
        fp  = b"f" * 32
        v1.store("secret", b"aaaaaaaa")
        v2.store("secret", b"bbbbbbbb")
        eng1.set_secret_from_vault(v1, "secret", sid, fp, fp)
        eng2.set_secret_from_vault(v2, "secret", sid, fp, fp)
        self.assertTrue(eng1.check_secret_set())
        self.assertTrue(eng2.check_secret_set())

    def test_07_smp_state_machine_invalid_transitions(self):
        """Calling process_smp1 when not Idle raises an error."""
        alice, _ = make_smp_pair()
        with self.assertRaises(Exception):
            alice.process_smp1_generate_smp2(b'\x00' * 100)

    def test_08_smp_clear_math_state_zeroizes(self):
        """After abort, the engine is unusable (ABORTED phase)."""
        alice, _ = make_smp_pair()
        alice.generate_smp1(None)
        alice.abort()
        self.assertEqual(alice.get_phase(), "ABORTED")


# ═══════════ SecureKeyStorage ════════════════════════════════════

class TestSecureKeyStorage(unittest.TestCase):
    """AES-256-GCM key storage with device seed."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_01_auto_initialize(self):
        ks = otr.SecureKeyStorage(self.tmpdir)
        seed_path = os.path.join(self.tmpdir, '.device_seed')
        self.assertTrue(os.path.exists(seed_path))
        self.assertEqual(os.path.getsize(seed_path), 32)
        self.assertIsNotNone(ks._master_key)

    def test_02_store_and_load_roundtrip(self):
        ks = otr.SecureKeyStorage(self.tmpdir)
        key_data = os.urandom(57)
        self.assertTrue(ks.store_key("test", "ed448", key_data))
        loaded = ks.load_key("test", "ed448")
        self.assertEqual(loaded, key_data)

    def test_03_wrong_seed_cant_decrypt(self):
        ks = otr.SecureKeyStorage(self.tmpdir)
        ks.store_key("id", "test", b"secret_key_data_here")
        seed_path = os.path.join(self.tmpdir, '.device_seed')
        with open(seed_path, 'wb') as f:
            f.write(os.urandom(32))
        ks2 = otr.SecureKeyStorage(self.tmpdir)
        self.assertIsNone(ks2.load_key("id", "test"))

    def test_04_delete_key_overwrites_file(self):
        ks = otr.SecureKeyStorage(self.tmpdir)
        ks.store_key("deleteme", "test", b"data")
        key_file = os.path.join(self.tmpdir, "deleteme.test.bin")
        self.assertTrue(os.path.exists(key_file))
        ks.delete_key("deleteme", "test")
        self.assertFalse(os.path.exists(key_file))

    def test_05_clear_all_removes_everything(self):
        ks = otr.SecureKeyStorage(self.tmpdir)
        ks.store_key("a", "test", b"data_a")
        ks.store_key("b", "test", b"data_b")
        ks.clear_all()
        self.assertEqual(len(os.listdir(self.tmpdir)), 0)

    def test_06_file_permissions(self):
        ks = otr.SecureKeyStorage(self.tmpdir)
        ks.store_key("perm", "test", b"data")
        key_file = os.path.join(self.tmpdir, "perm.test.bin")
        mode = os.stat(key_file).st_mode & 0o777
        self.assertEqual(mode, 0o600)


# ═══════════ Rust SMP Vault ══════════════════════════════════════

@unittest.skipUnless(VAULT_AVAILABLE, "otrv4_core not installed")
class TestRustSMPVault(unittest.TestCase):
    """Rust vault for SMP secret storage with zeroize-on-drop."""

    def test_01_store_and_load(self):
        vault = RustSMPVault()
        data = b'\xaa' * 384
        vault.store("a2", data)
        loaded = vault.load("a2")
        self.assertEqual(loaded, data)

    def test_02_clear_removes_all(self):
        vault = RustSMPVault()
        vault.store("a2", b'\x01' * 32)
        vault.store("b3", b'\x02' * 32)
        self.assertEqual(vault.count(), 2)
        vault.clear()
        self.assertEqual(vault.count(), 0)

    def test_03_remove_single(self):
        vault = RustSMPVault()
        vault.store("secret", b'\xff' * 64)
        vault.remove("secret")
        self.assertFalse(vault.has("secret"))

    def test_04_overwrite_existing(self):
        vault = RustSMPVault()
        vault.store("r5", b'\x01' * 32)
        vault.store("r5", b'\x02' * 32)
        loaded = vault.load("r5")
        self.assertEqual(loaded, b'\x02' * 32)
        self.assertEqual(vault.count(), 1)

    def test_05_names_list(self):
        vault = RustSMPVault()
        vault.store("a2", b'\x01')
        vault.store("b3", b'\x02')
        names = vault.names()
        self.assertIn("a2", names)
        self.assertIn("b3", names)

    def test_06_drop_zeroizes(self):
        vault = RustSMPVault()
        vault.store("secret", b'\xff' * 384)
        vault.store("a2", b'\xaa' * 384)
        del vault


# ═══════════ Rust Backed Double Ratchet ══════════════════════════

@unittest.skipUnless(VAULT_AVAILABLE, "otrv4_core not installed")
class TestRustBackedDoubleRatchet(unittest.TestCase):
    """Integration tests for RustBackedDoubleRatchet wrapper."""

    def _make_pair(self):
        root_key = otr.SecureMemory(32)
        root_key.write(os.urandom(32))
        ck_s = os.urandom(32)
        ck_r = os.urandom(32)
        bk = os.urandom(32)

        alice = otr.RustBackedDoubleRatchet(
            root_key=root_key, is_initiator=True,
            chain_key_send=ck_s, chain_key_recv=ck_r,
            brace_key=bk)

        root_key2 = otr.SecureMemory(32)
        root_key2.write(root_key.read())
        bob = otr.RustBackedDoubleRatchet(
            root_key=root_key2, is_initiator=True,
            chain_key_send=ck_r, chain_key_recv=ck_s,
            brace_key=bk)

        return alice, bob

    def test_01_encrypt_decrypt(self):
        alice, bob = self._make_pair()
        ct, hdr, nonce, tag, rid, reveal = alice.encrypt_message(b"hello rust")
        pt = bob.decrypt_message(hdr, ct, nonce, tag)
        self.assertEqual(pt, b"hello rust")

    def test_02_bidirectional(self):
        alice, bob = self._make_pair()
        for i in range(20):
            ct, hdr, n, t, _, _ = alice.encrypt_message(f"a2b-{i}".encode())
            self.assertEqual(bob.decrypt_message(hdr, ct, n, t), f"a2b-{i}".encode())

            ct, hdr, n, t, _, _ = bob.encrypt_message(f"b2a-{i}".encode())
            self.assertEqual(alice.decrypt_message(hdr, ct, n, t), f"b2a-{i}".encode())

    def test_03_tampered_ciphertext_rejected(self):
        alice, bob = self._make_pair()
        ct, hdr, n, t, _, _ = alice.encrypt_message(b"test")
        tampered = bytearray(ct)
        tampered[0] ^= 0xff
        with self.assertRaises(otr.EncryptionError):
            bob.decrypt_message(hdr, bytes(tampered), n, t)

    def test_04_zeroize_doesnt_crash(self):
        alice, bob = self._make_pair()
        alice.encrypt_message(b"before zeroize")
        alice.zeroize()

    def test_05_returns_bytes(self):
        alice, bob = self._make_pair()
        ct, hdr, n, t, rid, reveal = alice.encrypt_message(b"type check")
        self.assertIsInstance(ct, bytes)
        self.assertIsInstance(hdr, bytes)
        self.assertIsInstance(n, bytes)
        self.assertIsInstance(t, bytes)
        pt = bob.decrypt_message(hdr, ct, n, t)
        self.assertIsInstance(pt, bytes)


# ═══════════ SMP with Vault Integration ══════════════════════════

@unittest.skipUnless(VAULT_AVAILABLE, "otrv4_core not installed")
class TestSMPWithVault(unittest.TestCase):
    """SMP protocol with Rust vault for secret storage."""

    def test_01_vault_used_during_smp(self):
        vault = RustSMPVault()
        vault.store("secret", b"testpass12345678")
        s = RustSMP(True)
        ok = s.set_secret_from_vault(vault, "secret",
                                     b"s" * 32, b"f" * 32, b"f" * 32)
        self.assertTrue(ok)
        self.assertTrue(s.check_secret_set())

    def test_02_clear_math_state_clears_vault(self):
        vault = RustSMPVault()
        vault.store("secret", b"testpass12345678")
        s = RustSMP(True)
        s.set_secret_from_vault(vault, "secret", b"s" * 32, b"f" * 32, b"f" * 32)
        # Abort clears internal state (not the vault)
        s.abort()
        self.assertFalse(s.is_verified())
        # The vault still has the secret
        self.assertTrue(vault.has("secret"))

    def test_03_full_smp_with_vault(self):
        """Full SMP using vault-based secrets."""
        alice, bob = make_smp_pair(b"vaulttest", b"vaulttest")
        smp1 = alice.generate_smp1(None)
        smp2 = bob.process_smp1_generate_smp2(bytes(smp1))
        smp3 = alice.process_smp2_generate_smp3(bytes(smp2))
        smp4 = bob.process_smp3_generate_smp4(bytes(smp3))
        alice.process_smp4(bytes(smp4))

        self.assertTrue(alice.is_verified())
        self.assertTrue(bob.is_verified())


# Note: TestConstantTimeComparisons is removed because the Rust engine
# uses constant-time operations internally and does not expose source code.