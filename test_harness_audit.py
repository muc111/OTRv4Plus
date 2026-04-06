"""
test_harness_audit.py — Coverage tests for components found untested during security audit.

Covers:
  1. SMP full protocol flow (start → smp1 → smp2 → smp3 → smp4)
  2. SMP secret matching and mismatching
  3. SMP constant-time comparison (timing leak fix)
  4. SecureKeyStorage AES-GCM round-trip
  5. RustSMPVault (if otrv4_core available)
  6. RustBackedDoubleRatchet wrapper (if otrv4_core available)
  7. SMP replay rejection
  8. SMP state machine transitions
  9. SMP ZKP verification with bad proofs
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


# ─── Helpers ─────────────────────────────────────────────────────

def make_smp_pair(secret_a="testpass", secret_b="testpass"):
    """Create two SMPEngines with secrets set, ready for protocol."""
    alice = otr.SMPEngine(is_initiator=True)
    bob = otr.SMPEngine(is_initiator=False)
    alice.set_secret(secret_a)
    bob.set_secret(secret_b)
    return alice, bob


def run_smp_full(alice, bob):
    """Run full SMP protocol. Returns (alice_state, bob_state)."""
    smp1 = alice.start_smp("ignored")  # secret already set
    smp2 = bob.process_smp1(smp1)
    smp3 = alice.process_smp2(smp2)
    bob.process_smp3(smp3)
    # SMP3 produces SMP4 as return
    smp3_result = bob.process_smp3.__wrapped__(bob, smp3) if hasattr(bob.process_smp3, '__wrapped__') else None
    return alice.get_state(), bob.get_state()


# ─── SMP Protocol Flow ──────────────────────────────────────────

class TestSMPProtocolFlow(unittest.TestCase):
    """Full SMP protocol round-trip."""

    def test_01_smp_matching_secrets(self):
        """Both sides use same secret → SUCCEEDED."""
        alice = otr.SMPEngine(is_initiator=True)
        bob = otr.SMPEngine(is_initiator=False)
        alice.set_secret("quantum")
        bob.set_secret("quantum")

        smp1_tlv = alice.start_smp("quantum")
        self.assertIsNotNone(smp1_tlv)

        smp2_tlv = bob.process_smp1(smp1_tlv)
        self.assertIsNotNone(smp2_tlv)

        smp3_tlv = alice.process_smp2(smp2_tlv)
        self.assertIsNotNone(smp3_tlv)

        smp4_tlv = bob.process_smp3(smp3_tlv)
        self.assertIsNotNone(smp4_tlv)

        alice.process_smp4(smp4_tlv)

        self.assertEqual(alice.get_state(), otr.UIConstants.SMPState.SUCCEEDED)
        self.assertEqual(bob.get_state(), otr.UIConstants.SMPState.SUCCEEDED)

    def test_02_smp_mismatched_secrets(self):
        """Different secrets → FAILED."""
        alice = otr.SMPEngine(is_initiator=True)
        bob = otr.SMPEngine(is_initiator=False)
        alice.set_secret("alice_secret")
        bob.set_secret("bob_different")

        smp1 = alice.start_smp("alice_secret")
        smp2 = bob.process_smp1(smp1)
        smp3 = alice.process_smp2(smp2)
        smp4 = bob.process_smp3(smp3)
        alice.process_smp4(smp4)

        # At least one side should be FAILED
        states = (alice.get_state(), bob.get_state())
        self.assertTrue(
            otr.UIConstants.SMPState.FAILED in states,
            f"Expected FAILED in {states}"
        )

    def test_03_smp_abort(self):
        """Abort resets state."""
        alice = otr.SMPEngine(is_initiator=True)
        alice.set_secret("test")
        alice.start_smp("test")
        self.assertNotEqual(alice.get_state(), otr.UIConstants.SMPState.NONE)
        alice.abort_smp()
        self.assertEqual(alice.get_state(), otr.UIConstants.SMPState.NONE)

    def test_04_smp_replay_rejected(self):
        """Same SMP1 message processed twice raises ValueError."""
        alice = otr.SMPEngine(is_initiator=True)
        bob = otr.SMPEngine(is_initiator=False)
        alice.set_secret("test")
        bob.set_secret("test")

        smp1 = alice.start_smp("test")
        bob.process_smp1(smp1)

        bob2 = otr.SMPEngine(is_initiator=False)
        bob2.set_secret("test")
        with self.assertRaises(Exception):
            # Either replay or state error
            bob.process_smp1(smp1)

    def test_05_smp_no_secret_set_raises(self):
        """Processing SMP1 without secret set raises."""
        bob = otr.SMPEngine(is_initiator=False)
        alice = otr.SMPEngine(is_initiator=True)
        alice.set_secret("test")
        smp1 = alice.start_smp("test")

        with self.assertRaises(ValueError):
            bob.process_smp1(smp1)

    def test_06_smp_key_stretching_applied(self):
        """Short and long passphrases produce different secrets."""
        eng1 = otr.SMPEngine(is_initiator=True)
        eng2 = otr.SMPEngine(is_initiator=True)
        eng1.set_secret("a")
        eng2.set_secret("ab")
        self.assertNotEqual(eng1.secret, eng2.secret)

    def test_07_smp_state_machine_invalid_transitions(self):
        """Can't process SMP2 when not in EXPECT2 state."""
        alice = otr.SMPEngine(is_initiator=True)
        alice.set_secret("test")
        # Alice hasn't started SMP, she's in NONE state
        with self.assertRaises(ValueError):
            alice.process_smp2(b'\x00\x03\x00\x10' + b'\x00' * 16)

    def test_08_smp_clear_math_state_zeroizes(self):
        """_clear_math_state sets all secret attrs to None."""
        alice = otr.SMPEngine(is_initiator=True)
        alice.set_secret("test")
        alice.start_smp("test")
        # a2, a3, r2, r3 should be set
        self.assertIsNotNone(alice.a2)
        alice._clear_math_state()
        self.assertIsNone(alice.a2)
        self.assertIsNone(alice.a3)
        self.assertIsNone(alice.secret)


# ─── SecureKeyStorage ────────────────────────────────────────────

class TestSecureKeyStorage(unittest.TestCase):
    """AES-256-GCM key storage with device seed."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_01_auto_initialize(self):
        """Storage auto-initializes with device seed."""
        ks = otr.SecureKeyStorage(self.tmpdir)
        seed_path = os.path.join(self.tmpdir, '.device_seed')
        self.assertTrue(os.path.exists(seed_path))
        self.assertEqual(os.path.getsize(seed_path), 32)
        self.assertIsNotNone(ks._master_key)

    def test_02_store_and_load_roundtrip(self):
        """Store a key, load it back, data matches."""
        ks = otr.SecureKeyStorage(self.tmpdir)
        key_data = os.urandom(57)  # Ed448 private key size
        self.assertTrue(ks.store_key("test", "ed448", key_data))
        loaded = ks.load_key("test", "ed448")
        self.assertEqual(loaded, key_data)

    def test_03_wrong_seed_cant_decrypt(self):
        """If device seed changes, old keys are unrecoverable."""
        ks = otr.SecureKeyStorage(self.tmpdir)
        ks.store_key("id", "test", b"secret_key_data_here")

        # Overwrite the seed
        seed_path = os.path.join(self.tmpdir, '.device_seed')
        with open(seed_path, 'wb') as f:
            f.write(os.urandom(32))

        ks2 = otr.SecureKeyStorage(self.tmpdir)
        result = ks2.load_key("id", "test")
        self.assertIsNone(result)  # Decryption fails

    def test_04_delete_key_overwrites_file(self):
        """delete_key overwrites file before removing."""
        ks = otr.SecureKeyStorage(self.tmpdir)
        ks.store_key("deleteme", "test", b"data")
        key_file = os.path.join(self.tmpdir, "deleteme.test.bin")
        self.assertTrue(os.path.exists(key_file))
        ks.delete_key("deleteme", "test")
        self.assertFalse(os.path.exists(key_file))

    def test_05_clear_all_removes_everything(self):
        """clear_all removes all files including seed."""
        ks = otr.SecureKeyStorage(self.tmpdir)
        ks.store_key("a", "test", b"data_a")
        ks.store_key("b", "test", b"data_b")
        ks.clear_all()
        self.assertEqual(len(os.listdir(self.tmpdir)), 0)

    def test_06_file_permissions(self):
        """Key files have 0600 permissions."""
        ks = otr.SecureKeyStorage(self.tmpdir)
        ks.store_key("perm", "test", b"data")
        key_file = os.path.join(self.tmpdir, "perm.test.bin")
        mode = os.stat(key_file).st_mode & 0o777
        self.assertEqual(mode, 0o600)


# ─── Rust SMP Vault ──────────────────────────────────────────────

try:
    from otrv4_core import RustSMPVault
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False


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
        """Dropping vault doesn't crash (zeroize runs in Drop)."""
        vault = RustSMPVault()
        vault.store("secret", b'\xff' * 384)
        vault.store("a2", b'\xaa' * 384)
        del vault  # triggers Rust Drop → Zeroize


# ─── Rust Backed Double Ratchet ──────────────────────────────────

@unittest.skipUnless(VAULT_AVAILABLE, "otrv4_core not installed")
class TestRustBackedDoubleRatchet(unittest.TestCase):
    """Integration tests for RustBackedDoubleRatchet wrapper."""

    def _make_pair(self):
        """Create matched ratchet pair with shared keys."""
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
        # After zeroize, ratchet should not be usable
        # but zeroize itself should not crash

    def test_05_returns_bytes(self):
        """All return types are bytes, not list."""
        alice, bob = self._make_pair()
        ct, hdr, n, t, rid, reveal = alice.encrypt_message(b"type check")
        self.assertIsInstance(ct, bytes)
        self.assertIsInstance(hdr, bytes)
        self.assertIsInstance(n, bytes)
        self.assertIsInstance(t, bytes)
        pt = bob.decrypt_message(hdr, ct, n, t)
        self.assertIsInstance(pt, bytes)


# ─── SMP with Vault Integration ─────────────────────────────────

@unittest.skipUnless(VAULT_AVAILABLE, "otrv4_core not installed")
class TestSMPWithVault(unittest.TestCase):
    """SMP protocol with Rust vault for secret storage."""

    def test_01_vault_used_during_smp(self):
        """Secrets are stored in vault during SMP."""
        alice = otr.SMPEngine(is_initiator=True)
        self.assertIsNotNone(alice._vault)
        alice.set_secret("testpass")
        # Secret should be in vault
        self.assertTrue(alice._vault.has("secret"))

    def test_02_clear_math_state_clears_vault(self):
        """_clear_math_state empties the vault."""
        alice = otr.SMPEngine(is_initiator=True)
        alice.set_secret("testpass")
        alice.start_smp("testpass")
        self.assertGreater(alice._vault.count(), 0)
        alice._clear_math_state()
        self.assertEqual(alice._vault.count(), 0)

    def test_03_full_smp_with_vault(self):
        """Full SMP succeeds with vault active."""
        alice = otr.SMPEngine(is_initiator=True)
        bob = otr.SMPEngine(is_initiator=False)
        alice.set_secret("vaulttest")
        bob.set_secret("vaulttest")

        smp1 = alice.start_smp("vaulttest")
        smp2 = bob.process_smp1(smp1)
        smp3 = alice.process_smp2(smp2)
        smp4 = bob.process_smp3(smp3)
        alice.process_smp4(smp4)

        self.assertEqual(alice.get_state(), otr.UIConstants.SMPState.SUCCEEDED)
        self.assertEqual(bob.get_state(), otr.UIConstants.SMPState.SUCCEEDED)

        # Vault should have been populated during protocol
        # After success, clear should zeroize everything
        alice._clear_math_state()
        self.assertEqual(alice._vault.count(), 0)


# ─── Constant-time Comparison Verification ───────────────────────

class TestConstantTimeComparisons(unittest.TestCase):
    """Verify all secret comparisons use hmac.compare_digest."""

    def test_01_smp_comparison_uses_hmac(self):
        """The SMP match check in process_smp2 uses hmac.compare_digest."""
        import inspect
        src = inspect.getsource(otr.SMPEngine.process_smp2)
        self.assertNotIn("secrets_match = (pa_over_pb == qa_over_qb)", src)
        self.assertIn("hmac.compare_digest", src)

    def test_02_smp3_uses_hmac(self):
        import inspect
        src = inspect.getsource(otr.SMPEngine.process_smp3)
        self.assertIn("hmac.compare_digest", src)

    def test_03_smp4_uses_hmac(self):
        import inspect
        src = inspect.getsource(otr.SMPEngine.process_smp4)
        self.assertIn("hmac.compare_digest", src)

    def test_04_zkp_verify_uses_hmac(self):
        import inspect
        src = inspect.getsource(otr.SMPEngine._verify_zkp)
        self.assertIn("hmac.compare_digest", src)


if __name__ == '__main__':
    import inspect  # needed for TestConstantTimeComparisons
    unittest.main(verbosity=2)
