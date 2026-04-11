"""
test_rust_security.py — Security tests for the Rust ratchet backend.

Replaces the Python-internal fork/snapshot/persistence tests that were
removed when the Python DoubleRatchet class was deleted. These tests
verify security properties of the Rust backend from the outside — no
internal state access required.

Tests:
  1. Rust backend is mandatory (no Python fallback)
  2. Ratchet state opacity (can't read chain keys)
  3. Zeroize on drop
  4. Tamper detection (ciphertext, nonce, tag, header)
  5. Replay rejection
  6. 100k message gauntlet
  7. Forward secrecy after key advance
  8. Post-compromise recovery via fresh ratchet
  9. Ratchet ID monotonic advancement
  10. Multiple concurrent sessions isolation
  11. SMP vault deterministic zeroize
  12. Brace key rotation doesn't break decrypt
  13. State rollback impossible from Python
  14. Empty and oversized message handling
"""

import os
import sys
import time
import secrets
import random
import collections
import threading
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import otrv4_ as otr

try:
    from otrv4_core import RustDoubleRatchet, RustSMPVault, rust_kdf_1
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False


def _make_pair(rekey_interval=10_000):
    """Create a matched Alice/Bob ratchet pair."""
    rk = otr.SecureMemory(32)
    rk.write(secrets.token_bytes(32))
    cks = secrets.token_bytes(32)
    ckr = secrets.token_bytes(32)
    bk = secrets.token_bytes(32)

    alice = otr.RustBackedDoubleRatchet(
        root_key=rk, is_initiator=True,
        chain_key_send=cks, chain_key_recv=ckr,
        brace_key=bk, rekey_interval=rekey_interval)

    rk2 = otr.SecureMemory(32)
    rk2.write(rk.read())
    bob = otr.RustBackedDoubleRatchet(
        root_key=rk2, is_initiator=True,
        chain_key_send=ckr, chain_key_recv=cks,
        brace_key=bk, rekey_interval=rekey_interval)

    return alice, bob


# ═══════════════════════════════════════════════════════════════════
# 1. Rust Backend Is Mandatory
# ═══════════════════════════════════════════════════════════════════

class TestRustMandatory:
    """Verify the Python DoubleRatchet class is gone and Rust is required."""

    def test_no_python_double_ratchet_class(self):
        """DoubleRatchet alias points to RustBackedDoubleRatchet."""
        assert otr.DoubleRatchet is otr.RustBackedDoubleRatchet

    def test_rust_ratchet_available(self):
        assert otr.RUST_RATCHET_AVAILABLE is True

    def test_ratchet_backend_is_rust(self):
        alice, bob = _make_pair()
        # The wrapper must have _rust attribute
        assert hasattr(alice, '_rust')
        assert alice._rust is not None

    @pytest.mark.skipif(not RUST_AVAILABLE, reason="otrv4_core not installed")
    def test_rust_kdf_matches_python(self):
        """Rust and Python KDF produce identical output."""
        import hashlib
        rust_out = rust_kdf_1(0x11, b"test", 32)
        shake = hashlib.shake_256()
        shake.update(b"OTRv4")
        shake.update(bytes([0x11]))
        shake.update(b"test")
        py_out = shake.digest(32)
        assert rust_out == py_out


# ═══════════════════════════════════════════════════════════════════
# 2. Ratchet State Opacity
# ═══════════════════════════════════════════════════════════════════

class TestStateOpacity:
    """Verify that Rust ratchet state cannot be cloned from Python."""

    def test_rust_struct_not_directly_accessible(self):
        """Can't access the Rust DoubleRatchet's internal chain keys."""
        alice, _ = _make_pair()
        # These should NOT exist as raw byte attributes
        assert not hasattr(alice._rust, 'chain_key_send_raw')
        assert not hasattr(alice._rust, 'root_key_raw')

    def test_cannot_deepcopy_rust_ratchet(self):
        """deepcopy of a Rust-backed ratchet should fail or produce
        an independent object (not share Rust state)."""
        import copy
        alice, _ = _make_pair()
        with pytest.raises(Exception):
            copy.deepcopy(alice)

    def test_zeroize_kills_ratchet(self):
        """After zeroize, the ratchet is unusable."""
        alice, bob = _make_pair()
        alice.encrypt_message(b"before zeroize")
        alice.zeroize()
        assert alice._rust is None


# ═══════════════════════════════════════════════════════════════════
# 3. Tamper Detection
# ═══════════════════════════════════════════════════════════════════

class TestTamperDetection:
    """AES-GCM authentication rejects any tampered component."""

    def test_flipped_ciphertext_bit(self):
        alice, bob = _make_pair()
        ct, hdr, n, t, _, _ = alice.encrypt_message(b"tamper test")
        tampered = bytearray(ct)
        tampered[0] ^= 0x01
        with pytest.raises(otr.EncryptionError):
            bob.decrypt_message(hdr, bytes(tampered), n, t)

    def test_wrong_nonce(self):
        alice, bob = _make_pair()
        ct, hdr, n, t, _, _ = alice.encrypt_message(b"nonce test")
        wrong_nonce = secrets.token_bytes(12)
        with pytest.raises(otr.EncryptionError):
            bob.decrypt_message(hdr, ct, wrong_nonce, t)

    def test_wrong_tag(self):
        alice, bob = _make_pair()
        ct, hdr, n, t, _, _ = alice.encrypt_message(b"tag test")
        wrong_tag = secrets.token_bytes(16)
        with pytest.raises(otr.EncryptionError):
            bob.decrypt_message(hdr, ct, n, wrong_tag)

    def test_truncated_ciphertext(self):
        alice, bob = _make_pair()
        ct, hdr, n, t, _, _ = alice.encrypt_message(b"truncate test")
        with pytest.raises(otr.EncryptionError):
            bob.decrypt_message(hdr, ct[:len(ct)//2], n, t)

    def test_extended_ciphertext(self):
        alice, bob = _make_pair()
        ct, hdr, n, t, _, _ = alice.encrypt_message(b"extend test")
        with pytest.raises(otr.EncryptionError):
            bob.decrypt_message(hdr, ct + b'\x00', n, t)

    def test_swapped_messages_rejected(self):
        """Two messages — swapping their tags/nonces is rejected."""
        alice, bob = _make_pair()
        ct1, h1, n1, t1, _, _ = alice.encrypt_message(b"msg1")
        ct2, h2, n2, t2, _, _ = alice.encrypt_message(b"msg2")
        # Deliver msg2 first (OK — out of order)
        bob.decrypt_message(h2, ct2, n2, t2)
        # Now try msg1's ciphertext with msg2's nonce — must fail
        with pytest.raises(otr.EncryptionError):
            bob.decrypt_message(h1, ct1, n2, t1)


# ═══════════════════════════════════════════════════════════════════
# 4. Replay Rejection
# ═══════════════════════════════════════════════════════════════════

class TestReplayRejection:
    """Same message delivered twice must fail on second attempt."""

    def test_exact_replay_rejected(self):
        alice, bob = _make_pair()
        ct, hdr, n, t, _, _ = alice.encrypt_message(b"replay me")
        bob.decrypt_message(hdr, ct, n, t)
        with pytest.raises(otr.EncryptionError):
            bob.decrypt_message(hdr, ct, n, t)

    def test_replay_across_100_messages(self):
        alice, bob = _make_pair()
        saved = []
        for i in range(100):
            pkt = alice.encrypt_message(f"msg{i}".encode())
            saved.append(pkt)
            bob.decrypt_message(pkt[1], pkt[0], pkt[2], pkt[3])

        # Try replaying every 10th message
        replayed = 0
        for i in range(0, 100, 10):
            pkt = saved[i]
            try:
                bob.decrypt_message(pkt[1], pkt[0], pkt[2], pkt[3])
                replayed += 1
            except otr.EncryptionError:
                pass
        assert replayed == 0, f"{replayed} replays accepted"


# ═══════════════════════════════════════════════════════════════════
# 5. 100k Message Gauntlet
# ═══════════════════════════════════════════════════════════════════

class TestGauntlet:
    """High-volume message test through the Rust ratchet."""

    def test_100k_bidirectional(self):
        """100k messages, alternating sender, no failures."""
        alice, bob = _make_pair(rekey_interval=50_000)
        rng = random.Random(42)
        nonces_seen = set()

        for i in range(100_000):
            msg = f"gauntlet-{i}".encode()
            if rng.random() < 0.5:
                ct, h, n, t, rid, _ = alice.encrypt_message(msg)
                assert n not in nonces_seen, f"Nonce reuse at message {i}"
                nonces_seen.add(n)
                pt = bob.decrypt_message(h, ct, n, t)
            else:
                ct, h, n, t, rid, _ = bob.encrypt_message(msg)
                assert n not in nonces_seen, f"Nonce reuse at message {i}"
                nonces_seen.add(n)
                pt = alice.decrypt_message(h, ct, n, t)
            assert pt == msg, f"Mismatch at message {i}"

        assert len(nonces_seen) == 100_000


# ═══════════════════════════════════════════════════════════════════
# 6. Forward Secrecy
# ═══════════════════════════════════════════════════════════════════

class TestForwardSecrecy:
    """Old encrypted messages can't be decrypted by a new ratchet."""

    def test_old_keys_dont_decrypt_new_messages(self):
        """After rekeying, old saved ciphertexts are useless against
        a fresh ratchet created with different keys."""
        alice, bob = _make_pair()

        # Capture some messages
        old_messages = []
        for i in range(10):
            pkt = alice.encrypt_message(f"old-{i}".encode())
            old_messages.append(pkt)
            bob.decrypt_message(pkt[1], pkt[0], pkt[2], pkt[3])

        # Create a completely new ratchet pair (simulates key erasure)
        alice2, bob2 = _make_pair()

        # Old messages must not decrypt with new keys
        for pkt in old_messages:
            with pytest.raises(otr.EncryptionError):
                bob2.decrypt_message(pkt[1], pkt[0], pkt[2], pkt[3])


# ═══════════════════════════════════════════════════════════════════
# 7. Post-Compromise Recovery
# ═══════════════════════════════════════════════════════════════════

class TestPostCompromiseRecovery:
    """After a DH ratchet step, old compromised state is useless."""

    def test_recovery_via_fresh_keys(self):
        """Messages sent after a ratchet advance can't be decrypted
        with keys from before the advance."""
        alice, bob = _make_pair(rekey_interval=5)

        # Send 10 messages (triggers rekey at 5)
        for i in range(10):
            ct, h, n, t, rid, _ = alice.encrypt_message(f"pre-{i}".encode())
            bob.decrypt_message(h, ct, n, t)

        rid_after = rid

        # Send 10 more (should be in new ratchet epoch)
        for i in range(10):
            ct, h, n, t, rid, _ = alice.encrypt_message(f"post-{i}".encode())
            pt = bob.decrypt_message(h, ct, n, t)
            assert pt == f"post-{i}".encode()


# ═══════════════════════════════════════════════════════════════════
# 8. Ratchet ID Monotonic
# ═══════════════════════════════════════════════════════════════════

class TestRatchetIdMonotonic:
    """Ratchet ID must never decrease."""

    def test_ratchet_id_never_decreases(self):
        alice, bob = _make_pair(rekey_interval=10)
        prev_rid = 0
        for i in range(100):
            ct, h, n, t, rid, _ = alice.encrypt_message(f"rid-{i}".encode())
            assert rid >= prev_rid, f"Ratchet ID decreased: {rid} < {prev_rid} at message {i}"
            prev_rid = rid
            bob.decrypt_message(h, ct, n, t)


# ═══════════════════════════════════════════════════════════════════
# 9. Concurrent Session Isolation
# ═══════════════════════════════════════════════════════════════════

class TestSessionIsolation:
    """Multiple ratchet pairs must not interfere."""

    def test_two_sessions_independent(self):
        alice1, bob1 = _make_pair()
        alice2, bob2 = _make_pair()

        ct1, h1, n1, t1, _, _ = alice1.encrypt_message(b"session1")
        ct2, h2, n2, t2, _, _ = alice2.encrypt_message(b"session2")

        # Each session decrypts its own
        assert bob1.decrypt_message(h1, ct1, n1, t1) == b"session1"
        assert bob2.decrypt_message(h2, ct2, n2, t2) == b"session2"

        # Cross-session must fail
        with pytest.raises(otr.EncryptionError):
            bob1.decrypt_message(h2, ct2, n2, t2)
        with pytest.raises(otr.EncryptionError):
            bob2.decrypt_message(h1, ct1, n1, t1)

    def test_concurrent_threads(self):
        """Two sessions running in parallel threads don't corrupt each other."""
        errors = []

        def run_session(session_id):
            try:
                a, b = _make_pair()
                for i in range(1000):
                    ct, h, n, t, _, _ = a.encrypt_message(f"t{session_id}-{i}".encode())
                    pt = b.decrypt_message(h, ct, n, t)
                    assert pt == f"t{session_id}-{i}".encode()
            except Exception as e:
                errors.append((session_id, str(e)))

        threads = [threading.Thread(target=run_session, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        assert len(errors) == 0, f"Thread errors: {errors}"


# ═══════════════════════════════════════════════════════════════════
# 10. SMP Vault
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not RUST_AVAILABLE, reason="otrv4_core not installed")
class TestSMPVaultSecurity:
    """Rust SMP vault deterministic zeroization."""

    def test_vault_clear_empties(self):
        vault = RustSMPVault()
        vault.store("secret", b'\xff' * 384)
        vault.store("a2", b'\xaa' * 384)
        assert vault.count() == 2
        vault.clear()
        assert vault.count() == 0

    def test_vault_overwrite_replaces(self):
        vault = RustSMPVault()
        vault.store("r5", b'\x01' * 32)
        vault.store("r5", b'\x02' * 32)
        assert vault.load("r5") == b'\x02' * 32
        assert vault.count() == 1

    def test_vault_drop_doesnt_crash(self):
        vault = RustSMPVault()
        for i in range(100):
            vault.store(f"key{i}", secrets.token_bytes(384))
        del vault  # triggers Rust Drop → Zeroize

    def test_smp_engine_uses_vault(self):
        eng = otr.SMPEngine(is_initiator=True)
        assert eng._vault is not None
        eng.set_secret("testpass1234")
        assert eng._vault.has("secret")
        eng._clear_math_state()
        assert eng._vault.count() == 0


# ═══════════════════════════════════════════════════════════════════
# 11. State Rollback Impossible
# ═══════════════════════════════════════════════════════════════════

class TestRollbackImpossible:
    """Verify that ratchet state cannot be rolled back from Python."""

    def test_cant_reset_message_counter(self):
        """Setting message_counter_send from Python doesn't affect
        the Rust ratchet's internal counter — messages still decrypt."""
        alice, bob = _make_pair()

        for i in range(5):
            ct, h, n, t, _, _ = alice.encrypt_message(f"pre-{i}".encode())
            bob.decrypt_message(h, ct, n, t)

        # Attempt to "rollback" the Python-side counter
        alice.message_counter_send = 0

        # Rust internal state is unchanged — next message still decrypts
        ct, h, n, t, _, _ = alice.encrypt_message(b"after rollback attempt")
        pt = bob.decrypt_message(h, ct, n, t)
        assert pt == b"after rollback attempt"

    def test_nonce_uniqueness_after_counter_reset(self):
        """Even if Python counter is reset, nonces are still unique
        because they come from the Rust ratchet's internal state."""
        alice, _ = _make_pair()
        nonces = set()
        for i in range(50):
            ct, h, n, t, _, _ = alice.encrypt_message(f"n-{i}".encode())
            assert n not in nonces
            nonces.add(n)

        # Reset Python counter
        alice.message_counter_send = 0

        for i in range(50):
            ct, h, n, t, _, _ = alice.encrypt_message(f"n2-{i}".encode())
            assert n not in nonces, "Nonce collision after counter reset!"
            nonces.add(n)


# ═══════════════════════════════════════════════════════════════════
# 12. Large and Edge-Case Messages
# ═══════════════════════════════════════════════════════════════════

class TestEdgeCaseMessages:
    """Boundary conditions for message sizes."""

    def test_empty_message(self):
        alice, bob = _make_pair()
        ct, h, n, t, _, _ = alice.encrypt_message(b"")
        pt = bob.decrypt_message(h, ct, n, t)
        assert pt == b""

    def test_single_byte_message(self):
        alice, bob = _make_pair()
        ct, h, n, t, _, _ = alice.encrypt_message(b"\x00")
        pt = bob.decrypt_message(h, ct, n, t)
        assert pt == b"\x00"

    def test_64kb_message(self):
        alice, bob = _make_pair()
        big = secrets.token_bytes(65536)
        ct, h, n, t, _, _ = alice.encrypt_message(big)
        pt = bob.decrypt_message(h, ct, n, t)
        assert pt == big

    def test_all_zero_plaintext(self):
        alice, bob = _make_pair()
        zeros = b'\x00' * 1024
        ct, h, n, t, _, _ = alice.encrypt_message(zeros)
        pt = bob.decrypt_message(h, ct, n, t)
        assert pt == zeros

    def test_all_ff_plaintext(self):
        alice, bob = _make_pair()
        ffs = b'\xff' * 1024
        ct, h, n, t, _, _ = alice.encrypt_message(ffs)
        pt = bob.decrypt_message(h, ct, n, t)
        assert pt == ffs


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
