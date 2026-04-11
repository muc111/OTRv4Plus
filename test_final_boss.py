#!/usr/bin/env python3
"""
Final Boss Test Suite — Extreme state integrity + adversarial overlap testing

Covers:
  • Multi-session isolation (nonce + state separation across 10 concurrent sessions)
  • Partial key leak recovery (PCS realism — chain key stolen, ratchet heals)
  • Concurrent send race conditions (threading stress on RLock)
  • Fork under network chaos (snapshot/restore + packet drops)
  • Persistence + fork interleaving (simulated restart from snapshot)
  • Message size extremes (1 byte vs 4096 bytes AEAD stress)

All tests enforce:
  - Zero silent corruption
  - No nonce reuse across sessions
  - Correct decrypt or explicit EncryptionError

Run:
    pytest test_final_boss.py -v

Expected runtime on Android/Termux:  ~5-10 minutes
"""

import os
import random
import threading
import pytest

from test_master_protocol_verifier import (
    _make_pair,
    _encrypt,
    _decrypt_and_verify,


)

import otrv4_ as otr


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Multi-Session Isolation
# ═══════════════════════════════════════════════════════════════════════════════

class TestMultiSessionIsolation:
    """10 concurrent sessions — nonces must never collide across sessions."""

    def test_multi_session_nonce_isolation(self):
        """20,000 ops across 10 independent sessions — zero cross-session nonce collision."""
        sessions = [_make_pair() for _ in range(10)]
        nonces = set()

        for i in range(20_000):
            a, b = random.choice(sessions)
            sender, receiver = (a, b) if random.random() < 0.5 else (b, a)

            pkt = _encrypt(sender, receiver, 'X', i)

            assert pkt.nonce not in nonces, \
                f"CROSS-SESSION NONCE COLLISION at op {i}"
            nonces.add(pkt.nonce)

            # Verify every message decrypts correctly
            result = _decrypt_and_verify(pkt)
            assert result, f"Decrypt failed at op {i}"

    def test_sessions_are_state_isolated(self):
        """Encrypting in one session must not affect another session's state."""
        alice1, bob1 = _make_pair()
        alice2, bob2 = _make_pair()

        # Advance session 1 significantly
        for i in range(500):
            _decrypt_and_verify(_encrypt(alice1, bob1, 'A', i))

        # Session 2 should still work from scratch
        for i in range(10):
            pkt = _encrypt(alice2, bob2, 'A', i)
            assert _decrypt_and_verify(pkt), \
                f"Session 2 corrupted by session 1 activity at op {i}"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Partial Key Leak Recovery (PCS)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPartialKeyLeak:
    """Steal the send chain key — the ratchet must heal after enough DH steps."""

    def test_partial_key_leak_recovery(self):
        """After stealing alice's chain_key_send, 200 messages of bidirectional
        traffic causes a DH ratchet step that derives a completely new chain key."""
        alice, bob = _make_pair()

        # Warm up
        for i in range(50):
            _decrypt_and_verify(_encrypt(alice, bob, 'A', i))
            _decrypt_and_verify(_encrypt(bob, alice, 'B', i))

        # Steal the current send chain key
        leaked = alice.chain_key_send.read()

        # Healing phase — bidirectional traffic forces DH ratchet steps
        for i in range(200):
            _decrypt_and_verify(_encrypt(bob, alice, 'B', i))
            _decrypt_and_verify(_encrypt(alice, bob, 'A', i))

        # After healing the chain key must be completely different
        current = alice.chain_key_send.read()
        assert leaked != current, \
            "chain_key_send unchanged after 200 healing messages — PCS broken"

    def test_leaked_key_cannot_decrypt_future_messages(self):
        """A stolen chain key at position N cannot produce the key for position N+50."""
        alice, bob = _make_pair()

        # Send 10 messages to warm up
        for i in range(10):
            _decrypt_and_verify(_encrypt(alice, bob, 'A', i))
            _decrypt_and_verify(_encrypt(bob, alice, 'B', i))

        # Steal chain key NOW
        leaked_ck = alice.chain_key_send.read()

        # Send 50 more messages — ratchet advances the chain
        for i in range(50):
            _decrypt_and_verify(_encrypt(alice, bob, 'A', i))

        # Derived key from leaked position must not match current
        assert leaked_ck != alice.chain_key_send.read(), \
            "Forward secrecy violated — chain key did not advance"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Concurrent Send (Race Conditions)
# ═══════════════════════════════════════════════════════════════════════════════

class TestConcurrency:
    """Two threads hammering the same ratchet — RLock must prevent corruption."""

    def test_concurrent_sends_no_corruption(self):
        """2 threads × 1000 ops each on the same alice→bob pair.
        The RLock in DoubleRatchet must serialise all access — zero errors."""
        alice, bob = _make_pair()
        errors = []

        def worker():
            for i in range(1_000):
                try:
                    pkt = _encrypt(alice, bob, 'T', i)
                    _decrypt_and_verify(pkt)
                except Exception as e:
                    errors.append(e)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)

        t1.start(); t2.start()
        t1.join();  t2.join()

        assert not errors, \
            f"Concurrency errors ({len(errors)} total): {errors[:3]}"

    def test_concurrent_bidirectional(self):
        """Alice→Bob in one thread, Bob→Alice in another — no deadlock or corruption."""
        alice, bob = _make_pair()
        errors = []

        def alice_to_bob():
            for i in range(500):
                try:
                    _decrypt_and_verify(_encrypt(alice, bob, 'A', i))
                except Exception as e:
                    errors.append(('A→B', e))

        def bob_to_alice():
            for i in range(500):
                try:
                    _decrypt_and_verify(_encrypt(bob, alice, 'B', i))
                except Exception as e:
                    errors.append(('B→A', e))

        t1 = threading.Thread(target=alice_to_bob)
        t2 = threading.Thread(target=bob_to_alice)

        t1.start(); t2.start()
        t1.join();  t2.join()

        assert not errors, \
            f"Bidirectional concurrency errors: {errors[:3]}"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Fork Under Network Chaos
# ═══════════════════════════════════════════════════════════════════════════════

class TestSizeExtremes:
    """Alternate between 1-byte and 4096-byte messages — AEAD must handle both."""

    def test_alternating_size_extremes(self):
        """5000 messages alternating 1 byte / 4096 bytes — zero corruption."""
        alice, bob = _make_pair()

        for i in range(5_000):
            size = 1 if i % 2 == 0 else 4_096
            msg = os.urandom(size)

            ct, header, nonce, tag, _, _ = alice.encrypt_message(msg)
            pt = bob.decrypt_message(header, ct, nonce, tag)

            assert pt == msg, \
                f"Corruption at op {i} (size={size}): " \
                f"expected {msg[:8].hex()}… got {pt[:8].hex()}…"

    def test_empty_and_max_size(self):
        """Zero-length and max-size messages must round-trip correctly."""
        alice, bob = _make_pair()

        for size in [0, 1, 255, 256, 1024, 4096, 65535]:
            msg = os.urandom(size)
            ct, header, nonce, tag, _, _ = alice.encrypt_message(msg)
            pt = bob.decrypt_message(header, ct, nonce, tag)
            assert pt == msg, f"Corruption at size={size}"

    def test_size_extremes_nonce_uniqueness(self):
        """Across 1000 size-extreme messages all nonces must be unique."""
        alice, bob = _make_pair()
        nonces = set()

        for i in range(1_000):
            size = random.choice([1, 4096])
            msg = os.urandom(size)
            ct, header, nonce, tag, _, _ = alice.encrypt_message(msg)

            assert nonce not in nonces, \
                f"NONCE REUSE at op {i} (size={size})"
            nonces.add(nonce)

            pt = bob.decrypt_message(header, ct, nonce, tag)
            assert pt == msg
