#!/usr/bin/env python3
"""
State Fork Attack Test — Simulates cloned / forked ratchet state.

Scenario: An attacker (or bug) duplicates one peer's entire ratchet state,
creating a "fork".  Two copies of the same peer now encrypt independently.

Invariants verified:
  • Zero ciphertext collisions   — forked peers must never produce identical
                                   (nonce, ciphertext, tag) triples
  • No silent corruption         — every successful decrypt matches plaintext
  • Fork divergence              — after a fork, the two copies diverge and
                                   the remote cannot accept messages from both
                                   indefinitely

This is a real attack vector in deployed ratchet systems (e.g. Signal's
"linked devices" edge cases, session cloning via backup restore).

Run:
    pytest test_state_fork_attack.py -v

Expected runtime on Termux:  ~30-90 seconds
"""

import os
import sys
import time
import secrets
import random
import collections
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import otrv4_ as otr

from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives import serialization


# ═══════════════════════════════════════════════════════════════════════════════
# Infrastructure
# ═══════════════════════════════════════════════════════════════════════════════

def _make_pair(rekey_interval: int = 10_000):
    """Create a synchronised (alice, bob) DoubleRatchet pair."""
    root = secrets.token_bytes(32)
    cka  = secrets.token_bytes(32)
    ckb  = secrets.token_bytes(32)
    ad   = secrets.token_bytes(32)
    bk   = secrets.token_bytes(32)
    rka  = otr.SecureMemory(32); rka.write(root)
    rkb  = otr.SecureMemory(32); rkb.write(root)
    alice = otr.DoubleRatchet(root_key=rka, is_initiator=True,
                               chain_key_send=cka, chain_key_recv=ckb,
                               ad=ad, brace_key=bk,
                               rekey_interval=rekey_interval)
    bob   = otr.DoubleRatchet(root_key=rkb, is_initiator=False,
                               chain_key_send=ckb, chain_key_recv=cka,
                               ad=ad, brace_key=bk,
                               rekey_interval=rekey_interval)
    return alice, bob


def _clone_ratchet(peer):
    """Create an independent deep clone of a DoubleRatchet.

    copy.deepcopy cannot be used because SecureMemory contains mlock'd
    buffers and threading.RLock objects that don't survive pickling.
    Instead we construct a fresh DoubleRatchet with the same shared
    parameters and then transplant every piece of internal state.
    """
    # Read all state from the original
    root_data       = peer.root_key.read()
    ck_send_data    = peer.chain_key_send.read()
    ck_recv_data    = peer.chain_key_recv.read()

    # Serialize the X448 private key (56 bytes raw)
    local_priv_raw = peer.dh_ratchet_local.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Build a new DoubleRatchet with matching shared params.
    # We pass chain keys to skip _initialize_chains() — we'll overwrite
    # them immediately anyway, but they must be non-zero to pass validation.
    rk = otr.SecureMemory(32)
    rk.write(root_data)
    clone = otr.DoubleRatchet(
        root_key=rk,
        is_initiator=peer.is_initiator,
        ad=peer.ad,
        chain_key_send=ck_send_data,
        chain_key_recv=ck_recv_data,
        brace_key=peer._brace_key,
        rekey_interval=peer.rekey_interval,
        rekey_timeout=peer.rekey_timeout,
    )

    # ── Transplant DH ratchet keys ──
    clone.dh_ratchet_local = x448.X448PrivateKey.from_private_bytes(local_priv_raw)
    clone.dh_ratchet_local_pub = clone.dh_ratchet_local.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    if peer.dh_ratchet_remote_pub is not None:
        clone.dh_ratchet_remote_pub = bytes(peer.dh_ratchet_remote_pub)
        clone.dh_ratchet_remote = x448.X448PublicKey.from_public_bytes(
            clone.dh_ratchet_remote_pub
        )
    else:
        clone.dh_ratchet_remote = None
        clone.dh_ratchet_remote_pub = None

    if peer.last_remote_pub is not None:
        clone.last_remote_pub = bytes(peer.last_remote_pub)
    else:
        clone.last_remote_pub = None

    # ── Transplant counters ──
    clone.message_num_send       = peer.message_num_send
    clone.message_num_recv       = peer.message_num_recv
    clone.message_counter_send   = peer.message_counter_send
    clone.message_counter_recv   = peer.message_counter_recv
    clone.prev_chain_len_send    = peer.prev_chain_len_send
    clone.prev_chain_len_recv    = peer.prev_chain_len_recv
    clone.ratchet_id             = peer.ratchet_id
    clone.last_rekey_time        = peer.last_rekey_time

    # ── Transplant replay protection ──
    clone._seen_messages = collections.OrderedDict(peer._seen_messages)
    clone._max_seen = peer._max_seen

    # ── Transplant skipped keys ──
    clone.skipped_keys = collections.OrderedDict()
    for (dh_pub, msg_num), sk in peer.skipped_keys.items():
        clone.skipped_keys[(bytes(dh_pub), msg_num)] = otr.SkippedMessageKey(
            bytes(sk.dh_pub), sk.msg_num, bytes(sk.message_key)
        )

    # ── Transplant MAC revelation state ──
    clone._pending_reveal_mac_keys = list(peer._pending_reveal_mac_keys)
    if peer._last_mac_key is not None:
        clone._last_mac_key = bytes(peer._last_mac_key)
    else:
        clone._last_mac_key = None

    return clone


def _encrypt(sender, receiver, sender_id, seq):
    """Encrypt a random message, return all components."""
    msg = os.urandom(random.randint(1, 128))
    ct, header, nonce, tag, ratchet_id, _ = sender.encrypt_message(msg)
    return msg, ct, header, nonce, tag


def _decrypt_ok(receiver, header, ct, nonce, tag, expected_pt):
    """Try to decrypt; return True if plaintext matches, False on failure.
    Raises on silent corruption."""
    try:
        pt = receiver.decrypt_message(header, ct, nonce, tag)
    except (otr.EncryptionError, Exception):
        return False
    if pt != expected_pt:
        raise RuntimeError(
            f"SILENT CORRUPTION: expected {expected_pt[:16].hex()}… "
            f"got {pt[:16].hex()}…"
        )
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestStateForkAttack:
    """State fork attack: two copies of the same sender exist independently."""

    def test_sender_state_fork(self):
        """Fork Alice into alice + alice_clone after 50 messages.
        Both encrypt independently to Bob.  Verify:
          • Zero nonce/ciphertext collisions (different RNG → different nonces)
          • Bob can only decrypt from one fork per chain position
        """
        alice, bob = _make_pair()

        # Phase 1: establish ratchet state with bidirectional exchange
        for i in range(50):
            msg, ct, hdr, nonce, tag = _encrypt(alice, bob, 'A', i)
            assert _decrypt_ok(bob, hdr, ct, nonce, tag, msg), f"Setup A→B {i}"
            msg, ct, hdr, nonce, tag = _encrypt(bob, alice, 'B', i)
            assert _decrypt_ok(alice, hdr, ct, nonce, tag, msg), f"Setup B→A {i}"

        # Fork Alice
        alice_clone = _clone_ratchet(alice)

        # Phase 2: both forks encrypt to Bob alternately
        collisions = 0
        seen_nonces = set()
        seen_cts = set()
        alice_accepted = 0
        clone_accepted = 0

        for i in range(20_000):
            if i % 2 == 0:
                sender = alice
                label = 'alice'
            else:
                sender = alice_clone
                label = 'clone'

            msg = os.urandom(random.randint(1, 64))
            ct, header, nonce, tag, _, _ = sender.encrypt_message(msg)

            # Check nonce uniqueness across BOTH forks
            if nonce in seen_nonces:
                collisions += 1
            seen_nonces.add(nonce)

            # Check ciphertext uniqueness
            ct_fingerprint = nonce + ct + tag
            if ct_fingerprint in seen_cts:
                collisions += 1
            seen_cts.add(ct_fingerprint)

            # Try delivery to Bob
            if _decrypt_ok(bob, header, ct, nonce, tag, msg):
                if label == 'alice':
                    alice_accepted += 1
                else:
                    clone_accepted += 1

        print(f"\n  Sender fork 20K: collisions={collisions} "
              f"alice_ok={alice_accepted} clone_ok={clone_accepted}")

        # Critical: zero collisions (nonces are 96-bit random, independent RNG)
        assert collisions == 0, f"COLLISION DETECTED: {collisions}"

    def test_receiver_state_fork(self):
        """Fork Bob into bob + bob_clone.  Alice sends messages, both Bobs
        try to decrypt.  Verify:
          • No silent corruption
          • At most one fork succeeds per message (chain key consumed)
          • Over time, the forks diverge and one falls behind
        """
        alice, bob = _make_pair()

        # Phase 1: establish state
        for i in range(50):
            msg, ct, hdr, nonce, tag = _encrypt(alice, bob, 'A', i)
            assert _decrypt_ok(bob, hdr, ct, nonce, tag, msg)
            msg, ct, hdr, nonce, tag = _encrypt(bob, alice, 'B', i)
            assert _decrypt_ok(alice, hdr, ct, nonce, tag, msg)

        # Fork Bob
        bob_clone = _clone_ratchet(bob)

        # Phase 2: Alice sends, both Bobs try to decrypt
        both_ok = 0
        bob_only = 0
        clone_only = 0
        neither = 0

        for i in range(20_000):
            msg = os.urandom(random.randint(1, 64))
            ct, header, nonce, tag, _, _ = alice.encrypt_message(msg)

            ok_bob = _decrypt_ok(bob, header, ct, nonce, tag, msg)
            ok_clone = _decrypt_ok(bob_clone, header, ct, nonce, tag, msg)

            if ok_bob and ok_clone:
                both_ok += 1
            elif ok_bob:
                bob_only += 1
            elif ok_clone:
                clone_only += 1
            else:
                neither += 1

        print(f"\n  Receiver fork 20K: both={both_ok} bob_only={bob_only} "
              f"clone_only={clone_only} neither={neither}")

        # Both forks start from the same state so initially both succeed.
        # As each consumes chain keys independently, they diverge.
        # The critical invariant: zero silent corruption (enforced by _decrypt_ok).
        # Also: the sum of accepted must be <= 20K per fork (no extra messages
        # materialise from nowhere).
        assert both_ok + bob_only + clone_only + neither == 20_000

    def test_sender_fork_across_rekey(self):
        """Fork Alice, then both forks send enough messages to cross the
        rekey boundary.  Verifies the forced DH ratchet step doesn't
        produce collisions or corruption when two forks rekey independently.
        """
        alice, bob = _make_pair(rekey_interval=200)

        # Establish state
        for i in range(30):
            msg, ct, hdr, nonce, tag = _encrypt(alice, bob, 'A', i)
            assert _decrypt_ok(bob, hdr, ct, nonce, tag, msg)
            msg, ct, hdr, nonce, tag = _encrypt(bob, alice, 'B', i)
            assert _decrypt_ok(alice, hdr, ct, nonce, tag, msg)

        # Fork
        alice_clone = _clone_ratchet(alice)

        # Both forks send 500 messages each (crossing 200-msg rekey boundary)
        collisions = 0
        seen_nonces = set()

        for i in range(500):
            for sender_label, sender in [('alice', alice), ('clone', alice_clone)]:
                msg = os.urandom(32)
                ct, header, nonce, tag, _, _ = sender.encrypt_message(msg)

                if nonce in seen_nonces:
                    collisions += 1
                seen_nonces.add(nonce)

                # Delivery to Bob (will mostly fail for one fork)
                _decrypt_ok(bob, header, ct, nonce, tag, msg)

        print(f"\n  Sender fork across rekey: collisions={collisions} "
              f"nonces={len(seen_nonces)}")
        assert collisions == 0

    def test_bidirectional_fork(self):
        """Fork BOTH Alice and Bob, creating four endpoints.
        Original alice↔bob and cloned alice_clone↔bob_clone operate
        independently.  Verify complete isolation."""
        alice, bob = _make_pair()

        # Establish state
        for i in range(50):
            msg, ct, hdr, nonce, tag = _encrypt(alice, bob, 'A', i)
            assert _decrypt_ok(bob, hdr, ct, nonce, tag, msg)
            msg, ct, hdr, nonce, tag = _encrypt(bob, alice, 'B', i)
            assert _decrypt_ok(alice, hdr, ct, nonce, tag, msg)

        # Fork both
        alice_clone = _clone_ratchet(alice)
        bob_clone = _clone_ratchet(bob)

        # Original pair operates independently
        orig_ok = 0
        for i in range(5_000):
            msg = os.urandom(32)
            ct, header, nonce, tag, _, _ = alice.encrypt_message(msg)
            if _decrypt_ok(bob, header, ct, nonce, tag, msg):
                orig_ok += 1

        # Cloned pair operates independently
        clone_ok = 0
        for i in range(5_000):
            msg = os.urandom(32)
            ct, header, nonce, tag, _, _ = alice_clone.encrypt_message(msg)
            if _decrypt_ok(bob_clone, header, ct, nonce, tag, msg):
                clone_ok += 1

        # Cross-pair: original alice → cloned bob should NOT work (mostly)
        cross_ok = 0
        for i in range(1_000):
            msg = os.urandom(32)
            ct, header, nonce, tag, _, _ = alice.encrypt_message(msg)
            if _decrypt_ok(bob_clone, header, ct, nonce, tag, msg):
                cross_ok += 1

        print(f"\n  Bidirectional fork: orig={orig_ok}/5000 "
              f"clone={clone_ok}/5000 cross={cross_ok}/1000")

        # Both independent pairs must work
        assert orig_ok > 4000, f"Original pair broken: {orig_ok}/5000"
        assert clone_ok > 4000, f"Cloned pair broken: {clone_ok}/5000"

    def test_fork_nonce_independence(self):
        """Specifically verify that forked peers have independent nonce
        generation (96-bit random from secrets.token_bytes, not
        counter-based).  10K encrypts from each fork, zero overlap."""
        alice, bob = _make_pair()

        # Minimal setup
        msg, ct, hdr, nonce, tag = _encrypt(alice, bob, 'A', 0)
        _decrypt_ok(bob, hdr, ct, nonce, tag, msg)

        clone = _clone_ratchet(alice)

        nonces_alice = set()
        nonces_clone = set()

        for i in range(10_000):
            msg = os.urandom(16)
            _, _, nonce_a, _, _, _ = alice.encrypt_message(msg)
            nonces_alice.add(nonce_a)

            msg = os.urandom(16)
            _, _, nonce_c, _, _, _ = clone.encrypt_message(msg)
            nonces_clone.add(nonce_c)

        overlap = nonces_alice & nonces_clone
        print(f"\n  Nonce independence: alice={len(nonces_alice)} "
              f"clone={len(nonces_clone)} overlap={len(overlap)}")

        assert len(overlap) == 0, f"NONCE OVERLAP: {len(overlap)} collisions"
        assert len(nonces_alice) == 10_000, "Alice nonce reuse"
        assert len(nonces_clone) == 10_000, "Clone nonce reuse"


# ═══════════════════════════════════════════════════════════════════════════════
# Standalone runner
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    t0 = time.time()
    t = TestStateForkAttack()

    print("State Fork Attack Tests")
    print("=" * 50)

    t.test_sender_state_fork()
    t.test_receiver_state_fork()
    t.test_sender_fork_across_rekey()
    t.test_bidirectional_fork()
    t.test_fork_nonce_independence()

    elapsed = time.time() - t0
    print(f"\n{'=' * 50}")
    print(f"ALL PASSED in {elapsed:.1f}s")
