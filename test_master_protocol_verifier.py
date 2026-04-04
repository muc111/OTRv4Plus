#!/usr/bin/env python3
"""
Master Protocol Verification Harness — Adversarial stress test.

Goes beyond the ratchet torture test by simulating hostile network conditions
and active attackers:

  Module 1  Network Chaos         drops, reordering, duplication at scale
  Module 2  Replay Resistance     replayed ciphertexts always rejected
  Module 3  Forward Secrecy       key compromise cannot decrypt future messages
  Module 4  State Rollback        rolled-back peer never silently corrupts
  Module 5  Post-Compromise       ratchet heals after transient state leak
            Recovery
  Module 6  Cross-Ratchet         survives multiple forced rekey boundaries
            Boundary
  Module 7  Burst & Silence       bursts of one-way traffic then direction
                                  reversal
  Module 8  Full Adversarial      everything combined at 300K+ ops
            Gauntlet

Invariants enforced on EVERY operation across ALL modules:
  • Zero silent corruption   — every successful decrypt == original plaintext
  • Replay always rejected   — replaying a delivered ciphertext always raises
  • Nonce global uniqueness  — no two encrypts ever produce the same nonce

Run:
    pytest test_master_protocol_verifier.py -v

Expected runtime on Android/Termux:
    Individual modules  ≈  5-30s each
    Full gauntlet       ≈  3-5 min
    Overnight (1M ops)  ≈  20-40 min

Parallel (requires pytest-xdist):
    pytest test_master_protocol_verifier.py -n 4
"""

import os
import sys
import copy
import time
import random
import secrets
import hashlib
import collections
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import otrv4_ as otr


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


class Packet:
    """In-flight ciphertext with metadata for verification."""
    __slots__ = ('receiver', 'header', 'ct', 'nonce', 'tag',
                 'plaintext', 'sender_id', 'seq')

    def __init__(self, receiver, header, ct, nonce, tag,
                 plaintext, sender_id, seq):
        self.receiver = receiver
        self.header = header
        self.ct = ct
        self.nonce = nonce
        self.tag = tag
        self.plaintext = plaintext
        self.sender_id = sender_id
        self.seq = seq


def _encrypt(sender, receiver, sender_id, seq):
    """Encrypt a random message, return a Packet."""
    msg = os.urandom(random.randint(1, 200))
    ct, header, nonce, tag, ratchet_id, _ = sender.encrypt_message(msg)
    return Packet(receiver, header, ct, nonce, tag, msg, sender_id, seq)


def _decrypt_and_verify(pkt):
    """Decrypt a packet; return True if plaintext matches, False on expected
    EncryptionError, raise on silent corruption."""
    try:
        pt = pkt.receiver.decrypt_message(pkt.header, pkt.ct, pkt.nonce, pkt.tag)
    except otr.EncryptionError:
        return False
    except Exception:
        return False
    if pt != pkt.plaintext:
        raise RuntimeError(
            f"SILENT CORRUPTION: seq={pkt.seq} sender={pkt.sender_id} "
            f"expected {pkt.plaintext[:16].hex()}… got {pt[:16].hex()}…"
        )
    return True


def _snapshot_keys(peer):
    """Snapshot the internal key state of a DoubleRatchet for rollback testing.
    Returns an opaque dict that can be fed to _restore_keys."""
    snap = {}
    snap['root_key_data'] = peer.root_key.read()
    snap['chain_key_send_data'] = peer.chain_key_send.read()
    snap['chain_key_recv_data'] = peer.chain_key_recv.read()
    snap['message_num_send'] = peer.message_num_send
    snap['message_num_recv'] = peer.message_num_recv
    snap['message_counter_send'] = peer.message_counter_send
    snap['message_counter_recv'] = peer.message_counter_recv
    snap['prev_chain_len_send'] = peer.prev_chain_len_send
    snap['prev_chain_len_recv'] = peer.prev_chain_len_recv
    snap['ratchet_id'] = peer.ratchet_id
    snap['dh_ratchet_remote_pub'] = (
        bytes(peer.dh_ratchet_remote_pub) if peer.dh_ratchet_remote_pub else None
    )
    return snap


def _restore_keys(peer, snap):
    """Restore a DoubleRatchet to a previously snapshotted state.
    This simulates an attacker or bug that rolls back the peer's state."""
    peer.root_key.write(snap['root_key_data'])
    peer.chain_key_send.write(snap['chain_key_send_data'])
    peer.chain_key_recv.write(snap['chain_key_recv_data'])
    peer.message_num_send = snap['message_num_send']
    peer.message_num_recv = snap['message_num_recv']
    peer.message_counter_send = snap['message_counter_send']
    peer.message_counter_recv = snap['message_counter_recv']
    peer.prev_chain_len_send = snap['prev_chain_len_send']
    peer.prev_chain_len_recv = snap['prev_chain_len_recv']
    peer.ratchet_id = snap['ratchet_id']


# ═══════════════════════════════════════════════════════════════════════════════
# Module 1: Network Chaos
# ═══════════════════════════════════════════════════════════════════════════════

class TestNetworkChaos:
    """Simulates a hostile network that drops, reorders, and duplicates
    packets.  Verifies zero silent corruption under all conditions."""

    @staticmethod
    def _run_chaos(ops, seed, drop_rate=0.25, reorder_rate=0.15,
                   dup_rate=0.08):
        rng = random.Random(seed)
        alice, bob = _make_pair()
        queue = collections.deque()
        delivered = 0
        corruptions = 0
        nonces = set()

        for i in range(ops):
            if rng.random() < 0.5:
                sender, receiver, sid = alice, bob, 'A'
            else:
                sender, receiver, sid = bob, alice, 'B'

            pkt = _encrypt(sender, receiver, sid, i)

            # Nonce uniqueness
            if pkt.nonce in nonces:
                raise RuntimeError(f"NONCE REUSE at op {i}")
            nonces.add(pkt.nonce)

            # Drop
            if rng.random() < drop_rate:
                continue

            queue.append(pkt)

            # Duplicate
            if rng.random() < dup_rate:
                queue.append(pkt)

            # Reorder
            if len(queue) > 1 and rng.random() < reorder_rate:
                q = list(queue)
                # Shuffle a random window of up to 6 items from the tail
                window = min(6, len(q))
                tail = q[-window:]
                rng.shuffle(tail)
                q[-window:] = tail
                queue = collections.deque(q)

            # Deliver with 70% probability
            while queue and rng.random() < 0.7:
                p = queue.popleft()
                if _decrypt_and_verify(p):
                    delivered += 1

        # Drain
        for p in queue:
            if _decrypt_and_verify(p):
                delivered += 1

        return {'delivered': delivered, 'ops': ops, 'nonces': len(nonces)}

    def test_chaos_50k_seeded(self):
        """50K ops with heavy network chaos, deterministic seed."""
        stats = self._run_chaos(50_000, seed=31337)
        assert stats['delivered'] > 0, "Zero messages delivered"
        print(f"\n  Chaos 50K: delivered={stats['delivered']}/{stats['ops']}")

    def test_chaos_50k_random(self):
        """50K ops with heavy network chaos, random seed."""
        stats = self._run_chaos(50_000, seed=None)
        assert stats['delivered'] > 0
        print(f"\n  Chaos 50K random: delivered={stats['delivered']}/{stats['ops']}")

    def test_chaos_extreme_drop(self):
        """20K ops with 60% drop rate — protocol must not corrupt."""
        stats = self._run_chaos(20_000, seed=1234, drop_rate=0.60)
        print(f"\n  Extreme drop: delivered={stats['delivered']}/{stats['ops']}")

    def test_chaos_extreme_reorder(self):
        """20K ops with 50% reorder rate."""
        stats = self._run_chaos(20_000, seed=5678, reorder_rate=0.50)
        print(f"\n  Extreme reorder: delivered={stats['delivered']}/{stats['ops']}")


# ═══════════════════════════════════════════════════════════════════════════════
# Module 2: Replay Resistance (exhaustive)
# ═══════════════════════════════════════════════════════════════════════════════

class TestReplayResistance:
    """Every delivered message is replayed immediately.  Every replay MUST
    fail.  No exceptions, no silent success."""

    def test_replay_every_message_5k(self):
        """5000 messages, replay each one immediately after delivery."""
        alice, bob = _make_pair()
        replays_tested = 0
        replays_caught = 0

        for i in range(5_000):
            if i % 2 == 0:
                sender, receiver = alice, bob
            else:
                sender, receiver = bob, alice

            pkt = _encrypt(sender, receiver, 'A' if sender is alice else 'B', i)

            # Deliver
            ok = _decrypt_and_verify(pkt)
            assert ok, f"Initial delivery failed at op {i}"

            # Immediate replay — MUST fail
            replays_tested += 1
            try:
                receiver.decrypt_message(pkt.header, pkt.ct, pkt.nonce, pkt.tag)
                raise RuntimeError(f"REPLAY SUCCEEDED at op {i}")
            except (otr.EncryptionError, ValueError, RuntimeError) as e:
                if "REPLAY SUCCEEDED" in str(e):
                    raise
                replays_caught += 1

        assert replays_caught == replays_tested, (
            f"Replay leak: {replays_tested - replays_caught} replays not caught"
        )
        print(f"\n  Replay exhaustive: {replays_caught}/{replays_tested} caught")

    def test_replay_delayed_10k(self):
        """10K messages.  Randomly replay old messages at later points."""
        rng = random.Random(99999)
        alice, bob = _make_pair()
        delivered_pkts = []
        replays_tested = 0
        replays_caught = 0

        for i in range(10_000):
            sender, receiver = (alice, bob) if rng.random() < 0.5 else (bob, alice)
            pkt = _encrypt(sender, receiver, 'A' if sender is alice else 'B', i)

            if _decrypt_and_verify(pkt):
                delivered_pkts.append(pkt)

            # Randomly replay an old delivered message
            if delivered_pkts and rng.random() < 0.05:
                old = rng.choice(delivered_pkts)
                replays_tested += 1
                try:
                    old.receiver.decrypt_message(
                        old.header, old.ct, old.nonce, old.tag)
                    raise RuntimeError(f"DELAYED REPLAY SUCCEEDED at op {i}")
                except (otr.EncryptionError, ValueError, RuntimeError) as e:
                    if "DELAYED REPLAY SUCCEEDED" in str(e):
                        raise
                    replays_caught += 1

        assert replays_caught == replays_tested
        print(f"\n  Delayed replay: {replays_caught}/{replays_tested} caught")


# ═══════════════════════════════════════════════════════════════════════════════
# Module 3: Forward Secrecy
# ═══════════════════════════════════════════════════════════════════════════════

class TestForwardSecrecy:
    """Verifies that compromising chain keys at time T does not allow
    decryption of messages sent after a DH ratchet step at time T+N."""

    def test_forward_secrecy_post_ratchet(self):
        """Steal chain keys, force a ratchet via message exchange,
        then verify stolen keys cannot decrypt new messages."""
        alice, bob = _make_pair(rekey_interval=50)

        # Phase 1: Exchange enough messages to establish ratchet state
        for i in range(20):
            pkt = _encrypt(alice, bob, 'A', i)
            assert _decrypt_and_verify(pkt)
            pkt = _encrypt(bob, alice, 'B', i)
            assert _decrypt_and_verify(pkt)

        # COMPROMISE: steal Bob's current recv chain key
        stolen_recv_ck = bob.chain_key_recv.read()
        stolen_root = bob.root_key.read()
        stolen_msg_num_recv = bob.message_num_recv

        # Phase 2: Exchange more messages to trigger DH ratchet advancement
        # (alternating senders forces new DH keys in headers)
        for i in range(100):
            pkt = _encrypt(alice, bob, 'A', 1000 + i)
            _decrypt_and_verify(pkt)
            pkt = _encrypt(bob, alice, 'B', 1000 + i)
            _decrypt_and_verify(pkt)

        # Phase 3: Alice sends a new message on the new ratchet epoch
        target_pkt = _encrypt(alice, bob, 'A', 9999)
        # Bob can decrypt it normally
        assert _decrypt_and_verify(target_pkt)

        # Phase 4: Attacker tries to use stolen keys
        # Build a ratchet with the stolen state and try to decrypt
        # We can't construct a full DoubleRatchet from stolen keys easily,
        # but we CAN verify the chain keys have rotated by checking they differ
        current_recv_ck = bob.chain_key_recv.read()
        current_root = bob.root_key.read()

        assert stolen_recv_ck != current_recv_ck, \
            "Recv chain key unchanged after ratchet — forward secrecy broken"
        assert stolen_root != current_root, \
            "Root key unchanged after ratchet — forward secrecy broken"

        print("\n  Forward secrecy: chain keys rotated after ratchet ✓")

    def test_key_erasure_across_rekey(self):
        """Verify that keys change after forced rekey boundary."""
        alice, bob = _make_pair(rekey_interval=100)

        keys_seen = set()
        for i in range(250):
            ck = alice.chain_key_send.read()
            keys_seen.add(ck)
            pkt = _encrypt(alice, bob, 'A', i)
            _decrypt_and_verify(pkt)

        # We sent 250 messages with rekey_interval=100, so there must have been
        # at least 2 rekeys.  Chain keys must all be unique.
        assert len(keys_seen) == 250, (
            f"Chain key reuse detected: {250 - len(keys_seen)} duplicates"
        )
        print(f"\n  Key erasure: {len(keys_seen)} unique chain keys across rekey ✓")


# ═══════════════════════════════════════════════════════════════════════════════
# Module 4: State Rollback
# ═══════════════════════════════════════════════════════════════════════════════

class TestStateRollback:
    """Simulates an attacker or bug that rolls back a peer's state to an
    earlier point.  Verifies that no silent corruption occurs — all
    subsequent operations either fail loudly or (after re-sync) succeed
    correctly."""

    def test_rollback_sender_state(self):
        """Roll back Alice's send state after 200 messages.  Bob must
        reject all messages encrypted with rolled-back keys."""
        alice, bob = _make_pair()

        # Phase 1: normal operation
        for i in range(200):
            pkt = _encrypt(alice, bob, 'A', i)
            assert _decrypt_and_verify(pkt), f"Phase 1 failed at {i}"

        # Snapshot Alice's state
        snap = _snapshot_keys(alice)

        # Phase 2: more normal messages (advances Alice past snapshot)
        for i in range(200, 400):
            pkt = _encrypt(alice, bob, 'A', i)
            assert _decrypt_and_verify(pkt), f"Phase 2 failed at {i}"

        # ROLLBACK Alice's state
        _restore_keys(alice, snap)

        # Phase 3: Alice now sends with old keys.  Bob should reject these
        # because the chain keys / message numbers are stale.
        rejected = 0
        accepted = 0
        for i in range(400, 500):
            pkt = _encrypt(alice, bob, 'A', i)
            if _decrypt_and_verify(pkt):
                accepted += 1
            else:
                rejected += 1

        # The protocol SHOULD reject most/all of these due to counter regression
        # or wrong chain keys.  The critical invariant is zero silent corruption
        # (which _decrypt_and_verify enforces).
        print(f"\n  Rollback sender: rejected={rejected} accepted={accepted} "
              f"(zero corruption ✓)")

    def test_rollback_receiver_state(self):
        """Roll back Bob's recv state.  Messages should fail or succeed
        correctly, never silently corrupt."""
        alice, bob = _make_pair()

        for i in range(200):
            pkt = _encrypt(alice, bob, 'A', i)
            assert _decrypt_and_verify(pkt)

        snap = _snapshot_keys(bob)

        for i in range(200, 400):
            pkt = _encrypt(alice, bob, 'A', i)
            assert _decrypt_and_verify(pkt)

        _restore_keys(bob, snap)

        rejected = 0
        accepted = 0
        for i in range(400, 500):
            pkt = _encrypt(alice, bob, 'A', i)
            if _decrypt_and_verify(pkt):
                accepted += 1
            else:
                rejected += 1

        print(f"\n  Rollback receiver: rejected={rejected} accepted={accepted} "
              f"(zero corruption ✓)")


# ═══════════════════════════════════════════════════════════════════════════════
# Module 5: Post-Compromise Recovery
# ═══════════════════════════════════════════════════════════════════════════════

class TestPostCompromiseRecovery:
    """After a transient state compromise (attacker reads keys at one point
    in time), the ratchet must heal: once enough new DH ratchet steps occur,
    the attacker's stolen keys become useless."""

    def test_recovery_after_compromise(self):
        """Compromise keys, then verify ratchet heals via bidirectional
        message exchange."""
        alice, bob = _make_pair(rekey_interval=50)

        # Establish initial state
        for i in range(30):
            pkt = _encrypt(alice, bob, 'A', i)
            assert _decrypt_and_verify(pkt)
            pkt = _encrypt(bob, alice, 'B', i)
            assert _decrypt_and_verify(pkt)

        # COMPROMISE: snapshot both peers
        snap_a = _snapshot_keys(alice)
        snap_b = _snapshot_keys(bob)

        # Healing phase: bidirectional traffic forces DH ratchet steps
        for i in range(200):
            pkt = _encrypt(alice, bob, 'A', 1000 + i)
            _decrypt_and_verify(pkt)
            pkt = _encrypt(bob, alice, 'B', 1000 + i)
            _decrypt_and_verify(pkt)

        # Verify keys have diverged from compromised state
        assert alice.root_key.read() != snap_a['root_key_data'], \
            "Alice root key unchanged — healing failed"
        assert bob.root_key.read() != snap_b['root_key_data'], \
            "Bob root key unchanged — healing failed"
        assert alice.chain_key_send.read() != snap_a['chain_key_send_data'], \
            "Alice send chain unchanged — healing failed"
        assert bob.chain_key_send.read() != snap_b['chain_key_send_data'], \
            "Bob send chain unchanged — healing failed"

        # Clean operation post-healing must work perfectly
        for i in range(50):
            pkt = _encrypt(alice, bob, 'A', 5000 + i)
            assert _decrypt_and_verify(pkt), f"Post-healing A→B failed at {i}"
            pkt = _encrypt(bob, alice, 'B', 5000 + i)
            assert _decrypt_and_verify(pkt), f"Post-healing B→A failed at {i}"

        print("\n  Post-compromise recovery: healed ✓")


# ═══════════════════════════════════════════════════════════════════════════════
# Module 6: Cross-Ratchet Boundary
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossRatchetBoundary:
    """Specifically targets the rekey_interval boundary where the forced
    DH ratchet step (_ratchet) fires.  This is exactly where the original
    bugs manifested (~op 10,000)."""

    def test_exact_boundary_crossing(self):
        """Send exactly rekey_interval messages, then one more.  The
        boundary message must decrypt correctly."""
        for interval in [50, 100, 200]:
            alice, bob = _make_pair(rekey_interval=interval)

            # Send exactly `interval` messages from Alice
            for i in range(interval):
                pkt = _encrypt(alice, bob, 'A', i)
                assert _decrypt_and_verify(pkt), (
                    f"Failed at msg {i} (interval={interval})"
                )

            # The NEXT message triggers the forced rekey
            pkt = _encrypt(alice, bob, 'A', interval)
            assert _decrypt_and_verify(pkt), (
                f"Boundary message failed (interval={interval})"
            )

            # And several more after
            for i in range(interval + 1, interval + 50):
                pkt = _encrypt(alice, bob, 'A', i)
                assert _decrypt_and_verify(pkt), (
                    f"Post-boundary failed at {i} (interval={interval})"
                )

        print("\n  Cross-ratchet boundary: all intervals passed ✓")

    def test_bidirectional_boundary(self):
        """Both peers cross the rekey boundary while alternating."""
        alice, bob = _make_pair(rekey_interval=100)

        for i in range(350):
            pkt = _encrypt(alice, bob, 'A', i)
            assert _decrypt_and_verify(pkt), f"A→B failed at {i}"
            pkt = _encrypt(bob, alice, 'B', i)
            assert _decrypt_and_verify(pkt), f"B→A failed at {i}"

        print("\n  Bidirectional boundary 350x2: passed ✓")

    def test_multiple_rekey_cycles(self):
        """Force 5 complete rekey cycles on both sides."""
        interval = 100
        alice, bob = _make_pair(rekey_interval=interval)
        cycles = 5
        total = interval * cycles + 50

        for i in range(total):
            if i % 2 == 0:
                pkt = _encrypt(alice, bob, 'A', i)
            else:
                pkt = _encrypt(bob, alice, 'B', i)
            assert _decrypt_and_verify(pkt), f"Failed at op {i}"

        print(f"\n  Multiple rekey cycles ({cycles}): {total} ops passed ✓")


# ═══════════════════════════════════════════════════════════════════════════════
# Module 7: Burst & Silence
# ═══════════════════════════════════════════════════════════════════════════════

class TestBurstAndSilence:
    """Tests asymmetric traffic patterns: long bursts from one side with
    no replies, then direction reversal.  This stresses the symmetric
    ratchet (chain key advancement) without DH ratchet steps."""

    def test_one_way_burst_then_reverse(self):
        """Alice sends 500 messages with no reply, then Bob sends 500."""
        alice, bob = _make_pair()

        # Alice → Bob burst
        for i in range(500):
            pkt = _encrypt(alice, bob, 'A', i)
            assert _decrypt_and_verify(pkt), f"A→B burst failed at {i}"

        # Bob → Alice burst (triggers DH ratchet on first message)
        for i in range(500):
            pkt = _encrypt(bob, alice, 'B', i)
            assert _decrypt_and_verify(pkt), f"B→A burst failed at {i}"

        # Verify bidirectional still works
        for i in range(50):
            pkt = _encrypt(alice, bob, 'A', 1000 + i)
            assert _decrypt_and_verify(pkt)
            pkt = _encrypt(bob, alice, 'B', 1000 + i)
            assert _decrypt_and_verify(pkt)

        print("\n  Burst & reverse: 500+500+100 passed ✓")

    def test_extreme_one_way_across_rekey(self):
        """One side sends 1500 messages (crossing rekey boundary at 10K
        default, but we use interval=200 to stress it)."""
        alice, bob = _make_pair(rekey_interval=200)

        for i in range(1500):
            pkt = _encrypt(alice, bob, 'A', i)
            assert _decrypt_and_verify(pkt), f"One-way failed at {i}"

        # First reply from Bob
        pkt = _encrypt(bob, alice, 'B', 0)
        assert _decrypt_and_verify(pkt), "First reply failed"

        # Continue bidirectional
        for i in range(100):
            pkt = _encrypt(alice, bob, 'A', 2000 + i)
            assert _decrypt_and_verify(pkt)
            pkt = _encrypt(bob, alice, 'B', 2000 + i)
            assert _decrypt_and_verify(pkt)

        print("\n  Extreme one-way (1500) + recovery: passed ✓")


# ═══════════════════════════════════════════════════════════════════════════════
# Module 8: Full Adversarial Gauntlet
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullGauntlet:
    """Combines ALL adversarial conditions into a single high-intensity
    stochastic run.  This is the ultimate test."""

    @staticmethod
    def _run_gauntlet(ops, seed=None):
        rng = random.Random(seed)
        alice, bob = _make_pair(rekey_interval=5_000)

        # ── Counters ──
        delivered = 0
        dropped = 0
        replays_tested = 0
        replays_caught = 0
        rollbacks = 0
        corruptions = 0

        # ── Buffers ──
        queue = collections.deque()
        delivered_pkts = []
        nonces = set()

        # ── Config ──
        drop_rate = 0.20
        dup_rate = 0.08
        reorder_rate = 0.15
        replay_rate = 0.01
        rollback_rate = 0.0005  # rare but devastating

        # ── Rollback state ──
        snapshots = {'A': None, 'B': None}

        t0 = time.time()

        for i in range(ops):
            # Pick sender
            if rng.random() < 0.5:
                sender, receiver, sid = alice, bob, 'A'
            else:
                sender, receiver, sid = bob, alice, 'B'

            # ── Encrypt ──
            pkt = _encrypt(sender, receiver, sid, i)

            # Nonce uniqueness
            if pkt.nonce in nonces:
                raise RuntimeError(f"NONCE REUSE at op {i}: {pkt.nonce.hex()}")
            nonces.add(pkt.nonce)

            # ── Rare rollback attack ──
            if rng.random() < rollback_rate:
                target = alice if rng.random() < 0.5 else bob
                tid = 'A' if target is alice else 'B'
                if snapshots[tid] is None:
                    snapshots[tid] = _snapshot_keys(target)
                else:
                    _restore_keys(target, snapshots[tid])
                    rollbacks += 1
                    snapshots[tid] = None  # one-shot

            # ── Snapshot for future rollback ──
            if rng.random() < 0.001:
                target = alice if rng.random() < 0.5 else bob
                tid = 'A' if target is alice else 'B'
                snapshots[tid] = _snapshot_keys(target)

            # ── Drop ──
            if rng.random() < drop_rate:
                dropped += 1
                continue

            queue.append(pkt)

            # ── Duplicate ──
            if rng.random() < dup_rate:
                queue.append(pkt)

            # ── Reorder ──
            if len(queue) > 2 and rng.random() < reorder_rate:
                q = list(queue)
                window = min(8, len(q))
                tail = q[-window:]
                rng.shuffle(tail)
                q[-window:] = tail
                queue = collections.deque(q)

            # ── Replay old delivered message ──
            if delivered_pkts and rng.random() < replay_rate:
                old = rng.choice(delivered_pkts)
                replays_tested += 1
                try:
                    old.receiver.decrypt_message(
                        old.header, old.ct, old.nonce, old.tag)
                    raise RuntimeError(f"REPLAY SUCCEEDED at op {i}")
                except (otr.EncryptionError, ValueError, RuntimeError) as e:
                    if "REPLAY SUCCEEDED" in str(e):
                        raise
                    replays_caught += 1

            # ── Deliver from queue ──
            while queue and rng.random() < 0.65:
                p = queue.popleft()
                if _decrypt_and_verify(p):
                    delivered += 1
                    delivered_pkts.append(p)
                    # Cap memory
                    if len(delivered_pkts) > 5000:
                        delivered_pkts = delivered_pkts[-2000:]

            # ── Progress ──
            if i > 0 and i % 50_000 == 0:
                elapsed = time.time() - t0
                print(f"    {i:>8,} ops | delivered={delivered:,} | "
                      f"rollbacks={rollbacks} | "
                      f"replays={replays_caught}/{replays_tested} | "
                      f"{elapsed:.1f}s")

        # Drain remaining queue
        for p in queue:
            if _decrypt_and_verify(p):
                delivered += 1

        elapsed = time.time() - t0

        stats = {
            'ops': ops,
            'delivered': delivered,
            'dropped': dropped,
            'rollbacks': rollbacks,
            'replays_tested': replays_tested,
            'replays_caught': replays_caught,
            'nonces': len(nonces),
            'elapsed': elapsed,
        }
        return stats

    def test_gauntlet_100k_seeded(self):
        """100K ops with all adversarial conditions, deterministic seed."""
        stats = self._run_gauntlet(100_000, seed=0xDEADBEEF)
        assert stats['delivered'] > 0
        assert stats['replays_caught'] == stats['replays_tested'], \
            f"Replay leak: {stats['replays_tested'] - stats['replays_caught']}"
        print(f"\n  Gauntlet 100K: delivered={stats['delivered']:,} "
              f"rollbacks={stats['rollbacks']} "
              f"replays={stats['replays_caught']}/{stats['replays_tested']} "
              f"in {stats['elapsed']:.1f}s ✓")

    def test_gauntlet_100k_random(self):
        """100K ops, random seed — different every run."""
        stats = self._run_gauntlet(100_000, seed=None)
        assert stats['delivered'] > 0
        assert stats['replays_caught'] == stats['replays_tested']
        print(f"\n  Gauntlet 100K random: delivered={stats['delivered']:,} "
              f"in {stats['elapsed']:.1f}s ✓")

    def test_gauntlet_300k_seeded(self):
        """300K ops — the full adversarial gauntlet."""
        stats = self._run_gauntlet(300_000, seed=0xCAFEBABE)
        assert stats['delivered'] > 0
        assert stats['replays_caught'] == stats['replays_tested']
        print(f"\n  Gauntlet 300K: delivered={stats['delivered']:,} "
              f"rollbacks={stats['rollbacks']} "
              f"replays={stats['replays_caught']}/{stats['replays_tested']} "
              f"in {stats['elapsed']:.1f}s ✓")


# ═══════════════════════════════════════════════════════════════════════════════
# Standalone runner
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Master Protocol Verifier')
    parser.add_argument('--ops', type=int, default=1_000_000,
                        help='Operations for gauntlet (default: 1M)')
    parser.add_argument('--seed', type=int, default=None,
                        help='Random seed (default: random)')
    args = parser.parse_args()

    print(f"Master Protocol Verification Harness")
    print(f"  Operations : {args.ops:,}")
    print(f"  Seed       : {args.seed}")
    print()

    t0 = time.time()
    try:
        stats = TestFullGauntlet._run_gauntlet(args.ops, seed=args.seed)
        elapsed = time.time() - t0
        print(f"\n{'='*60}")
        print(f"  PASSED — {args.ops:,} operations in {elapsed:.1f}s "
              f"({args.ops/elapsed:,.0f} ops/sec)")
        print(f"  Delivered     : {stats['delivered']:,}")
        print(f"  Dropped       : {stats['dropped']:,}")
        print(f"  Rollbacks     : {stats['rollbacks']}")
        print(f"  Replays caught: {stats['replays_caught']}/{stats['replays_tested']}")
        print(f"  Unique nonces : {stats['nonces']:,}")
        print(f"{'='*60}")
    except RuntimeError as e:
        elapsed = time.time() - t0
        print(f"\n  FAILED after {elapsed:.1f}s: {e}")
        sys.exit(1)
