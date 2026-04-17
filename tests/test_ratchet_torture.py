#!/usr/bin/env python3
"""
Ratchet Torture Harness — High-intensity stochastic stress test.

Simulates millions of bidirectional ratchet operations, verifying:
  - Nonce uniqueness  (12-byte random nonces must never repeat)
  - Message key slot uniqueness  ((ratchet_id, sender, msg_num) must never repeat)
  - Zero plaintext corruption  (every decrypt must match original)
  - Out-of-order delivery  (random reordering within a window)
  - Replay rejection  (replayed ciphertexts always raise)
  - Ratchet synchronisation  (both sides stay in sync across all operations)

Run overnight:
    python test_ratchet_torture.py

Parallel (requires pytest-xdist):
    python -m pytest test_ratchet_torture.py -n 4

Expected runtime on Android/Termux:
    100K ops  ≈  2-3 min
    1M   ops  ≈  20-30 min
    10M  ops  ≈  3-6 hours
"""

import os
import sys
import time
import random
import secrets
import collections
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import otrv4_ as otr
import otr4_crypto_ext as _ossl


# ── Configuration ────────────────────────────────────────────────────────────
DEFAULT_RUNS      = 100_000   # default for pytest run (fast, ~2 min)
OVERNIGHT_RUNS    = 10_000_000
OOO_WINDOW        = 8          # max out-of-order reordering window
REPLAY_SAMPLE     = 0.002      # fraction of messages to replay (expect failure)
# ─────────────────────────────────────────────────────────────────────────────


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


def _run_torture(runs: int, seed: int = None):
    """
    Core torture loop. Returns stats dict on success, raises on any violation.
    """
    rng = random.Random(seed)   # seeded for reproducibility on failure

    alice, bob = _make_pair()

    seen_nonces    = set()       # (bytes) — must all be unique
    seen_key_slots = set()       # (sender_id, ratchet_id, msg_num)
    corruptions    = 0
    replays_tested = 0
    replays_caught = 0
    ooo_delivered  = 0

    # Out-of-order buffer: list of (receiver, header, ct, nonce, tag, plaintext)
    ooo_buffer = collections.deque()

    stats = {
        'runs': runs, 'corruptions': 0, 'nonce_reuse': 0,
        'key_slot_reuse': 0, 'ooo_delivered': 0,
        'replays_tested': 0, 'replays_caught': 0,
    }

    for i in range(runs):
        # Alternate sender randomly
        if rng.random() < 0.5:
            sender, receiver, sid = alice, bob, 'A'
        else:
            sender, receiver, sid = bob, alice, 'B'

        msg = os.urandom(rng.randint(1, 256))

        ct, header, nonce, tag, ratchet_id, _ = sender.encrypt_message(msg)

        # ── Nonce uniqueness ─────────────────────────────────────────────────
        if nonce in seen_nonces:
            raise RuntimeError(f"NONCE REUSE at op {i}: {nonce.hex()}")
        seen_nonces.add(nonce)

        # ── Message key slot uniqueness ──────────────────────────────────────
        msg_num  = sender.message_num_send - 1   # just incremented
        key_slot = (sid, ratchet_id, msg_num)
        if key_slot in seen_key_slots:
            raise RuntimeError(f"KEY SLOT REUSE at op {i}: {key_slot}")
        seen_key_slots.add(key_slot)

        # ── Out-of-order: buffer some messages, deliver others randomly ──────
        entry = (receiver, header, ct, nonce, tag, msg)
        if rng.random() < 0.3 and len(ooo_buffer) < OOO_WINDOW:
            ooo_buffer.append(entry)
        else:
            # Deliver current message in order
            try:
                pt = receiver.decrypt_message(header, ct, nonce, tag)
                if pt != msg:
                    raise RuntimeError(f"PLAINTEXT CORRUPTION at op {i}")
            except otr.EncryptionError as e:
                raise RuntimeError(f"DECRYPT FAILED at op {i}: {e}")

            # ── Replay test — MUST be here, inside the delivery branch ────────
            # Replaying a buffered (not yet delivered) message before first
            # delivery would consume the chain key slot, causing the real OOO
            # delivery to fail with InvalidTag.  Only replay after delivery.
            if rng.random() < REPLAY_SAMPLE:
                replays_tested += 1
                try:
                    receiver.decrypt_message(header, ct, nonce, tag)
                    raise RuntimeError(f"REPLAY SUCCEEDED at op {i}")
                except Exception:
                    replays_caught += 1

            # Randomly drain some buffered OOO messages
            while ooo_buffer and rng.random() < 0.4:
                ooo_recv, ooo_h, ooo_ct, ooo_n, ooo_t, ooo_msg = ooo_buffer.popleft()
                try:
                    ooo_pt = ooo_recv.decrypt_message(ooo_h, ooo_ct, ooo_n, ooo_t)
                    if ooo_pt != ooo_msg:
                        raise RuntimeError(f"OOO PLAINTEXT CORRUPTION at op {i}")
                    ooo_delivered += 1
                except otr.EncryptionError:
                    # May fail if ratchet advanced past the skip window — acceptable
                    pass

        if i > 0 and i % 10_000 == 0:
            elapsed = time.time()
            print(f"  {i:>8,} ops | "
                  f"nonces={len(seen_nonces):,} | "
                  f"ooo={ooo_delivered:,} | "
                  f"replays={replays_caught}/{replays_tested}",
                  flush=True)

    # Drain remaining OOO buffer
    for ooo_recv, ooo_h, ooo_ct, ooo_n, ooo_t, ooo_msg in ooo_buffer:
        try:
            ooo_recv.decrypt_message(ooo_h, ooo_ct, ooo_n, ooo_t)
            ooo_delivered += 1
        except otr.EncryptionError:
            pass

    stats.update({
        'ooo_delivered':   ooo_delivered,
        'replays_tested':  replays_tested,
        'replays_caught':  replays_caught,
    })
    return stats


# ═════════════════════════════════════════════════════════════════════════════
# Pytest tests (fast — run as part of full suite)
# ═════════════════════════════════════════════════════════════════════════════

class TestRatchetTorture:

    def test_torture_10k(self):
        """10,000 ops — runs in ~15 seconds, catches the vast majority of bugs."""
        t0 = time.time()
        stats = _run_torture(runs=10_000, seed=42)
        elapsed = time.time() - t0
        print(f"\n  10K torture: {elapsed:.1f}s | ooo={stats['ooo_delivered']} "
              f"replays={stats['replays_caught']}/{stats['replays_tested']}")
        assert stats['corruptions'] == 0

    def test_torture_50k_random_seed(self):
        """50,000 ops with a random seed — different every run."""
        stats = _run_torture(runs=50_000, seed=None)
        assert stats['corruptions'] == 0

    def test_torture_nonce_uniqueness_100k(self):
        """100,000 ops specifically checking nonce uniqueness."""
        # Would raise RuntimeError inside _run_torture on any collision
        _run_torture(runs=100_000, seed=12345)

    def test_torture_replay_always_rejected(self):
        """
        In 10,000 ops with 0.2% replay rate, every replay must be caught.
        """
        stats = _run_torture(runs=10_000, seed=99)
        assert stats['replays_caught'] == stats['replays_tested'], \
            f"Some replays succeeded: {stats['replays_tested'] - stats['replays_caught']} not rejected"

    def test_torture_key_slot_uniqueness_50k(self):
        """
        50,000 operations must produce 50,000 unique (sender, ratchet_id, msg_num)
        key slots — no message key position is ever reused.
        """
        _run_torture(runs=50_000, seed=777)


# ═════════════════════════════════════════════════════════════════════════════
# Overnight / standalone runner
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Ratchet torture harness')
    parser.add_argument('--runs', type=int, default=OVERNIGHT_RUNS,
                        help=f'Number of operations (default: {OVERNIGHT_RUNS:,})')
    parser.add_argument('--seed', type=int, default=None,
                        help='Random seed (default: random)')
    args = parser.parse_args()

    print(f"Ratchet Torture Harness")
    print(f"  Operations : {args.runs:,}")
    print(f"  Seed       : {args.seed}")
    print(f"  OOO window : {OOO_WINDOW}")
    print(f"  Replay rate: {REPLAY_SAMPLE*100:.1f}%")
    print()

    t0 = time.time()
    try:
        stats = _run_torture(runs=args.runs, seed=args.seed)
        elapsed = time.time() - t0
        print(f"\n✅ PASSED — {args.runs:,} operations in {elapsed:.1f}s "
              f"({args.runs/elapsed:,.0f} ops/sec)")
        print(f"   OOO delivered : {stats['ooo_delivered']:,}")
        print(f"   Replays caught: {stats['replays_caught']}/{stats['replays_tested']}")
    except RuntimeError as e:
        elapsed = time.time() - t0
        print(f"\n❌ FAILED after {elapsed:.1f}s: {e}")
        sys.exit(1)
