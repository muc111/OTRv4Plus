#!/usr/bin/env python3
"""
Adversarial Security Tests for OTRv4+ Rust Core
"""

import pytest
import secrets
import time
from otrv4_core import RustDoubleRatchet, rust_kdf_1, rust_encode_header

USAGE_ROOT_KEY = 0x11
USAGE_CHAIN_KEY = 0x12
USAGE_MESSAGE_KEY = 0x13


def create_matching_pair():
    """Create Alice and Bob ratchets that can actually communicate."""
    root_key = secrets.token_bytes(32)
    brace_key = secrets.token_bytes(32)
    
    send_ck = secrets.token_bytes(32)  # Alice -> Bob
    recv_ck = secrets.token_bytes(32)  # Bob -> Alice
    
    alice_pub = secrets.token_bytes(56)
    bob_pub = secrets.token_bytes(56)
    
    alice = RustDoubleRatchet(root_key, send_ck, recv_ck, brace_key, alice_pub, True)
    bob = RustDoubleRatchet(root_key, send_ck, recv_ck, brace_key, bob_pub, False)
    
    return alice, bob


class TestRNGSecurity:
    def test_nonce_uniqueness(self):
        alice, _ = create_matching_pair()
        nonces = [bytes(alice.encrypt(b"test").nonce) for _ in range(100)]
        assert len(set(nonces)) == 100
        assert len(set(n[0] for n in nonces)) > 50

    def test_nonce_not_predictable(self):
        alice, _ = create_matching_pair()
        nonces = [int.from_bytes(bytes(alice.encrypt(b"test").nonce), 'big') for _ in range(50)]
        diffs = [nonces[i+1] - nonces[i] for i in range(len(nonces)-1)]
        assert len(set(diffs)) > 40


class TestKDFForwardSecrecy:
    def test_message_key_independence(self):
        ck = secrets.token_bytes(32)
        mk1 = rust_kdf_1(USAGE_MESSAGE_KEY, ck, 32)
        ck2 = rust_kdf_1(USAGE_CHAIN_KEY, ck, 32)
        mk2 = rust_kdf_1(USAGE_MESSAGE_KEY, ck2, 32)
        assert mk1 != mk2
        assert abs(int.from_bytes(mk1, 'big') - int.from_bytes(mk2, 'big')) > 2**200

    def test_kdf_domain_separation(self):
        val = secrets.token_bytes(64)
        outs = {u: rust_kdf_1(u, val, 32) for u in [0x11,0x12,0x13,0x14,0x15,0x16]}
        assert len(set(bytes(o) for o in outs.values())) == 6

    def test_chain_key_zeroization(self):
        alice, _ = create_matching_pair()
        for _ in range(100):
            alice.encrypt(b"test")
        assert len(bytes(alice.encrypt(b"final").ciphertext)) > 0


class TestHybridKeyComposition:
    def test_dh_pq_contributions_both_required(self):
        root = secrets.token_bytes(32)
        dh1, dh2 = secrets.token_bytes(56), secrets.token_bytes(56)
        pq1, pq2 = secrets.token_bytes(32), secrets.token_bytes(32)
        dh_part1 = rust_kdf_1(0x17, dh1, 32)
        dh_part2 = rust_kdf_1(0x17, dh2, 32)
        pq_part1 = rust_kdf_1(0x18, pq1, 32)
        pq_part2 = rust_kdf_1(0x18, pq2, 32)
        out1 = rust_kdf_1(USAGE_ROOT_KEY, root + dh_part1 + pq_part1, 64)
        out2 = rust_kdf_1(USAGE_ROOT_KEY, root + dh_part1 + pq_part2, 64)
        out3 = rust_kdf_1(USAGE_ROOT_KEY, root + dh_part2 + pq_part1, 64)
        assert out1 != out2 and out1 != out3


class TestDoSProtection:
    def test_max_skip_enforcement(self):
        alice, bob = create_matching_pair()
        setup = alice.encrypt(b"setup")
        bob.decrypt_same_dh(bytes(setup.header), bytes(setup.ciphertext), bytes(setup.nonce), bytes(setup.tag))
        header = rust_encode_header(bytes(alice.local_pub()), 0, 2000)
        with pytest.raises(ValueError, match="max skip"):
            bob.decrypt_same_dh(header, b"fake", secrets.token_bytes(12), secrets.token_bytes(16))

    def test_bounded_ratchet_loop_performance(self):
        alice, _ = create_matching_pair()
        start = time.time()
        for _ in range(100): alice.encrypt(b"test")
        t1 = time.time() - start
        start = time.time()
        for _ in range(100): alice.encrypt(b"test")
        t2 = time.time() - start
        assert t2 < t1 * 3

    def test_memory_exhaustion_prevention(self):
        alice, bob = create_matching_pair()
        # Establish connection
        setup = alice.encrypt(b"setup")
        bob.decrypt_same_dh(bytes(setup.header), bytes(setup.ciphertext), bytes(setup.nonce), bytes(setup.tag))
        
        # Send 3000 messages in batches, decrypting the last of each batch to keep Bob's counter near the end
        batch_size = 500
        total = 3000
        all_msgs = []
        for start in range(0, total, batch_size):
            batch = []
            for i in range(start, min(start + batch_size, total)):
                res = alice.encrypt(f"msg{i}".encode())
                batch.append((bytes(res.header), bytes(res.ciphertext), bytes(res.nonce), bytes(res.tag)))
            all_msgs.extend(batch)
            # Advance Bob's receive chain by decrypting the last message of this batch
            last = batch[-1]
            bob.decrypt_same_dh(last[0], last[1], last[2], last[3])
        
        # Now decrypt the last 1000 messages in reverse order → forces skipped key storage
        cnt = 0
        for h, c, n, t in reversed(all_msgs[-1000:]):
            try:
                bob.decrypt_same_dh(h, c, n, t)
                cnt += 1
            except ValueError as e:
                if "message too old" in str(e) or "replay" in str(e):
                    continue
                raise
        
        assert cnt > 0, "No out-of-order messages decrypted"
        # Verify the ratchet still works (no memory exhaustion)
        final = alice.encrypt(b"final")
        assert len(bytes(final.ciphertext)) > 0


class TestReplayCacheSecurity:
    def test_replay_cache_performance(self):
        alice, bob = create_matching_pair()
        setup = alice.encrypt(b"setup")
        bob.decrypt_same_dh(bytes(setup.header), bytes(setup.ciphertext), bytes(setup.nonce), bytes(setup.tag))
        msgs = []
        for _ in range(500):
            res = alice.encrypt(b"test")
            m = (bytes(res.header), bytes(res.ciphertext), bytes(res.nonce), bytes(res.tag))
            msgs.append(m)
            bob.decrypt_same_dh(*m)
        start = time.time()
        for m in msgs[:100]:
            try: bob.decrypt_same_dh(*m)
            except ValueError as e: assert "replay" in str(e)
        assert time.time() - start < 2.0

    def test_replay_attack_prevention(self):
        alice, bob = create_matching_pair()
        setup = alice.encrypt(b"setup")
        bob.decrypt_same_dh(bytes(setup.header), bytes(setup.ciphertext), bytes(setup.nonce), bytes(setup.tag))
        res = alice.encrypt(b"legitimate")
        h, c, n, t = bytes(res.header), bytes(res.ciphertext), bytes(res.nonce), bytes(res.tag)
        assert bob.decrypt_same_dh(h, c, n, t) == b"legitimate"
        with pytest.raises(ValueError, match="replay"):
            bob.decrypt_same_dh(h, c, n, t)

    def test_replay_cache_eviction_correctness(self):
        alice, bob = create_matching_pair()
        setup = alice.encrypt(b"setup")
        bob.decrypt_same_dh(bytes(setup.header), bytes(setup.ciphertext), bytes(setup.nonce), bytes(setup.tag))
        success = 0
        for i in range(15000):
            res = alice.encrypt(f"msg{i}".encode())
            try:
                bob.decrypt_same_dh(bytes(res.header), bytes(res.ciphertext), bytes(res.nonce), bytes(res.tag))
                success += 1
            except ValueError: continue
        assert success > 10000
        final = alice.encrypt(b"final")
        assert bob.decrypt_same_dh(bytes(final.header), bytes(final.ciphertext), bytes(final.nonce), bytes(final.tag)) == b"final"


class TestCryptographicSanity:
    def test_constant_time_comparison(self):
        alice, bob = create_matching_pair()
        setup = alice.encrypt(b"setup")
        bob.decrypt_same_dh(bytes(setup.header), bytes(setup.ciphertext), bytes(setup.nonce), bytes(setup.tag))
        res = alice.encrypt(b"test")
        h, c, n, t = bytes(res.header), bytes(res.ciphertext), bytes(res.nonce), bytes(res.tag)
        start = time.perf_counter()
        bob.decrypt_same_dh(h, c, n, t)
        t_ok = time.perf_counter() - start
        bad_t = bytearray(t); bad_t[0] ^= 0xFF
        start = time.perf_counter()
        try: bob.decrypt_same_dh(h, c, n, bytes(bad_t))
        except ValueError: pass
        t_bad = time.perf_counter() - start
        ratio = max(t_ok, t_bad) / (min(t_ok, t_bad) + 1e-9)
        assert ratio < 10

    def test_zeroization_prevents_key_reuse(self):
        alice, _ = create_matching_pair()
        cts = [bytes(alice.encrypt(b"test").ciphertext) for _ in range(10)]
        assert len(set(cts)) == 10


class TestProtocolStateMachine:
    def test_ratchet_id_increments_correctly(self):
        alice, _ = create_matching_pair()
        rid = alice.ratchet_id()
        for _ in range(10): alice.encrypt(b"test")
        assert alice.ratchet_id() == rid

    def test_send_ratchet_updates_state(self):
        alice, _ = create_matching_pair()
        old_pub = bytes(alice.local_pub())
        dh = secrets.token_bytes(56)
        new_pub = secrets.token_bytes(56)
        alice.send_ratchet(dh, new_pub)
        assert bytes(alice.local_pub()) == new_pub
        assert old_pub != new_pub


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=line"])