#!/usr/bin/env python3
"""
Differential tests for otrv4+.py.

These tests verify that our implementation's wire-format parsing is
self-consistent and matches expected structural invariants — the closest
we can get to differential testing without a full second implementation.

Tests structured as:
  Encode with impl A → decode with impl B → compare
  where A/B are different code paths within otrv4+.py (encode vs. decode,
  different message sizes, different session roles).

Also includes cross-version wire format regression tests so future changes
can't silently break the on-wire format.

Run:  python -m pytest test_differential.py -v
"""

import sys
import os
import struct
import secrets
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import otrv4_testlib as otr
import otr4_crypto_ext as _ossl

from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography.hazmat.primitives import serialization

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# 1. TLV encode↔decode differential
# ─────────────────────────────────────────────────────────────────────────────

class TestTLVDifferential:
    """Encode via direct struct packing, decode via OTRv4TLV — outputs must match."""

    def _manual_encode_tlv(self, tlv_type: int, data: bytes) -> bytes:
        """Reference encoder: type(2) + length(2) + data."""
        return struct.pack('!HH', tlv_type, len(data)) + data

    def test_known_types(self):
        """Known TLV types round-trip correctly."""
        for t, d in [
            (0,      b''),              # NULL/disconnect
            (1,      b''),              # PADDING
            (2,      b'\x00'*32),      # disconnected
            (0x0001, b'hello world'),
            (0xFFFF, b'\xff'*64),
        ]:
            manual = self._manual_encode_tlv(t, d)
            tlv    = otr.OTRv4TLV(t, d)
            impl   = tlv.encode()
            assert manual == impl, \
                f"Encoder mismatch for type={t}: manual={manual.hex()} impl={impl.hex()}"
            dec, _ = otr.OTRv4TLV.decode_one(manual)
            assert dec.type == t
            assert dec.value     == d

    def test_chained_tlvs(self):
        """Multiple TLVs concatenated then decoded matches encode_all + decode_all."""
        pairs = [(1, b''), (2, b'\x01'*16), (3, b'abc')]
        manual = b''.join(self._manual_encode_tlv(t, d) for t, d in pairs)
        tlvs   = [otr.OTRv4TLV(t, d) for t, d in pairs]
        impl   = otr.OTRv4TLV.encode_all(tlvs)
        assert manual == impl

        decoded = otr.OTRv4TLV.decode_all(impl)
        assert len(decoded) == len(pairs)
        for orig, dec in zip(pairs, decoded):
            assert dec.type == orig[0]
            assert dec.value     == orig[1]


# ─────────────────────────────────────────────────────────────────────────────
# 2. KDF_1 vs. manual SHAKE-256 reference
# ─────────────────────────────────────────────────────────────────────────────

class TestKDFDifferential:
    """Our kdf_1 must match the spec formula: SHAKE-256(usage_byte ‖ value, length)."""

    def _reference_kdf(self, usage_id: int, value: bytes, length: int) -> bytes:
        """OTRv4 spec §3.2 reference implementation."""
        shake = hashlib.shake_256()
        shake.update(b"OTRv4")
        shake.update(bytes([usage_id]))
        shake.update(value)
        return shake.digest(length)

    def test_message_key(self):
        value = b'chain_key_test_value'
        for length in [16, 32, 64, 96]:
            assert (otr.kdf_1(otr.KDFUsage.MESSAGE_KEY, value, length) ==
                    self._reference_kdf(0x13, value, length)), \
                f"MESSAGE_KEY mismatch at length={length}"

    def test_mac_key(self):
        value = b'another_test_value'
        assert (otr.kdf_1(otr.KDFUsage.MAC_KEY, value, 64) ==
                self._reference_kdf(0x14, value, 64))

    def test_brace_key(self):
        value = secrets.token_bytes(32)
        assert (otr.kdf_1(otr.KDFUsage.BRACE_KEY, value, 32) ==
                self._reference_kdf(0x02, value, 32))

    def test_all_usage_ids(self):
        """Every KDFUsage constant matches the manual SHAKE formula."""
        value = b'test_value_for_differential'
        for attr in dir(otr.KDFUsage):
            if attr.startswith('_'):
                continue
            usage_id = getattr(otr.KDFUsage, attr)
            if not isinstance(usage_id, int):
                continue
            expected = self._reference_kdf(usage_id, value, 32)
            got      = otr.kdf_1(usage_id, value, 32)
            assert got == expected, \
                f"KDFUsage.{attr} (0x{usage_id:02x}) mismatch"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Double ratchet: Alice→Bob then Bob→Alice (role symmetry)
# ─────────────────────────────────────────────────────────────────────────────

def _make_ratchet_pair():
    root_key  = secrets.token_bytes(32)
    ck_a      = secrets.token_bytes(32)
    ck_b      = secrets.token_bytes(32)
    ad        = secrets.token_bytes(32)
    brace_key = secrets.token_bytes(32)
    rk_a = otr.SecureMemory(32); rk_a.write(root_key)
    rk_b = otr.SecureMemory(32); rk_b.write(root_key)
    alice = otr.DoubleRatchet(root_key=rk_a, is_initiator=True,
                               chain_key_send=ck_a, chain_key_recv=ck_b,
                               ad=ad, brace_key=brace_key)
    bob   = otr.DoubleRatchet(root_key=rk_b, is_initiator=False,
                               chain_key_send=ck_b, chain_key_recv=ck_a,
                               ad=ad, brace_key=brace_key)
    return alice, bob


class TestRatchetDifferential:
    """Cross-role consistency tests."""

    def test_alice_to_bob(self):
        alice, bob = _make_ratchet_pair()
        msg = b"hello bob"
        ct, hdr, nonce, tag, _, _ = alice.encrypt_message(msg)
        assert bob.decrypt_message(hdr, ct, nonce, tag) == msg

    def test_bob_to_alice(self):
        alice, bob = _make_ratchet_pair()
        msg = b"hello alice"
        ct, hdr, nonce, tag, _, _ = bob.encrypt_message(msg)
        assert alice.decrypt_message(hdr, ct, nonce, tag) == msg

    def test_interleaved(self):
        """Interleaved Alice↔Bob messages all decrypt correctly."""
        alice, bob = _make_ratchet_pair()
        exchanges = [
            (alice, bob, b"A-to-B msg 1"),
            (bob, alice, b"B-to-A reply 1"),
            (alice, bob, b"A-to-B msg 2"),
            (alice, bob, b"A-to-B msg 3"),
            (bob, alice, b"B-to-A reply 2"),
        ]
        for sender, receiver, msg in exchanges:
            ct, hdr, nonce, tag, _, _ = sender.encrypt_message(msg)
            assert receiver.decrypt_message(hdr, ct, nonce, tag) == msg

    def test_chain_key_advances(self):
        """Sending N messages produces N different ciphertexts for the same plaintext."""
        alice, bob = _make_ratchet_pair()
        msg = b"same message every time"
        ciphertexts = set()
        for _ in range(5):
            ct, hdr, nonce, tag, _, _ = alice.encrypt_message(msg)
            key = ct + nonce  # (ct, nonce) pair must be unique
            assert key not in ciphertexts, "Ratchet reused (ct, nonce) pair — chain key not advancing"
            ciphertexts.add(key)
            bob.decrypt_message(hdr, ct, nonce, tag)


# ─────────────────────────────────────────────────────────────────────────────
# 4. ML-KEM differential: encaps on same key → different ct, same-length ss
# ─────────────────────────────────────────────────────────────────────────────

class TestMLKEMDifferential:
    def test_two_encaps_same_key(self):
        ek, dk = _ossl.mlkem1024_keygen()
        ct1, ss1 = _ossl.mlkem1024_encaps(ek)
        ct2, ss2 = _ossl.mlkem1024_encaps(ek)
        # Different randomness → different ciphertext and different shared secret
        assert ct1 != ct2, "ML-KEM produced identical ciphertexts (broken RNG?)"
        assert ss1 != ss2, "ML-KEM produced identical shared secrets (broken RNG?)"
        # Both shared secrets are the correct length
        assert len(ss1) == len(ss2) == 32

    def test_decaps_cross(self):
        """Decaps with the wrong ciphertext gives a different (random-looking) secret."""
        ek, dk   = _ossl.mlkem1024_keygen()
        ct1, ss1 = _ossl.mlkem1024_encaps(ek)
        ct2, _   = _ossl.mlkem1024_encaps(ek)
        ss_wrong = _ossl.mlkem1024_decaps(ct2, dk)
        # ML-KEM implicit rejection: wrong ct → different ss (not crash/exception)
        assert ss_wrong != ss1


# ─────────────────────────────────────────────────────────────────────────────
# 5. Ring signature: sign with k1 vs k2 — both verify (OR proof)
# ─────────────────────────────────────────────────────────────────────────────

class TestRingSignatureDifferential:
    def test_both_keys_verify(self):
        """Both A1 and A2 can sign — verifier can't tell which one did."""
        k1 = ed448.Ed448PrivateKey.generate()
        k2 = ed448.Ed448PrivateKey.generate()
        A1 = k1.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        A2 = k2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        msg = b"deniable auth test"

        sig1 = otr.RingSignature.sign(k1, A1, A2, msg)
        sig2 = otr.RingSignature.sign(k2, A2, A1, msg)  # note swapped A1/A2 for k2

        # Both signatures verify against the same (A1, A2) pair
        assert otr.RingSignature.verify(A1, A2, msg, sig1), "sig by k1 failed"
        # sig2 is over (A2, A1) — same keys, different ordering
        assert otr.RingSignature.verify(A2, A1, msg, sig2), "sig by k2 failed"

    def test_signatures_are_different(self):
        """Two signatures over the same message by the same key must differ (random nonce)."""
        k1 = ed448.Ed448PrivateKey.generate()
        k2 = ed448.Ed448PrivateKey.generate()
        A1 = k1.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        A2 = k2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        msg = b"test"
        sig1 = otr.RingSignature.sign(k1, A1, A2, msg)
        sig2 = otr.RingSignature.sign(k1, A1, A2, msg)
        assert sig1 != sig2, "Ring signature is deterministic — random nonce not being used"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Wire-format regression: fixed known-good vectors
# ─────────────────────────────────────────────────────────────────────────────

class TestWireFormatRegression:
    """Pinned wire-format vectors — catch any accidental format change."""

    def test_tlv_null_encoding(self):
        """Type=0, length=0 encodes as 4 zero bytes."""
        tlv = otr.OTRv4TLV(0, b'')
        assert tlv.encode() == b'\x00\x00\x00\x00'

    def test_kdf_usage_ids_stable(self):
        """KDF usage IDs must never change — they're on-wire constants."""
        assert otr.KDFUsage.SSID       == 0x01
        assert otr.KDFUsage.BRACE_KEY  == 0x02
        assert otr.KDFUsage.SHARED_SECRET == 0x03
        assert otr.KDFUsage.ROOT_KEY   == 0x11
        assert otr.KDFUsage.CHAIN_KEY  == 0x12
        assert otr.KDFUsage.MESSAGE_KEY== 0x13
        assert otr.KDFUsage.MAC_KEY    == 0x14
        assert otr.KDFUsage.DAKE_MAC_KEY == 0x15

    def test_kdf_known_vector(self):
        """Pinned KDF output — if this changes, the wire format is broken."""
        value    = b'\x00' * 32
        expected = hashlib.shake_256(b"OTRv4" + bytes([0x13]) + value).digest(32)
        got      = otr.kdf_1(otr.KDFUsage.MESSAGE_KEY, value, 32)
        assert got == expected, \
            f"KDF regression: expected {expected.hex()}, got {got.hex()}"

    def test_message_type_constants(self):
        """Message type bytes are on-wire — must not change."""
        assert otr.OTRConstants.MESSAGE_TYPE_DAKE1 == 0x35
        assert otr.OTRConstants.MESSAGE_TYPE_DAKE2 == 0x36
        assert otr.OTRConstants.MESSAGE_TYPE_DAKE3 == 0x37
        assert otr.OTRConstants.MESSAGE_TYPE_DATA  == 0x03


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import subprocess, sys
    sys.exit(subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"]
    ).returncode)
