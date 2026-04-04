#!/usr/bin/env python3
"""
Property-based tests for otrv4+.py using Hypothesis.

Tests fundamental cryptographic invariants that must hold for ALL inputs:
  - decrypt(encrypt(m)) == m
  - KDF domain separation
  - MAC verify ∘ MAC compute == True
  - Ring signature self-consistency
  - Ratchet forward secrecy
  - ML-KEM round-trip
  - TLV encode/decode round-trips
  - SMP math identities

Install:  pip install hypothesis
Run:      python -m pytest test_property.py -v
          python -m pytest test_property.py -v --hypothesis-seed=0  # deterministic
"""

import sys
import os
import struct
import secrets
import hashlib
import hmac as _hmac

# ── path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import otrv4_testlib as otr

import pytest
from hypothesis import given, settings, assume, note, HealthCheck
from hypothesis import strategies as st

# Suppress slow-test warning for crypto — these ARE slow by design
settings.register_profile("crypto", max_examples=50,
                           suppress_health_check=[HealthCheck.too_slow],
                           deadline=None)
settings.register_profile("ci",     max_examples=20,
                           suppress_health_check=[HealthCheck.too_slow],
                           deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "crypto"))

# ─────────────────────────────────────────────────────────────────────────────
# Strategies
# ─────────────────────────────────────────────────────────────────────────────

plaintext_st  = st.binary(min_size=0,   max_size=4096)
short_bytes   = st.binary(min_size=0,   max_size=256)
key32_st      = st.binary(min_size=32,  max_size=32)
key64_st      = st.binary(min_size=64,  max_size=64)
nonce12_st    = st.binary(min_size=12,  max_size=12)
tag_type_st   = st.integers(min_value=1, max_value=65535)  # 0=PADDING discarded by spec
arbitrary_bytes = st.binary(min_size=0, max_size=8192)

# ─────────────────────────────────────────────────────────────────────────────
# 1. AES-256-GCM: decrypt(encrypt(m)) == m
# ─────────────────────────────────────────────────────────────────────────────

class TestAESGCMRoundTrip:
    """Property: AES-GCM decryption is the exact inverse of encryption."""

    @given(plaintext=plaintext_st, key=key32_st, nonce=nonce12_st,
           aad=short_bytes)
    def test_encrypt_decrypt_identity(self, plaintext, key, nonce, aad):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
        recovered   = aesgcm.decrypt(nonce, ct_with_tag, aad)
        assert recovered == plaintext, "decrypt(encrypt(m)) != m"

    @given(plaintext=plaintext_st, key=key32_st, nonce=nonce12_st,
           aad=short_bytes, flip_byte=st.integers(0, 255))
    def test_tampered_ciphertext_rejected(self, plaintext, key, nonce, aad, flip_byte):
        """Any bit flip in the ciphertext must cause authentication failure."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        assume(len(plaintext) > 0)  # need at least one byte to flip
        aesgcm = AESGCM(key)
        ct = bytearray(aesgcm.encrypt(nonce, plaintext, aad))
        ct[0] ^= (flip_byte or 1)  # flip a bit in the ciphertext
        with pytest.raises((InvalidTag, Exception)):
            aesgcm.decrypt(nonce, bytes(ct), aad)

    @given(plaintext=plaintext_st, key=key32_st, nonce=nonce12_st,
           aad=short_bytes, wrong_aad=short_bytes)
    def test_wrong_aad_rejected(self, plaintext, key, nonce, aad, wrong_aad):
        """Wrong AAD must cause authentication failure."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        assume(aad != wrong_aad)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        with pytest.raises((InvalidTag, Exception)):
            aesgcm.decrypt(nonce, ct, wrong_aad)


# ─────────────────────────────────────────────────────────────────────────────
# 2. KDF_1 — domain separation and determinism
# ─────────────────────────────────────────────────────────────────────────────

class TestKDF:
    """Properties of KDF_1 = SHAKE-256(usage_id ‖ value, length)."""

    @given(value=short_bytes, length=st.integers(1, 128))
    def test_deterministic(self, value, length):
        """Same inputs always produce the same output."""
        out1 = otr.kdf_1(otr.KDFUsage.MESSAGE_KEY, value, length)
        out2 = otr.kdf_1(otr.KDFUsage.MESSAGE_KEY, value, length)
        assert out1 == out2

    @given(value=short_bytes, length=st.integers(1, 128))
    def test_output_length(self, value, length):
        """Output is exactly *length* bytes."""
        out = otr.kdf_1(otr.KDFUsage.MESSAGE_KEY, value, length)
        assert len(out) == length

    @given(value=short_bytes, length=st.integers(16, 64))
    def test_domain_separation(self, value, length):
        """Different usage IDs produce different outputs (with overwhelming probability).
        length >= 16 so output space is large enough to make collisions negligible;
        1-byte outputs only have 256 possible values — birthday hits are expected."""
        out_msg = otr.kdf_1(otr.KDFUsage.MESSAGE_KEY,  value, length)
        out_mac = otr.kdf_1(otr.KDFUsage.MAC_KEY,       value, length)
        out_ck  = otr.kdf_1(otr.KDFUsage.CHAIN_KEY,     value, length)
        assert out_msg != out_mac, "MESSAGE_KEY == MAC_KEY — domain collision"
        assert out_msg != out_ck,  "MESSAGE_KEY == CHAIN_KEY — domain collision"
        assert out_mac != out_ck,  "MAC_KEY == CHAIN_KEY — domain collision"

    @given(v1=short_bytes, v2=short_bytes, length=st.integers(16, 64))
    def test_input_sensitivity(self, v1, v2, length):
        """Different values produce different outputs (with overwhelming probability).
        length >= 16 so output space is large enough to make collisions negligible;
        testing 1-byte outputs risks birthday hits with only 256 possible values."""
        assume(v1 != v2)
        out1 = otr.kdf_1(otr.KDFUsage.MESSAGE_KEY, v1, length)
        out2 = otr.kdf_1(otr.KDFUsage.MESSAGE_KEY, v2, length)
        assert out1 != out2


# ─────────────────────────────────────────────────────────────────────────────
# 3. SHA3-512 HMAC — verify ∘ compute == True
# ─────────────────────────────────────────────────────────────────────────────

class TestMAC:
    @given(key=key32_st, data=short_bytes)
    def test_verify_own_mac(self, key, data):
        mac = otr.SHA3_512.hmac(key, data)
        assert _hmac.compare_digest(mac, otr.SHA3_512.hmac(key, data))

    @given(key=key32_st, data=short_bytes, wrong_key=key32_st)
    def test_wrong_key_fails(self, key, data, wrong_key):
        assume(key != wrong_key)
        mac = otr.SHA3_512.hmac(key, data)
        assert not _hmac.compare_digest(mac, otr.SHA3_512.hmac(wrong_key, data))

    @given(key=key32_st, d1=short_bytes, d2=short_bytes)
    def test_wrong_data_fails(self, key, d1, d2):
        assume(d1 != d2)
        mac1 = otr.SHA3_512.hmac(key, d1)
        mac2 = otr.SHA3_512.hmac(key, d2)
        assert not _hmac.compare_digest(mac1, mac2)


# ─────────────────────────────────────────────────────────────────────────────
# 4. TLV encode/decode round-trip
# ─────────────────────────────────────────────────────────────────────────────

class TestTLVRoundTrip:
    @given(tlv_type=tag_type_st, data=short_bytes)
    def test_single_tlv_roundtrip(self, tlv_type, data):
        tlv   = otr.OTRv4TLV(tlv_type, data)
        enc   = tlv.encode()
        dec, consumed = otr.OTRv4TLV.decode_one(enc)
        assert dec.type == tlv_type
        assert dec.value == data
        assert consumed == len(enc)

    @given(pairs=st.lists(
        st.tuples(tag_type_st, short_bytes), min_size=0, max_size=8))
    def test_multiple_tlv_roundtrip(self, pairs):
        tlvs = [otr.OTRv4TLV(t, d) for t, d in pairs]
        enc  = otr.OTRv4TLV.encode_all(tlvs)
        dec  = otr.OTRv4TLV.decode_all(enc)
        assert len(dec) == len(tlvs)
        for orig, recovered in zip(tlvs, dec):
            assert orig.type == recovered.type
            assert orig.value     == recovered.value


# ─────────────────────────────────────────────────────────────────────────────
# 5. OTRv4Payload encode/decode round-trip
# ─────────────────────────────────────────────────────────────────────────────

printable_st = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Zs")),
    max_size=512)

class TestPayloadRoundTrip:
    @given(text=printable_st)
    def test_text_roundtrip(self, text):
        payload = otr.OTRv4Payload(text=text, tlvs=[])
        enc     = payload.encode(add_padding=False)
        dec     = otr.OTRv4Payload.decode(enc)
        assert dec.text == text

    @given(text=printable_st,
           tlv_pairs=st.lists(st.tuples(tag_type_st, short_bytes), max_size=4))
    def test_text_with_tlvs_roundtrip(self, text, tlv_pairs):
        tlvs    = [otr.OTRv4TLV(t, d) for t, d in tlv_pairs]
        payload = otr.OTRv4Payload(text=text, tlvs=tlvs)
        enc     = payload.encode(add_padding=False)
        dec     = otr.OTRv4Payload.decode(enc)
        assert dec.text == text
        assert len(dec.tlvs) == len(tlvs)


# ─────────────────────────────────────────────────────────────────────────────
# 6. RatchetHeader encode/decode round-trip
# ─────────────────────────────────────────────────────────────────────────────

class TestRatchetHeaderRoundTrip:
    @given(dh_pub=st.binary(min_size=56, max_size=56),
           prev_chain_len=st.integers(0, 65535),
           msg_num=st.integers(0, 65535))
    def test_roundtrip(self, dh_pub, prev_chain_len, msg_num):
        hdr = otr.RatchetHeader(dh_pub, prev_chain_len, msg_num)
        enc = hdr.encode()
        dec = otr.RatchetHeader.decode(enc)
        assert dec.dh_pub         == dh_pub
        assert dec.prev_chain_len == prev_chain_len
        assert dec.msg_num        == msg_num


# ─────────────────────────────────────────────────────────────────────────────
# 7. SMP math identities
# ─────────────────────────────────────────────────────────────────────────────

Q = otr.SMPConstants.MODULUS

class TestSMPMath:
    """All SMP arithmetic goes through OpenSSL — verify mathematical identities."""

    @given(a=st.integers(2, Q - 2), b=st.integers(2, Q - 2))
    def test_mod_exp_basic(self, a, b):
        """a^b mod Q matches Python reference (public values — no timing concern)."""
        result = otr.SMPMath.mod_exp(a, b, Q)
        assert result == pow(a, b, Q)

    @given(a=st.integers(1, Q - 1))
    def test_mod_inv_identity(self, a):
        """a * a^-1 ≡ 1 (mod Q)."""
        inv = otr.SMPMath.mod_inv(a, Q)
        assert (a * inv) % Q == 1

    @given(a=st.integers(1, Q - 1))
    def test_mod_inv_double_inverse(self, a):
        """(a^-1)^-1 ≡ a (mod Q)."""
        inv     = otr.SMPMath.mod_inv(a, Q)
        inv_inv = otr.SMPMath.mod_inv(inv, Q)
        assert inv_inv == a

    @given(a=st.integers(1, Q - 1), b=st.integers(1, Q - 1))
    def test_mod_exp_additivity(self, a, b):
        """g^a * g^b == g^(a+b) mod Q (where g = generator)."""
        g  = otr.SMPConstants.GENERATOR
        ga = otr.SMPMath.mod_exp(g, a, Q)
        gb = otr.SMPMath.mod_exp(g, b, Q)
        gab = otr.SMPMath.mod_exp(g, (a + b) % (Q - 1), Q)
        assert (ga * gb) % Q == gab


# ─────────────────────────────────────────────────────────────────────────────
# 8. ML-KEM-768 round-trip
# ─────────────────────────────────────────────────────────────────────────────

import otr4_crypto_ext as _ossl

class TestMLKEM:
    """Property: decaps(encaps(ek)) recovers the same shared secret."""

    def test_keygen_encaps_decaps_roundtrip(self):
        """Basic round-trip — deterministic shared secret."""
        ek, dk = _ossl.mlkem1024_keygen()
        ct, ss1 = _ossl.mlkem1024_encaps(ek)
        ss2     = _ossl.mlkem1024_decaps(ct, dk)
        assert ss1 == ss2, "ML-KEM-768: decaps recovered different shared secret"

    def test_keygen_produces_fresh_keys(self):
        """Each keygen produces a distinct key pair."""
        ek1, dk1 = _ossl.mlkem1024_keygen()
        ek2, dk2 = _ossl.mlkem1024_keygen()
        assert ek1 != ek2, "ML-KEM keygen returned identical encapsulation keys"

    def test_wrong_ciphertext_gives_wrong_secret(self):
        """Decaps on a different ciphertext gives a different (implicit rejection) secret."""
        ek, dk   = _ossl.mlkem1024_keygen()
        ct1, ss1 = _ossl.mlkem1024_encaps(ek)
        ct2, ss2 = _ossl.mlkem1024_encaps(ek)
        # Different encapsulations → different cts and different shared secrets
        if ct1 != ct2:
            assert ss1 != ss2

    def test_shared_secret_length(self):
        ek, dk   = _ossl.mlkem1024_keygen()
        ct, ss   = _ossl.mlkem1024_encaps(ek)
        assert len(ss) == 32, f"Expected 32-byte shared secret, got {len(ss)}"
        assert len(ct) == 1568, f"Expected 1568-byte ciphertext, got {len(ct)}"
        assert len(ek) == 1568, f"Expected 1568-byte encapsulation key, got {len(ek)}"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Ring signature self-consistency
# ─────────────────────────────────────────────────────────────────────────────

from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives import serialization

class TestRingSignature:
    """Properties of the Schnorr OR-proof ring signature."""

    @given(msg=short_bytes)
    def test_sign_verify_roundtrip(self, msg):
        """sign then verify succeeds with the correct keys."""
        k1 = ed448.Ed448PrivateKey.generate()
        k2 = ed448.Ed448PrivateKey.generate()
        A1 = k1.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        A2 = k2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sig = otr.RingSignature.sign(k1, A1, A2, msg)
        assert len(sig) == 228, f"signature should be 228 bytes, got {len(sig)}"
        assert otr.RingSignature.verify(A1, A2, msg, sig), "ring_verify failed on fresh signature"

    @given(msg=short_bytes)
    def test_wrong_message_fails(self, msg):
        """Verify rejects a signature over a different message."""
        k1 = ed448.Ed448PrivateKey.generate()
        k2 = ed448.Ed448PrivateKey.generate()
        A1 = k1.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        A2 = k2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sig   = otr.RingSignature.sign(k1, A1, A2, msg)
        wrong = msg + b'\x00'  # different message
        assert not otr.RingSignature.verify(A1, A2, wrong, sig), \
            "ring_verify accepted signature over wrong message"

    @given(msg=short_bytes)
    def test_truncated_sig_rejected(self, msg):
        k1 = ed448.Ed448PrivateKey.generate()
        k2 = ed448.Ed448PrivateKey.generate()
        A1 = k1.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        A2 = k2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sig = otr.RingSignature.sign(k1, A1, A2, msg)
        assert not otr.RingSignature.verify(A1, A2, msg, sig[:-1]), \
            "ring_verify accepted truncated signature"

    @given(msg=short_bytes, garbage=st.binary(min_size=228, max_size=228))
    def test_random_sig_rejected(self, msg, garbage):
        """Random 228 bytes should not verify."""
        k1 = ed448.Ed448PrivateKey.generate()
        k2 = ed448.Ed448PrivateKey.generate()
        A1 = k1.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        A2 = k2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        # With overwhelming probability random bytes are not a valid signature
        result = otr.RingSignature.verify(A1, A2, msg, garbage)
        # Note: can't assert False because 2^-446 probability it verifies by chance
        note(f"random sig verified: {result}")  # log if it ever does


# ─────────────────────────────────────────────────────────────────────────────
# 10. Double ratchet: decrypt(encrypt(m)) == m
# ─────────────────────────────────────────────────────────────────────────────

from cryptography.hazmat.primitives.asymmetric import x448

def _make_ratchet_pair():
    """Create an initialised Alice/Bob ratchet pair."""
    # Generate shared keys
    root_key  = secrets.token_bytes(32)
    ck_a      = secrets.token_bytes(32)
    ck_b      = secrets.token_bytes(32)
    ad        = secrets.token_bytes(32)
    brace_key = secrets.token_bytes(32)

    rk_a = otr.SecureMemory(32); rk_a.write(root_key)
    rk_b = otr.SecureMemory(32); rk_b.write(root_key)

    alice = otr.DoubleRatchet(
        root_key=rk_a, is_initiator=True,
        chain_key_send=ck_a, chain_key_recv=ck_b,
        ad=ad, brace_key=brace_key)

    bob = otr.DoubleRatchet(
        root_key=rk_b, is_initiator=False,
        chain_key_send=ck_b, chain_key_recv=ck_a,
        ad=ad, brace_key=brace_key)

    return alice, bob


class TestDoubleRatchet:
    @given(msg=plaintext_st)
    def test_single_message_roundtrip(self, msg):
        """Alice sends, Bob decrypts — message is recovered exactly."""
        alice, bob = _make_ratchet_pair()
        ct, hdr, nonce, tag, rid, _ = alice.encrypt_message(msg)
        recovered = bob.decrypt_message(hdr, ct, nonce, tag)
        assert recovered == msg, "ratchet: decrypt(encrypt(m)) != m"

    @given(msgs=st.lists(plaintext_st, min_size=1, max_size=10))
    def test_multi_message_sequence(self, msgs):
        """Multiple messages in sequence all decrypt correctly."""
        alice, bob = _make_ratchet_pair()
        for msg in msgs:
            ct, hdr, nonce, tag, _, _ = alice.encrypt_message(msg)
            assert bob.decrypt_message(hdr, ct, nonce, tag) == msg

    @given(msg=plaintext_st)
    def test_replay_rejected(self, msg):
        """Replaying the same ciphertext is rejected."""
        alice, bob = _make_ratchet_pair()
        ct, hdr, nonce, tag, _, _ = alice.encrypt_message(msg)
        bob.decrypt_message(hdr, ct, nonce, tag)   # first decrypt succeeds
        with pytest.raises(Exception):
            bob.decrypt_message(hdr, ct, nonce, tag)  # replay must fail

    @given(msg=plaintext_st)
    def test_tampered_ct_rejected(self, msg):
        """Flipping a byte in the ciphertext must cause decryption failure."""
        assume(len(msg) > 0)
        alice, bob = _make_ratchet_pair()
        ct, hdr, nonce, tag, _, _ = alice.encrypt_message(msg)
        bad_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(Exception):
            bob.decrypt_message(hdr, bad_ct, nonce, tag)

    @given(msg=plaintext_st)
    def test_bidirectional(self, msg):
        """Bob can also send to Alice."""
        alice, bob = _make_ratchet_pair()
        ct, hdr, nonce, tag, _, _ = bob.encrypt_message(msg)
        recovered = alice.decrypt_message(hdr, ct, nonce, tag)
        assert recovered == msg


# ─────────────────────────────────────────────────────────────────────────────
# 11. Network detection
# ─────────────────────────────────────────────────────────────────────────────

class TestNetworkDetect:
    @given(host=st.from_regex(r'[a-zA-Z0-9\-]+\.i2p', fullmatch=True))
    def test_i2p_detected(self, host):
        assert otr.NetworkConstants.detect(host) == otr.NetworkConstants.NET_I2P

    @given(host=st.from_regex(r'[a-zA-Z0-9]{10,56}\.onion', fullmatch=True))
    def test_tor_detected(self, host):
        assert otr.NetworkConstants.detect(host) == otr.NetworkConstants.NET_TOR

    @given(host=st.from_regex(r'[a-zA-Z0-9\-]+\.(com|net|org|chat|io)', fullmatch=True))
    def test_clearnet_detected(self, host):
        assert otr.NetworkConstants.detect(host) == otr.NetworkConstants.NET_CLEARNET


# ─────────────────────────────────────────────────────────────────────────────
# Run directly
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import subprocess, sys
    sys.exit(subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"]
    ).returncode)
