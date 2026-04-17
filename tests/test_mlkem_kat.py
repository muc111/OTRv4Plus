#!/usr/bin/env python3
"""
ML-KEM-1024 Known-Answer Tests (FIPS 203, NIST Level 5)
Tests the ML-KEM-1024 C extension implementation.
No Python fallback — C extension is required.
"""

import os
import sys
import unittest
import otr4_crypto_ext as _ossl

# Hard check — no fallback
_REQUIRED = ('mlkem1024_keygen', 'mlkem1024_encaps', 'mlkem1024_decaps')
_missing = [s for s in _REQUIRED if not hasattr(_ossl, s)]
if _missing:
    raise ImportError(
        f"otr4_crypto_ext missing ML-KEM-1024 symbols: {_missing}\n"
        "Rebuild: python setup_otr4.py build_ext --inplace"
    )

# ML-KEM-1024 sizes (FIPS 203)
EK_BYTES  = 1568
CT_BYTES  = 1568
DK_BYTES  = 3168
SS_BYTES  = 32


class TestMLKEM1024KAT(unittest.TestCase):
    """ML-KEM-1024 tests against FIPS 203 spec properties."""

    def test_01_keygen_sizes(self):
        """Key generation produces correct sizes per FIPS 203."""
        ek, dk = _ossl.mlkem1024_keygen()
        self.assertEqual(len(ek), EK_BYTES,  f"ek must be {EK_BYTES} bytes")
        self.assertEqual(len(dk), DK_BYTES,  f"dk must be {DK_BYTES} bytes")

    def test_02_encaps_sizes(self):
        """Encapsulation produces correct sizes per FIPS 203."""
        ek, _ = _ossl.mlkem1024_keygen()
        ct, ss = _ossl.mlkem1024_encaps(ek)
        self.assertEqual(len(ct), CT_BYTES, f"ct must be {CT_BYTES} bytes")
        self.assertEqual(len(ss), SS_BYTES, f"ss must be {SS_BYTES} bytes")

    def test_03_roundtrip_single(self):
        """Single encaps/decaps roundtrip succeeds."""
        ek, dk = _ossl.mlkem1024_keygen()
        ct, ss1 = _ossl.mlkem1024_encaps(ek)
        ss2 = _ossl.mlkem1024_decaps(ct, dk)
        self.assertEqual(ss1, ss2, "Shared secrets must match")

    def test_04_roundtrip_100(self):
        """100 random roundtrips all succeed."""
        failures = []
        for i in range(100):
            ek, dk = _ossl.mlkem1024_keygen()
            ct, ss1 = _ossl.mlkem1024_encaps(ek)
            ss2 = _ossl.mlkem1024_decaps(ct, dk)
            if ss1 != ss2:
                failures.append(i)
        self.assertEqual(failures, [], f"Roundtrip failed at indices: {failures}")

    def test_05_keygen_produces_unique_keys(self):
        """Each keygen call produces a fresh random keypair."""
        ek1, dk1 = _ossl.mlkem1024_keygen()
        ek2, dk2 = _ossl.mlkem1024_keygen()
        self.assertNotEqual(ek1, ek2, "ek values must be unique")
        self.assertNotEqual(dk1, dk2, "dk values must be unique")

    def test_06_encaps_produces_unique_ciphertexts(self):
        """Two encapsulations to same key produce different ciphertexts."""
        ek, _ = _ossl.mlkem1024_keygen()
        ct1, ss1 = _ossl.mlkem1024_encaps(ek)
        ct2, ss2 = _ossl.mlkem1024_encaps(ek)
        self.assertNotEqual(ct1, ct2, "Ciphertexts must be unique")
        self.assertNotEqual(ss1, ss2, "Shared secrets must be unique per encaps")

    def test_07_shared_secret_not_zero(self):
        """Shared secret is never all-zero."""
        for _ in range(10):
            ek, dk = _ossl.mlkem1024_keygen()
            ct, ss = _ossl.mlkem1024_encaps(ek)
            self.assertNotEqual(ss, b'\x00' * SS_BYTES, "ss must not be all zeros")

    def test_08_implicit_rejection(self):
        """Modified ciphertext triggers implicit rejection (different ss)."""
        ek, dk = _ossl.mlkem1024_keygen()
        ct, ss_good = _ossl.mlkem1024_encaps(ek)
        ss_legit = _ossl.mlkem1024_decaps(ct, dk)
        self.assertEqual(ss_good, ss_legit, "Normal decaps must match")

        # Flip one byte
        ct_bad = bytearray(ct)
        ct_bad[42] ^= 0xFF
        ss_reject = _ossl.mlkem1024_decaps(bytes(ct_bad), dk)
        self.assertNotEqual(ss_reject, ss_good, "Modified ct must produce different ss")

    def test_09_implicit_rejection_deterministic(self):
        """Implicit rejection is deterministic for same invalid ciphertext."""
        ek, dk = _ossl.mlkem1024_keygen()
        ct, _ = _ossl.mlkem1024_encaps(ek)
        ct_bad = bytearray(ct); ct_bad[0] ^= 0x01
        ct_bad = bytes(ct_bad)
        ss1 = _ossl.mlkem1024_decaps(ct_bad, dk)
        ss2 = _ossl.mlkem1024_decaps(ct_bad, dk)
        self.assertEqual(ss1, ss2, "Implicit rejection must be deterministic")

    def test_10_wrong_dk_gives_wrong_ss(self):
        """Decapsulating with wrong dk gives different shared secret."""
        ek1, dk1 = _ossl.mlkem1024_keygen()
        ek2, dk2 = _ossl.mlkem1024_keygen()
        ct, ss1 = _ossl.mlkem1024_encaps(ek1)
        ss_wrong = _ossl.mlkem1024_decaps(ct, dk2)
        self.assertNotEqual(ss1, ss_wrong, "Wrong dk must not recover correct ss")

    def test_11_short_ek_rejected(self):
        """Encapsulation with truncated ek raises ValueError."""
        ek, _ = _ossl.mlkem1024_keygen()
        with self.assertRaises((ValueError, TypeError)):
            _ossl.mlkem1024_encaps(ek[:EK_BYTES - 1])

    def test_12_short_ct_rejected(self):
        """Decapsulation with truncated ct raises ValueError."""
        ek, dk = _ossl.mlkem1024_keygen()
        ct, _ = _ossl.mlkem1024_encaps(ek)
        with self.assertRaises((ValueError, TypeError)):
            _ossl.mlkem1024_decaps(ct[:CT_BYTES - 1], dk)

    def test_13_empty_ek_rejected(self):
        """Encapsulation with empty ek raises ValueError."""
        with self.assertRaises((ValueError, TypeError)):
            _ossl.mlkem1024_encaps(b'')

    def test_14_cross_key_encaps(self):
        """ct from ek1 decapsulates only with dk1, not dk2."""
        ek1, dk1 = _ossl.mlkem1024_keygen()
        ek2, dk2 = _ossl.mlkem1024_keygen()
        ct, ss1 = _ossl.mlkem1024_encaps(ek1)
        ss_ok   = _ossl.mlkem1024_decaps(ct, dk1)
        ss_fail = _ossl.mlkem1024_decaps(ct, dk2)
        self.assertEqual(ss1, ss_ok)
        self.assertNotEqual(ss1, ss_fail)

    def test_15_ss_uniformity_rough(self):
        """Shared secrets look uniform — no byte position always zero."""
        # Collect 50 shared secrets, check no byte column is always zero
        secrets_list = []
        for _ in range(50):
            ek, dk = _ossl.mlkem1024_keygen()
            ct, ss = _ossl.mlkem1024_encaps(ek)
            secrets_list.append(ss)
        for pos in range(SS_BYTES):
            col = bytes(s[pos] for s in secrets_list)
            self.assertNotEqual(col, b'\x00' * 50,
                f"Byte position {pos} always zero — suspicious")


if __name__ == "__main__":
    unittest.main(verbosity=2)
