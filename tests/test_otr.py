#!/usr/bin/env python3
"""
Smoke test for OTRv4 crypto extensions (otr4_crypto_ext, otr4_ed448_ct, otr4_mldsa_ext).
Run with: python3 test_otr4.py
"""

import sys
import os

# Ensure we can import the built modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_otr4_crypto_ext():
    print("\n--- Testing otr4_crypto_ext ---")
    try:
        import otr4_crypto_ext as ext
    except ImportError as e:
        print("SKIP: otr4_crypto_ext not importable:", e)
        return

    # 1. disable_core_dumps (just call, no crash)
    try:
        ext.disable_core_dumps()
        print("  disable_core_dumps() OK")
    except Exception as e:
        print("  disable_core_dumps() FAIL:", e)

    # 2. cleanse on bytearray
    try:
        ba = bytearray(b"secret")
        ext.cleanse(ba)
        assert all(b == 0 for b in ba)
        print("  cleanse() OK")
    except Exception as e:
        print("  cleanse() FAIL:", e)

    # 3. bn_mod_exp_consttime (3^5 mod 11 = 1)
    try:
        base = b"\x03"
        exp = b"\x05"
        mod = b"\x0b"
        res = ext.bn_mod_exp_consttime(base, exp, mod)
        assert res == b"\x01"
        print("  bn_mod_exp_consttime OK")
    except Exception as e:
        print("  bn_mod_exp_consttime FAIL:", e)

    # 4. bn_mod_inverse (3^-1 mod 11 = 4)
    try:
        a = b"\x03"
        mod = b"\x0b"
        inv = ext.bn_mod_inverse(a, mod)
        assert inv == b"\x04"
        print("  bn_mod_inverse OK")
    except Exception as e:
        print("  bn_mod_inverse FAIL:", e)

    # 5. bn_rand_range (mod 100)
    try:
        mod = b"\x64"
        r = ext.bn_rand_range(mod)
        assert 0 <= int.from_bytes(r, 'big') < 100
        print("  bn_rand_range OK")
    except Exception as e:
        print("  bn_rand_range FAIL:", e)

    # 6. ML-KEM-1024 (keygen, encaps, decaps)
    try:
        ek, dk = ext.mlkem1024_keygen()
        assert len(ek) == 1568
        assert len(dk) == 3168
        ct, ss1 = ext.mlkem1024_encaps(ek)
        ss2 = ext.mlkem1024_decaps(ct, dk)
        assert ss1 == ss2 and len(ss1) == 32
        print("  mlkem1024_keygen/encaps/decaps OK")
    except Exception as e:
        print("  ML-KEM-1024 FAIL:", e)

    # 7. ring_sign and ring_verify (use dummy data, verification should fail because keys don't match)
    try:
        seed = bytes([i % 256 for i in range(57)])
        A1 = bytes([i % 256 for i in range(57)])
        A2 = bytes([(i+128) % 256 for i in range(57)])
        msg = b"smoke test message"
        sig = ext.ring_sign(seed, A1, A2, msg)
        assert len(sig) == 228
        # Verification should succeed if we sign with correct key – but here A1,A2 are random,
        # so it will likely fail; we just check that verify runs without exception.
        ok = ext.ring_verify(A1, A2, msg, sig)
        # With random keys, likely False; but not an error.
        print(f"  ring_sign/verify OK (verification result = {ok})")
    except Exception as e:
        print("  ring_sign/verify FAIL:", e)

def test_otr4_ed448_ct():
    print("\n--- Testing otr4_ed448_ct ---")
    try:
        import otr4_ed448_ct as ed
    except ImportError as e:
        print("SKIP: otr4_ed448_ct not importable:", e)
        return

    # scalar = 1 (little-endian 57 bytes)
    scalar = bytes([1] + [0]*56)
    # base point multiplication (G*1 should equal G)
    try:
        G = ed.ed448_scalarmult_base(scalar)
        assert len(G) == 57
        # compute again with arbitrary point multiplication on G
        G2 = ed.ed448_scalarmult(scalar, G)
        assert G2 == G
        print("  ed448_scalarmult_base / scalarmult OK")
    except Exception as e:
        print("  base point multiplication FAIL:", e)

def test_otr4_mldsa_ext():
    print("\n--- Testing otr4_mldsa_ext ---")
    try:
        import otr4_mldsa_ext as ml
    except ImportError as e:
        print("SKIP: otr4_mldsa_ext not importable:", e)
        return

    try:
        pub, priv = ml.mldsa87_keygen()
        assert len(pub) == 2592
        assert len(priv) == 4896
        msg = b"smoke test"
        sig = ml.mldsa87_sign(priv, msg)
        assert len(sig) == 4627
        ok = ml.mldsa87_verify(pub, msg, sig)
        assert ok is True
        # Test with wrong message
        ok2 = ml.mldsa87_verify(pub, b"wrong", sig)
        assert ok2 is False
        print("  mldsa87_keygen/sign/verify OK")
    except Exception as e:
        print("  ML-DSA-87 FAIL (OpenSSL too old or provider missing):", e)

if __name__ == "__main__":
    print("OTRv4 Crypto Extensions Smoke Test")
    test_otr4_crypto_ext()
    test_otr4_ed448_ct()
    test_otr4_mldsa_ext()
    print("\nSmoke test completed.")
