#!/usr/bin/env python3
"""Quick smoke test for otr4_mldsa_ext — run after compiling."""
import sys, time

try:
    import otr4_mldsa_ext as mldsa
except ImportError as e:
    print(f"❌ Import failed: {e}")
    print("   Build with: gcc -shared -fPIC -O2 -o otr4_mldsa_ext.so "
          "otr4_mldsa_ext.c $(python3-config --includes) -lcrypto")
    sys.exit(1)

print(f"✓ Module loaded")
print(f"  PUB_BYTES:  {mldsa.PUB_BYTES}")
print(f"  PRIV_BYTES: {mldsa.PRIV_BYTES}")
print(f"  SIG_BYTES:  {mldsa.SIG_BYTES}")

# Keygen
t0 = time.time()
pub, priv = mldsa.mldsa87_keygen()
t_keygen = time.time() - t0
print(f"✓ Keygen: pub={len(pub)} priv={len(priv)} ({t_keygen*1000:.0f}ms)")

assert len(pub) == mldsa.PUB_BYTES, f"pub size mismatch: {len(pub)}"
assert len(priv) == mldsa.PRIV_BYTES, f"priv size mismatch: {len(priv)}"

# Sign
msg = b"OTRv4+ hybrid DAKE3 transcript test"
t0 = time.time()
sig = mldsa.mldsa87_sign(bytes(priv), msg)
t_sign = time.time() - t0
print(f"✓ Sign: sig={len(sig)} bytes ({t_sign*1000:.0f}ms)")

assert len(sig) == mldsa.SIG_BYTES, f"sig size mismatch: {len(sig)}"

# Verify (valid)
t0 = time.time()
ok = mldsa.mldsa87_verify(pub, msg, sig)
t_verify = time.time() - t0
assert ok is True, "Valid signature should verify"
print(f"✓ Verify (valid): True ({t_verify*1000:.0f}ms)")

# Verify (wrong message)
ok2 = mldsa.mldsa87_verify(pub, b"tampered", sig)
assert ok2 is False, "Tampered message should fail"
print(f"✓ Verify (tampered msg): False")

# Verify (wrong key)
pub2, _ = mldsa.mldsa87_keygen()
ok3 = mldsa.mldsa87_verify(pub2, msg, sig)
assert ok3 is False, "Wrong key should fail"
print(f"✓ Verify (wrong key): False")

# Verify (corrupted sig)
sig_bad = bytearray(sig)
sig_bad[100] ^= 0xFF
ok4 = mldsa.mldsa87_verify(pub, msg, bytes(sig_bad))
assert ok4 is False, "Corrupted sig should fail"
print(f"✓ Verify (corrupted sig): False")

print(f"\n✅ ML-DSA-87 smoke test PASSED — OpenSSL supports FIPS 204")
