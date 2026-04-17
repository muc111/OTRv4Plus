"""Quick on-device test — run from ~/otr4/ to verify ring_sign works on this platform."""
import sys, os, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import otr4_crypto_ext as ext
    print(f"✓ otr4_crypto_ext loaded: {ext.__file__}")
except ImportError as e:
    print(f"✗ import failed: {e}"); sys.exit(1)

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

print("\n── ring_sign / ring_verify ─────────────────")
fails = 0
for i in range(10):
    try:
        p1 = Ed448PrivateKey.generate(); p2 = Ed448PrivateKey.generate()
        A1 = p1.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        A2 = p2.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        seed = p1.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        msg = os.urandom(64)

        sig = ext.ring_sign(bytes(seed), A1, A2, msg)
        ok      = ext.ring_verify(A1, A2, msg, sig)
        rej_msg = ext.ring_verify(A1, A2, b"wrong", sig)
        rej_key = ext.ring_verify(A2, A1, msg, sig)

        if ok and not rej_msg and not rej_key:
            print(f"  [{i}] ✓")
        else:
            print(f"  [{i}] ✗  ok={ok} rej_msg={rej_msg} rej_key={rej_key}")
            fails += 1
    except Exception:
        print(f"  [{i}] ✗  EXCEPTION:"); traceback.print_exc(); fails += 1

print(f"\nring_sign: {'PASS' if fails==0 else f'FAIL ({fails}/10)'}")

print("\n── simulate generate_dake3 inputs ─────────")
# Reproduce exactly what generate_dake3 passes to ring_sign:
# transcript_msg = SHAKE256("OTRv4" || 0x05 || dake1_bytes || dake2_bytes, 64)
import hashlib
dake1_bytes = os.urandom(1479)   # typical DAKE1 length
dake2_bytes = os.urandom(1447)   # typical DAKE2 length
shake = hashlib.shake_256()
shake.update(b"OTRv4"); shake.update(bytes([0x05]))
shake.update(dake1_bytes + dake2_bytes)
transcript_msg = shake.digest(64)

p1 = Ed448PrivateKey.generate(); p2 = Ed448PrivateKey.generate()
A1 = p1.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
A2 = p2.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
seed = p1.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

try:
    sig = ext.ring_sign(bytes(seed), A1, A2, transcript_msg)
    ok = ext.ring_verify(A1, A2, transcript_msg, sig)
    print(f"  DAKE-style ring_sign: {'✓ PASS' if ok else '✗ FAIL'}")
except Exception:
    print("  ✗ EXCEPTION:"); traceback.print_exc()

print("\n── ML-KEM-768 ──────────────────────────────")
try:
    ek, dk = ext.mlkem768_keygen()
    ct, K1 = ext.mlkem768_encaps(ek)
    K2     = ext.mlkem768_decaps(ct, dk)
    print(f"  round-trip: {'✓ PASS' if K1==K2 else '✗ FAIL'}")
except Exception:
    print("  ✗ EXCEPTION:"); traceback.print_exc()
