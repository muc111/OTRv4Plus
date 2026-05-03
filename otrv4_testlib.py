"""
otrv4_testlib.py — import shim and compatibility layer for the test suite.

Strategy
--------
1. Load otrv4+.py (or otrv4_.py) as `otrv4_`.
2. Re-export every crypto class the tests need.
3. For classes that were removed in the Rust migration (SMPMath,
   SMPConstants, SMPProtocolCodec) provide pure-Python stubs so that
   the math-only unit tests still pass without touching the Rust core.

Usage in test files:
    from otrv4_testlib import *
    import otrv4_testlib as otr
"""

import os, sys, types, struct, hashlib, importlib.util

# ── Stub Termux-only imports ──────────────────────────────────────────────────
def _stub(name):
    if name in sys.modules:
        return sys.modules[name]
    mod = types.ModuleType(name)
    class _Any:
        def __call__(self, *a, **kw): return _Any()
        def __getattr__(self, k):    return _Any()
        def __enter__(self):         return self
        def __exit__(self, *a):      pass
        def __iter__(self):          return iter([])
        def __bool__(self):          return False
        def __int__(self):           return 0
        def __str__(self):           return ''
    _a = _Any()
    mod.__getattr__ = lambda k: _a
    mod.__file__ = os.devnull
    mod.__spec__ = None
    sys.modules[name] = mod
    return mod

for _m in ['socks', 'termios', 'tty', 'readline', 'pty',
           'resource', 'fcntl', 'grp', 'pwd']:
    _stub(_m)

_socks = sys.modules['socks']
_socks.PROXY_TYPE_SOCKS5 = 2
_socks.setdefaultproxy = lambda *a, **kw: None
import socket as _rsock
class _SS(_rsock.socket): pass
_socks.socksocket = _SS

# ── Load otrv4+.py ────────────────────────────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))

def _load_otrv4():
    if 'otrv4_' in sys.modules:
        return sys.modules['otrv4_']
    for cand in ['otrv4+.py', 'otrv4_.py', 'otrv4_combined.py']:
        p = os.path.join(HERE, cand)
        if os.path.exists(p):
            spec = importlib.util.spec_from_file_location('otrv4_', p)
            mod  = importlib.util.module_from_spec(spec)
            sys.modules['otrv4_'] = mod
            spec.loader.exec_module(mod)
            return mod
    raise ImportError("Cannot find otrv4+.py or otrv4_.py")

_mod = _load_otrv4()

# ── Re-export every class tests need ─────────────────────────────────────────
def _get(name, default=None):
    return getattr(_mod, name, default)

kdf_1             = _get('kdf_1')
KDFUsage          = _get('KDFUsage')
SHA3_512          = _get('SHA3_512')
OTRv4TLV          = _get('OTRv4TLV')
OTRv4Payload      = _get('OTRv4Payload')
OTRv4DataMessage  = _get('OTRv4DataMessage')
RatchetHeader     = _get('RatchetHeader')
RingSignature     = _get('RingSignature')
DoubleRatchet     = _get('DoubleRatchet')
SecureMemory      = _get('SecureMemory')
ClientProfile     = _get('ClientProfile')
OTRConstants      = _get('OTRConstants')
NetworkConstants  = _get('NetworkConstants')
MLKEM1024BraceKEM = _get('MLKEM1024BraceKEM')
MLDSA87Auth       = _get('MLDSA87Auth')
MLDSA87_AVAILABLE = _get('MLDSA87_AVAILABLE', False)
SMPEngine         = _get('SMPEngine')
EncryptionError   = _get('EncryptionError', Exception)
RustBackedDoubleRatchet = _get('RustBackedDoubleRatchet')
RUST_RATCHET_AVAILABLE  = _get('RUST_RATCHET_AVAILABLE', False)

# ── SMPMath / SMPConstants / SMPProtocolCodec ─────────────────────────────────
# These were pure-Python classes in ≤v10.5.8. After the Rust migration they no
# longer exist in the main module. Provide Python stubs so math-only tests
# (test_property.py, test_attacks.py) still pass without Rust.

# Try module first; fall back to stubs.
_SMPMath_mod      = _get('SMPMath')
_SMPConstants_mod = _get('SMPConstants')
_SMPCodec_mod     = _get('SMPProtocolCodec')

# ─────────────────────────────────────────────────────────────────────────────
# RFC 3526 Group 14, 2048-bit safe prime
# ─────────────────────────────────────────────────────────────────────────────
_SMP_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
_SMP_PRIME = int(_SMP_PRIME_HEX, 16)
_SMP_GEN   = 2
_SMP_ORDER = (_SMP_PRIME - 1) >> 1


class _SMPConstantsStub:
    MODULUS   = _SMP_PRIME
    GENERATOR = _SMP_GEN
    ORDER     = _SMP_ORDER


class _SMPMathStub:
    @staticmethod
    def mod_exp(base, exp, mod):
        return pow(base, exp, mod)

    @staticmethod
    def mod_inv(a, mod):
        # Extended Euclidean
        g, x, _ = _SMPMathStub._xgcd(a % mod, mod)
        if g != 1:
            raise ValueError("No modular inverse")
        return x % mod

    @staticmethod
    def _xgcd(a, b):
        old_r, r   = a, b
        old_s, s   = 1, 0
        while r:
            q = old_r // r
            old_r, r = r, old_r - q * r
            old_s, s = s, old_s - q * s
        return old_r, old_s, (old_r - old_s * a) // b


class _SMPProtocolCodecStub:
    """
    Minimal wire encoder/decoder matching the OTRv4 SMP TLV layout.

    All values are length-prefixed big-endian:
        SMP1: [g2a, c2, d2, g3a, c3, d3]  (6 elems)
        SMP2: [g2b, c2b, d2b, g3b, c3b, d3b, pb, qb, cp, d5, d6]  (11)
        SMP3: [pa, qa, ra, cr, d7]  (5)
        SMP4: [rb, cr2, d8]  (3)
    """
    @staticmethod
    def _encode_mpi(n: int) -> bytes:
        if n == 0:
            return b'\x00\x00\x00\x00'
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return struct.pack('!I', len(b)) + b

    @staticmethod
    def _decode_mpi(data: bytes, off: int):
        if off + 4 > len(data):
            raise ValueError("Truncated MPI length")
        ln = struct.unpack_from('!I', data, off)[0]
        off += 4
        if off + ln > len(data):
            raise ValueError("Truncated MPI body")
        val = int.from_bytes(data[off:off+ln], 'big') if ln else 0
        return val, off + ln

    @classmethod
    def _encode_elems(cls, *vals):
        return b''.join(cls._encode_mpi(v) for v in vals)

    @classmethod
    def _decode_n_elems(cls, data: bytes, n: int, *, has_question=False):
        off = 0
        if has_question:
            if off + 4 > len(data):
                raise ValueError("Truncated question length")
            qlen = struct.unpack_from('!I', data, off)[0]
            off += 4 + qlen
        elems = []
        for _ in range(n):
            v, off = cls._decode_mpi(data, off)
            elems.append(v)
        return elems

    @classmethod
    def encode_smp1(cls, g2a, c2, d2, g3a, c3, d3, question=None):
        body = cls._encode_elems(g2a, c2, d2, g3a, c3, d3)
        if question is not None:
            q = question.encode() if isinstance(question, str) else question
            body = struct.pack('!I', len(q)) + q + body
        return body

    @classmethod
    def decode_smp1(cls, data: bytes, has_question=False):
        return cls._decode_n_elems(data, 6, has_question=has_question)

    @classmethod
    def encode_smp2(cls, *args):   # 11 values
        return cls._encode_elems(*args)

    @classmethod
    def decode_smp2(cls, data: bytes):
        return cls._decode_n_elems(data, 11)

    @classmethod
    def encode_smp3(cls, *args):   # 5 values
        return cls._encode_elems(*args)

    @classmethod
    def decode_smp3(cls, data: bytes):
        return cls._decode_n_elems(data, 5)

    @classmethod
    def encode_smp4(cls, *args):   # 3 values
        return cls._encode_elems(*args)

    @classmethod
    def decode_smp4(cls, data: bytes):
        return cls._decode_n_elems(data, 3)

    @classmethod
    def encode_abort(cls) -> bytes:
        """Return an SMP ABORT TLV body (empty payload)."""
        return b''


# Use module classes if available, otherwise stubs
SMPConstants      = _SMPConstants_mod if _SMPConstants_mod is not None else _SMPConstantsStub
SMPMath           = _SMPMath_mod      if _SMPMath_mod      is not None else _SMPMathStub
SMPProtocolCodec  = _SMPCodec_mod     if _SMPCodec_mod     is not None else _SMPProtocolCodecStub

# ── SMPEngine (removed in v10.5.10, re-injected via compat wrapper) ──────────
if SMPEngine is None:
    try:
        import smp_engine_compat as _smp_compat
        SMPEngine = _smp_compat.SMPEngine
        # Also patch into the loaded module so `import otrv4_ as otr; otr.SMPEngine` works
        if not hasattr(_mod, 'SMPEngine'):
            _mod.SMPEngine = SMPEngine
    except ImportError:
        pass
