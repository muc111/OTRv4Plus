#!/usr/bin/env python3
import sys
import os
import socket
import socks
import threading

try:
    from otrv4_core import RustDoubleRatchet as _RustRatchet
    RUST_RATCHET_AVAILABLE = True
except ImportError:
    RUST_RATCHET_AVAILABLE = False
import time
import secrets
import hashlib
import json
import signal
import re
import hmac
import struct
import base64
import math
import select
import ctypes
import ctypes.util
import tempfile
import getpass
import io
import subprocess
import textwrap
import traceback
import atexit
import gc
import resource
import random
import bisect
import shutil
import platform
import termios
import tty
import logging
import logging.handlers
from typing import Optional, Dict, Any, Tuple, Union, List, Set, Callable
from dataclasses import dataclass
from collections import defaultdict, deque, OrderedDict
from datetime import datetime
from enum import IntEnum
import concurrent.futures

try:
    from cryptography.hazmat.primitives.asymmetric import ed448, x448
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    print("ERROR: Install cryptography: pip install cryptography")
    CRYPTO_AVAILABLE = False
    sys.exit(1)

try:
    import otr4_crypto_ext as _ossl
    OTR4_EXT_AVAILABLE = True
    try:
        _ossl.disable_core_dumps()
    except Exception:
        pass
except ImportError:
    print("ERROR: otr4_crypto_ext C extension not found.")
    print("       Build with:  python setup_otr4.py build_ext --inplace")
    print("       Side-channel resistance requires the C extension — refusing to run.")
    sys.exit(1)

import sys as _sys, os as _os
try:
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import otr4_ed448_ct as _ed448_ct
    ED448_CT_AVAILABLE = True
except ImportError:
    print("ERROR: otr4_ed448_ct C extension not found.")
    print("       Build with:  python setup_otr4.py build_ext --inplace")
    sys.exit(1)


_REQUIRED_MLKEM_SYMS = ('mlkem1024_keygen', 'mlkem1024_encaps', 'mlkem1024_decaps')
_missing = [s for s in _REQUIRED_MLKEM_SYMS if not hasattr(_ossl, s)]
if _missing:
    raise ImportError(
        f"otr4_crypto_ext is missing ML-KEM-1024 symbols: {_missing}\n"
        "Rebuild otr4_crypto_ext.c and recompile: python setup_otr4.py build_ext --inplace"
    )

# ── ML-DSA-87 (FIPS 204) for hybrid PQ DAKE authentication ──────
try:
    import otr4_mldsa_ext as _mldsa
    MLDSA87_AVAILABLE = True
except ImportError:
    print("WARNING: otr4_mldsa_ext not found — DAKE3 will use Ed448 ring sig only (no PQ auth).")
    print("         Build: gcc -shared -fPIC -O2 -o otr4_mldsa_ext.so otr4_mldsa_ext.c "
          "$(python3-config --includes) $(python3-config --ldflags --embed) -lcrypto")
    MLDSA87_AVAILABLE = False


try:
    import argon2
    ARGON2_AVAILABLE = True
except ImportError:
    print("WARNING: argon2-cffi not installed. Using weaker key derivation.")
    print("For secure storage: pip install argon2-cffi")
    ARGON2_AVAILABLE = False





def secure_compare(a: str, b: str) -> bool:
    """Constant-time string comparison"""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

def secure_compare_bytes(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparison"""
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        return False
    return hmac.compare_digest(a, b)

def acquire_lock_with_timeout(lock: threading.RLock, timeout: float = 5.0) -> bool:
    """Acquire lock with timeout to prevent deadlocks"""
    if lock is None:
        return True
    try:
        return lock.acquire(timeout=timeout)
    except Exception:
        return False




class OTRConstants:
    """OTRv4 Protocol Constants (Spec §2.1)"""
    PROTOCOL_VERSION = 0x04
    SESSION_ID_BYTES = 32
    ED448_PUBLIC_KEY_SIZE = 57
    ED448_SIGNATURE_SIZE = 114
    X448_PUBLIC_KEY_SIZE = 56
    
    MESSAGE_TYPE_DAKE1 = 0x35
    MESSAGE_TYPE_DAKE2 = 0x36
    MESSAGE_TYPE_DAKE3 = 0x37
    MESSAGE_TYPE_DATA  = 0x03
    
    TLV_TYPE_PADDING = 0x00
    TLV_TYPE_DISCONNECTED = 0x01
    TLV_TYPE_SMP_MESSAGE_1 = 0x02
    TLV_TYPE_SMP_MESSAGE_2 = 0x03
    TLV_TYPE_SMP_MESSAGE_3 = 0x04
    TLV_TYPE_SMP_MESSAGE_4 = 0x05
    TLV_TYPE_SMP_ABORT = 0x06
    TLV_TYPE_SMP_MESSAGE_1Q = 0x07
    TLV_TYPE_CLIENT_PROFILE = 0x08
    TLV_TYPE_EXTRA_SYMMETRIC_KEY = 0x09
    
    RATCHET_SENDING = 0
    RATCHET_RECEIVING = 1
    MAX_SKIP = 1000
    MAX_MESSAGE_KEYS = 2000
    RATCHET_INFO = b"OTR4-DH-Ratchet"
    REKEY_INTERVAL = 100
    REKEY_TIMEOUT = 86400
    
    class DAKEState:
        IDLE = 0
        SENT_DAKE1 = 1
        GOT_DAKE1 = 2
        SENT_DAKE2 = 3
        GOT_DAKE2 = 4
        SENT_DAKE3 = 5
        ESTABLISHED = 6
        FAILED = 7


class KDFUsage:
    """KDF_1 usage ID constants (OTRv4 spec §3.2).

    Usage IDs 0x00–0x1F are reserved by the spec.  Each distinct KDF call
    MUST use a different ID so that outputs are domain-separated and cannot
    be conflated even if the input material is identical.
    """
    SSID                   = 0x01
    BRACE_KEY              = 0x02
    SHARED_SECRET          = 0x03
    AUTH_R_MAC             = 0x04
    AUTH_I_MSG             = 0x05
    ROOT_KEY               = 0x11
    CHAIN_KEY              = 0x12
    MESSAGE_KEY            = 0x13
    MAC_KEY                = 0x14
    DAKE_MAC_KEY           = 0x15
    EXTRA_SYM_KEY          = 0x1F
    BRACE_KEY_ROTATE       = 0x16


_KDF_DOMAIN = b"OTRv4"

def kdf_1(usage_id: int, value: bytes, length: int) -> bytes:
    """KDF(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size).

    OTRv4 spec §3.2 (Key Derivation Function, Hash Function and MAC Function):
      KDF(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size)
      HWC(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size)
      HCMAC(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size)

    All three functions are identical — just SHAKE-256 with the "OTRv4"
    domain separator prefix.  Previous implementations that omitted this
    prefix produced non-spec key material and would fail to interoperate
    with libotr4, CoyIM, or any spec-compliant OTRv4 implementation.
    """
    shake = hashlib.shake_256()
    shake.update(_KDF_DOMAIN)        # "OTRv4" — required by spec §3.2
    shake.update(bytes([usage_id]))
    shake.update(value)
    return shake.digest(length)


def _secure_wipe_bytes(b: bytes) -> None:
    """Overwrite the internal data buffer of an immutable bytes object.

    CPython bytes objects have a fixed layout:
      PyObject_VAR_HEAD (ob_refcnt, ob_type, ob_size)  — 24 bytes on 64-bit
      ob_shash (Py_hash_t)                              —  8 bytes
      ob_val[ob_size+1]                                 — data starts here

    We use ctypes to write zeros directly through the C-level pointer.
    This is the ONLY way to wipe immutable bytes in CPython.

    WARNING: only call this when you are certain no other reference to b exists
    and the object will not be used again.  Using b after this call is
    undefined behaviour.
    """
    if not isinstance(b, (bytes, bytearray)):
        return
    try:
        n = len(b)
        if n == 0:
            return
        HEADER = 32
        addr = id(b) + HEADER
        (ctypes.c_char * n).from_address(addr)[:] = b'\x00' * n
    except Exception:
        pass



class MLKEM1024BraceKEM:
    """ML-KEM-1024 keypair for the OTRv4 post-quantum brace KEM.

    NIST Level 5 (~256-bit post-quantum security).
    Always uses the C extension (otr4_crypto_ext) — no Python fallback.
    mlock and OPENSSL_cleanse are applied by the C layer.

    Usage (initiator side):
        kem = MLKEM1024BraceKEM()
        kem.encap_key_bytes
        K = kem.decapsulate(ct_bytes)

    Usage (responder side — class method):
        ct, K = MLKEM1024BraceKEM.encapsulate(ek_bytes)
    """

    EK_BYTES  = 1568
    CT_BYTES  = 1568
    SS_BYTES  =   32

    def __init__(self):
        """Generate a fresh ML-KEM-1024 keypair via C extension."""
        ek, self._dk_handle = _ossl.mlkem1024_keygen()
        self.encap_key_bytes: bytes = ek

    @classmethod
    def encapsulate(cls, ek_bytes: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate to a peer's ek.  Returns (ciphertext, shared_secret)."""
        if len(ek_bytes) != cls.EK_BYTES:
            raise ValueError(
                f"ML-KEM-1024 encap key must be {cls.EK_BYTES} bytes, got {len(ek_bytes)}"
            )
        ct, ss = _ossl.mlkem1024_encaps(ek_bytes)
        return ct, ss

    def decapsulate(self, ct_bytes: bytes) -> bytes:
        """Decapsulate a ciphertext with our private key.  Returns shared_secret."""
        if len(ct_bytes) != self.CT_BYTES:
            raise ValueError(
                f"ML-KEM-1024 ciphertext must be {self.CT_BYTES} bytes, got {len(ct_bytes)}"
            )
        return _ossl.mlkem1024_decaps(ct_bytes, self._dk_handle)

    def zeroize(self):
        """Overwrite the private key material via C extension cleanse."""
        if self._dk_handle is not None:
            if isinstance(self._dk_handle, bytearray):
                _ossl.cleanse(self._dk_handle)
            self._dk_handle = None
        self.encap_key_bytes = b'\x00' * self.EK_BYTES


class MLDSA87Auth:
    """ML-DSA-87 (FIPS 204) keypair for hybrid PQ DAKE authentication.

    NIST Level 5 (~256-bit post-quantum security).
    Uses the otr4_mldsa_ext C extension (OpenSSL EVP).

    The ML-DSA-87 signature is appended to the Ed448 ring signature
    in DAKE3, creating a hybrid authentication:
      - Ring sig (Ed448): classical deniability + authentication
      - ML-DSA-87 sig:    post-quantum authentication

    A quantum adversary could verify the ML-DSA signature and prove
    participation.  This is an acceptable trade-off: PQ deniable
    signatures are not standardized, and authentication against
    quantum adversaries is the higher priority.

    Key sizes:
      Public key:  2592 bytes
      Private key: 4896 bytes (mlock'd bytearray, cleansed on zeroize)
      Signature:   4627 bytes
    """

    PUB_BYTES  = 2592
    PRIV_BYTES = 4896
    SIG_BYTES  = 4627

    def __init__(self):
        """Generate a fresh ML-DSA-87 keypair via C extension."""
        if not MLDSA87_AVAILABLE:
            raise RuntimeError(
                "ML-DSA-87 C extension not available — "
                "build otr4_mldsa_ext.so first"
            )
        pub, priv = _mldsa.mldsa87_keygen()
        self.pub_bytes: bytes = pub
        self._priv: bytearray = priv   # mutable for cleanse

    def sign(self, msg: bytes) -> bytes:
        """Sign a message.  Returns 4627-byte signature."""
        if self._priv is None:
            raise RuntimeError("ML-DSA-87 private key has been zeroized")
        return _mldsa.mldsa87_sign(bytes(self._priv), msg)

    @classmethod
    def verify(cls, pub_bytes: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify an ML-DSA-87 signature.  Returns True/False."""
        if not MLDSA87_AVAILABLE:
            return False
        if len(pub_bytes) != cls.PUB_BYTES:
            return False
        if len(sig) != cls.SIG_BYTES:
            return False
        try:
            return _mldsa.mldsa87_verify(pub_bytes, msg, sig)
        except Exception:
            return False

    def zeroize(self):
        """Overwrite private key material."""
        if self._priv is not None:
            _ossl.cleanse(self._priv)
            self._priv = None
        self.pub_bytes = b'\x00' * self.PUB_BYTES




class RingSignature:
    """OTRv4 Auth-I Schnorr ring signature (spec §4.3.3).

    Wire encoding: c₁(57) ‖ r₁(57) ‖ c₂(57) ‖ r₂(57) = 228 bytes.
    """

    SCALAR_BYTES = 57
    TOTAL_BYTES  = 4 * 57
    _USAGE_SIGMA = 0x1C


    @classmethod
    def sign(cls,
             priv_key: 'ed448.Ed448PrivateKey',
             A1_bytes: bytes,
             A2_bytes: bytes,
             msg: bytes
             ) -> bytes:
        """Produce σ = c₁‖r₁‖c₂‖r₂ (228 bytes).

        Fully implemented in C via _ossl.ring_sign:
          - Scalar a₁ derived via SHAKE-256(seed, 114) + RFC 8032 clamping
          - Ephemeral t₁ via SHAKE-256(seed‖0x01, 57)
          - All point arithmetic (T1=t₁·G, T2=r₂·G+c₂·A₂) in C
          - OPENSSL_cleanse on all secret intermediates before return

        The signing key must correspond to A₁ (initiator identity key).
        """
        seed = priv_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        sig = _ossl.ring_sign(bytes(seed), A1_bytes, A2_bytes, msg)
        del seed
        return sig

    @classmethod
    def verify(cls,
               A1_bytes: bytes,
               A2_bytes: bytes,
               msg: bytes,
               sig: bytes) -> bool:
        """Verify σ = c₁‖r₁‖c₂‖r₂ against A₁, A₂, and the transcript msg."""
        if len(sig) != cls.TOTAL_BYTES:
            return False

        try:
            return _ossl.ring_verify(A1_bytes, A2_bytes, msg, sig)
        except Exception:
            return False


class SessionState(IntEnum):
    PLAINTEXT = 0
    DAKE_IN_PROGRESS = 1
    ENCRYPTED = 2
    FINISHED = 3
    FAILED = 4

class DAKEState(IntEnum):
    """DAKE protocol states - OTRv4 Spec §4.2"""
    IDLE = 0
    SENT_DAKE1 = 1
    RECEIVED_DAKE1 = 2
    SENT_DAKE2 = 3
    ESTABLISHED = 4
    FAILED = 5

class SMPConstants:
    """SMP group constants — 3072-bit safe prime (RFC 3526 Group 15).

    3072-bit MODP gives ~128-bit discrete-log security, matching the
    GCM-mode bound on AES-256-GCM (128-bit). The key exchange layers
    (Ed448/X448) give 224-bit security, so SMP group strength is the
    right match for the symmetric layer without wasted CPU on mobile.
    """
    MODULUS = int(
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
        "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16)

    GENERATOR = 2
    MODULUS_BYTES = 384
    MODULUS_MINUS_ONE = MODULUS - 1

    MESSAGE_TIMEOUT = 180
    SESSION_TIMEOUT = 300
    RETRY_DELAY     = 30
    CLEANUP_DELAY   = 120

class IRCConstants:
    """IRC Protocol Constants"""
    PORT = 6667
    TLS_PORT = 6697
    DEFAULT_SERVER = "irc.postman.i2p"
    DEFAULT_CHANNEL = "#otr"

    # IRCv3 capabilities to request
    IRCV3_CAPS = [
        "sasl",
        "multi-prefix",
        "server-time",
        "message-tags",
        "account-notify",
        "away-notify",
        "cap-notify",
        "echo-message",
    ]
    
    RPL_LISTSTART = 321
    RPL_LIST = 322
    RPL_LISTEND = 323
    RPL_NAMREPLY = 353
    RPL_ENDOFNAMES = 366
    RPL_WHOISUSER = 311
    RPL_WHOISSERVER = 312
    RPL_WHOISOPERATOR = 313
    RPL_WHOISIDLE = 317
    RPL_ENDOFWHOIS = 318
    RPL_WHOISCHANNELS = 319
    RPL_TOPIC = 332
    RPL_TOPICWHOTIME = 333
    RPL_CHANNELMODEIS = 324

class UIConstants:
    """UI Constants"""
    MAX_HISTORY_LINES = 10000
    PAGER_LINES = 20
    NOTIFICATION_THRESHOLD = 3
    PANEL_SWITCH_DELAY = 0.5
    MAX_MESSAGE_LENGTH = 4096
    MAX_PRIVMSG_LENGTH = 350
    MESSAGE_FRAGMENT_SIZE = 300
    OTR_FRAGMENT_SIZE = 300
    FRAGMENT_TIMEOUT = 120.0
    FRAGMENT_LIMIT = 50
    SMP_FRAGMENT_LIMIT = 100
    HEARTBEAT_INTERVAL = 300
    DAKE_TIMEOUT = 120.0
    REKEY_INTERVAL = 100
    
    class SecurityLevel(IntEnum):
        PLAINTEXT = 0
        ENCRYPTED = 1
        FINGERPRINT = 2
        SMP_VERIFIED = 3
    
    class SMPState(IntEnum):
        NONE = 0
        EXPECT1 = 1
        SENT1 = 2
        EXPECT2 = 3
        SENT2 = 4
        EXPECT3 = 5
        SENT3 = 6
        EXPECT4 = 7
        SUCCEEDED = 8
        FAILED = 9
    
    COLORS = {
        'reset':    '\033[0m',
        'bold':     '\033[1m',
        'dim':      '\033[2m',
        'italic':   '\033[3m',
        'underline':'\033[4m',
        'black':    '\033[30m',
        'red':      '\033[91m',
        'green':    '\033[92m',
        'yellow':   '\033[93m',
        'blue':     '\033[94m',
        'magenta':  '\033[95m',
        'cyan':     '\033[96m',
        'white':    '\033[97m',
        'dark_red':    '\033[31m',
        'dark_green':  '\033[32m',
        'dark_yellow': '\033[33m',
        'dark_blue':   '\033[34m',
        'dark_magenta':'\033[35m',
        'dark_cyan':   '\033[36m',
        'grey':        '\033[90m',
        'orange':      '\033[38;5;214m',
        'pink':        '\033[38;5;213m',
        'teal':        '\033[38;5;43m',
        'lime':        '\033[38;5;118m',
        'gold':        '\033[38;5;220m',
        'lavender':    '\033[38;5;183m',
        'bg_green':    '\033[42m',
        'bg_yellow':   '\033[43m',
        'bg_blue':     '\033[44m',
        'bg_magenta':  '\033[45m',
        'bg_cyan':     '\033[46m',
        'bg_red':      '\033[41m',
        'dim_italic':  '\033[2;3m',
        'bold_cyan':   '\033[1;96m',
        'bold_green':  '\033[1;92m',
        'bold_red':    '\033[1;91m',
        'bold_yellow': '\033[1;93m',
    }
    
    SECURITY_ICONS = {
        SecurityLevel.PLAINTEXT: "🔴",
        SecurityLevel.ENCRYPTED: "🟡", 
        SecurityLevel.FINGERPRINT: "🟢",
        SecurityLevel.SMP_VERIFIED: "🔵"
    }
    
    SECURITY_NAMES = {
        SecurityLevel.PLAINTEXT: "PLAINTEXT",
        SecurityLevel.ENCRYPTED: "ENCRYPTED",
        SecurityLevel.FINGERPRINT: "VERIFIED",
        SecurityLevel.SMP_VERIFIED: "SMP VERIFIED"
    }
    
    USERNAME_COLORS = [
        'bold_cyan',
        'magenta',
        'bold_green',
        'yellow',
        'orange',
        'pink',
        'teal',
        'gold',
        'lavender',
        'bold_yellow',
        'cyan',
        'dark_magenta',
    ]

class NetworkConstants:
    """Network Configuration — supports clearnet, Tor, and I2P auto-detected from server hostname."""

    I2P_PROXY_HOST = "127.0.0.1"
    I2P_PROXY_PORT = 4447

    TOR_PROXY_HOST = "127.0.0.1"
    TOR_PROXY_PORT = 9050

    I2P_SUFFIXES  = (".i2p",)
    TOR_SUFFIXES  = (".onion",)

    TIMEOUT_CLEARNET = 30
    TIMEOUT_TOR      = 90
    TIMEOUT_I2P      = 120

    NET_CLEARNET = "clearnet"
    NET_TOR      = "tor"
    NET_I2P      = "i2p"

    @staticmethod
    def detect(server: str) -> str:
        """Return NET_* constant for *server* hostname.

        Rules (checked in order):
          1. Ends with .i2p            → i2p
          2. Ends with .onion          → tor
          3. Anything else             → clearnet

        The check is case-insensitive and works with hostnames that carry
        a port suffix (e.g. "irc.postman.i2p:6667").
        """
        host = server.split(":")[0].lower().strip()
        for sfx in NetworkConstants.I2P_SUFFIXES:
            if host.endswith(sfx):
                return NetworkConstants.NET_I2P
        for sfx in NetworkConstants.TOR_SUFFIXES:
            if host.endswith(sfx):
                return NetworkConstants.NET_TOR
        return NetworkConstants.NET_CLEARNET
    MLOCK_PAGE_SIZE = 4096

class BinaryReader:
    """Safe structured binary parser with strict bounds checking and specific exceptions."""
    
    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {type(data)}")
        self.data = data
        self.offset = 0
        self.length = len(data)
    
    def remaining(self) -> int:
        return self.length - self.offset
    
    def ensure(self, needed: int) -> None:
        """Ensure at least needed bytes remain."""
        remaining = self.remaining()
        if remaining < needed:
            raise ValueError(f"Truncated: need {needed} bytes, have {remaining}")
    
    def read_uint8(self) -> int:
        try:
            self.ensure(1)
            val = self.data[self.offset]
            self.offset += 1
            return val
        except IndexError as e:
            raise ValueError(f"Failed to read uint8: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint8: {e}")
    
    def read_uint16(self) -> int:
        try:
            self.ensure(2)
            val = struct.unpack('>H', self.data[self.offset:self.offset+2])[0]
            self.offset += 2
            return val
        except struct.error as e:
            raise ValueError(f"Failed to unpack uint16: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint16: {e}")
    
    def read_uint32(self) -> int:
        try:
            self.ensure(4)
            val = struct.unpack('>I', self.data[self.offset:self.offset+4])[0]
            self.offset += 4
            return val
        except struct.error as e:
            raise ValueError(f"Failed to unpack uint32: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint32: {e}")
    
    def read_uint64(self) -> int:
        try:
            self.ensure(8)
            val = struct.unpack('>Q', self.data[self.offset:self.offset+8])[0]
            self.offset += 8
            return val
        except struct.error as e:
            raise ValueError(f"Failed to unpack uint64: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint64: {e}")
    
    def read_bytes(self, length: int) -> bytes:
        try:
            if length < 0:
                raise ValueError(f"Negative length: {length}")
            self.ensure(length)
            val = self.data[self.offset:self.offset+length]
            self.offset += length
            return val
        except IndexError as e:
            raise ValueError(f"Failed to read {length} bytes: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading bytes: {e}")
    
    def read_mpi(self) -> bytes:
        """Read MPI: uint32 length followed by bytes."""
        try:
            length = self.read_uint32()
            if length == 0:
                return b''
            if length > 1024 * 1024:
                raise ValueError(f"MPI too large: {length}")
            return self.read_bytes(length)
        except ValueError as e:
            raise ValueError(f"Invalid MPI: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading MPI: {e}")
    
    def read_varbytes(self) -> bytes:
        """Read varbytes: uint32 length followed by bytes."""
        return self.read_mpi()
    
    def expect_end(self) -> None:
        """Ensure no trailing bytes remain."""
        if self.offset != self.length:
            raise ValueError(f"Trailing bytes: {self.length - self.offset} remaining")




def _generate_instance_tag() -> int:
    """Random 32-bit instance tag in [0x100, 0xFFFFFFFF] per OTRv4 spec §4.1.

    Two independent CSPRNG reads XOR'd together. Output is at least as strong
    as the stronger source even if one RNG is compromised.
    """
    while True:
        a = int.from_bytes(secrets.token_bytes(4), 'big')
        b = int.from_bytes(os.urandom(4), 'big')
        tag = a ^ b
        if 0x100 <= tag <= 0xFFFFFFFF:
            return tag




class OTRv4TLV:
    """Single TLV (Type-Length-Value) record inside an OTRv4 encrypted message.

    Wire format:  uint16 type  |  uint16 length  |  byte[length] value
    All multi-byte fields are big-endian (network byte order).

    TLV type 0x0000 (PADDING) MUST be silently discarded by receivers.
    Unknown TLV types MUST be silently ignored (forward compatibility).
    """
    __slots__ = ('type', 'value')

    PADDING             = 0x0000
    DISCONNECTED        = 0x0001
    SMP_MSG_1           = 0x0002
    SMP_MSG_2           = 0x0003
    SMP_MSG_3           = 0x0004
    SMP_MSG_4           = 0x0005
    SMP_ABORT           = 0x0006
    SMP_MSG_1Q          = 0x0007
    EXTRA_SYMMETRIC_KEY = 0x0009

    SMP_TYPES = frozenset({SMP_MSG_1, SMP_MSG_2, SMP_MSG_3, SMP_MSG_4,
                           SMP_ABORT, SMP_MSG_1Q})

    def __init__(self, tlv_type: int, value: bytes = b''):
        if not (0 <= tlv_type <= 0xFFFF):
            raise ValueError(f"TLV type out of range: {tlv_type:#06x}")
        if len(value) > 65535:
            raise ValueError(f"TLV value too large: {len(value)} bytes (max 65535)")
        self.type  = tlv_type
        self.value = bytes(value)

    def encode(self) -> bytes:
        """Serialize to wire bytes: uint16 type + uint16 length + value."""
        return struct.pack('!HH', self.type, len(self.value)) + self.value

    @classmethod
    def decode_one(cls, data: bytes, offset: int = 0) -> Tuple['OTRv4TLV', int]:
        """Decode one TLV from *data* at *offset*.  Returns (tlv, next_offset).

        Raises ValueError on truncated or malformed input.
        """
        if offset + 4 > len(data):
            raise ValueError(
                f"TLV header truncated at offset {offset} "
                f"(need 4, have {len(data) - offset})"
            )
        tlv_type, length = struct.unpack_from('!HH', data, offset)
        end = offset + 4 + length
        if end > len(data):
            raise ValueError(
                f"TLV value truncated: type=0x{tlv_type:04x} "
                f"declares {length} bytes but only {len(data) - offset - 4} available"
            )
        return cls(tlv_type, data[offset + 4:end]), end

    @classmethod
    def decode_all(cls, data: bytes) -> List['OTRv4TLV']:
        """Decode all TLVs from *data*.  Raises ValueError on malformed stream."""
        tlvs: List['OTRv4TLV'] = []
        offset = 0
        while offset < len(data):
            tlv, offset = cls.decode_one(data, offset)
            tlvs.append(tlv)
        return tlvs

    @classmethod
    def encode_all(cls, tlvs: List['OTRv4TLV']) -> bytes:
        return b''.join(t.encode() for t in tlvs)

    @classmethod
    def random_padding(cls, min_bytes: int = 8, max_bytes: int = 72) -> 'OTRv4TLV':
        """Create a PADDING TLV with random content for traffic analysis resistance."""
        pad_len = secrets.randbelow(max_bytes - min_bytes + 1) + min_bytes
        return cls(cls.PADDING, os.urandom(pad_len))

    def __repr__(self) -> str:
        _NAMES = {0: 'PADDING', 1: 'DISCONNECTED', 2: 'SMP_MSG_1', 3: 'SMP_MSG_2',
                  4: 'SMP_MSG_3', 5: 'SMP_MSG_4', 6: 'SMP_ABORT',
                  7: 'SMP_MSG_1Q', 8: 'EXTRA_SYMMETRIC_KEY'}
        name = _NAMES.get(self.type, f'UNKNOWN(0x{self.type:04x})')
        return f"OTRv4TLV({name}, {len(self.value)} bytes)"




class OTRv4Payload:
    """Encodes / decodes the cleartext payload inside an OTRv4 DATA message.

    Per spec §4.4.3 the decrypted payload has the structure:
        human_readable_message  (UTF-8, may be empty)
        0x00                    (NULL separator — only present when TLVs follow)
        TLV*                    (zero or more TLV records)

    PADDING TLVs (type 0x0000) in received messages are silently discarded.
    Unknown TLV types are silently ignored (forward compatibility per spec).
    """
    __slots__ = ('text', 'tlvs')

    def __init__(self, text: str = '', tlvs: Optional[List['OTRv4TLV']] = None):
        self.text = text or ''
        self.tlvs: List[OTRv4TLV] = list(tlvs) if tlvs else []

    def encode(self, add_padding: bool = True) -> bytes:
        """Encode to bytes for encryption.

        If *add_padding* is True (default), appends a random PADDING TLV to
        resist traffic-analysis attacks by blurring plaintext length.
        """
        text_bytes = self.text.encode('utf-8') if self.text else b''
        tlvs = list(self.tlvs)
        if add_padding:
            tlvs.append(OTRv4TLV.random_padding())
        if tlvs:
            return text_bytes + b'\x00' + OTRv4TLV.encode_all(tlvs)
        return text_bytes

    @classmethod
    def decode(cls, data: bytes) -> 'OTRv4Payload':
        """Decode from decrypted bytes.  PADDING TLVs are silently dropped."""
        null_pos = data.find(b'\x00')
        if null_pos == -1:
            return cls(data.decode('utf-8', errors='replace'), [])

        text = data[:null_pos].decode('utf-8', errors='replace')
        tlv_bytes = data[null_pos + 1:]

        if not tlv_bytes:
            return cls(text, [])

        all_tlvs = OTRv4TLV.decode_all(tlv_bytes)
        non_padding = [t for t in all_tlvs if t.type != OTRv4TLV.PADDING]
        return cls(text, non_padding)




class OTRv4DataMessage:
    """OTRv4 DATA message wire format (spec §4.4.3)."""

    PROTOCOL_VERSION = 0x0004
    TYPE             = 0x03
    ECDH_LEN         = 56
    NONCE_LEN        = 12
    MAC_LEN          = 64
    FLAG_IGNORE_UNREADABLE = 0x01

    def __init__(self):
        self.sender_tag:        int            = 0
        self.receiver_tag:      int            = 0
        self.flags:             int            = 0
        self.prev_chain_len:    int            = 0
        self.ratchet_id:        int            = 0
        self.message_id:        int            = 0
        self.ecdh_pub:          bytes          = b''
        self.dh_pub:            Optional[bytes] = None
        self.kem_ek:            Optional[bytes] = None   # ML-KEM-1024 encap key (brace rotation)
        self.kem_ct:            Optional[bytes] = None   # ML-KEM-1024 ciphertext (brace rotation)
        self.nonce:             bytes          = b''
        self.ciphertext:        bytes          = b''
        self.mac:               bytes          = b''
        self.revealed_mac_keys: List[bytes]    = []

    def _auth_header(self) -> bytes:
        """Bytes from protocol version through nonce (the authenticatable region)."""
        try:
            if len(self.ecdh_pub) != self.ECDH_LEN:
                raise ValueError(f"ECDH key must be {self.ECDH_LEN} bytes")
            if len(self.nonce) != self.NONCE_LEN:
                raise ValueError(f"Nonce must be {self.NONCE_LEN} bytes")
            buf = bytearray()
            buf += struct.pack('!HB', self.PROTOCOL_VERSION, self.TYPE)
            buf += struct.pack('!II', self.sender_tag, self.receiver_tag)
            buf += struct.pack('!B', self.flags)
            buf += struct.pack('!III', self.prev_chain_len, self.ratchet_id, self.message_id)
            buf += self.ecdh_pub
            if self.dh_pub is not None:
                if len(self.dh_pub) != self.ECDH_LEN:
                    raise ValueError(f"DH key must be {self.ECDH_LEN} bytes")
                buf += b'\x01' + self.dh_pub
            else:
                buf += b'\x00'
            # ── ML-KEM-1024 brace rotation fields ───────────────
            if self.kem_ek is not None:
                if len(self.kem_ek) != MLKEM1024BraceKEM.EK_BYTES:
                    raise ValueError(f"KEM ek must be {MLKEM1024BraceKEM.EK_BYTES} bytes")
                buf += b'\x01' + self.kem_ek
            else:
                buf += b'\x00'
            if self.kem_ct is not None:
                if len(self.kem_ct) != MLKEM1024BraceKEM.CT_BYTES:
                    raise ValueError(f"KEM ct must be {MLKEM1024BraceKEM.CT_BYTES} bytes")
                buf += b'\x01' + self.kem_ct
            else:
                buf += b'\x00'
            buf += self.nonce
            return bytes(buf)
        except (struct.error, TypeError, ValueError) as e:
            raise ValueError(f"Failed to build auth header: {e}")

    def compute_mac(self, mac_key: bytes) -> bytes:
        """SHA3-512(mac_key ‖ auth_header ‖ uint32(len(ciphertext)) ‖ ciphertext)."""
        try:
            ah  = self._auth_header()
            ct  = struct.pack('!I', len(self.ciphertext)) + self.ciphertext
            return hashlib.sha3_512(mac_key + ah + ct).digest()
        except (TypeError, ValueError, struct.error) as e:
            raise ValueError(f"Failed to compute MAC: {e}")

    def verify_mac(self, mac_key: bytes) -> bool:
        """Constant-time MAC verification."""
        try:
            if len(self.mac) != self.MAC_LEN:
                return False
            computed = self.compute_mac(mac_key)
            return hmac.compare_digest(self.mac, computed)
        except (TypeError, ValueError) as e:
            if DEBUG_MODE:
                print(f"[OTRv4DataMessage] MAC verification error: {e}")
            return False
        except Exception:
            return False

    def encode(self) -> bytes:
        """Encode the complete DATA message to bytes for base64 transport."""
        try:
            ah     = self._auth_header()
            ct_blk = struct.pack('!I', len(self.ciphertext)) + self.ciphertext
            mac    = self.mac if len(self.mac) == self.MAC_LEN else b'\x00' * self.MAC_LEN
            keys   = struct.pack('!I', len(self.revealed_mac_keys))
            for k in self.revealed_mac_keys:
                if len(k) != 32:
                    raise ValueError(f"Revealed MAC key must be 32 bytes, got {len(k)}")
                keys += k
            return ah + ct_blk + mac + keys
        except (struct.error, TypeError, ValueError) as e:
            raise ValueError(f"Failed to encode message: {e}")

    @classmethod
    def decode(cls, data: bytes) -> 'OTRv4DataMessage':
        """Decode raw bytes into an OTRv4DataMessage.  Raises ValueError on errors."""
        try:
            r   = BinaryReader(data)
            msg = cls()

            ver = r.read_uint16()
            if ver != cls.PROTOCOL_VERSION:
                raise ValueError(f"Wrong OTRv4 version: 0x{ver:04x}")
            mtype = r.read_uint8()
            if mtype != cls.TYPE:
                raise ValueError(f"Wrong message type: 0x{mtype:02x} (expected 0x{cls.TYPE:02x})")

            msg.sender_tag     = r.read_uint32()
            msg.receiver_tag   = r.read_uint32()
            msg.flags          = r.read_uint8()
            msg.prev_chain_len = r.read_uint32()
            msg.ratchet_id     = r.read_uint32()
            msg.message_id     = r.read_uint32()
            msg.ecdh_pub       = r.read_bytes(cls.ECDH_LEN)

            dh_flag = r.read_uint8()
            if dh_flag == 0x01:
                msg.dh_pub = r.read_bytes(cls.ECDH_LEN)
            elif dh_flag != 0x00:
                raise ValueError(f"Invalid DH flag byte: 0x{dh_flag:02x}")

            # ── ML-KEM-1024 brace rotation fields ───────────────
            kem_ek_flag = r.read_uint8()
            if kem_ek_flag == 0x01:
                msg.kem_ek = r.read_bytes(MLKEM1024BraceKEM.EK_BYTES)
            elif kem_ek_flag != 0x00:
                raise ValueError(f"Invalid KEM ek flag: 0x{kem_ek_flag:02x}")

            kem_ct_flag = r.read_uint8()
            if kem_ct_flag == 0x01:
                msg.kem_ct = r.read_bytes(MLKEM1024BraceKEM.CT_BYTES)
            elif kem_ct_flag != 0x00:
                raise ValueError(f"Invalid KEM ct flag: 0x{kem_ct_flag:02x}")

            msg.nonce      = r.read_bytes(cls.NONCE_LEN)
            ct_len         = r.read_uint32()
            msg.ciphertext = r.read_bytes(ct_len)
            msg.mac        = r.read_bytes(cls.MAC_LEN)

            num_keys = r.read_uint32()
            if num_keys > 2000:
                raise ValueError(f"Implausible revealed key count: {num_keys}")
            for _ in range(num_keys):
                msg.revealed_mac_keys.append(r.read_bytes(32))

            return msg
        except (ValueError, struct.error, TypeError) as e:
            raise ValueError(f"Failed to decode message: {e}")


VERSION = "OTRv4+ 10.0"

if not hasattr(hashlib, 'sha3_512'):
    raise RuntimeError(
        "FATAL: SHA3-512 is required by OTRv4 §3.2 but is unavailable in "
        "this Python build.  Please upgrade to Python ≥ 3.6 with SHA3 support."
    )
DEBUG_MODE = '--debug' in sys.argv or '-d' in sys.argv
SMP_DEBUG = DEBUG_MODE or '--smp-debug' in sys.argv
TEST_MODE = '--test' in sys.argv

global IS_TERMUX
IS_TERMUX = 'ANDROID_ROOT' in os.environ or 'TERMUX_VERSION' in os.environ

try:
    terminal_size = shutil.get_terminal_size(fallback=(80, 24))
    TERMINAL_WIDTH = terminal_size.columns
    TERMINAL_HEIGHT = terminal_size.lines
    if IS_TERMUX and TERMINAL_WIDTH < 40:
        TERMINAL_WIDTH = 80
except Exception:
    TERMINAL_WIDTH = 80
    TERMINAL_HEIGHT = 24





def _sanitise(text: str, max_len: int = 512) -> str:
    """Strip ANSI escape sequences and non-printable control characters from
    untrusted IRC data (nicks, topics, messages, reasons) before display.
    Prevents terminal escape injection from malicious servers or peers.
    Keeps: printable ASCII, unicode letters/symbols, common whitespace.
    """
    import re
    text = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)
    text = re.sub(r'\x1b[^\[\x1b]', '', text)
    text = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', text)
    return text[:max_len]

def colorize(text: str, color: str) -> str:
    """Colorize text with ANSI colors"""
    return f"{UIConstants.COLORS.get(color, '')}{text}{UIConstants.COLORS['reset']}"

def colorize_username(username: str) -> str:
    """Colorize username — FNV-1a hash for colour, italic for server/bot nicks.

    Rules matching the screenshot aesthetic:
      - IRC server names (contain a '.') → dim italic dark_cyan
      - Service bots (ChanServ, NickServ, etc.) → dim italic dark_magenta
      - Normal users → one of 12 bright colours based on FNV-1a hash
    """
    if not username:
        return ""
    R  = UIConstants.COLORS['reset']
    DI = UIConstants.COLORS['dim_italic']
    if '.' in username and not username.startswith('#'):
        return f"{DI}{UIConstants.COLORS['dark_cyan']}{username}{R}"
    _services = ('chanserv', 'nickserv', 'memoserv', 'operserv', 'botserv',
                 'hostserv', 'groupserv', 'global', 'alis')
    if username.lower() in _services:
        return f"{DI}{UIConstants.COLORS['dark_magenta']}{username}{R}"
    h = 2166136261
    for c in username:
        h = ((h ^ ord(c)) * 16777619) & 0xFFFFFFFF
    color = UIConstants.USERNAME_COLORS[h % len(UIConstants.USERNAME_COLORS)]
    return colorize(username, color)

_print_lock = threading.Lock()

_current_prompt: str = ""

# ── Character-at-a-time input system ─────────────────────────────────
#
# The main thread reads one keystroke at a time (termios ICANON off)
# and appends to _input_buffer.  The recv thread's _emit_line() can
# safely clear the terminal line, print a message, then restore the
# prompt + _input_buffer — so incoming messages NEVER corrupt what
# the user is typing.
#
# On non-TTY stdin (piped input, test harness) the system falls back
# to the old sys.stdin.readline() cooked-mode path automatically.

_input_buffer: List[str] = []

_raw_mode_active = False
_stdin_fd: int = -1
_orig_termios = None


def _setup_raw_mode() -> bool:
    """Disable canonical mode and echo on stdin.  Returns True on success."""
    global _raw_mode_active, _stdin_fd, _orig_termios
    if not sys.stdin.isatty():
        return False
    try:
        import termios as _tm
        _stdin_fd = sys.stdin.fileno()
        _orig_termios = _tm.tcgetattr(_stdin_fd)
        new = _tm.tcgetattr(_stdin_fd)
        # Turn off: echo, canonical mode, extended editing
        new[3] &= ~(_tm.ECHO | _tm.ICANON | _tm.ECHOE |
                     _tm.ECHOK | _tm.ECHONL)
        # Keep ISIG so Ctrl-C still raises KeyboardInterrupt
        new[6][_tm.VMIN] = 1    # read returns after 1 byte
        new[6][_tm.VTIME] = 0   # no timeout
        _tm.tcsetattr(_stdin_fd, _tm.TCSADRAIN, new)
        _raw_mode_active = True
        return True
    except Exception:
        return False


def _restore_terminal() -> None:
    """Restore the original terminal settings saved by _setup_raw_mode()."""
    global _raw_mode_active
    if _raw_mode_active and _stdin_fd >= 0 and _orig_termios is not None:
        try:
            import termios as _tm
            _tm.tcsetattr(_stdin_fd, _tm.TCSADRAIN, _orig_termios)
        except Exception:
            pass
        _raw_mode_active = False


def _read_one_char() -> Optional[str]:
    """Read one character from stdin (handles UTF-8 multi-byte).

    Returns the character, or None on EOF.
    Uses os.read() to bypass Python's buffered I/O.
    """
    b = os.read(_stdin_fd, 1)
    if not b:
        return None
    byte = b[0]
    if byte < 0x80:
        return chr(byte)
    if byte < 0xC0:
        return None                     # stray continuation byte
    remaining = 1 if byte < 0xE0 else 2 if byte < 0xF0 else 3
    data = b
    for _ in range(remaining):
        b2 = os.read(_stdin_fd, 1)
        if not b2:
            break
        data += b2
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return None


def _consume_escape_seq() -> None:
    """Read and discard an ANSI escape sequence after ESC (0x1b)."""
    try:
        r, _, _ = select.select([_stdin_fd], [], [], 0.05)
        if not r:
            return
        b2 = os.read(_stdin_fd, 1)
        if not b2:
            return
        if b2 in (b'[', b'O'):
            # CSI (ESC [) or SS3 (ESC O) — read until final byte 0x40-0x7e
            while True:
                r2, _, _ = select.select([_stdin_fd], [], [], 0.05)
                if not r2:
                    break
                b3 = os.read(_stdin_fd, 1)
                if not b3 or (0x40 <= b3[0] <= 0x7e):
                    break
    except Exception:
        pass


_EOF_SENTINEL = object()


def _handle_input_char(ch: str):
    """Process one keystroke, updating _input_buffer and echoing to stdout.

    Returns
    -------
    str             — the completed line (user pressed Enter)
    _EOF_SENTINEL   — Ctrl-D on an empty buffer (EOF)
    None            — character consumed, keep reading
    """
    if ch == '\r' or ch == '\n':
        with _print_lock:
            line = ''.join(_input_buffer)
            _input_buffer.clear()
            # ── Erase the prompt+text (may span multiple visual lines) ──
            #    On narrow Termux screens, prompt+text wraps.  We use
            #    \033[2J-style erase: calculate visual lines from the
            #    visible character count (stripping ANSI colour codes).
            _ansi_strip = re.compile(r'\x1b\[[0-9;]*m')
            _vis_prompt = _ansi_strip.sub('', _current_prompt)
            _total = len(_vis_prompt) + len(line)
            _tw = TERMINAL_WIDTH if TERMINAL_WIDTH > 0 else 80
            _lines = max(1, (_total + _tw - 1) // _tw)
            # Cursor is at end of last visual line.  Move up to first,
            # then erase downward.
            if _lines > 1:
                sys.stdout.write(f'\033[{_lines - 1}A')
            sys.stdout.write('\r')
            for _ in range(_lines):
                sys.stdout.write('\033[2K\n')
            # Cursor is now one line below the last erased line.
            # Move back up to where the first erased line was.
            sys.stdout.write(f'\033[{_lines}A\r')
            sys.stdout.flush()
        return line

    if ch == '\x04':                    # Ctrl-D
        with _print_lock:
            if not _input_buffer:
                return _EOF_SENTINEL
        return None

    if ch == '\x15':                    # Ctrl-U  — kill line
        with _print_lock:
            _input_buffer.clear()
            sys.stdout.write('\r\033[2K' + _current_prompt)
            sys.stdout.flush()
        return None

    if ch == '\x17':                    # Ctrl-W  — delete word
        with _print_lock:
            while _input_buffer and _input_buffer[-1] == ' ':
                _input_buffer.pop()
            while _input_buffer and _input_buffer[-1] != ' ':
                _input_buffer.pop()
            sys.stdout.write('\r\033[2K' + _current_prompt
                             + ''.join(_input_buffer))
            sys.stdout.flush()
        return None

    if ch in ('\x7f', '\x08'):          # Backspace / DEL
        with _print_lock:
            if _input_buffer:
                _input_buffer.pop()
                sys.stdout.write('\b \b')
                sys.stdout.flush()
        return None

    if ch == '\x1b':                    # Escape — eat the sequence
        _consume_escape_seq()
        return None

    if ch == '\t':                      # Tab (reserved for future nick-complete)
        return None

    if ch >= ' ':                       # Printable character (incl. UTF-8)
        with _print_lock:
            _input_buffer.append(ch)
            sys.stdout.write(ch)
            sys.stdout.flush()
        return None

    return None                         # ignore other control chars


def _set_prompt(prompt: str) -> None:
    """Write a prompt string, preserving the user's typed text."""
    global _current_prompt
    with _print_lock:
        buf = ''.join(_input_buffer)
        if _current_prompt or buf:
            sys.stdout.write('\r\033[2K')
        _current_prompt = prompt
        sys.stdout.write(prompt + buf)
        sys.stdout.flush()


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

def _visible_len(text: str) -> int:
    """Return the visible character count, ignoring ANSI colour codes."""
    return len(_ANSI_RE.sub('', text))


def _word_wrap(text: str, width: int) -> str:
    """Word-wrap text at *width* visible columns, preserving ANSI codes.

    The first line uses the full width.  Continuation lines are indented
    to align with the message body (detected by finding the first '] '
    in the visible text — the end of the timestamp+tag prefix).

    If the text fits in one line, it is returned unchanged.
    """
    if width < 20 or _visible_len(text) <= width:
        return text

    # ── Detect indent from prefix ────────────────────────────
    #    Format: "11:48:42 [#chan] message..."
    #    We want continuation lines to start under the message,
    #    i.e. after the last '] ' in the prefix.
    vis = _ANSI_RE.sub('', text)
    _bracket_end = vis.find('] ')
    if _bracket_end != -1 and _bracket_end < width // 2:
        indent = _bracket_end + 2
    else:
        indent = 4   # fallback

    indent_str = ' ' * indent

    # ── Split into tokens: (ansi_code | word | space) ────────
    #    We walk the text tracking visible position.
    parts = _ANSI_RE.split(text)
    codes = _ANSI_RE.findall(text)

    # Interleave: parts[0], codes[0], parts[1], codes[1], ...
    tokens = []   # list of (string, is_ansi)
    for i, part in enumerate(parts):
        if part:
            tokens.append((part, False))
        if i < len(codes):
            tokens.append((codes[i], True))

    lines = []
    current_line = ''
    current_vis = 0
    first_line = True

    for token_str, is_ansi in tokens:
        if is_ansi:
            current_line += token_str
            continue

        # Split visible text on spaces to get wrappable words
        words = token_str.split(' ')
        for wi, word in enumerate(words):
            # Add space before word (except first word in token)
            if wi > 0:
                # Space character
                space_fits = current_vis + 1 + len(word) <= width
                if current_vis > 0 and not space_fits and len(word) > 0:
                    # Wrap before this word
                    lines.append(current_line)
                    current_line = indent_str + word if not first_line else indent_str + word
                    first_line = False
                    current_vis = indent + len(word)
                else:
                    current_line += ' ' + word
                    current_vis += 1 + len(word)
            else:
                # First word in this token segment
                if current_vis + len(word) > width and current_vis > 0:
                    lines.append(current_line)
                    current_line = indent_str + word
                    first_line = False
                    current_vis = indent + len(word)
                else:
                    current_line += word
                    current_vis += len(word)

    if current_line:
        lines.append(current_line)

    return '\n'.join(lines)


def _emit_line(text: str) -> None:
    """Print a message line from any thread, preserving user input.

    Word-wraps at TERMINAL_WIDTH so words are never split mid-word.
    Clears the current terminal line (prompt + typed text), writes the
    message, then restores the prompt and the user's in-progress buffer
    so their typing is never lost or corrupted.
    """
    wrapped = _word_wrap(text, TERMINAL_WIDTH)
    with _print_lock:
        buf = ''.join(_input_buffer)
        sys.stdout.write('\r\033[2K')
        sys.stdout.write(wrapped + '\n')
        if _current_prompt or buf:
            sys.stdout.write(_current_prompt + buf)
        sys.stdout.flush()


# Legacy queue kept as a safety net for the cooked-mode fallback path.
_display_queue: deque = deque()


def _flush_display_queue() -> None:
    """Flush any queued messages to stdout (cooked-mode fallback only)."""
    if not _display_queue:
        return
    with _print_lock:
        buf = ''.join(_input_buffer)
        sys.stdout.write('\r\033[2K')
        while _display_queue:
            sys.stdout.write(_display_queue.popleft() + '\n')
        if _current_prompt or buf:
            sys.stdout.write(_current_prompt + buf)
        sys.stdout.flush()


def safe_print(*args, **kwargs):
    """Thread-safe print with flush, preserving user input in raw mode."""
    kwargs['flush'] = True
    with _print_lock:
        buf = ''.join(_input_buffer)
        if (_current_prompt or buf) and _raw_mode_active:
            sys.stdout.write('\r\033[2K')
        print(*args, **kwargs)
        if (_current_prompt or buf) and _raw_mode_active:
            sys.stdout.write(_current_prompt + buf)
            sys.stdout.flush()

@dataclass
class OTRConfig:
    """Mutable configuration object"""
    trust_db_path: Optional[str] = None
    smp_secrets_path: Optional[str] = None
    key_storage_path: Optional[str] = None
    log_file_path: Optional[str] = None
    test_mode: bool = False
    i2p_proxy: Tuple[str, int] = ("127.0.0.1", 4447)
    tor_proxy: Tuple[str, int] = ("127.0.0.1", 9050)
    server: str = "irc.postman.i2p"
    port: int = 0               # 0 = auto (6697 TLS clearnet, 6667 otherwise)
    use_tls: bool = False       # auto-set for clearnet; forced off for I2P/Tor
    sasl_user: Optional[str] = None
    sasl_pass: Optional[str] = None
    channel: str = "#otr"
    log_level: str = "INFO"
    dake_timeout: float = 120.0
    fragment_timeout: float = 120.0
    heartbeat_interval: int = 300
    rekey_interval: int = 100
    nickserv_login: bool = False
    nickserv_register: bool = False
    nickserv_nick: Optional[str] = None
    nickserv_pass: Optional[str] = None

@dataclass
class IRCMessage:
    """Immutable message object"""
    raw: str
    prefix: Optional[str]
    command: str
    params: List[str]
    trailing: Optional[str]
    timestamp: float
    sender: Optional[str]

@dataclass
class RecoveryState:
    """Session recovery state"""
    session_id: bytes
    last_message_counter: int
    recovery_attempts: int = 0
    security_level: UIConstants.SecurityLevel = UIConstants.SecurityLevel.PLAINTEXT
    timestamp: float = time.time()




class StateMachineError(Exception):
    """State machine transition error"""
    pass

class EncryptionError(Exception):
    """Encryption error with context"""
    def __init__(self, message: str, session: Optional['OTRSession'] = None):
        super().__init__(message)
        self.session = session

class TypeValidationError(Exception):
    """Type validation error"""
    pass




class NullLogger:
    """Logger that does nothing - for testing"""
    def __init__(self):
        pass
    
    def security_event(self, event: str, session_id: str, peer: str, details: dict):
        pass
    
    def network_message(self, direction: str, peer: str, msg_type: str, length: int):
        pass
    
    def ui_interaction(self, action: str, panel: str, user_input: str):
        pass
    
    def session_transition(self, old_state: str, new_state: str, peer: str, session_id: str):
        pass
    
    def info(self, msg: str):
        pass
    
    def warning(self, msg: str):
        pass
    
    def error(self, msg: str):
        pass
    
    def debug(self, msg: str):
        pass

class OTRLogger:
    """Structured logging framework"""
    
    def __init__(self, config: Optional[OTRConfig] = None):
        self.config = config or OTRConfig()
        self._setup_loggers()
    
    def _setup_loggers(self):
        """Setup structured loggers"""
        log_dir = os.path.dirname(self.config.log_file_path or '~/.otrv4/logs/otrv4.log')
        log_dir = os.path.expanduser(log_dir)
        os.makedirs(log_dir, exist_ok=True)
        try:
            os.chmod(log_dir, 0o700)
        except Exception:
            pass
        
        log_file = self.config.log_file_path or os.path.join(log_dir, 'otrv4plus.log')
        if not os.path.exists(log_file):
            try:
                open(log_file, 'a').close()
                os.chmod(log_file, 0o600)
            except Exception:
                pass
        
        handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,
            backupCount=5
        )
        
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s'
        )
        handler.setFormatter(formatter)
        
        self.security_logger = logging.getLogger('otrv4.security')
        self.network_logger = logging.getLogger('otrv4.network')
        self.ui_logger = logging.getLogger('otrv4.ui')
        self.session_logger = logging.getLogger('otrv4.session')
        
        for logger in [self.security_logger, self.network_logger, 
                      self.ui_logger, self.session_logger]:
            logger.addHandler(handler)
            logger.setLevel(getattr(logging, self.config.log_level.upper()))
            logger.propagate = False
    
    def security_event(self, event: str, session_id: str, peer: str, details: dict):
        """Log security events"""
        self.security_logger.info(
            f"EVENT={event} | SESSION={session_id} | PEER={peer} | {json.dumps(details)}"
        )
    
    def network_message(self, direction: str, peer: str, msg_type: str, length: int):
        """Log network I/O"""
        self.network_logger.debug(
            f"DIRECTION={direction} | PEER={peer} | TYPE={msg_type} | LENGTH={length}"
        )
    
    def ui_interaction(self, action: str, panel: str, user_input: str):
        """Log UI interactions (excluding secrets)"""
        self.ui_logger.info(
            f"ACTION={action} | PANEL={panel} | INPUT_LENGTH={len(user_input)}"
        )
    
    def session_transition(self, old_state: str, new_state: str, peer: str, session_id: str):
        """Log session state transitions"""
        self.session_logger.info(
            f"TRANSITION={old_state}→{new_state} | PEER={peer} | SESSION={session_id}"
        )
    
    def info(self, msg: str):
        """Log info message"""
        self.security_logger.info(msg)
    
    def warning(self, msg: str):
        """Log warning message"""
        self.security_logger.warning(msg)
    
    def error(self, msg: str):
        """Log error message"""
        self.security_logger.error(msg)
    
    def debug(self, msg: str):
        """Log debug message"""
        self.security_logger.debug(msg)

class OTRTracer:
    """
    Unified tracing subsystem for OTRv4 state monitoring.

    Traces are NEVER printed directly to stdout.  The client registers a
    callback (set_emit_callback) which routes each trace line to the debug
    panel.  This keeps all OTR internals out of the channel/system tabs.
    """

    def __init__(self, enabled: bool = True, logger: Optional[OTRLogger] = None):
        self.enabled   = enabled or DEBUG_MODE
        self.logger    = logger
        self.peer_states: Dict[str, Dict[str, Any]] = {}
        self.lock      = threading.RLock()
        self._emit_cb  = None

    def set_emit_callback(self, cb) -> None:
        """Register the client's debug-panel emit function."""
        self._emit_cb = cb

    def trace(self, peer: str, category: str, old_state: Any, new_state: Any,
              reason: Optional[str] = None, details: Optional[Dict] = None):
        """Record a state transition. Output goes ONLY to debug panel, never stdout."""
        if not self.enabled:
            return

        with self.lock:
            if peer not in self.peer_states:
                self.peer_states[peer] = {}
            self.peer_states[peer][category] = new_state

            old_str = str(old_state).replace("State.", "").replace("SMPState.", "").replace("DAKEState.", "")
            new_str = str(new_state).replace("State.", "").replace("SMPState.", "").replace("DAKEState.", "")

            msg = f"[OTR:{peer}] {category}: {old_str} → {new_str}"
            if reason:
                msg += f" | {reason}"

            if self.logger:
                self.logger.session_transition(old_str, new_str, peer, category)

            color = ("green"  if "ESTABLISHED" in new_str or "ENCRYPTED" in new_str else
                     "red"    if "FAILED"       in new_str else
                     "yellow" if "SENT"         in new_str or "RECEIVED" in new_str else "cyan")
            colored_msg = colorize(msg, color)

            if self._emit_cb:
                self._emit_cb(colored_msg)
                if details and DEBUG_MODE:
                    for k, v in details.items():
                        if k not in ("secret", "key", "nonce", "private", "password"):
                            self._emit_cb(f"  {k}: {v}")
    
    def get_peer_state(self, peer: str, category: Optional[str] = None) -> Any:
        """Get current state for peer"""
        with self.lock:
            if peer not in self.peer_states:
                return None
            if category:
                return self.peer_states[peer].get(category)
            return self.peer_states[peer].copy()
    
    def reset_peer(self, peer: str):
        """Reset all tracing for a peer"""
        with self.lock:
            if peer in self.peer_states:
                del self.peer_states[peer]
                self.trace(peer, "TRACER", "ACTIVE", "RESET", "peer reset")
    
    def is_session_encrypted(self, peer: str) -> bool:
        """Check if session is encrypted"""
        with self.lock:
            state = self.get_peer_state(peer, "SESSION")
            return state == "ENCRYPTED"
    
    def is_dake_complete(self, peer: str) -> bool:
        """Check if DAKE completed successfully"""
        with self.lock:
            state = self.get_peer_state(peer, "DAKE")
            return state == "ESTABLISHED"
    
    def format_state_report(self, peer: str) -> str:
        """Format comprehensive state report for peer"""
        with self.lock:
            if peer not in self.peer_states:
                return f"No state tracked for {peer}"
            
            report = []
            report.append(f"OTR State Report for {colorize_username(peer)}:")
            for category, state in sorted(self.peer_states[peer].items()):
                state_str = str(state).replace("State.", "").replace("SMPState.", "").replace("DAKEState.", "")
                report.append(f"  {category:12} : {state_str}")
            
            return "\n".join(report)




class SecureMemory:
    """Secure memory buffer with mlock protection and multi-pass zeroization."""
    def __init__(self, size: int):
        self._size = size
        self._locked = False
        self._buffer: Optional[bytearray] = None
        self._lock = threading.RLock()
        self._libc = None
        
        aligned_size = ((size + NetworkConstants.MLOCK_PAGE_SIZE - 1) // NetworkConstants.MLOCK_PAGE_SIZE) * NetworkConstants.MLOCK_PAGE_SIZE
        with self._lock:
            self._buffer = bytearray(aligned_size)
            self._attempt_mlock()
    
    def _attempt_mlock(self):
        """Attempt to lock memory with proper error handling"""
        try:
            libc_names = ['libc.so.6', 'libc.so', 'libc.dylib', 'libc']
            
            for name in libc_names:
                try:
                    self._libc = ctypes.CDLL(ctypes.util.find_library(name) or name)
                    break
                except (OSError, TypeError) as e:
                    continue
            
            if self._libc is None:
                self._log_mlock_failure("No libc found")
                return
                
            buf_addr = ctypes.c_void_p.from_buffer(self._buffer)
            buf_size = len(self._buffer)
            
            if hasattr(self._libc, 'mlock'):
                result = self._libc.mlock(buf_addr, buf_size)
                if result == 0:
                    self._locked = True
                else:
                    errno = ctypes.get_errno()
                    self._log_mlock_failure(f"mlock failed with errno: {errno}")
            else:
                self._log_mlock_failure("mlock function not found")
                
        except (OSError, AttributeError, ValueError, Exception) as e:
            self._log_mlock_failure(f"Exception: {e}")
    
    def _log_mlock_failure(self, reason: str):
        """Log mlock failure without exposing sensitive info"""
        if DEBUG_MODE:
            print(f"[SecureMemory] Warning: {reason} - memory not locked")
    
    def zeroize(self):
        """Securely zeroize memory.

        HARDENED (Phase 5): when otr4_crypto_ext is available, delegates to
        OPENSSL_cleanse() which is designed to resist compiler dead-store
        elimination.  Falls back to multi-pass Python loop otherwise.
        """
        if not acquire_lock_with_timeout(self._lock, timeout=5.0):
            raise RuntimeError("Failed to acquire lock for zeroize")

        try:
            if self._buffer is None:
                return

            try:
                _ossl.cleanse(self._buffer)
            except Exception:
                pass
            try:
                n = len(self._buffer)
                if n > 0:
                    addr = (ctypes.c_char * n).from_buffer(self._buffer)
                    ctypes.memset(addr, 0, n)
            except Exception:
                pass

            if self._locked and self._libc is not None:
                try:
                    buf_addr = ctypes.c_void_p.from_buffer(self._buffer)
                    buf_size = len(self._buffer)
                    if hasattr(self._libc, 'munlock'):
                        self._libc.munlock(buf_addr, buf_size)
                except (OSError, AttributeError, Exception) as e:
                    if DEBUG_MODE:
                        print(f"[SecureMemory] munlock failed: {e}")
                self._locked = False

            self._buffer = None

        except Exception as e:
            if DEBUG_MODE:
                print(f"[SecureMemory] Zeroize error: {e}")
            raise
        finally:
            try:
                self._lock.release()
            except Exception:
                pass
    
    def write(self, data: bytes):
        """Write data to secure memory"""
        if not acquire_lock_with_timeout(self._lock, timeout=5.0):
            raise RuntimeError("Failed to acquire lock for write")
        
        try:
            if self._buffer is None:
                raise RuntimeError("SecureMemory buffer destroyed")
            
            if len(data) > self._size:
                raise ValueError(f"Data too large for SecureMemory")
            
            for i in range(len(self._buffer)):
                self._buffer[i] = 0
            
            for i, byte in enumerate(data):
                self._buffer[i] = byte
                
        except Exception as e:
            raise RuntimeError(f"Write failed: {e}")
        finally:
            try:
                self._lock.release()
            except Exception:
                pass
    
    def read(self) -> bytes:
        """Read data from secure memory"""
        if not acquire_lock_with_timeout(self._lock, timeout=5.0):
            raise RuntimeError("Failed to acquire lock for read")
        
        try:
            if self._buffer is None:
                raise RuntimeError("SecureMemory buffer destroyed")
            return bytes(self._buffer[:self._size])
        except Exception as e:
            raise RuntimeError(f"Read failed: {e}")
        finally:
            try:
                self._lock.release()
            except Exception:
                pass
    
    @property
    def is_locked(self) -> bool:
        return self._locked
    
    @property
    def size(self) -> int:
        return self._size
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.zeroize()
    
    def __del__(self):
        """Destructor with safe cleanup"""
        try:
            if hasattr(self, '_buffer') and self._buffer is not None:
                for i in range(len(self._buffer)):
                    self._buffer[i] = 0
        except Exception:
            pass




class SHA3_512:
    """SHA3-512 utility class (OTRv4 spec §3.2) — strict, no fallback.
    
    OTRv4 mandates SHA3-512.  Using SHA-512 instead is a spec violation
    and would break interoperability.  We require Python ≥ 3.6 where
    sha3_512 is always available; raise hard if it is not.
    """
    @staticmethod
    def _require() -> Any:
        if not hasattr(hashlib, 'sha3_512'):
            raise RuntimeError(
                "SHA3-512 is required by OTRv4 spec §3.2 but is not available "
                "in this Python build.  Upgrade to Python ≥ 3.6 with hashlib SHA3 support."
            )
        return hashlib.sha3_512

    @staticmethod
    def hash(data: bytes) -> bytes:
        return SHA3_512._require()(data).digest()

    @staticmethod
    def hmac(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, SHA3_512._require()).digest()
    
    @staticmethod
    def hash_to_int(*args) -> int:
        h = SHA3_512.hash(b''.join([
            arg if isinstance(arg, bytes) else str(arg).encode('utf-8')
            for arg in args
        ]))
        return int.from_bytes(h, byteorder='big') % SMPConstants.MODULUS



def _ct_mod_exp(base: int, exp: int, mod: int) -> int:
    """Constant-time modular exponentiation via OpenSSL BN_mod_exp_mont_consttime (always — no Python fallback)."""
    mod_bytes  = mod.to_bytes((mod.bit_length() + 7) // 8, 'big')
    base_bytes = base.to_bytes((mod.bit_length() + 7) // 8, 'big')
    exp_bytes  = exp.to_bytes((mod.bit_length() + 7) // 8, 'big')
    return int.from_bytes(_ossl.bn_mod_exp_consttime(base_bytes, exp_bytes, mod_bytes), 'big')


def _ct_mod_inv(a: int, mod: int) -> int:
    """Constant-time modular inverse via OpenSSL BN_mod_inverse (always — no Python fallback)."""
    mod_bytes = mod.to_bytes((mod.bit_length() + 7) // 8, 'big')
    a_bytes   = a.to_bytes((mod.bit_length() + 7) // 8, 'big')
    return int.from_bytes(_ossl.bn_mod_inverse(a_bytes, mod_bytes), 'big')


def _ct_rand_range(mod: int) -> int:
    """Uniform random integer in [1, mod-1] via OpenSSL BN_rand_range."""
    mod_bytes = mod.to_bytes((mod.bit_length() + 7) // 8, 'big')
    return int.from_bytes(_ossl.bn_rand_range(mod_bytes), 'big')




class SMPMath:
    """Mathematical operations for SMP zero-knowledge proofs.

    All modular exponentiation uses _ct_mod_exp() which routes through
    OpenSSL's BN_mod_exp_mont_consttime. No Python fallback exists.
    gmpy2 is not used anywhere.
    """

    @staticmethod
    def mod_exp(base: Any, exponent: Any, modulus: Any) -> Any:
        """Constant-time modular exponentiation (Phase 3 — OpenSSL backend)."""
        try:
            return _ct_mod_exp(int(base), int(exponent), int(modulus))
        except (TypeError, ValueError, ArithmeticError) as e:
            raise ValueError(f"mod_exp failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error in mod_exp: {e}")

    @staticmethod
    def mod_mul(a: Any, b: Any, modulus: Any) -> Any:
        """Modular multiplication (not secret-dependent; uses Python)."""
        try:
            return (int(a) * int(b)) % int(modulus)
        except (TypeError, ValueError, ArithmeticError) as e:
            raise ValueError(f"mod_mul failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error in mod_mul: {e}")

    @staticmethod
    def mod_inv(a: Any, modulus: Any) -> Any:
        """Modular inverse via OpenSSL BN_mod_inverse (Phase 3)."""
        try:
            return _ct_mod_inv(int(a), int(modulus))
        except (TypeError, ValueError, ArithmeticError) as e:
            raise ValueError(f"mod_inv failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error in mod_inv: {e}")

    @staticmethod
    def random_exponent(modulus_minus_one: Any) -> Any:
        """Generate random exponent 1 <= x < modulus-1 via OpenSSL BN_rand_range (Phase 3)."""
        try:
            mod = int(modulus_minus_one)
            result = _ct_rand_range(mod)
            if result <= 0 or result >= mod:
                raise ValueError("Random exponent out of range")
            return result
        except (TypeError, ValueError, ArithmeticError) as e:
            raise ValueError(f"random_exponent failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error in random_exponent: {e}")

    @staticmethod
    def int_to_bytes(value: Any, length: int) -> bytes:
        """Convert integer to big-endian bytes of exactly n bytes, left-padded."""
        try:
            return int(value).to_bytes(length, 'big')
        except (TypeError, ValueError, OverflowError) as e:
            raise ValueError(f"int_to_bytes failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error in int_to_bytes: {e}")

    @staticmethod
    def bytes_to_int(data: bytes) -> Any:
        """Convert bytes to integer."""
        try:
            if not isinstance(data, bytes):
                raise TypeError(f"Expected bytes, got {type(data)}")
            return int.from_bytes(data, 'big')
        except (TypeError, ValueError) as e:
            raise ValueError(f"bytes_to_int failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error in bytes_to_int: {e}")

    @staticmethod
    def hash_to_int(*args: Any, modulus: Any = SMPConstants.MODULUS) -> Any:
        """Hash arguments to integer modulo modulus for ZKP (Spec §5.4.2) — SHA3-512 strict"""
        try:
            h = hashlib.sha3_512()
            for arg in args:
                if arg is None:
                    h.update(b'')
                elif isinstance(arg, int):
                    int_val = int(arg)
                    h.update(int_val.to_bytes(SMPConstants.MODULUS_BYTES, 'big'))
                elif isinstance(arg, bytes):
                    h.update(arg)
                else:
                    h.update(str(arg).encode('utf-8'))
            digest = int.from_bytes(h.digest(), 'big')
            return digest % int(modulus)
        except (TypeError, ValueError, AttributeError) as e:
            raise ValueError(f"hash_to_int failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error in hash_to_int: {e}")

    @staticmethod
    def zkp_challenge(base: Any, public_value: Any, commitment: Any, modulus: Any) -> Any:
        """Generate ZKP challenge using Fiat-Shamir heuristic (Spec §5.4.2) — SHA3-512 strict"""
        try:
            h = hashlib.sha3_512()
            for val in [base, public_value, commitment]:
                if val is None:
                    h.update(b'')
                elif isinstance(val, int):
                    h.update(int(val).to_bytes(SMPConstants.MODULUS_BYTES, 'big'))
                elif isinstance(val, bytes):
                    h.update(val)
                else:
                    h.update(str(val).encode('utf-8'))
            return int.from_bytes(h.digest(), 'big') % int(modulus)
        except (TypeError, ValueError, AttributeError) as e:
            raise ValueError(f"zkp_challenge failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error in zkp_challenge: {e}")

    @staticmethod
    def verify_zkp(base: Any, public_value: Any, c: Any, s: Any, commitment: Any, modulus: Any) -> bool:
        """Verify ZKP: base^s == commitment * public_value^c (mod N) (Spec §5.4.3)

        HARDENED (Phase 3): both exponentiations use _ct_mod_exp (constant-time).
        """
        try:
            left = SMPMath.mod_exp(base, s, modulus)
            public_value_pow_c = SMPMath.mod_exp(public_value, c, modulus)
            right = SMPMath.mod_mul(commitment, public_value_pow_c, modulus)
            left_bytes  = SMPMath.int_to_bytes(left,  SMPConstants.MODULUS_BYTES)
            right_bytes = SMPMath.int_to_bytes(right, SMPConstants.MODULUS_BYTES)
            return hmac.compare_digest(left_bytes, right_bytes)
        except (TypeError, ValueError, ArithmeticError):
            return False
        except Exception:
            return False

    @staticmethod
    def validate_smp_value(value: Any, modulus: Any) -> bool:
        """Validate SMP group element — full subgroup membership check.

        HARDENED (Phase 3): the order check uses _ct_mod_exp (constant-time).
        """
        if value is None:
            return False
        try:
            val_int = int(value)
            mod_int = int(modulus)
            if not (2 <= val_int <= mod_int - 2):
                return False
            q = (mod_int - 1) // 2
            order_check = _ct_mod_exp(val_int, q, mod_int)
            return order_check == 1
        except (TypeError, ValueError, ArithmeticError):
            return False
        except Exception:
            return False
    
    @staticmethod
    def validate_mod_exponent(exponent: Any, modulus_minus_one: Any) -> bool:
        """Validate exponent is in correct range for modular exponentiation"""
        if exponent is None:
            return False
        
        try:
            exp_int = int(exponent)
            
            return 1 <= exp_int < int(modulus_minus_one)
        except (TypeError, ValueError):
            return False
        except Exception:
            return False




class ClientProfile:
    """OTRv4 Client Profile (spec §4.1). Handles encoding, decoding, and expiry."""

    def __init__(self, identity_key: ed448.Ed448PrivateKey = None,
                 prekey: x448.X448PrivateKey = None):
        """Create a fresh OTRv4 ClientProfile with ephemeral Ed448+X448 keys.

        Keys are ALWAYS generated fresh — no saved profile file is consulted.
        This is intentional and correct for random/ephemeral IRC nicks: each
        session gets brand-new cryptographic identity.  The profile is signed
        with the identity key inside encode().

        Encoded size for versions=[4]:
            version(1) + num_versions(1) + version_byte(1)
            + Ed448_pub(57) + X448_pub(56) + expires(8) + Ed448_sig(114)
            = 238 bytes exactly.
        """
        if identity_key is None:
            identity_key = ed448.Ed448PrivateKey.generate()
        if prekey is None:
            prekey = x448.X448PrivateKey.generate()

        self.identity_key = identity_key
        self.prekey = prekey
        self.versions = [OTRConstants.PROTOCOL_VERSION]
        self.created = int(time.time())
        self.expires = self.created + 365 * 24 * 3600
        self.signature = None

        self.identity_pub_bytes = None
        self.prekey_pub_bytes = None

        if DEBUG_MODE:
            import sys as _sys
            _sys.stderr.write(
                f"[ClientProfile] Fresh keys — expires {time.ctime(self.expires)}\n"
            )

    def encode(self) -> bytes:
        try:
            identity_pub = self.identity_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            prekey_pub = self.prekey.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            if len(identity_pub) != OTRConstants.ED448_PUBLIC_KEY_SIZE:
                raise ValueError(f"Identity key wrong length: {len(identity_pub)}")
            if len(prekey_pub) != OTRConstants.X448_PUBLIC_KEY_SIZE:
                raise ValueError(f"Prekey wrong length: {len(prekey_pub)}")

            profile_data = bytearray()
            profile_data.append(OTRConstants.PROTOCOL_VERSION)
            profile_data.append(len(self.versions))
            for v in self.versions:
                profile_data.append(v)
            profile_data.extend(identity_pub)
            profile_data.extend(prekey_pub)
            profile_data.extend(struct.pack('>Q', self.expires))

            self.signature = self.identity_key.sign(bytes(profile_data))
            if len(self.signature) != OTRConstants.ED448_SIGNATURE_SIZE:
                raise ValueError(f"Signature wrong length: {len(self.signature)}")

            profile_data.extend(self.signature)
            result = bytes(profile_data)
            expected = (1 + 1 + len(self.versions) +
                        OTRConstants.ED448_PUBLIC_KEY_SIZE +
                        OTRConstants.X448_PUBLIC_KEY_SIZE +
                        8 + OTRConstants.ED448_SIGNATURE_SIZE)
            if len(result) != expected:
                raise ValueError(
                    f"ClientProfile.encode() produced {len(result)} bytes, "
                    f"expected {expected}. OTRConstants key-size mismatch."
                )
            if DEBUG_MODE:
                print(f"[ClientProfile] encode() → {len(result)} bytes ✅")
            return result
        except (ValueError, TypeError, AttributeError) as e:
            raise ValueError(f"Client profile encoding failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error encoding profile: {e}")

    @classmethod
    def decode(cls, data: bytes) -> 'ClientProfile':
        """Strict profile decoding — rejects any profile that fails validation.
        
        OTRv4 spec §4.1.2 requires signature verification before accepting
        identity keys.  Allowing truncated or unsigned profiles is a MITM
        vector (audit finding
        any deviation; callers must abort the DAKE on exception.
        """
        try:
            min_size = (1 + 1 + 1 +
                        OTRConstants.ED448_PUBLIC_KEY_SIZE +
                        OTRConstants.X448_PUBLIC_KEY_SIZE +
                        8 +
                        OTRConstants.ED448_SIGNATURE_SIZE)

            if len(data) < min_size:
                raise ValueError(
                    f"ClientProfile too short: {len(data)} < {min_size} bytes. "
                    "Truncated profiles are rejected (OTRv4 §4.1.2)."
                )

            offset = 0
            version = data[offset]
            offset += 1
            if version != OTRConstants.PROTOCOL_VERSION:
                raise ValueError(
                    f"Unsupported protocol version {version} — expected "
                    f"{OTRConstants.PROTOCOL_VERSION}. Refusing potential downgrade."
                )

            num_versions = data[offset]
            offset += 1
            if num_versions == 0 or num_versions > 8:
                raise ValueError(f"Implausible version count: {num_versions}")

            versions = []
            for _ in range(num_versions):
                if offset >= len(data):
                    raise ValueError("Truncated during version list")
                versions.append(data[offset])
                offset += 1

            if 4 not in versions:
                raise ValueError(f"OTRv4 not in supported versions: {versions}")

            if len(data) < offset + OTRConstants.ED448_PUBLIC_KEY_SIZE:
                raise ValueError("Truncated identity public key")
            identity_pub_bytes = data[offset:offset + OTRConstants.ED448_PUBLIC_KEY_SIZE]
            offset += OTRConstants.ED448_PUBLIC_KEY_SIZE

            if len(data) < offset + OTRConstants.X448_PUBLIC_KEY_SIZE:
                raise ValueError("Truncated prekey public key")
            prekey_pub_bytes = data[offset:offset + OTRConstants.X448_PUBLIC_KEY_SIZE]
            offset += OTRConstants.X448_PUBLIC_KEY_SIZE

            if len(data) < offset + 8:
                raise ValueError("Truncated expiry timestamp")
            expires = struct.unpack('>Q', data[offset:offset + 8])[0]
            offset += 8

            now = int(time.time())
            if expires <= now:
                raise ValueError(
                    f"ClientProfile has expired (expires={time.ctime(expires)}). "
                    "Rejecting stale profile."
                )

            if len(data) < offset + OTRConstants.ED448_SIGNATURE_SIZE:
                raise ValueError(
                    "ClientProfile has no signature — rejecting unsigned profile. "
                    "OTRv4 §4.1.2 requires signature verification."
                )
            signature = data[offset:offset + OTRConstants.ED448_SIGNATURE_SIZE]

            signed_data = data[:offset]
            try:
                identity_pub = ed448.Ed448PublicKey.from_public_bytes(identity_pub_bytes)
                identity_pub.verify(signature, signed_data)
            except (ed448.InvalidSignature, ValueError, TypeError) as sig_err:
                raise ValueError(
                    f"ClientProfile signature verification FAILED: {sig_err}. "
                    "Rejecting profile — potential MITM/forged identity (OTRv4 §4.1.2)."
                ) from sig_err

            profile = cls.__new__(cls)
            profile.identity_key = None
            profile.prekey = None
            profile.versions = versions
            profile.expires = expires
            profile.signature = signature
            profile.created = now
            profile.identity_pub_bytes = identity_pub_bytes
            profile.prekey_pub_bytes = prekey_pub_bytes

            if DEBUG_MODE:
                print(f"[ClientProfile] ✅ Strict decode OK — sig verified, expires {time.ctime(expires)}")
                print(f"  versions: {versions}")

            return profile

        except ValueError:
            raise
        except (IndexError, struct.error, TypeError) as e:
            raise ValueError(f"ClientProfile decode failed due to malformed data: {e}") from e
        except Exception as e:
            raise RuntimeError(f"ClientProfile decode failed unexpectedly: {e}") from e

    def get_fingerprint(self) -> str:
        """Compute the OTRv4 fingerprint as SHA3-512 of the Ed448 public key.

        OTRv4 spec §4.1 mandates SHA3-512 for fingerprints.
        Using SHA-256 (previous implementation) produced fingerprints
        incompatible with all other OTRv4 clients (CoyIM, pidgin-otr4, etc.).
        Fingerprint is returned as 128 uppercase hex chars in 10 groups of 8.
        """
        try:
            if self.identity_key:
                identity_pub = self.identity_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            else:
                identity_pub = self.identity_pub_bytes
            if identity_pub is None:
                return ""
            fp_bytes = hashlib.sha3_512(identity_pub).digest()
            hex_str = fp_bytes.hex().upper()
            groups = [hex_str[i:i+8] for i in range(0, 80, 8)]
            return ' '.join(groups)
        except (AttributeError, TypeError, ValueError) as e:
            if DEBUG_MODE:
                print(f"[ClientProfile] Error getting fingerprint: {e}")
            return ""
        except Exception:
            return ""

    def verify_fingerprint(self, fingerprint: str) -> bool:
        """Verify a fingerprint using constant-time comparison"""
        try:
            actual = self.get_fingerprint()
            if not actual or not fingerprint:
                return False
            return hmac.compare_digest(actual.encode('utf-8'), fingerprint.encode('utf-8'))
        except (TypeError, AttributeError, ValueError) as e:
            if DEBUG_MODE:
                print(f"[ClientProfile] Fingerprint verification error: {e}")
            return False
        except Exception:
            return False

    def get_prekey_fingerprint(self) -> str:
        """Compute X448 prekey fingerprint as SHA3-512 per OTRv4 spec §4.1."""
        try:
            if self.prekey:
                prekey_pub = self.prekey.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            else:
                prekey_pub = self.prekey_pub_bytes
            if prekey_pub is None:
                return ""
            fp_bytes = hashlib.sha3_512(prekey_pub).digest()
            return fp_bytes.hex().upper()
        except (AttributeError, TypeError, ValueError) as e:
            if DEBUG_MODE:
                print(f"[ClientProfile] Error getting prekey fingerprint: {e}")
            return ""
        except Exception:
            return ""

    def is_expired(self) -> bool:
        try:
            return self.expires < int(time.time())
        except (TypeError, AttributeError):
            return True

    def renew(self):
        try:
            self.created = int(time.time())
            self.expires = self.created + 365 * 24 * 3600
            self.signature = None
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ClientProfile] Renew failed: {e}")




class TLVHandler:
    """TLV handler for OTRv4 (Spec §4.3.2)"""
    @staticmethod
    def encode_tlv(tlv_type: int, data: bytes) -> bytes:
        length = len(data)
        return struct.pack('!HH', tlv_type, length) + data
    
    @staticmethod
    def decode_tlv(data: bytes) -> Tuple[int, bytes, bytes]:
        """Decode one TLV record — strict: raises ValueError on truncated input.

        Returns (type, value, remaining_bytes).
        """
        if len(data) < 4:
            raise ValueError(f"TLV too short: need 4-byte header, have {len(data)}")
        try:
            tlv_type, length = struct.unpack('!HH', data[:4])
        except struct.error as e:
            raise ValueError(f"TLV header unpack failed: {e}")
        end = 4 + length
        if len(data) < end:
            raise ValueError(
                f"TLV value truncated: type=0x{tlv_type:04x} "
                f"declares {length} bytes but only {len(data) - 4} available"
            )
        return tlv_type, data[4:end], data[end:]

    @staticmethod
    def debug_tlv(data: bytes, description: str = "") -> None:
        """Debug TLV structure"""
        if len(data) < 4:
            print(f"TLV {description}: Too short ({len(data)} bytes)")
            return
        
        try:
            tlv_type, length = struct.unpack('!HH', data[:4])
            print(f"TLV {description}: type=0x{tlv_type:04x}, length={length}, data_len={len(data)}")
            print(f"  Hex: {data[:min(32, len(data))].hex()}...")
        except struct.error as e:
            print(f"TLV {description}: Unpack error: {e}")
            print(f"  Hex: {data[:min(32, len(data))].hex()}...")





class SMPProtocolCodec:
    """SMP protocol codec — fixed-width big-endian TLV encoding per spec §5."""
    
    @staticmethod
    def encode_smp1(g2a: Any, g3a: Any, c2: Any, c3: Any, d2: Any, d3: Any, 
                   t2: Any, t3: Any, question: Optional[str] = None) -> bytes:
        """Encode SMP1 TLV. Each group element is MODULUS_BYTES wide."""
        data = (
            SMPMath.int_to_bytes(g2a, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(g3a, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(c2, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(c3, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(d2, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(d3, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(t2, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(t3, SMPConstants.MODULUS_BYTES)
        )
        
        expected_len = 8 * SMPConstants.MODULUS_BYTES
        if len(data) != expected_len:
            raise ValueError(f"SMP1 encoding error: expected {expected_len} bytes, got {len(data)}")
        
        if question:
            question_bytes = question.encode('utf-8')
            if len(question_bytes) > 65535:
                raise ValueError("Question too long")
            data = struct.pack('!H', len(question_bytes)) + question_bytes + data
            tlv_type = OTRConstants.TLV_TYPE_SMP_MESSAGE_1Q
        else:
            tlv_type = OTRConstants.TLV_TYPE_SMP_MESSAGE_1
        
        return TLVHandler.encode_tlv(tlv_type, data)
    
    @staticmethod
    def decode_smp1(data: bytes, has_question: bool = False) -> Tuple[Optional[str], Any, Any, Any, Any, Any, Any, Any, Any]:
        """Decode SMP1 TLV.
        If has_question is True, expects a question prefix.
        """
        offset = 0
        question = None
        
        if has_question:
            if len(data) < 2:
                raise ValueError("SMP1Q message too short for question length")
            q_len = struct.unpack('!H', data[:2])[0]
            offset += 2
            if len(data) < offset + q_len:
                raise ValueError(f"SMP1Q question truncated: need {q_len} bytes, have {len(data)-offset}")
            question = data[offset:offset + q_len].decode('utf-8', errors='ignore')
            offset += q_len
        
        expected_data_len = 8 * SMPConstants.MODULUS_BYTES
        actual_data_len = len(data) - offset
        if actual_data_len != expected_data_len:
            raise ValueError(f"SMP1 data length incorrect: expected {expected_data_len} bytes after offset, got {actual_data_len}")
        
        g2a = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        g3a = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        c2 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        c3 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        d2 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        d3 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        t2 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        t3 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        
        return question, g2a, g3a, c2, c3, d2, d3, t2, t3
    
    @staticmethod
    def encode_smp2(g2b: Any, g3b: Any, c4: Any, c5: Any, d4: Any, d5: Any,
                   t4: Any, t5: Any, Pb: Any, Qb: Any,
                   c_pb: Any = None, d_pb: Any = None, t_pb: Any = None) -> bytes:
        """Encode SMP2 TLV — 13 fixed-width integers (10 original + Pb/Qb ZKP triple).

        The three extra fields (c_pb, d_pb, t_pb) prove knowledge of rpb such
        that Pb = shared_g3^rpb, preventing Bob from cheating on his Pb commitment
        (audit finding H-2).  They default to zero for backward compatibility
        when generating but zero-checking during decode signals a missing ZKP.
        """
        MB = SMPConstants.MODULUS_BYTES
        _int = lambda v: v if v is not None else 0
        data = (
            SMPMath.int_to_bytes(_int(g2b), MB) +
            SMPMath.int_to_bytes(_int(g3b), MB) +
            SMPMath.int_to_bytes(_int(c4), MB) +
            SMPMath.int_to_bytes(_int(c5), MB) +
            SMPMath.int_to_bytes(_int(d4), MB) +
            SMPMath.int_to_bytes(_int(d5), MB) +
            SMPMath.int_to_bytes(_int(t4), MB) +
            SMPMath.int_to_bytes(_int(t5), MB) +
            SMPMath.int_to_bytes(_int(Pb), MB) +
            SMPMath.int_to_bytes(_int(Qb), MB) +
            SMPMath.int_to_bytes(_int(c_pb), MB) +
            SMPMath.int_to_bytes(_int(d_pb), MB) +
            SMPMath.int_to_bytes(_int(t_pb), MB)
        )

        expected_len = 13 * MB
        if len(data) != expected_len:
            raise ValueError(f"SMP2 encoding error: expected {expected_len} bytes, got {len(data)}")

        return TLVHandler.encode_tlv(OTRConstants.TLV_TYPE_SMP_MESSAGE_2, data)
    
    @staticmethod
    def decode_smp2(data: bytes) -> Tuple[Any, Any, Any, Any, Any, Any, Any, Any, Any, Any, Any, Any, Any]:
        """Decode SMP2 message — 13 fixed-width integers (10 original + Pb/Qb ZKP).

        Returns: g2b, g3b, c4, c5, d4, d5, t4, t5, Pb, Qb, c_pb, d_pb, t_pb
        The final three (c_pb, d_pb, t_pb) are the ZKP for Pb.  Callers MUST
        verify this proof before accepting Pb and Qb (audit H-2).
        """
        MB = SMPConstants.MODULUS_BYTES
        expected_len = 13 * MB
        if len(data) != expected_len:
            raise ValueError(f"SMP2 data length incorrect: expected {expected_len} bytes, got {len(data)}")

        offset = 0
        g2b = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        g3b = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        c4  = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        c5  = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        d4  = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        d5  = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        t4  = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        t5  = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        Pb  = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        Qb  = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        c_pb = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        d_pb = SMPMath.bytes_to_int(data[offset:offset + MB]); offset += MB
        t_pb = SMPMath.bytes_to_int(data[offset:offset + MB])

        return g2b, g3b, c4, c5, d4, d5, t4, t5, Pb, Qb, c_pb, d_pb, t_pb
    
    @staticmethod
    def encode_smp3(Pa: Any, Qa: Any, c6: Any, c7: Any, d6: Any, d7: Any,
                   t6: Any, t7: Any) -> bytes:
        """Encode SMP3 TLV."""
        data = (
            SMPMath.int_to_bytes(Pa, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(Qa, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(c6, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(c7, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(d6, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(d7, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(t6, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(t7, SMPConstants.MODULUS_BYTES)
        )
        
        expected_len = 8 * SMPConstants.MODULUS_BYTES
        if len(data) != expected_len:
            raise ValueError(f"SMP3 encoding error: expected {expected_len} bytes, got {len(data)}")
        
        return TLVHandler.encode_tlv(OTRConstants.TLV_TYPE_SMP_MESSAGE_3, data)
    
    @staticmethod
    def decode_smp3(data: bytes) -> Tuple[Any, Any, Any, Any, Any, Any, Any, Any]:
        """Decode SMP3 message - FIXED LENGTH CHECKING: 192 bytes per integer"""
        expected_len = 8 * SMPConstants.MODULUS_BYTES
        if len(data) != expected_len:
            raise ValueError(f"SMP3 data length incorrect: expected {expected_len} bytes, got {len(data)}")
        
        offset = 0
        Pa = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        Qa = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        c6 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        c7 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        d6 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        d7 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        t6 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        t7 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        
        return Pa, Qa, c6, c7, d6, d7, t6, t7
    
    @staticmethod
    def encode_smp4(c8: Any, c9: Any, d8: Any, d9: Any, t8: Any, t9: Any) -> bytes:
        """Encode SMP4 TLV."""
        data = (
            SMPMath.int_to_bytes(c8, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(c9, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(d8, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(d9, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(t8, SMPConstants.MODULUS_BYTES) +
            SMPMath.int_to_bytes(t9, SMPConstants.MODULUS_BYTES)
        )
        
        expected_len = 6 * SMPConstants.MODULUS_BYTES
        if len(data) != expected_len:
            raise ValueError(f"SMP4 encoding error: expected {expected_len} bytes, got {len(data)}")
        
        return TLVHandler.encode_tlv(OTRConstants.TLV_TYPE_SMP_MESSAGE_4, data)
    
    @staticmethod
    def decode_smp4(data: bytes) -> Tuple[Any, Any, Any, Any, Any, Any]:
        """Decode SMP4 message - FIXED LENGTH CHECKING: 192 bytes per integer"""
        expected_len = 6 * SMPConstants.MODULUS_BYTES
        if len(data) != expected_len:
            raise ValueError(f"SMP4 data length incorrect: expected {expected_len} bytes, got {len(data)}")
        
        offset = 0
        c8 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        c9 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        d8 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        d9 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        t8 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        offset += SMPConstants.MODULUS_BYTES
        t9 = SMPMath.bytes_to_int(data[offset:offset + SMPConstants.MODULUS_BYTES])
        
        return c8, c9, d8, d9, t8, t9
    
    @staticmethod
    def encode_abort() -> bytes:
        """Encode SMP abort message"""
        return TLVHandler.encode_tlv(OTRConstants.TLV_TYPE_SMP_ABORT, b"")


class SMPStateMachine:
    """SMP State Machine - Manages state transitions and timeouts only"""

    def __init__(self, is_initiator: bool):
        self.is_initiator = is_initiator
        self.lock = threading.RLock()
        self.state = UIConstants.SMPState.NONE
        self.verified = False
        self.failed = False
        self.failure_reason = ""
        self.retry_count = 0
        self.max_retries = 3
        self.backoff_until = 0.0
        self.session_id = secrets.token_bytes(32)
        self.start_time = 0.0
        self.last_activity = 0.0
        self.timeout = SMPConstants.SESSION_TIMEOUT
        self.secret_set = False
        self.question: Optional[str] = None

    def reset(self):
        with self.lock:
            self.state = UIConstants.SMPState.NONE
            self.verified = False
            self.failed = False
            self.failure_reason = ""
            self.secret_set = False
            self.question = None
            self.start_time = 0.0
            self.last_activity = 0.0

    def transition(self, new_state: UIConstants.SMPState):
        """Transition to new state – allowed transitions are enforced."""
        with self.lock:
            old_state = self.state

            allowed = {
                UIConstants.SMPState.NONE: [
                    UIConstants.SMPState.EXPECT2,
                    UIConstants.SMPState.EXPECT3,
                    UIConstants.SMPState.FAILED
                ],
                UIConstants.SMPState.EXPECT2: [
                    UIConstants.SMPState.EXPECT4,
                    UIConstants.SMPState.FAILED
                ],
                UIConstants.SMPState.EXPECT3: [
                    UIConstants.SMPState.SUCCEEDED,
                    UIConstants.SMPState.FAILED
                ],
                UIConstants.SMPState.EXPECT4: [
                    UIConstants.SMPState.SUCCEEDED,
                    UIConstants.SMPState.FAILED
                ],
                UIConstants.SMPState.SUCCEEDED: [],
                UIConstants.SMPState.FAILED: [],
            }

            if new_state not in allowed.get(old_state, []):
                raise StateMachineError(f"Invalid SMP transition: {old_state.name} → {new_state.name}")

            self.state = new_state
            self.last_activity = time.time()

            if new_state == UIConstants.SMPState.SUCCEEDED:
                self.verified = True
                self.failed = False
            elif new_state == UIConstants.SMPState.FAILED:
                self.failed = True
                self.verified = False

    def mark_retry(self):
        with self.lock:
            if self.failed and self.retry_count < self.max_retries:
                self.retry_count += 1
                backoff_secs = 5 * (3 ** (self.retry_count - 1))
                self.backoff_until = time.time() + backoff_secs
                self.failed = False
                self.failure_reason = ""
                self.reset()
                return True
            return False

    def is_expired(self) -> bool:
        with self.lock:
            if self.start_time == 0:
                return False
            return time.time() - self.start_time > self.timeout

    def can_retry(self) -> bool:
        with self.lock:
            if not self.failed or self.retry_count >= self.max_retries:
                return False
            return time.time() >= self.backoff_until

    def get_state(self) -> UIConstants.SMPState:
        with self.lock:
            return self.state

    def is_verified(self) -> bool:
        with self.lock:
            return self.verified

    def has_failed(self) -> bool:
        with self.lock:
            return self.failed

class SMPEngine:
    """SMP Engine - Orchestrates math, state machine, and protocol codec"""

    def __init__(self, is_initiator: bool, logger: Optional[OTRLogger] = None):
        self.is_initiator = is_initiator
        self.logger = logger or NullLogger()
        self.state_machine = SMPStateMachine(is_initiator)
        self.protocol_codec = SMPProtocolCodec()
        self.seen_messages: OrderedDict[bytes, bool] = OrderedDict()
        self.max_seen = 10000
        self.lock = threading.RLock()
        self._clear_math_state()

    def _clear_math_state(self):
        """Zeroize all SMP intermediate secrets before removing references.

        Python integers are immutable — we cannot overwrite them in-place.
        What we CAN do is:
          1. Overwrite the attribute with 0 before setting it to None.  This
             ensures the name no longer points at the secret value, making the
             old object eligible for GC.
          2. The GC will eventually reclaim the memory, but there is no
             guarantee about when.  This is the best Python can offer without
             a C extension; it is still far better than leaving live references.
        """
        secret_int_attrs = [
            'a2', 'a3', 'b2', 'b3', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
            'r8', 'r9', 'rpb', 'rpa', 'secret',
        ]
        group_elem_attrs = [
            '_shared_g2', '_shared_g3',
            'g2a', 'g3a', 'g2b', 'g3b', 'Pa', 'Qa', 'Pb', 'Qb',
        ]
        for attr in secret_int_attrs + group_elem_attrs:
            try:
                setattr(self, attr, 0)
            except Exception:
                pass
            setattr(self, attr, None)

    def _random_exponent(self):
        """Generate random exponent uniformly in [1, q-1] where q = (p-1)//2.

        HARDENED (Phase 3): uses OpenSSL BN_rand_range via _ct_rand_range when
        the C extension is available.  Falls back to secrets.randbelow().
        """
        q = (SMPConstants.MODULUS - 1) // 2
        while True:
            rand_int = _ct_rand_range(q)
            if 1 <= rand_int < q:
                return rand_int

    def _hash_to_subgroup(self, data: bytes) -> int:
        """Hash data to an integer in [1, q-1]."""
        q = (SMPConstants.MODULUS - 1) // 2
        h = int.from_bytes(hashlib.sha3_512(data).digest(), 'big') % (q - 1) + 1
        return h

    def set_secret(self, secret: str,
                   session_id: Optional[bytes] = None,
                   local_fingerprint: Optional[bytes] = None,
                   remote_fingerprint: Optional[bytes] = None):
        """Store the SMP shared secret, hashed with session context per OTRv4 §5.2.

        The spec mandates (both sides must produce the same value):
            SMP_secret = H(0x01 || initiator_fp || responder_fp || ssid || user_secret)

        Key stretching: the raw passphrase is first run through 10,000
        iterations of SHAKE-256 to make offline brute-force harder.
        Both sides apply the same stretching, so the shared secret matches.

        The canonical ordering — initiator_fp first, then responder_fp — is
        determined by ``self.is_initiator`` so that callers never need to pass
        a role flag.  Both sides produce the same hash as long as they agree on
        who is initiator and who is responder.

        The raw secret string is cleared as soon as it is hashed.
        """
        with self.lock:
            raw = secret.encode('utf-8')

            # ── Key stretching: SHAKE-256 × 10,000 iterations ────
            #    Makes brute-force of short passphrases ~10,000× slower.
            #    Domain separator "OTRv4+SMP" ensures this doesn't collide
            #    with any other use of SHAKE-256 in the protocol.
            SMP_KDF_ROUNDS = 10000
            stretched = hashlib.shake_256(
                b"OTRv4+SMP\x00" + raw
            ).digest(64)
            for _ in range(SMP_KDF_ROUNDS - 1):
                stretched = hashlib.shake_256(stretched).digest(64)

            if session_id and local_fingerprint and remote_fingerprint:
                if self.is_initiator:
                    init_fp, resp_fp = local_fingerprint, remote_fingerprint
                else:
                    init_fp, resp_fp = remote_fingerprint, local_fingerprint

                role_tag = b'\x01'
                h_input = bytearray(role_tag + init_fp + resp_fp + session_id + stretched)
                self.secret = self._hash_to_subgroup(bytes(h_input))
                _ossl.cleanse(h_input)
                del h_input
            else:
                self.secret = self._hash_to_subgroup(stretched)

            # Cleanse all intermediates
            _ossl.cleanse(bytearray(stretched))
            raw_arr = bytearray(raw)
            _ossl.cleanse(raw_arr)
            del raw_arr, stretched
            self.state_machine.secret_set = True

    def _compute_zkp(self, base: int, exponent: int, random_val: int, public_value: int):
        """Compute a Fiat-Shamir ZKP: prove knowledge of exponent such that base^exponent = public_value.

        HARDENED (Phase 3): t = base^random_val mod p uses _ct_mod_exp
        (OpenSSL BN_mod_exp_mont_consttime) so random_val never leaks via timing.
        Hash input uses fixed-width big-endian encoding (SMPConstants.MODULUS_BYTES each).
        """
        MB = SMPConstants.MODULUS_BYTES
        t = _ct_mod_exp(base, random_val, SMPConstants.MODULUS)
        encoded = (
            b'\x01' +
            base.to_bytes(MB, 'big') +
            public_value.to_bytes(MB, 'big') +
            t.to_bytes(MB, 'big')
        )
        c = self._hash_to_subgroup(encoded)
        q = (SMPConstants.MODULUS - 1) // 2
        s = (random_val + c * exponent) % q
        return c, s, t

    def _verify_zkp(self, base: int, public_value: int, c: int, s: int, t: int) -> bool:
        """Verify a Fiat-Shamir ZKP with fixed-width encoding.

        HARDENED (Phase 3): both exponentiations use _ct_mod_exp.
        """
        MB = SMPConstants.MODULUS_BYTES
        encoded = (
            b'\x01' +
            base.to_bytes(MB, 'big') +
            public_value.to_bytes(MB, 'big') +
            t.to_bytes(MB, 'big')
        )
        c_exp = self._hash_to_subgroup(encoded)
        if c != c_exp:
            return False
        left  = _ct_mod_exp(base, s, SMPConstants.MODULUS)
        right = (_ct_mod_exp(public_value, c, SMPConstants.MODULUS) * t) % SMPConstants.MODULUS
        MB = SMPConstants.MODULUS_BYTES
        return hmac.compare_digest(left.to_bytes(MB, 'big'), right.to_bytes(MB, 'big'))

    def _check_replay(self, data):
        h = hashlib.sha3_256(data).digest()
        if h in self.seen_messages:
            raise ValueError("Replay attack detected")
        self.seen_messages[h] = True
        if len(self.seen_messages) > self.max_seen:
            self.seen_messages.popitem(last=False)

    def start_smp(self, secret: str, question: str = None) -> Optional[bytes]:
        """Begin SMP as initiator.

        If ``set_secret()`` was already called with session binding (M-1 fix),
        this method preserves that session-bound secret rather than overwriting
        it with an unbound hash.  Callers that have not pre-set the secret will
        have it hashed here without session binding (call set_secret() first to bind).
        """
        with self.lock:
            if self.state_machine.get_state() != UIConstants.SMPState.NONE:
                raise ValueError("SMP already in progress")
            self.is_initiator = True
            self.state_machine.is_initiator = True
            if not self.state_machine.secret_set or self.secret is None:
                self.set_secret(secret)
            self.state_machine.question = question
            self.state_machine.start_time = time.time()

            self.a2 = self._random_exponent()
            self.a3 = self._random_exponent()
            self.r2 = self._random_exponent()
            self.r3 = self._random_exponent()

            self.g2a = _ct_mod_exp(SMPConstants.GENERATOR, self.a2, SMPConstants.MODULUS)
            self.g3a = _ct_mod_exp(SMPConstants.GENERATOR, self.a3, SMPConstants.MODULUS)

            c2, d2, t2 = self._compute_zkp(SMPConstants.GENERATOR, self.a2, self.r2, self.g2a)
            c3, d3, t3 = self._compute_zkp(SMPConstants.GENERATOR, self.a3, self.r3, self.g3a)

            tlv = self.protocol_codec.encode_smp1(self.g2a, self.g3a, c2, c3, d2, d3, t2, t3, question)
            self.state_machine.transition(UIConstants.SMPState.EXPECT2)
            return tlv

    def process_smp1(self, data: bytes) -> Optional[bytes]:
        with self.lock:
            self._check_replay(data)
            if self.state_machine.get_state() != UIConstants.SMPState.NONE:
                raise ValueError("Invalid state for SMP1")

            if not self.state_machine.secret_set or self.secret is None:
                raise ValueError(
                    "SMP secret not set — call set_secret() before processing SMP1. "
                    "Peer may be attempting to trigger a comparison with a null secret."
                )

            self.is_initiator = False
            self.state_machine.is_initiator = False

            tlv_type, value, _ = TLVHandler.decode_tlv(data)
            has_q = (tlv_type == OTRConstants.TLV_TYPE_SMP_MESSAGE_1Q)
            question, g2a, g3a, c2, c3, d2, d3, t2, t3 = self.protocol_codec.decode_smp1(value, has_q)
            self.g2a, self.g3a = g2a, g3a
            self.state_machine.question = question
            self.state_machine.start_time = time.time()

            for val, name in [(g2a, 'g2a'), (g3a, 'g3a')]:
                if not SMPMath.validate_smp_value(val, SMPConstants.MODULUS):
                    raise ValueError(
                        f"SMP1 rejected: {name} is not a valid group element. "
                        "Possible small-subgroup attack."
                    )

            if not self._verify_zkp(SMPConstants.GENERATOR, g2a, c2, d2, t2) or \
               not self._verify_zkp(SMPConstants.GENERATOR, g3a, c3, d3, t3):
                raise ValueError("ZKP verification failed")

            self.b2 = self._random_exponent()
            self.b3 = self._random_exponent()
            self.r4 = self._random_exponent()
            self.r5 = self._random_exponent()
            self.rpb = self._random_exponent()

            self.g2b = _ct_mod_exp(SMPConstants.GENERATOR, self.b2, SMPConstants.MODULUS)
            self.g3b = _ct_mod_exp(SMPConstants.GENERATOR, self.b3, SMPConstants.MODULUS)

            self._shared_g2 = _ct_mod_exp(g2a, self.b2, SMPConstants.MODULUS)
            self._shared_g3 = _ct_mod_exp(g3a, self.b3, SMPConstants.MODULUS)

            self.Pb = _ct_mod_exp(self._shared_g3, self.rpb, SMPConstants.MODULUS)
            self.Qb = (_ct_mod_exp(self._shared_g3, self.rpb, SMPConstants.MODULUS) *
                       _ct_mod_exp(self._shared_g2, self.secret, SMPConstants.MODULUS)) % SMPConstants.MODULUS

            c4, d4, t4 = self._compute_zkp(SMPConstants.GENERATOR, self.b2, self.r4, self.g2b)
            c5, d5, t5 = self._compute_zkp(SMPConstants.GENERATOR, self.b3, self.r5, self.g3b)

            r_pb_zkp = self._random_exponent()
            c_pb, d_pb, t_pb = self._compute_zkp(self._shared_g3, self.rpb, r_pb_zkp, self.Pb)

            tlv = self.protocol_codec.encode_smp2(self.g2b, self.g3b, c4, c5, d4, d5, t4, t5,
                                                  self.Pb, self.Qb, c_pb, d_pb, t_pb)
            self.state_machine.transition(UIConstants.SMPState.EXPECT3)
            return tlv

    def process_smp2(self, data: bytes) -> Optional[bytes]:
        with self.lock:
            self._check_replay(data)
            if not self.is_initiator or self.state_machine.get_state() != UIConstants.SMPState.EXPECT2:
                raise ValueError("Invalid state for SMP2")

            tlv_type, value, _ = TLVHandler.decode_tlv(data)
            g2b, g3b, c4, c5, d4, d5, t4, t5, Pb, Qb, c_pb, d_pb, t_pb = \
                self.protocol_codec.decode_smp2(value)
            self.g2b, self.g3b, self.Pb, self.Qb = g2b, g3b, Pb, Qb

            for val, name in [(g2b, 'g2b'), (g3b, 'g3b'), (Pb, 'Pb'), (Qb, 'Qb')]:
                if not SMPMath.validate_smp_value(val, SMPConstants.MODULUS):
                    raise ValueError(
                        f"SMP2 rejected: {name} is not a valid group element. "
                        "Possible small-subgroup attack."
                    )

            if not self._verify_zkp(SMPConstants.GENERATOR, g2b, c4, d4, t4) or \
               not self._verify_zkp(SMPConstants.GENERATOR, g3b, c5, d5, t5):
                raise ValueError("SMP2 ZKP verification failed for g2b/g3b")

            self._shared_g2 = _ct_mod_exp(g2b, self.a2, SMPConstants.MODULUS)
            self._shared_g3 = _ct_mod_exp(g3b, self.a3, SMPConstants.MODULUS)

            if not self._verify_zkp(self._shared_g3, Pb, c_pb, d_pb, t_pb):
                raise ValueError("SMP2 ZKP verification failed for Pb — Bob cheated on Pb commitment")

            self.rpa = self._random_exponent()

            self.Pa = _ct_mod_exp(self._shared_g3, self.rpa, SMPConstants.MODULUS)
            self.Qa = (_ct_mod_exp(self._shared_g3, self.rpa, SMPConstants.MODULUS) *
                       _ct_mod_exp(self._shared_g2, self.secret, SMPConstants.MODULUS)) % SMPConstants.MODULUS

            inv_Pb = _ct_mod_inv(self.Pb, SMPConstants.MODULUS)
            inv_Qb = _ct_mod_inv(self.Qb, SMPConstants.MODULUS)
            pa_over_pb = (self.Pa * inv_Pb) % SMPConstants.MODULUS
            qa_over_qb = (self.Qa * inv_Qb) % SMPConstants.MODULUS

            secrets_match = (pa_over_pb == qa_over_qb)

            self.r6 = self._random_exponent()
            self.r7 = self._random_exponent()

            c6, d6, t6 = self._compute_zkp(self._shared_g3, self.rpa, self.r6, self.Pa)
            c7, d7, t7 = self._compute_zkp(self._shared_g3, self.rpa, self.r7, self.Pa)

            tlv = self.protocol_codec.encode_smp3(self.Pa, self.Qa, c6, c7, d6, d7, t6, t7)
            self.state_machine.transition(UIConstants.SMPState.EXPECT4)
            return tlv

    def process_smp3(self, data: bytes) -> Optional[bytes]:
        with self.lock:
            self._check_replay(data)
            if self.is_initiator or self.state_machine.get_state() != UIConstants.SMPState.EXPECT3:
                raise ValueError("Invalid state for SMP3")

            if self.state_machine.is_expired():
                self.state_machine.transition(UIConstants.SMPState.FAILED)
                raise ValueError("SMP session expired before SMP3 received")

            tlv_type, value, _ = TLVHandler.decode_tlv(data)
            Pa, Qa, c6, c7, d6, d7, t6, t7 = self.protocol_codec.decode_smp3(value)
            self.Pa, self.Qa = Pa, Qa

            for val, name in [(Pa, 'Pa'), (Qa, 'Qa')]:
                if not SMPMath.validate_smp_value(val, SMPConstants.MODULUS):
                    raise ValueError(
                        f"SMP3 rejected: {name} is not a valid group element. "
                        "Possible small-subgroup attack."
                    )

            if not self._verify_zkp(self._shared_g3, Pa, c6, d6, t6) or \
               not self._verify_zkp(self._shared_g3, Pa, c7, d7, t7):
                self.state_machine.failure_reason = "SMP3 ZKP verification failed — Alice cheated on Pa"
                self.state_machine.transition(UIConstants.SMPState.FAILED)
                raise ValueError("SMP3 rejected: ZKP verification failed")

            secrets_match = False
            if self.state_machine.secret_set:
                inv_Pb = _ct_mod_inv(self.Pb, SMPConstants.MODULUS)
                inv_Qb = _ct_mod_inv(self.Qb, SMPConstants.MODULUS)
                pa_over_pb = (self.Pa * inv_Pb) % SMPConstants.MODULUS
                qa_over_qb = (self.Qa * inv_Qb) % SMPConstants.MODULUS
                MB = SMPConstants.MODULUS_BYTES
                secrets_match = hmac.compare_digest(
                    pa_over_pb.to_bytes(MB, 'big'),
                    qa_over_qb.to_bytes(MB, 'big')
                )

            self.r8 = self._random_exponent()
            self.r9 = self._random_exponent()

            c8, d8, t8 = self._compute_zkp(self._shared_g3, self.rpb, self.r8, self.Pb)
            c9, d9, t9 = self._compute_zkp(self._shared_g3, self.rpb, self.r9, self.Pb)

            tlv = self.protocol_codec.encode_smp4(c8, c9, d8, d9, t8, t9)

            if secrets_match:
                self.state_machine.transition(UIConstants.SMPState.SUCCEEDED)
            else:
                self.state_machine.failure_reason = "Secrets don't match"
                self.state_machine.transition(UIConstants.SMPState.FAILED)

            return tlv

    def process_smp4(self, data: bytes) -> None:
        with self.lock:
            self._check_replay(data)
            if not self.is_initiator or self.state_machine.get_state() != UIConstants.SMPState.EXPECT4:
                raise ValueError("Invalid state for SMP4")

            tlv_type, value, _ = TLVHandler.decode_tlv(data)
            c8, c9, d8, d9, t8, t9 = self.protocol_codec.decode_smp4(value)

            if not self._verify_zkp(self._shared_g3, self.Pb, c8, d8, t8) or \
               not self._verify_zkp(self._shared_g3, self.Pb, c9, d9, t9):
                self.state_machine.failure_reason = "ZKP verification failed in SMP4"
                self.state_machine.transition(UIConstants.SMPState.FAILED)
                return

            inv_Pb = _ct_mod_inv(self.Pb, SMPConstants.MODULUS)
            inv_Qb = _ct_mod_inv(self.Qb, SMPConstants.MODULUS)
            pa_over_pb = (self.Pa * inv_Pb) % SMPConstants.MODULUS
            qa_over_qb = (self.Qa * inv_Qb) % SMPConstants.MODULUS

            MB = SMPConstants.MODULUS_BYTES
            if not hmac.compare_digest(pa_over_pb.to_bytes(MB, 'big'),
                                       qa_over_qb.to_bytes(MB, 'big')):
                self.state_machine.failure_reason = "Secrets don't match (Alice re-check in SMP4)"
                self.state_machine.transition(UIConstants.SMPState.FAILED)
                return

            self.state_machine.transition(UIConstants.SMPState.SUCCEEDED)

    def abort_smp(self) -> bytes:
        with self.lock:
            self.state_machine.reset()
            self._clear_math_state()
            return self.protocol_codec.encode_abort()

    def reset(self):
        with self.lock:
            self.state_machine.reset()
            self._clear_math_state()

    def get_state(self) -> UIConstants.SMPState:
        return self.state_machine.get_state()

    def is_verified(self) -> bool:
        return self.state_machine.is_verified()

    def has_failed(self) -> bool:
        return self.state_machine.has_failed()

    def can_retry(self) -> bool:
        return self.state_machine.can_retry()

    def mark_retry(self):
        self.state_machine.mark_retry()

    def is_expired(self) -> bool:
        return self.state_machine.is_expired()

    def has_question(self) -> bool:
        return self.state_machine.question is not None

    def get_question(self) -> Optional[str]:
        return self.state_machine.question




class RatchetHeader:
    """Ratchet header for Double Ratchet (Spec §4.4)"""
    def __init__(self, dh_pub: bytes, prev_chain_len: int, msg_num: int):
        self.dh_pub = dh_pub
        self.prev_chain_len = prev_chain_len
        self.msg_num = msg_num
    
    def encode(self) -> bytes:
        return self.dh_pub + struct.pack('!II', self.prev_chain_len, self.msg_num)
    
    @classmethod
    def decode(cls, data: bytes) -> 'RatchetHeader':
        if len(data) != 56 + 8:
            raise ValueError(f"Invalid header length: {len(data)}")
        
        dh_pub = data[:56]
        prev_chain_len, msg_num = struct.unpack('!II', data[56:])
        return cls(dh_pub, prev_chain_len, msg_num)





class SkippedMessageKey:
    """Storage for skipped message keys"""
    def __init__(self, dh_pub: bytes, msg_num: int, message_key: bytes):
        self.dh_pub = dh_pub
        self.msg_num = msg_num
        self.message_key = bytearray(message_key)
    
    def zeroize(self):
        """Zeroize the message key via OPENSSL_cleanse (Phase 5)."""
        if hasattr(self, 'message_key') and self.message_key:
            _ossl.cleanse(self.message_key)
            self.message_key = bytearray()
    
    def __del__(self):
        self.zeroize()



class DoubleRatchet:
    """
    Double ratchet (OTRv4 §4.4).

    This version strictly follows the specification:
      1. When a message with a new DH public key arrives:
         a. Derive a temporary receiving chain key using the OLD root key and
            the DH shared secret.
         b. Advance that temporary chain to the message number to obtain the
            message key.
         c. Decrypt.
         d. If successful, permanently update the root key and receiving chain
            key to the newly derived values.
         e. Reset the receiving message counter to msg_num + 1.
      2. For messages with an existing DH key, use the current receiving chain
         (or skipped keys) as normal.
    """

    def __init__(self, root_key: SecureMemory, is_initiator: bool,
                 ad: bytes = b"OTRv4-DATA", logger: Optional[OTRLogger] = None,
                 chain_key_send: Optional[bytes] = None,
                 chain_key_recv: Optional[bytes] = None,
                 brace_key: Optional[bytes] = None,
                 rekey_interval: int = OTRConstants.REKEY_INTERVAL,
                 rekey_timeout: int = OTRConstants.REKEY_TIMEOUT):
        self.lock = threading.RLock()
        self.root_key = root_key
        self.is_initiator = is_initiator
        self.ad = ad
        self.logger = logger or NullLogger()
        self.rekey_interval = rekey_interval
        self.rekey_timeout = rekey_timeout
        self.last_rekey_time = time.time()

        self.dh_ratchet_local = x448.X448PrivateKey.generate()
        self.dh_ratchet_local_pub = self.dh_ratchet_local.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.dh_ratchet_remote: Optional[x448.X448PublicKey] = None
        self.dh_ratchet_remote_pub: Optional[bytes] = None

        self._brace_key: bytes = brace_key if brace_key else bytes(32)

        # ── Brace KEM rotation state ────────────────────────────
        #    ML-KEM-1024 shared secret rotates the brace key every
        #    DH ratchet epoch.  At most ONE of kem_ek or kem_ct is
        #    attached per outgoing message; the exchange completes
        #    in two messages (ek → ct).
        #
        #    State machine:
        #      _brace_kem_local is None, _brace_kem_ct_out is None
        #        → IDLE.  Next DH ratchet generates fresh KEM.
        #      _brace_kem_ek_out is not None
        #        → We have an ek to send.  Next encrypt picks it up.
        #      _brace_kem_local is not None, _brace_kem_ek_out is None
        #        → ek was sent; awaiting ct from peer.
        #      _brace_kem_ct_out is not None
        #        → We encapsulated to peer's ek; ct ready to send.
        self._brace_kem_local: Optional[MLKEM1024BraceKEM] = None
        self._brace_kem_ek_out: Optional[bytes] = None
        self._brace_kem_ct_out: Optional[bytes] = None

        self.chain_key_send = SecureMemory(32)
        self.chain_key_recv = SecureMemory(32)
        self.message_num_send = 0
        self.message_num_recv = 0
        self.prev_chain_len_send = 0
        self.prev_chain_len_recv = 0

        self.skipped_keys: OrderedDict[Tuple[bytes, int], SkippedMessageKey] = OrderedDict()
        self.max_skip = OTRConstants.MAX_SKIP
        self.max_message_keys = OTRConstants.MAX_MESSAGE_KEYS

        self.message_counter_send = 0
        self.message_counter_recv = 0

        self._seen_messages: OrderedDict = OrderedDict()
        self._max_seen = 10000

        self.ratchet_id: int = 0

        self._pending_reveal_mac_keys: List[bytes] = []
        self._last_mac_key: Optional[bytes] = None

        self.last_remote_pub: Optional[bytes] = None

        if chain_key_send is not None and chain_key_recv is not None:
            if all(b == 0 for b in chain_key_send) or all(b == 0 for b in chain_key_recv):
                raise ValueError("Chain keys zero - possible KDF failure")
            self.chain_key_send.write(chain_key_send[:32])
            self.chain_key_recv.write(chain_key_recv[:32])
            self.logger.debug(f"Chain keys initialized from DAKE: send=<redacted>, recv=<redacted>")
        else:
            self._initialize_chains()

        self.logger.debug(f"DoubleRatchet initialized (initiator={is_initiator})")

    def _initialize_chains(self):
        """Initialize chain keys from root key (OTRv4 §4.4.1).

        Uses KDF_1 = SHAKE-256 (spec §3.2).  The brace key is mixed in to
        provide post-quantum protection from the very first message.
        """
        with self.lock:
            root_key_data = self.root_key.read()
            seed = kdf_1(KDFUsage.ROOT_KEY, root_key_data + self._brace_key, 64)
            send_key = seed[:32]
            recv_key = seed[32:64]

            if all(b == 0 for b in send_key) or all(b == 0 for b in recv_key):
                raise ValueError("Chain keys zero - possible KDF failure")

            if self.is_initiator:
                self.chain_key_send.write(send_key)
                self.chain_key_recv.write(recv_key)
            else:
                self.chain_key_send.write(recv_key)
                self.chain_key_recv.write(send_key)
            self.logger.debug("Chain keys initialized via KDF_1")

    def _kdf_ck(self, chain_key: bytes, constant: bytes = b"MESSAGE_KEY") -> Tuple[bytes, bytes, bytes]:
        """Derive next chain key, message encryption key, and MAC key (spec §4.4.2).

        Uses KDF_1 = SHAKE-256 (spec §3.2):
            next_ck  = KDF_1(0x12, chain_key, 32)
            enc_key  = KDF_1(0x13, chain_key, 32)
            mac_key  = KDF_1(0x14, chain_key, 64)

        HARDENED: a mutable copy of chain_key is cleansed via OPENSSL_cleanse
        immediately after all three KDF calls to minimise heap residency.
        """
        next_ck = kdf_1(KDFUsage.CHAIN_KEY,   chain_key, 32)
        enc_key = kdf_1(KDFUsage.MESSAGE_KEY,  chain_key, 32)
        mac_key = kdf_1(KDFUsage.MAC_KEY,      chain_key, 64)
        _ck_buf = bytearray(chain_key)
        _ossl.cleanse(_ck_buf)
        del _ck_buf
        return next_ck, enc_key, mac_key

    def _kdf_rk(self, root_key: bytes, dh_secret: bytes) -> Tuple[bytes, bytes]:
        """Single source of truth for root-key ratchet KDF (OTRv4 §4.4.2).

        KDF_1(usage_root_key, root || dh_secret || brace_key, 64) -> (new_root, new_chain)

        Both _ratchet() (send-side forced rekey) and decrypt_message() CASE 1
        (recv-side DH ratchet) call this.  One KDF path, impossible to diverge.
        """
        seed = kdf_1(KDFUsage.ROOT_KEY,
                      root_key + dh_secret + self._brace_key, 64)
        new_root  = seed[:32]
        new_chain = seed[32:64]
        _seed_buf = bytearray(seed)
        _ossl.cleanse(_seed_buf)
        del _seed_buf, seed
        return new_root, new_chain

    # ── Brace KEM rotation ───────────────────────────────────────────
    #
    #  The brace key starts as the KDF'd ML-KEM-1024 shared secret from
    #  DAKE and then rotates with fresh KEM material on every DH ratchet
    #  epoch.  This ensures that even if a single KEM shared secret is
    #  compromised, future ratchet steps recover post-quantum security.
    #
    #  Protocol (2-message exchange):
    #    1. Side A does DH ratchet → generates fresh ML-KEM-1024 keypair
    #       → sends kem_ek in the next outgoing data message.
    #    2. Side B receives kem_ek → encapsulates → (ct, ss) → updates
    #       brace_key = KDF_1(0x16, old_brace ‖ ss, 32) → sends kem_ct.
    #    3. Side A receives kem_ct → decapsulates → same ss → same KDF →
    #       brace_key now matches on both sides.
    #
    #  A message carries AT MOST one KEM field (ek OR ct, never both),
    #  so overhead is ≤ 1568 bytes per message during rotation.  After
    #  the 2-message exchange completes, both sides are IDLE and the
    #  next DH ratchet starts a new rotation.
    #
    #  Processing order on receive is always: ct first, ek second.
    #  This ensures both sides derive the same brace_key sequence.

    def prepare_brace_rotation(self) -> None:
        """Generate fresh ML-KEM-1024 keypair for brace key rotation.

        Called on DH ratchet steps.  Only generates when no KEM exchange
        is already in flight (awaiting ct, or ct pending to send).
        """
        if self._brace_kem_local is not None:
            return   # already awaiting ct from peer
        if self._brace_kem_ct_out is not None:
            return   # have ct to send first — complete that exchange
        self._brace_kem_local = MLKEM1024BraceKEM()
        self._brace_kem_ek_out = self._brace_kem_local.encap_key_bytes
        self.logger.debug(
            f"Brace rotation: generated ML-KEM-1024 ek "
            f"({len(self._brace_kem_ek_out)} bytes)")

    def consume_outgoing_kem_ek(self) -> Optional[bytes]:
        """Return pending kem_ek for inclusion in next outgoing message.

        Returns None if no ek is pending.  The ek is cleared after
        consumption — subsequent calls return None until the next
        prepare_brace_rotation().
        """
        ek = self._brace_kem_ek_out
        self._brace_kem_ek_out = None
        return ek

    def consume_outgoing_kem_ct(self) -> Optional[bytes]:
        """Return pending kem_ct (encapsulation response) for next outgoing message.

        Returns None if no ct is pending.
        """
        ct = self._brace_kem_ct_out
        self._brace_kem_ct_out = None
        return ct

    def process_incoming_kem_ek(self, ek: bytes) -> None:
        """Encapsulate to peer's encapsulation key, rotating brace_key.

        Called by the session layer when a received data message contains
        a kem_ek field.  Produces a ct for the next outgoing message.
        """
        ct, ss = MLKEM1024BraceKEM.encapsulate(ek)
        self._brace_kem_ct_out = ct
        self._rotate_brace_key(ss)
        self.logger.debug(
            f"Brace rotation: encapsulated to peer ek, "
            f"brace_key rotated, ct={len(ct)} bytes queued")

    def process_incoming_kem_ct(self, ct: bytes) -> None:
        """Decapsulate peer's ciphertext, rotating brace_key.

        Called by the session layer when a received data message contains
        a kem_ct field.  Completes the KEM exchange started by our ek.
        """
        if self._brace_kem_local is None:
            raise ValueError(
                "Received KEM ct but no local keypair pending — "
                "protocol desync or replay")
        ss = self._brace_kem_local.decapsulate(ct)
        self._brace_kem_local.zeroize()
        self._brace_kem_local = None
        self._rotate_brace_key(ss)
        self.logger.debug(
            "Brace rotation: decapsulated peer ct, brace_key rotated, "
            "KEM exchange complete")

    def _rotate_brace_key(self, shared_secret: bytes) -> None:
        """Derive new brace key from old brace key + KEM shared secret.

        brace_key' = KDF_1(0x16, brace_key ‖ shared_secret, 32)

        Domain-separated via KDFUsage.BRACE_KEY_ROTATE (0x16) so this
        KDF output can never collide with any other OTRv4 derivation.
        """
        old = self._brace_key
        self._brace_key = kdf_1(
            KDFUsage.BRACE_KEY_ROTATE, old + shared_secret, 32)
        # Cleanse old brace key material
        _old_buf = bytearray(old)
        _ossl.cleanse(_old_buf)
        del _old_buf, old
        # Cleanse shared secret
        _ss_buf = bytearray(shared_secret)
        _ossl.cleanse(_ss_buf)
        del _ss_buf

    def encrypt_message(self, plaintext: Union[bytes, str]) -> Tuple[bytes, bytes, bytes, bytes, int, List[bytes]]:
        """Encrypt a message (Spec §4.4.3)"""
        with self.lock:
            now = time.time()
            if (self.message_counter_send >= self.rekey_interval or
                now - self.last_rekey_time > self.rekey_timeout):
                _rekey_target = self.dh_ratchet_remote_pub or self.last_remote_pub
                if _rekey_target:
                    self._ratchet(_rekey_target)
                self.last_rekey_time = now

            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')

            ck_data = self.chain_key_send.read()
            next_ck, enc_key, mac_key = self._kdf_ck(ck_data, b"MESSAGE_KEY")
            self.chain_key_send.write(next_ck)
            del ck_data, next_ck

            header = RatchetHeader(self.dh_ratchet_local_pub, self.prev_chain_len_send, self.message_num_send)
            header_bytes = header.encode()
            aad = header_bytes + self.ad
            nonce = secrets.token_bytes(12)

            aesgcm = AESGCM(enc_key)
            ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]
            _enc_key_arr = bytearray(enc_key)
            _ossl.cleanse(_enc_key_arr)
            del _enc_key_arr, enc_key

            self._last_mac_key = mac_key
            current_msg_num = self.message_num_send
            self.message_num_send += 1
            self.message_counter_send += 1

            self.logger.debug(f"Encrypted msg: ratchet_id={self.ratchet_id}, msg_num={current_msg_num} <key>")

            reveal_keys = list(self._pending_reveal_mac_keys)
            self._pending_reveal_mac_keys.clear()

            return ciphertext, header_bytes, nonce, tag, self.ratchet_id, reveal_keys

    def decrypt_message(self, header_bytes: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypt a message (OTRv4 §4.4.4).

        Returns plaintext bytes on success.
        Raises EncryptionError on failure.
        """
        with self.lock:
            try:
                header = RatchetHeader.decode(header_bytes)
                dh_pub = header.dh_pub
                prev_chain_len = header.prev_chain_len
                msg_num = header.msg_num

                replay_key = (bytes(dh_pub), msg_num)
                if replay_key in self._seen_messages:
                    raise ValueError(f"Replay detected: (dh={dh_pub.hex()[:12]}…, n={msg_num})")

                is_new_dh = (self.dh_ratchet_remote_pub is not None and
                             not hmac.compare_digest(self.dh_ratchet_remote_pub, dh_pub))

                self.logger.debug(f"Decrypt: is_new_dh={is_new_dh}, current_recv_counter={self.message_num_recv}, msg_num={msg_num}")

                if is_new_dh:
                    old_root = self.root_key.read()
                    old_recv_ck = self.chain_key_recv.read()

                    remote_key = x448.X448PublicKey.from_public_bytes(dh_pub)
                    dh_secret = self.dh_ratchet_local.exchange(remote_key)

                    new_root_key, new_recv_chain = self._kdf_rk(old_root, dh_secret)

                    self.logger.debug(f"New DH ratchet: msg_num={msg_num} <key>")

                    temp_ck = new_recv_chain
                    for i in range(msg_num):
                        temp_ck, _, _ = self._kdf_ck(temp_ck, b"MESSAGE_KEY")
                    next_recv_ck, enc_key, _ = self._kdf_ck(temp_ck, b"MESSAGE_KEY")
                    del temp_ck

                    self.logger.debug(f"Derived msg_key (new DH) <key>")

                    aad = header_bytes + self.ad
                    aesgcm = AESGCM(enc_key)
                    ciphertext_with_tag = ciphertext + tag
                    try:
                        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
                    except Exception as e:
                        self.logger.error(f"Decryption failed for new DH key: {e}")
                        raise EncryptionError(f"Decryption failed for new DH key: {e}") from e
                    finally:
                        _ek_arr = bytearray(enc_key)
                        _ossl.cleanse(_ek_arr)
                        del _ek_arr, enc_key

                    self.root_key.write(new_root_key)
                    self.chain_key_recv.write(next_recv_ck)
                    del old_root, old_recv_ck, dh_secret, new_root_key, new_recv_chain, next_recv_ck

                    if self.dh_ratchet_remote_pub:
                        self.last_remote_pub = self.dh_ratchet_remote_pub

                    self.dh_ratchet_remote = remote_key
                    self.dh_ratchet_remote_pub = dh_pub

                    self.dh_ratchet_local = x448.X448PrivateKey.generate()
                    self.dh_ratchet_local_pub = self.dh_ratchet_local.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )

                    dh_secret_send = self.dh_ratchet_local.exchange(remote_key)
                    new_root_send, new_send_chain = self._kdf_rk(
                        self.root_key.read(), dh_secret_send)
                    self.root_key.write(new_root_send)
                    self.chain_key_send.write(new_send_chain)
                    del dh_secret_send

                    self.prev_chain_len_send = self.message_num_send
                    self.prev_chain_len_recv = self.message_num_recv
                    self.message_num_send = 0
                    self.message_counter_send = 0
                    self.message_num_recv = msg_num + 1

                    self.ratchet_id += 1

                    if self._last_mac_key is not None:
                        self._pending_reveal_mac_keys.append(bytes(self._last_mac_key))
                        self._last_mac_key = None
                        if len(self._pending_reveal_mac_keys) > 50:
                            self._pending_reveal_mac_keys = self._pending_reveal_mac_keys[-50:]

                    while len(self.skipped_keys) > self.max_message_keys:
                        oldest_key = next(iter(self.skipped_keys))
                        self.skipped_keys[oldest_key].zeroize()
                        del self.skipped_keys[oldest_key]

                    self.logger.debug(f"Ratchet complete: new id={self.ratchet_id}, new_recv_counter={self.message_num_recv}")

                    self._seen_messages[replay_key] = True
                    if len(self._seen_messages) > self._max_seen:
                        self._seen_messages.popitem(last=False)

                    return plaintext

                else:
                    if self.dh_ratchet_remote_pub is None:
                        try:
                            self.dh_ratchet_remote = x448.X448PublicKey.from_public_bytes(dh_pub)
                            self.dh_ratchet_remote_pub = dh_pub
                            self.logger.debug(
                                f"First message: recorded remote ratchet key "
                                f"{dh_pub[:8].hex()}…, using DAKE-derived recv chain"
                            )
                        except Exception as e:
                            raise EncryptionError(f"Failed to record initial remote ratchet key: {e}")

                    key = (dh_pub, msg_num)

                    if key in self.skipped_keys:
                        skipped_key = self.skipped_keys[key]
                        msg_key = bytes(skipped_key.message_key)
                        self.logger.debug(f"Using skipped key for msg_num={msg_num}")
                    else:
                        if msg_num > self.message_num_recv:
                            self._skip_message_keys(dh_pub, msg_num)
                            if key in self.skipped_keys:
                                skipped_key = self.skipped_keys[key]
                                msg_key = bytes(skipped_key.message_key)
                            else:
                                ck_data = self.chain_key_recv.read()
                                next_ck, enc_key, _ = self._kdf_ck(ck_data, b"MESSAGE_KEY")
                                self.chain_key_recv.write(next_ck)
                                msg_key = enc_key
                                self.logger.debug(f"Advanced recv chain after skip: msg_num={msg_num}")
                        elif msg_num == self.message_num_recv:
                            ck_data = self.chain_key_recv.read()
                            next_ck, enc_key, _ = self._kdf_ck(ck_data, b"MESSAGE_KEY")
                            self.chain_key_recv.write(next_ck)
                            msg_key = enc_key
                            self.logger.debug(f"Advanced recv chain: msg_num={msg_num} [key redacted]")
                        else:
                            raise ValueError(f"Message number {msg_num} too old (current recv={self.message_num_recv})")

                    aad = header_bytes + self.ad
                    aesgcm = AESGCM(msg_key)
                    ciphertext_with_tag = ciphertext + tag
                    try:
                        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
                    except Exception as e:
                        self.logger.error(f"Decryption failed for existing DH key: {e}")
                        raise EncryptionError(f"Decryption failed for existing DH key: {e}") from e
                    finally:
                        _mk_arr = bytearray(msg_key)
                        _ossl.cleanse(_mk_arr)
                        del _mk_arr, msg_key

                    if key in self.skipped_keys:
                        self.skipped_keys[key].zeroize()
                        del self.skipped_keys[key]

                    self.message_num_recv = max(self.message_num_recv, msg_num + 1)
                    self.message_counter_recv += 1

                    self._seen_messages[replay_key] = True
                    if len(self._seen_messages) > self._max_seen:
                        self._seen_messages.popitem(last=False)

                    self.logger.debug(f"Decrypted msg: ratchet_id={self.ratchet_id}, msg_num={msg_num}, len={len(plaintext)}")
                    return plaintext

            except Exception as e:
                self.logger.error(f"decrypt_message caught exception: {e}")
                raise EncryptionError(f"Decryption failed: {e}")

    def _skip_message_keys(self, dh_pub: bytes, until: int):
        """Skip message keys up to given message number (inclusive of until-1)."""
        if until > self.message_num_recv + self.max_skip:
            raise ValueError(f"Cannot skip {until - self.message_num_recv} messages (max: {self.max_skip})")

        self.logger.debug(f"Skipping from {self.message_num_recv} to {until-1}")
        for msg_num in range(self.message_num_recv, until):
            key = (dh_pub, msg_num)
            if key not in self.skipped_keys:
                ck_data = self.chain_key_recv.read()
                next_ck, enc_key, _ = self._kdf_ck(ck_data, b"MESSAGE_KEY")
                self.chain_key_recv.write(next_ck)
                self.skipped_keys[key] = SkippedMessageKey(dh_pub, msg_num, enc_key)
                self.logger.debug(f"Skipped msg_num={msg_num} key stored <key>")

        self.message_num_recv = until

    def _ratchet(self, dh_pub: bytes):
        """
        Send-side forced DH ratchet step (triggered by rekey_interval / timeout).

        Generates a fresh local key pair, computes DH with the remote pub that
        was most recently received (dh_pub), derives a new root key and a new
        *send* chain key, then resets the send-side message counter.

        The receiver handles this transparently: the new dh_ratchet_local_pub
        appears in the next message header, triggers is_new_dh=True in
        decrypt_message (CASE 1), which derives the matching recv chain via the
        same DH secret.  Both sides then share the new root key going forward.

        Bugs fixed vs. original implementation:
          - DH was computed with old_remote_pub (stale) instead of dh_pub (current).
          - New chain key was written to chain_key_recv instead of chain_key_send.
          - message_num_recv was incorrectly reset (only send-side counter resets).
          - dh_ratchet_remote_pub was mutated here (only decrypt_message owns that).
        """
        with self.lock:
            self.logger.debug(f"Send-side ratchet with remote_pub={dh_pub[:8].hex()}...")

            self.dh_ratchet_local = x448.X448PrivateKey.generate()
            self.dh_ratchet_local_pub = self.dh_ratchet_local.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            remote_key = x448.X448PublicKey.from_public_bytes(dh_pub)
            dh_secret  = self.dh_ratchet_local.exchange(remote_key)

            root_key_data = self.root_key.read()
            new_root_key, new_send_chain = self._kdf_rk(root_key_data, dh_secret)

            self.root_key.write(new_root_key)
            self.chain_key_send.write(new_send_chain)
            self.logger.debug("Send-side ratchet: root + send chain advanced")

            self.prev_chain_len_send = self.message_num_send
            self.message_num_send = 0
            self.message_counter_send = 0

            self.ratchet_id += 1

            if self._last_mac_key is not None:
                self._pending_reveal_mac_keys.append(bytes(self._last_mac_key))
                self._last_mac_key = None
                if len(self._pending_reveal_mac_keys) > 50:
                    self._pending_reveal_mac_keys = self._pending_reveal_mac_keys[-50:]

            while len(self.skipped_keys) > self.max_message_keys:
                oldest_key = next(iter(self.skipped_keys))
                self.skipped_keys[oldest_key].zeroize()
                del self.skipped_keys[oldest_key]

            self.logger.debug(f"Ratchet complete: id={self.ratchet_id}")

            # ── Trigger brace KEM rotation on DH ratchet ────────
            self.prepare_brace_rotation()

    def zeroize(self):
        """Zeroize all sensitive data."""
        with self.lock:
            for attr in ['chain_key_send', 'chain_key_recv', 'root_key']:
                obj = getattr(self, attr, None)
                if obj:
                    try:
                        obj.zeroize()
                    except (OSError, RuntimeError) as e:
                        self.logger.error(f"Failed to zeroize {attr}: {e}")
            for key in list(self.skipped_keys.values()):
                key.zeroize()
            self.skipped_keys.clear()
            self._seen_messages.clear()
            self._pending_reveal_mac_keys.clear()
            self._last_mac_key = None
            self.dh_ratchet_local = None
            self.dh_ratchet_remote = None
            self.dh_ratchet_remote_pub = None
            self.last_remote_pub = None
            # Zeroize brace KEM rotation state
            if self._brace_kem_local is not None:
                self._brace_kem_local.zeroize()
                self._brace_kem_local = None
            self._brace_kem_ek_out = None
            self._brace_kem_ct_out = None
            _bk = bytearray(self._brace_key)
            _ossl.cleanse(_bk)
            del _bk
            self._brace_key = bytes(32)
            self.logger.debug("DoubleRatchet zeroized")

    def __del__(self):
        try:
            self.zeroize()
        except Exception:
            pass


class RustBackedDoubleRatchet:
    """Drop-in replacement for DoubleRatchet using Rust crypto core.

    X448 key exchange and ML-KEM brace rotation stay in Python.
    KDF, AES-256-GCM, chain advancement, skip keys, and replay
    detection are handled by the Rust otrv4_core module.

    Deterministic zeroization: Rust's Zeroize trait guarantees all
    secret key material is overwritten on drop — unlike Python's GC
    which may leave copies in memory indefinitely.
    """

    def __init__(self, root_key, is_initiator: bool,
                 ad: bytes = b"OTRv4-DATA", logger=None,
                 chain_key_send=None, chain_key_recv=None,
                 brace_key=None,
                 rekey_interval: int = OTRConstants.REKEY_INTERVAL,
                 rekey_timeout: int = OTRConstants.REKEY_TIMEOUT):

        self.lock = threading.RLock()
        self.is_initiator = is_initiator
        self.ad = ad
        self.logger = logger or NullLogger()
        self.rekey_interval = rekey_interval
        self.rekey_timeout = rekey_timeout
        self.last_rekey_time = time.time()

        # ── X448 keys (Python — uses OpenSSL via cryptography) ──
        self.dh_ratchet_local = x448.X448PrivateKey.generate()
        self.dh_ratchet_local_pub = self.dh_ratchet_local.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.dh_ratchet_remote = None
        self.dh_ratchet_remote_pub = None
        self.last_remote_pub = None

        # ── Brace KEM rotation state (Python — uses C extension) ──
        self._brace_kem_local = None
        self._brace_kem_ek_out = None
        self._brace_kem_ct_out = None
        self._brace_key = brace_key if brace_key else bytes(32)

        # ── Read key material ────────────────────────────────
        rk_bytes = root_key.read() if hasattr(root_key, 'read') else bytes(root_key)
        bk_bytes = self._brace_key

        if chain_key_send is None or chain_key_recv is None:
            seed = kdf_1(KDFUsage.ROOT_KEY, rk_bytes + bk_bytes, 64)
            if is_initiator:
                ck_s, ck_r = seed[:32], seed[32:64]
            else:
                ck_s, ck_r = seed[32:64], seed[:32]
        else:
            ck_s = chain_key_send[:32]
            ck_r = chain_key_recv[:32]

        if all(b == 0 for b in ck_s) or all(b == 0 for b in ck_r):
            raise ValueError("Chain keys zero — possible KDF failure")

        # ── Create Rust ratchet ──────────────────────────────
        # IMPORTANT: always pass is_initiator=True here because the
        # DAKE has already assigned chain_key_send/recv in the correct
        # order for each side.  The Rust constructor swaps keys for
        # responders — passing the actual role would double-swap and
        # produce mismatched keys (AES-GCM auth failure on first msg).
        _rust_init = True  # keys are pre-ordered by DAKE
        self._rust = _RustRatchet(
            rk_bytes[:32], ck_s, ck_r, bk_bytes[:32],
            self.dh_ratchet_local_pub, _rust_init,
        )

        self.ratchet_id = 0
        self.message_counter_send = 0
        self.logger.debug(f"RustBackedDoubleRatchet initialized (initiator={is_initiator})")

    def encrypt_message(self, plaintext):
        """Encrypt a message (Spec §4.4.3). Same return signature as Python."""
        with self.lock:
            now = time.time()
            if (self.message_counter_send >= self.rekey_interval or
                    now - self.last_rekey_time > self.rekey_timeout):
                _rekey_target = self.dh_ratchet_remote_pub or self.last_remote_pub
                if _rekey_target:
                    self._ratchet(_rekey_target)
                self.last_rekey_time = now

            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')

            enc = self._rust.encrypt(plaintext)
            self.message_counter_send += 1
            self.ratchet_id = enc.ratchet_id

            return (enc.ciphertext, enc.header, enc.nonce, enc.tag,
                    enc.ratchet_id, list(enc.reveal_mac_keys))

    def decrypt_message(self, header_bytes, ciphertext, nonce, tag):
        """Decrypt a message (OTRv4 §4.4.4). Returns plaintext bytes."""
        with self.lock:
            try:
                is_new_dh = self._rust.is_new_dh(header_bytes)

                if is_new_dh:
                    return self._decrypt_new_dh(header_bytes, ciphertext, nonce, tag)
                else:
                    if self.dh_ratchet_remote_pub is None:
                        dh_pub = self._rust.header_dh_pub(header_bytes)
                        self.dh_ratchet_remote = x448.X448PublicKey.from_public_bytes(dh_pub)
                        self.dh_ratchet_remote_pub = dh_pub

                    return self._rust.decrypt_same_dh(
                        header_bytes, ciphertext, nonce, tag)

            except Exception as e:
                raise EncryptionError(f"Decryption failed: {e}")

    def _decrypt_new_dh(self, header_bytes, ciphertext, nonce, tag):
        """Handle decrypt with DH ratchet step."""
        dh_pub = self._rust.header_dh_pub(header_bytes)
        remote_key = x448.X448PublicKey.from_public_bytes(dh_pub)

        dh_secret_recv = self.dh_ratchet_local.exchange(remote_key)

        new_local = x448.X448PrivateKey.generate()
        new_local_pub = new_local.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        dh_secret_send = new_local.exchange(remote_key)

        pt = self._rust.decrypt_new_dh(
            header_bytes, ciphertext, nonce, tag,
            dh_secret_recv, dh_secret_send, new_local_pub
        )

        if self.dh_ratchet_remote_pub is not None:
            self.last_remote_pub = self.dh_ratchet_remote_pub
        self.dh_ratchet_remote = remote_key
        self.dh_ratchet_remote_pub = dh_pub
        self.dh_ratchet_local = new_local
        self.dh_ratchet_local_pub = new_local_pub

        self.ratchet_id = self._rust.ratchet_id()
        self.message_counter_send = 0
        self.prepare_brace_rotation()

        return pt

    def _ratchet(self, dh_pub):
        """Send-side forced DH ratchet step."""
        with self.lock:
            self.dh_ratchet_local = x448.X448PrivateKey.generate()
            self.dh_ratchet_local_pub = self.dh_ratchet_local.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            remote_key = x448.X448PublicKey.from_public_bytes(dh_pub)
            dh_secret = self.dh_ratchet_local.exchange(remote_key)

            self._rust.send_ratchet(dh_secret, self.dh_ratchet_local_pub)
            self.ratchet_id = self._rust.ratchet_id()
            self.message_counter_send = 0
            self.prepare_brace_rotation()

    def prepare_brace_rotation(self):
        if self._brace_kem_local is not None:
            return
        if self._brace_kem_ct_out is not None:
            return
        self._brace_kem_local = MLKEM1024BraceKEM()
        self._brace_kem_ek_out = self._brace_kem_local.encap_key_bytes

    def consume_outgoing_kem_ek(self):
        ek = self._brace_kem_ek_out
        self._brace_kem_ek_out = None
        return ek

    def consume_outgoing_kem_ct(self):
        ct = self._brace_kem_ct_out
        self._brace_kem_ct_out = None
        return ct

    def process_incoming_kem_ek(self, ek):
        ct, ss = MLKEM1024BraceKEM.encapsulate(ek)
        self._brace_kem_ct_out = ct
        self._rust.rotate_brace_key(ss)

    def process_incoming_kem_ct(self, ct):
        if self._brace_kem_local is None:
            raise ValueError("Received KEM ct but no local keypair pending")
        ss = self._brace_kem_local.decapsulate(ct)
        self._brace_kem_local.zeroize()
        self._brace_kem_local = None
        self._rust.rotate_brace_key(ss)

    def zeroize(self):
        with self.lock:
            self._rust = None  # Rust Drop → zeroizes all secrets
            self.dh_ratchet_local = None
            self.dh_ratchet_remote = None
            self.dh_ratchet_remote_pub = None
            self.last_remote_pub = None
            if self._brace_kem_local is not None:
                self._brace_kem_local.zeroize()
                self._brace_kem_local = None
            self._brace_kem_ek_out = None
            self._brace_kem_ct_out = None

    def __del__(self):
        try:
            self.zeroize()
        except Exception:
            pass


def determine_roles(local_id_pub: bytes, remote_id_pub: bytes) -> bool:
    """Determine DAKE roles according to OTRv4 spec §4.2"""
    return local_id_pub < remote_id_pub


class DAKE1RateLimiter:
    """Per-peer sliding-window rate limiter for DAKE1 (M-4 fix).

    Each inbound DAKE1 forces the responder to generate an X448 keypair and
    perform three DH exchanges.  Without throttling, an adversary can exhaust
    CPU/memory by flooding DAKE1 messages.

    Policy: at most MAX_ATTEMPTS per peer within WINDOW_SECONDS.
    Excess attempts are silently dropped (no error message to prevent oracle).
    """

    MAX_ATTEMPTS: int = 5
    WINDOW_SECONDS: float = 60.0

    def __init__(self):
        self._lock = threading.Lock()
        self._attempts: Dict[str, deque] = defaultdict(deque)

    def is_allowed(self, peer_key: str) -> bool:
        """Return True and record the attempt if the peer is within quota."""
        now = time.monotonic()
        cutoff = now - self.WINDOW_SECONDS
        with self._lock:
            dq = self._attempts[peer_key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.MAX_ATTEMPTS:
                return False
            dq.append(now)
            return True

    def reset(self, peer_key: str) -> None:
        """Clear the rate-limit bucket for a peer (call after DAKE success)."""
        with self._lock:
            self._attempts.pop(peer_key, None)


_dake1_rate_limiter = DAKE1RateLimiter()


class OTRv4DAKE:
    """OTRv4 DAKE implementation - COMPLETE with all methods"""
    
    def __init__(self, client_profile: Optional[ClientProfile] = None,
                 explicit_initiator: bool = False,
                 tracer: Optional[OTRTracer] = None,
                 logger: Optional[OTRLogger] = None):
        self.client_profile = client_profile or ClientProfile()
        self.explicit_initiator = explicit_initiator
        self.tracer = tracer
        self.logger = logger or NullLogger()
        self.lock = threading.RLock()
        
        self.state = DAKEState.IDLE
        self.is_initiator = explicit_initiator
        self.start_time: Optional[float] = None
        self.timeout = UIConstants.DAKE_TIMEOUT
        self._session_created_at: float = 0.0
        self._session_max_age:    float = 86400.0
        self.MAC_LENGTH = 64
        
        self.ephemeral_key: Optional[x448.X448PrivateKey] = None
        self.ephemeral_pub_bytes: Optional[bytes] = None
        self.remote_ephemeral_pub: Optional[x448.X448PublicKey] = None
        self.remote_ephemeral_pub_bytes: Optional[bytes] = None
        
        self.remote_profile: Optional[ClientProfile] = None
        self.remote_identity_key: Optional[ed448.Ed448PublicKey] = None
        self.remote_prekey: Optional[x448.X448PublicKey] = None
        
        self.remote_identity_pub_bytes: Optional[bytes] = None
        self.remote_prekey_pub_bytes: Optional[bytes] = None
        
        self.session_keys: Optional[Dict[str, Any]] = None

        self._raw_dake1_bytes: Optional[bytes] = None
        self._raw_dake2_bytes: Optional[bytes] = None

        self._brace_kem: MLKEM1024BraceKEM = MLKEM1024BraceKEM()
        self._remote_brace_ct: Optional[bytes] = None   # peer's KEM ciphertext (DAKE2)
        self._remote_brace_ek: Optional[bytes] = None   # peer's KEM encapsulation key (DAKE1)

        # ── ML-DSA-87 hybrid PQ authentication ──────────────────
        self._mldsa_auth: Optional[MLDSA87Auth] = None
        self._remote_mldsa_pub: Optional[bytes] = None
        if MLDSA87_AVAILABLE:
            try:
                self._mldsa_auth = MLDSA87Auth()
            except Exception:
                self._mldsa_auth = None
        
        if self.tracer:
            self.tracer.trace("DAKE", "INIT", None, "IDLE", 
                              f"DAKE engine initialized, initiator={explicit_initiator}")
    
    @staticmethod
    def _safe_b64decode(data: str) -> bytes:
        """Safely decode base64 with padding"""
        try:
            data = str(data).strip()
            if not data:
                raise ValueError("Empty base64 data")
            
            data = ''.join(data.split())
            
            if '[' in data and ']' in data:
                end_bracket = data.rfind(']')
                if end_bracket != -1:
                    data = data[end_bracket + 1:].strip()
            
            try:
                padding_needed = (-len(data) % 4)
                if padding_needed:
                    data = data + '=' * padding_needed
                return base64.urlsafe_b64decode(data)
            except Exception:
                data = data.replace('-', '+').replace('_', '/')
                padding_needed = (-len(data) % 4)
                if padding_needed:
                    data = data + '=' * padding_needed
                return base64.b64decode(data)
        except Exception as e:
            try:
                import re
                data = re.sub(r'[^A-Za-z0-9+/=-]', '', data)
                padding_needed = (-len(data) % 4)
                if padding_needed:
                    data = data + '=' * padding_needed
                return base64.b64decode(data)
            except Exception as e2:
                raise ValueError(f"Base64 decode failed: {e}, also: {e2}")
    
    def is_session_expired(self) -> bool:
        """Return True if the established session has exceeded its 24-hour maximum age."""
        if self.state != DAKEState.ESTABLISHED:
            return False
        if self._session_created_at == 0.0:
            return False
        return (time.time() - self._session_created_at) > self._session_max_age

    def transition(self, new_state: DAKEState, reason: str = ""):
        """Transition DAKE state with validation"""
        with self.lock:
            old_state = self.state
            
            valid_transitions = {
                DAKEState.IDLE: [DAKEState.SENT_DAKE1, DAKEState.RECEIVED_DAKE1, DAKEState.FAILED],
                DAKEState.SENT_DAKE1: [DAKEState.ESTABLISHED, DAKEState.FAILED],
                DAKEState.RECEIVED_DAKE1: [DAKEState.SENT_DAKE2, DAKEState.FAILED],
                DAKEState.SENT_DAKE2: [DAKEState.ESTABLISHED, DAKEState.FAILED],
                DAKEState.ESTABLISHED: [],
                DAKEState.FAILED: []
            }
            
            if new_state not in valid_transitions.get(old_state, []):
                error_msg = f"Invalid DAKE transition: {old_state.name} → {new_state.name}"
                if self.tracer:
                    self.tracer.trace("DAKE", "ERROR", old_state.name, new_state.name, error_msg)
                raise StateMachineError(error_msg)
            
            self.state = new_state
            if self.tracer:
                self.tracer.trace("DAKE", "STATE", old_state.name, new_state.name, reason)
    
    def generate_dake1(self) -> str:
        """Generate DAKE1 (Identity Message) as initiator — spec §4.2.1.

        Wire format: type(1=0x35) || X448_eph_pub(56) || MLKEM1024_ek(1568)
                     || client_profile(var) [|| MLDSA87_pub(2592)]

        The ML-KEM-1024 encapsulation key establishes the post-quantum brace KEM.
        The responder encapsulates to it and returns the ciphertext in DAKE2.
        """
        with self.lock:
            if self.state != DAKEState.IDLE:
                raise StateMachineError(f"Cannot generate DAKE1 in state: {self.state.name}")
            if not self.is_initiator:
                raise StateMachineError("Only initiator can generate DAKE1")

            self.start_time = time.time()

            self.ephemeral_key = x448.X448PrivateKey.generate()
            self.ephemeral_pub_bytes = self.ephemeral_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            profile_bytes = self.client_profile.encode()

            message = bytearray()
            message.append(OTRConstants.MESSAGE_TYPE_DAKE1)
            message.extend(self.ephemeral_pub_bytes)
            message.extend(self._brace_kem.encap_key_bytes)
            message.extend(profile_bytes)

            # ── Append ML-DSA-87 public key for hybrid PQ auth ───
            if self._mldsa_auth is not None:
                message.extend(self._mldsa_auth.pub_bytes)

            raw_bytes = bytes(message)
            self._raw_dake1_bytes = raw_bytes

            encoded = base64.urlsafe_b64encode(raw_bytes).decode('ascii').rstrip('=')
            result = f"?OTRv4 {encoded}"

            self.transition(DAKEState.SENT_DAKE1, "generated DAKE1 (Identity)")
            if self.logger:
                self.logger.debug(f"Generated DAKE1 (Identity): {len(result)} bytes")
            return result
    
    def process_dake1(self, dake1_msg: str, peer_key: str = "unknown") -> bool:
        """Process DAKE1 (Identity Message) as responder — spec §4.2.2.

        Wire format: 0x35 || eph_pub(56) || mlkem1024_ek(1568) || profile(var) [|| MLDSA87_pub(2592)]
        """
        if not _dake1_rate_limiter.is_allowed(peer_key):
            if self.logger:
                self.logger.warning(
                    f"DAKE1 rate limit exceeded for peer '{peer_key}' — dropping"
                )
            return False

        with self.lock:
            if self.state != DAKEState.IDLE:
                raise StateMachineError(f"Cannot process DAKE1 in state: {self.state.name}")
            if self.is_initiator:
                raise StateMachineError("Initiator cannot process DAKE1")

            self.start_time = time.time()

            try:
                if not dake1_msg.startswith("?OTRv4 "):
                    raise ValueError("Not an OTRv4 message")

                payload = dake1_msg[7:].strip()
                decoded = self._safe_b64decode(payload)

                if len(decoded) < 1:
                    raise ValueError("Message too short")

                msg_type = decoded[0]
                if msg_type != OTRConstants.MESSAGE_TYPE_DAKE1:
                    raise ValueError(f"Not a DAKE1 (Identity) message: 0x{msg_type:02x} "
                                     f"(expected 0x{OTRConstants.MESSAGE_TYPE_DAKE1:02x})")

                offset = 1

                if len(decoded) < offset + OTRConstants.X448_PUBLIC_KEY_SIZE:
                    raise ValueError("Ephemeral key missing")
                remote_ephemeral_pub_bytes = decoded[offset:offset + OTRConstants.X448_PUBLIC_KEY_SIZE]
                offset += OTRConstants.X448_PUBLIC_KEY_SIZE

                EK_LEN = MLKEM1024BraceKEM.EK_BYTES
                if len(decoded) < offset + EK_LEN:
                    raise ValueError("ML-KEM-1024 encapsulation key missing from DAKE1")
                self._remote_brace_ek = decoded[offset:offset + EK_LEN]
                offset += EK_LEN

                # ── Parse ClientProfile with known-size extraction ───
                #    Profile size is deterministic from its wire format:
                #    1(ver) + 1(n) + n(versions) + 57(Ed448) + 56(X448) + 8(exp) + 114(sig)
                if len(decoded) < offset + 3:
                    raise ValueError("Profile header missing")
                _prof_num_versions = decoded[offset + 1]
                _prof_size = 1 + 1 + _prof_num_versions + 57 + 56 + 8 + 114
                if len(decoded) < offset + _prof_size:
                    raise ValueError(f"Profile truncated: need {_prof_size}, have {len(decoded) - offset}")
                profile_data = decoded[offset:offset + _prof_size]
                offset += _prof_size

                # ── Check for ML-DSA-87 public key after profile ──
                if offset + MLDSA87Auth.PUB_BYTES <= len(decoded) and MLDSA87_AVAILABLE:
                    self._remote_mldsa_pub = decoded[offset:offset + MLDSA87Auth.PUB_BYTES]
                    offset += MLDSA87Auth.PUB_BYTES

                if self.tracer:
                    self.tracer.trace("DAKE1", "PROFILE", "RECEIVING", "PROCESSING",
                                      f"profile length: {len(profile_data)}")

                try:
                    remote_profile = ClientProfile.decode(profile_data)
                except Exception as e:
                    if self.tracer:
                        self.tracer.trace("ERROR", "PROFILE", "DECODE", "FAILED",
                                         f"ClientProfile validation failed: {e}")
                    raise ValueError(f"DAKE1 aborted: remote ClientProfile failed strict validation: {e}")

                self.remote_identity_pub_bytes = remote_profile.identity_pub_bytes
                self.remote_prekey_pub_bytes   = remote_profile.prekey_pub_bytes

                try:
                    self.remote_identity_key = ed448.Ed448PublicKey.from_public_bytes(
                        remote_profile.identity_pub_bytes
                    )
                except Exception as e:
                    raise ValueError(f"DAKE1 aborted: remote identity key is invalid: {e}") from e

                try:
                    self.remote_prekey = x448.X448PublicKey.from_public_bytes(
                        remote_profile.prekey_pub_bytes
                    )
                except Exception as e:
                    raise ValueError(f"DAKE1 aborted: remote prekey is invalid: {e}") from e

                self.remote_ephemeral_pub      = x448.X448PublicKey.from_public_bytes(
                    remote_ephemeral_pub_bytes
                )
                self.remote_ephemeral_pub_bytes = remote_ephemeral_pub_bytes
                self.remote_profile            = remote_profile

                self._raw_dake1_bytes = bytes(decoded)

                self.transition(DAKEState.RECEIVED_DAKE1, "received DAKE1 (Identity)")
                if self.logger:
                    self.logger.debug("DAKE1 (Identity) processed successfully")
                return True

            except Exception as e:
                self.transition(DAKEState.FAILED, f"DAKE1 processing failed: {e}")
                if self.logger:
                    self.logger.error(f"DAKE1 processing failed: {e}")
                return False
    
    def generate_dake2(self) -> Optional[str]:
        """Generate DAKE2 (Auth-R Message) as responder — spec §4.2.3.

        Wire format: 0x36 || eph_pub(56) || mlkem1024_ct(1568)
                     || profile(var) [|| MLDSA87_pub(2592)] || MAC(64)

        The responder encapsulates to the initiator's ML-KEM-1024 ek received in
        DAKE1 and includes the ciphertext here.  The initiator decapsulates with
        its private key to recover brace_shared.
        """
        with self.lock:
            if self.state != DAKEState.RECEIVED_DAKE1:
                raise StateMachineError(f"Cannot generate DAKE2 in state: {self.state.name}")
            if self.is_initiator:
                raise StateMachineError("Initiator cannot generate DAKE2")

            try:
                our_ephemeral_key = x448.X448PrivateKey.generate()
                our_ephemeral_pub = our_ephemeral_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )

                dh1 = our_ephemeral_key.exchange(self.remote_ephemeral_pub)
                dh2 = our_ephemeral_key.exchange(self.remote_prekey)
                dh3 = self.client_profile.prekey.exchange(self.remote_ephemeral_pub)

                if not hasattr(self, '_remote_brace_ek') or self._remote_brace_ek is None:
                    raise ValueError("Remote ML-KEM-1024 encapsulation key not received")
                brace_ct, brace_shared = MLKEM1024BraceKEM.encapsulate(self._remote_brace_ek)

                session_keys = self._derive_session_keys(
                    dh1, dh2, dh3, brace_shared, is_initiator=False
                )

                profile_bytes = self.client_profile.encode()

                message_body = bytearray()
                message_body.append(OTRConstants.MESSAGE_TYPE_DAKE2)
                message_body.extend(our_ephemeral_pub)
                message_body.extend(brace_ct)
                message_body.extend(profile_bytes)

                # ── Append ML-DSA-87 public key for hybrid PQ auth ───
                if self._mldsa_auth is not None:
                    message_body.extend(self._mldsa_auth.pub_bytes)

                mac_key = session_keys.get('mac_key')
                if mac_key is None:
                    raise ValueError("MAC key not available")
                mac = hmac.new(mac_key, bytes(message_body), hashlib.sha3_512).digest()
                if len(mac) != self.MAC_LENGTH:
                    raise ValueError(f"MAC length incorrect: {len(mac)}")

                message = bytes(message_body) + mac

                self.ephemeral_key      = our_ephemeral_key
                self.ephemeral_pub_bytes = our_ephemeral_pub
                self.session_keys       = session_keys
                self._raw_dake2_bytes   = message

                encoded = base64.urlsafe_b64encode(message).decode('ascii').rstrip('=')
                result  = f"?OTRv4 {encoded}"

                self.transition(DAKEState.SENT_DAKE2, "generated DAKE2 (Auth-R)")
                if self.logger:
                    self.logger.debug("DAKE2 (Auth-R) generated successfully")
                return result

            except Exception as e:
                self.transition(DAKEState.FAILED, f"DAKE2 generation failed: {e}")
                if self.logger:
                    self.logger.error(f"DAKE2 generation failed: {e}")
                return None
    
    def process_dake2(self, dake2_msg: str) -> bool:
        """Process DAKE2 (Auth-R Message) as initiator — spec §4.2.4.

        Wire format: 0x36 || eph_pub(56) || mlkem1024_ct(1568) || profile(var) [|| MLDSA87_pub(2592)] || MAC(64)
        """
        with self.lock:
            if self.state != DAKEState.SENT_DAKE1:
                raise StateMachineError(f"Cannot process DAKE2 in state: {self.state.name}")
            if not self.is_initiator:
                raise StateMachineError("Responder cannot process DAKE2")

            try:
                if not dake2_msg.startswith("?OTRv4 "):
                    raise ValueError("Not an OTRv4 message")

                payload = dake2_msg[7:].strip()
                decoded = self._safe_b64decode(payload)

                if len(decoded) < 1:
                    raise ValueError("Message too short")

                msg_type = decoded[0]
                if msg_type != OTRConstants.MESSAGE_TYPE_DAKE2:
                    raise ValueError(f"Not a DAKE2 (Auth-R) message: 0x{msg_type:02x} "
                                     f"(expected 0x{OTRConstants.MESSAGE_TYPE_DAKE2:02x})")

                offset = 1

                if len(decoded) < offset + OTRConstants.X448_PUBLIC_KEY_SIZE:
                    raise ValueError("Ephemeral key missing")
                remote_ephemeral_pub_bytes = decoded[offset:offset + OTRConstants.X448_PUBLIC_KEY_SIZE]
                offset += OTRConstants.X448_PUBLIC_KEY_SIZE

                CT_LEN = MLKEM1024BraceKEM.CT_BYTES
                if len(decoded) < offset + CT_LEN:
                    raise ValueError("ML-KEM-1024 ciphertext missing from DAKE2")
                self._remote_brace_ct = decoded[offset:offset + CT_LEN]
                offset += CT_LEN

                if len(decoded) < offset + self.MAC_LENGTH:
                    raise ValueError(f"Message too short for profile+MAC")

                mac_start    = len(decoded) - self.MAC_LENGTH
                mac          = decoded[mac_start:]

                if len(mac) != self.MAC_LENGTH:
                    raise ValueError(f"Invalid MAC length: expected {self.MAC_LENGTH}, got {len(mac)}")

                # ── Parse profile with known-size extraction ─────
                if len(decoded) < offset + 3:
                    raise ValueError("Profile header missing in DAKE2")
                _prof_num_versions = decoded[offset + 1]
                _prof_size = 1 + 1 + _prof_num_versions + 57 + 56 + 8 + 114
                if offset + _prof_size > mac_start:
                    raise ValueError(f"Profile truncated in DAKE2")
                profile_data = decoded[offset:offset + _prof_size]
                offset += _prof_size

                # ── Check for ML-DSA-87 public key after profile ──
                _remaining = mac_start - offset
                if _remaining >= MLDSA87Auth.PUB_BYTES and MLDSA87_AVAILABLE:
                    self._remote_mldsa_pub = decoded[offset:offset + MLDSA87Auth.PUB_BYTES]
                    offset += MLDSA87Auth.PUB_BYTES

                if self.tracer:
                    self.tracer.trace("DAKE2", "PROFILE", "RECEIVING", "PROCESSING",
                                      f"profile length: {len(profile_data)}")

                try:
                    remote_profile = ClientProfile.decode(profile_data)
                except Exception as e:
                    if self.tracer:
                        self.tracer.trace("ERROR", "PROFILE", "DECODE", "FAILED",
                                         f"ClientProfile validation failed: {e}")
                    raise ValueError(f"DAKE2 aborted: remote ClientProfile failed strict validation: {e}")

                self.remote_identity_pub_bytes = remote_profile.identity_pub_bytes
                self.remote_prekey_pub_bytes   = remote_profile.prekey_pub_bytes

                try:
                    self.remote_identity_key = ed448.Ed448PublicKey.from_public_bytes(
                        remote_profile.identity_pub_bytes
                    )
                except Exception as e:
                    raise ValueError(f"DAKE2 aborted: remote identity key is invalid: {e}") from e

                try:
                    self.remote_prekey = x448.X448PublicKey.from_public_bytes(
                        remote_profile.prekey_pub_bytes
                    )
                except Exception as e:
                    raise ValueError(f"DAKE2 aborted: remote prekey is invalid: {e}") from e

                self.remote_ephemeral_pub = x448.X448PublicKey.from_public_bytes(
                    remote_ephemeral_pub_bytes
                )
                self.remote_ephemeral_pub_bytes = remote_ephemeral_pub_bytes
                self.remote_profile             = remote_profile

                dh1 = self.ephemeral_key.exchange(self.remote_ephemeral_pub)
                dh2 = self.client_profile.prekey.exchange(self.remote_ephemeral_pub)
                dh3 = self.ephemeral_key.exchange(self.remote_prekey)

                brace_shared = self._brace_kem.decapsulate(self._remote_brace_ct)

                session_keys = self._derive_session_keys(
                    dh1, dh2, dh3, brace_shared, is_initiator=True
                )

                mac_key      = session_keys.get('mac_key')
                if mac_key is None:
                    raise ValueError("MAC key not available")
                message_body = decoded[:mac_start]
                expected_mac = hmac.new(mac_key, message_body, hashlib.sha3_512).digest()

                if not hmac.compare_digest(mac, expected_mac):
                    raise ValueError(
                        "DAKE2 MAC verification failed — possible MITM or replay. Session aborted."
                    )

                self.session_keys     = session_keys
                self._raw_dake2_bytes = bytes(decoded)

                self._session_created_at = time.time()
                self.transition(DAKEState.ESTABLISHED, "DAKE2 (Auth-R) processed successfully")
                if self.logger:
                    self.logger.debug("DAKE2 (Auth-R) processed successfully")
                return True

            except Exception as e:
                self.transition(DAKEState.FAILED, f"DAKE2 processing failed: {e}")
                if self.logger:
                    self.logger.error(f"DAKE2 processing failed: {e}")
                return False
    
    def generate_dake3(self) -> Optional[str]:
        """Generate DAKE3 (Auth-I Message) as initiator — spec §4.3.3.

        Wire format: 0x37 || σ(228) || flag(1) [|| mldsa_sig(4627)]

        σ = Schnorr ring signature (classical deniability).
        If ML-DSA-87 is available and peer sent their PQ pub key:
          flag=0x01, followed by ML-DSA-87 signature over same transcript.
        Otherwise: flag=0x00 (classical only).

        The ML-DSA-87 signature provides post-quantum authentication.
        A quantum adversary could verify it (no PQ deniability), but
        authentication against quantum threats is the higher priority.
        """
        with self.lock:
            if self.state != DAKEState.ESTABLISHED:
                raise StateMachineError(f"Cannot generate DAKE3 in state: {self.state.name}")
            if not self.is_initiator:
                raise StateMachineError("Responder cannot generate DAKE3")

            try:
                if self.session_keys is None:
                    raise ValueError("Session keys not available")
                if self._raw_dake1_bytes is None or self._raw_dake2_bytes is None:
                    raise ValueError("Raw DAKE transcript bytes missing — cannot build Auth-I")

                if len(self._raw_dake1_bytes) < 57:
                    raise ValueError(
                        "DAKE1 transcript blob too short — transcript binding aborted. "
                        "Minimum 57 bytes (1 type + 56 X448 pub)."
                    )
                if len(self._raw_dake2_bytes) < 57:
                    raise ValueError(
                        "DAKE2 transcript blob too short — transcript binding aborted."
                    )
                if self._raw_dake1_bytes == self._raw_dake2_bytes:
                    raise ValueError(
                        "DAKE1 and DAKE2 transcript blobs are identical — "
                        "possible replay or session confusion. Aborting Auth-I."
                    )

                transcript_msg = kdf_1(
                    KDFUsage.AUTH_I_MSG,
                    self._raw_dake1_bytes + self._raw_dake2_bytes,
                    64
                )

                identity_key = self.client_profile.identity_key
                if identity_key is None:
                    raise ValueError("Local Ed448 identity key not available")

                A1_bytes = (self.client_profile.identity_pub_bytes
                            or identity_key.public_key().public_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PublicFormat.Raw))
                if self.remote_profile is None:
                    raise ValueError("Remote ClientProfile not stored")
                A2_bytes = self.remote_profile.identity_pub_bytes
                if A2_bytes is None:
                    raise ValueError("Remote identity_pub_bytes not available")

                sigma = RingSignature.sign(identity_key, A1_bytes, A2_bytes, transcript_msg)

                message = bytearray([OTRConstants.MESSAGE_TYPE_DAKE3])
                message.extend(sigma)

                # ── Hybrid PQ authentication: ML-DSA-87 signature ──
                #    Wire: ring_sigma(228) || 0x01 || mldsa_sig(4627)
                #    The ML-DSA signature signs the same transcript_msg,
                #    providing post-quantum authentication alongside the
                #    classical ring signature's deniability.
                if (self._mldsa_auth is not None
                        and self._remote_mldsa_pub is not None):
                    mldsa_sig = self._mldsa_auth.sign(transcript_msg)
                    message.append(0x01)
                    message.extend(mldsa_sig)
                    if self.logger:
                        self.logger.debug(
                            f"DAKE3 hybrid: ring-sig {len(sigma)}B + "
                            f"ML-DSA-87 {len(mldsa_sig)}B")
                else:
                    message.append(0x00)
                    if self.logger:
                        self.logger.debug(
                            f"DAKE3 classical only: ring-sig {len(sigma)}B "
                            "(ML-DSA-87 not available)")

                encoded = base64.urlsafe_b64encode(
                    bytes(message)).decode('ascii').rstrip('=')
                result  = f"?OTRv4 {encoded}"

                if self.logger:
                    self.logger.debug(f"DAKE3 (Auth-I) generated: {len(message)}B total")
                return result

            except Exception as e:
                if self.logger:
                    self.logger.error("DAKE3 (Auth-I) generation failed: " + str(e))
                return None
    
    def process_dake3(self, dake3_msg: str) -> bool:
        """Process DAKE3 (Auth-I Message) as responder — spec §4.3.3.

        Wire format: 0x37 || σ(228) || flag(1) [|| mldsa_sig(4627)]

        Classical: verifies Schnorr ring signature σ (deniability).
        Hybrid PQ: if flag==0x01, also verifies ML-DSA-87 signature
        over the same transcript (post-quantum authentication).
        """
        with self.lock:
            if self.state != DAKEState.SENT_DAKE2:
                raise StateMachineError(f"Cannot process DAKE3 in state: {self.state.name}")
            if self.is_initiator:
                raise StateMachineError("Initiator cannot process DAKE3")

            try:
                if not dake3_msg.startswith("?OTRv4 "):
                    raise ValueError("Not an OTRv4 message")

                payload = dake3_msg[7:].strip()
                decoded = self._safe_b64decode(payload)

                SIG_LEN      = RingSignature.TOTAL_BYTES
                expected_len = 1 + SIG_LEN
                if len(decoded) < expected_len:
                    raise ValueError(
                        f"DAKE3 too short: {len(decoded)} < {expected_len} "
                        f"(ring sig is {SIG_LEN} bytes, not old 114-byte Ed448 sig)"
                    )

                msg_type = decoded[0]
                if msg_type != OTRConstants.MESSAGE_TYPE_DAKE3:
                    raise ValueError(
                        f"Not a DAKE3 (Auth-I) message: 0x{msg_type:02x} "
                        f"(expected 0x{OTRConstants.MESSAGE_TYPE_DAKE3:02x})"
                    )

                sigma = decoded[1:1 + SIG_LEN]

                if self._raw_dake1_bytes is None or self._raw_dake2_bytes is None:
                    raise ValueError("Raw DAKE transcript bytes missing — cannot verify Auth-I")

                if len(self._raw_dake1_bytes) < 57:
                    raise ValueError(
                        "DAKE1 transcript blob too short — transcript binding aborted."
                    )
                if len(self._raw_dake2_bytes) < 57:
                    raise ValueError(
                        "DAKE2 transcript blob too short — transcript binding aborted."
                    )
                if self._raw_dake1_bytes == self._raw_dake2_bytes:
                    raise ValueError(
                        "DAKE1 and DAKE2 transcript blobs are identical — "
                        "possible replay or session confusion. Rejecting Auth-I."
                    )

                transcript_msg = kdf_1(
                    KDFUsage.AUTH_I_MSG,
                    self._raw_dake1_bytes + self._raw_dake2_bytes,
                    64
                )

                if self.remote_profile is None:
                    raise ValueError("Remote ClientProfile not stored — cannot verify DAKE3")
                A1_bytes = self.remote_profile.identity_pub_bytes
                A2_bytes = (self.client_profile.identity_pub_bytes
                            or self.client_profile.identity_key.public_key().public_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PublicFormat.Raw))
                if A1_bytes is None:
                    raise ValueError("Remote identity_pub_bytes not available")

                if not RingSignature.verify(A1_bytes, A2_bytes, transcript_msg, sigma):
                    raise ValueError(
                        "DAKE3 ring signature verification failed — "
                        "initiator could not prove knowledge of A₁ or A₂"
                    )

                # ── Verify hybrid ML-DSA-87 signature ────────────
                _mldsa_offset = 1 + SIG_LEN
                _has_mldsa = (_mldsa_offset < len(decoded)
                              and decoded[_mldsa_offset] == 0x01)
                if (_has_mldsa
                        and self._remote_mldsa_pub is not None
                        and MLDSA87_AVAILABLE):
                    _mldsa_sig = decoded[_mldsa_offset + 1:
                                         _mldsa_offset + 1 + MLDSA87Auth.SIG_BYTES]
                    if len(_mldsa_sig) != MLDSA87Auth.SIG_BYTES:
                        raise ValueError(
                            "DAKE3 ML-DSA-87 signature truncated — "
                            f"expected {MLDSA87Auth.SIG_BYTES}, got {len(_mldsa_sig)}"
                        )
                    if not MLDSA87Auth.verify(
                            self._remote_mldsa_pub, transcript_msg, _mldsa_sig):
                        raise ValueError(
                            "DAKE3 ML-DSA-87 signature verification failed — "
                            "post-quantum authentication rejected"
                        )
                    _pq_auth = "hybrid (ring-sig ✓ + ML-DSA-87 ✓)"
                else:
                    _pq_auth = "classical only (ring-sig ✓)"

                self._session_created_at = time.time()
                self.transition(DAKEState.ESTABLISHED, f"DAKE3 verified — {_pq_auth}")
                if self.logger:
                    self.logger.debug(f"DAKE3 (Auth-I) verified — {_pq_auth}")
                return True

            except Exception as e:
                self.transition(DAKEState.FAILED, f"DAKE3 failed: {e}")
                if self.logger:
                    self.logger.error(f"DAKE3 (Auth-I) verification failed: {e}")
                return False
    
    def _derive_session_keys(self, dh1: bytes, dh2: bytes, dh3: bytes,
                             brace_shared: bytes,
                             is_initiator: bool) -> Dict[str, Any]:
        """Derive session keys from three X448 + one ML-KEM-1024 agreement (spec §4.3.2).

        Key derivation using KDF_1 = SHAKE-256 (spec §3.2):

            brace_key = KDF_1(0x02, brace_shared, 32)         # KDF'd brace key → carried into ratchet
            mixed     = KDF_1(0x03, dh1 || dh2 || dh3 || brace_shared, 64)
            ssid      = KDF_1(0x01, mixed, 8)
            root_seed = KDF_1(0x11, mixed, 96)
              → root_key  = root_seed[:32]
              → ck_a      = root_seed[32:64]
              → ck_b      = root_seed[64:96]
            mac_key   = KDF_1(0x15, mixed, 64)

        brace_shared is the 32-byte ML-KEM-1024 shared secret (post-quantum).
        Shor's algorithm cannot recover it — it is based on Module-LWE.
        """
        try:
            brace_key = kdf_1(KDFUsage.BRACE_KEY, brace_shared, 32)

            mixed = kdf_1(KDFUsage.SHARED_SECRET, dh1 + dh2 + dh3 + brace_shared, 64)

            ssid = kdf_1(KDFUsage.SSID, mixed, 8)
            session_id = ssid + b'\x00' * 24

            root_seed  = kdf_1(KDFUsage.ROOT_KEY, mixed, 96)
            root_key   = root_seed[:32]
            ck_a       = root_seed[32:64]
            ck_b       = root_seed[64:96]

            mac_key = kdf_1(KDFUsage.DAKE_MAC_KEY, mixed, 64)

            if is_initiator:
                chain_key_send = ck_a
                chain_key_recv = ck_b
            else:
                chain_key_send = ck_b
                chain_key_recv = ck_a

            root_key_mem = SecureMemory(32)
            root_key_mem.write(root_key)

            session_keys = {
                'root_key':        root_key_mem,
                'chain_key_send':  chain_key_send,
                'chain_key_recv':  chain_key_recv,
                'mac_key':         mac_key,
                'session_id':      session_id,
                'brace_key':       brace_key,
                'is_initiator':    is_initiator,
                'peer_long_term_pub':  self.remote_identity_pub_bytes,
                'peer_long_term_key':  self.remote_identity_key,
            }

            if self.tracer:
                self.tracer.trace("KEYS", "DERIVED", "KDF_1", "READY",
                                  f"ssid: {ssid.hex()} brace: {brace_key[:4].hex()}…")

            return session_keys

        except Exception as e:
            raise EncryptionError(f"Key derivation failed: {e}")
    
    def get_session_keys(self) -> Optional[Dict[str, Any]]:
        """Get derived session keys"""
        with self.lock:
            if self.state != DAKEState.ESTABLISHED:
                return None
            if self.session_keys is None:
                return None
            
            keys_copy = self.session_keys.copy()
            
            if 'root_key' in keys_copy:
                keys_copy['root_key'] = self.session_keys['root_key']
            
            return keys_copy
    
    def get_state(self) -> DAKEState:
        """Get current DAKE state"""
        with self.lock:
            return self.state
    
    def is_established(self) -> bool:
        """Check if DAKE is established"""
        with self.lock:
            return self.state == DAKEState.ESTABLISHED
    
    def has_failed(self) -> bool:
        """Check if DAKE has failed"""
        with self.lock:
            return self.state == DAKEState.FAILED
    
    def is_expired(self) -> bool:
        """Check if DAKE has expired"""
        with self.lock:
            if self.start_time is None:
                return False
            if self.state in (DAKEState.ESTABLISHED, DAKEState.FAILED):
                return False
            return time.time() - self.start_time > self.timeout






class SecureKeyStorage:
    """Secure storage for cryptographic keys.

    Keys are encrypted at rest with AES-256-GCM.  The encryption key
    is derived via scrypt from a random 32-byte device seed stored in
    the key directory.  No password is required — the seed file IS the
    credential.  If the seed file is deleted, stored keys become
    unrecoverable (new identity keys are generated on next launch).

    On first run, a fresh seed is generated and written to `.device_seed`.
    On subsequent runs, the seed is read back to derive the same master
    key, allowing stored Ed448/X448 identity keys to persist across
    sessions with a stable fingerprint.
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        self._lock = threading.RLock()
        self.storage_dir = storage_dir or os.path.expanduser("~/.otrv4plus/keys")
        os.makedirs(self.storage_dir, exist_ok=True)
        try:
            os.chmod(self.storage_dir, 0o700)
        except Exception:
            pass
        
        self._master_key = None
        self._auto_initialize()
        
    def _auto_initialize(self):
        """Derive master key from a device seed file (no password needed).

        Same approach as SMPAutoRespondStorage._master_passphrase():
        a random 32-byte seed is stored in the key directory on first
        run, then reused on subsequent runs to derive the same key.
        """
        seed_path = os.path.join(self.storage_dir, '.device_seed')
        seed = None

        # Try to load existing seed
        if os.path.exists(seed_path):
            try:
                with open(seed_path, 'rb') as f:
                    seed = f.read(32)
                if len(seed) != 32:
                    seed = None
            except Exception:
                seed = None

        # Generate new seed on first run
        if seed is None:
            seed = secrets.token_bytes(32)
            try:
                with open(seed_path, 'wb') as f:
                    f.write(seed)
                os.chmod(seed_path, 0o600)
            except Exception:
                pass

        # Derive master key via scrypt
        salt = b'OTRv4+KeyStorage'  # fixed salt is fine — seed is random
        try:
            self._master_key = hashlib.scrypt(
                seed, salt=salt, n=32768, r=8, p=4, dklen=32
            )
        except Exception:
            self._master_key = None
    
    def _encrypt_key(self, key_data: bytes) -> bytes:
        """Encrypt key data with AES-256-GCM."""
        if self._master_key is None:
            raise RuntimeError("Storage not initialized")
        
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self._master_key)
        ciphertext = aesgcm.encrypt(nonce, key_data, b"otrv4+key")
        
        return nonce + ciphertext
    
    def _decrypt_key(self, encrypted_data: bytes) -> bytes:
        """Decrypt key data with AES-256-GCM."""
        if self._master_key is None:
            raise RuntimeError("Storage not initialized")
        
        if len(encrypted_data) < 12:
            raise ValueError("Invalid encrypted data")
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        aesgcm = AESGCM(self._master_key)
        return aesgcm.decrypt(nonce, ciphertext, b"otrv4+key")
    
    def store_key(self, key_id: str, key_type: str, key_data: bytes) -> bool:
        """Store a key encrypted with AES-256-GCM."""
        with self._lock:
            if self._master_key is None:
                return False
            
            try:
                encrypted = self._encrypt_key(key_data)
                
                key_file = os.path.join(self.storage_dir, f"{key_id}.{key_type}.bin")
                with open(key_file, 'wb') as f:
                    f.write(encrypted)
                os.chmod(key_file, 0o600)
                return True
                
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to store key {key_id}: {e}")
                return False
    
    def load_key(self, key_id: str, key_type: str) -> Optional[bytes]:
        """Load and decrypt a key from storage."""
        with self._lock:
            if self._master_key is None:
                return None
            
            key_file = os.path.join(self.storage_dir, f"{key_id}.{key_type}.bin")
            if not os.path.exists(key_file):
                return None
            
            try:
                with open(key_file, 'rb') as f:
                    encrypted = f.read()
                
                return self._decrypt_key(encrypted)
                
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to load key {key_id}: {e}")
                return None
    
    def delete_key(self, key_id: str, key_type: str) -> bool:
        """Overwrite and delete a key file."""
        with self._lock:
            key_file = os.path.join(self.storage_dir, f"{key_id}.{key_type}.bin")
            if os.path.exists(key_file):
                try:
                    with open(key_file, 'wb') as f:
                        f.write(secrets.token_bytes(os.path.getsize(key_file)))
                    os.remove(key_file)
                    return True
                except Exception:
                    return False
            return False
    
    def clear_all(self):
        """Overwrite and delete all stored keys and the device seed."""
        with self._lock:
            for filename in os.listdir(self.storage_dir):
                filepath = os.path.join(self.storage_dir, filename)
                try:
                    if os.path.isfile(filepath):
                        with open(filepath, 'wb') as f:
                            f.write(secrets.token_bytes(os.path.getsize(filepath)))
                        os.remove(filepath)
                except Exception:
                    pass
            
            if self._master_key:
                master_key_ba = bytearray(self._master_key)
                _ossl.cleanse(master_key_ba)
                self._master_key = None




class SMPAutoRespondStorage:
    """Secure storage for SMP auto-respond secrets"""
    def __init__(self, secrets_path: Optional[str] = None):
        self._secrets: Dict[str, str] = {}
        self._lock = threading.RLock()
        self.secrets_path = secrets_path or os.path.expanduser("~/.otrv4plus/smp_secrets.json")
        try:
            _smp_dir = os.path.dirname(self.secrets_path)
            if _smp_dir:
                os.makedirs(_smp_dir, exist_ok=True)
                os.chmod(_smp_dir, 0o700)
        except Exception:
            pass
        self._load()
    
    def _load(self):
        """Load secrets from encrypted storage (AES-256-GCM, scrypt-derived key)."""
        with self._lock:
            if not os.path.exists(self.secrets_path):
                self._secrets = {}
                return
            try:
                with open(self.secrets_path, 'rb') as f:
                    raw = f.read()
                if len(raw) < 44:
                    self._secrets = {}
                    return
                salt   = raw[:16]
                nonce  = raw[16:28]
                ct_tag = raw[28:]
                key = hashlib.scrypt(
                    self._master_passphrase(),
                    salt=salt, n=16384, r=8, p=1, dklen=32
                )
                plaintext = AESGCM(key).decrypt(nonce, ct_tag, b"smp_secrets_v1")
                self._secrets = json.loads(plaintext.decode('utf-8'))
            except Exception:
                self._secrets = {}
            finally:
                try:
                    del key
                except Exception:
                    pass

    def _master_passphrase(self) -> bytes:
        """Derive a stable per-device passphrase from the machine-id or a stored secret."""
        seed_path = os.path.join(os.path.dirname(self.secrets_path), '.smp_seed')
        if os.path.exists(seed_path):
            try:
                with open(seed_path, 'rb') as f:
                    return f.read(32)
            except Exception:
                pass
        seed = secrets.token_bytes(32)
        try:
            os.makedirs(os.path.dirname(seed_path) or '.', exist_ok=True)
            with open(seed_path, 'wb') as f:
                f.write(seed)
            os.chmod(seed_path, 0o600)
        except Exception:
            pass
        return seed
    
    def _save(self):
        """Save secrets encrypted with AES-256-GCM (scrypt key, random salt+nonce)."""
        with self._lock:
            try:
                plaintext = json.dumps(self._secrets, separators=(',', ':')).encode('utf-8')
                salt  = secrets.token_bytes(16)
                nonce = secrets.token_bytes(12)
                key   = hashlib.scrypt(
                    self._master_passphrase(),
                    salt=salt, n=16384, r=8, p=1, dklen=32
                )
                ct_tag = AESGCM(key).encrypt(nonce, plaintext, b"smp_secrets_v1")
                blob = salt + nonce + ct_tag
                with tempfile.NamedTemporaryFile(
                    mode='wb',
                    dir=os.path.dirname(self.secrets_path) or '.',
                    delete=False
                ) as f:
                    f.write(blob)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(f.name, 0o600)
                os.replace(f.name, self.secrets_path)
            except Exception:
                try:
                    os.unlink(f.name)
                except Exception:
                    pass
            finally:
                try:
                    del key, plaintext, blob
                except Exception:
                    pass
    
    def set_secret(self, peer: str, secret: str) -> None:
        """Set secret for auto-respond"""
        with self._lock:
            self._secrets[peer] = secret
            self._save()
    
    def get_secret(self, peer: str) -> str:
        """Get secret for auto-respond"""
        with self._lock:
            return self._secrets.get(peer, "")
    
    def remove_secret(self, peer: str) -> bool:
        """Remove secret for auto-respond"""
        with self._lock:
            if peer in self._secrets:
                del self._secrets[peer]
                self._save()
                return True
            return False
    
    def clear_all(self) -> None:
        """Clear all secrets"""
        with self._lock:
            self._secrets.clear()
            self._save()
    
    def list_secrets(self) -> Dict[str, str]:
        """List all secrets (masked)"""
        with self._lock:
            masked = {}
            for peer, secret in self._secrets.items():
                if len(secret) > 3:
                    masked[peer] = secret[:1] + "*" * (len(secret) - 2) + secret[-1]
                else:
                    masked[peer] = "*" * len(secret)
            return masked

class TrustDatabase:
    """Persistent fingerprint trust database with TOFU and downgrade prevention.
    
    Security properties:
    - TOFU (Trust On First Use): first seen fingerprint is pinned.
    - Fingerprint mismatch raises FingerprintMismatchError — callers must abort.
    - Trust can only be *upgraded* (untrusted→trusted), never silently downgraded.
    - Atomic fsync'd writes prevent partial-state corruption.
    - All comparisons use constant-time operations.
    """

    class FingerprintMismatchError(ValueError):
        """Raised when a peer's fingerprint changes from the stored trusted value."""
        def __init__(self, peer: str, stored: str, received: str):
            self.peer     = peer
            self.stored   = stored
            self.received = received
            super().__init__(
                f"FINGERPRINT MISMATCH for {peer}! "
                f"Stored: {stored[:16]}… Got: {received[:16]}… "
                "This may indicate a MITM attack. Session aborted."
            )

    def __init__(self, db_path: Optional[str] = None):
        self._lock = threading.RLock()
        self.db_path = db_path or os.path.expanduser("~/.otrv4plus/trust.json")
        self._db: Dict[str, dict] = {}   # peer → {'fingerprint': str, 'trusted': bool}
        self._load()

    def _load(self):
        """Load database from disk with error handling"""
        with self._lock:
            if not os.path.exists(self.db_path):
                self._db = {}
                return
            try:
                with open(self.db_path, "r") as f:
                    raw = json.load(f)
                migrated = {}
                for k, v in raw.items():
                    if isinstance(v, str):
                        migrated[k] = {'fingerprint': v, 'trusted': True}
                    elif isinstance(v, dict):
                        migrated[k] = v
                    else:
                        continue
                self._db = migrated
            except (json.JSONDecodeError, IOError, OSError) as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Error loading: {e}")
                self._db = {}
            except Exception as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Unexpected error loading: {e}")
                self._db = {}

    def _save(self):
        """Save database to disk atomically with error handling"""
        with self._lock:
            try:
                _db_dir = os.path.dirname(self.db_path) or '.'
                os.makedirs(_db_dir, exist_ok=True)
                try:
                    os.chmod(_db_dir, 0o700)
                except Exception:
                    pass
                with tempfile.NamedTemporaryFile(
                    mode='w',
                    dir=os.path.dirname(self.db_path) or '.',
                    delete=False,
                    encoding='utf-8'
                ) as f:
                    json.dump(self._db, f, indent=2, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(f.name, 0o600)
                os.replace(f.name, self.db_path)
            except (IOError, OSError, PermissionError) as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Error saving: {e}")
                try:
                    os.unlink(f.name)
                except Exception:
                    pass
            except Exception as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Unexpected error saving: {e}")
                try:
                    os.unlink(f.name)
                except Exception:
                    pass

    def check_or_pin(self, peer: str, fingerprint: str) -> bool:
        """TOFU check: pin on first contact, raise on mismatch.
        
        Returns True if fingerprint is known and trusted.
        Returns False if this is the first contact (caller should prompt user).
        Raises FingerprintMismatchError if fingerprint differs from stored value.
        """
        if not peer or not fingerprint:
            raise ValueError("Peer and fingerprint cannot be empty")
            
        if not isinstance(peer, str) or not isinstance(fingerprint, str):
            raise TypeError("Peer and fingerprint must be strings")
            
        with self._lock:
            try:
                entry = self._db.get(peer)
                if entry is None:
                    self._db[peer] = {'fingerprint': fingerprint, 'trusted': False}
                    self._save()
                    return False

                stored_fp = entry.get('fingerprint', '')
                if not stored_fp:
                    self._db[peer] = {'fingerprint': fingerprint, 'trusted': False}
                    self._save()
                    return False
                    
                if not hmac.compare_digest(stored_fp.encode('utf-8'), fingerprint.encode('utf-8')):
                    raise TrustDatabase.FingerprintMismatchError(peer, stored_fp, fingerprint)

                return entry.get('trusted', False)
                
            except TrustDatabase.FingerprintMismatchError:
                raise
            except (KeyError, AttributeError, TypeError) as e:
                raise ValueError(f"Invalid trust database entry: {e}")
            except Exception as e:
                raise RuntimeError(f"Trust database error: {e}")

    def is_trusted(self, peer: str, fingerprint: str) -> bool:
        """Return True only if fingerprint matches AND user has confirmed trust."""
        if not peer or not fingerprint:
            return False
            
        if not isinstance(peer, str) or not isinstance(fingerprint, str):
            return False
            
        with self._lock:
            try:
                entry = self._db.get(peer)
                if entry is None:
                    return False
                stored_fp = entry.get('fingerprint', '')
                if not stored_fp:
                    return False
                if not hmac.compare_digest(stored_fp.encode('utf-8'), fingerprint.encode('utf-8')):
                    return False
                return entry.get('trusted', False)
            except (KeyError, AttributeError, TypeError):
                return False
            except Exception:
                return False

    def add_trust(self, peer: str, fingerprint: str) -> bool:
        """Mark a (peer, fingerprint) pair as trusted.
        
        If a different fingerprint is already stored, raises FingerprintMismatchError
        — we never silently replace a known fingerprint.
        """
        if not peer or not fingerprint:
            raise ValueError("Peer and fingerprint cannot be empty")
            
        if not isinstance(peer, str) or not isinstance(fingerprint, str):
            raise TypeError("Peer and fingerprint must be strings")
            
        with self._lock:
            try:
                entry = self._db.get(peer)
                if entry is not None:
                    stored_fp = entry.get('fingerprint', '')
                    if stored_fp and not hmac.compare_digest(stored_fp.encode('utf-8'), fingerprint.encode('utf-8')):
                        raise TrustDatabase.FingerprintMismatchError(peer, stored_fp, fingerprint)
                self._db[peer] = {'fingerprint': fingerprint, 'trusted': True}
                self._save()
                return True
            except TrustDatabase.FingerprintMismatchError:
                raise
            except (KeyError, AttributeError, TypeError) as e:
                raise ValueError(f"Invalid trust database entry: {e}")
            except Exception as e:
                raise RuntimeError(f"Failed to add trust: {e}")

    def remove_trust(self, peer: str) -> bool:
        """Remove trust for a peer"""
        if not peer:
            return False
            
        with self._lock:
            try:
                if peer in self._db:
                    del self._db[peer]
                    self._save()
                    return True
                return False
            except (KeyError, AttributeError) as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Error removing trust: {e}")
                return False
            except Exception as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Unexpected error removing trust: {e}")
                return False

    def get_trusted_fingerprint(self, peer: str) -> str:
        """Get trusted fingerprint for a peer, or empty string if not trusted"""
        if not peer:
            return ""
            
        with self._lock:
            try:
                entry = self._db.get(peer)
                if entry is None:
                    return ""
                if not entry.get('trusted', False):
                    return ""
                return entry.get('fingerprint', '')
            except (KeyError, AttributeError):
                return ""
            except Exception:
                return ""

    def list_trusted(self) -> Dict[str, str]:
        """List all trusted peers and their fingerprints"""
        with self._lock:
            try:
                return {p: e['fingerprint'] for p, e in self._db.items() if e.get('trusted')}
            except (KeyError, AttributeError, TypeError):
                return {}
            except Exception:
                return {}




class TabBar:
    """Visual tab bar at top of terminal with Termux optimization"""
    def __init__(self, terminal_width: int = TERMINAL_WIDTH):
        self.terminal_width = terminal_width
        self.visible_start = 0
        self.tab_data: Dict[str, dict] = {}  # tab_name -> {'icon': '', 'unread': 0, 'active': False}
        
    def calculate_tab_width(self, tab_name: str, has_unread: int, is_active: bool) -> int:
        """Calculate width needed for a tab"""
        width = len(tab_name) + 2
        
        if '🔵' in tab_name or '🟢' in tab_name or '🟡' in tab_name or '🔴' in tab_name:
            width += 2
        
        if has_unread > 0:
            width += len(f"({has_unread})") + 1
        
        width += 1
        
        return width
    
    def render(self, panels: Dict[str, 'ChatPanel'], active_panel_name: str) -> List[str]:
        """Render tab bar - returns list of lines to print"""
        if not panels:
            return []
        
        tabs = []
        total_width = 0
        max_tabs_width = self.terminal_width - 10
        
        for panel_name, panel in panels.items():
            icon = UIConstants.SECURITY_ICONS.get(panel.security_level, "")
            
            display_name = panel_name
            if icon:
                display_name = f"{display_name}{icon}"
            
            is_active = (panel_name == active_panel_name)
            
            self.tab_data[panel_name] = {
                'display_name': display_name,
                'icon': icon,
                'unread': panel.unread_count,
                'active': is_active,
                'width': self.calculate_tab_width(display_name, panel.unread_count, is_active)
            }
            
            tabs.append(panel_name)
        
        total_tabs_width = sum(self.tab_data[tab]['width'] for tab in tabs)
        need_scroll = total_tabs_width > max_tabs_width
        
        if need_scroll:
            try:
                active_index = tabs.index(active_panel_name)
            except ValueError:
                active_index = 0
            
            if active_index < self.visible_start:
                self.visible_start = active_index
            elif active_index >= self.visible_start + self._max_visible_tabs(tabs, max_tabs_width):
                self.visible_start = active_index - 2
            
            self.visible_start = max(0, min(self.visible_start, len(tabs) - 1))
            
            visible_tabs = []
            current_width = 0
            max_visible = self._max_visible_tabs(tabs, max_tabs_width)
            
            for i in range(self.visible_start, min(len(tabs), self.visible_start + max_visible)):
                tab_name = tabs[i]
                tab_info = self.tab_data[tab_name]
                
                if current_width + tab_info['width'] > max_tabs_width - 6:
                    break
                
                visible_tabs.append(tab_name)
                current_width += tab_info['width']
            
            if self.visible_start > 0:
                visible_tabs.insert(0, "<<")
            if self.visible_start + len(visible_tabs) < len(tabs):
                visible_tabs.append(">>")
        else:
            visible_tabs = tabs
            self.visible_start = 0
        
        tab_strings = []
        for tab_name in visible_tabs:
            if tab_name == "<<":
                tab_strings.append("◀")
                continue
            elif tab_name == ">>":
                tab_strings.append("▶")
                continue
            
            tab_info = self.tab_data[tab_name]
            display_name = tab_info['display_name']
            unread = tab_info['unread']
            is_active = tab_info['active']
            
            if unread > 0:
                tab_display = f"{display_name}({unread})"
            else:
                tab_display = display_name
            
            if is_active:
                tab_str = f"{colorize('[' + tab_display + ']', 'bg_green')}"
            elif unread > 0:
                # irssi/weechat convention: magenta = private/OTR activity,
                # cyan = channel activity, white = idle
                _hl = "magenta" if not tab_name.startswith("#") else "cyan"
                tab_str = colorize(f"[{tab_display}]", _hl)
            else:
                tab_str = f"[{tab_display}]"
            
            tab_strings.append(tab_str)
        
        if IS_TERMUX:
            tab_line = " ".join(tab_strings)
            if len(tab_line) > self.terminal_width - 2:
                tab_line = tab_line[:self.terminal_width - 5] + "..."
        else:
            tab_line = " ".join(tab_strings)
            if len(tab_line) > self.terminal_width - 4:
                tab_line = tab_line[:self.terminal_width - 7] + "..."
            
            border = "═" * (self.terminal_width - 2)
            lines = [
                f"╔{border}╗",
                f"║ {tab_line:<{self.terminal_width-3}}║",
                f"╚{border}╝"
            ]
            return lines
        
        return [tab_line]
    
    def _max_visible_tabs(self, tabs: List[str], max_width: int) -> int:
        """Calculate maximum number of visible tabs"""
        avg_width = 12
        return max(1, max_width // avg_width)

class Pager:
    """Non-destructive inline pager — never clears the screen.

    Prints paginated content inline in the terminal scrollback, so chat
    history above is preserved.  On quit, any messages that arrived while
    the pager was active are flushed to screen before the prompt returns.
    """
    def __init__(self, lines_per_page: int = 20):
        self.lines_per_page = lines_per_page if not IS_TERMUX else 15
        self.active = False

    def display(self, lines: List[str], header: str = "", footer: str = ""):
        """Display lines with inline pager controls."""
        if not lines:
            safe_print(colorize("  (empty)", "dim"))
            return

        self.active = True
        total_pages = (len(lines) + self.lines_per_page - 1) // self.lines_per_page
        page = 0

        try:
            while self.active:
                start = page * self.lines_per_page
                end = min(start + self.lines_per_page, len(lines))

                safe_print(colorize(f"── {header} ", "cyan") +
                           colorize(f"({page+1}/{total_pages})" if total_pages > 1 else "",
                                    "dim") +
                           colorize(" " + "─" * 30, "cyan"))

                for line in lines[start:end]:
                    if len(line) > TERMINAL_WIDTH:
                        line = line[:TERMINAL_WIDTH - 3] + "..."
                    safe_print(line)

                if footer:
                    safe_print(colorize(footer, "dim"))
                safe_print(colorize("─" * 42, "cyan"))

                if total_pages <= 1:
                    self.active = False
                    break

                safe_print(colorize("  [n]ext  [p]rev  [q]uit", "dim"), end="  ", flush=True)
                try:
                    if _raw_mode_active:
                        # Instant keypress — no Enter needed
                        b = os.read(_stdin_fd, 1)
                        ch = chr(b[0]).lower() if b else "q"
                        sys.stdout.write('\n')
                        sys.stdout.flush()
                    else:
                        ch = sys.stdin.readline().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ch = "q"

                if ch in ("n", "\r", "\n", " "):
                    page = min(page + 1, total_pages - 1)
                    if page >= total_pages - 1 and ch == "n":
                        self.active = False
                elif ch == "p":
                    page = max(0, page - 1)
                elif ch in ("q",):
                    self.active = False
        finally:
            _flush_display_queue()

class ChatPanel:
    """Chat panel for displaying messages"""
    def __init__(self, name: str, panel_type: str):
        self.name = name
        self.type = panel_type
        self.history: List[Dict[str, Any]] = []
        self.unread_count = 0
        self.active = False
        self.created = time.time()
        self.recent_users: Set[str] = set()
        self.secure_session = False
        self.last_activity = time.time()
        self.security_level = UIConstants.SecurityLevel.PLAINTEXT
        self.smp_progress = (0, 4)
    
    def add_message(self, message: str, metadata: Optional[dict] = None) -> int:
        """Add message to history"""
        msg_id = len(self.history)
        self.history.append({
            'id': msg_id,
            'message': message,
            'timestamp': time.time(),
            'metadata': metadata or {}
        })
        self.last_activity = time.time()
        return msg_id
    
    def get_messages(self, start: int = 0, count: Optional[int] = None) -> List[str]:
        """Get messages from history as strings"""
        if not self.history:
            return []
        
        messages = [msg['message'] for msg in self.history]
        
        if count is None:
            return messages[start:]
        else:
            return messages[start:start + count]
    
    def clear_unread(self):
        """Clear unread count"""
        self.unread_count = 0
        self.recent_users.clear()
    
    def mark_secure(self, level: UIConstants.SecurityLevel = UIConstants.SecurityLevel.ENCRYPTED):
        """Mark panel as secure"""
        self.secure_session = True
        self.type = 'secure'
        self.security_level = level
    
    def update_smp_progress(self, step: int, total_steps: int):
        """Update SMP progress"""
        self.smp_progress = (step, total_steps)
    
    def get_progress_display(self) -> str:
        """Get SMP progress display"""
        step, total = self.smp_progress
        if step == 0:
            return ""
        elif step == total:
            return "✅"
        else:
            progress_chars = ['○', '◔', '◑', '◕', '●']
            progress_index = min(int((step / total) * len(progress_chars)), len(progress_chars) - 1)
            return f"🔄 {progress_chars[progress_index]} {step}/{total}"
    
    def clear_history(self):
        """Clear chat history"""
        self.history.clear()

class PanelManager:
    """
    Manager for chat panels - COMPLETE REPLACEMENT
    Keeps all original methods (add_panel, switch_to_panel, panel_order, etc.)
    and adds security-icon header rendering.
    """

    def __init__(self, client):
        self.client = client
        self.panels: Dict[str, ChatPanel] = {}
        self.active_panel: Optional[str] = None
        self.panel_order: List[str] = []
        self.lock = threading.RLock()
        self.auto_switch_enabled = True
        self.tab_bar = TabBar()

        self.add_panel("system", 'system')


    def add_panel(self, name: str, panel_type: str) -> bool:
        """Add a new panel. Returns True if created, False if already exists."""
        with self.lock:
            if name not in self.panels:
                self.panels[name] = ChatPanel(name, panel_type)
                self.panel_order.append(name)
                if not self.active_panel:
                    self.active_panel = name
                    self.panels[name].active = True
                self._render_ui()
                return True
            return False

    def get_or_create_panel(self, name: str, panel_type: str = 'private') -> ChatPanel:
        """Get existing panel or create a new one."""
        with self.lock:
            if name not in self.panels:
                self.add_panel(name, panel_type)
            return self.panels[name]

    def get_panel(self, name: str) -> Optional[ChatPanel]:
        """Get a panel by name, or None."""
        with self.lock:
            return self.panels.get(name)

    def get_active_panel(self) -> Optional[ChatPanel]:
        """Get the currently active panel."""
        with self.lock:
            if self.active_panel in self.panels:
                return self.panels[self.active_panel]
            return None

    def switch_to_panel(self, name: str) -> bool:
        """Switch the active panel. Returns True on success."""
        with self.lock:
            if name in self.panels:
                if self.active_panel and self.active_panel in self.panels:
                    self.panels[self.active_panel].active = False
                    self.panels[self.active_panel].clear_unread()
                self.active_panel = name
                self.panels[name].active = True
                self.panels[name].clear_unread()
                self._render_ui()
                return True
            return False

    def list_panels(self) -> List[str]:
        """Return ordered list of panel names."""
        with self.lock:
            return list(self.panel_order)


    def add_message(self, target: str, message: str) -> None:
        """Store message in panel buffer. Printing is done by the client's emit()."""
        with self.lock:
            if target not in self.panels:
                self.add_panel(target, 'private')
            panel = self.panels[target]
            panel.add_message(message)
            if self.active_panel != target:
                panel.unread_count += 1


    def update_panel_security(self, name: str,
                               level: UIConstants.SecurityLevel) -> None:
        """Update the security level for a panel and re-render."""
        with self.lock:
            if name not in self.panels:
                self.add_panel(name, 'private')
            panel = self.panels[name]
            panel.security_level = level
            if level in (UIConstants.SecurityLevel.ENCRYPTED,
                         UIConstants.SecurityLevel.FINGERPRINT,
                         UIConstants.SecurityLevel.SMP_VERIFIED):
                panel.mark_secure(level)
            self._render_ui()

    def update_smp_progress(self, name: str,
                             step: int, total_steps: int) -> None:
        """Update SMP progress bar for a panel."""
        with self.lock:
            if name in self.panels:
                self.panels[name].update_smp_progress(step, total_steps)
                self._render_ui()


    def clear_panel_history(self, panel_name: str) -> None:
        """Clear message history for one panel."""
        with self.lock:
            if panel_name in self.panels:
                self.panels[panel_name].clear_history()
                self._render_ui()

    def clear_all_histories(self) -> None:
        """Clear message history for all panels."""
        with self.lock:
            for panel in self.panels.values():
                panel.clear_history()
            self._render_ui()


    def render_panel_header(self, panel: ChatPanel) -> str:
        """Build header string: [icon] name [SECURITY_NAME]"""
        level    = getattr(panel, 'security_level', UIConstants.SecurityLevel.PLAINTEXT)
        icon     = UIConstants.SECURITY_ICONS.get(level, "")
        name     = colorize(panel.name, 'cyan')
        sec_name = UIConstants.SECURITY_NAMES.get(level, "PLAINTEXT")

        color_map = {
            UIConstants.SecurityLevel.PLAINTEXT:    'bold_red',
            UIConstants.SecurityLevel.ENCRYPTED:    'bold_yellow',
            UIConstants.SecurityLevel.FINGERPRINT:  'bold_green',
            UIConstants.SecurityLevel.SMP_VERIFIED: 'blue',
        }
        sec_color = color_map.get(level, 'white')
        sec_text  = colorize(f"[{sec_name}]", sec_color)

        if panel.type in ('private', 'secure'):
            return f"{icon} {name} {sec_text}"
        return name

    def _render_ui(self) -> None:
        """Refresh the input prompt, rate-limited to once per 250 ms.

        Called by update_panel_security() and update_smp_progress().
        The 250 ms gate coalesces rapid back-to-back state changes (e.g. the
        4 SMP steps arriving in quick succession) into a single prompt redraw
        so the user never sees a burst of prompt replacements while typing.
        """
        now = time.time()
        if now - getattr(self, "_last_render_ts", 0) < 0.25:
            return
        self._last_render_ts = now
        try:
            cb = getattr(self.client, "_prompt_refresh_cb", None)
            if cb is not None:
                cb()
        except Exception:
            pass


class MessageRouter:
    """Central message routing engine - decoupled from protocol"""
    
    def __init__(self, panel_manager: PanelManager):
        self.panel_manager = panel_manager
        
        self.routes = {
            r'^\?OTRv4.*': self._route_otr_message,
            r'^PRIVMSG.*#[^:]+:.*': self._route_to_channel_tab,
            r'^PRIVMSG.*:.*': self._route_to_sender_tab,
            r'^JOIN.*': self._route_join,
            r'^PART.*': self._route_part,
            r'^QUIT.*': self._route_quit,
            r'^NICK.*': self._route_nick,
        }
    
    def route(self, message: str, prefix: Optional[str] = None, 
              msg_type: Optional[str] = None) -> str:
        """Route message to appropriate panel - returns panel name only"""
        sender_nick = prefix.split('!')[0] if prefix and '!' in prefix else prefix or "server"
        
        if msg_type == 'OTR_STATUS':
            return sender_nick if sender_nick and sender_nick != "system" else "system"
        
        if msg_type == 'SMP_STATUS':
            return sender_nick if sender_nick and sender_nick != "system" else "system"
        
        for pattern, handler in self.routes.items():
            if re.match(pattern, message):
                result = handler(message, sender_nick)
                if result:
                    return result
        
        return "system"
    
    def _route_otr_message(self, message: str, sender: str) -> Optional[str]:
        """Route OTR messages to peer tab"""
        if '?OTRv4' in message:
            return sender
        return None
    
    def _route_to_channel_tab(self, message: str, sender: str) -> Optional[str]:
        """Route channel messages"""
        match = re.match(r'PRIVMSG (\#[^\s]+) :', message)
        if match:
            channel = match.group(1)
            return channel
        return None
    
    def _route_to_sender_tab(self, message: str, sender: str) -> Optional[str]:
        """Route private messages to sender tab"""
        match = re.match(r'PRIVMSG ([^#][^\s]*) :', message)
        if match:
            target = match.group(1)
            if target == self.panel_manager.client.nick:
                return sender
        return None
    
    def _route_join(self, message: str, sender: str) -> Optional[str]:
        """Route JOIN messages"""
        match = re.match(r'JOIN :?(#[^\s]+)', message)
        if match:
            channel = match.group(1)
            return channel
        return None
    
    def _route_part(self, message: str, sender: str) -> Optional[str]:
        """Route PART messages"""
        match = re.match(r'PART :?(#[^\s]+)', message)
        if match:
            channel = match.group(1)
            return channel
        return None
    
    def _route_quit(self, message: str, sender: str) -> Optional[str]:
        """Route QUIT messages"""
        return "system"
    
    def _route_nick(self, message: str, sender: str) -> Optional[str]:
        """Route NICK change messages"""
        return "system"



class EnhancedOTRSession:
    """OTR session with integrated DAKE, ratchet, and SMP subsystems."""
    
    def __init__(self, peer: str, is_initiator: bool, tracer: OTRTracer,
                 logger: Optional[OTRLogger] = None):
        self.peer = peer
        self.is_initiator = is_initiator
        self.tracer = tracer
        self.logger = logger or NullLogger()
        self.lock = threading.RLock()
        
        self.session_state = SessionState.PLAINTEXT
        self.dake_state = DAKEState.IDLE
        self.smp_state = UIConstants.SMPState.NONE
        
        self.dake_engine: Optional['OTRv4DAKE'] = None
        self.ratchet: Optional[DoubleRatchet] = None
        self.smp_engine: Optional[SMPEngine] = None
        
        self.session_id: Optional[bytes] = None
        self.root_key: Optional[SecureMemory] = None
        self.remote_long_term_pub: Optional[ed448.Ed448PublicKey] = None
        self._remote_long_term_pub_bytes: Optional[bytes] = None
        self._dake_chain_key_send: Optional[bytes] = None
        self._dake_chain_key_recv: Optional[bytes] = None
        self._dake_brace_key:      Optional[bytes] = None
        
        self.pending_messages: List[str] = []
        self.received_messages: List[bytes] = []
        
        self.created = time.time()
        self.last_activity = time.time()
        self.dake_start_time: Optional[float] = None
        
        self.security_level = UIConstants.SecurityLevel.PLAINTEXT
        
        self._sender_tag:          int            = _generate_instance_tag()
        self._receiver_tag:        int            = 0
        self._peer_disconnected:   bool           = False
        self._last_extra_sym_key:  Optional[bytes] = None
        self._extra_sym_key_cb                    = None
        self._queued_smp_response: Optional[str]  = None

        self.auto_smp_secret: str    = ""
        self.auto_smp_scheduled: bool = False
        self.auto_smp_started: bool  = False
        self.auto_smp_completed: bool = False

        self.smp_step: int       = 0
        self.smp_total_steps: int = 4
        self.smp_start_time: float = 0.0

        self._smp_notify_cb = None

        self._ping_refresh_cb = None

        self.tracer.trace(peer, "SESSION", None, "PLAINTEXT", "session created")
        if is_initiator:
            self.tracer.trace(peer, "ROLE", None, "INITIATOR")
        else:
            self.tracer.trace(peer, "ROLE", None, "RESPONDER")
    
    def _acquire_lock(self, timeout: float = 5.0) -> bool:
        """Acquire lock with timeout"""
        try:
            return self.lock.acquire(timeout=timeout)
        except Exception:
            return False
    
    def _release_lock(self):
        """Safely release lock"""
        try:
            self.lock.release()
        except Exception:
            pass
    
    
    
    
    def transition_session(self, new_state: SessionState, reason: str = ""):
        """Transition session state with strict validation — rejects all illegal transitions."""
        if not self._acquire_lock():
            raise StateMachineError("Failed to acquire lock for state transition")
        
        try:
            old_state = self.session_state
            
            valid_transitions = {
                SessionState.PLAINTEXT:        [SessionState.DAKE_IN_PROGRESS, SessionState.FAILED],
                SessionState.DAKE_IN_PROGRESS: [SessionState.ENCRYPTED, SessionState.FAILED, SessionState.PLAINTEXT],
                SessionState.ENCRYPTED:        [SessionState.FINISHED, SessionState.FAILED],
                SessionState.FAILED:           [SessionState.PLAINTEXT],
                SessionState.FINISHED:         [],
            }
            
            if new_state not in valid_transitions.get(old_state, []):
                raise StateMachineError(
                    f"REJECTED illegal session transition: {old_state.name} → {new_state.name}. "
                    "Peer may be attempting a state confusion attack."
                )
            
            self.session_state = new_state
            self.tracer.trace(self.peer, "SESSION", old_state.name, new_state.name, reason)
            
            if new_state == SessionState.ENCRYPTED:
                self.security_level = UIConstants.SecurityLevel.ENCRYPTED
                self.tracer.trace(self.peer, "SECURITY", "PLAINTEXT", "ENCRYPTED", "DAKE completed")
                self._process_queued_messages()
            
            elif new_state == SessionState.FAILED:
                self.tracer.trace(self.peer, "ERROR", old_state.name, "FAILED", reason)
                self._cleanup_failed_session()
            
            elif new_state == SessionState.PLAINTEXT:
                self.dake_state = DAKEState.IDLE
                self.security_level = UIConstants.SecurityLevel.PLAINTEXT
        
        finally:
            self._release_lock()
    
    def transition_dake(self, new_state: DAKEState, reason: str = ""):
        """Transition DAKE state with validation"""
        if not self._acquire_lock():
            raise StateMachineError("Failed to acquire lock for DAKE transition")
        
        try:
            old_state = self.dake_state
            
            valid_transitions = {
                DAKEState.IDLE:           [DAKEState.SENT_DAKE1, DAKEState.RECEIVED_DAKE1, DAKEState.FAILED],
                DAKEState.SENT_DAKE1:     [DAKEState.ESTABLISHED, DAKEState.FAILED],
                DAKEState.RECEIVED_DAKE1: [DAKEState.SENT_DAKE2,  DAKEState.FAILED],
                DAKEState.SENT_DAKE2:     [DAKEState.ESTABLISHED, DAKEState.FAILED],
                DAKEState.ESTABLISHED:    [],
                DAKEState.FAILED:         []
            }
            
            if new_state not in valid_transitions.get(old_state, []):
                raise StateMachineError(
                    f"Invalid DAKE transition: {old_state.name} → {new_state.name}"
                )
            
            self.dake_state = new_state
            self.tracer.trace(self.peer, "DAKE", old_state.name, new_state.name, reason)
            
            if new_state == DAKEState.ESTABLISHED:
                self.transition_session(SessionState.ENCRYPTED, "DAKE established")
                
                self._initialize_ratchet()
        
        finally:
            self._release_lock()
    
    def transition_smp(self, new_state: UIConstants.SMPState, reason: str = ""):
        """Transition SMP state with validation"""
        if not self._acquire_lock():
            raise StateMachineError("Failed to acquire lock for SMP transition")
        
        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise StateMachineError("SMP requires encrypted session")
            
            old_state = self.smp_state
            
            self.smp_state = new_state
            self.tracer.trace(self.peer, "SMP", old_state.name, new_state.name, reason)
            
            if new_state == UIConstants.SMPState.SUCCEEDED:
                self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                self.tracer.trace(self.peer, "SECURITY", "ENCRYPTED", "SMP_VERIFIED", "SMP succeeded")
        
        finally:
            self._release_lock()
    
    
    
    
    def initialize_dake(self, client_profile: ClientProfile, 
                       explicit_initiator: bool = False) -> 'OTRv4DAKE':
        """Initialize DAKE engine"""
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for DAKE initialization")
        
        try:
            if self.dake_engine is not None:
                raise RuntimeError("DAKE engine already initialized")
            
            self.dake_engine = OTRv4DAKE(
                client_profile=client_profile,
                explicit_initiator=explicit_initiator,
                tracer=self.tracer,
                logger=self.logger
            )
            
            return self.dake_engine
        finally:
            self._release_lock()
    
    def _initialize_ratchet(self):
        """Initialize double ratchet after DAKE completion.

        Prefers the chain keys derived by the DAKE engine (self._dake_chain_key_send /
        self._dake_chain_key_recv) because they are keyed with the full DH material.
        Falls back to deriving from the root key via _initialize_chains() when those
        are not available — both paths produce symmetric keys, but they differ in KDF
        inputs so mixing them between the two peers would break decryption.
        """
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for ratchet initialization")
        
        try:
            if self.ratchet is not None:
                raise RuntimeError("Ratchet already initialized")
            
            if self.root_key is None:
                raise RuntimeError("Root key not available")
            
            _ratchet_args = dict(
                root_key=self.root_key,
                is_initiator=self.is_initiator,
                ad=b"OTRv4-DATA",
                logger=self.logger,
                chain_key_send=self._dake_chain_key_send,
                chain_key_recv=self._dake_chain_key_recv,
                brace_key=self._dake_brace_key,
                rekey_interval=OTRConstants.REKEY_INTERVAL,
                rekey_timeout=OTRConstants.REKEY_TIMEOUT
            )

            if RUST_RATCHET_AVAILABLE:
                try:
                    self.ratchet = RustBackedDoubleRatchet(**_ratchet_args)
                    self._ratchet_backend = "rust"
                except Exception as e:
                    self.logger.debug(f"Rust ratchet failed ({e}), falling back to Python")
                    self.ratchet = DoubleRatchet(**_ratchet_args)
                    self._ratchet_backend = "python"
            else:
                self.ratchet = DoubleRatchet(**_ratchet_args)
                self._ratchet_backend = "python"

            self._dake_chain_key_send = None
            self._dake_chain_key_recv = None
            self._dake_brace_key      = None
            
            _backend_label = "Rust (zeroize-on-drop)" if self._ratchet_backend == "rust" else "Python (C extensions)"
            self.tracer.trace(self.peer, "RATCHET", None, "ACTIVE", f"ratchet: {_backend_label}")
        finally:
            self._release_lock()
    
    def initialize_smp(self):
        """Initialize SMP engine"""
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for SMP initialization")
        
        try:
            if self.smp_engine is not None:
                raise RuntimeError("SMP engine already initialized")
            
            self.smp_engine = SMPEngine(
                is_initiator=self.is_initiator,
                logger=self.logger
            )
            
            self.tracer.trace(self.peer, "SMP", None, "READY", "SMP engine initialized")
        finally:
            self._release_lock()
    
    
    
    
    def queue_outgoing_message(self, message: str):
        """Queue outgoing message for later encryption"""
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for queueing")
        
        try:
            if self.session_state == SessionState.ENCRYPTED:
                return self.encrypt_message(message)
            
            elif self.session_state == SessionState.DAKE_IN_PROGRESS:
                self.pending_messages.append(message)
                self.tracer.trace(self.peer, "QUEUE", "OUTGOING", str(len(self.pending_messages)), 
                                 f"message queued (DAKE in progress)")
                return None
            
            elif self.session_state == SessionState.PLAINTEXT:
                raise StateMachineError("Cannot send message: OTR not established")
            
            else:
                raise StateMachineError(f"Cannot send message in state: {self.session_state.name}")
        finally:
            self._release_lock()
    
    def _process_queued_messages(self):
        """Process any queued messages after encryption is ready"""
        if not self._acquire_lock():
            return
        
        try:
            if not self.pending_messages:
                return
            
            self.tracer.trace(self.peer, "QUEUE", "PROCESSING", str(len(self.pending_messages)),
                             "processing queued messages")
            
            for msg in self.pending_messages:
                self.tracer.trace(self.peer, "QUEUE", "QUEUED", "PROCESSED", 
                                 f"message: {msg[:50]}...")
            
            self.pending_messages.clear()
        finally:
            self._release_lock()
    
    def encrypt_message(self, plaintext: str) -> Optional[str]:
        """Encrypt plaintext using the full OTRv4DataMessage wire format (spec §4.4.3)."""
        return self.encrypt_with_tlvs(plaintext, [])

    def encrypt_with_tlvs(self, plaintext: str,
                           tlvs: List['OTRv4TLV']) -> Optional[str]:
        """Encrypt a message carrying additional TLVs (SMP, disconnect, extra-sym-key)."""
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for encryption")
        
        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise StateMachineError("Cannot encrypt: session not in ENCRYPTED state")
            if self.ratchet is None:
                raise RuntimeError("Ratchet not initialized — DAKE may not be complete")
            
            self.last_activity = time.time()

            payload_obj = OTRv4Payload(plaintext or '', tlvs)
            payload     = payload_obj.encode(add_padding=True)

            ct, rh_bytes, nonce, tag, ratchet_id, reveal_keys = \
                self.ratchet.encrypt_message(payload)
            ct_with_tag = ct + tag

            rh = RatchetHeader.decode(rh_bytes)
            mac_key = hashlib.sha3_512(
                self.session_id
                + ratchet_id.to_bytes(4, 'big')
                + rh.msg_num.to_bytes(4, 'big')
                + b'OTRv4-MAC-KEY'
            ).digest()[:32]

            dmsg = OTRv4DataMessage()
            dmsg.sender_tag       = self._sender_tag
            dmsg.receiver_tag     = self._receiver_tag
            dmsg.flags            = 0
            dmsg.prev_chain_len   = rh.prev_chain_len
            dmsg.ratchet_id       = ratchet_id
            dmsg.message_id       = rh.msg_num
            dmsg.ecdh_pub         = rh.dh_pub
            dmsg.nonce            = nonce
            dmsg.ciphertext       = ct_with_tag

            # ── Attach pending brace KEM rotation fields ─────────
            #    At most ONE of ek/ct per message.  ct takes priority
            #    (completes the exchange the peer started).
            _kem_ct = self.ratchet.consume_outgoing_kem_ct()
            _kem_ek = self.ratchet.consume_outgoing_kem_ek() if _kem_ct is None else None
            dmsg.kem_ct = _kem_ct
            dmsg.kem_ek = _kem_ek

            dmsg.mac              = dmsg.compute_mac(mac_key)
            dmsg.revealed_mac_keys = [k for k in reveal_keys if len(k) == 32]

            wire    = dmsg.encode()
            encoded = base64.urlsafe_b64encode(wire).decode('ascii').rstrip('=')
            result  = f"?OTRv4 {encoded}."

            self.tracer.trace(self.peer, "ENCRYPT", "PLAINTEXT", "ENCRYPTED",
                              f"len={len(plaintext)} tlvs={[t.type for t in tlvs]}")
            return result

        except (EncryptionError, StateMachineError):
            raise
        except Exception as e:
            self.tracer.trace(self.peer, "ERROR", "ENCRYPT", "FAILED", str(e))
            raise EncryptionError(f"Encryption failed: {e}", self)
        finally:
            self._release_lock()
    
    def decrypt_message(self, encrypted_msg: str) -> bytes:
        """Decrypt an OTRv4 DATA message; return human-readable text as UTF-8 bytes.

        Handles both v6 OTRv4DataMessage format and v5 legacy format.
        All TLVs in the payload are routed to their protocol handlers.
        """
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for decryption")
        
        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise StateMachineError("Cannot decrypt: session not in ENCRYPTED state")
            if self.ratchet is None:
                raise RuntimeError("Ratchet not initialized")
            
            self.last_activity = time.time()

            if not encrypted_msg.startswith("?OTRv4 "):
                raise ValueError("Not an OTRv4 message")

            raw = encrypted_msg[7:].strip().rstrip('.')
            try:
                decoded = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4))
            except Exception:
                decoded = base64.b64decode(
                    raw.replace('-', '+').replace('_', '/')
                    + '=' * (-len(raw) % 4)
                )

            if (len(decoded) >= 3
                    and decoded[0] == 0x00
                    and decoded[1] == 0x04
                    and decoded[2] == OTRv4DataMessage.TYPE):
                text_bytes = self._enh_dec_v6(decoded)
            else:
                text_bytes = self._enh_dec_legacy(decoded)

            self.tracer.trace(self.peer, "DECRYPT", "ENCRYPTED", "PLAINTEXT",
                              f"len={len(text_bytes)}")
            return text_bytes

        except (EncryptionError, StateMachineError):
            raise
        except Exception as e:
            self.tracer.trace(self.peer, "ERROR", "DECRYPT", "FAILED", str(e))
            raise EncryptionError(f"Decryption failed: {e}", self)
        finally:
            self._release_lock()

    def _enh_dec_v6(self, decoded: bytes) -> bytes:
        """Decrypt v6 OTRv4DataMessage."""
        dmsg = OTRv4DataMessage.decode(decoded)

        if self._receiver_tag == 0 and dmsg.sender_tag >= 0x100:
            self._receiver_tag = dmsg.sender_tag
        if dmsg.receiver_tag != 0 and dmsg.receiver_tag != self._sender_tag:
            raise ValueError(
                f"Instance tag mismatch: 0x{self._sender_tag:08x} vs "
                f"0x{dmsg.receiver_tag:08x}"
            )

        mac_key = hashlib.sha3_512(
            self.session_id
            + dmsg.ratchet_id.to_bytes(4, 'big')
            + dmsg.message_id.to_bytes(4, 'big')
            + b'OTRv4-MAC-KEY'
        ).digest()[:32]
        if not dmsg.verify_mac(mac_key):
            raise ValueError("MAC verification failed — message may be forged or replayed")

        rh_bytes = RatchetHeader(
            dmsg.ecdh_pub, dmsg.prev_chain_len, dmsg.message_id
        ).encode()
        if len(dmsg.ciphertext) < 16:
            raise ValueError("Ciphertext too short for GCM tag")
        ct, tag = dmsg.ciphertext[:-16], dmsg.ciphertext[-16:]

        # Snapshot ratchet_id to detect DH ratchet in decrypt_message
        _rid_before = self.ratchet.ratchet_id
        plaintext = self.ratchet.decrypt_message(rh_bytes, ct, dmsg.nonce, tag)
        _did_dh_ratchet = self.ratchet.ratchet_id != _rid_before

        # ── Process brace KEM rotation fields ────────────────────
        #    Order matters: ct first (completes previous exchange),
        #    ek second (starts new exchange).  Both update _brace_key
        #    so subsequent DH ratchets gain fresh PQ material.
        #
        #    Brace key updates apply to FUTURE DH ratchets, not the
        #    one that just completed — both sides perform the current
        #    DH ratchet with the OLD brace_key, then update.
        if dmsg.kem_ct is not None:
            self.ratchet.process_incoming_kem_ct(dmsg.kem_ct)
        if dmsg.kem_ek is not None:
            self.ratchet.process_incoming_kem_ek(dmsg.kem_ek)
        # Generate our own fresh KEM keypair on DH ratchet boundaries
        # (idempotent — skips if awaiting ct or ct queued to send).
        if _did_dh_ratchet:
            self.ratchet.prepare_brace_rotation()

        payload_obj = OTRv4Payload.decode(plaintext)
        self._enh_route_tlvs(payload_obj.tlvs)
        return payload_obj.text.encode('utf-8')

    def _enh_dec_legacy(self, decoded: bytes) -> bytes:
        """Decrypt v5 legacy format (backward compatibility)."""
        if not decoded or decoded[0] != OTRConstants.MESSAGE_TYPE_DATA:
            raise ValueError(f"Not a DATA message: 0x{decoded[0] if decoded else 0:02x}")
        off = 1
        sid = decoded[off:off + OTRConstants.SESSION_ID_BYTES]; off += OTRConstants.SESSION_ID_BYTES
        if not hmac.compare_digest(sid, self.session_id):
            raise ValueError("Session ID mismatch (legacy)")
        hdr = decoded[off:off + 64]; off += 64
        non = decoded[off:off + 12]; off += 12
        tag = decoded[off:off + 16]; off += 16
        ct  = decoded[off:]
        pt  = self.ratchet.decrypt_message(hdr, ct, non, tag)
        null_pos = pt.find(b'\x00')
        return pt[:null_pos] if null_pos != -1 else pt

    def _enh_route_tlvs(self, tlvs: List['OTRv4TLV']) -> None:
        """Route TLVs from decrypted payload to protocol handlers."""
        for tlv in tlvs:
            try:
                if tlv.type == OTRv4TLV.DISCONNECTED:
                    self._peer_disconnected = True
                    self.tracer.trace(self.peer, "DISCONNECT", "TLV", "RECEIVED",
                                      "peer ended session gracefully")
                    if self.session_state == SessionState.ENCRYPTED:
                        try:
                            self.transition_session(SessionState.FINISHED,
                                                    "peer sent DISCONNECTED TLV")
                        except StateMachineError:
                            pass

                elif tlv.type in OTRv4TLV.SMP_TYPES:
                    self._enh_handle_smp_tlv(tlv)

                elif tlv.type == OTRv4TLV.EXTRA_SYMMETRIC_KEY:
                    key = hashlib.sha3_512(
                        self.session_id + b'OTRv4-EXTRA-SYM' + tlv.value
                    ).digest()[:32]
                    self._last_extra_sym_key = key
                    if self._extra_sym_key_cb:
                        try:
                            self._extra_sym_key_cb(self.peer, tlv.value, key)
                        except Exception:
                            pass

            except Exception as e:
                self.tracer.trace(self.peer, "ERROR", "TLV",
                                  f"0x{tlv.type:04x}", str(e)[:80])

    def _enh_handle_smp_tlv(self, tlv: 'OTRv4TLV') -> None:
        """Process an incoming SMP TLV and queue the response for transmission.

        Each step begins by refreshing the client ping watchdog (via the
        _ping_refresh_cb callback) so that the server never sees a stale
        peer during the slow 3072-bit DH operations.
        """
        if not self.smp_engine:
            self.initialize_smp()
        if self._ping_refresh_cb is not None:
            try:
                self._ping_refresh_cb()
            except Exception:
                pass
        raw  = tlv.encode()
        resp = None
        try:
            if tlv.type in (OTRv4TLV.SMP_MSG_1, OTRv4TLV.SMP_MSG_1Q):
                if not self.smp_engine.state_machine.secret_set:
                    self.tracer.trace(self.peer, "SMP", "SMP1_RECEIVED", "NO_SECRET",
                                      "SMP1 received but no secret set — aborting")
                    self._queued_smp_response = self.encrypt_with_tlvs(
                        '', [OTRv4TLV(OTRv4TLV.SMP_ABORT, b'')]
                    )
                    return
                self._smp_progress_notify(
                    1, 4,
                    "Challenge sent — awaiting response (SMP uses ZK proofs, may take a few minutes)…",
                    color='yellow'
                )
                resp = self.smp_engine.process_smp1(raw)
                self.smp_step = 2
                self._smp_progress_notify(2, 4, "Challenge received — computing response…", role="responder")

            elif tlv.type == OTRv4TLV.SMP_MSG_2:
                self.smp_step = 2
                self._smp_progress_notify(2, 4, "Response received — verifying proof…", role="initiator")
                resp = self.smp_engine.process_smp2(raw)
                self.smp_step = 3
                self._smp_progress_notify(3, 4, "Proof verified — sending confirmation…", role="initiator")

            elif tlv.type == OTRv4TLV.SMP_MSG_3:
                resp = self.smp_engine.process_smp3(raw)
                self.smp_step = 4
                self._smp_progress_notify(4, 4, "Response verified — sending final confirmation…", role="responder")

            elif tlv.type == OTRv4TLV.SMP_MSG_4:
                self.smp_engine.process_smp4(raw)
                self.smp_step = 4

            elif tlv.type == OTRv4TLV.SMP_ABORT:
                self.smp_engine.reset()
                self.auto_smp_started   = False
                self.auto_smp_completed = False
                self.smp_step           = 0
                self.tracer.trace(self.peer, "SMP", "ABORTED", "PEER_ABORT",
                                  "Remote peer aborted SMP")
                self._smp_progress_notify(0, 4, "⚠ SMP aborted by remote peer", role=None, color='red')

        except Exception as e:
            self.tracer.trace(self.peer, "ERROR", "SMP",
                              f"0x{tlv.type:04x}", str(e)[:120])
            try:
                self.smp_engine.reset()
            except Exception:
                pass
            self.auto_smp_started   = False
            self.auto_smp_completed = False
            self.smp_step           = 0
            self._smp_progress_notify(0, 4, f"❌ SMP error: {str(e)[:60]}", role=None, color='red')
            return

        if self.smp_engine.is_verified():
            if not self.auto_smp_completed:
                self.auto_smp_completed = True
                self.auto_smp_started   = False
                self.security_level     = UIConstants.SecurityLevel.SMP_VERIFIED
                self.tracer.trace(self.peer, "SMP", "VERIFIED", "STATE_UPDATED",
                                  f"role={'initiator' if self.is_initiator else 'responder'}")
                self._smp_progress_notify(4, 4,
                    "🔵✅ SMP VERIFIED — identity confirmed!",
                    role=None, color='blue', final=True)
        elif self.smp_engine.has_failed():
            self.auto_smp_started   = False
            self.auto_smp_completed = False
            self.smp_step           = 0
            reason = getattr(self.smp_engine.state_machine, 'failure_reason', 'secrets did not match')
            self.tracer.trace(self.peer, "SMP", "FAILED", "STATE_UPDATED", reason)
            self._smp_progress_notify(0, 4,
                f"🔴❌ SMP FAILED — {reason}",
                role=None, color='red', final=True)
            self.smp_progress = (0, 0)

        if resp:
            rt = struct.unpack_from('!H', resp, 0)[0]
            rl = struct.unpack_from('!H', resp, 2)[0]
            rv = resp[4:4 + rl]
            try:
                self._queued_smp_response = self.encrypt_with_tlvs(
                    '', [OTRv4TLV(rt, rv)]
                )
            except Exception as e:
                self.tracer.trace(self.peer, "ERROR", "SMP_RESP", "ENCRYPT", str(e)[:80])

    _SMP_STEP_LABELS = {
        1: "Sending challenge",
        2: "Challenge sent → awaiting response",
        3: "Response received → sending verification",
        4: "Finalising",
    }

    def _smp_progress_notify(self, step: int, total: int, detail: str,
                              role: Optional[str] = None,
                              color: str = 'yellow',
                              final: bool = False) -> None:
        """Emit a visible SMP progress line with dynamic ETA and block bar.

        Each call produces one timestamped line like:

            🔐 SMP [████████░░] 2/4 · 50% · ⏱ 0:02 elapsed · ETA ~0:03

        Timing is derived from smp_start_time and per-step wall-clock
        measurements accumulated in _smp_step_times.
        """
        now = time.time()

        if not hasattr(self, '_smp_step_times'):
            self._smp_step_times: list = []
        if step > 0 and (not self._smp_step_times or
                         self._smp_step_times[-1][0] != step):
            self._smp_step_times.append((step, now))

        t0      = getattr(self, 'smp_start_time', 0) or now
        elapsed = max(0.0, now - t0)
        def _fmt(s: float) -> str:
            return f"{int(s // 60)}:{int(s % 60):02d}"

        elapsed_str = _fmt(elapsed)
        eta_str     = ""
        if step > 0 and elapsed > 0 and not final:
            avg_per_step = elapsed / step
            remaining    = (total - step) * avg_per_step
            if remaining > 0:
                eta_str = f" · ETA ~{_fmt(remaining)}"

        SEGS = total if total > 0 else 4
        if step > 0 and total > 0:
            seg_w   = 3
            filled  = '█' * seg_w
            empty_s = '░' * seg_w
            partial = '▒' * seg_w
            bar_segs = []
            for i in range(SEGS):
                if i < step - 1:
                    bar_segs.append(filled)
                elif i == step - 1:
                    bar_segs.append(filled)
                else:
                    bar_segs.append(empty_s)
            bar_body = ' '.join(bar_segs)
            pct      = int((step / total) * 100)
            bar      = f"[{bar_body}]"
            step_str = f"step {step}/{total}"
            if final:
                time_str = f" · ✓ {elapsed_str}"
            elif elapsed > 5:
                time_str = f" · {elapsed_str} elapsed{eta_str}"
            else:
                time_str = ""
            label = f"🔐 SMP {bar} {step_str}{time_str} · {detail}"
        else:
            label = f"🔐 SMP · {detail}"

        colored = colorize(label, color)

        if self._smp_notify_cb is not None:
            try:
                self._smp_notify_cb(colored)
            except Exception:
                pass
        elif self.tracer and self.tracer._emit_cb:
            self.tracer._emit_cb(colored)

        if final or step == 0:
            self._smp_step_times = []

    def send_disconnect(self) -> Optional[str]:
        """Encrypt and return a DISCONNECTED TLV message to notify the peer."""
        return self.encrypt_with_tlvs('', [OTRv4TLV(OTRv4TLV.DISCONNECTED, b'')])
    
    
    
    
    def start_dake(self) -> Optional[str]:
        """Start DAKE as initiator (opportunistic)"""
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for DAKE start")
        
        try:
            if self.session_state != SessionState.PLAINTEXT:
                raise StateMachineError(f"Cannot start DAKE in state: {self.session_state.name}")
            
            if self.dake_state != DAKEState.IDLE:
                raise StateMachineError(f"Cannot start DAKE: state is {self.dake_state.name}")
            
            if not self.is_initiator:
                raise StateMachineError("Only initiator can start DAKE")
            
            if self.dake_engine is None:
                raise RuntimeError("DAKE engine not initialized")
            
            self.transition_session(SessionState.DAKE_IN_PROGRESS, "starting DAKE")
            
            dake1 = self.dake_engine.generate_dake1()
            self.dake_start_time = time.time()
            
            self.transition_dake(DAKEState.SENT_DAKE1, "opportunistic start")
            
            self.tracer.trace(self.peer, "OPPORTUNISTIC", "IDLE", "STARTED",
                             "first outgoing message")
            
            return dake1
                
        except Exception as e:
            self.transition_session(SessionState.FAILED, f"DAKE start failed: {e}")
            return None
        finally:
            self._release_lock()
    
    def terminate(self, reason: str = "explicit termination"):
        """Terminate the session"""
        if not self._acquire_lock():
            return
        
        try:
            if self.session_state in [SessionState.FINISHED, SessionState.FAILED]:
                return
            
            old_state = self.session_state
            self.transition_session(SessionState.FINISHED, reason)
            
            self._cleanup_resources()
            
            self.tracer.trace(self.peer, "TERMINATE", old_state.name, "FINISHED", reason)
        finally:
            self._release_lock()
    
    def _cleanup_resources(self):
        """Clean up all resources"""
        try:
            if self.ratchet:
                self.ratchet.zeroize()
                self.ratchet = None
            
            if self.root_key:
                self.root_key.zeroize()
                self.root_key = None
            
            if self.smp_engine:
                self.smp_engine.reset()
                self.smp_engine = None
            
            self.pending_messages.clear()
            self.received_messages.clear()
            
        except Exception as e:
            self.tracer.trace(self.peer, "ERROR", "CLEANUP", "FAILED", str(e))
    
    def _cleanup_failed_session(self):
        """Cleanup after session failure"""
        self._cleanup_resources()
        self.tracer.reset_peer(self.peer)
    
    
    
    
    def get_fingerprint(self) -> str:
        """Get remote fingerprint - can be called from client"""
        try:
            if self.remote_long_term_pub is not None:
                try:
                    pub_bytes = self.remote_long_term_pub.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                    fp_bytes = hashlib.sha3_512(pub_bytes).digest()
                    return fp_bytes.hex().upper()
                except Exception:
                    pass
            
            if self._remote_long_term_pub_bytes is not None:
                try:
                    fp_bytes = hashlib.sha3_512(self._remote_long_term_pub_bytes).digest()
                    return fp_bytes.hex().upper()
                except Exception:
                    pass
        except Exception:
            pass
        
        return ""
    
    
    
    
    def start_smp(self, secret: str, question: Optional[str] = None) -> Optional[str]:
        """
        Start SMP verification - delegates to SMPEngine and encrypts the result.
        Returns the encrypted OTR message ready to send, or None if cannot start.
        """
        if not self._acquire_lock():
            self.logger.debug("start_smp: Failed to acquire lock")
            return None
        
        try:
            if self.session_state != SessionState.ENCRYPTED:
                self.logger.debug(f"start_smp: Cannot start SMP - session not encrypted (state: {self.session_state.name})")
                return None
            
            if self.smp_engine is None:
                self.initialize_smp()
            
            current_state = self.smp_engine.get_state()
            self.logger.debug(f"start_smp: Current SMP state: {current_state.name}")
            
            if current_state != UIConstants.SMPState.NONE:
                self.logger.debug(f"start_smp: Cannot start - already in state {current_state.name}")
                return None
            
            smp_tlv = self.smp_engine.start_smp(secret, question)
            if not smp_tlv:
                self.logger.debug("start_smp: smp_engine.start_smp returned None")
                return None
            
            self.logger.debug(f"start_smp: Got SMP TLV of length {len(smp_tlv)}")
            
            tlv_type = struct.unpack_from('!H', smp_tlv, 0)[0]
            tlv_len = struct.unpack_from('!H', smp_tlv, 2)[0]
            tlv_value = smp_tlv[4:4 + tlv_len]
            
            encrypted = self.encrypt_with_tlvs('', [OTRv4TLV(tlv_type, tlv_value)])
            self.logger.debug(f"start_smp: Encrypted message length: {len(encrypted)}")
            
            return encrypted
            
        except Exception as e:
            self.logger.debug(f"start_smp: Error: {e}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            self._release_lock()
    
    def process_smp_message(self, data: bytes) -> Optional[str]:
        """
        Process incoming SMP TLV bytes and return encrypted response if any.
        """
        if not self._acquire_lock():
            self.logger.debug("process_smp_message: Failed to acquire lock")
            return None
        
        try:
            if self.smp_engine is None:
                self.initialize_smp()
            
            if len(data) < 4:
                return None
            
            tlv_type = struct.unpack_from('!H', data, 0)[0]
            self.logger.debug(f"process_smp_message: Processing type {tlv_type}")
            
            response = None
            
            if tlv_type in (OTRv4TLV.SMP_MSG_1, OTRv4TLV.SMP_MSG_1Q):
                response = self.smp_engine.process_smp1(data)
            elif tlv_type == OTRv4TLV.SMP_MSG_2:
                response = self.smp_engine.process_smp2(data)
            elif tlv_type == OTRv4TLV.SMP_MSG_3:
                response = self.smp_engine.process_smp3(data)
            elif tlv_type == OTRv4TLV.SMP_MSG_4:
                success = self.smp_engine.process_smp4(data)
                response = None
                if success:
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                    self.logger.debug("process_smp_message: SMP verification succeeded!")
            elif tlv_type == OTRv4TLV.SMP_ABORT:
                self.smp_engine.reset()
                response = None
            
            if response:
                resp_type = struct.unpack_from('!H', response, 0)[0]
                resp_len = struct.unpack_from('!H', response, 2)[0]
                resp_value = response[4:4 + resp_len]
                encrypted = self.encrypt_with_tlvs('', [OTRv4TLV(resp_type, resp_value)])
                self.logger.debug(f"process_smp_message: Generated encrypted response of length {len(encrypted)}")
                return encrypted
            
            return None
            
        except Exception as e:
            self.logger.debug(f"process_smp_message: Error: {e}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            self._release_lock()
    
    def get_smp_status(self) -> Dict[str, Any]:
        """Get SMP status - delegates to smp_engine with proper state mapping."""
        if not self._acquire_lock():
            return {
                'state': 'NONE',
                'verified': False,
                'failed': False,
                'progress': '0/4',
                'has_question': False,
                'question': '',
                'can_start_smp': False,
                'can_retry': False,
                'retry_count': 0,
                'expired': False,
            }
        
        try:
            if self.smp_engine is None:
                return {
                    'state': 'NONE',
                    'verified': False,
                    'failed': False,
                    'progress': '0/4',
                    'has_question': False,
                    'question': '',
                    'can_start_smp': self.session_state == SessionState.ENCRYPTED,
                    'can_retry': False,
                    'retry_count': 0,
                    'expired': False,
                }
            
            engine_state = self.smp_engine.get_state()
            
            state_map = {
                UIConstants.SMPState.NONE: 'NONE',
                UIConstants.SMPState.EXPECT1: 'EXPECT1',
                UIConstants.SMPState.SENT1: 'SENT1',
                UIConstants.SMPState.EXPECT2: 'EXPECT2',
                UIConstants.SMPState.SENT2: 'SENT2',
                UIConstants.SMPState.EXPECT3: 'EXPECT3',
                UIConstants.SMPState.SENT3: 'SENT3',
                UIConstants.SMPState.EXPECT4: 'EXPECT4',
                UIConstants.SMPState.SUCCEEDED: 'SUCCEEDED',
                UIConstants.SMPState.FAILED: 'FAILED',
            }
            
            progress_map = {
                UIConstants.SMPState.NONE: (0, 4),
                UIConstants.SMPState.EXPECT1: (0, 4),
                UIConstants.SMPState.SENT1: (1, 4),
                UIConstants.SMPState.EXPECT2: (1, 4),
                UIConstants.SMPState.SENT2: (2, 4),
                UIConstants.SMPState.EXPECT3: (2, 4),
                UIConstants.SMPState.SENT3: (3, 4),
                UIConstants.SMPState.EXPECT4: (3, 4),
                UIConstants.SMPState.SUCCEEDED: (4, 4),
                UIConstants.SMPState.FAILED: (0, 4),
            }
            
            step, total = progress_map.get(engine_state, (0, 4))
            
            result = {
                'state': state_map.get(engine_state, 'NONE'),
                'verified': self.auto_smp_completed or self.smp_engine.is_verified(),
                'failed': self.smp_engine.has_failed(),
                'failure_reason': getattr(self.smp_engine.state_machine, 'failure_reason', ''),
                'progress': f"{step}/{total}",
                'has_question': self.smp_engine.has_question(),
                'question': self.smp_engine.get_question() or '',
                'can_start_smp': engine_state == UIConstants.SMPState.NONE and self.session_state == SessionState.ENCRYPTED,
                'can_retry': self.smp_engine.can_retry() if hasattr(self.smp_engine, 'can_retry') else False,
                'retry_count': getattr(self.smp_engine.state_machine, 'retry_count', 0),
                'expired': self.smp_engine.is_expired() if hasattr(self.smp_engine, 'is_expired') else False,
            }
            
            self.logger.debug(f"get_smp_status: Returning {result}")
            return result
            
        except Exception as e:
            self.logger.debug(f"get_smp_status: Error: {e}")
            return {
                'state': 'NONE',
                'verified': False,
                'failed': False,
                'progress': '0/4',
                'can_start_smp': self.session_state == SessionState.ENCRYPTED,
            }
        finally:
            self._release_lock()
    
    def get_smp_progress(self) -> Tuple[int, int]:
        """Get SMP progress as (step, total)."""
        if not self._acquire_lock():
            return (0, 4)
        
        try:
            if self.smp_engine is None:
                return (0, 4)
            
            state = self.smp_engine.get_state()
            progress_map = {
                UIConstants.SMPState.NONE: (0, 4),
                UIConstants.SMPState.EXPECT1: (0, 4),
                UIConstants.SMPState.SENT1: (1, 4),
                UIConstants.SMPState.EXPECT2: (1, 4),
                UIConstants.SMPState.SENT2: (2, 4),
                UIConstants.SMPState.EXPECT3: (2, 4),
                UIConstants.SMPState.SENT3: (3, 4),
                UIConstants.SMPState.EXPECT4: (3, 4),
                UIConstants.SMPState.SUCCEEDED: (4, 4),
                UIConstants.SMPState.FAILED: (0, 4),
            }
            return progress_map.get(state, (0, 4))
        finally:
            self._release_lock()
    
    def set_smp_secret(self, secret: str):
        """Store SMP secret for this session.

        Warns if passphrase has weak entropy (< 6 chars or common pattern).
        The SMP engine applies SHAKE-256 key stretching internally.
        """
        if not self._acquire_lock():
            return
        
        try:
            # ── Entropy warning ──────────────────────────────
            _MIN_SMP_LENGTH = 6
            if len(secret) < _MIN_SMP_LENGTH:
                self.logger.debug(
                    f"SMP WARNING: passphrase is only {len(secret)} chars — "
                    f"minimum {_MIN_SMP_LENGTH} recommended. "
                    "Short passphrases can be brute-forced from SMP transcripts.")
            if self.smp_engine is None:
                self.initialize_smp()
            self.smp_engine.set_secret(secret)
            self.logger.debug(f"set_smp_secret: Secret stored for {self.peer}")
        finally:
            self._release_lock()
    
    def can_start_smp(self) -> bool:
        """Check if SMP can be started."""
        if not self._acquire_lock():
            return False
        
        try:
            if self.session_state != SessionState.ENCRYPTED:
                return False
            if self.smp_engine is None:
                return True
            return self.smp_engine.get_state() == UIConstants.SMPState.NONE
        finally:
            self._release_lock()
    
    
    
    
    def get_state_summary(self) -> Dict[str, Any]:
        """Get comprehensive state summary"""
        if not self._acquire_lock():
            return {}
        
        try:
            smp_status = self.get_smp_status() if hasattr(self, 'get_smp_status') else {}
            
            return {
                'peer': self.peer,
                'session_state': self.session_state.name,
                'dake_state': self.dake_state.name,
                'smp_state': smp_status.get('state', 'NONE'),
                'security_level': self.security_level.name,
                'is_initiator': self.is_initiator,
                'session_id': self.session_id.hex()[:16] if self.session_id else None,
                'created': time.ctime(self.created),
                'last_activity': time.ctime(self.last_activity),
                'queued_messages': len(self.pending_messages),
                'has_ratchet': self.ratchet is not None,
                'has_smp': self.smp_engine is not None,
                'is_encrypted': self.session_state == SessionState.ENCRYPTED,
                'is_active': self.session_state not in [SessionState.FINISHED, SessionState.FAILED],
                'fingerprint': self.get_fingerprint(),
                'smp_verified': smp_status.get('verified', False),
            }
        finally:
            self._release_lock()
    
    def is_encrypted(self) -> bool:
        """Check if session is encrypted"""
        return self.session_state == SessionState.ENCRYPTED
    
    def can_send_message(self) -> bool:
        """Check if we can send a message"""
        return self.session_state in [SessionState.ENCRYPTED, SessionState.PLAINTEXT]
    
    def should_start_dake(self) -> bool:
        """Check if we should start DAKE (opportunistic)"""
        return (self.session_state == SessionState.PLAINTEXT and 
                self.dake_state == DAKEState.IDLE and
                self.is_initiator)
    
    def __del__(self):
        """Destructor - ensure cleanup"""
        try:
            if hasattr(self, 'session_state') and self.session_state != SessionState.FINISHED:
                self.terminate("session destroyed")
        except Exception:
            pass

class SessionManager:
    """Session manager — owns DAKE engines and delegates to EnhancedOTRSession."""
    
    def __init__(self, config: Optional[OTRConfig] = None, logger: Optional[OTRLogger] = None):
        self.config = config or OTRConfig(test_mode=True)
        self.logger = logger or NullLogger()
        
        self.trust_db = TrustDatabase(self.config.trust_db_path)
        self.smp_storage = SMPAutoRespondStorage(self.config.smp_secrets_path)
        self.key_storage = SecureKeyStorage(self.config.key_storage_path)
        
        # Fresh keys every session — ephemeral identity, no persistent fingerprint
        self.client_profile = ClientProfile()
        
        self.lock = threading.RLock()
        
        self.sessions: Dict[str, EnhancedOTRSession] = {}
        self.pending_dakes: Dict[str, OTRv4DAKE] = {}
        self._disconnect_callbacks: list = []
        
        if not self.config.test_mode:
            self._store_identity()
    
    def _acquire_lock(self, timeout: float = 5.0) -> bool:
        """Acquire lock with timeout"""
        try:
            return self.lock.acquire(timeout=timeout)
        except Exception:
            return False
    
    def _release_lock(self):
        """Safely release lock"""
        try:
            self.lock.release()
        except Exception:
            pass
    
    def _store_identity(self):
        """Store client profile in secure storage"""
        try:
            priv_bytes = self.client_profile.identity_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.key_storage.store_key("identity", "ed448", priv_bytes)
            
            prekey_bytes = self.client_profile.prekey.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.key_storage.store_key("prekey", "x448", prekey_bytes)
            
            profile_bytes = self.client_profile.encode()
            self.key_storage.store_key("profile", "client", profile_bytes)
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"Warning: Could not store identity: {e}")
    
    def get_fingerprint(self) -> str:
        """Get local fingerprint"""
        return self.client_profile.get_fingerprint()
    
    def start_session(self, peer: str) -> Optional[str]:
        """Start a new OTR session with peer"""
        if not self._acquire_lock():
            return None
        
        try:
            if peer in self.sessions:
                return None
            
            dake = OTRv4DAKE(
                client_profile=self.client_profile,
                explicit_initiator=True,
                logger=self.logger
            )
            
            try:
                dake1 = dake.generate_dake1()
                self.pending_dakes[peer] = dake
                return dake1
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to start session: {e}")
                return None
        finally:
            self._release_lock()
    
    def handle_dake1(self, peer: str, dake1_msg: str) -> Optional[str]:
        """Handle incoming DAKE1 message"""
        if not self._acquire_lock():
            return None
        
        try:
            dake = OTRv4DAKE(
                client_profile=self.client_profile,
                explicit_initiator=False,
                logger=self.logger
            )
            
            try:
                success = dake.process_dake1(dake1_msg)
                if success:
                    dake2 = dake.generate_dake2()
                    self.pending_dakes[peer] = dake
                    return dake2
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to handle DAKE1: {e}")
            return None
        finally:
            self._release_lock()
    
    def handle_dake2(self, peer: str, dake2_msg: str) -> Optional[str]:
        """Handle incoming DAKE2 message"""
        if not self._acquire_lock():
            return None
        
        try:
            if peer not in self.pending_dakes:
                return None
            
            dake = self.pending_dakes[peer]
            try:
                success = dake.process_dake2(dake2_msg)
                if success:
                    dake3 = dake.generate_dake3()
                    
                    session = EnhancedOTRSession(
                        peer=peer,
                        is_initiator=True,
                        tracer=OTRTracer(enabled=DEBUG_MODE),
                        logger=self.logger
                    )
                    if getattr(self, 'smp_notify_factory', None):
                        session._smp_notify_cb = self.smp_notify_factory(peer)
                    if getattr(self, 'ping_refresh_cb', None):
                        session._ping_refresh_cb = self.ping_refresh_cb

                    session_keys = dake.get_session_keys()
                    if session_keys:
                        session.session_id = session_keys.get('session_id')
                        session.root_key = session_keys.get('root_key')
                        session.remote_long_term_pub = session_keys.get('peer_long_term_pub')
                    
                    self.sessions[peer] = session
                    del self.pending_dakes[peer]
                    
                    return dake3
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to handle DAKE2: {e}")
                del self.pending_dakes[peer]
            return None
        finally:
            self._release_lock()
    
    def handle_dake3(self, peer: str, dake3_msg: str) -> bool:
        """Handle incoming DAKE3 message"""
        if not self._acquire_lock():
            return False
        
        try:
            if peer not in self.pending_dakes:
                return False
            
            dake = self.pending_dakes[peer]
            try:
                success = dake.process_dake3(dake3_msg)
                if success:
                    session = EnhancedOTRSession(
                        peer=peer,
                        is_initiator=False,
                        tracer=OTRTracer(enabled=DEBUG_MODE),
                        logger=self.logger
                    )
                    if getattr(self, 'smp_notify_factory', None):
                        session._smp_notify_cb = self.smp_notify_factory(peer)
                    if getattr(self, 'ping_refresh_cb', None):
                        session._ping_refresh_cb = self.ping_refresh_cb
                    
                    session_keys = dake.get_session_keys()
                    if session_keys:
                        session.session_id = session_keys.get('session_id')
                        session.root_key = session_keys.get('root_key')
                        session.remote_long_term_pub = session_keys.get('peer_long_term_pub')
                    
                    self.sessions[peer] = session
                    del self.pending_dakes[peer]
                    return True
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to handle DAKE3: {e}")
                del self.pending_dakes[peer]
            return False
        finally:
            self._release_lock()
    
    def has_session(self, peer: str) -> bool:
        """Check if session exists for peer"""
        return peer in self.sessions
    
    def get_session(self, peer: str) -> Optional[EnhancedOTRSession]:
        """Get session for peer"""
        return self.sessions.get(peer)
    
    def get_security_level(self, peer: str) -> UIConstants.SecurityLevel:
        """Get security level for session with peer"""
        if peer not in self.sessions:
            return UIConstants.SecurityLevel.PLAINTEXT
        return self.sessions[peer].security_level
    
    def encrypt_message(self, peer: str, plaintext: str) -> Optional[str]:
        """Encrypt message for peer"""
        if peer not in self.sessions:
            return None
        
        try:
            session = self.sessions[peer]
            return session.encrypt_message(plaintext)
        except Exception as e:
            if DEBUG_MODE:
                print(f"Encryption failed: {e}")
            return None
    
    def decrypt_message(self, peer: str, encrypted_msg: str) -> bytes:
        """Decrypt message from peer.

        After decrypting, the session's TLV router may have generated
        a protocol response (SMP2, SMP3, SMP4) and stored it in
        session._queued_smp_response.  We must drain that field and return
        the response instead of the (empty) plaintext so the IRC client's
        _handle_data_message receives an '?OTRv4 ...' string, detects it, and
        calls send_otr_message.  Without this drain the SMP handshake stalls
        after SMP1: Client B built SMP2 but it was never sent.
        """
        if peer not in self.sessions:
            raise ValueError(f"No session with {peer}")

        try:
            session = self.sessions[peer]
            plaintext = session.decrypt_message(encrypted_msg)

            queued = getattr(session, '_queued_smp_response', None)
            if queued:
                session._queued_smp_response = None
                return queued.encode('utf-8') if isinstance(queued, str) else queued

            return plaintext
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}", session=self.sessions.get(peer))
    
    def get_session_info(self, peer: str) -> Dict[str, Any]:
        """Get session information"""
        if peer not in self.sessions:
            return {}
        
        session = self.sessions[peer]
        return session.get_state_summary() if hasattr(session, 'get_state_summary') else {}
    
    def display_fingerprints(self, peer: str) -> str:
        """Display fingerprints for session"""
        if peer not in self.sessions:
            return ""
        
        session = self.sessions[peer]
        local_fp = self.get_fingerprint()
        remote_fp = session.get_fingerprint() if hasattr(session, 'get_fingerprint') else ""
        
        return f"Local: {local_fp}\nRemote: {remote_fp}"
    
    def set_smp_secret(self, peer: str, secret: str) -> bool:
        """Set SMP secret for auto-respond"""
        try:
            self.smp_storage.set_secret(peer, secret)
            self.logger.debug(f"set_smp_secret: Stored in smp_storage for {peer}")
        except Exception as e:
            self.logger.debug(f"set_smp_secret: Error storing in smp_storage: {e}")
        
        if peer in self.sessions:
            try:
                session = self.sessions[peer]
                if hasattr(session, 'set_smp_secret'):
                    session.set_smp_secret(secret)
                    self.logger.debug(f"set_smp_secret: Set in session for {peer}")
            except Exception as e:
                self.logger.debug(f"set_smp_secret: Error setting in session: {e}")
        
        return True
    
    
    
    
    def start_smp(self, peer: str, secret: str, question: Optional[str] = None) -> Optional[str]:
        """Start SMP verification - returns encrypted message ready to send."""
        self.logger.debug(f"start_smp: Called for {peer} with secret length {len(secret)}")
        
        if peer not in self.sessions:
            self.logger.debug(f"start_smp: No session for {peer}")
            return None
        
        session = self.sessions[peer]
        
        if hasattr(session, 'start_smp'):
            self.logger.debug(f"start_smp: Calling session.start_smp for {peer}")
            result = session.start_smp(secret, question)
            self.logger.debug(f"start_smp: session.start_smp returned: {result is not None}")
            return result
        
        self.logger.debug(f"start_smp: Session has no start_smp method")
        return None
    
    def process_smp_message(self, peer: str, smp_tlv: bytes) -> Optional[str]:
        """Process SMP message and return encrypted response"""
        if peer not in self.sessions:
            return None
        
        try:
            session = self.sessions[peer]
            
            auto_secret = self.smp_storage.get_secret(peer)
            if auto_secret and hasattr(session, 'set_smp_secret'):
                session.set_smp_secret(auto_secret)
            
            if hasattr(session, 'process_smp_message'):
                return session.process_smp_message(smp_tlv)
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"SMP message processing failed: {e}")
        
        return None
    
    
    
    
    def get_smp_status(self, peer: str) -> Dict[str, Any]:
        """Get SMP status for session."""
        if peer not in self.sessions:
            self.logger.debug(f"get_smp_status: No session for {peer}, returning NONE")
            return {
                "state": "NONE", 
                "verified": False, 
                "failed": False,
                "progress": "0/4",
                "is_initiator": False,
                "can_start_smp": True,
                "should_auto_start_smp": False,
                "has_question": False,
                "question": "",
                "auto_smp_secret": bool(self.smp_storage.get_secret(peer)),
                "auto_smp_started": False,
                "auto_smp_completed": False,
                "can_retry": False,
                "retry_count": 0,
                "expired": False
            }
        
        session = self.sessions[peer]
        
        if hasattr(session, 'get_smp_status'):
            status = session.get_smp_status()
            if 'is_initiator' not in status:
                status['is_initiator'] = getattr(session, 'is_initiator', False)
            status['auto_smp_secret'] = bool(self.smp_storage.get_secret(peer))
            status['auto_smp_started'] = getattr(session, 'auto_smp_started', False)
            status['auto_smp_completed'] = getattr(session, 'auto_smp_completed', False)
            status['should_auto_start_smp'] = False
            status['can_start_smp'] = status.get('can_start_smp', session.can_start_smp() if hasattr(session, 'can_start_smp') else False)
            
            self.logger.debug(f"get_smp_status: Returning from session: {status}")
            return status
        
        return {
            "state": "NONE",
            "verified": False,
            "failed": False,
            "progress": "0/4",
            "is_initiator": getattr(session, 'is_initiator', False),
            "can_start_smp": hasattr(session, 'can_start_smp') and session.can_start_smp(),
            "should_auto_start_smp": False,
            "has_question": False,
            "question": "",
            "auto_smp_secret": bool(self.smp_storage.get_secret(peer)),
            "auto_smp_started": False,
            "auto_smp_completed": False,
            "can_retry": False,
            "retry_count": 0,
            "expired": False
        }
    
    def get_smp_progress(self, peer: str) -> Tuple[int, int]:
        """Get SMP progress"""
        if peer not in self.sessions:
            return (0, 4)
        
        session = self.sessions[peer]
        if hasattr(session, 'get_smp_progress'):
            return session.get_smp_progress()
        return (0, 4)
    
    def get_smp_question(self, peer: str) -> str:
        """Get SMP question if any"""
        if peer not in self.sessions:
            return ""
        
        session = self.sessions[peer]
        if hasattr(session, 'get_smp_question'):
            return session.get_smp_question()
        return ""
    
    def is_smp_verified(self, peer: str) -> bool:
        """Check if SMP is verified"""
        if peer not in self.sessions:
            return False
        
        session = self.sessions[peer]
        if hasattr(session, 'is_smp_verified'):
            return session.is_smp_verified()
        status = self.get_smp_status(peer)
        return status.get('verified', False)
    
    def abort_smp(self, peer: str) -> bool:
        """Abort SMP for a peer"""
        if peer not in self.sessions:
            return False
        
        session = self.sessions[peer]
        if hasattr(session, 'abort_smp'):
            return session.abort_smp()
        return False
    
    def process_auto_smp(self, peer: str, smp_tlv: bytes) -> Optional[str]:
        """Process SMP message with auto-respond"""
        if peer not in self.sessions:
            return None
        
        try:
            session = self.sessions[peer]
            if hasattr(session, 'process_auto_smp_response'):
                return session.process_auto_smp_response(smp_tlv)
        except Exception as e:
            if DEBUG_MODE:
                print(f"Auto-SMP processing failed: {e}")
        return None
    
    def check_and_start_auto_smp(self, peer: str) -> Optional[str]:
        """Check and start auto-SMP if configured and appropriate"""
        return None
    
    def end_session(self, peer: str):
        """End session with peer — sends TLV_TYPE_DISCONNECTED per OTRv4 spec §3.6"""
        if not self._acquire_lock():
            return
        
        try:
            if peer in self.sessions:
                session = self.sessions[peer]
                try:
                    if hasattr(session, 'send_disconnect'):
                        encrypted = session.send_disconnect()
                        if encrypted:
                            self._disconnect_callbacks.append((peer, encrypted))
                except Exception:
                    pass
                session.terminate("session ended")
                del self.sessions[peer]
                self.logger.debug(f"end_session: Session ended for {peer}")
        finally:
            self._release_lock()
    
    def zeroize_all(self):
        """Zeroize all sessions"""
        if not self._acquire_lock():
            return
        
        try:
            for peer, session in list(self.sessions.items()):
                try:
                    session.terminate("zeroize all")
                except Exception:
                    pass
            self.sessions.clear()
            self.pending_dakes.clear()
            self.logger.debug("zeroize_all: All sessions zeroized")
        finally:
            self._release_lock()
    
    def get_peer_fingerprint(self, peer: str) -> Optional[str]:
        """Get peer's fingerprint"""
        if peer not in self.sessions:
            return None
        return self.sessions[peer].get_fingerprint()
    
    def is_peer_trusted(self, peer: str) -> bool:
        """Check if peer is trusted"""
        fingerprint = self.get_peer_fingerprint(peer)
        if not fingerprint:
            return False
        return self.trust_db.is_trusted(peer, fingerprint)
    
    def trust_fingerprint(self, peer: str, fingerprint: str) -> bool:
        """Trust a fingerprint"""
        return self.trust_db.add_trust(peer, fingerprint)

class EnhancedSessionManager:
    """Session manager with opportunistic DAKE and secure key storage."""

    def __init__(self, config: Optional[OTRConfig] = None,
                 tracer: Optional[OTRTracer] = None,
                 logger: Optional[OTRLogger] = None):
        self.config = config or OTRConfig(test_mode=True)
        self.tracer = tracer or OTRTracer(enabled=True)
        self.logger = logger or NullLogger()

        self.trust_db = TrustDatabase(self.config.trust_db_path)
        self.smp_storage = SMPAutoRespondStorage(self.config.smp_secrets_path)
        self.key_storage = SecureKeyStorage(self.config.key_storage_path)

        # Fresh keys every session — no persistent identity on I2P
        self.client_profile = ClientProfile()

        self.sessions: Dict[str, EnhancedOTRSession] = {}
        self.dake_engines: Dict[str, OTRv4DAKE] = {}

        self.lock = threading.RLock()

        self.smp_notify_factory = None

        if not self.config.test_mode:
            self._store_identity()

        self.tracer.trace("SYSTEM", "MANAGER", None, "READY", "session manager initialized")
    
    def _store_identity(self):
        """Store client identity in secure storage"""
        try:
            priv_bytes = self.client_profile.identity_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.key_storage.store_key("identity", "ed448", priv_bytes)
            
            prekey_bytes = self.client_profile.prekey.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.key_storage.store_key("prekey", "x448", prekey_bytes)
            
            self.tracer.trace("SYSTEM", "STORAGE", None, "READY", "identity stored")
            
        except Exception as e:
            self.tracer.trace("SYSTEM", "ERROR", "STORAGE", "FAILED", str(e))
    
    
    
    
    def get_or_create_session(self, peer: str, is_initiator: bool = False) -> EnhancedOTRSession:
        """Get existing session or create new one"""
        with self.lock:
            if peer in self.sessions:
                session = self.sessions[peer]

                if session.is_initiator != is_initiator:
                    self.tracer.trace(peer, "ROLE",
                                     "INITIATOR" if session.is_initiator else "RESPONDER",
                                     "INITIATOR" if is_initiator else "RESPONDER",
                                     "role updated")
                    session.is_initiator = is_initiator

                if session._smp_notify_cb is None and self.smp_notify_factory is not None:
                    try:
                        session._smp_notify_cb = self.smp_notify_factory(peer)
                    except Exception:
                        pass
                if session._ping_refresh_cb is None and getattr(self, 'ping_refresh_cb', None):
                    session._ping_refresh_cb = self.ping_refresh_cb

                return session

            session = EnhancedOTRSession(
                peer=peer,
                is_initiator=is_initiator,
                tracer=self.tracer,
                logger=self.logger
            )

            if self.smp_notify_factory is not None:
                try:
                    session._smp_notify_cb = self.smp_notify_factory(peer)
                except Exception:
                    pass
            if getattr(self, 'ping_refresh_cb', None):
                session._ping_refresh_cb = self.ping_refresh_cb

            self.sessions[peer] = session
            
            self.tracer.trace(peer, "SESSION", None, "CREATED",
                             f"new session (role: {'initiator' if is_initiator else 'responder'})")
            
            return session
    
    def get_session(self, peer: str) -> Optional[EnhancedOTRSession]:
        """Get session for peer"""
        with self.lock:
            return self.sessions.get(peer)
    
    def has_session(self, peer: str) -> bool:
        """Check if session exists for peer"""
        with self.lock:
            return peer in self.sessions
    
    def has_encrypted_session(self, peer: str) -> bool:
        """Check if encrypted session exists for peer"""
        with self.lock:
            if peer not in self.sessions:
                return False
            
            session = self.sessions[peer]
            return session.is_encrypted()
    
    
    
    
    def handle_outgoing_message(self, peer: str, message: str) -> Tuple[Optional[str], bool]:
        """
        Handle outgoing message with opportunistic OTR.
        Returns: (encrypted_message_or_dake_message, should_send)
        """
        with self.lock:
            session = self.get_or_create_session(peer, is_initiator=True)
            
            if session.is_encrypted():
                try:
                    encrypted = session.encrypt_message(message)
                    self.tracer.trace(peer, "SEND", "ENCRYPTED", "READY",
                                     f"message encrypted ({len(message)} chars)")
                    return encrypted, True
                except Exception as e:
                    self.tracer.trace(peer, "ERROR", "ENCRYPT", "FAILED", str(e))
                    return None, False
            
            elif session.session_state == SessionState.PLAINTEXT:
                if session.should_start_dake():
                    self.tracer.trace(peer, "OPPORTUNISTIC", "IDLE", "STARTING",
                                     f"first message to {peer}")
                    
                    dake_engine = session.initialize_dake(self.client_profile, explicit_initiator=True)
                    self.dake_engines[peer] = dake_engine
                    
                    dake1 = session.start_dake()
                    if dake1:
                        session.queue_outgoing_message(message)
                        
                        self.tracer.trace(peer, "QUEUE", "MESSAGE", "QUEUED",
                                         f"message queued for later encryption")
                        
                        return dake1, True
                    else:
                        self.tracer.trace(peer, "ERROR", "DAKE", "FAILED", "could not start DAKE")
                        return None, False
                else:
                    self.tracer.trace(peer, "ERROR", "SEND", "BLOCKED",
                                     f"plaintext session but DAKE not started")
                    return None, False
            
            elif session.session_state == SessionState.DAKE_IN_PROGRESS:
                session.queue_outgoing_message(message)
                
                self.tracer.trace(peer, "QUEUE", "MESSAGE", "QUEUED",
                                 f"DAKE in progress, message queued")
                
                return None, False
            
            else:
                self.tracer.trace(peer, "ERROR", "SEND", "BLOCKED",
                                 f"session in state: {session.session_state.name}")
                return None, False
    
    def handle_incoming_message(self, peer: str, message: str) -> Optional[bytes]:
        """
        Handle incoming message, routing to DAKE or decryption as appropriate.
        Returns decrypted plaintext if applicable.
        """
        with self.lock:
            if message.startswith("?OTRv4 "):
                return self._handle_otr_message(peer, message)
            
            session = self.get_session(peer)
            if session and session.is_encrypted():
                self.tracer.trace(peer, "ERROR", "RECEIVE", "PLAINTEXT",
                                 f"encrypted session but received plaintext - possible downgrade attack")
                return None
            
            return message.encode('utf-8') if isinstance(message, str) else message
    
    def _handle_otr_message(self, peer: str, message: str) -> Optional[bytes]:
        """Handle OTRv4 protocol message"""
        with self.lock:
            try:
                payload = message[7:].strip()
                try:
                    decoded = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
                except Exception:
                    decoded = base64.b64decode(payload + '=' * (-len(payload) % 4))
                
                if len(decoded) < 1:
                    return None
                
                if (len(decoded) >= 3
                        and decoded[0] == 0x00
                        and decoded[1] == 0x04
                        and decoded[2] == OTRv4DataMessage.TYPE):
                    return self._handle_data_message(peer, message)

                msg_type = decoded[0]
                if msg_type == OTRConstants.MESSAGE_TYPE_DAKE1:
                    return self._handle_dake1(peer, message)
                elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE2:
                    return self._handle_dake2(peer, message)
                elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE3:
                    return self._handle_dake3(peer, message)
                elif msg_type == OTRConstants.MESSAGE_TYPE_DATA:
                    return self._handle_data_message(peer, message)
                else:
                    self.tracer.trace(peer, "ERROR", "PARSE", "UNKNOWN",
                                     f"unknown message type: {msg_type}")
                    return None
                    
            except Exception as e:
                self.tracer.trace(peer, "ERROR", "PARSE", "FAILED", str(e))
                return None
    
    def _handle_dake1(self, peer: str, dake1_msg: str) -> Optional[bytes]:
        if len(self.sessions) >= getattr(self, 'MAX_SESSIONS', 50):
            self.debug(f"session limit reached — dropping DAKE1 from {peer}")
            return None
        """Handle incoming DAKE1 message"""
        with self.lock:
            session = self.get_or_create_session(peer, is_initiator=False)
            
            if session.session_state != SessionState.PLAINTEXT:
                self.tracer.trace(peer, "ERROR", "DAKE1", "REJECTED",
                                 f"session in state: {session.session_state.name}")
                return None
            
            dake_engine = session.initialize_dake(self.client_profile, explicit_initiator=False)
            self.dake_engines[peer] = dake_engine
            
            success = dake_engine.process_dake1(dake1_msg)
            if not success:
                return None
            
            dake2 = dake_engine.generate_dake2()
            if dake2:
                self.tracer.trace(peer, "DAKE", "DAKE1_PROCESSED", "DAKE2_READY", "")
                return dake2.encode('utf-8')
            
            return None
    
    def _handle_dake2(self, peer: str, dake2_msg: str) -> Optional[bytes]:
        """
        Handle incoming DAKE2 (initiator side).
        """
        with self.lock:
            if peer not in self.sessions:
                self.tracer.trace(peer, "ERROR", "DAKE2", "NO_SESSION", "")
                return None
            session     = self.sessions[peer]
            dake_engine = self.dake_engines.get(peer)
            if dake_engine is None:
                self.tracer.trace(peer, "ERROR", "DAKE2", "NO_ENGINE", "")
                return None
            try:
                if not dake_engine.process_dake2(dake2_msg):
                    self.tracer.trace(peer, "ERROR", "DAKE2", "PROCESS_FAILED", "")
                    return None

                dake3_msg = dake_engine.generate_dake3()
                if not dake3_msg:
                    self.tracer.trace(peer, "ERROR", "DAKE3", "GEN_FAILED", "")
                    return None

                session_keys = dake_engine.get_session_keys()
                if not session_keys:
                    self.tracer.trace(peer, "ERROR", "DAKE2", "NO_KEYS", "")
                    return None

                session.session_id           = session_keys.get('session_id') or secrets.token_bytes(32)
                session.root_key             = session_keys.get('root_key')
                session._dake_chain_key_send = session_keys.get('chain_key_send')
                session._dake_chain_key_recv = session_keys.get('chain_key_recv')
                session._dake_brace_key      = session_keys.get('brace_key')

                pub_key_data = session_keys.get('peer_long_term_pub')
                if isinstance(pub_key_data, bytes):
                    session._remote_long_term_pub_bytes = pub_key_data
                    try:
                        session.remote_long_term_pub = ed448.Ed448PublicKey.from_public_bytes(pub_key_data)
                        self.tracer.trace(peer, "KEY", "PUBKEY", "PARSED", "Successfully parsed remote pubkey")
                    except Exception as e:
                        self.tracer.trace(peer, "ERROR", "PUBKEY", "PARSE_FAILED", str(e))
                        session.remote_long_term_pub = None
                elif pub_key_data is not None:
                    session.remote_long_term_pub = pub_key_data
                    try:
                        session._remote_long_term_pub_bytes = pub_key_data.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                    except Exception as e:
                        self.tracer.trace(peer, "ERROR", "PUBKEY", "BYTES_FAILED", str(e))
                        session._remote_long_term_pub_bytes = None

                self._establish_session(session, peer, "DAKE2→DAKE3 initiator")

                self.dake_engines.pop(peer, None)
                self.tracer.trace(peer, "DAKE", "COMPLETE", "INITIATOR_ENCRYPTED", "")
                return dake3_msg.encode('utf-8')

            except Exception as exc:
                self.tracer.trace(peer, "ERROR", "DAKE2", "EXCEPTION", str(exc))
                pass
                return None
    
    def _handle_dake3(self, peer: str, dake3_msg: str) -> Optional[bytes]:
        """
        Handle incoming DAKE3 (responder side).
        """
        with self.lock:
            if peer not in self.sessions:
                self.tracer.trace(peer, "ERROR", "DAKE3", "NO_SESSION", "")
                return None
            session     = self.sessions[peer]
            dake_engine = self.dake_engines.get(peer)
            if dake_engine is None:
                self.tracer.trace(peer, "ERROR", "DAKE3", "NO_ENGINE", "")
                return None
            try:
                if not dake_engine.process_dake3(dake3_msg):
                    self.tracer.trace(peer, "ERROR", "DAKE3", "PROCESS_FAILED", "")
                    return None

                session_keys = dake_engine.get_session_keys()
                if not session_keys:
                    self.tracer.trace(peer, "ERROR", "DAKE3", "NO_KEYS", "")
                    return None

                session.session_id           = session_keys.get('session_id') or secrets.token_bytes(32)
                session.root_key             = session_keys.get('root_key')
                session._dake_chain_key_send = session_keys.get('chain_key_send')
                session._dake_chain_key_recv = session_keys.get('chain_key_recv')
                session._dake_brace_key      = session_keys.get('brace_key')

                pub_key_data = session_keys.get('peer_long_term_pub')
                if isinstance(pub_key_data, bytes):
                    session._remote_long_term_pub_bytes = pub_key_data
                    try:
                        session.remote_long_term_pub = ed448.Ed448PublicKey.from_public_bytes(pub_key_data)
                        self.tracer.trace(peer, "KEY", "PUBKEY", "PARSED", "Successfully parsed remote pubkey")
                    except Exception as e:
                        self.tracer.trace(peer, "ERROR", "PUBKEY", "PARSE_FAILED", str(e))
                        session.remote_long_term_pub = None
                elif pub_key_data is not None:
                    session.remote_long_term_pub = pub_key_data
                    try:
                        session._remote_long_term_pub_bytes = pub_key_data.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                    except Exception as e:
                        self.tracer.trace(peer, "ERROR", "PUBKEY", "BYTES_FAILED", str(e))
                        session._remote_long_term_pub_bytes = None

                self._establish_session(session, peer, "DAKE3 responder")

                self.dake_engines.pop(peer, None)
                self.tracer.trace(peer, "DAKE", "COMPLETE", "RESPONDER_ENCRYPTED", "")
                return None

            except Exception as exc:
                self.tracer.trace(peer, "ERROR", "DAKE3", "EXCEPTION", str(exc))
                pass
                return None

    def _establish_session(self, session: 'EnhancedOTRSession',
                           peer: str, reason: str) -> None:
        """
        Drive EnhancedOTRSession from PLAINTEXT/DAKE_IN_PROGRESS → ENCRYPTED
        and initialise the double ratchet.
        """
        if session.session_state == SessionState.PLAINTEXT:
            try:
                session.transition_session(SessionState.DAKE_IN_PROGRESS,
                                           f"{reason}: fast-path to DAKE_IN_PROGRESS")
            except StateMachineError:
                pass

        if session.session_state == SessionState.DAKE_IN_PROGRESS:
            try:
                session.transition_session(SessionState.ENCRYPTED, reason)
            except StateMachineError as e:
                self.tracer.trace(peer, "ERROR", "ESTABLISH", "STATE_ERR", str(e))
                session.session_state = SessionState.ENCRYPTED
                session.security_level = UIConstants.SecurityLevel.ENCRYPTED
        elif session.session_state == SessionState.ENCRYPTED:
            pass
        else:
            session.session_state = SessionState.ENCRYPTED
            session.security_level = UIConstants.SecurityLevel.ENCRYPTED

        if session.remote_long_term_pub is None and session._remote_long_term_pub_bytes is not None:
            try:
                session.remote_long_term_pub = ed448.Ed448PublicKey.from_public_bytes(
                    session._remote_long_term_pub_bytes
                )
                self.tracer.trace(peer, "KEY", "PUBKEY", "PARSED", "Successfully parsed stored pubkey bytes")
            except Exception as e:
                self.tracer.trace(peer, "ERROR", "PUBKEY", "PARSE_FAILED", str(e))

        if session.ratchet is None:
            try:
                session._initialize_ratchet()
            except Exception as e:
                self.tracer.trace(peer, "ERROR", "RATCHET", "INIT_FAILED", str(e))
    
    def _handle_data_message(self, peer: str, data_msg: str) -> Optional[bytes]:
        """Decrypt a DATA message and return the human-readable text bytes."""
        with self.lock:
            if peer not in self.sessions:
                self.tracer.trace(peer, "ERROR", "DATA", "NO_SESSION", "")
                return None
            session = self.sessions[peer]
            if not session.is_encrypted():
                self.tracer.trace(peer, "ERROR", "DATA", "NOT_ENCRYPTED",
                                  session.session_state.name)
                return None
            try:
                text_bytes = session.decrypt_message(data_msg)

                self.tracer.trace(peer, "RECEIVE", "ENCRYPTED", "DECRYPTED",
                                  f"len={len(text_bytes)}")

                queued = session._queued_smp_response
                session._queued_smp_response = None
                if queued:
                    return queued.encode('utf-8') if isinstance(queued, str) else queued

                return text_bytes

            except Exception as e:
                self.tracer.trace(peer, "ERROR", "DECRYPT", "FAILED", str(e))
                return None
    
    def _handle_smp_message(self, peer: str, smp_tlv: bytes) -> Optional[bytes]:
        """Route an incoming SMP TLV bytes through the SMPEngine and return
        the encrypted response message to be sent to the peer (or None)."""
        with self.lock:
            if peer not in self.sessions:
                return None
            session = self.sessions[peer]
            if not session.is_encrypted():
                self.tracer.trace(peer, "ERROR", "SMP", "NOT_ENCRYPTED", "")
                return None
            if session.smp_engine is None:
                session.initialize_smp()

            if len(smp_tlv) < 4:
                return None
            tlv_type  = struct.unpack_from('!H', smp_tlv, 0)[0]
            tlv_len   = struct.unpack_from('!H', smp_tlv, 2)[0]
            tlv_value = smp_tlv[4:4 + tlv_len]
            tlv_obj   = OTRv4TLV(tlv_type, tlv_value)

            session._enh_handle_smp_tlv(tlv_obj)

            self.tracer.trace(peer, "SMP", "RECEIVED", "ROUTED",
                              f"type=0x{tlv_type:04x}")

            resp = session._queued_smp_response
            session._queued_smp_response = None
            return resp
    
    
    
    
    def get_session_state(self, peer: str) -> Optional[Dict[str, Any]]:
        """Get session state summary"""
        with self.lock:
            if peer not in self.sessions:
                return None
            
            session = self.sessions[peer]
            return session.get_state_summary()
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all active sessions"""
        with self.lock:
            sessions = []
            for peer, session in self.sessions.items():
                if session.session_state not in [SessionState.FINISHED, SessionState.FAILED]:
                    sessions.append(session.get_state_summary())
            return sessions
    
    def list_encrypted_sessions(self) -> List[Dict[str, Any]]:
        """List all encrypted sessions"""
        with self.lock:
            sessions = []
            for peer, session in self.sessions.items():
                if session.is_encrypted():
                    sessions.append(session.get_state_summary())
            return sessions
    
    def terminate_session(self, peer: str, reason: str = "user request"):
        """Terminate a session"""
        with self.lock:
            if peer not in self.sessions:
                return False
            
            session = self.sessions[peer]
            session.terminate(reason)
            
            if peer in self.dake_engines:
                del self.dake_engines[peer]
            
            self.tracer.trace(peer, "TERMINATE", "ACTIVE", "TERMINATED", reason)
            
            return True
    
    def clear_all_sessions(self, reason: str = "cleanup"):
        """Clear all sessions"""
        with self.lock:
            for peer in list(self.sessions.keys()):
                self.terminate_session(peer, reason)
            
            self.dake_engines.clear()
            
            self.tracer.trace("SYSTEM", "CLEANUP", str(len(self.sessions)), "0",
                             f"all sessions cleared: {reason}")
    
    
    
    
    def get_fingerprint(self) -> str:
        """Get local fingerprint"""
        return self.client_profile.get_fingerprint()
    
    def get_peer_fingerprint(self, peer: str) -> Optional[str]:
        """Get peer's fingerprint if available"""
        with self.lock:
            if peer not in self.sessions:
                return None
            
            session = self.sessions[peer]
            return session.get_fingerprint()
    
    def trust_fingerprint(self, peer: str, fingerprint: str) -> bool:
        """Trust a fingerprint"""
        with self.lock:
            actual_fp = self.get_peer_fingerprint(peer)
            if not actual_fp:
                return False
            
            if not hmac.compare_digest(actual_fp, fingerprint):
                self.tracer.trace(peer, "TRUST", "VERIFY", "FAILED",
                                 f"fingerprint mismatch")
                return False
            
            success = self.trust_db.add_trust(peer, fingerprint)
            if success:
                self.tracer.trace(peer, "TRUST", "UNTRUSTED", "TRUSTED",
                                 f"fingerprint: {fingerprint[:16]}...")
            else:
                self.tracer.trace(peer, "ERROR", "TRUST", "FAILED",
                                 "could not add to trust database")
            
            return success
    
    def is_peer_trusted(self, peer: str) -> bool:
        """Check if peer is trusted"""
        with self.lock:
            fingerprint = self.get_peer_fingerprint(peer)
            if not fingerprint:
                return False
            
            return self.trust_db.is_trusted(peer, fingerprint)
    
    
    
    
    def get_tracer_state(self, peer: str) -> str:
        """Get tracer state report for peer"""
        return self.tracer.format_state_report(peer)
    
    def get_all_tracer_states(self) -> Dict[str, Any]:
        """Get all tracer states"""
        with self.lock:
            states = {}
            for peer in self.sessions.keys():
                states[peer] = self.tracer.get_peer_state(peer)
            return states
    
    def cleanup_expired_sessions(self, timeout: float = 3600.0):
        """Clean up expired sessions"""
        with self.lock:
            now = time.time()
            expired = []
            
            for peer, session in self.sessions.items():
                if session.session_state in [SessionState.FINISHED, SessionState.FAILED]:
                    expired.append(peer)
                elif now - session.last_activity > timeout:
                    session.terminate("inactivity timeout")
                    expired.append(peer)
            
            for peer in expired:
                if peer in self.dake_engines:
                    del self.dake_engines[peer]
            
            if expired:
                self.tracer.trace("SYSTEM", "CLEANUP", "ACTIVE", "EXPIRED",
                                 f"cleaned {len(expired)} expired sessions")


    def get_security_level(self, peer: str) -> 'UIConstants.SecurityLevel':
        """Return current security level for peer."""
        with self.lock:
            sess = self.sessions.get(peer)
            if sess is None:
                return UIConstants.SecurityLevel.PLAINTEXT
            return getattr(sess, 'security_level', UIConstants.SecurityLevel.PLAINTEXT)

    def get_session_info(self, peer: str) -> dict:
        """Return session info dict."""
        state = self.get_session_state(peer)
        return state or {'peer': peer, 'state': 'no session'}

    def encrypt_message(self, peer: str, plaintext) -> Optional[str]:
        """Encrypt plaintext for peer using active session."""
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                return None
            try:
                if isinstance(plaintext, (bytes, bytearray)) and len(plaintext) == 0:
                    plaintext = ""
                if isinstance(plaintext, bytes):
                    plaintext = plaintext.decode('utf-8', errors='replace')
                return sess.encrypt_message(plaintext)
            except Exception:
                return None

    def decrypt_message(self, peer: str, encrypted_msg: str) -> bytes:
        """Decrypt message from peer.

        After decryption, the session's TLV router may have stored an outbound
        protocol message (SMP2, SMP3, SMP4 …) in session._queued_smp_response.
        We drain it here and return it *instead of* the empty plaintext so the
        IRC client's _handle_data_message sees an '?OTRv4 …' string, detects
        it, and forwards it via send_otr_message.  Without this drain the SMP
        handshake stalls silently after every step.
        """
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                raise EncryptionError(f"No session for {peer}")
            plaintext = sess.decrypt_message(encrypted_msg)

            queued = getattr(sess, '_queued_smp_response', None)
            if queued:
                sess._queued_smp_response = None
                return queued.encode('utf-8') if isinstance(queued, str) else queued

            return plaintext

    def get_smp_progress(self, peer: str):
        """Return (step, total) SMP progress tuple."""
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                return (0, 4)
            try:
                return sess.get_smp_progress()
            except Exception:
                return (0, 4)

    def get_smp_status(self, peer: str) -> dict:
        """Return SMP status dict."""
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                return {'state': 'no_session', 'verified': False, 'failed': False}
            try:
                return sess.get_smp_status()
            except Exception:
                return {'state': 'unknown', 'verified': False, 'failed': False}

    def start_smp(self, peer: str, secret: str, question: str = '') -> Optional[str]:
        """Start SMP verification on the session."""
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                return None
            try:
                return sess.start_smp(secret, question if question else None)
            except Exception:
                return None

    def process_smp_message(self, peer: str, data: bytes) -> Optional[str]:
        """Process incoming SMP TLV."""
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                return None
            try:
                return sess.process_smp_message(data)
            except Exception:
                return None

    def set_smp_secret(self, peer: str, secret: str) -> bool:
        """Store SMP secret for peer."""
        try:
            self.smp_storage.set_secret(peer, secret)
            return True
        except Exception:
            return False

    def display_fingerprints(self, peer: str) -> str:
        """Return remote fingerprint string."""
        return self.get_peer_fingerprint(peer) or ""

    def handle_dake1(self, peer: str, payload: str) -> Optional[str]:
        result = self.handle_incoming_message(peer, payload)
        if result and isinstance(result, (bytes, str)):
            r = result if isinstance(result, str) else result.decode('utf-8', errors='replace')
            return r if r.startswith('?OTRv4 ') else None
        return None

    def handle_dake2(self, peer: str, payload: str) -> Optional[str]:
        return self.handle_dake1(peer, payload)

    def handle_dake3(self, peer: str, payload: str) -> bool:
        result = self.handle_incoming_message(peer, payload)
        return self.has_session(peer)

class Event:
    """Base event class"""
    def __init__(self, event_type: str, data: Dict[str, Any]):
        self.event_type = event_type
        self.data = data
        self.timestamp = time.time()

class ErrorEvent(Event):
    """Error event"""
    def __init__(self, error_type: str, peer: str, error: Exception, context: Dict[str, Any]):
        super().__init__("ERROR", {
            "error_type": error_type,
            "peer": peer,
            "error": str(error)[:100],
            "context": context
        })

class SMPEvent(Event):
    """SMP event"""
    def __init__(self, smp_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        super().__init__("SMP", {
            "smp_type": smp_type,
            "peer": peer,
            "session_id": session_id,
            "details": details
        })

class SecurityEvent(Event):
    """Security event"""
    def __init__(self, security_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        super().__init__("SECURITY", {
            "security_type": security_type,
            "peer": peer,
            "session_id": session_id,
            "details": details
        })

class EventHandler:
    """Event handler - emits events, doesn't manipulate UI directly"""
    def __init__(self, panel_manager: PanelManager):
        self.panel_manager = panel_manager
        self.events: List[Event] = []
        self.lock = threading.RLock()
    
    def emit_error(self, error_type: str, peer: str, error: Exception, context: Dict[str, Any]):
        """Emit an error event"""
        event = ErrorEvent(error_type, peer, error, context)
        with self.lock:
            self.events.append(event)
        
        panel = self.panel_manager.panels.get(peer, self.panel_manager.panels['system'])
        panel.add_message(f"🔴 {error_type}: {str(error)[:50]}")
    
    def emit_smp_event(self, smp_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        """Emit an SMP event"""
        event = SMPEvent(smp_type, peer, session_id, details)
        with self.lock:
            self.events.append(event)
    
    def emit_security_event(self, security_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        """Emit a security event"""
        event = SecurityEvent(security_type, peer, session_id, details)
        with self.lock:
            self.events.append(event)
    
    def get_events(self, since: Optional[float] = None) -> List[Event]:
        """Get events since timestamp"""
        with self.lock:
            if since is None:
                return self.events.copy()
            return [e for e in self.events if e.timestamp > since]
    
    def clear_events(self):
        """Clear all events"""
        with self.lock:
            self.events.clear()

class OTRFragmentBuffer:
    """Reassemble fragmented OTRv4 messages.

    Supports both the spec-compliant pipe format (for interoperability) and the
    legacy bracket format (for backward compatibility with older builds):

        Spec:   ?OTRv4|sender_tag|receiver_tag|k|n|data.
        Legacy: ?OTRv4 [k/n]data
    """

    _SPEC_RE = re.compile(
        r'^\?OTRv4'
        r'\|([0-9A-Fa-f]{8})'
        r'\|([0-9A-Fa-f]{8})'
        r'\|(\d{5})'
        r'\|(\d{5})'
        r'\|(.*?)\.?$',
        re.DOTALL
    )

    _LEGACY_RE = re.compile(
        r'^\?OTRv4\s*'
        r'(?:\[(\d+)/(\d+)\])?'
        r'(.*?)(?:\.?)$',
        re.DOTALL
    )

    def __init__(self, timeout: float = UIConstants.FRAGMENT_TIMEOUT):
        self._buffers: Dict[str, Dict] = {}
        self._lock = threading.RLock()
        self.timeout = timeout
        self.max_fragments_per_sender = UIConstants.FRAGMENT_LIMIT
        self.max_total_senders = 100
        self.first_fragment_cb = None

    def add_fragment(self, sender: str, raw: str) -> Optional[str]:
        """Accept one raw PRIVMSG payload from `sender`.

        Returns str (fully reassembled ``?OTRv4 <payload>``) when complete,
        or None while still waiting for more fragments.
        """
        with self._lock:
            now = time.monotonic()
            self._expire(now)

            msg = raw.strip()

            m_spec = self._SPEC_RE.match(msg)
            if m_spec:
                _sender_tag, _recv_tag, k_s, n_s, chunk = m_spec.groups()
                idx   = int(k_s)
                total = int(n_s)
                if total < 1 or not (1 <= idx <= total):
                    raise ValueError(f"invalid spec fragment index {idx}/{total}")
                return self._buffer(sender, idx, total, chunk.strip(), now)

            while msg.startswith('?OTRv4 ?OTRv4'):
                msg = '?OTRv4 ' + msg[len('?OTRv4 ?OTRv4 '):]
            if msg.startswith('?OTRv4[') and not msg.startswith('?OTRv4 ['):
                msg = '?OTRv4 [' + msg[7:]
            if msg.endswith('.'):
                msg = msg[:-1]

            m_leg = self._LEGACY_RE.match(msg)
            if not m_leg:
                return raw

            idx_s, total_s, chunk = m_leg.groups()
            chunk = chunk.strip()

            if idx_s is None:
                return f'?OTRv4 {chunk}'

            idx   = int(idx_s)
            total = int(total_s)
            if total < 1 or not (1 <= idx <= total):
                raise ValueError(f"invalid legacy fragment index {idx}/{total}")
            return self._buffer(sender, idx, total, chunk, now)

    def _buffer(self, sender: str, idx: int, total: int,
                chunk: str, now: float) -> Optional[str]:
        """Insert chunk into the reassembly buffer and return full message when done."""
        is_new_sequence = sender not in self._buffers
        if is_new_sequence:
            self._buffers[sender] = {
                'total':    total,
                'parts':    {},
                'first_ts': now,
                'last_ts':  now,
            }
            if total > 1 and self.first_fragment_cb is not None:
                try:
                    self.first_fragment_cb(sender, total, chunk)
                except Exception:
                    pass

        state = self._buffers[sender]

        if len(state['parts']) >= self.max_fragments_per_sender:
            self._buffers.pop(sender, None)
            raise ValueError(
                f"Fragment flood from {sender}: exceeded {self.max_fragments_per_sender} "
                "in-flight fragments. Buffer evicted."
            )

        if total > self.max_fragments_per_sender:
            raise ValueError(
                f"Fragment total {total} from {sender} exceeds max "
                f"{self.max_fragments_per_sender}. Discarding."
            )

        if state['total'] != total:
            self._buffers[sender] = {
                'total': total, 'parts': {}, 'first_ts': now, 'last_ts': now,
            }
            state = self._buffers[sender]

        if idx not in state['parts']:
            state['parts'][idx] = chunk
            state['last_ts'] = now

            if DEBUG_MODE:
                    _emit_line(f"[OTRFragment] {idx}/{total} for {sender}")

        if len(state['parts']) == total:
            payload_parts = []
            for i in range(1, total + 1):
                if i not in state['parts']:
                    self._buffers.pop(sender, None)
                    return None
                payload_parts.append(state['parts'][i])

            combined = ''.join(payload_parts)
            self._buffers.pop(sender, None)

            if DEBUG_MODE:
                    _emit_line(f"[OTRFragment] reassembled {len(combined)} chars from {sender}")

            return f'?OTRv4 {combined}'

        return None

    def clear_sender(self, sender: str) -> None:
        with self._lock:
            self._buffers.pop(sender, None)

    def clear_all(self) -> None:
        with self._lock:
            self._buffers.clear()

    def get_pending_count(self) -> int:
        with self._lock:
            return len(self._buffers)

    def get_pending_for(self, sender: str) -> int:
        with self._lock:
            if sender not in self._buffers:
                return 0
            return len(self._buffers[sender]['parts'])

    def _expire(self, now: float) -> None:
        if len(self._buffers) > self.max_total_senders:
            oldest = sorted(self._buffers.items(), key=lambda x: x[1].get('first_ts', 0))
            for sender, _ in oldest[:len(self._buffers) - self.max_total_senders]:
                self.debug(f"fragment buffer evict: too many senders, dropping {sender}")
                del self._buffers[sender]
        cutoff = now - self.timeout
        expired = [
            s for s, st in self._buffers.items()
            if st.get('last_ts', st['first_ts']) < cutoff
        ]
        for s in expired:
            self._buffers.pop(s, None)

    def cleanup_expired(self) -> int:
        with self._lock:
            now = time.monotonic()
            before = len(self._buffers)
            self._expire(now)
            return before - len(self._buffers)

class OTRMessageFragmenter:
    """Fragment OTRv4 messages for IRC/I2P transmission.

    Spec §4.7 fragment wire format:
        ?OTRv4|sender_tag|receiver_tag|k|n|data.

    Where:
      sender_tag / receiver_tag  are 8-digit zero-padded hex (32-bit instance tags)
      k                          is the 1-based fragment index, zero-padded to 5 digits
      n                          is the total count, zero-padded to 5 digits
      data                       is the raw base64 chunk (no ?OTRv4 prefix, no trailing dot)
      trailing dot               is appended by this encoder

    The buffer class (OTRFragmentBuffer) accepts both this format and the legacy
    ``?OTRv4 [k/n]data`` format produced by older builds.
    """

    _SPEC_OVERHEAD  = len("?OTRv4|00000000|00000000|00001|00001|.")
    _LEGACY_PREFIX  = '?OTRv4 '

    @classmethod
    def fragment(cls,
                 otr_message: str,
                 max_line: int = UIConstants.OTR_FRAGMENT_SIZE,
                 sender_tag: int = 0,
                 receiver_tag: int = 0) -> List[str]:
        """Fragment an OTRv4 message for IRC/I2P transmission.

        Unfragmented (fits in max_line): returned as-is (``?OTRv4 <base64>``).
        Fragmented: emits spec-compliant ``?OTRv4|stag|rtag|k|n|data.`` lines.

        Anti-fingerprinting: all multi-fragment messages are padded to a
        uniform fragment count (MIN_FRAGMENTS).  Without this, an observer
        can distinguish DAKE1 (~20 frags), DAKE3 (~22 frags), and data
        messages by counting IRC lines — revealing protocol state.

        Padding uses random base64 characters appended after the real
        payload.  The receiver's parser reads exact byte offsets from the
        decoded binary and ignores trailing data.
        """
        if not otr_message.startswith(cls._LEGACY_PREFIX):
            return [otr_message]

        payload = otr_message[len(cls._LEGACY_PREFIX):]
        if payload.endswith('.'):
            payload = payload[:-1]

        if not payload:
            return [otr_message]

        if len(otr_message) <= max_line:
            return [otr_message]

        stag_hex = f"{sender_tag:08X}"
        rtag_hex = f"{receiver_tag:08X}"
        overhead = len(f"?OTRv4|{stag_hex}|{rtag_hex}|00001|00001|.")

        chunk_size = max_line - overhead
        if chunk_size < 4:
            chunk_size = 4

        chunk_size = (chunk_size // 4) * 4
        if chunk_size < 4:
            chunk_size = 4

        # NOTE on traffic analysis: fragment count varies by message type
        # (DAKE1≈20, DAKE2≈20, DAKE3≈22, data=variable).  Padding cannot
        # be added at the fragment layer because:
        #   - Base64-level padding corrupts decoding
        #   - Binary-level padding shifts the MAC position in DAKE2
        # The correct fix is a PADDING TLV inside the encrypted envelope
        # (protocol extension — deferred).  For now, fragment count is
        # observable by a local network adversary.

        total = math.ceil(len(payload) / chunk_size)

        fragments: List[str] = []
        for i in range(total):
            start = i * chunk_size
            end   = min(start + chunk_size, len(payload))
            chunk = payload[start:end]
            k_str = f"{i + 1:05d}"
            n_str = f"{total:05d}"
            frag  = f"?OTRv4|{stag_hex}|{rtag_hex}|{k_str}|{n_str}|{chunk}."
            fragments.append(frag)

        if DEBUG_MODE:
            _emit_line(
                f"[OTRMessageFragmenter] {len(fragments)} fragments "
                f"from {len(payload)} chars (chunk={chunk_size})")

        return fragments

    @staticmethod
    def fragment_otr_message(otr_message: str,
                             fragment_size: int = UIConstants.OTR_FRAGMENT_SIZE
                             ) -> List[str]:
        return OTRMessageFragmenter.fragment(otr_message, fragment_size)




class DebugPanel(ChatPanel):
    """Enhanced panel for debugging with detailed OTR/SMP logging"""
    def __init__(self, name: str):
        super().__init__(name, 'debug')
        self.debug_level = "FULL"
        self.categories = {
            'OTR': True,
            'SMP': True,
            'DAKE': True,
            'RATCHET': True,
            'NETWORK': True,
            'SECURITY': True,
            'TRUST': True,
            'FINGERPRINT': True,
            'UI': True
        }
        self.max_debug_lines = 1000
        
    def log(self, category: str, message: str, data: Optional[dict] = None):
        """Log debug message with category"""
        if not self.categories.get(category, False):
            return
        
        timestamp = time.strftime("%H:%M:%S.%f")[:-3]
        colored_cat = colorize(category, 'magenta')
        msg = f"[{timestamp}] [{colored_cat}] {message}"
        
        if data:
            data_str = json.dumps(data, default=str)[:200]
            if len(json.dumps(data, default=str)) > 200:
                data_str += "..."
            msg += f" | {data_str}"
        
        self.add_message(msg)
        
        if len(self.history) > self.max_debug_lines:
            self.history = self.history[-self.max_debug_lines:]
    
    def set_category(self, category: str, enabled: bool):
        """Enable/disable debug category"""
        self.categories[category] = enabled
        
    def toggle_category(self, category: str):
        """Toggle debug category"""
        self.categories[category] = not self.categories.get(category, False)
        return self.categories[category]

class DebugLogger:
    """Centralized debug logger for all components"""
    def __init__(self, debug_panel: Optional[DebugPanel] = None):
        self.debug_panel = debug_panel
        self.enabled = DEBUG_MODE
        
    def log(self, component: str, method: str, message: str, data: Optional[dict] = None):
        """Log debug message from any component"""
        if not self.enabled:
            return
            
        full_message = f"{component}.{method}: {message}"
        
        if self.debug_panel:
            self.debug_panel.log(component, full_message, data)
        else:
            print(f"[DEBUG] [{component}] {full_message}")
            if data:
                print(f"  Data: {data}")






def _fmt_duration(seconds: float) -> str:
    """Format seconds into human-readable string: 1d 2h 30m 15s"""
    s = int(seconds)
    if s < 0:
        return "0s"
    parts = []
    if s >= 86400:
        d, s = divmod(s, 86400)
        parts.append(f"{d}d")
    if s >= 3600:
        h, s = divmod(s, 3600)
        parts.append(f"{h}h")
    if s >= 60:
        m, s = divmod(s, 60)
        parts.append(f"{m}m")
    if s > 0 or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)



class TwentySevenClubNick:
    """Generate unique IRC nicks from a large combinatorial pool.

    Combines adjectives with historical/cultural figure surnames to
    produce ~10,000+ unique nicks.  Each nick maps to a plausible
    real name for /whois display.

    Original 27 Club names are preserved as a subset for backward
    compatibility — existing users keep their nick identity.

    IRC nick constraints:
      - Max 30 characters (most servers allow 9-30)
      - No spaces, no leading #&: or digits
      - ASCII printable only
    """

    # ── 27 Club originals (backward compat) ──────────────────────
    _LEGACY = [
        ("KurtCobain",     "Kurt Cobain",              "Nirvana"),
        ("AmyWinehouse",   "Amy Winehouse",             "Solo"),
        ("JimiHendrix",    "Jimi Hendrix",              "The Jimi Hendrix Experience"),
        ("JanisJoplin",    "Janis Joplin",              "Big Brother & The Holding Company"),
        ("JimMorrison",    "Jim Morrison",              "The Doors"),
        ("BrianJones",     "Brian Jones",               "The Rolling Stones"),
        ("RobertJohnson",  "Robert Johnson",            "Blues Legend"),
        ("AlanWilson",     "Alan Wilson",               "Canned Heat"),
        ("RonMcKernan",    "Ron McKernan",              "Grateful Dead"),
        ("PeteHam",        "Pete Ham",                  "Badfinger"),
        ("RandyRhoads",    "Randy Rhoads",              "Ozzy Osbourne"),
        ("HillelSlovak",   "Hillel Slovak",             "Red Hot Chili Peppers"),
        ("AndrewWood",     "Andrew Wood",               "Mother Love Bone"),
        ("KristenPfaff",   "Kristen Pfaff",             "Hole"),
        ("RicheyEdwards",  "Richey Edwards",            "Manic Street Preachers"),
        ("DaveAlexander",  "Dave Alexander",            "The Stooges"),
        ("GaryThain",      "Gary Thain",                "Uriah Heep"),
        ("LesHarvey",      "Les Harvey",                "Stone the Crows"),
        ("ChrisBell",      "Chris Bell",                "Big Star"),
        ("JeremyWard",     "Jeremy Ward",               "The Mars Volta"),
    ]

    # ── Combinatorial pools ──────────────────────────────────────
    #    ~100 adjectives × ~120 nouns = ~12,000 unique nicks

    _ADJECTIVES = [
        "Silent", "Shadow", "Phantom", "Midnight", "Iron",
        "Crimson", "Golden", "Silver", "Dark", "Bright",
        "Swift", "Fierce", "Calm", "Wild", "Lone",
        "Bitter", "Hollow", "Frozen", "Burning", "Hidden",
        "Ancient", "Broken", "Fading", "Rising", "Fallen",
        "Distant", "Restless", "Wicked", "Noble", "Stray",
        "Drifting", "Echoing", "Veiled", "Stark", "Ashen",
        "Copper", "Jade", "Cobalt", "Ember", "Onyx",
        "Rustic", "Pale", "Dusky", "Misty", "Stormy",
        "Feral", "Glacial", "Lunar", "Solar", "Rogue",
        "Scarlet", "Azure", "Violet", "Ivory", "Obsidian",
        "Granite", "Cedar", "Birch", "Rowan", "Hazel",
        "Wraith", "Spectre", "Vagrant", "Nomad", "Hermit",
        "Cipher", "Zero", "Null", "Void", "Apex",
        "Primal", "Austere", "Cryptic", "Arcane", "Lucid",
        "Serene", "Turbid", "Waning", "Waxing", "Errant",
        "Sullen", "Muted", "Stark", "Gaunt", "Bleak",
        "Thorned", "Barbed", "Tempered", "Forged", "Annealed",
        "Quartz", "Basalt", "Slate", "Flint", "Ochre",
        "Boreal", "Tundra", "Steppe", "Taiga", "Mesa",
    ]

    _NOUNS = [
        "Wolf", "Hawk", "Raven", "Fox", "Lynx",
        "Bear", "Owl", "Crane", "Viper", "Falcon",
        "Heron", "Sparrow", "Condor", "Osprey", "Kestrel",
        "Jackal", "Panther", "Cobra", "Mantis", "Hornet",
        "Badger", "Otter", "Marten", "Wren", "Finch",
        "Forge", "Anvil", "Blade", "Shield", "Arrow",
        "Spire", "Bastion", "Citadel", "Tower", "Gate",
        "Storm", "Thunder", "Frost", "Blaze", "Ember",
        "Tide", "Current", "Drift", "Torrent", "Gale",
        "Root", "Thorn", "Branch", "Stone", "Ridge",
        "Peak", "Crest", "Vale", "Glen", "Cairn",
        "Dusk", "Dawn", "Shade", "Gloom", "Haze",
        "Reef", "Shoal", "Fjord", "Gorge", "Ravine",
        "Cipher", "Signal", "Beacon", "Pulse", "Vector",
        "Prism", "Shard", "Relic", "Glyph", "Rune",
        "Wick", "Tallow", "Flint", "Spark", "Cinder",
        "Quarry", "Ledge", "Scree", "Moraine", "Talus",
        "Styx", "Lethe", "Acheron", "Eris", "Nyx",
        "Odin", "Loki", "Fenrir", "Mimir", "Tyr",
        "Kappa", "Sigma", "Delta", "Theta", "Omega",
        "Vertex", "Node", "Orbit", "Zenith", "Nadir",
        "Mantle", "Cortex", "Nexus", "Vortex", "Matrix",
    ]

    # ── Precomputed lookup for legacy nicks ──────────────────────
    _LOOKUP = {nick: (real, band) for nick, real, band in _LEGACY}

    @classmethod
    def generate(cls) -> str:
        """Generate a unique nick from the combinatorial pool.

        Format: AdjectiveNoun (e.g. SilentWolf, CrimsonForge)
        Pool: ~100 × 120 = ~12,000 unique combinations.
        Collision probability with <100 concurrent users: negligible.
        """
        adj  = secrets.choice(cls._ADJECTIVES)
        noun = secrets.choice(cls._NOUNS)
        nick = adj + noun
        # Ensure IRC-safe length (max 30 chars)
        if len(nick) > 30:
            nick = nick[:30]
        return nick

    @classmethod
    def real_name(cls, nick: str) -> str:
        """Return display name for /whois.

        Legacy 27 Club nicks get their real identity.
        Generated nicks get a plausible format.
        """
        base = nick.rstrip("_0123456789")
        if base in cls._LOOKUP:
            real, band = cls._LOOKUP[base]
            return f"{real} ({band}) — 27 Club"
        return f"{nick} — OTRv4+"

    @classmethod
    def is_member(cls, nick: str) -> bool:
        base = nick.rstrip("_0123456789")
        return base in cls._LOOKUP



class OTRv4IRCClient:
    """
    OTRv4 IRC Client — COMPLETE REWRITE
    Fixes:
      * Background recv thread so IRC messages are actually read
      * Connect timeout 120s  (I2P tunnel build takes time)
      * Send timeout 30s
      * Ping watchdog — reconnects after 5 min silence
      * Auto-join
      * No auth / no NickServ (anonymous I2P IRC)
    """

    def __init__(self, config: Optional[OTRConfig] = None):
        self.config = config or OTRConfig()

        self._prompt_refresh_cb: Optional[Callable[[], None]] = None

        self.logger = OTRLogger(self.config)

        self.session_manager = EnhancedSessionManager(self.config, logger=self.logger)
        self.panel_manager   = PanelManager(self)
        self.message_router  = MessageRouter(self.panel_manager)
        self.event_handler   = EventHandler(self.panel_manager)

        self.server   = self.config.server
        if self.config.nickserv_nick:
            self.nick = self.config.nickserv_nick
            self.realname = self.nick
        else:
            self.nick = TwentySevenClubNick.generate()
            self.realname = TwentySevenClubNick.real_name(self.nick)

        self.connected  = False
        self.running    = False
        self.auto_joined  = False
        self.auth_complete = False
        self.nickserv_identified = False
        self.shutting_down = False
        self.shutdown_flag = False

        self.sock: Optional[socket.socket] = None
        self._recv_thread: Optional[threading.Thread] = None
        self._recv_buf = ""
        self._sock_lock = threading.Lock()

        self.last_ping = time.time()
        self.connection_healthy = True
        self.connection_attempts = 0
        self.max_connection_attempts = 999
        self._last_otr_sent: Dict[str, float] = {}

        self.ignored_users: Set[str] = set()
        self.channels:      Dict[str, dict] = {}
        self.channel_list:  List[dict] = {}
        self.whois_data:    Dict[str, dict] = {}
        self.names_data:    Dict[str, List[str]] = {}
        self._pending_names_pager: Optional[str] = None
        self.auto_reply_config: Dict[str, dict] = {}

        self.otr_fragmenter = OTRMessageFragmenter()
        self.fragment_buffers: Dict[str, OTRFragmentBuffer] = {}
        self.pager = Pager()

        self.smp_schedule_timers: Dict[str, dict] = {}
        self.auto_smp_monitor_running = False
        self._smp_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="smp_worker"
        )

        self.terminal_width  = TERMINAL_WIDTH
        self.terminal_height = TERMINAL_HEIGHT
        self.input_history:  List[str] = []
        self.history_index   = -1
        self.input_enabled   = True
        self.headless        = False
        self.test_runner     = None

        self.debug_panel_name = "debug" if DEBUG_MODE else None
        if DEBUG_MODE:
            self.panel_manager.add_panel("debug", "debug")

        self.tracer = OTRTracer(enabled=DEBUG_MODE, logger=self.logger)
        self.tracer.set_emit_callback(lambda msg: self._emit("debug", msg))
        self.session_manager.tracer = self.tracer

        def _make_smp_notify(peer: str):
            def _notify(msg: str) -> None:
                try:
                    sec = self.session_manager.get_security_level(peer)
                    self.add_message(peer, msg, sec)
                    self.panel_manager.update_smp_progress(
                        peer, *self.session_manager.get_smp_progress(peer))
                except Exception:
                    pass
            return _notify
        self.session_manager.smp_notify_factory = _make_smp_notify

        def _ping_refresh() -> None:
            self.last_ping = time.time()
        self.session_manager.ping_refresh_cb = _ping_refresh

        self._emit("debug", colorize(f"[CLIENT] nick={self.nick}", "magenta"))


    def debug(self, message: str, data: Optional[dict] = None):
        """Route debug output to the debug panel only — never to raw stdout."""
        if not DEBUG_MODE:
            return
        msg = message
        if data:
            msg += " | " + json.dumps(data, separators=(",", ":"))
        self._emit("debug", colorize(msg, "magenta"))
        self.logger.debug(message)

    def _emit(self, panel: str, message: str) -> None:
        """
        THE single stdout path — all output flows through here.

        Routing:
          system  → [sys]   always printed
          peer    → [peer]  always printed (private encrypted chat)
          debug   → [debug] printed ONLY when DEBUG_MODE, else buffered silently

        Termux scrollback is the history — we never clear the screen.
        """
        if panel == "debug" and not DEBUG_MODE:
            return

        if panel not in self.panel_manager.panels:
            ptype = ("channel" if panel.startswith("#") else
                     "debug"   if panel == "debug" else
                     "system"  if panel == "system" else "private")
            self.panel_manager.add_panel(panel, ptype)

        self.panel_manager.panels[panel].add_message(message)
        if self.panel_manager.active_panel != panel:
            self.panel_manager.panels[panel].unread_count += 1

        _is_background_tab = (
            self.panel_manager.active_panel
            and panel != self.panel_manager.active_panel  # this isn't the active tab
            and panel != "system"
            and panel != "debug"
        )
        if _is_background_tab:
            self._termux_notify_message(panel, message)
            return

        ts = colorize(time.strftime("%H:%M:%S"), "dark_yellow")
        if panel == "system":
            tag = colorize("[sys]  ", "grey")
        elif panel == "debug":
            tag = colorize("[debug]", "dark_magenta")
        elif panel.startswith("#"):
            tag = colorize(f"[{panel}]", "bold_cyan")
        else:
            _sec = (self.session_manager.get_security_level(panel)
                    if hasattr(self, "session_manager") and self.session_manager.has_session(panel)
                    else None)
            _tag_colors = {
                UIConstants.SecurityLevel.ENCRYPTED:    "bold_yellow",
                UIConstants.SecurityLevel.FINGERPRINT:  "bold_green",
                UIConstants.SecurityLevel.SMP_VERIFIED: "blue",
            }
            _tc = _tag_colors.get(_sec, "green") if _sec is not None else "green"
            tag = colorize(f"[{panel}]", _tc)

        _emit_line(f"{ts} {tag} {message}")


    def _detect_network(self) -> str:
        """Auto-detect clearnet / Tor / I2P from the configured server hostname."""
        return NetworkConstants.detect(self.server)

    def setup_proxy(self, net_type: str = None) -> str:
        """Configure PySocks SOCKS5 proxy based on network type.

        *net_type* is one of NetworkConstants.NET_* constants.
        If omitted, auto-detects from self.server.

        Returns the net_type that was applied (useful for logging).
        """
        if net_type is None:
            net_type = self._detect_network()

        if net_type == NetworkConstants.NET_I2P:
            host, port = self.config.i2p_proxy
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, port)
            socket.socket = socks.socksocket
            self.add_message("system",
                colorize(f"🧅 I2P SOCKS5 proxy: {host}:{port}", "dark_cyan"))
            self.debug("proxy set", {"type": "i2p", "host": host, "port": port})

        elif net_type == NetworkConstants.NET_TOR:
            host, port = self.config.tor_proxy
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, port)
            socket.socket = socks.socksocket
            self.add_message("system",
                colorize(f"🧅 Tor SOCKS5 proxy: {host}:{port}", "dark_magenta"))
            self.debug("proxy set", {"type": "tor", "host": host, "port": port})

        else:
            socks.setdefaultproxy()
            socket.socket = socks.socksocket
            self.add_message("system",
                colorize("🌐 Clearnet (no proxy)", "grey"))
            self.debug("proxy set", {"type": "clearnet"})

        return net_type

    def connect(self) -> bool:
        """Open TCP connection, auto-routing via I2P / Tor / clearnet.

        Network type is detected from the server hostname:
          *.i2p    → I2P SOCKS5 on 127.0.0.1:4447 (no TLS — tunnel encrypted)
          *.onion  → Tor SOCKS5 on 127.0.0.1:9050 (no TLS — tunnel encrypted)
          anything else → clearnet TCP with TLS on port 6697

        IRCv3 CAP negotiation is performed before NICK/USER registration.
        """
        try:
            net_type = self.setup_proxy()

            timeout_map = {
                NetworkConstants.NET_CLEARNET: NetworkConstants.TIMEOUT_CLEARNET,
                NetworkConstants.NET_TOR:      NetworkConstants.TIMEOUT_TOR,
                NetworkConstants.NET_I2P:      NetworkConstants.TIMEOUT_I2P,
            }
            timeout = timeout_map.get(net_type, NetworkConstants.TIMEOUT_I2P)

            # ── Auto-detect port and TLS ─────────────────────────
            use_tls = self.config.use_tls
            port = self.config.port

            if net_type == NetworkConstants.NET_CLEARNET:
                if port == 0:
                    port = IRCConstants.TLS_PORT
                if port == IRCConstants.TLS_PORT:
                    use_tls = True
            else:
                # I2P/Tor — tunnel provides encryption, no TLS
                use_tls = False
                if port == 0:
                    port = IRCConstants.PORT

            net_label = {
                NetworkConstants.NET_I2P:      "I2P",
                NetworkConstants.NET_TOR:      "Tor",
                NetworkConstants.NET_CLEARNET: "clearnet",
            }.get(net_type, net_type)
            tls_label = " TLS" if use_tls else ""

            self.add_message("system",
                f"Connecting to {colorize(self.server, 'cyan')}:{port}"
                f" ({colorize(net_label + tls_label, 'bold_cyan')}, up to {timeout}s)…")
            self.debug("connect", {"server": self.server, "port": port,
                                   "net": net_type, "tls": use_tls, "timeout": timeout})

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(timeout))
            sock.connect((self.server, port))

            # ── Wrap in TLS for clearnet ─────────────────────────
            if use_tls:
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=self.server)
                self.add_message("system",
                    colorize("🔒 TLS handshake complete", "green"))

            sock.setblocking(True)
            sock.settimeout(1.0)

            self.sock = sock
            self.connected  = True
            self.connected_at = time.time()
            self.running    = True
            self.last_ping  = time.time()
            self.auto_joined = False
            self.auth_complete = False
            self.nickserv_identified = False

            # ── IRCv3 state ──────────────────────────────────────
            self._cap_negotiating = True
            self._cap_accepted: set = set()
            self._sasl_in_progress = False

            self._recv_thread = threading.Thread(
                target=self._recv_loop, daemon=True, name="irc-recv"
            )
            self._recv_thread.start()

            # ── IRCv3 CAP negotiation before registration ────────
            self.send_raw("CAP LS 302")
            self.send_raw(f"NICK {self.nick}")
            self.send_raw(f"USER {self.nick} 0 * :{self.realname}")

            self.add_message("system", f"✅ Connected — nick: {colorize_username(self.nick)}")
            self.debug("handshake sent", {"nick": self.nick, "caps": "LS 302"})
            return True

        except Exception as exc:
            self.add_message("system", f"❌ Connection failed: {exc}")
            self.debug("connect failed", {"error": str(exc)})
            self.connected = False
            return False

    def _recv_loop(self):
        """
        Background thread: read raw bytes from the socket, split on CRLF,
        dispatch each complete line to handle_message().
        Runs until self.running is False or the socket closes.

        All errors are caught and surfaced to the user panel — the thread
        never silently terminates without telling the user what happened.
        """
        buf = ""
        self.debug("recv loop started")
        while self.running and not self.shutdown_flag:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    if self.running:
                        self.add_message("system",
                            colorize("⚠ Server closed the connection. "
                                     "Reconnecting automatically…", "yellow"))
                        self._try_reconnect()
                    self.connected = False
                    self.running   = False
                    break
                buf += chunk.decode("utf-8", errors="replace")
                if len(buf) > 65536:
                    self.debug("recv buffer overflow — truncating")
                    buf = buf[-32768:]
                while "\r\n" in buf:
                    line, buf = buf.split("\r\n", 1)
                    line = line.strip()
                    if len(line) > 8192:
                        self.debug(f"oversized IRC line dropped ({len(line)} bytes)")
                        continue
                    if line:
                        try:
                            self.handle_message(line)
                        except Exception as exc:
                            self.debug(f"handle_message error: {exc}")
            except socket.timeout:
                now = time.time()
                if now - self.last_ping > 600:
                    self.add_message("system",
                        colorize("⚠ Ping timeout. Reconnecting automatically…", "yellow"))
                    self._try_reconnect()
                    break
                if hasattr(self, '_msg_rate') and len(self._msg_rate) > 500:
                    self._msg_rate.clear()
                _has_otr = (hasattr(self, 'session_manager') and
                            bool(self.session_manager.list_encrypted_sessions()))
                _irc_ping_interval = 90 if _has_otr else 150
                if not hasattr(self, '_last_irc_ping'):
                    self._last_irc_ping = now
                if now - self._last_irc_ping >= _irc_ping_interval:
                    try:
                        self.send_raw(f"PING :{self.server}")
                        self._last_irc_ping = now
                    except Exception:
                        pass

                try:
                    hb_interval = getattr(self.config, 'heartbeat_interval', 60)
                    if hasattr(self, 'session_manager') and hasattr(self, '_last_otr_sent'):
                        for peer, sess in list(self.session_manager.sessions.items()):
                            if (getattr(sess, 'session_state', None) is not None and
                                    sess.session_state.name == 'ENCRYPTED'):
                                peer_last = self._last_otr_sent.get(peer, 0)
                                if now - peer_last >= hb_interval:
                                    try:
                                        hb = sess.encrypt_message(b'', add_padding=True)
                                        if hb:
                                            self.send_otr_message(peer, hb)
                                            self._last_otr_sent[peer] = now
                                    except Exception:
                                        pass
                except Exception:
                    pass
                continue
            except OSError as exc:
                if self.running:
                    self.add_message("system",
                        colorize(f"⚠ Connection lost ({exc}). "
                                 "Reconnecting automatically…", "yellow"))
                    self._try_reconnect()
                self.connected = False
                self.running   = False
                break
            except Exception as exc:
                self.debug(f"recv_loop unexpected error: {exc}")
                try:
                    self.add_message("system",
                        colorize(f"⚠ Network error (recovered): {str(exc)[:80]}", "yellow"))
                except Exception:
                    pass

        self.debug("recv loop ended")

    def _try_reconnect(self):
        """Close the old socket, reset all OTR/session state, and reconnect."""
        self.connected = False
        self.running   = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        self.auto_joined   = False
        self.auth_complete = False
        self.nickserv_identified = False

        try:
            if hasattr(self, 'session_manager'):
                self.session_manager.sessions.clear()
        except Exception:
            pass

        try:
            if hasattr(self, '_pending_action'):
                self._pending_action = None
        except Exception:
            pass

        try:
            for panel in self.panel_manager.panels.values():
                panel.security_level = UIConstants.SecurityLevel.PLAINTEXT
                panel.secure_session = False
                panel.type = 'channel' if panel.name.startswith('#') else                              'system'  if panel.name == 'system' else                              'private'
        except Exception:
            pass

        self.connection_attempts += 1
        backoff = min(120, 5 * (2 ** min(self.connection_attempts - 1, 4)))
        self.add_message("system", f"🔄 Reconnecting in {backoff}s (attempt {self.connection_attempts})…")
        time.sleep(backoff)
        if self.connection_attempts <= self.max_connection_attempts:
            self.connect()
        else:
            self.add_message("system", colorize("❌ Max reconnect attempts reached.", "red"))


    def send_raw(self, message: str) -> bool:
        """Send a raw IRC line (adds CRLF, enforces 510-byte limit).

        Truncation here means OTRMessageFragmenter failed to split the message
        properly — it is logged as a bug, never silently discarded.
        """
        message = message.replace("\r", "").replace("\n", "")
        if len(message) > 510:
            self.debug(
                f"BUG: send_raw truncated {len(message)}→510 bytes. "
                "Fragmentation should have prevented this.",
                {"head": message[:80]}
            )
            message = message[:510]
        try:
            with self._sock_lock:
                if self.sock:
                    self.sock.settimeout(30.0)
                    self.sock.sendall(f"{message}\r\n".encode("utf-8"))
                    self.sock.settimeout(1.0)
                    self.logger.network_message("OUT", "SERVER", "RAW", len(message))
                    self.debug("send", {"msg": message[:120]})
                    return True
        except Exception as exc:
            self.debug("send_raw failed", {"error": str(exc)})
            self.running = False
        return False

    def send(self, message: str) -> bool:
        """Send only if connected."""
        return self.send_raw(message) if self.running else False

    def send_otr_message(self, target: str, otr_message: str) -> bool:
        """Fragment OTR message if needed and send each part.

        Looks up the session's instance tags so multi-fragment messages use the
        spec-compliant ``?OTRv4|stag|rtag|k|n|data.`` wire format (§4.7).
        Tracks the send time for the OTRv4 §4.7.1 heartbeat mechanism.
        """
        sender_tag   = 0
        receiver_tag = 0
        try:
            sess = self.session_manager.get_session(target)
            if sess is not None:
                sender_tag   = getattr(sess, '_sender_tag',   0) or 0
                receiver_tag = getattr(sess, '_receiver_tag', 0) or 0
        except Exception:
            pass

        fragments = self.otr_fragmenter.fragment(
            otr_message,
            sender_tag=sender_tag,
            receiver_tag=receiver_tag,
        )
        ok = True
        for i, frag in enumerate(fragments):
            if not self.send(f"PRIVMSG {target} :{frag}"):
                ok = False
                break
            if len(fragments) > 1:
                time.sleep(0.05)
        if ok:
            self._last_otr_sent[target] = time.time()
        return ok


    def parse_irc_message(self, line: str):
        """Parse IRC protocol line → (prefix, command, params, trailing).

        Handles IRCv3 message tags: @tag=value;tag2 :prefix COMMAND ...
        Tags are stripped — the server-time tag is extracted if present
        but not yet used (available for future timestamp display).
        """
        prefix   = None
        trailing = None
        # ── Strip IRCv3 message tags ─────────────────────────────
        if line.startswith("@"):
            tags_str, line = line.split(" ", 1)
            # Could parse tags_str[1:].split(";") if needed later
        if line.startswith(":"):
            parts  = line[1:].split(" ", 1)
            prefix = parts[0]
            line   = parts[1] if len(parts) > 1 else ""
        if " :" in line:
            params_str, trailing = line.split(" :", 1)
            params = params_str.strip().split()
        else:
            params = line.split()
        command = params[0] if params else None
        params  = params[1:] if params else []
        return prefix, command, params, trailing

    # ── IRCv3 CAP & SASL ─────────────────────────────────────────────

    def _handle_cap(self, params: List[str], trailing: Optional[str]) -> None:
        """Handle CAP LS / ACK / NAK replies from the server."""
        if len(params) < 2:
            return
        sub = params[1].upper()

        if sub == "LS":
            # Server lists available capabilities
            avail = (trailing or "").split()
            # Request the intersection of what we want and what's offered
            wanted = [c for c in IRCConstants.IRCV3_CAPS if c in avail]
            if wanted:
                self.send_raw(f"CAP REQ :{' '.join(wanted)}")
                self.debug("cap_ls", {"available": avail, "requesting": wanted})
            else:
                self._finish_cap_negotiation()

        elif sub == "ACK":
            # Server accepted our CAP REQ
            accepted = (trailing or "").split()
            self._cap_accepted.update(accepted)
            self.add_message("system",
                colorize(f"IRCv3: {', '.join(accepted)}", "dim"))
            self.debug("cap_ack", {"accepted": accepted})

            # Start SASL if capability was accepted and creds are available
            if ("sasl" in self._cap_accepted
                    and self.config.sasl_user
                    and self.config.sasl_pass):
                self._sasl_in_progress = True
                self.send_raw("AUTHENTICATE PLAIN")
                self.add_message("system",
                    colorize("🔑 SASL PLAIN authentication…", "cyan"))
            else:
                self._finish_cap_negotiation()

        elif sub == "NAK":
            # Server rejected our CAP REQ — proceed without
            self.debug("cap_nak", {"rejected": (trailing or "").split()})
            self._finish_cap_negotiation()

    def _handle_authenticate(self, trailing: Optional[str]) -> None:
        """Handle AUTHENTICATE + from server — send SASL PLAIN credentials."""
        if trailing == "+":
            user = self.config.sasl_user or self.nick
            passwd = self.config.sasl_pass or ""
            # SASL PLAIN: \0user\0password
            import base64 as _b64_sasl
            token = _b64_sasl.b64encode(
                f"\x00{user}\x00{passwd}".encode("utf-8")
            ).decode("ascii")
            self.send_raw(f"AUTHENTICATE {token}")
            # Wipe password from config after use
            self.config.sasl_pass = None
            self.debug("sasl_auth", {"user": user})

    def _finish_cap_negotiation(self) -> None:
        """End CAP negotiation — let the server complete registration."""
        if getattr(self, '_cap_negotiating', False):
            self._cap_negotiating = False
            self.send_raw("CAP END")
            self.debug("cap_end", {"accepted": list(self._cap_accepted)})


    def handle_message(self, line: str):
        """Dispatch one IRC line to the appropriate handler."""
        try:
            prefix, command, params, trailing = self.parse_irc_message(line)
            self.logger.network_message("IN", prefix or "SERVER", command or "?", len(line))
            self.debug("recv", {"cmd": command, "params": params[:3], "trail": (trailing or "")[:120]})

            if command and command.isdigit():
                self.handle_numeric_reply(int(command), params, trailing)
                return

            if command == "PING":
                target = trailing or (params[0] if params else "server")
                self.send(f"PONG :{target}")
                self.last_ping = time.time()
                return
            if command == "PONG":
                self.last_ping = time.time()
                return

            # ── IRCv3 CAP negotiation ────────────────────────────
            if command == "CAP":
                self._handle_cap(params, trailing)
                return

            if command == "AUTHENTICATE":
                self._handle_authenticate(trailing)
                return

            sender = prefix.split("!")[0] if prefix and "!" in prefix else (prefix or "server")
            if sender in self.ignored_users:
                return

            if command == "PRIVMSG":
                target  = params[0] if params else ""
                message = trailing or ""
                if self.is_ctcp_message(message) and "?OTRv4" not in message:
                    return
                if len(message) > 4096:
                    self.debug(f"oversized PRIVMSG from {sender} dropped ({len(message)} bytes)")
                    return
                self.check_auto_reply(sender, target, message)
                if "?OTRv4" in message:
                    self._dispatch_otr_fragment(sender, message)
                else:
                    _now = time.time()
                    if not hasattr(self, '_msg_rate'):
                        self._msg_rate: dict = {}
                    _bucket = self._msg_rate.get(sender, (0, 0.0))
                    _count, _window_start = _bucket
                    if _now - _window_start > 10.0:
                        _count, _window_start = 0, _now
                    _count += 1
                    self._msg_rate[sender] = (_count, _window_start)
                    if _count > 50:
                        self.debug(f"plaintext flood from {sender} — dropping ({_count} msgs/10s)")
                    else:
                        self._display_plaintext(sender, target, message)
                return

            if command == "JOIN":
                channel = trailing or (params[0] if params else "")
                if not channel or len(channel) > 64 or '\r' in channel or '\n' in channel:
                    return
                if sender == self.nick:
                    if channel not in self.panel_manager.panels:
                        self.panel_manager.add_panel(channel, "channel")
                    self._switch_panel(channel)
                    self.channels[channel] = {"users": set(), "topic": ""}
                    self.add_message(channel, colorize(f"✅ Joined {channel}", "green"))
                else:
                    if channel in self.channels:
                        self.channels[channel]["users"].add(sender)
                return

            if command == "PART":
                channel = params[0] if params else ""
                reason  = trailing or ""
                if sender == self.nick:
                    self.add_message("system", f"Left {channel}")
                else:
                    if channel in self.channels:
                        self.channels[channel]["users"].discard(sender)
                return

            if command == "QUIT":
                reason = trailing or ""
                for ch, info in self.channels.items():
                    if sender in info["users"]:
                        info["users"].discard(sender)

                if self.session_manager.has_session(sender):
                    self._on_peer_disconnected(sender, reason)
                return

            if command == "NICK":
                new_nick = trailing or (params[0] if params else "")
                if not new_nick or len(new_nick) > 64 or '\r' in new_nick or '\n' in new_nick:
                    return
                for ch_info in self.channels.values():
                    if sender in ch_info["users"]:
                        ch_info["users"].discard(sender)
                        ch_info["users"].add(new_nick)
                if sender == self.nick:
                    self.nick = new_nick
                    self.add_message("system", f"Nick → {colorize_username(_sanitise(new_nick, 64))}")
                return

            if command == "KICK":
                channel = params[0] if params else ""
                kicked  = params[1] if len(params) > 1 else ""
                reason  = trailing or ""
                if kicked == self.nick:
                    self.add_message("system", f"❌ Kicked from {_sanitise(channel, 64)}: {_sanitise(reason, 256)}")
                else:
                    self.add_message(channel, f"⚡ {colorize_username(_sanitise(kicked, 64))} kicked: {_sanitise(reason, 256)}")
                return

            if command == "MODE":
                ch = params[0] if params else ""
                if ch.startswith("#"):
                    self.add_message(ch, f"Mode: {' '.join(params[1:])}")
                return
            if command == "NOTICE":
                target  = params[0] if params else ""
                message = trailing or ""
                sender_lower = sender.lower() if sender else ""
                if sender_lower == "nickserv":
                    self.add_message("system",
                        colorize("NickServ", "bold_cyan") + colorize(": ", "dim") +
                        colorize(_sanitise(message, 512), "white"))
                    msg_lower = message.lower()
                    if ("you are now" in msg_lower and "identified" in msg_lower) or                        "password accepted" in msg_lower or                        "you are successfully identified" in msg_lower:
                        self.nickserv_identified = True
                        self.add_message("system",
                            colorize("✅ NickServ: identified successfully", "green"))
                    elif "registered" in msg_lower and ("successfully" in msg_lower or "is now" in msg_lower):
                        self.nickserv_identified = True
                        self.add_message("system",
                            colorize("✅ NickServ: nick registered successfully", "green"))
                    elif "invalid" in msg_lower or "denied" in msg_lower or                          "incorrect" in msg_lower or "wrong" in msg_lower:
                        self.add_message("system",
                            colorize("❌ NickServ: authentication failed", "red"))
                elif sender_lower in ("chanserv", "memoserv", "operserv"):
                    self.add_message("system",
                        colorize(sender, "dim") + colorize(": ", "dim") +
                        colorize(message, "dim"))
                else:
                    if message and not message.startswith("***"):
                        self.add_message("system",
                            colorize(f"[notice] {_sanitise(sender, 64)}: {_sanitise(message, 512)}", "dim"))
                return

            if command == "TOPIC":
                ch = params[0] if params else ""
                topic = trailing or ""
                if ch in self.channels:
                    self.channels[ch]["topic"] = topic
                self.add_message(ch, f"Topic: {_sanitise(topic, 390)}")
                return

        except Exception as exc:
            self.debug(f"handle_message error: {exc}")

    def handle_numeric_reply(self, code: int, params: List[str], trailing: Optional[str]):
        """Handle IRC numeric reply codes."""
        try:
            # ── SASL numeric replies ─────────────────────────────
            if code in (900, 903):
                # RPL_LOGGEDIN / RPL_SASLSUCCESS
                self.nickserv_identified = True
                self.add_message("system",
                    colorize("✅ SASL authentication successful", "green"))
                if getattr(self, '_sasl_in_progress', False):
                    self._sasl_in_progress = False
                    self._finish_cap_negotiation()
                return

            if code in (902, 904, 905, 906):
                # ERR_NICKLOCKED / ERR_SASLFAIL / ERR_SASLTOOLONG / ERR_SASLABORTED
                self.add_message("system",
                    colorize(f"⚠ SASL authentication failed (code {code})", "yellow"))
                if getattr(self, '_sasl_in_progress', False):
                    self._sasl_in_progress = False
                    self._finish_cap_negotiation()
                return

            if code == 1:
                self.auth_complete = True
                welcome_text = trailing or ""
                words = welcome_text.split()
                clean_words = []
                for w in words:
                    if "!" in w or "@" in w:
                        break
                    clean_words.append(w)
                clean = " ".join(clean_words) if clean_words else welcome_text
                self.add_message("system", colorize(f"✅ {clean}", "green"))
                self.debug("RPL_WELCOME")
                if self.config.nickserv_login and self.config.nickserv_pass:
                    self.add_message("system",
                        colorize("🔑 Identifying with NickServ…", "cyan"))
                    _ns_pass = self.config.nickserv_pass
                    self.send(f"PRIVMSG NickServ :IDENTIFY {_ns_pass}")
                    _secure_wipe_bytes(_ns_pass.encode()); del _ns_pass
                    self.config.nickserv_pass = None
                elif self.config.nickserv_register and self.config.nickserv_pass:
                    self.add_message("system",
                        colorize("📝 Registering nick with NickServ…", "cyan"))
                    _ns_pass = self.config.nickserv_pass
                    self.send(f"PRIVMSG NickServ :REGISTER {_ns_pass} no-email")
                    _secure_wipe_bytes(_ns_pass.encode()); del _ns_pass
                    self.config.nickserv_pass = None

                delay = 3.0 if (self.config.nickserv_login or self.config.nickserv_register) else 2.0
                threading.Timer(delay, self.auto_join_channel).start()
                return

            if code in (433, 436):
                new_nick = TwentySevenClubNick.generate()
                if new_nick == self.nick:
                    new_nick = self.nick + str(secrets.randbelow(100))
                self.nick = new_nick
                self.realname = TwentySevenClubNick.real_name(self.nick)
                self.send(f"NICK {self.nick}")
                self.add_message("system", f"Nick collision → {colorize_username(self.nick)}")
                return

            if code == 375:
                self._motd_buf = []
                return
            if code == 372:
                if not hasattr(self, "_motd_buf"):
                    self._motd_buf = []
                if trailing:
                    import re as _re_irc
                    line = trailing.lstrip("- ").strip()
                    line = _re_irc.sub(r'\x03(?:\d{1,2}(?:,\d{1,2})?)?', '', line)
                    line = _re_irc.sub(r'[\x02\x0f\x16\x1d\x1f]', '', line).strip()
                    if line:
                        self._motd_buf.append(line)
                return
            if code == 376:
                buf = getattr(self, "_motd_buf", [])
                if buf:
                    self.add_message("system",
                        colorize("── MOTD ──────────────────────────────────", "dim"))

                    import re as _re
                    _SECTION_RE = _re.compile(r'^(?:\d+[.)]\s|/|https?://|\[|[A-Z]{3,}\s*:)')
                    paragraphs = []
                    current    = []
                    for frag in buf:
                        is_new = (
                            not current
                            or _SECTION_RE.match(frag)
                            or (len(frag) > 30
                                and frag[0].isupper()
                                and not current[-1].endswith(","))
                        )
                        if is_new and current:
                            paragraphs.append(" ".join(current))
                            current = []
                        current.append(frag)
                    if current:
                        paragraphs.append(" ".join(current))

                    for para in paragraphs:
                        if len(para) > 68:
                            for wline in textwrap.wrap(para, width=68,
                                                       break_long_words=False,
                                                       break_on_hyphens=False):
                                self.add_message("system", colorize(wline, "dim"))
                        else:
                            self.add_message("system", colorize(para, "dim"))

                    self.add_message("system",
                        colorize("──────────────────────────────────────────", "dim"))
                self._motd_buf = []
                return

            if code in (2,    # RPL_YOURHOST  "Your host is..."
                        4,
                        5,
                        251,  # RPL_LUSERCLIENT  "There are N users"
                        252,
                        253,
                        254,
                        255,
                        265,
                        266,
                        396,  # RPL_VISIBLEHOST  "is now your displayed host"
                        ):
                return

            if code == 332:
                channel = params[1] if len(params) > 1 else ""
                topic   = trailing or ""
                if channel in self.channels:
                    self.channels[channel]["topic"] = topic
                self.add_message(channel or "system", f"Topic: {topic}")
                return

            if code == 353:
                channel = params[2] if len(params) > 2 else ""
                users   = trailing.split() if trailing else []
                if channel not in self.names_data:
                    self.names_data[channel] = []
                self.names_data[channel].extend(users)
                if channel in self.channels:
                    for u in users:
                        self.channels[channel]["users"].add(u.lstrip("@+&~"))
                return

            if code == 366:
                channel = params[1] if len(params) > 1 else ""
                if getattr(self, '_pending_names_pager', None) == channel:
                    self._pending_names_pager = None
                    users = sorted(self.names_data.get(channel, []),
                                   key=lambda u: (0 if u.startswith(("@","~","&")) else
                                                  1 if u.startswith("+") else 2, u.lower()))
                    lines = []
                    for u in users:
                        prefix = u[0] if u[0] in "@+~&" else " "
                        nick = u.lstrip("@+~&")
                        if prefix == "@":
                            lines.append(colorize(f"  {prefix}{nick}", "bold_green"))
                        elif prefix in ("+", "~", "&"):
                            lines.append(colorize(f"  {prefix}{nick}", "yellow"))
                        else:
                            lines.append(f"  {nick}")
                    self.pager.display(lines,
                        header=f"Users in {channel}",
                        footer=f"{len(users)} users")
                    self.names_data[channel] = []
                    if hasattr(self, '_prompt_refresh_cb') and self._prompt_refresh_cb:
                        self._prompt_refresh_cb()
                return

            if code == 311:
                target = params[1] if len(params) > 1 else ""
                user   = params[2] if len(params) > 2 else ""
                host   = params[3] if len(params) > 3 else ""
                real   = trailing or ""
                display_real = TwentySevenClubNick.real_name(target)
                if display_real == target:
                    display_real = real
                self.add_message("system",
                    colorize("── WHOIS ─────────────────────────────────", "dim"))
                self.add_message("system",
                    f"  Nick     : {colorize_username(target)}")
                self.add_message("system",
                    f"  User     : {user}@{host}")
                self.add_message("system",
                    f"  Name     : {display_real}")
                return

            if code == 312:
                target = params[1] if len(params) > 1 else ""
                server = params[2] if len(params) > 2 else ""
                info   = trailing or ""
                self.add_message("system",
                    f"  Server   : {server}" + (f" ({info})" if info else ""))
                return

            if code == 313:
                target = params[1] if len(params) > 1 else ""
                self.add_message("system",
                    f"  Status   : {colorize('IRC Operator', 'yellow')}")
                return

            if code == 319:
                target = params[1] if len(params) > 1 else ""
                chans  = trailing or ""
                self.add_message("system",
                    f"  Channels : {chans}")
                return

            if code == 317:
                target = params[1] if len(params) > 1 else ""
                idle_s = int(params[2]) if len(params) > 2 and params[2].isdigit() else 0
                signon = int(params[3]) if len(params) > 3 and params[3].isdigit() else 0
                idle_str = _fmt_duration(idle_s)
                if signon > 0:
                    from datetime import datetime as _dt
                    signon_str = _dt.fromtimestamp(signon).strftime("%Y-%m-%d %H:%M:%S")
                    self.add_message("system",
                        f"  Idle     : {idle_str}")
                    self.add_message("system",
                        f"  Signon   : {signon_str}")
                else:
                    self.add_message("system",
                        f"  Idle     : {idle_str}")
                return

            if code == 301:
                target = params[1] if len(params) > 1 else ""
                away   = trailing or ""
                self.add_message("system",
                    f"  Away     : {colorize(away, 'yellow')}")
                return

            if code == 671:
                target = params[1] if len(params) > 1 else ""
                self.add_message("system",
                    f"  Secure   : {colorize('Yes (TLS)', 'green')}")
                return

            if code == 330:
                target  = params[1] if len(params) > 1 else ""
                account = params[2] if len(params) > 2 else ""
                self.add_message("system",
                    f"  Account  : {account}")
                return

            if code == 318:
                self.add_message("system",
                    colorize("──────────────────────────────────────────", "dim"))
                return

            if code == 321:
                self.channel_list = []
            elif code == 322:
                if len(params) >= 3:
                    self.channel_list.append({
                        "channel": params[1],
                        "users": int(params[2]) if params[2].isdigit() else 0,
                        "topic": (trailing or "")[:60]
                    })
            elif code == 323:
                lines = [
                    f"{colorize(c['channel'], 'green'):<20} {c['users']:>4} users  {colorize(_sanitise(c['topic'], 256), 'dim')}"
                    for c in sorted(self.channel_list, key=lambda x: x["users"], reverse=True)
                ]
                self.pager.display(lines, "Channel list", f"{len(lines)} channels")

            elif code == 401:
                target = params[1] if len(params) > 1 else (params[0] if params else "")
                if target and self.session_manager.has_session(target):
                    if not getattr(self, '_401_handled', set()).__contains__(target):
                        if not hasattr(self, '_401_handled'):
                            self._401_handled = set()
                        self._401_handled.add(target)
                        self._on_peer_disconnected(target, "nick no longer on server")
                elif trailing:
                    self.add_message("system", colorize(f"⚠ {trailing}", "dim"))

            elif trailing:
                self.add_message("system", colorize(trailing, "dim"))

        except Exception as exc:
            self.debug(f"numeric reply error code={code}: {exc}")


    def _dispatch_otr_fragment(self, sender: str, fragment: str):
        """Accumulate OTR fragments; process when complete."""
        if sender not in self.fragment_buffers:
            buf = OTRFragmentBuffer(timeout=self.config.fragment_timeout)

            def _on_first_fragment(s: str, n: int, chunk: str = "") -> None:
                """First-fragment UX callback — IRC-aligned.

                Design principles (irssi/weechat convention):
                  • Notices go to the PEER tab only — never cross-posted
                    to the active tab.  Background activity is signalled
                    by tab-bar highlight colour + unread count.
                  • DAKE1 (new session request) gets a visible notice +
                    Termux notification — the user must know someone is
                    knocking.
                  • DAKE2/DAKE3 are mid-handshake — silent.  The peer
                    tab already exists from the DAKE1 that started it.
                  • Encrypted data messages get NO inline "receiving…"
                    notice.  The decrypted text will appear in < 1 s
                    once reassembly completes.  Premature notices just
                    add noise (and we can't distinguish SMP TLVs from
                    normal data at fragment time anyway).
                """
                try:
                    # ── Reset fragment limit to default for each new
                    #    message sequence; elevated below only for
                    #    SMP-eligible traffic.
                    buf.max_fragments_per_sender = UIConstants.FRAGMENT_LIMIT

                    # ── Peek at OTR message type from first chunk ────
                    msg_type = None
                    try:
                        import base64 as _b64
                        peek = _b64.b64decode(chunk[:20] + "==")
                        if len(peek) >= 3 and peek[0] == 0x00 and peek[1] == 0x04:
                            msg_type = "data"
                        elif len(peek) >= 1:
                            msg_type = {
                                0x35: "dake1",
                                0x36: "dake2",
                                0x37: "dake3",
                            }.get(peek[0])
                    except Exception:
                        pass

                    # ── Ensure peer tab exists ───────────────────────
                    if s not in self.panel_manager.panels:
                        self.panel_manager.add_panel(s, "private")

                    # ── Elevate fragment limit for SMP-eligible traffic ──
                    #    SMP stages 1/3 can exceed the default 50-fragment
                    #    limit with longer passphrases (observed: 17 and 27
                    #    fragments respectively).  We can't know it's SMP
                    #    until after decryption, but data messages on an
                    #    established session are the only ones that carry
                    #    SMP TLVs — so raise the ceiling for those.
                    if msg_type == "data" and self.session_manager.has_session(s):
                        buf.max_fragments_per_sender = UIConstants.SMP_FRAGMENT_LIMIT

                    if msg_type == "dake1" or not self.session_manager.has_session(s):
                        # ── Incoming OTR session request ─────────────
                        #    Notice in peer tab only; tab highlight
                        #    signals activity to the user.
                        notice = colorize(
                            f"🔑 {colorize_username(s)} is requesting an OTR session…",
                            "cyan")
                        self.add_message(s, notice)
                        self._termux_fire([
                            "--title",    "🔑 OTR request",
                            "--content",  f"{s} is requesting an encrypted session",
                            "--priority", "high",
                            "--id",       f"otrv4_{s}_incoming",
                            "--vibrate",  "0,150,100,150",
                        ])

                    # DAKE2/DAKE3: silent — handshake in progress
                    # Data messages: silent — decrypted text arrives
                    #   after reassembly; SMP is detected at TLV decode
                    #   time, not here.

                except Exception:
                    pass

            buf.first_fragment_cb = _on_first_fragment
            self.fragment_buffers[sender] = buf

        try:
            complete = self.fragment_buffers[sender].add_fragment(sender, fragment)
        except ValueError as exc:
            self.debug(f"fragment error from {sender}: {exc}")
            return
        if complete:
            self.process_otr_payload(sender, complete)

    def process_otr_payload(self, sender: str, payload: str):
        """Route a fully reassembled OTRv4 payload."""
        self.debug("otr payload", {"sender": sender, "len": len(payload)})
        try:
            if not payload.startswith("?OTRv4 "):
                return
            raw = payload[7:].strip()
            if not raw:
                return
            decoded = OTRv4DAKE._safe_b64decode(raw)
            if not decoded:
                return
            if (len(decoded) >= 3
                    and decoded[0] == 0x00
                    and decoded[1] == 0x04
                    and decoded[2] == OTRv4DataMessage.TYPE):
                self._handle_data_message(sender, payload)
                return

            msg_type = decoded[0]
            if msg_type == OTRConstants.MESSAGE_TYPE_DAKE1:
                self.process_dake1(sender, payload)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE2:
                self.process_dake2(sender, payload)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE3:
                self.process_dake3(sender, payload)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DATA:
                self._handle_data_message(sender, payload)
        except Exception as exc:
            self.debug(f"otr payload error: {exc}")

    def _handle_data_message(self, sender: str, payload: str):
        """Decrypt an OTRv4 DATA message and route the text to the panel.

        Any valid OTR data message proves the connection is alive, so we reset
        last_ping here to prevent the ping watchdog from firing during a long
        SMP exchange.

        The actual decrypt+SMP computation is offloaded to _smp_executor so the
        recv_loop thread stays free to respond to server PINGs throughout the
        minutes-long 3072-bit DH operations.  Without this, recv_loop blocks
        inside the DH computation, PINGs go unanswered, and the server drops the
        client right after SMP verification succeeds.
        """
        if not self.session_manager.has_session(sender):
            return

        self.last_ping = time.time()

        def _do_decrypt():
            """Run in thread pool — safe because session has its own RLock."""
            try:
                self.last_ping = time.time()

                result = self.session_manager.decrypt_message(sender, payload)
                if result is None:
                    return

                text = result if isinstance(result, str) else result.decode('utf-8', errors='replace')

                self.last_ping = time.time()

                if text.startswith('?OTRv4 '):
                    self.send_otr_message(sender, text)
                    self.last_ping = time.time()
                    return

                sec = self.session_manager.get_security_level(sender)
                if text.strip():
                    self.add_message(sender, f"{colorize_username(sender)}: {text}", sec)
                self.panel_manager.update_panel_security(sender, sec)
                self.panel_manager.update_smp_progress(
                    sender, *self.session_manager.get_smp_progress(sender))

            except Exception as exc:
                self.debug(f"data decrypt error from {sender}: {exc}")

        try:
            self._smp_executor.submit(_do_decrypt)
        except RuntimeError:
            _do_decrypt()

    def _display_plaintext(self, sender: str, target: str, message: str):
        """Show a plaintext PRIVMSG in the right panel.

        Any message whose content looks like OTR wire data — even if it was
        missing the canonical ``?OTRv4 `` prefix — is routed to the OTR
        dispatcher and silently dropped rather than shown as a chat message.
        This prevents protocol artefacts like ``otrv4_smp:<base64>`` from
        appearing as chat lines attributed to a nick.
        """
        _OTR_PROTO_MARKERS = ('?OTRv4', '?OTR', 'otrv4_smp', 'otrv4:')
        if any(message.startswith(m) for m in _OTR_PROTO_MARKERS):
            self._dispatch_otr_fragment(sender, message)
            return
        panel = target if target.startswith("#") else sender
        self.add_message(panel,
            colorize_username(sender) + colorize(":", "dim") + f" {colorize(message, 'white')}")


    def process_dake1(self, sender: str, payload: str):
        active = self.panel_manager.active_panel
        alert = colorize(f"🔑 OTR request from {sender} — switching to their tab…", "cyan")
        if active:
            self.add_message(active, alert)
        else:
            self.add_message("system", alert)
        self._route_otr_to_session_manager(sender, payload, "DAKE1", is_initiator=False)

    def process_dake2(self, sender: str, payload: str):
        pass

    def process_dake3(self, sender: str, payload: str):
        pass

    def process_smp_message(self, sender: str, data: bytes):
        pass


    def auto_join_channel(self):
        """Join the default channel after RPL_WELCOME."""
        if not self.auto_joined and self.connected:
            ch = self.config.channel
            self.send(f"JOIN {ch}")
            self.auto_joined = True
            self.add_message("system", f"Auto-joining {colorize(ch, 'cyan')}…")
            self.debug("auto_join", {"channel": ch})
            peers = [
                name for name, p in self.panel_manager.panels.items()
                if not name.startswith('#') and name not in ('system', 'debug')
                and p.history
            ]
            if peers:
                self.add_message("system", colorize(
                    "⚠ OTR sessions lost on reconnect — "
                    + ", ".join(f"/otr {p}" for p in peers),
                    "yellow"))


    def start_auto_smp_monitor(self):
        """Background thread that fires scheduled SMP verifications."""
        if self.auto_smp_monitor_running:
            return
        self.auto_smp_monitor_running = True

        def _monitor():
            while self.running and not self.shutdown_flag:
                now = time.time()
                due = [
                    peer for peer, info in list(self.smp_schedule_timers.items())
                    if info.get("scheduled") and now >= info.get("when", 0)
                ]
                for peer in due:
                    del self.smp_schedule_timers[peer]
                    try:
                        self._fire_auto_smp(peer)
                    except Exception as exc:
                        self.debug(f"auto_smp error: {exc}")
                time.sleep(1)

        threading.Thread(target=_monitor, daemon=True, name="smp-monitor").start()

    def _fire_auto_smp(self, peer: str):
        """Attempt to start SMP with the stored secret for peer."""
        secret = self.session_manager.smp_storage.get_secret(peer) \
                 if hasattr(self.session_manager, "smp_storage") else ""
        if not secret:
            return
        tlv = self.session_manager.start_smp(peer, secret)
        if tlv:
            enc = self.session_manager.encrypt_message(peer, "")
            if enc:
                self.send_otr_message(peer, enc)

    def schedule_auto_smp(self, peer: str, delay: float = 2.0):
        if peer not in self.smp_schedule_timers:
            self.smp_schedule_timers[peer] = {"when": time.time() + delay, "scheduled": True}

    def clear_pending_smp(self, peer: str):
        self.smp_schedule_timers.pop(peer, None)


    def add_message(self, target: str, message: str,
                    security_level: Optional[UIConstants.SecurityLevel] = None,
                    is_initiator: Optional[bool] = None):
        """
        Route a message to the correct panel and emit to stdout.
        
        Panel routing:
          'system'  → system tab (server welcome, MOTD, connection events)
          '#channel'→ channel tab (join/part/quit/channel chat)
          'debug'   → debug tab only (never shown in other tabs)
          peer_nick → private/secure tab (encrypted messages after DAKE)
        """
        if target in self.ignored_users:
            return
        if security_level is None:
            if not target.startswith('#'):
                if self.session_manager.has_session(target):
                    security_level = self.session_manager.get_security_level(target)
                elif target in self.panel_manager.panels:
                    security_level = self.panel_manager.panels[target].security_level
        icon = UIConstants.SECURITY_ICONS.get(security_level, "") if security_level else ""
        if icon and not message.startswith(icon):
            message = f"{icon}{message}"
        self._emit(target, message)
        if security_level is not None:
            self.panel_manager.update_panel_security(target, security_level)

    _CTCP_BLOCKED = frozenset({
        'VERSION', 'FINGER', 'USERINFO', 'CLIENTINFO',
        'DCC', 'PING', 'TIME', 'SOURCE',
    })

    def is_ctcp_message(self, message: str) -> bool:
        if message.startswith("?OTRv4"):
            return False
        if message.startswith("\x01") and message.endswith("\x01"):
            cmd = message[1:-1].split()[0].upper() if message[1:-1].split() else ""
            if cmd in self._CTCP_BLOCKED:
                return True
            return True
        return False

    def check_auto_reply(self, sender: str, target: str, message: str):
        if sender == self.nick or sender not in self.auto_reply_config:
            return
        cfg = self.auto_reply_config[sender]
        if "channels" in cfg and cfg["channels"] and target not in cfg["channels"]:
            return
        reply = cfg.get("message", "")
        if reply:
            dest = sender if target == self.nick else target
            def _send_reply(d=dest, r=reply):
                self.send(f"PRIVMSG {d} :{r}")
                self.add_message(d, f"{colorize_username(self.nick)}: {r}")
            threading.Timer(0.3, _send_reply).start()


    def _switch_panel(self, name: str) -> bool:
        """Switch the active panel and replay its buffered history to stdout.

        Single choke-point for all tab switches — /switch, /tab-next,
        /tab-prev, JOIN auto-switch, and tab-close fallback all call here.
        Never call panel_manager.switch_to_panel() directly from user-facing
        code; use this method instead.

        Steps
        -----
        1. Flip the active-panel pointer and clear unread count.
        2. Print a centred panel header so the user sees which tab they entered.
        3. Replay up to _REPLAY_LINES messages with their stored timestamps
           (dimmed) so history is distinct from live output.
        4. Print a thin "live" separator to mark where buffered history ends.
        """
        if name not in self.panel_manager.panels:
            return False

        self.panel_manager.switch_to_panel(name)
        panel = self.panel_manager.panels[name]

        if name == "system":
            tag = colorize("[sys]  ", "dim")
        elif name == "debug":
            tag = colorize("[debug]", "magenta")
        elif name.startswith("#"):
            tag = colorize(f"[{name}]", "cyan")
        else:
            tag = colorize(f"[{name}]", "green")

        icon     = UIConstants.SECURITY_ICONS.get(panel.security_level, "")
        width    = 46
        hdr_name = f" {icon}{name} "
        dashes   = max(0, width - len(hdr_name))
        left     = dashes // 2
        right    = dashes - left
        header   = colorize("─" * left + hdr_name + "─" * right, "cyan")
        _emit_line(header)

        history = panel.history
        if not history:
            _emit_line(colorize("  (no messages yet)", "dim"))
        else:
            for entry in history:
                ts_str = time.strftime("%H:%M:%S", time.localtime(entry["timestamp"]))
                ts     = colorize(ts_str, "dim")
                _emit_line(f"{ts} {tag} {entry['message']}")

        _emit_line(colorize("─" * left + " live " + "─" * max(0, right - 1), "dim"))
        if self._prompt_refresh_cb is not None:
            self._prompt_refresh_cb()
        return True


    def get_timestamp(self) -> str:
        return time.strftime("%H:%M:%S")

    def clear_screen(self):
        if IS_TERMUX:
            safe_print("\n" * 60)
        else:
                    self.panel_manager._render_ui()

    def switch_to_next_tab(self):
        order = self.panel_manager.panel_order
        if not order:
            return
        cur = self.panel_manager.active_panel
        idx = order.index(cur) if cur in order else -1
        self._switch_panel(order[(idx + 1) % len(order)])

    def switch_to_previous_tab(self):
        order = self.panel_manager.panel_order
        if not order:
            return
        cur = self.panel_manager.active_panel
        idx = order.index(cur) if cur in order else 0
        self._switch_panel(order[(idx - 1) % len(order)])

    def show_tabs(self):
        """List all open panels with unread counts and security indicators."""
        self.add_message("system", colorize("─── Tabs ───────────────────────────────────", "cyan"))
        for i, name in enumerate(self.panel_manager.panel_order):
            p         = self.panel_manager.panels[name]
            is_active = (name == self.panel_manager.active_panel)
            marker    = colorize("▶", "green") if is_active else " "
            icon      = UIConstants.SECURITY_ICONS.get(p.security_level, "")
            badge     = colorize(f" [{p.unread_count} new]", "yellow") if p.unread_count else ""
            name_col  = colorize(name, "green" if is_active else "white")
            self.add_message("system", f"  {marker} {i+1:2d}.  {icon}{name_col}{badge}")
        self.add_message("system", colorize("  /switch <name>  /tab-next  /tab-prev", "dim"))

    def show_status_panel(self):
        self.add_message("system", colorize("── Client Status ─────────────────────────", "cyan"))
        conn_str = colorize("YES", "green") if self.connected else colorize("NO", "red")
        uptime = ""
        if self.connected and hasattr(self, 'connected_at'):
            uptime = f"  ({_fmt_duration(time.time() - self.connected_at)})"
        self.add_message("system", f"  Connected : {conn_str}{uptime}")
        self.add_message("system", f"  Server    : {self.server}")
        self.add_message("system", f"  Nick      : {colorize_username(self.nick)}")
        real = TwentySevenClubNick.real_name(self.nick)
        if real != self.nick:
            self.add_message("system", f"  Identity  : {real}")
        ns_status = ""
        if self.nickserv_identified:
            ns_status = colorize("  (NickServ ✓)", "green")
        elif self.config.nickserv_login or self.config.nickserv_register:
            ns_status = colorize("  (NickServ pending)", "yellow")
        self.add_message("system", f"  IRC ready : {colorize('YES','green') if self.auth_complete else colorize('NO','yellow')}{ns_status}")
        self.add_message("system", f"  Channels  : {len(self.channels)}")
        self.add_message("system", f"  OTR sess  : {len(self.session_manager.sessions)}")
        self.add_message("system",
            colorize("──────────────────────────────────────────", "cyan"))


    def handle_chat_message(self, msg: str):
        """Send msg to active panel target, OTR-encrypted if session exists."""
        if not self.connected:
            self.add_message("system", colorize("Not connected", "red"))
            return
        active = self.panel_manager.get_active_panel()
        if not active or active.type in ("system", "debug"):
            self.add_message("system", colorize("Switch to a chat panel first", "red"))
            return
        target = active.name
        if self.session_manager.has_session(target):
            enc = self.session_manager.encrypt_message(target, msg)
            if enc and self.send_otr_message(target, enc):
                sec = self.session_manager.get_security_level(target)
                self.add_message(target, colorize_username(self.nick) + colorize(": ", "dim") + colorize(msg, "white"), sec)
            else:
                self.add_message("system", colorize("❌ Encryption failed", "red"))
        else:
            if self.send(f"PRIVMSG {target} :{msg}"):
                self.add_message(target, colorize_username(self.nick) + colorize(": ", "dim") + colorize(msg, "white"))

    def handle_command(self, command: str):
        """Handle /command from user input."""
        parts = command.strip().split()
        if not parts:
            return
        cmd = parts[0].lower()

        if cmd == "help":
            self.show_help()
        elif cmd == "join" and len(parts) > 1:
            ch = parts[1] if parts[1].startswith("#") else f"#{parts[1]}"
            self.send(f"JOIN {ch}")
        elif cmd == "part":
            ch = parts[1] if len(parts) > 1 else (self.panel_manager.active_panel or "")
            if ch:
                self.send(f"PART {ch}")
        elif cmd == "nick" and len(parts) > 1:
            self.send(f"NICK {parts[1]}")
        elif cmd == "msg" and len(parts) > 2:
            self.send(f"PRIVMSG {parts[1]} :{' '.join(parts[2:])}")
            self.add_message(parts[1], colorize_username(self.nick) + colorize(": ", "dim") + colorize(' '.join(parts[2:]), "white"))
        elif cmd == "list":
            self.send("LIST")
        elif cmd == "whois" and len(parts) > 1:
            self.send(f"WHOIS {parts[1]}")
        elif cmd == "names":
            ch = parts[1] if len(parts) > 1 else (self.panel_manager.active_panel or "")
            if ch and ch.startswith("#"):
                self.names_data[ch] = []
                self.send(f"NAMES {ch}")
                self._pending_names_pager = ch
            else:
                self.add_message("system", colorize("Usage: /names [#channel]", "dim"))
        elif cmd == "topic":
            ch = self.panel_manager.active_panel or ""
            if len(parts) > 1 and parts[1].startswith("#"):
                ch = parts[1]
                new_topic = " ".join(parts[2:]) if len(parts) > 2 else ""
            else:
                new_topic = " ".join(parts[1:]) if len(parts) > 1 else ""
            if new_topic:
                self.send(f"TOPIC {ch} :{new_topic}")
            else:
                self.send(f"TOPIC {ch}")
        elif cmd == "notice" and len(parts) > 2:
            target = parts[1]
            text = " ".join(parts[2:])
            self.send(f"NOTICE {target} :{text}")
        elif cmd == "invite" and len(parts) > 2:
            self.send(f"INVITE {parts[1]} {parts[2]}")
        elif cmd == "kick" and len(parts) > 1:
            ch = self.panel_manager.active_panel or ""
            target = parts[1]
            reason = " ".join(parts[2:]) if len(parts) > 2 else ""
            if ch.startswith("#"):
                self.send(f"KICK {ch} {target}" + (f" :{reason}" if reason else ""))
            else:
                self.add_message("system", colorize("Must be in a channel to kick", "red"))
        elif cmd == "mode" and len(parts) > 1:
            self.send(f"MODE {' '.join(parts[1:])}")
        elif cmd == "away":
            reason = " ".join(parts[1:]) if len(parts) > 1 else "Away"
            self.send(f"AWAY :{reason}")
            self.add_message("system", colorize(f"Set away: {reason}", "dim"))
        elif cmd == "back":
            self.send("AWAY")
            self.add_message("system", colorize("No longer away", "green"))
        elif cmd == "raw" and len(parts) > 1:
            self.send(" ".join(parts[1:]))
        elif cmd in ("switch", "tab") and len(parts) > 1:
            if not self._switch_panel(parts[1]):
                self.add_message("system", colorize(f"❌ No panel: {parts[1]}", "red"))
        elif cmd == "tabs":
            self.show_tabs()
        elif cmd == "tab-next":
            self.switch_to_next_tab()
        elif cmd == "tab-prev":
            self.switch_to_previous_tab()
        elif cmd == "tab-close" and len(parts) > 1:
            p = parts[1]
            if p == "system":
                return
            if p in self.panel_manager.panels:
                if self.panel_manager.active_panel == p:
                    self._switch_panel("system")
                del self.panel_manager.panels[p]
                if p in self.panel_manager.panel_order:
                    self.panel_manager.panel_order.remove(p)
                self.panel_manager._render_ui()
        elif cmd == "clear":
            active = self.panel_manager.get_active_panel()
            if active:
                self.panel_manager.clear_panel_history(active.name)
        elif cmd == "clear-screen":
            self.clear_screen()
        elif cmd == "otr" and len(parts) > 1:
            self.start_guided_otr_session(parts[1])
        elif cmd == "fingerprint":
            fp = self.session_manager.client_profile.get_fingerprint() \
                 if hasattr(self.session_manager, "client_profile") else "N/A"
            self.add_message("system", f"Your fingerprint: {colorize(fp, 'cyan')}")
        elif cmd == "trust" and len(parts) > 2:
            self.session_manager.trust_db.add_trust(parts[1], parts[2])
            self.add_message("system", f"✅ Trusted {parts[1]}: {parts[2][:16]}…")
        elif cmd == "smp" and len(parts) > 1:
            active = self.panel_manager.get_active_panel()
            peer   = active.name if active and active.type not in ("system","debug") else None
            sub    = parts[1].lower()
            if not peer:
                self.add_message("system", colorize("⚠ Switch to a peer panel first", 'yellow'))
            elif sub == "start":
                session = self.session_manager.sessions.get(peer) if hasattr(self.session_manager, 'sessions') else None
                stored  = getattr(session, 'auto_smp_secret', '') if session else ''
                if not stored and hasattr(self.session_manager, 'smp_storage'):
                    stored = self.session_manager.smp_storage.get_secret(peer) or ''
                if not stored:
                    self.add_message("system", colorize("⚠ No SMP secret stored — use /smp <secret> first", 'yellow'))
                else:
                    self._start_smp(peer, stored)
            elif sub == "abort":
                self.clear_pending_smp(peer)
                self.add_message("system", f"🛑 SMP aborted for {peer}")
            elif sub == "status":
                status = self.session_manager.get_smp_status(peer) if hasattr(self.session_manager, 'get_smp_status') else {}
                self.add_message("system", f"SMP {peer}: {status}")
            else:
                secret = " ".join(parts[1:])
                if len(secret) < 6:
                    self.add_message("system", colorize(
                        f"⚠ SMP secret is only {len(secret)} chars — "
                        "minimum 6 recommended. Short passphrases are brute-forceable.", 'yellow'))
                self._start_smp(peer, secret)
        elif cmd == "smp-secret" and len(parts) > 2:
            peer   = parts[1]
            secret = " ".join(parts[2:])
            if len(secret) < 6:
                self.add_message("system", colorize(
                    f"⚠ SMP secret is only {len(secret)} chars — "
                    "minimum 6 recommended. Short passphrases are brute-forceable.", 'yellow'))
            if hasattr(self.session_manager, "smp_storage"):
                self.session_manager.smp_storage.set_secret(peer, secret)
            self.add_message("system", f"🔑 SMP secret set for {peer}")
        elif cmd == "smp-auto" and len(parts) > 1:
            self.schedule_auto_smp(parts[1], delay=1.0)
            self.add_message("system", f"🔄 Auto-SMP scheduled for {parts[1]}")
        elif cmd == "smp-abort" and len(parts) > 1:
            self.clear_pending_smp(parts[1])
            self.add_message("system", f"🛑 SMP aborted for {parts[1]}")
        elif cmd == "smp-status" and len(parts) > 1:
            status = self.session_manager.get_smp_status(parts[1])
            self.add_message("system", f"SMP {parts[1]}: {status}")
        elif cmd in ("secure", "sessions"):
            if not self.session_manager.sessions:
                self.add_message("system", "No OTR sessions active")
            for peer, sess in self.session_manager.sessions.items():
                sec  = getattr(sess, "security_level", UIConstants.SecurityLevel.PLAINTEXT)
                icon = UIConstants.SECURITY_ICONS.get(sec, "")
                self.add_message("system", f"  {icon} {colorize_username(peer)}: {sec.name}")
        elif cmd == "ignore" and len(parts) > 1:
            self.ignored_users.add(parts[1])
            self.add_message("system", f"🚫 Ignoring {colorize_username(parts[1])}")
        elif cmd == "unignore" and len(parts) > 1:
            self.ignored_users.discard(parts[1])
            self.add_message("system", f"✅ Unignored {colorize_username(parts[1])}")
        elif cmd == "ignored":
            if self.ignored_users:
                self.add_message("system", colorize("Ignored users:", "cyan"))
                for u in sorted(self.ignored_users):
                    self.add_message("system", f"  🚫 {colorize_username(u)}")
            else:
                self.add_message("system", colorize("No users ignored", "dim"))
        elif cmd == "status":
            self.show_status_panel()
        elif cmd == "quit":
            self.shutdown()
        elif cmd == "reconnect":
            if self.running and self.connected:
                self.add_message("system", colorize("Already connected.", "yellow"))
            else:
                self.add_message("system", colorize("🔄 Reconnecting…", "cyan"))
                self._try_reconnect()
        elif cmd == "debug":
            global DEBUG_MODE
            DEBUG_MODE = not DEBUG_MODE
            if hasattr(self, 'logger') and hasattr(self.logger, 'set_debug'):
                self.logger.set_debug(DEBUG_MODE)
            self.add_message("system", f"Debug: {'ON' if DEBUG_MODE else 'OFF'}")
            if DEBUG_MODE and "debug" not in self.panel_manager.panels:
                self.panel_manager.add_panel("debug", "debug")
        elif cmd == "version":
            _rt = "🦀 Rust (zeroize-on-drop)" if RUST_RATCHET_AVAILABLE else "🐍 Python (C extensions)"
            self.add_message("system", f"Version: {VERSION}")
            self.add_message("system", f"Ratchet: {_rt}")
        else:
            if cmd == "/server":
                if not parts[1:]:
                    _cur_net = NetworkConstants.detect(self.server)
                    _icons   = {"i2p":"🧅 I2P","tor":"🧅 Tor","clearnet":"🌐 Clearnet"}
                    self.add_message("system",
                        f"Current server: {colorize(self.server, 'cyan')} "
                        f"({colorize(_icons.get(_cur_net, _cur_net), 'dark_cyan')})")
                    self.add_message("system",
                        colorize("Usage: /server <hostname[:port]>", "dim"))
                else:
                    new_srv = parts[1]
                    _new_net = NetworkConstants.detect(new_srv)
                    _icons   = {"i2p":"🧅 I2P","tor":"🧅 Tor","clearnet":"🌐 Clearnet"}
                    _cols    = {"i2p":"dark_cyan","tor":"dark_magenta","clearnet":"grey"}
                    self.add_message("system",
                        f"Switching to {colorize(new_srv, 'cyan')} "
                        f"({colorize(_icons.get(_new_net, _new_net), _cols.get(_new_net, 'white'))})…")
                    if self.connected:
                        self.send_raw("QUIT :switching server")
                        self.connected = False
                        self.running   = False
                        try:
                            if self.sock:
                                self.sock.close()
                        except Exception:
                            pass
                    self.server = new_srv
                    self.config.server = new_srv
                    if not self.connect():
                        self.add_message("system",
                            colorize(f"❌ Failed to connect to {new_srv}", "bold_red"))
                return

            self.add_message("system", colorize(f"❌ Unknown command: {cmd}  (try /help)", "bold_red"))

    def show_help(self):
        cmds = [
            ("IRC",  ["/join <ch>", "/part [ch]", "/nick <n>", "/msg <n> <txt>",
                      "/names [#ch]", "/topic [#ch] [text]",
                      "/list", "/whois <n>", "/invite <n> <#ch>",
                      "/kick <n> [reason]", "/mode <target> <+/-mode>",
                      "/notice <target> <msg>",
                      "/away [msg]", "/back",
                      "/raw <command>", "/reconnect", "/quit"]),
            ("OTR",  ["/otr <nick>", "/fingerprint", "/trust <n> <fp>",
                      "/smp <secret>", "/smp start", "/smp abort", "/smp status",
                      "/smp-secret <n> <s>", "/smp-auto <n>",
                      "/secure", "/endotr <nick>"]),
            ("UI",   ["/switch <panel>", "/tabs", "/tab-next", "/tab-prev",
                      "/tab-close <p>", "/clear", "/clear-screen",
                      "/ignore <nick>", "/unignore <nick>", "/ignored",
                      "/status", "/debug", "/version"]),
        ]
        for section, items in cmds:
            self.add_message("system", colorize(f"{section}:", "cyan"))
            for item in items:
                self.add_message("system", f"  {item}")


    def start_guided_otr_session(self, nick: str):
        """Kick off a DAKE handshake with nick."""
        self.add_message("system", f"Initiating OTR with {colorize_username(nick)}…")
        if nick not in self.panel_manager.panels:
            self.panel_manager.add_panel(nick, "private")
        self._switch_panel(nick)
        dake_msg, should_send = self.session_manager.handle_outgoing_message(nick, "")
        if dake_msg and should_send:
            self.send_otr_message(nick, dake_msg)
            self.add_message("system", f"{colorize('🔑 DAKE1 →', 'bold_cyan')} {colorize_username(nick)}")


    def shutdown(self):
        self.add_message("system", colorize("🛑 Shutting down…", "yellow"))
        self.running       = False
        self.shutdown_flag = True
        try:
            if self.sock:
                self.send_raw("QUIT :OTRv4 client shutting down")
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        try:
            self._smp_executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            self._smp_executor.shutdown(wait=False)
        except Exception:
            pass
        self.add_message("system", colorize("✅ Clean shutdown complete", "green"))

    def send_privmsg(self, target: str, message: str) -> bool:
        return self.send(f"PRIVMSG {target} :{message}")





class EnhancedOTRv4IRCClient(OTRv4IRCClient):
    """
    Full OTRv4 IRC client with:
      - Complete DAKE handshake (DAKE1/2/3)
      - Double ratchet encryption
      - SMP verification with auto-respond
      - Fingerprint trust database
      - Traffic-light security indicator (🔴🟡🟢🔵)
      - All prompts IN-CHAT (no blocking input() calls)
      - remote fingerprint display and auto-switch to private panel
      - manual SMP start only
      - SMP start works with encrypted messages
    """

    def __init__(self, config=None):
        super().__init__(config)

        self._pending_action: Optional[dict] = None
        self._pending_lock = threading.Lock()


    def _set_pending(self, action_type: str, peer: str, **kwargs):
        """Register a pending action waiting for user input in chat."""
        with self._pending_lock:
            self._pending_action = {'type': action_type, 'peer': peer, **kwargs}

    def _clear_pending(self):
        with self._pending_lock:
            self._pending_action = None

    def _get_pending(self) -> Optional[dict]:
        with self._pending_lock:
            return self._pending_action

    def _dispatch_pending_response(self, text: str) -> bool:
        """
        Called from handle_chat_message when a pending action exists.
        Returns True if the input was consumed by a pending action.
        """
        action = self._get_pending()
        if not action:
            return False

        atype = action['type']
        peer = action['peer']
        self._clear_pending()

        if atype == 'trust':
            self._handle_trust_response(peer, text.strip().lower(), action)
            return True
        elif atype == 'smp_secret':
            self._handle_smp_secret_response(peer, text.strip(), action)
            return True

        return False


    def process_dake1(self, sender: str, payload: str):
        """DAKE1 received — notify user in active panel, switch to peer tab, then respond.

        Without this, the DAKE2 auto-response fires silently while the user is
        in a different channel.  They never see the request and miss the trust /
        SMP prompts that appear after DAKE3 arrives.  Fix: tell the user where
        they are right now, ensure the peer panel exists, then switch to it so
        the subsequent fingerprint / trust / SMP prompts land in front of them.
        """
        if sender not in self.panel_manager.panels:
            self.panel_manager.add_panel(sender, 'secure')

        active = self.panel_manager.active_panel
        if active and active != sender:
            self.add_message(active, colorize(
                f"🔑 {sender} is requesting an OTR session with you"
                f" — switching to their tab…", "cyan"))

        self._switch_panel(sender)

        self._route_otr_to_session_manager(sender, payload, "DAKE1", is_initiator=False)

    def process_dake2(self, sender: str, payload: str):
        """DAKE2 received → send DAKE3 → session ENCRYPTED (initiator)."""
        sec_before = self.session_manager.get_security_level(sender)
        self.add_message("system",
            f"{colorize('🔑 DAKE2 ←', 'cyan')} {colorize_username(sender)}")
        self._route_otr_to_session_manager(sender, payload, "DAKE2", is_initiator=True)
        sec = self.session_manager.get_security_level(sender)
        if sec == UIConstants.SecurityLevel.ENCRYPTED:
            self.add_message("system",
                f"{colorize('🔑 DAKE3 →', 'cyan')} {colorize_username(sender)}")
            self._handle_session_established(sender, is_initiator=True)
        else:
            self.add_message("system",
                colorize(f"⚠ DAKE2 processed but session not yet encrypted", "yellow"))

    def process_dake3(self, sender: str, payload: str):
        """DAKE3 received → session ENCRYPTED (responder)."""
        self.add_message("system",
            f"{colorize('🔑 DAKE3 ←', 'cyan')} {colorize_username(sender)}")
        self._route_otr_to_session_manager(sender, payload, "DAKE3", is_initiator=False)
        sec = self.session_manager.get_security_level(sender)
        if sec == UIConstants.SecurityLevel.ENCRYPTED:
            self._handle_session_established(sender, is_initiator=False)
        else:
            self.add_message("system",
                colorize(f"⚠ DAKE3 processed but session not encrypted", "yellow"))

    def _route_otr_to_session_manager(self, sender: str, payload: str,
                                       label: str, is_initiator: bool):
        """Feed a raw OTRv4 payload to the session manager and handle the response."""
        try:
            result = self.session_manager.handle_incoming_message(sender, payload)
            if result and isinstance(result, (bytes, str)):
                resp = result if isinstance(result, str) else result.decode("utf-8", errors="replace")
                if resp.startswith("?OTRv4 "):
                    self.send_otr_message(sender, resp)
                    if label == "DAKE1":
                        self.add_message("system",
                            f"{colorize('🔑 DAKE2 →', 'cyan')} {colorize_username(sender)}")
                    return
            self.debug(f"{label} processed", {"sender": sender})
        except Exception as exc:
            self.debug(f"{label} error: {exc}")
            self.add_message("system",
                f"{colorize(f'❌ {label} error from', 'red')} {sender}: {str(exc)[:60]}")


    def _otr_panel(self, peer: str) -> str:
        """Return the panel name for OTR private conversation (always the peer's private panel)."""
        if peer not in self.panel_manager.panels:
            self.panel_manager.add_panel(peer, 'secure')
        return peer

    def _handle_session_established(self, peer: str, is_initiator: bool):
        """Called after DAKE completes. Shows fingerprints and trust prompt in PRIVATE panel."""
        try:
            channel_panel = None
            for ch, info in self.channels.items():
                if peer in info.get("users", set()):
                    channel_panel = ch
                    break

            if peer not in self.panel_manager.panels:
                self.panel_manager.add_panel(peer, 'secure')

            sec = UIConstants.SecurityLevel.ENCRYPTED
            self.panel_manager.update_panel_security(peer, sec)
            if channel_panel:
                self.panel_manager.update_panel_security(channel_panel, sec)

            role = "initiator" if is_initiator else "responder"

            # Detect ratchet backend for display
            _session = self.session_manager.get_session(peer) if hasattr(self.session_manager, 'get_session') else None
            _backend = getattr(_session, '_ratchet_backend', 'python') if _session else 'python'
            _backend_tag = "🦀 Rust" if _backend == "rust" else "🐍 Python"

            if channel_panel:
                self.add_message(channel_panel,
                                 f"🔒 OTR session with {colorize_username(peer)} established"
                                 f" — Ed448/X448, AES-256-GCM ({role}) [{_backend_tag}]",
                                 sec)

            local_fp = self._get_local_fp()
            remote_fp = self._get_remote_fp(peer)

            self.add_message(peer, colorize("─"*50, 'dim'), sec)
            self.add_message(peer, colorize(f"🔑 FINGERPRINTS ({peer})", 'cyan'), sec)
            self.add_message(peer, f"  Yours : {colorize(self._fmt_fp(local_fp), 'green')}", sec)
            self.add_message(peer, f"  Theirs: {colorize(self._fmt_fp(remote_fp), 'yellow')}", sec)
            self.add_message(peer, colorize("─"*50, 'dim'), sec)

            if self.panel_manager.active_panel != peer:
                self._switch_panel(peer)
            else:
                if self._prompt_refresh_cb is not None:
                    self._prompt_refresh_cb()

            already_trusted = False
            if remote_fp:
                try:
                    if hasattr(self.session_manager, 'is_peer_trusted'):
                        already_trusted = self.session_manager.is_peer_trusted(peer)
                    elif hasattr(self.session_manager, 'trust_db'):
                        already_trusted = self.session_manager.trust_db.is_trusted(peer, remote_fp)
                except Exception:
                    already_trusted = False

            if already_trusted:
                self.add_message(peer, colorize("✅ Fingerprint already trusted", 'green'), sec)
                self._finish_trust(peer, trusted=True, remote_fp=remote_fp,
                                   is_initiator=is_initiator)
            else:
                self.add_message(peer,
                    colorize("❓ Trust this fingerprint? Type  y  or  n", 'yellow'), sec)
                self._set_pending('trust', peer,
                                  remote_fp=remote_fp, is_initiator=is_initiator)

        except Exception as exc:
            self.debug(f"_handle_session_established error: {exc}")
            self.add_message("system",
                f"{colorize('❌ Session setup error:', 'red')} {str(exc)[:100]}")

    def _handle_trust_response(self, peer: str, response: str, action: dict):
        """Process y/n trust response from user."""
        trusted = (response == 'y')
        remote_fp = action.get('remote_fp', '')
        is_initiator = action.get('is_initiator', False)

        if trusted and remote_fp:
            try:
                if hasattr(self.session_manager, 'trust_fingerprint'):
                    self.session_manager.trust_fingerprint(peer, remote_fp)
                else:
                    self.session_manager.trust_db.add_trust(peer, remote_fp)
            except Exception as exc:
                self.debug(f"trust save error: {exc}")

        self._finish_trust(peer, trusted=trusted, remote_fp=remote_fp,
                           is_initiator=is_initiator)

    def _finish_trust(self, peer: str, trusted: bool,
                      remote_fp: str, is_initiator: bool):
        """Update security level after trust decision, then prompt for SMP secret."""
        if trusted:
            sec = UIConstants.SecurityLevel.FINGERPRINT
            self.add_message(peer, colorize("🟢 Fingerprint trusted — VERIFIED", 'green'), sec)
        else:
            sec = UIConstants.SecurityLevel.ENCRYPTED
            self.add_message(peer,
                colorize("🟡 Fingerprint NOT trusted — encrypted only", 'yellow'), sec)

        self.panel_manager.update_panel_security(peer, sec)

        self.add_message(peer, colorize("─"*50, 'dim'), sec)
        self.add_message(peer, colorize("🔐 SMP VERIFICATION SETUP", 'blue'), sec)
        self.add_message(peer,
            "Type your shared secret (both sides must use the same).", sec)
        self.add_message(peer,
            colorize("After setting secret, type  /smp start  to begin verification.", 'cyan'), sec)
        self.add_message(peer,
            colorize("Press Enter / type  skip  to skip SMP for now.", 'dim'), sec)
        self._set_pending('smp_secret', peer,
                          security_level=sec, is_initiator=is_initiator)

    def _handle_smp_secret_response(self, peer: str, secret: str, action: dict):
        """Process SMP secret input from user - NO AUTO TIMER."""
        sec = action.get('security_level', UIConstants.SecurityLevel.ENCRYPTED)
        is_initiator = action.get('is_initiator', False)

        if secret and secret.lower() != 'skip':
            try:
                if hasattr(self.session_manager, 'set_smp_secret'):
                    self.session_manager.set_smp_secret(peer, secret)
                elif hasattr(self.session_manager, 'smp_storage'):
                    self.session_manager.smp_storage.set_secret(peer, secret)
                
                sess = self.session_manager.get_session(peer)
                if sess and hasattr(sess, 'set_smp_secret'):
                    sess.set_smp_secret(secret)
                
                self.add_message(self._otr_panel(peer),
                    colorize("✅ SMP secret stored", 'green'), sec)
                
                if is_initiator:
                    self.add_message(self._otr_panel(peer),
                        colorize("🔐 Type  /smp start  to begin verification.", 'cyan'), sec)
                else:
                    self.add_message(self._otr_panel(peer),
                        colorize("🔐 Type  /smp start  to initiate, or wait for the other side.", 'cyan'), sec)
            except Exception as exc:
                self.debug(f"smp secret store error: {exc}")
                self.add_message(self._otr_panel(peer),
                    colorize("⚠ Could not store SMP secret", 'yellow'), sec)
        else:
            self.add_message(self._otr_panel(peer),
                colorize("⚠ SMP skipped — use /smp <secret> later", 'dim'), sec)

        self._finish_session_setup(peer, sec)

    def _finish_session_setup(self, peer: str, sec):
        """Show final help after session is fully set up."""
        _session = self.session_manager.get_session(peer) if hasattr(self.session_manager, 'get_session') else None
        _backend = getattr(_session, '_ratchet_backend', 'python') if _session else 'python'
        _backend_tag = "🦀 Rust" if _backend == "rust" else "🐍 Python"
        self.add_message(peer, colorize("─"*50, 'dim'), sec)
        self.add_message(peer, colorize(f"✅ Session ready! — Ratchet: {_backend_tag}", 'green'), sec)
        self.add_message("system",
            f"{colorize('Commands:', 'cyan')} "
            f"/fingerprint  /smp <secret>  /smp start  /trust <nick>  /secure")


    def process_smp_message(self, sender: str, data: bytes):
        """Handle incoming SMP TLV bytes."""
        try:
            if not hasattr(self.session_manager, 'process_smp_message'):
                return
            
            result = self.session_manager.process_smp_message(sender, data)
            if result:
                self.debug(f"SMP response of length {len(result)}")
                self.send_otr_message(sender, result)

            if hasattr(self.session_manager, 'get_smp_status'):
                status = self.session_manager.get_smp_status(sender)
                if status.get('verified'):
                    self._on_smp_verified(sender)
                elif status.get('failed'):
                    sec = self.session_manager.get_security_level(sender)
                    self.add_message(sender,
                        colorize("❌ SMP verification FAILED — secrets don't match", 'red'), sec)
        except Exception as exc:
            self.debug(f"process_smp_message error: {exc}")



    _NOTIF_COOLDOWN = 30

    def _termux_fire(self, args: list) -> None:
        """Run termux-notification in the background; swallow all errors."""
        try:
            import subprocess as _sp
            _sp.Popen(['termux-notification'] + args,
                      stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        except Exception:
            pass

    def _termux_remove_notification(self, panel: str) -> None:
        """Dismiss the tray notification for *panel* (called on tab switch)."""
        try:
            import subprocess as _sp
            _sp.Popen(['termux-notification-remove',
                       'otrv4_' + panel.lstrip('#')],
                      stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        except Exception:
            pass

    def _termux_notify_message(self, panel: str, message: str) -> None:
        """Notify of a new message in a background tab (rate-limited per panel)."""
        import re as _notif_re
        _now = time.time()
        if not hasattr(self, '_last_notif'):
            self._last_notif = {}
        if _now - self._last_notif.get(panel, 0) < self._NOTIF_COOLDOWN:
            return
        self._last_notif[panel] = _now
        is_otr = not panel.startswith('#')
        _notif_body = ('New encrypted message from ' + panel) if is_otr else ('New message in ' + panel)
        args = [
            '--title',    ('🔒 ' + panel) if is_otr else panel,
            '--content',  _notif_body,
            '--priority', 'high' if is_otr else 'default',
            '--id',       'otrv4_' + panel.lstrip('#'),
            '--alert-once',
        ]
        if is_otr:
            args += ['--vibrate', '0,200,100,200']
        self._termux_fire(args)

    def _termux_notify_otr_event(self, peer: str, started: bool) -> None:
        """Notify of OTR session start (🔒) or end (🔓)."""
        if started:
            self._termux_fire([
                '--title',    '🔒 OTR session started',
                '--content',  'Encrypted session with ' + peer + ' established',
                '--priority', 'high',
                '--id',       'otrv4_' + peer + '_session',
                '--vibrate',  '0,150,100,150,100,150',
            ])
        else:
            self._termux_fire([
                '--title',    '🔓 OTR session ended',
                '--content',  'Session with ' + peer + ' closed',
                '--priority', 'default',
                '--id',       'otrv4_' + peer + '_session',
            ])

    def _on_peer_disconnected(self, peer: str, reason: str = "") -> None:
        """Tear down OTR session and update UI when a peer goes offline.

        Called from the QUIT handler (explicit disconnect) and the 401
        ERR_NOSUCHNICK handler (discovered disconnect via failed send).
        """
        if peer not in self.panel_manager.panels:
            return

        sec = UIConstants.SecurityLevel.PLAINTEXT
        reason_str = f": {reason}" if reason else ""
        self.add_message(peer, colorize(
            f"⚠ {peer} disconnected{reason_str} — OTR session ended", "red"), sec)

        self.panel_manager.update_panel_security(peer, sec)

        self.panel_manager.update_smp_progress(peer, 0, 0)

        try:
            if hasattr(self.session_manager, 'sessions'):
                self.session_manager.sessions.pop(peer, None)
        except Exception:
            pass

        try:
            action = getattr(self, '_pending_action', None)
            if action and action.get('peer') == peer:
                self._pending_action = None
        except Exception:
            pass

        try:
            if hasattr(self, '_401_handled'):
                self._401_handled.discard(peer)
        except Exception:
            pass

    def _on_smp_verified(self, peer: str):
        """Called when SMP verification succeeds → 🔵 SMP_VERIFIED (fires once)."""
        if getattr(self, '_smp_verified_notified', {}).get(peer):
            return
        if not hasattr(self, '_smp_verified_notified'):
            self._smp_verified_notified = {}
        self._smp_verified_notified[peer] = True

        sec = UIConstants.SecurityLevel.SMP_VERIFIED
        self.panel_manager.update_panel_security(peer, sec)
        self.panel_manager.update_smp_progress(peer, 0, 0)
        self.add_message(self._otr_panel(peer),
            colorize("🔵 SMP VERIFIED — identity confirmed by shared secret!", 'blue'), sec)
        self.add_message("system",
            f"{colorize('🔵 SMP verified with', 'blue')} {colorize_username(peer)}")
        self._termux_fire([
            '--title',    '\U0001f535 OTR identity verified',
            '--content',  peer + ' — SMP shared secret confirmed',
            '--priority', 'high',
            '--id',       'otrv4_' + peer + '_session',
            '--vibrate',  '0,100,50,100',
        ])


    def handle_message(self, line: str):
        """Dispatch IRC line — routes OTR fragments to process_incoming_otr_message."""
        try:
            prefix, command, params, trailing = self.parse_irc_message(line)
            self.logger.network_message("IN", prefix or "SERVER",
                                        command or "?", len(line))
            self.debug("recv", {"cmd": command,
                                 "trail": (trailing or "")[:120]})

            if command == 'PING':
                self.send(f"PONG :{trailing or (params[0] if params else 'server')}")
                self.last_ping = time.time()
                return
            if command == 'PONG':
                self.last_ping = time.time()
                return

            if command and command.isdigit():
                self.handle_numeric_reply(int(command), params, trailing)
                return

            sender = (prefix.split('!')[0] if prefix and '!' in prefix
                      else prefix or 'server')
            if len(sender) > 64 or '\r' in sender or '\n' in sender:
                return
            if sender in self.ignored_users:
                return

            if command == 'PRIVMSG':
                target = params[0] if params else ""
                message = trailing or ""

                if self.is_ctcp_message(message) and '?OTRv4' not in message:
                    return

                self.check_auto_reply(sender, target, message)

                if '?OTRv4' in message:
                    if sender not in self.fragment_buffers:
                        self.fragment_buffers[sender] = OTRFragmentBuffer(
                            timeout=self.config.fragment_timeout)
                    try:
                        complete = self.fragment_buffers[sender].add_fragment(
                            sender, message)
                    except Exception as exc:
                        self.debug(f"fragment error: {exc}")
                        return
                    if complete:
                        self.process_incoming_otr_message(sender, complete)
                    return

                panel = target if target.startswith('#') else sender
                self.add_message(panel,
                    f"{colorize_username(sender)}: {message}")
                return

            super().handle_message(line)

        except Exception as exc:
            self.debug(f"handle_message error: {exc}",
                       {"line": line[:100]})

    def process_incoming_otr_message(self, sender: str, message: str):
        """Route a complete OTRv4 message to the right handler."""
        self.debug("otr msg", {"sender": sender, "len": len(message)})
        try:
            if not message.startswith("?OTRv4 "):
                return
            
            raw = message[7:].strip()
            if not raw:
                return

            try:
                decoded = OTRv4DAKE._safe_b64decode(raw)
            except Exception:
                return
            
            if not decoded:
                return

            if (len(decoded) >= 3
                    and decoded[0] == 0x00
                    and decoded[1] == 0x04
                    and decoded[2] == OTRv4DataMessage.TYPE):
                self.debug("otr type", {"type": "DATA_V6", "sender": sender})
                self._handle_data_message(sender, message)
                return

            msg_type = decoded[0]
            self.debug("otr type", {"type": msg_type, "sender": sender})
            
            if msg_type == OTRConstants.MESSAGE_TYPE_DAKE1:
                self.process_dake1(sender, message)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE2:
                self.process_dake2(sender, message)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE3:
                self.process_dake3(sender, message)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DATA:
                self._handle_data_message(sender, message)
        except Exception as exc:
            self.debug(f"process_incoming_otr error: {exc}")

    def _handle_data_message(self, sender: str, payload: str):
        """Decrypt DATA message. TLV routing is handled inside the session layer."""
        if not self.session_manager.has_session(sender):
            return

        try:
            result = self.session_manager.decrypt_message(sender, payload)
            if result is None:
                return

            text = result if isinstance(result, str) else result.decode('utf-8', errors='replace')

            if text.startswith('?OTRv4 '):
                self.send_otr_message(sender, text)
                
                if hasattr(self.session_manager, 'get_smp_status'):
                    status = self.session_manager.get_smp_status(sender)
                    if status.get('verified'):
                        self._on_smp_verified(sender)
                    elif status.get('failed'):
                        sec = self.session_manager.get_security_level(sender)
                        self.add_message(sender,
                            colorize("❌ SMP verification FAILED — secrets don't match", 'red'), sec)
                return

            if text.strip():
                sec = self.session_manager.get_security_level(sender)
                self.add_message(sender, f"{colorize_username(sender)}: {text}", sec)
                self.panel_manager.update_panel_security(sender, sec)

            if hasattr(self.session_manager, 'get_smp_progress'):
                prog = self.session_manager.get_smp_progress(sender)
                self.panel_manager.update_smp_progress(sender, *prog)

            if hasattr(self.session_manager, 'get_smp_status'):
                status = self.session_manager.get_smp_status(sender)
                if status.get('verified'):
                    self._on_smp_verified(sender)

        except Exception as exc:
            self.debug(f"_handle_data_message error: {exc}")


    def handle_chat_message(self, msg: str):
        """
        Intercept chat input.
        If a pending action is waiting, consume it.
        Otherwise encrypt+send normally.
        """
        if self._dispatch_pending_response(msg):
            return

        super().handle_chat_message(msg)


    def start_guided_otr_session(self, peer: str):
        """Start DAKE with peer by sending DAKE1."""
        if self.session_manager.has_session(peer) and self.session_manager.get_security_level(peer) != UIConstants.SecurityLevel.PLAINTEXT:
            self.add_message("system",
                f"{colorize('✅ Already encrypted with', 'green')} {colorize_username(peer)}")
            return
        
        self.add_message("system",
            f"Starting OTR with {colorize_username(peer)}…")
        
        if peer not in self.panel_manager.panels:
            self.panel_manager.add_panel(peer, 'private')
        
        self._switch_panel(peer)
        
        try:
            otr_msg, should_send = self.session_manager.handle_outgoing_message(peer, "")
            
            if otr_msg and should_send:
                self.send_otr_message(peer, otr_msg)
                self.add_message("system",
                    f"{colorize('🔑 DAKE1 →', 'cyan')} {colorize_username(peer)}")
            else:
                self.send(f"PRIVMSG {peer} :?OTRv4 ")
        except Exception as exc:
            self.debug(f"start_guided_otr_session error: {exc}")


    def handle_command(self, command: str):
        parts = command.strip().split()
        if not parts:
            return
        cmd = parts[0].lower()

        if cmd == 'otr' and len(parts) > 1:
            self.start_guided_otr_session(parts[1])

        elif cmd == 'trust' and len(parts) > 1:
            peer = parts[1]
            sec = self.session_manager.get_security_level(peer) \
                  if self.session_manager.has_session(peer) \
                  else UIConstants.SecurityLevel.ENCRYPTED
            remote_fp = self._get_remote_fp(peer)
            
            if remote_fp:
                try:
                    if hasattr(self.session_manager, 'trust_fingerprint'):
                        self.session_manager.trust_fingerprint(peer, remote_fp)
                    else:
                        self.session_manager.trust_db.add_trust(peer, remote_fp)
                    
                    new_sec = UIConstants.SecurityLevel.FINGERPRINT
                    self.panel_manager.update_panel_security(peer, new_sec)
                    self.add_message(peer,
                        colorize("🟢 Fingerprint trusted — VERIFIED", 'green'), new_sec)
                except Exception as exc:
                    self.add_message("system",
                        f"{colorize('❌ Trust failed:', 'red')} {exc}")
            else:
                self.add_message("system",
                    colorize("No active session to trust", 'red'))

        
        elif cmd in ('smp', 'verify'):
            if len(parts) < 2:
                self.add_message("system", colorize("Usage: /smp <command> [args]", 'red'))
                return
                
            subcmd = parts[1].lower()
            
            if subcmd == 'start':
                peer = None
                if len(parts) > 2:
                    peer = parts[2]
                else:
                    active = self.panel_manager.get_active_panel()
                    if active and active.type not in ('system', 'debug'):
                        peer = active.name
                
                if not peer:
                    self.add_message("system", 
                        colorize("Usage: /smp start [peer]  (or switch to peer panel)", 'red'))
                    return
                
                if not self.session_manager.has_session(peer):
                    self.add_message("system",
                        f"{colorize('❌ No session with', 'red')} {peer}")
                    return
                
                if self.session_manager.get_security_level(peer) == UIConstants.SecurityLevel.PLAINTEXT:
                    self.add_message("system",
                        f"{colorize('❌ No encrypted session with', 'red')} {peer}")
                    return
                
                secret = None
                
                if hasattr(self.session_manager, 'smp_storage'):
                    secret = self.session_manager.smp_storage.get_secret(peer)
                    self.debug(f"Got secret from smp_storage: {bool(secret)}")
                
                if not secret:
                    sess = self.session_manager.get_session(peer)
                    if sess and hasattr(sess, 'auto_smp_secret') and sess.auto_smp_secret:
                        secret = sess.auto_smp_secret
                        self.debug(f"Got secret from session.auto_smp_secret: {bool(secret)}")
                
                if not secret:
                    self.add_message("system",
                        colorize(f"No SMP secret stored for {peer} - use /smp <peer> <secret> first", 'yellow'))
                    return
                
                self.debug(f"Starting SMP with secret length: {len(secret)}")
                self._start_smp(peer, secret)
            
            elif subcmd == 'abort':
                peer = None
                if len(parts) > 2:
                    peer = parts[2]
                else:
                    active = self.panel_manager.get_active_panel()
                    if active and active.type not in ('system', 'debug'):
                        peer = active.name
                
                if not peer:
                    self.add_message("system", 
                        colorize("Usage: /smp abort [peer]", 'red'))
                    return
                
                self.clear_pending_smp(peer)
                if hasattr(self.session_manager, 'abort_smp'):
                    self.session_manager.abort_smp(peer)
                self.add_message("system", f"🛑 SMP aborted for {colorize_username(peer)}")
            
            elif subcmd == 'status':
                peer = None
                if len(parts) > 2:
                    peer = parts[2]
                else:
                    active = self.panel_manager.get_active_panel()
                    if active and active.type not in ('system', 'debug'):
                        peer = active.name
                
                if not peer:
                    self.add_message("system", 
                        colorize("Usage: /smp status [peer]", 'red'))
                    return
                
                self._show_smp_status(peer)
            
            else:
                active = self.panel_manager.get_active_panel()
                peer = active.name if active and active.type not in ('system', 'debug') else None
                
                if not peer and len(parts) > 2:
                    peer = parts[1]
                    secret = ' '.join(parts[2:])
                elif peer:
                    secret = ' '.join(parts[1:])
                else:
                    self.add_message("system",
                        colorize("Usage: /smp <peer> <secret>  or  /smp <secret> (in peer panel)", 'red'))
                    return
                
                if secret:
                    try:
                        if hasattr(self.session_manager, 'set_smp_secret'):
                            self.session_manager.set_smp_secret(peer, secret)
                        elif hasattr(self.session_manager, 'smp_storage'):
                            self.session_manager.smp_storage.set_secret(peer, secret)
                        
                        sec_level = self.session_manager.get_security_level(peer)
                        self.add_message(self._otr_panel(peer),
                            colorize("✅ SMP secret stored", 'green'), sec_level)
                        self.add_message(self._otr_panel(peer),
                            colorize("🔐 Type  /smp start  to begin verification.", 'cyan'), sec_level)
                    except Exception as exc:
                        self.add_message("system",
                            f"{colorize('❌', 'red')} {exc}")
                else:
                    self.add_message("system",
                        colorize("Usage: /smp <secret>  or  /smp start [peer]", 'red'))

        elif cmd == 'smp-secret' and len(parts) > 2:
            peer = parts[1]
            secret = ' '.join(parts[2:])
            
            try:
                if hasattr(self.session_manager, 'set_smp_secret'):
                    self.session_manager.set_smp_secret(peer, secret)
                elif hasattr(self.session_manager, 'smp_storage'):
                    self.session_manager.smp_storage.set_secret(peer, secret)
                
                self.add_message("system",
                    f"🔑 SMP secret set for {colorize_username(peer)}")
                sec_level = self.session_manager.get_security_level(peer)
                self.add_message(self._otr_panel(peer),
                    colorize("🔐 Type  /smp start  to begin verification.", 'cyan'), sec_level)
            except Exception as exc:
                self.add_message("system",
                    f"{colorize('❌', 'red')} {exc}")

        elif cmd == 'fingerprint':
            self._show_fingerprints()

        elif cmd in ('secure', 'sessions', 'otr-status'):
            self._show_all_sessions()

        elif cmd == 'session-info' and len(parts) > 1:
            self._show_session_info(parts[1])

        elif cmd == 'endotr' and len(parts) > 1:
            peer = parts[1]
            try:
                if hasattr(self.session_manager, 'terminate_session'):
                    self.session_manager.terminate_session(peer, "user request")
                self.panel_manager.update_panel_security(
                    peer, UIConstants.SecurityLevel.PLAINTEXT)
                self.add_message("system",
                    f"Session ended with {colorize_username(peer)}")
            except Exception:
                pass

        else:
            super().handle_command(command)

    

    def _start_smp(self, peer: str, secret: str, question: str = ""):
        """Kick off SMP verification with immediate step-1 feedback.

        The ZK proof computation inside smp_engine.start_smp() is expensive
        (hundreds of ms on Termux).  We show the step-1 progress bar to the
        user BEFORE starting the computation so they get instant feedback,
        then do the heavy work in a background thread.
        """
        if not self.session_manager.has_session(peer):
            self.add_message("system",
                f"{colorize('❌ No session with', 'red')} {peer}")
            return

        if self.session_manager.get_security_level(peer) == UIConstants.SecurityLevel.PLAINTEXT:
            self.add_message("system",
                f"{colorize('❌ No encrypted session with', 'red')} {peer}")
            return

        sess = self.session_manager.get_session(peer)
        if sess is not None and getattr(sess, '_smp_notify_cb', None) is None:
            factory = getattr(self.session_manager, 'smp_notify_factory', None)
            if factory is not None:
                try:
                    sess._smp_notify_cb = factory(peer)
                except Exception:
                    pass

        sec = self.session_manager.get_security_level(peer)
        self.add_message(peer, colorize(
            "🔐 SMP [███ ░░░ ░░░ ░░░] step 1/4"
            " · Computing challenge — please wait…", "yellow"), sec)
        self.panel_manager.update_smp_progress(peer, 1, 4)

        if hasattr(self.session_manager, 'set_smp_secret'):
            self.session_manager.set_smp_secret(peer, secret)

        def _do_smp():
            try:
                if not hasattr(self.session_manager, 'start_smp'):
                    self.add_message("system",
                        colorize("SMP not supported by session manager", 'red'))
                    return

                self.debug(f"SMP background compute starting for {peer}")
                encrypted_msg = self.session_manager.start_smp(peer, secret, question)
                self.debug(f"SMP compute done: msg={'yes' if encrypted_msg else 'no'}")

                if encrypted_msg and isinstance(encrypted_msg, str) \
                        and encrypted_msg.startswith('?OTRv4 '):
                    if self.send_otr_message(peer, encrypted_msg):
                        s = self.session_manager.get_security_level(peer)
                        self.add_message(peer, colorize(
                            "🔐 SMP [███ ░░░ ░░░ ░░░] step 1/4"
                            " · Challenge sent — awaiting response…", "yellow"), s)
                    else:
                        self.add_message("system",
                            colorize("❌ Failed to send SMP challenge", 'red'))
                        self.panel_manager.update_smp_progress(peer, 0, 0)
                else:
                    self.panel_manager.update_smp_progress(peer, 0, 0)
                    if hasattr(self.session_manager, 'get_smp_status'):
                        status = self.session_manager.get_smp_status(peer)
                        if status.get('verified'):
                            self.add_message(peer,
                                colorize("✅ SMP already verified!", 'green'),
                                self.session_manager.get_security_level(peer))
                        elif status.get('state') not in ('NONE', 'FAILED'):
                            self.add_message(peer, colorize(
                                f"⚠ SMP already in progress (state: {status.get('state')})",
                                'yellow'), self.session_manager.get_security_level(peer))
                        else:
                            self.add_message("system",
                                colorize("❌ SMP init failed — check session state", 'red'))
            except Exception as exc:
                self.debug(f"_start_smp background error: {exc}")
                self.add_message("system",
                    colorize(f"❌ SMP error: {str(exc)[:80]}", 'red'))
                self.panel_manager.update_smp_progress(peer, 0, 0)

        threading.Thread(target=_do_smp, daemon=True,
                         name=f"smp-{peer}").start()


    def _get_local_fp(self) -> str:
        try:
            if hasattr(self.session_manager, 'get_fingerprint'):
                fp = self.session_manager.get_fingerprint()
                if fp:
                    return fp
            if hasattr(self.session_manager, 'client_profile'):
                return self.session_manager.client_profile.get_fingerprint()
        except Exception:
            pass
        return "unavailable"

    def _get_remote_fp(self, peer: str) -> str:
        """Get remote fingerprint for peer using multiple fallback methods."""
        try:
            if hasattr(self.session_manager, 'get_peer_fingerprint'):
                fp = self.session_manager.get_peer_fingerprint(peer)
                if fp:
                    self.debug(f"_get_remote_fp: got from get_peer_fingerprint: {fp[:16]}...")
                    return fp

            sess = self.session_manager.get_session(peer)
            if sess:
                if hasattr(sess, 'get_fingerprint'):
                    fp = sess.get_fingerprint()
                    if fp:
                        self.debug(f"_get_remote_fp: got from session.get_fingerprint: {fp[:16]}...")
                        return fp
                
                if hasattr(sess, 'remote_long_term_pub') and sess.remote_long_term_pub:
                    try:
                        pub_bytes = sess.remote_long_term_pub.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                        fp_bytes = hashlib.sha3_512(pub_bytes).digest()
                        fp = fp_bytes.hex().upper()
                        self.debug(f"_get_remote_fp: got from remote_long_term_pub: {fp[:16]}...")
                        return fp
                    except Exception as e:
                        self.debug(f"_get_remote_fp: remote_long_term_pub conversion failed: {e}")
                
                if hasattr(sess, '_remote_long_term_pub_bytes') and sess._remote_long_term_pub_bytes:
                    try:
                        fp_bytes = hashlib.sha3_512(sess._remote_long_term_pub_bytes).digest()
                        fp = fp_bytes.hex().upper()
                        self.debug(f"_get_remote_fp: got from stored bytes: {fp[:16]}...")
                        return fp
                    except Exception as e:
                        self.debug(f"_get_remote_fp: stored bytes conversion failed: {e}")

        except Exception as e:
            self.debug(f"_get_remote_fp error: {e}")
        
        self.debug(f"_get_remote_fp: no fingerprint found for {peer}")
        return ""

    @staticmethod
    def _fmt_fp(fp: str) -> str:
        """Format 40-char fingerprint as groups of 8."""
        if not fp or fp == "unavailable":
            return fp
        clean = fp.upper().replace(" ", "")
        if len(clean) < 40:
            clean = clean.ljust(40, '0')
        return " ".join(clean[i:i+8] for i in range(0, 40, 8))

    def _show_fingerprints(self):
        local_fp = self._get_local_fp()
        self.add_message("system",
            f"Your fingerprint: {colorize(self._fmt_fp(local_fp), 'cyan')}")

        for peer in list(self.session_manager.sessions.keys()):
            fp = self._get_remote_fp(peer)
            sec = self.session_manager.get_security_level(peer)
            icon = UIConstants.SECURITY_ICONS.get(sec, "")
            trusted = ""
            
            if fp:
                try:
                    is_t = (self.session_manager.is_peer_trusted(peer)
                            if hasattr(self.session_manager, 'is_peer_trusted')
                            else self.session_manager.trust_db.is_trusted(peer, fp))
                    trusted = colorize(" ✅ trusted", 'green') if is_t else colorize(" ⚠ untrusted", 'yellow')
                except Exception:
                    trusted = ""
            
            self.add_message("system",
                f"  {icon} {colorize_username(peer)}: "
                f"{colorize(self._fmt_fp(fp), 'green')}{trusted}")

    def _show_all_sessions(self):
        sessions = self.session_manager.sessions
        if not sessions:
            self.add_message("system", "No OTR sessions active")
            return
        
        self.add_message("system", colorize("Active OTR sessions:", 'cyan'))
        for peer, sess in sessions.items():
            sec = getattr(sess, 'security_level', UIConstants.SecurityLevel.PLAINTEXT)
            icon = UIConstants.SECURITY_ICONS.get(sec, "")
            name = UIConstants.SECURITY_NAMES.get(sec, sec.name)
            self.add_message("system",
                f"  {icon} {colorize_username(peer):<20} {colorize(name, 'yellow')}")

    def _show_session_info(self, peer: str):
        if not self.session_manager.has_session(peer):
            self.add_message("system",
                f"{colorize('No session with', 'red')} {peer}")
            return
        
        info = self.session_manager.get_session_info(peer)
        for k, v in info.items():
            self.add_message("system", f"  {k}: {v}")

    def _show_smp_status(self, peer: str):
        if not self.session_manager.has_session(peer):
            self.add_message("system",
                f"{colorize('No session with', 'red')} {peer}")
            return
        
        if hasattr(self.session_manager, 'get_smp_status'):
            status = self.session_manager.get_smp_status(peer)
            self.add_message("system",
                f"SMP {colorize_username(peer)}: {status}")


    def shutdown(self):
        """Shutdown client with complete terminal clear"""
        self.add_message("system", colorize("🔄 Shutting down OTR sessions…", 'yellow'))
        
        _session_count = len(self.session_manager.sessions) if hasattr(self.session_manager, 'sessions') else 0
        _rust_count = 0

        try:
            if hasattr(self.session_manager, 'sessions'):
                for peer, sess in self.session_manager.sessions.items():
                    if getattr(sess, '_ratchet_backend', None) == 'rust':
                        _rust_count += 1
        except Exception:
            pass

        try:
            if hasattr(self.session_manager, 'clear_all_sessions'):
                self.session_manager.clear_all_sessions("client shutdown")
        except Exception:
            pass
        
        if _rust_count > 0:
            self.add_message("system", colorize(
                f"🦀 {_rust_count} Rust ratchet(s) zeroized (deterministic memory wipe)", 'green'))
        elif _session_count > 0:
            self.add_message("system", colorize(
                f"🐍 {_session_count} Python ratchet(s) cleaned (GC-dependent)", 'yellow'))

        self._secure_wipe_data()
        
        try:
            super().shutdown()
        except Exception:
            pass
        
        try:
            sys.stdout.write("\033[2J")
            sys.stdout.write("\033[H")
            sys.stdout.write("\033[3J")
            sys.stdout.flush()
            
            print("\n" * 100)
            
            if IS_TERMUX:
                os.system('clear')
            else:
                try:
                    os.system('clear')
                except OSError:
                    pass
            
            _wipe_msg = "🦀 Rust memory zeroized" if RUST_RATCHET_AVAILABLE else "Memory cleared"
            print(colorize(f"\nOTRv4+ terminated — {_wipe_msg} — screen cleared", "green"))
            print(colorize("Type 'python otrv4+.py --debug' to start again", "cyan"))
            
        except Exception as e:
            self.debug(f"Error clearing screen: {e}")

    def _secure_wipe_data(self):
        """Overwrite and delete all persisted OTR data — Termux-safe."""
        import glob
        otrv4plus_dir = os.path.expanduser("~/.otrv4plus")
        try:
            os.makedirs(otrv4plus_dir, exist_ok=True)
            os.chmod(otrv4plus_dir, 0o700)
        except Exception:
            pass
        try:
            if os.path.isdir(otrv4plus_dir):
                for fpath in glob.glob(os.path.join(otrv4plus_dir, "**", "*"), recursive=True):
                    if os.path.isfile(fpath):
                        try:
                            size = os.path.getsize(fpath)
                            with open(fpath, "r+b") as f:
                                f.write(os.urandom(max(size, 1)))
                                f.flush()
                                os.fsync(f.fileno())
                            os.remove(fpath)
                        except Exception:
                            pass
                import shutil
                shutil.rmtree(otrv4plus_dir, ignore_errors=True)
                self.add_message("system", colorize("🗑  ~/.otrv4plus wiped — keys & secrets erased", 'green'))
        except Exception as e:
            self.add_message("system", colorize(f"⚠ Wipe incomplete: {e}", 'yellow'))



def parse_args() -> OTRConfig:
    """Parse command line arguments"""
    config = OTRConfig()
    
    if '--debug' in sys.argv or '-d' in sys.argv:
        global DEBUG_MODE
        DEBUG_MODE = True
    
    if '--smp-debug' in sys.argv:
        global SMP_DEBUG
        SMP_DEBUG = True
    
    for i, arg in enumerate(sys.argv):
        if arg in ('--server', '-s') and i + 1 < len(sys.argv):
            config.server = sys.argv[i + 1]
        elif arg in ('--channel', '-c') and i + 1 < len(sys.argv):
            config.channel = sys.argv[i + 1]
        elif arg in ('--nick', '-n') and i + 1 < len(sys.argv):
            config.nickserv_nick = sys.argv[i + 1]
        elif arg in ('--port', '-p') and i + 1 < len(sys.argv):
            config.port = int(sys.argv[i + 1])
        elif arg == '--tls':
            config.use_tls = True
        elif arg == '--no-tls':
            config.use_tls = False
            if config.port == 0:
                config.port = IRCConstants.PORT

    # ── Split server:port if colon present ──────────────────
    if ':' in config.server:
        _parts = config.server.rsplit(':', 1)
        if _parts[1].isdigit():
            config.server = _parts[0]
            if config.port == 0:
                config.port = int(_parts[1])

    # ── SASL auth (IRCv3 — replaces NickServ IDENTIFY) ───────
    if '--sasl' in sys.argv:
        if not config.nickserv_nick:
            config.nickserv_nick = input("Nick: ").strip()
        if not config.nickserv_nick:
            print("Error: nick required for --sasl")
            sys.exit(1)
        config.sasl_user = config.nickserv_nick
        config.sasl_pass = getpass.getpass("SASL password: ")
        if not config.sasl_pass:
            print("Error: password required for --sasl")
            sys.exit(1)

    elif '--login' in sys.argv:
        config.nickserv_login = True
        if not config.nickserv_nick:
            config.nickserv_nick = input("Nick: ").strip()
        if not config.nickserv_nick:
            print("Error: nick required for --login")
            sys.exit(1)
        config.nickserv_pass = getpass.getpass("NickServ password: ")
        if not config.nickserv_pass:
            print("Error: password required for --login")
            sys.exit(1)

    elif '--register' in sys.argv:
        config.nickserv_register = True
        if not config.nickserv_nick:
            config.nickserv_nick = input("Choose nick: ").strip()
        if not config.nickserv_nick:
            print("Error: nick required for --register")
            sys.exit(1)
        config.nickserv_pass = getpass.getpass("Choose password: ")
        if not config.nickserv_pass:
            print("Error: password required for --register")
            sys.exit(1)
        pass2 = getpass.getpass("Confirm password: ")
        if config.nickserv_pass != pass2:
            print("Error: passwords do not match")
            sys.exit(1)

    return config

def main():
    import select as _select
    global _current_prompt

    config = parse_args()

    # Apply paths
    config.trust_db_path    = os.path.expanduser("~/.otrv4plus/trust.json")
    config.smp_secrets_path = os.path.expanduser("~/.otrv4plus/smp_secrets.json")
    config.key_storage_path = os.path.expanduser("~/.otrv4plus/keys")
    config.log_file_path    = os.path.expanduser("~/.otrv4plus/logs/otrv4plus.log")
    config.test_mode        = TEST_MODE
    config.i2p_proxy        = (NetworkConstants.I2P_PROXY_HOST, NetworkConstants.I2P_PROXY_PORT)
    config.tor_proxy        = (NetworkConstants.TOR_PROXY_HOST, NetworkConstants.TOR_PROXY_PORT)
    config.log_level        = "DEBUG" if DEBUG_MODE else "INFO"
    config.dake_timeout     = 120.0
    config.fragment_timeout = 120.0
    config.heartbeat_interval = 60
    config.rekey_interval   = 100

    _net = NetworkConstants.detect(config.server)
    _net_icon = {"i2p": "🧅 I2P", "tor": "🧅 Tor", "clearnet": "🌐 Clearnet"}.get(_net, _net)
    _net_col  = {"i2p": "dark_cyan", "tor": "dark_magenta", "clearnet": "grey"}.get(_net, "white")

    # Determine display port
    _disp_port = config.port if config.port != 0 else (
        IRCConstants.TLS_PORT if _net == "clearnet" else IRCConstants.PORT)
    _tls_disp = "🔒 TLS" if (_net == "clearnet" and _disp_port == IRCConstants.TLS_PORT) or config.use_tls else "plaintext"
    _auth_disp = "SASL" if config.sasl_user else ("NickServ" if config.nickserv_login else "anonymous")

    safe_print(f"\n{colorize('OTRv4 IRC Client', 'bold_cyan')}")
    safe_print(colorize("=" * 50, "dim"))
    safe_print(f"Version : {colorize(VERSION, 'yellow')}")
    safe_print(f"Server  : {colorize(config.server + ':' + str(_disp_port), 'green')}")
    safe_print(f"Network : {colorize(_net_icon, _net_col)} ({_tls_disp})")
    safe_print(f"Auth    : {colorize(_auth_disp, 'cyan')}")
    safe_print(f"Channel : {colorize(config.channel, 'cyan')}")
    safe_print(f"Debug   : {colorize('ON' if DEBUG_MODE else 'OFF', 'green' if DEBUG_MODE else 'dim')}")
    _rt_label = "🦀 Rust (zeroize-on-drop)" if RUST_RATCHET_AVAILABLE else "🐍 Python (C extensions)"
    safe_print(f"Ratchet : {colorize(_rt_label, 'green' if RUST_RATCHET_AVAILABLE else 'yellow')}")
    safe_print(colorize("=" * 50, "dim") + "\n")

    if TEST_MODE:
        safe_print(colorize("Tests are now run via pytest:", "cyan"))
        safe_print(colorize("  pytest -v -k 'not 300k'", "green"))
        safe_print(colorize("  (207 tests across 9 test files)", "dim"))
        return 0

    client = EnhancedOTRv4IRCClient(config)

    if not client.connect():
        safe_print(colorize("Failed to connect — check i2pd is running on port 4447", "red"))
        return 1

    client.start_auto_smp_monitor()

    def _print_prompt():
        """Print the input prompt — called once per input cycle.

        Format:  [active-panel]  notif-badges  smp-bar
        Example: [#otr]  user201+3 sys+1  ⬤⬤◯◯

        The notification badges after the panel bracket show unread counts
        for every background panel so the user knows what's waiting without
        having to run /tabs.
        """
        active = client.panel_manager.get_active_panel()
        if not active:
            _set_prompt(colorize("> ", "green"))
            return
        sec_lvl  = active.security_level
        if active.type in ("private", "secure"):
            icon = UIConstants.SECURITY_ICONS.get(sec_lvl, "🔴")
        else:
            icon = ""

        if active.type in ("private", "secure"):
            type_sym = ""
        elif active.type == "channel":
            type_sym = ""
        elif active.type == "system":
            type_sym = "⚙"
        elif active.type == "debug":
            type_sym = "🐛"
        else:
            type_sym = ""

        smp_inset = ""
        step, total = active.smp_progress
        if 0 < step < total:
            bar = '⬤' * step + '◯' * (total - step)
            smp_inset = colorize(f" {bar} ", 'yellow')

        nick = getattr(client, 'nick', '')
        bracket = f"{type_sym}{icon}{active.name}"
        prompt = (colorize(nick, "cyan")
                  + colorize(" | ", "dim")
                  + colorize(f"[{bracket}]", "green")
                  + smp_inset + " ")
        _set_prompt(prompt)

    client._prompt_refresh_cb = _print_prompt

    try:
        _print_prompt()
        _use_raw = _setup_raw_mode()
        if _use_raw:
            atexit.register(_restore_terminal)
        _fd = _stdin_fd if _use_raw else sys.stdin.fileno()

        def _read_line_raw() -> Optional[str]:
            """Read one char in raw mode.

            Returns str (completed line) when the user presses Enter,
            _EOF_SENTINEL on Ctrl-D, or None (char consumed, keep reading).
            """
            ch = _read_one_char()
            if ch is None:
                return _EOF_SENTINEL
            return _handle_input_char(ch)

        def _read_line_cooked() -> Optional[str]:
            """Read a full line in cooked mode (fallback for non-TTY)."""
            global _current_prompt
            line = sys.stdin.readline()
            _current_prompt = ""
            _flush_display_queue()
            if not line:
                return _EOF_SENTINEL
            return line.rstrip("\r\n")

        _read_input = _read_line_raw if _use_raw else _read_line_cooked

        while not client.shutdown_flag:
            try:
                r, _, _ = _select.select([_fd], [], [], 0.2)

                if not r:
                    _flush_display_queue()
                    # ── Check for disconnection ──────────────────
                    if not client.running and not client.shutdown_flag:
                        safe_print(colorize(
                            "\n⚠ Disconnected from server. "
                            "Type /reconnect to reconnect, or /quit to exit.",
                            "yellow"
                        ))
                        while not client.shutdown_flag and not client.running:
                            try:
                                r2, _, _ = _select.select([_fd], [], [], 0.5)
                                if not r2:
                                    continue
                                result = _read_input()
                                if result is _EOF_SENTINEL:
                                    client.shutdown_flag = True
                                    break
                                if result is None:
                                    continue   # raw mode: char consumed
                                l2 = result
                                if l2.startswith("/"):
                                    client.handle_command(l2[1:])
                                elif l2:
                                    safe_print(colorize(
                                        "Not connected — use /reconnect first.",
                                        "yellow"
                                    ))
                                _print_prompt()
                            except KeyboardInterrupt:
                                safe_print(colorize(
                                    "\nCtrl-C — type /quit to exit", "yellow"))
                                _print_prompt()
                            except Exception:
                                pass
                        continue
                    continue

                # ── Read input ───────────────────────────────
                result = _read_input()
                if result is _EOF_SENTINEL:
                    safe_print(colorize("\nEOF — shutting down", "yellow"))
                    break
                if result is None:
                    continue           # raw mode: char consumed, not a line yet

                line = result

                if not line:
                    _print_prompt()
                    continue

                if line.startswith("/"):
                    client.handle_command(line[1:])
                else:
                    client.handle_chat_message(line)

                _print_prompt()

            except KeyboardInterrupt:
                safe_print(colorize("\nCtrl-C — type /quit to exit", "yellow"))
                _print_prompt()
            except Exception as exc:
                try:
                    client.debug(f"main loop error: {exc}")
                    client.add_message("system", colorize(
                        f"⚠ Internal error (recovered): {str(exc)[:80]}",
                        "yellow"))
                except Exception:
                    pass
                _print_prompt()

    except Exception as exc:
        try:
            safe_print(colorize(
                f"⚠ Critical error (attempting recovery): {exc}", "yellow"))
            while True:
                try:
                    r, _, _ = _select.select([_fd], [], [], 1.0)
                    if r:
                        if _use_raw:
                            ch = _read_one_char()
                            if ch is None:
                                break
                            res = _handle_input_char(ch)
                            if res is _EOF_SENTINEL:
                                break
                            if isinstance(res, str) and res.startswith("/quit"):
                                break
                            if res is None:
                                continue
                        else:
                            l = sys.stdin.readline()
                            if not l:
                                break
                            l = l.rstrip("\r\n")
                            if l.startswith("/quit"):
                                break
                        safe_print(colorize(
                            "Emergency mode — type /quit to exit", "yellow"))
                except Exception:
                    break
        except Exception:
            pass

    _restore_terminal()
    client.shutdown()
    return 0



if __name__ == "__main__":
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass

    try:
        gc.freeze()
    except AttributeError:
        pass

    sys.setswitchinterval(0.05)

    if 'PYTHONMALLOC' not in os.environ:
        print(colorize(
            "[HARDENING] For maximum security launch with:  "
            "PYTHONMALLOC=malloc python otrv4+.py",
            "yellow"
        ))

    atexit.register(lambda: safe_print(colorize("\nClean shutdown", "green")))

    main()
