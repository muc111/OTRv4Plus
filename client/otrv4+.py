# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
# =============================================================================
#  OTRv4+  -  IRC transport client
#  Post-quantum Off-the-Record messaging over IRC (clearnet TLS / Tor / I2P).
#
#  SECURITY MODEL (enforced throughout this file):
#    * All cryptography lives in the Rust core (otrv4_core). This Python layer
#      never holds private key material and never implements a primitive; it
#      orchestrates the handshake, ratchet, and SMP and renders the UI.
#    * Every byte of untrusted network data (nicks, channels, topics, message
#      bodies, AND decrypted OTR payloads) passes through _sanitise() before it
#      reaches the terminal, blocking ANSI/OSC/CSI escape-sequence injection and
#      OSC title-hijack from a malicious server or peer.
#    * Inbound OTR fragments are bounded on every axis (per-sender count, total
#      senders, in-flight fragments, 1 MiB reassembly cap, and a timeout) to
#      prevent memory-exhaustion denial of service. See OTRFragmentBuffer.
#    * TLS certificate validation is ON by default. It is only relaxed behind an
#      explicit opt-in, for self-signed servers reached over an already
#      cryptographically authenticated I2P or Tor tunnel.
#    * Subprocess calls (termux-notification) use argv lists, never a shell, and
#      untrusted values are sanitised against command-line option injection.
#    * Fingerprints are pinned on first use (TOFU); a mismatch raises and aborts.
#
#  Audited for: shell/command injection, escape-sequence injection, ReDoS,
#  unsafe deserialisation, weak hashing, and insecure randomness. None present:
#  no eval/exec, no pickle/marshal, no shell=True, no user-compiled regexes,
#  no md5/sha1, and no use of the `random` module for any security decision.
# =============================================================================
import sys
import os
import socket
import threading

# Started as `python <client>`: run again with the project interpreter
# (~/OTRv4Plus/.venv, where Rust/build.sh installs otrv4_core). Loaded by
# name: the APK never runs a client as a script and does not ship it.
if __name__ == "__main__":
    import importlib as _importlib
    _importlib.import_module("otrv4plus_venv").ensure(__file__)

# `socks` comes from the **PySocks** distribution.  Naming it here matters:
# there is also a PyPI project literally called `socks`, and it is an empty
# placeholder ("automatically generated with 'register_pypi' and should be
# deleted soon", version 0) that installs no module at all.  A tester ran
# `pip install socks`, saw it succeed, and still got `No module named
# 'socks'` -- so this import says which package, and checks that what it
# got is actually PySocks rather than something that merely took the name.
try:
    import socks
except ImportError as _socks_exc:            # pragma: no cover - install path
    raise ImportError(
        "OTRv4+ needs the 'socks' module, which is supplied by the PySocks "
        "distribution:\n"
        "    pip install PySocks\n"
        "Note: the PyPI package literally named 'socks' is an empty "
        "placeholder and installs nothing -- installing it will NOT fix this."
    ) from _socks_exc
if not all(hasattr(socks, _attr) for _attr in
           ("setdefaultproxy", "socksocket", "PROXY_TYPE_SOCKS5")):
    raise ImportError(
        "the installed 'socks' module is not PySocks: it has no "
        "setdefaultproxy/socksocket/PROXY_TYPE_SOCKS5.  Something else has "
        "taken the name.  Fix with:\n"
        "    pip uninstall -y socks && pip install PySocks"
    )

# The SMP consent state machine, shared with the XMPP client.  Imported
# rather than reimplemented: INV-06 is the property that a remote peer may
# make the client ASK for the passphrase but never make the next typed line
# BECOME one, and that property is structural in SmpFlow -- there is no edge
# from a remote transition into AWAITING_SECRET.  A second copy of the logic
# here would be a second chance to get it wrong.
import otrv4plus_smpflow as _smpflow
# Address rules shared with the Android app, including the project server's
# shipped address (SHIPPED_SERVERS). Standard library only.
import otrv4plus_address as _address

try:
    from otrv4plus_log import ChannelLogManager as _ChannelLogManager
    _LOG_AVAILABLE = True
except ImportError:
    _ChannelLogManager = None
    _LOG_AVAILABLE = False

try:
    from otrv4_core import RustDoubleRatchet as _RustRatchet

    RUST_RATCHET_AVAILABLE = True
except ImportError:
    RUST_RATCHET_AVAILABLE = False

try:
    from otrv4_core import RustDAKE as _RustDAKE
    import otrv4_core as _RustDAKE_module

    RUST_DAKE_AVAILABLE = True
except ImportError:
    _RustDAKE = None
    _RustDAKE_module = None
    RUST_DAKE_AVAILABLE = False


try:
    # Verification only. Signing is `Ed448KeyHandle.ring_sign` (the seed
    # stays in Rust); the raw-seed `py_ring_sign` exists only in test builds
    # (Cargo feature `raw-key-test-api`).
    from otrv4_core import py_ring_verify as _rust_ring_verify

    RUST_RING_SIG_AVAILABLE = True
except ImportError:
    _rust_ring_verify = None
    RUST_RING_SIG_AVAILABLE = False


def _check_rust_requirements():
    try:
        import otrv4_core as _probe  # noqa: F401
    except ImportError:
        # Not a build without the DAKE: no core at all for THIS Python.
        # build.sh installs it into ~/OTRv4Plus/.venv only.
        raise ImportError(
            "otrv4_core is not installed for this Python (%s).  Start the "
            "client with the project interpreter:  .venv/bin/python otrv4+.py "
            "...  -- or build it first:  bash Rust/build.sh" % sys.executable
        )
    if not RUST_DAKE_AVAILABLE or _RustDAKE is None:
        raise ImportError(
            "OTRv4+ v10.6.11+ requires otrv4_core.RustDAKE.  "
            "The .so was not built with the dake module.  "
            "Rebuild Rust/ with: cargo build --release --features pq-rust"
        )
    if not RUST_RING_SIG_AVAILABLE or _rust_ring_verify is None:
        raise ImportError(
            "OTRv4+ v10.6.11+ requires "
            "otrv4_core.py_ring_verify.  The .so was not built with the "
            "ring_sig module.  Rebuild Rust/ with the latest src/ring_sig.rs "
            "and src/lib.rs that registers it."
        )
    # Only the handle-based surface the live path uses. The raw-key
    # constructors are compiled into test builds only (R3).
    _required_methods = [
        "sign_profile_body_and_construct_with_handles",
        "generate_dake2_output",
        "process_dake2_output",
        "generate_dake3",
        "process_dake3",
    ]
    _missing = [m for m in _required_methods if not hasattr(_RustDAKE, m)]
    if _missing:
        raise ImportError(
            f"OTRv4+ v10.6.11+ requires the following methods on "
            f"otrv4_core.RustDAKE: {_required_methods }.  Missing: {_missing }.  "
            f"Rebuild the .so from the current Rust/src/dake.rs."
        )

    _required_module_symbols = [
        "Ed448KeyHandle",
        "X448KeyHandle",
        "generate_ed448_keypair",
        "generate_x448_keypair",
        "verify_ed448_sig",
        "mldsa87_verify",
        "MlDsa87KeyHandle",
        "MlKem1024Keypair",
        "MessageMacKey",
    ]
    _missing_mod = [s for s in _required_module_symbols if not hasattr(_RustDAKE_module, s)]
    if _missing_mod:
        raise ImportError(
            f"OTRv4+ v10.6.20+ requires the following on the otrv4_core "
            f"module: {_required_module_symbols }.  Missing: {_missing_mod }.  "
            f"Rebuild the .so from the current Rust/src/key_handles.rs, "
            f"Rust/src/mldsa.rs, Rust/src/aead.rs, Rust/src/mlkem.rs, "
            f"and Rust/src/lib.rs."
        )


_check_rust_requirements()

import time
import secrets
import hashlib
import json
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
import textwrap
import atexit
import gc
import resource
import shutil
import logging
import logging.handlers
from typing import Optional, Dict, Any, Tuple, List, Set, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import IntEnum
import concurrent.futures

CRYPTO_AVAILABLE = True

try:
    import resource as _resource

    _resource.setrlimit(_resource.RLIMIT_CORE, (0, 0))
except Exception:

    pass

import sys as _sys, os as _os

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

MLDSA87_AVAILABLE = True

# No argon2-cffi. The at-rest key handling it served (the SMP auto-respond
# store and the unused SecureKeyStorage) moved into the Rust core
# (`Rust/src/at_rest.rs`), which has its own Argon2id for reading the legacy
# store format; the Python derivation and its scrypt fallback are gone.


def secure_compare(a: str, b: str) -> bool:
    """Constant-time string comparison"""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


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
    #: Capability byte in the signed ClientProfile version list: "I run the
    #: v2 ratchet" (SPEC §5.2, docs/VERSIONING.md). The profile is signed and
    #: is in the DAKE transcript, so it cannot be stripped in transit; a
    #: decoder that predates it accepts the profile because 4 is still listed.
    PQ_RATCHET_VERSION = 0x50
    #: "Authenticates with ML-DSA-87 in both directions" (SPEC §4.3, audit
    #: A2): with both profiles listing it, the responder signs DAKE2 and the
    #: initiator DAKE3, each with its long-term ML-DSA key, and both are
    #: mandatory. Peers pin that key (TrustDatabase.check_or_pin_pq).
    PQ_AUTH_VERSION = 0x51
    SESSION_ID_BYTES = 32
    ED448_PUBLIC_KEY_SIZE = 57
    ED448_SIGNATURE_SIZE = 114
    X448_PUBLIC_KEY_SIZE = 56

    MESSAGE_TYPE_DAKE1 = 0x35
    MESSAGE_TYPE_DAKE2 = 0x36
    MESSAGE_TYPE_DAKE3 = 0x37
    MESSAGE_TYPE_DATA = 0x03

    # TLV types are NOT here. They live in OTRv4TLV, which is the class the
    # engine constructs and dispatches on; this block was a second table with
    # no call sites, and it disagreed -- it allocated 0x08 for a client-profile
    # TLV that OTRv4+ does not use, because the client profile travels in the
    # DAKE. Two tables where one is dead and wrong is a trap for anyone reading
    # the engine alongside docs/SPEC.md §5.6.

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

    Usage IDs 0x00-0x1F are reserved by the spec.  Each distinct KDF call
    MUST use a different ID so that outputs are domain-separated and cannot
    be conflated even if the input material is identical.
    """

    SSID = 0x01
    BRACE_KEY = 0x02
    SHARED_SECRET = 0x03
    AUTH_R_MAC = 0x04
    AUTH_I_MSG = 0x05
    ROOT_KEY = 0x11
    CHAIN_KEY = 0x12
    MESSAGE_KEY = 0x13
    MAC_KEY = 0x14
    DAKE_MAC_KEY = 0x15
    EXTRA_SYM_KEY = 0x1F
    BRACE_KEY_ROTATE = 0x16


_KDF_DOMAIN = b"OTRv4"


def kdf_1(usage_id: int, value: bytes, length: int) -> bytes:
    """KDF(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size).

    OTRv4 spec §3.2 (Key Derivation Function, Hash Function and MAC Function):
      KDF(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size)
      HWC(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size)
      HCMAC(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size)

    All three functions are identical - just SHAKE-256 with the "OTRv4"
    domain separator prefix.  Previous implementations that omitted this
    prefix produced non-spec key material and would fail to interoperate
    with libotr4, CoyIM, or any spec-compliant OTRv4 implementation.
    """
    shake = hashlib.shake_256()
    shake.update(_KDF_DOMAIN)
    shake.update(bytes([usage_id]))
    shake.update(value)
    return shake.digest(length)


def _secure_wipe(buf: bytearray) -> None:
    """Zero a mutable bytearray in place, resistant to dead-store elimination.

    v10.7.2 (Phase 5.3i-B): replaces _ossl.cleanse() from the
    otr4_crypto_ext C extension.  Uses ctypes.memset, which is a call into
    libc's memset - the Python compiler cannot see through it or optimise
    it away, giving the same dead-store-elimination resistance that
    OPENSSL_cleanse provided, without any C-extension or FFI dependency.
    This is the exact technique SecureMemory.zeroize already used as its
    ctypes-based wipe path.

    Only operates on bytearray (mutable).  Passing bytes is a no-op: bytes
    objects are immutable and may be interned/shared - see
    _secure_wipe_bytes.  Silently tolerant of None and empty buffers so
    call sites do not each need a guard.
    """
    if buf is None:
        return
    try:
        n = len(buf)
        if n == 0:
            return
        addr = (ctypes.c_char * n).from_buffer(buf)
        ctypes.memset(addr, 0, n)
    except (TypeError, BufferError):

        try:
            for _i in range(len(buf)):
                buf[_i] = 0
        except (TypeError, IndexError):
            pass


def _secure_wipe_bytes(b: bytes) -> None:
    """No-op stub - do NOT attempt to wipe immutable bytes objects.

    CPython's bytes objects are immutable and may be interned or shared.
    Writing through ctypes into their internal buffer is undefined behaviour:
    it corrupts shared references and relies on a CPython-version-specific
    memory layout that can change without notice.

    CORRECT PATTERN: use bytearray for all mutable secrets and call
    _secure_wipe() on them before deletion.  Do NOT call this function.

    This stub is retained to avoid breaking callers while they are migrated;
    it intentionally does nothing so that no UB can occur.
    """
    pass


def _secure_file_destroy(filepath: str) -> None:
    """Overwrite a file once with random bytes, fsync it, and unlink it.

    WHAT THIS DOES NOT DO: guarantee the old contents are gone from flash.
    On flash storage (every phone, most laptops) the controller's
    wear-levelling writes the overwrite to NEW physical blocks and leaves the
    old ones -- holding the old plaintext -- to be erased whenever it chooses.
    Neither this function nor any other file-level call can reach them. An
    earlier version of this docstring claimed NIST SP 800-88 compliance and
    that surviving blocks would be "ciphertext whose key has been destroyed";
    both were wrong, because the old blocks were never encrypted by the
    overwrite. What this does achieve: the file's logical contents are
    replaced before unlink, so the data is not recoverable through the file
    system, by undelete tools, or from a copy-on-write-free journal.

    The overwrite bytes come straight from the kernel CSPRNG. (It used to
    AES-GCM-encrypt zeros under a throwaway Python-held key to get the same
    thing: a key in a Python bytearray bought nothing os.urandom does not.)
    """
    size = os.path.getsize(filepath)
    if size == 0:
        os.remove(filepath)
        return

    with open(filepath, "r+b") as f:
        written = 0
        while written < size:
            chunk = os.urandom(min(65536, size - written))
            f.write(chunk)
            written += len(chunk)
        f.flush()
        os.fsync(f.fileno())

    os.remove(filepath)


class MLKEM1024BraceKEM:
    """ML-KEM-1024 (FIPS 203) wire sizes for the OTRv4 post-quantum brace KEM.

    Sizes only. The brace KEM runs entirely in the Rust core
    (`otrv4_core.MlKem1024Keypair`, `RustDoubleRatchet.brace_encapsulate` /
    `brace_decapsulate`), so its decapsulation key and shared secret never
    become Python objects. This class used to wrap the raw
    `mlkem1024_keygen` / `encaps` / `decaps` primitives and hand the shared
    secret back as Python bytes; nothing in production used it, and a
    Python-side key holder that nothing uses is only somewhere for a future
    change to put a secret. The primitives remain in the core for
    known-answer tests, which call them directly.
    """

    EK_BYTES = 1568
    CT_BYTES = 1568
    SS_BYTES = 32


class MLDSA87Auth:
    """ML-DSA-87 (FIPS 204) keypair for hybrid PQ DAKE authentication.

    NIST Level 5 (~256-bit post-quantum security).

    v10.6.18 (Phase 5.3j): backed by Rust pqcrypto-mldsa 0.1.2 via the
    otrv4_core PyO3 module.  Previously used the otr4_mldsa_ext C
    extension (OpenSSL EVP).  Wire format is byte-identical; both
    implementations are PQClean-derived reference implementations of
    the same FIPS 204 parameter set.

    The ML-DSA-87 signature is appended to the Ed448 ring signature
    in DAKE3, creating a hybrid authentication:
      - Ring sig (Ed448): classical deniability + authentication
      - ML-DSA-87 sig:    post-quantum authentication

    A quantum adversary could verify the ML-DSA signature and prove
    participation.  This is an acceptable trade-off: PQ deniable
    signatures are not standardized, and authentication against
    quantum adversaries is the higher priority.

    Key sizes (FIPS 204 §4):
      Public key:  2592 bytes
      Private key: 4896 bytes (held in Rust by MlDsa87KeyHandle)
      Signature:   4627 bytes
    """

    PUB_BYTES = 2592
    PRIV_BYTES = 4896
    SIG_BYTES = 4627

    def __init__(self, handle=None):
        """Generate a fresh ML-DSA-87 keypair inside Rust, or wrap `handle`
        (a long-term key reopened by otrv4plus_identity.load_or_create_mldsa).

        The secret key is held by an opaque `MlDsa87KeyHandle` and never
        becomes a Python object: `mldsa87_keygen` would return it as a
        bytearray and `mldsa87_sign` would need it passed back as `bytes`
        -- a fresh unwipeable copy per signature. `_priv` is the handle.
        """
        self._priv = handle if handle is not None else _RustDAKE_module.MlDsa87KeyHandle()
        self.pub_bytes: bytes = bytes(self._priv.public_bytes)

    def sign(self, msg: bytes) -> bytes:
        """Sign a message.  Returns 4627-byte signature."""
        if self._priv is None:
            raise RuntimeError("ML-DSA-87 private key has been zeroized")
        return bytes(self._priv.sign(msg))

    @classmethod
    def verify(cls, pub_bytes: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify an ML-DSA-87 signature.  Returns True/False."""
        if len(pub_bytes) != cls.PUB_BYTES:
            return False
        if len(sig) != cls.SIG_BYTES:
            return False
        try:
            return bool(_RustDAKE_module.mldsa87_verify(pub_bytes, msg, sig))
        except Exception:
            return False

    def zeroize(self):
        """Destroy the signing key inside Rust, then drop the handle."""
        if self._priv is not None:
            try:
                self._priv.zeroize()
            except Exception:
                pass
            self._priv = None
        self.pub_bytes = b"\x00" * self.PUB_BYTES


class RingSignature:
    """OTRv4 Auth-I Schnorr ring signature (spec §4.3.3).

    Wire encoding: c₁(57) ‖ r₁(57) ‖ c₂(57) ‖ r₂(57) = 228 bytes.

    Phase 5.3c (v10.6.9): the production path is Rust (otrv4_core's
    py_ring_sign / py_ring_verify).  v10.6.17 (Phase 5.3f-narrow):
    the previous boot-time cross-verify against the C extension has
    been removed.  RFC 8032 Ed448 test vectors in src/test_vectors.rs
    are the build-time guarantee that Rust ring signatures are
    wire-correct.
    """

    SCALAR_BYTES = 57
    TOTAL_BYTES = 4 * 57
    _USAGE_SIGMA = 0x1C

    @classmethod
    def sign(cls, handle, A1_bytes: bytes, A2_bytes: bytes, msg: bytes) -> bytes:
        """Produce σ = c₁‖r₁‖c₂‖r₂ (228 bytes).

        v10.6.12 (Phase 5.3e): the signing key is now passed as an
        Ed448KeyHandle (Rust-owned).  The handle's .ring_sign() method
        performs the OTRv4 Schnorr ring signature internally using the
        stored seed; the seed never appears in Python.

        v10.6.17 (Phase 5.3f-narrow): the boot-time cross-verify between
        Rust and the C reference has been removed.  RFC 8032 Ed448 test
        vectors in Rust's src/test_vectors.rs are the build-time
        guarantee that Rust ring signatures are wire-correct.
        """
        return bytes(handle.ring_sign(A1_bytes, A2_bytes, msg))

    @classmethod
    def verify(cls, A1_bytes: bytes, A2_bytes: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify σ = c₁‖r₁‖c₂‖r₂ against A₁, A₂, and the transcript msg.

        v10.6.11 (Phase 5.4): Rust-only. No C extension fallback.
        v10.6.17 (Phase 5.3f-narrow): no boot cross-verify; correctness
        guaranteed by Rust's RFC 8032 test vector suite at build time.
        """
        if len(sig) != cls.TOTAL_BYTES:
            return False
        try:
            return bool(_rust_ring_verify(A1_bytes, A2_bytes, msg, sig))
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


class IRCConstants:
    """IRC Protocol Constants"""

    PORT = 6667
    TLS_PORT = 6697
    DEFAULT_SERVER = "irc.postman.i2p"
    DEFAULT_CHANNEL = "#otr"

    IRCV3_CAPS = [
        "sasl",
        "multi-prefix",
        "server-time",
        "message-tags",
        "account-notify",
        "away-notify",
        "cap-notify",
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
    MESSAGE_FRAGMENT_SIZE = 450
    OTR_FRAGMENT_SIZE = 450
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
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "italic": "\033[3m",
        "underline": "\033[4m",
        "black": "\033[30m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "dark_red": "\033[31m",
        "dark_green": "\033[32m",
        "dark_yellow": "\033[33m",
        "dark_blue": "\033[34m",
        "dark_magenta": "\033[35m",
        "dark_cyan": "\033[36m",
        "grey": "\033[90m",
        "orange": "\033[38;5;214m",
        "pink": "\033[38;5;213m",
        "teal": "\033[38;5;43m",
        "lime": "\033[38;5;118m",
        "gold": "\033[38;5;220m",
        "lavender": "\033[38;5;183m",
        "bg_green": "\033[42m",
        "bg_yellow": "\033[43m",
        "bg_blue": "\033[44m",
        "bg_magenta": "\033[45m",
        "bg_cyan": "\033[46m",
        "bg_red": "\033[41m",
        "dim_italic": "\033[2;3m",
        "bold_cyan": "\033[1;96m",
        "bold_green": "\033[1;92m",
        "bold_red": "\033[1;91m",
        "bold_yellow": "\033[1;93m",
    }

    SECURITY_ICONS = {
        SecurityLevel.PLAINTEXT: "🔴",
        SecurityLevel.ENCRYPTED: "🟡",
        SecurityLevel.FINGERPRINT: "🟢",
        SecurityLevel.SMP_VERIFIED: "🔵",
    }

    SECURITY_NAMES = {
        SecurityLevel.PLAINTEXT: "PLAINTEXT",
        SecurityLevel.ENCRYPTED: "ENCRYPTED",
        SecurityLevel.FINGERPRINT: "VERIFIED",
        SecurityLevel.SMP_VERIFIED: "SMP VERIFIED",
    }

    USERNAME_COLORS = [
        "bold_cyan",
        "magenta",
        "bold_green",
        "yellow",
        "orange",
        "pink",
        "teal",
        "gold",
        "lavender",
        "bold_yellow",
        "cyan",
        "dark_magenta",
    ]


def _probe_socks5(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if a SOCKS5 proxy is accepting connections on host:port.

    Uses a raw TCP connect (not PySocks) so it never mutates the global
    socket.socket binding that PySocks requires.
    """
    import socket as _sock_mod

    try:
        with _sock_mod.socket(_sock_mod.AF_INET, _sock_mod.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
        return True
    except OSError:
        return False


class NetworkConstants:
    """Network Configuration - supports clearnet, Tor, and I2P auto-detected from server hostname."""

    I2P_PROXY_HOST = "127.0.0.1"
    I2P_PROXY_PORT = 4447

    TOR_PROXY_HOST = "127.0.0.1"
    TOR_PROXY_PORT = 9050

    I2P_SUFFIXES = (".i2p",)
    TOR_SUFFIXES = (".onion",)

    TIMEOUT_CLEARNET = 30
    TIMEOUT_TOR = 90
    TIMEOUT_I2P = 120

    NET_CLEARNET = "clearnet"
    NET_TOR = "tor"
    NET_I2P = "i2p"

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

    I2P_SAM_HOST = "127.0.0.1"
    I2P_SAM_PORT = 7656


# ─────────────────────────────────────────────────────────────────────────────
# I2P short names
# ─────────────────────────────────────────────────────────────────────────────
#
# `.i2p` names are NOT DNS.  There is no global resolver: a router only knows
# the names in its own address book, which it builds from subscriptions.  A
# private server is in nobody's subscription, so `otrv4plus.i2p` resolves on
# the machine that created it and nowhere else, while the 52-character
# `.b32.i2p` form works everywhere because it IS the destination hash.
#
# That is why the b32 has to be pasted, and it is a genuine usability problem:
# nobody is going to type 52 base32 characters correctly on a phone keyboard.
#
# This file is the local answer.  One line per name:
#
#     otrv4plus.i2p = <52 characters>.b32.i2p
#
# WHAT AN ALIAS IS AND IS NOT.  It is a note to yourself about what a name
# means on this device.  It is not authenticated, it is not published, and it
# proves nothing about who answers.  The security of a conversation does not
# rest on it: the DAKE authenticates the peer and TOFU pins their identity
# key, so pointing an alias at the wrong server yields a failed connection or
# a server that cannot read anything, not a silent impersonation.
#
# A name given in full as .b32.i2p is never looked up here -- see
# _apply_i2p_alias -- so a local file cannot redirect an address typed in
# full.

I2P_HOSTS_FILENAME = "i2p_hosts"

#: What a router answers NAMING LOOKUP with for a well-formed short name its
#: address book does not have. Java I2P says KEY_NOT_FOUND; i2pd says
#: INVALID_KEY (it keeps KEY_NOT_FOUND for a b32 whose LeaseSet it cannot
#: find). The name is validated before it is sent, so for a short name both
#: mean "unknown here" -- the case the alias file and the fallback below are
#: for. Device report 2026-10-01: i2pd answered INVALID_KEY for otrv4plus.i2p
#: and the fallback, which accepted only KEY_NOT_FOUND, never ran.
I2P_NAME_UNKNOWN_RESULTS = ("KEY_NOT_FOUND", "INVALID_KEY")

#: The project's own server name and the b32 it is dialled at, without asking
#: the router (otrv4plus_address.SHIPPED_SERVERS says why). Re-exported here
#: for the terminal client's callers.
SHIPPED_SERVERS = _address.SHIPPED_SERVERS


def remember_i2p_alias(name: str, destination: str, path: str = None,
                       learned: bool = True) -> str:
    """Record `name = destination` in the local alias file.

    So the 52-character b32 is typed once and never again: the client calls
    this after a connection has actually succeeded, which is the only moment
    it knows the pair is good.

    Three refusals, and the third is the one that matters:

      * a name that is not a short `.i2p` name, or a destination that is not a
        b32 or a full destination -- the file must stay loadable;
      * a name already recorded with THE SAME destination -- nothing to do;
      * a name already recorded with a DIFFERENT destination -- left alone and
        reported.  A server whose destination changed is something the user
        needs to see, not something a client should quietly rewrite under
        them.  Editing the file by hand is the way to accept such a change.

    Returns a short status string for display: "" when nothing was written.
    """
    name = (name or "").strip().lower()
    destination = (destination or "").strip()
    if not name.endswith(".i2p") or name.endswith(".b32.i2p"):
        return ""
    if not _valid_i2p_destination(destination):
        return ""

    path = path or i2p_hosts_path()
    if i2p_aliases(i2p_hosts_defaults_path()).get(name) == destination:
        return ""            # the shipped defaults already say this
    existing = i2p_aliases(path).get(name)
    if existing == destination:
        return ""
    if existing:
        return (f"{name } is already recorded as {existing }, which is not "
                f"the destination just used. Not changing it -- edit "
                f"{path } yourself if the server really moved.")

    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        new_file = not os.path.exists(path)
        with open(path, "a", encoding="utf-8") as fh:
            if new_file:
                fh.write("# OTRv4+ I2P name aliases.  One per line:\n")
                fh.write("#     name.i2p = <52 chars>.b32.i2p\n")
                fh.write("# A local note about what a name means on this "
                         "device; it is not\n"
                         "# authenticated and proves nothing about who "
                         "answers.  Delete a line\n"
                         "# to forget it.\n")
            marker = f"  {LEARNED_MARKER }" if learned else ""
            fh.write(f"{name } = {destination }{marker }\n")
        if new_file:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except OSError as exc:
        return f"could not write {path }: {exc }"
    return f"recorded {name } = {destination } in {path }"


def i2p_hosts_path() -> str:
    """Where the local alias file lives."""
    return os.path.join(os.path.expanduser("~/.otrv4plus"), I2P_HOSTS_FILENAME)


def _valid_i2p_destination(value: str) -> bool:
    """A b32 address or a full base64 destination, and nothing else.

    Deliberately strict: an alias that expands to something the router cannot
    use produces a confusing failure much later, and an alias that expands to
    another short name would let one line chain into another.
    """
    if value.endswith(".b32.i2p"):
        label = value[:-len(".b32.i2p")]
        return (len(label) == 52
                and all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in label))
    # A full destination is base64 (I2P's alphabet) and long.
    return (len(value) >= 516
            and all(c.isalnum() or c in "-~=" for c in value))


#: Written after an entry the client learned from a successful connection.
#: The marker is what separates "this device worked it out" from "the user
#: decided this", and the two are treated differently when a shipped default
#: disagrees -- see resolve_i2p_aliases().
LEARNED_MARKER = "# learned"

#: Shipped defaults, updated by `git pull` like any other code.
I2P_HOSTS_DEFAULTS = "i2p_hosts.defaults"


def i2p_hosts_defaults_path() -> str:
    """The defaults that travel with the source, beside this file."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        I2P_HOSTS_DEFAULTS)


def i2p_aliases(path: str = None, with_provenance: bool = False):
    """Read an alias file.  Returns {} when it does not exist.

    Never raises: a malformed line is skipped with a warning rather than
    stopping the client from starting, because the alternative is that one
    typo makes the whole thing unusable.

    With `with_provenance`, values are `(destination, learned)` pairs.
    """
    path = path or i2p_hosts_path()
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError):
        return out

    for number, raw in enumerate(lines, 1):
        learned = LEARNED_MARKER in raw
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" in line:
            name, _, dest = line.partition("=")
        else:
            parts = line.split()
            if len(parts) != 2:
                print(f"[i2p] {path }:{number }: cannot read this line, skipping")
                continue
            name, dest = parts
        name, dest = name.strip().lower(), dest.strip()
        if not name.endswith(".i2p") or name.endswith(".b32.i2p"):
            print(f"[i2p] {path }:{number }: {name !r} is not a short .i2p "
                  "name, skipping")
            continue
        if not _valid_i2p_destination(dest):
            print(f"[i2p] {path }:{number }: {name } does not point at a "
                  ".b32.i2p address or a full destination, skipping")
            continue
        out[name] = (dest, learned) if with_provenance else dest
    return out


def resolve_i2p_aliases(user_path: str = None,
                        defaults_path: str = None,
                        on_message=print) -> dict:
    """Merge the shipped defaults with the user's own file.

    The precedence rule, and the reason for it:

      * a hand-written user entry ALWAYS wins.  Someone who typed a line into
        that file meant it, and an update has no business overruling them;
      * a LEARNED entry -- one this client recorded itself after a successful
        connection -- yields to a shipped default that disagrees, with a
        notice.  Otherwise the first successful connection would pin an
        address forever, and moving the server would strand every user who had
        ever connected, which is exactly the case this layer exists for;
      * otherwise the shipped default applies.

    Nothing here writes.  `~/.otrv4plus/i2p_hosts` is the user's file and an
    update never edits it; the defaults change because `git pull` changed
    them, which is visible in the diff.
    """
    defaults = i2p_aliases(defaults_path or i2p_hosts_defaults_path())
    merged = dict(defaults)
    for name, (dest, learned) in i2p_aliases(
            user_path, with_provenance=True).items():
        shipped = defaults.get(name)
        if learned and shipped and shipped != dest:
            on_message(
                f"[i2p] the address shipped for {name } has changed; using "
                f"the new one.\n"
                f"[i2p]   was (remembered here): {dest }\n"
                f"[i2p]   now (from this build): {shipped }\n"
                f"[i2p] to keep the old one, edit {user_path or i2p_hosts_path ()} "
                f"and remove the '{LEARNED_MARKER }' marker from that line.")
            continue
        merged[name] = dest
    return merged


class SamError(ConnectionError):
    """A SAM failure, classified by the layer that failed.

    `stage` is one of:
      * "bridge"  -- the LOCAL SAM bridge: unreachable, closed, refused HELLO,
                     or sent a malformed / oversized / mismatched reply;
      * "naming"  -- the router could not resolve the name (RESULT= says why);
      * "session" -- SESSION CREATE failed;
      * "stream"  -- STREAM CONNECT failed: the destination is not reachable;
      * "cancelled" -- the caller gave up (I2PSAMConnection.abandon).
    `result` is the SAM RESULT= value when there was one. These are different
    problems with different remedies, and callers report which one it was.
    """

    def __init__(self, stage: str, message: str, result: str = ""):
        super().__init__(message)
        self.stage = stage
        self.result = result


#: A short I2P name: dot-separated labels of letters, digits and hyphens,
#: ending in `.i2p`. Checked BEFORE anything is sent, so a malformed name can
#: never inject text (a space, a newline) into a SAM command.
_I2P_NAME_RE = re.compile(r"^(?=.{5,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+i2p$")
_B32_RE = re.compile(r"^[a-z2-7]{52}\.b32\.i2p$")
#: A full destination in I2P's base64 alphabet (at least 387 characters).
_I2P_DEST_RE = re.compile(r"^[A-Za-z0-9~-]{387,}={0,2}$")
#: A SAM reply line is a few hundred bytes (a destination is under 1 KB).
#: Anything far larger is not a SAM reply and is refused unread.
SAM_MAX_REPLY = 16384


def i2p_target_error(target: str) -> Optional[str]:
    """Why `target` is not an I2P address this client will look up, or None."""
    t = (target or "").strip().lower()
    if not t.endswith(".i2p"):
        return "not an .i2p address"
    if t.endswith(".b32.i2p"):
        return None if _B32_RE.match(t) else (
            "a .b32.i2p address is 52 characters of a-z and 2-7 before "
            "'.b32.i2p'")
    return None if _I2P_NAME_RE.match(t) else (
        "an .i2p name is letters, digits, hyphens and dots, ending in .i2p")

class I2PSAMConnection:
    """Connect to I2P via the SAM bridge instead of SOCKS5.

    SAM creates a unique transient destination per session. With SOCKS5,
    all connections share one local destination - an observer at the IRC
    server can trivially correlate your sessions across reconnects.

    SAM v3.1 is supported by both i2pd and Java I2P.
    Default port: 7656.

    Usage:
        sam = I2PSAMConnection()
        if sam.is_available():
            sock = sam.connect("irc.postman.i2p")
            # sock is a raw TCP stream to the IRC server
    """

    #: Longest wait for one SAM reply line. NAMING LOOKUP and SESSION CREATE
    #: on a cold router legitimately take 60-90 s.
    reply_timeout = 90

    def __init__(self, sam_host: str = None, sam_port: int = None):
        self.sam_host = sam_host or NetworkConstants.I2P_SAM_HOST
        self.sam_port = sam_port or NetworkConstants.I2P_SAM_PORT
        self._session_id = f"otrv4plus_{secrets .token_hex (4 )}"
        self._control_sock = None
        self._our_destination = None
        #: Set by `resolve`: the name is the project's server and was dialled
        #: at the address shipped for it (SHIPPED_SERVERS).
        self.used_shipped_address = False
        #: Set by `abandon`; see there.
        self._abandoned = False
        self._pending_stream = None

    def _send_cmd(self, sock, cmd: str) -> str:
        """Send a SAM command and read ONE reply line.

        Deadline is 90s - I2P NAMING LOOKUP and SESSION CREATE on a cold tunnel
        can legitimately take 60-90 seconds.  The reply is bounded
        (SAM_MAX_REPLY): a peer that streams without a newline is not a SAM
        bridge and must not be able to grow this buffer without limit.  Every
        failure is a SamError("bridge"), never a bare socket error."""
        if "\n" in cmd or "\r" in cmd:
            raise SamError("bridge", "refusing to send a multi-line SAM command")
        try:
            sock.sendall((cmd + "\n").encode("utf-8"))
            buf = b""
            deadline = time.time() + self.reply_timeout
            while b"\n" not in buf:
                if time.time() > deadline:
                    raise SamError("bridge", "SAM bridge timeout")
                if len(buf) > SAM_MAX_REPLY:
                    raise SamError("bridge", "SAM reply too long")
                chunk = sock.recv(4096)
                if not chunk:
                    raise SamError("bridge", "SAM bridge closed connection")
                buf += chunk
        except SamError:
            raise
        except socket.timeout:
            raise SamError("bridge", "SAM bridge timeout") from None
        except OSError as exc:
            raise SamError("bridge", "SAM bridge I/O error (%s)"
                           % type(exc).__name__) from None
        line = buf.split(b"\n", 1)[0]
        try:
            return line.decode("ascii").strip()
        except UnicodeDecodeError:
            raise SamError("bridge", "SAM reply is not ASCII") from None

    def _parse_reply(self, reply: str, prefix: str) -> dict:
        """Parse SAM key=value reply."""
        if not reply.startswith(prefix):
            raise SamError("bridge", f"SAM unexpected reply: {reply[:120] }")
        parts = reply[len(prefix) :].strip().split(" ")
        result = {}
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                result[k] = v
        return result

    def _handshake(self, sock):
        """SAM v3.1 handshake on a socket."""
        reply = self._send_cmd(sock, "HELLO VERSION MIN=3.1 MAX=3.1")
        parsed = self._parse_reply(reply, "HELLO REPLY ")
        if parsed.get("RESULT") != "OK":
            raise SamError("bridge", f"SAM handshake failed: {reply[:120] }",
                           parsed.get("RESULT", ""))

    @staticmethod
    def _explain_stream_failure(target_host, parsed, reply) -> str:
        """Say which step failed, because they need different fixes.

        The old message ended with "Is the server b32 correct?" for every
        result, which is actively misleading for the common one: by the time
        STREAM CONNECT runs the address has already been resolved, so a
        CANT_REACH_PEER means the address was fine and the destination is not
        reachable.  Sending someone to re-check an address that is correct is
        worse than saying nothing.
        """
        result = parsed.get("RESULT", "")
        detail = f"SAM stream connect failed: {reply }"

        if result == "CANT_REACH_PEER":
            return (
                f"{detail }\n"
                f"The address resolved; the destination is not reachable "
                f"right now.\n"
                f"'LeaseSet not found' means the server has not published "
                f"tunnels the router can find -- usually the server is down "
                f"or its I2P tunnel is not running. It can also be a cold "
                f"local router that has not integrated into the netDB yet, "
                f"in which case waiting a few minutes and retrying is enough."
                f"\nThe address is not the problem: {target_host }")
        if result in ("I2P_ERROR", "TIMEOUT"):
            return (f"{detail }\n"
                    f"The router accepted the address but the connection did "
                    f"not complete. Cold tunnels can take 30-120 s; retrying "
                    f"is reasonable.")
        if result == "INVALID_KEY":
            return (f"{detail }\n"
                    f"The router would not accept that destination. Check the "
                    f"address, and any alias pointing at it.")
        return detail

    @staticmethod
    def _retired_destinations(path: str = None) -> dict:
        """{old b32: name it moved to}, from the shipped defaults.

        Read so a user whose command still names the old address in full is
        told where it went.  They are NOT redirected: an address given in full
        is used as given, which is the rule that stops any file from
        re-pointing something the user spelled out.
        """
        out = {}
        try:
            with open(path or i2p_hosts_defaults_path(), encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.split("#", 1)[0].strip()
                    parts = line.split()
                    if len(parts) == 3 and parts[0] == "retired":
                        out[parts[1].lower()] = parts[2].lower()
        except OSError:
            pass
        return out

    @staticmethod
    def _apply_i2p_alias(target_host):
        """Substitute a short name from the local alias file.

        Returns (host_to_resolve, alias_source_or_None).
        """
        if not target_host or target_host.endswith(".b32.i2p"):
            # A b32 address is self-describing: the router resolves it from the
            # hash itself, with no address book involved.  Never let an alias
            # shadow one -- that would let a local file redirect an address the
            # user typed in full.
            #
            # If we know it moved, say so.  Saying is not redirecting.
            moved_to = I2PSAMConnection._retired_destinations().get(
                target_host.lower())
            if moved_to:
                print(f"[i2p] {target_host } is a retired address for "
                      f"{moved_to }.")
                print(f"[i2p] Still trying it as given. The current form is:  "
                      f"--server {moved_to }")
            return target_host, None
        aliases = resolve_i2p_aliases()
        dest = aliases.get(target_host.lower())
        if not dest:
            return target_host, None
        print(f"[i2p] {target_host } -> {dest } (from {i2p_hosts_path ()})")
        return dest, i2p_hosts_path()

    @staticmethod
    def _explain_resolve_failure(target_host, reply, alias_source):
        """Say why a name did not resolve, and what to do about it.

        The bare SAM reply ("Cannot resolve x: NAMING REPLY RESULT=KEY_NOT_FOUND")
        is accurate and useless: it does not say that short .i2p names have to
        come from somewhere, or that this client keeps a file for exactly that.
        """
        if alias_source:
            return (f"Cannot resolve {target_host }, which came from "
                    f"{alias_source }: {reply }\n"
                    "The alias points at a destination the router does not "
                    "recognise. Check the line in that file.")
        if target_host.endswith(".b32.i2p"):
            return (f"Cannot resolve {target_host }: {reply }\n"
                    "That is a b32 address, so this is a router or tunnel "
                    "problem rather than a naming one.")
        return (
            f"Cannot resolve {target_host }: {reply }\n"
            f"Short .i2p names are not global the way DNS is -- the router "
            f"only knows names in its address book, and a private server is "
            f"not in anyone's.\n"
            f"Either use the full <52 chars>.b32.i2p address, or add a line to "
            f"{i2p_hosts_path ()}:\n"
            f"    {target_host } = <52 chars>.b32.i2p")

    def _bridge_socket(self, timeout: float) -> "socket.socket":
        """A connected, HELLO'd socket to the LOCAL SAM bridge.

        `sam_host` is the bridge's own address (normally 127.0.0.1). The I2P
        destination never reaches this call or any resolver: it only ever
        travels inside a SAM command on this socket.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(timeout, self.reply_timeout))
        try:
            sock.connect((self.sam_host, self.sam_port))
        except OSError as exc:
            sock.close()
            raise SamError("bridge", "no SAM bridge at %s:%s (%s)"
                           % (self.sam_host, self.sam_port,
                              type(exc).__name__)) from None
        try:
            self._handshake(sock)
        except Exception:
            sock.close()
            raise
        return sock

    def naming_lookup(self, name: str) -> str:
        """`NAMING LOOKUP NAME=<name>` on the router.

        Returns the full base64 destination, or raises SamError("naming",
        ..., RESULT). The reply must name what was asked and carry a
        well-formed destination; anything else is a bridge fault, never a
        destination to connect to."""
        sock = self._bridge_socket(90)
        try:
            reply = self._send_cmd(sock, f"NAMING LOOKUP NAME={name }")
        finally:
            sock.close()
        parsed = self._parse_reply(reply, "NAMING REPLY ")
        result = parsed.get("RESULT", "")
        if result != "OK":
            raise SamError("naming", reply[:200], result or "MISSING")
        if parsed.get("NAME", "").lower() != name.lower():
            raise SamError("bridge", "SAM answered for a different NAME")
        value = parsed.get("VALUE", "")
        if not _I2P_DEST_RE.match(value):
            raise SamError("bridge", "SAM NAMING REPLY carried no valid destination")
        return value

    def _naming_failure(self, target, exc, alias_source=None):
        if exc.stage != "naming":
            return exc
        return SamError("naming", self._explain_resolve_failure(
            target, str(exc), alias_source), exc.result)

    def resolve(self, target_host: str, allow_aliases: bool = True) -> str:
        """The full destination for an .i2p address, from the ROUTER.

        THE NAMING MODEL, and why it is this way round
        ----------------------------------------------
        * `x.b32.i2p` is the hash of the destination and the router resolves
          it from the hash. No address book and no local file is consulted,
          so nothing can redirect an address typed in full.
        * A short `x.i2p` is asked of the router first -- NAMING LOOKUP,
          always. The router's address book is the authority for what a name
          means NOW. The local alias file (Termux) is consulted only when the
          router does not know the name (I2P_NAME_UNKNOWN_RESULTS:
          KEY_NOT_FOUND from Java I2P, INVALID_KEY from i2pd), and its use is
          announced.
          It used to be consulted FIRST, together with a shipped defaults file
          that mapped the project's server name to its old b32. A server
          recreated under that name was therefore never looked up: the name
          was quietly rewritten to the retired destination (Android, device
          report 2026-09-28).
        * The project's own server name (SHIPPED_SERVERS) is the exception:
          it is dialled at its shipped b32 and the router is not asked what
          the name means. An address book that mapped it elsewhere sent the
          app's server list entry to another destination; the b32 can only
          reach the server's own key. The alias file is not consulted for it.
        * A malformed name (refused before anything is sent), a bridge
          fault, or any other result is a clean naming failure. There is no
          fallback to DNS or to anything else: no path in this class hands
          an .i2p name to a system resolver.
        """
        target = (target_host or "").strip().lower()
        problem = i2p_target_error(target)
        if problem:
            raise SamError("naming", f"{target_host !r}: {problem }", "INVALID_NAME")
        if target.endswith(".b32.i2p"):
            moved_to = I2PSAMConnection._retired_destinations().get(target)
            if moved_to:
                print(f"[i2p] {target } is a retired address for {moved_to }; "
                      "trying it as given.")
            try:
                return self.naming_lookup(target)
            except SamError as exc:
                raise self._naming_failure(target, exc) from None
        self.used_shipped_address = False
        shipped = _address.shipped_server_address(target)
        if shipped:
            # Reported by the caller (`used_shipped_address`), which knows
            # whether its log may name the address.
            try:
                dest = self.naming_lookup(shipped)
            except SamError as exc:
                raise self._naming_failure(shipped, exc) from None
            self.used_shipped_address = True
            return dest
        try:
            return self.naming_lookup(target)
        except SamError as exc:
            if not (exc.stage == "naming"
                    and exc.result in I2P_NAME_UNKNOWN_RESULTS):
                raise self._naming_failure(target, exc) from None
            router_reply = exc
        if allow_aliases:
            alias, alias_source = self._apply_i2p_alias(target)
            if alias_source:
                if _I2P_DEST_RE.match(alias):
                    return alias
                try:
                    return self.naming_lookup(alias)
                except SamError as exc:
                    raise self._naming_failure(alias, exc, alias_source) from None
        raise self._naming_failure(target, router_reply) from None

    def session_alive(self) -> bool:
        """Whether this object still holds an open SAM session: the router
        ends one by closing its control connection, which reads as EOF."""
        sock = self._control_sock
        if sock is None or self._abandoned:
            return False
        try:
            sock.setblocking(False)
            try:
                return sock.recv(1, socket.MSG_PEEK) != b""
            except (BlockingIOError, InterruptedError):
                return True
            finally:
                sock.setblocking(True)
        except OSError:
            return False

    def connect(self, target_host: str, target_port: int = 0,
                allow_aliases: bool = True,
                verify_destination=None,
                keep_session: bool = False) -> "socket.socket":
        """Connect to an I2P destination via SAM. Returns a raw socket.

        Creates a transient destination (fresh identity, not saved).
        The port arg is ignored - I2P destinations don't use ports.
        `target_host` is a 52-character .b32.i2p address or a short .i2p
        name; `resolve` says how each becomes a destination. Every failure
        is a SamError naming the stage that failed.

        `verify_destination(dest_b64)`, when given, is called with the
        resolved destination BEFORE any session or stream exists; whatever it
        raises propagates and nothing is sent to that destination. This is
        where the Android bridge enforces its destination pin (X1).

        `keep_session` (Android sign-in retries): when STREAM CONNECT fails,
        the session -- its destination, its built tunnels and what its router
        has learnt about the server -- is kept open, and calling `connect`
        again on this object reuses it instead of starting from nothing.
        Without it, every retry was a brand-new destination that had to build
        tunnels and look the server up again, so retries a few seconds apart
        kept failing the same way. The caller must `close()` it when done.
        """
        dest_b64 = self.resolve(target_host, allow_aliases=allow_aliases)
        if verify_destination is not None:
            verify_destination(dest_b64)

        if not self.session_alive():
            self.close()
            self._session_id = f"otrv4plus_{secrets .token_hex (4 )}"
            self._control_sock = self._bridge_socket(90)
            if self._abandoned:
                self.close()
                raise SamError("cancelled", "the SAM connection was abandoned")
            reply = self._send_cmd(
                self._control_sock,
                f"SESSION CREATE STYLE=STREAM ID={self ._session_id } "
                f"DESTINATION=TRANSIENT SIGNATURE_TYPE=7",
            )
            parsed = self._parse_reply(reply, "SESSION STATUS ")
            if parsed.get("RESULT") != "OK":
                self.close()
                raise SamError("session", f"SAM session failed: {reply[:200] }",
                               parsed.get("RESULT", ""))
            self._our_destination = parsed.get("DESTINATION", "")

        stream_sock = self._bridge_socket(NetworkConstants.TIMEOUT_I2P)
        self._pending_stream = stream_sock
        try:
            reply = self._send_cmd(
                stream_sock,
                f"STREAM CONNECT ID={self ._session_id } " f"DESTINATION={dest_b64 } SILENT=false",
            )
        finally:
            self._pending_stream = None
        if self._abandoned:
            stream_sock.close()
            self.close()
            raise SamError("cancelled", "the SAM connection was abandoned")
        parsed = self._parse_reply(reply, "STREAM STATUS ")
        if parsed.get("RESULT") != "OK":
            stream_sock.close()
            if not keep_session:
                self.close()
            raise SamError("stream",
                           self._explain_stream_failure(target_host, parsed, reply),
                           parsed.get("RESULT", ""))

        stream_sock.settimeout(1.0)
        return stream_sock

    def abandon(self):
        """Give up on a `connect` that another thread is still inside.

        A connect that times out on Android is cancelled, but the thread
        doing the SAM work is not: it went on to finish SESSION CREATE and
        sat in STREAM CONNECT, and the session -- a transient destination
        with its own tunnels -- stayed open in the router for the life of the
        app. Every retry added another. Closing the sockets here ends the
        session in the router and wakes the blocked thread; the flag stops a
        step that was already past its socket from opening a new one.
        """
        self._abandoned = True
        # shutdown before close: on Linux, close() from another thread does
        # not wake a recv() blocked on the same socket; shutdown() does.
        for sock in (self._pending_stream, self._control_sock):
            if sock is None:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
        self.close()

    def close(self):
        """Close the SAM control session."""
        try:
            if self._control_sock:
                self._control_sock.close()
                self._control_sock = None
        except Exception:
            pass
        self._our_destination = None

    @staticmethod
    def is_available(host: str = None, port: int = None) -> bool:
        """Check if SAM bridge is reachable and speaking SAM v3.1."""
        host = host or NetworkConstants.I2P_SAM_HOST
        port = port or NetworkConstants.I2P_SAM_PORT
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.sendall(b"HELLO VERSION MIN=3.1 MAX=3.1\n")
            reply = sock.recv(256)
            sock.close()
            return b"RESULT=OK" in reply
        except Exception:
            return False


class BinaryReader:
    """Safe structured binary parser with strict bounds checking and specific exceptions."""

    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {type (data )}")
        self.data = data
        self.offset = 0
        self.length = len(data)

    def remaining(self) -> int:
        return self.length - self.offset

    def ensure(self, needed: int) -> None:
        """Ensure at least needed bytes remain."""
        remaining = self.remaining()
        if remaining < needed:
            raise ValueError(f"Truncated: need {needed } bytes, have {remaining }")

    def read_uint8(self) -> int:
        try:
            self.ensure(1)
            val = self.data[self.offset]
            self.offset += 1
            return val
        except IndexError as e:
            raise ValueError(f"Failed to read uint8: {e }")
        except ValueError:
            # Truncation is EXPECTED on untrusted input. ensure() raises
            # ValueError; the bare `except Exception` below would convert it
            # to RuntimeError, which decode() does not catch and no caller
            # expects. read_bytes() already re-raises; the integer readers
            # must behave identically or a short header escapes as an
            # "unexpected error" instead of a clean parse failure.
            raise
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint8: {e }")

    def read_uint16(self) -> int:
        try:
            self.ensure(2)
            val = struct.unpack(">H", self.data[self.offset : self.offset + 2])[0]
            self.offset += 2
            return val
        except struct.error as e:
            raise ValueError(f"Failed to unpack uint16: {e }")
        except ValueError:
            raise  # truncation: see read_uint8
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint16: {e }")

    def read_uint32(self) -> int:
        try:
            self.ensure(4)
            val = struct.unpack(">I", self.data[self.offset : self.offset + 4])[0]
            self.offset += 4
            return val
        except struct.error as e:
            raise ValueError(f"Failed to unpack uint32: {e }")
        except ValueError:
            raise  # truncation: see read_uint8
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint32: {e }")

    def read_uint64(self) -> int:
        try:
            self.ensure(8)
            val = struct.unpack(">Q", self.data[self.offset : self.offset + 8])[0]
            self.offset += 8
            return val
        except struct.error as e:
            raise ValueError(f"Failed to unpack uint64: {e }")
        except ValueError:
            raise  # truncation: see read_uint8
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint64: {e }")

    def read_bytes(self, length: int) -> bytes:
        try:
            if length < 0:
                raise ValueError(f"Negative length: {length }")
            self.ensure(length)
            val = self.data[self.offset : self.offset + length]
            self.offset += length
            return val
        except IndexError as e:
            raise ValueError(f"Failed to read {length } bytes: {e }")
        except ValueError:
            # Truncation is an EXPECTED condition on untrusted input, not an
            # internal error. ensure() raises ValueError; the bare `except
            # Exception` below used to convert it to RuntimeError, which
            # OTRv4DataMessage.decode does not catch — so a short message
            # escaped as "Unexpected error" instead of a clean parse failure.
            raise
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading bytes: {e }")

    def read_mpi(self) -> bytes:
        """Read MPI: uint32 length followed by bytes."""
        try:
            length = self.read_uint32()
            if length == 0:
                return b""
            if length > 1024 * 1024:
                raise ValueError(f"MPI too large: {length }")
            return self.read_bytes(length)
        except ValueError as e:
            raise ValueError(f"Invalid MPI: {e }")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading MPI: {e }")

    def read_varbytes(self) -> bytes:
        """Read varbytes: uint32 length followed by bytes."""
        return self.read_mpi()

    def expect_end(self) -> None:
        """Ensure no trailing bytes remain."""
        if self.offset != self.length:
            raise ValueError(f"Trailing bytes: {self .length -self .offset } remaining")


def _generate_instance_tag() -> int:
    """Random 32-bit instance tag in [0x100, 0xFFFFFFFF] per OTRv4 spec §4.1.

    Two independent CSPRNG reads XOR'd together. Output is at least as strong
    as the stronger source even if one RNG is compromised.
    """
    while True:
        a = int.from_bytes(secrets.token_bytes(4), "big")
        b = int.from_bytes(os.urandom(4), "big")
        tag = a ^ b
        if 0x100 <= tag <= 0xFFFFFFFF:
            return tag


SMP_VERSION_MISMATCH_HELP = (
    "⚠ SMP stopped: version mismatch. The two devices are running different "
    "OTRv4+ builds, so they derive different secrets from the same "
    "passphrase.\n"
    "   This is NOT a wrong passphrase. Update both devices to the same "
    "version (git pull, then rebuild the Rust core) and run  /smp start  "
    "again."
)


def _is_smp_version_mismatch(exc: BaseException) -> bool:
    """Recognise the Rust core's SMP version-mismatch abort.

    Matched on the error text because PyO3 raises it as a plain ValueError.
    Kept deliberately narrow: this only changes which local help line is
    printed, never whether anything is trusted or verified.
    """
    return "version mismatch" in str(exc).lower()


#: Handlers for the non-protocol TLV types, keyed by type.
#:
#: The engine routes DISCONNECTED, the SMP types and EXTRA_SYMMETRIC_KEY
#: itself; anything else is a feature, and a feature does not belong in the
#: session state machine.  A client registers here and gets called with
#: `(peer, value)` for its type, on any session, once the payload has been
#: decrypted and authenticated.
#:
#: Deliberately NOT a general extension point.  `register_tlv_handler`
#: refuses any type outside `_HANDLER_TLV_TYPES`, so this cannot become the
#: way arbitrary protocol gets bolted onto a session -- which is how a
#: forwarding hook turns into an unreviewed second protocol.
_TLV_HANDLERS: Dict[int, Callable[[str, bytes], None]] = {}

#: The only types a client may register for: TIP (0x0020) and MESSAGE_META
#: (0x0021, ids/corrections/deletions/reactions/replies -- otrv4plus_actions).
_HANDLER_TLV_TYPES = frozenset({0x0020, 0x0021})


def register_tlv_handler(tlv_type: int, handler: Callable[[str, bytes], None]) -> None:
    """Route inbound TLVs of `tlv_type` to `handler(peer, value)`.

    Raises for a type the engine owns, or one nobody has thought about.
    """
    if tlv_type not in _HANDLER_TLV_TYPES:
        raise ValueError(
            "TLV type 0x%04x is not open to handlers (allowed: %s)"
            % (tlv_type, ", ".join("0x%04x" % t
                                   for t in sorted(_HANDLER_TLV_TYPES))))
    _TLV_HANDLERS[tlv_type] = handler


def clear_tlv_handlers() -> None:
    """Drop every registered handler.  For teardown and for tests."""
    _TLV_HANDLERS.clear()


class OTRv4TLV:
    """Single TLV (Type-Length-Value) record inside an OTRv4 encrypted message.

    Wire format:  uint16 type  |  uint16 length  |  byte[length] value
    All multi-byte fields are big-endian (network byte order).

    TLV type 0x0000 (PADDING) MUST be silently discarded by receivers.
    Unknown TLV types MUST be silently ignored (forward compatibility).
    """

    __slots__ = ("type", "value")

    PADDING = 0x0000
    DISCONNECTED = 0x0001
    SMP_MSG_1 = 0x0002
    SMP_MSG_2 = 0x0003
    SMP_MSG_3 = 0x0004
    SMP_MSG_4 = 0x0005
    SMP_ABORT = 0x0006
    SMP_MSG_1Q = 0x0007
    EXTRA_SYMMETRIC_KEY = 0x0009

    #: v10.21.0: /tip -- a Monero address relayed between two SMP-verified
    #: peers.  Above the OTRv4-allocated range (0x0000-0x0009) so it cannot
    #: collide with a future spec type, and forward-compatible by the rule at
    #: the top of this class: a peer that does not know it ignores it.
    TIP = 0x0020

    #: rc.65: MESSAGE META -- the id of a typed message, and what it does to
    #: an earlier one (a correction, a deletion for everyone, a reaction, a
    #: reply), carried INSIDE the encrypted, authenticated payload so the
    #: server can neither forge nor redirect them. Same forward-compatibility
    #: rule: an older peer ignores it and shows the text, if any.
    MESSAGE_META = 0x0021

    SMP_TYPES = frozenset({SMP_MSG_1, SMP_MSG_2, SMP_MSG_3, SMP_MSG_4, SMP_ABORT, SMP_MSG_1Q})

    # Optional SMP_ABORT payload naming WHY the abort happened.
    #
    # The TLV payload was always empty and receivers ignored it, so adding a
    # reason is additive: an older peer drops it exactly as before. It exists
    # because "aborted" collapsed three different situations into one message
    # -- the peer has no secret configured, the peer has the wrong secret, or
    # something genuinely failed -- and only the first is fixed by the user
    # typing a command.
    #
    # It is a DIAGNOSTIC, never a predicate. Nothing branches on it beyond the
    # wording of a line printed locally: it is attacker-controlled text like
    # any other field a peer sends.
    SMP_ABORT_NO_SECRET = b"NOSECRET"

    # The user was asked and said no.  Distinct from NOSECRET, which means
    # nobody was asked because nothing was configured.  Same rules apply: a
    # diagnostic that chooses local wording, never a security predicate.
    SMP_ABORT_DECLINED = b"DECLINED"

    def __init__(self, tlv_type: int, value: bytes = b""):
        if not (0 <= tlv_type <= 0xFFFF):
            raise ValueError(f"TLV type out of range: {tlv_type :#06x}")
        if len(value) > 65535:
            raise ValueError(f"TLV value too large: {len (value )} bytes (max 65535)")
        self.type = tlv_type
        self.value = bytes(value)

    def encode(self) -> bytes:
        """Serialize to wire bytes: uint16 type + uint16 length + value."""
        return struct.pack("!HH", self.type, len(self.value)) + self.value

    @classmethod
    def decode_one(cls, data: bytes, offset: int = 0) -> Tuple["OTRv4TLV", int]:
        """Decode one TLV from *data* at *offset*.  Returns (tlv, next_offset).

        Raises ValueError on truncated or malformed input.
        """
        if offset + 4 > len(data):
            raise ValueError(
                f"TLV header truncated at offset {offset } " f"(need 4, have {len (data )-offset })"
            )
        tlv_type, length = struct.unpack_from("!HH", data, offset)
        end = offset + 4 + length
        if end > len(data):
            raise ValueError(
                f"TLV value truncated: type=0x{tlv_type :04x} "
                f"declares {length } bytes but only {len (data )-offset -4 } available"
            )
        return cls(tlv_type, data[offset + 4 : end]), end

    @classmethod
    def decode_all(cls, data: bytes) -> List["OTRv4TLV"]:
        """Decode all TLVs from *data*.  Raises ValueError on malformed stream."""
        tlvs: List["OTRv4TLV"] = []
        offset = 0
        while offset < len(data):
            tlv, offset = cls.decode_one(data, offset)
            tlvs.append(tlv)
        return tlvs

    @classmethod
    def encode_all(cls, tlvs: List["OTRv4TLV"]) -> bytes:
        return b"".join(t.encode() for t in tlvs)

    @classmethod
    def random_padding(cls, min_bytes: int = 8, max_bytes: int = 72) -> "OTRv4TLV":
        """Create a PADDING TLV with random content for traffic analysis resistance."""
        pad_len = secrets.randbelow(max_bytes - min_bytes + 1) + min_bytes
        return cls(cls.PADDING, os.urandom(pad_len))

    def __repr__(self) -> str:
        _NAMES = {
            0: "PADDING",
            1: "DISCONNECTED",
            2: "SMP_MSG_1",
            3: "SMP_MSG_2",
            4: "SMP_MSG_3",
            5: "SMP_MSG_4",
            6: "SMP_ABORT",
            7: "SMP_MSG_1Q",
            8: "EXTRA_SYMMETRIC_KEY",
            0x0020: "TIP",
        }
        name = _NAMES.get(self.type, f"UNKNOWN(0x{self .type :04x})")
        return f"OTRv4TLV({name }, {len (self .value )} bytes)"


class OTRv4Payload:
    """Encodes / decodes the cleartext payload inside an OTRv4 DATA message.

    Per spec §4.4.3 the decrypted payload has the structure:
        human_readable_message  (UTF-8, may be empty)
        0x00                    (NULL separator - only present when TLVs follow)
        TLV*                    (zero or more TLV records)

    PADDING TLVs (type 0x0000) in received messages are silently discarded.
    Unknown TLV types are silently ignored (forward compatibility per spec).
    """

    __slots__ = ("text", "tlvs")

    def __init__(self, text: str = "", tlvs: Optional[List["OTRv4TLV"]] = None):
        self.text = text or ""
        self.tlvs: List[OTRv4TLV] = list(tlvs) if tlvs else []

    def encode(self, add_padding: bool = True) -> bytes:
        """Encode to bytes for encryption.

        If *add_padding* is True (default), appends a random PADDING TLV to
        resist traffic-analysis attacks by blurring plaintext length.
        """
        text_bytes = self.text.encode("utf-8") if self.text else b""
        tlvs = list(self.tlvs)
        if add_padding:
            tlvs.append(OTRv4TLV.random_padding())
        if tlvs:
            return text_bytes + b"\x00" + OTRv4TLV.encode_all(tlvs)
        return text_bytes

    @classmethod
    def decode(cls, data: bytes) -> "OTRv4Payload":
        """Decode from decrypted bytes.  PADDING TLVs are silently dropped."""
        null_pos = data.find(b"\x00")
        if null_pos == -1:
            return cls(data.decode("utf-8", errors="replace"), [])

        text = data[:null_pos].decode("utf-8", errors="replace")
        tlv_bytes = data[null_pos + 1 :]

        if not tlv_bytes:
            return cls(text, [])

        all_tlvs = OTRv4TLV.decode_all(tlv_bytes)
        non_padding = [t for t in all_tlvs if t.type != OTRv4TLV.PADDING]
        return cls(text, non_padding)


class OTRv4DataMessage:
    """OTRv4 DATA message wire format (spec §4.4.3)."""

    # OTRv4+ data-message wire revision.
    #
    # 0x0004 -> 0x0005 (C1): the MKmac fix changed this message's wire
    # behaviour in two incompatible ways.
    #
    #   1. The MAC value differs. MKmac is now KDF(0x14, MKenc, 64) per OTRv4
    #      4.4.2, replacing sha3_512(session_id || ratchet_id || msg_num). Same
    #      field, same offset, different value.
    #   2. REVEALED_MAC_KEY_LEN widened 32 -> 64, changing the byte layout of
    #      any message carrying revealed keys.
    #
    # Both ends must run the same revision. The version field is read and
    # checked in decode() before any key material is touched, so a mismatch
    # surfaces as ProtocolVersionError rather than as a MAC failure.
    #
    # Only THIS layer is incremented. The ClientProfile/DAKE format did not
    # change, so OTRConstants.PROTOCOL_VERSION stays at 4 -- bumping it would
    # falsely signal a handshake change and invalidate profiles needlessly.
    PROTOCOL_VERSION = 0x0005
    TYPE = 0x03
    ECDH_LEN = 56
    NONCE_LEN = 12
    MAC_LEN = 64
    REVEALED_MAC_KEY_LEN = 64   # OTRv4 §4.4.2 MKmac
    FLAG_IGNORE_UNREADABLE = 0x01

    def __init__(self):
        self.sender_tag: int = 0
        self.receiver_tag: int = 0
        self.flags: int = 0
        self.prev_chain_len: int = 0
        self.ratchet_id: int = 0
        self.message_id: int = 0
        self.ecdh_pub: bytes = b""
        self.dh_pub: Optional[bytes] = None
        self.kem_ek: Optional[bytes] = None
        self.kem_ct: Optional[bytes] = None
        self.nonce: bytes = b""
        self.ciphertext: bytes = b""
        self.mac: bytes = b""
        self.revealed_mac_keys: List[bytes] = []
        #: L1: the encoded field exactly as the Rust ratchet produced it
        #: (uint32 count || keys). Set on send, so the retired keys never
        #: exist in Python as a list of key objects; wins over the list.
        self.revealed_field: Optional[bytes] = None

    #: Keys one message may carry: the decoder's limit (and Rust's
    #: REVEAL_FIELD_MAX).
    MAX_REVEALED_KEYS = 2000

    @classmethod
    def check_revealed_field(cls, field: bytes) -> bytes:
        """`field` is a well-formed revealed_mac_keys field, or ValueError."""
        if len(field) < 4:
            raise ValueError("revealed-key field shorter than its count")
        n = struct.unpack("!I", field[:4])[0]
        if n > cls.MAX_REVEALED_KEYS or len(field) != 4 + n * cls.REVEALED_MAC_KEY_LEN:
            raise ValueError("revealed-key field does not match its count")
        return bytes(field)

    @classmethod
    def parse_revealed_field(cls, field: bytes) -> List[bytes]:
        """The keys a field publishes, as any third party reads them off the
        wire. Public data: used by tests and by a verifier, never on send."""
        cls.check_revealed_field(field)
        n = struct.unpack("!I", field[:4])[0]
        size = cls.REVEALED_MAC_KEY_LEN
        return [bytes(field[4 + i * size:4 + (i + 1) * size]) for i in range(n)]

    def _auth_header(self) -> bytes:
        """Bytes from protocol version through nonce (the authenticatable region)."""
        try:
            if len(self.ecdh_pub) != self.ECDH_LEN:
                raise ValueError(f"ECDH key must be {self .ECDH_LEN } bytes")
            if len(self.nonce) != self.NONCE_LEN:
                raise ValueError(f"Nonce must be {self .NONCE_LEN } bytes")
            buf = bytearray()
            buf += struct.pack("!HB", self.PROTOCOL_VERSION, self.TYPE)
            buf += struct.pack("!II", self.sender_tag, self.receiver_tag)
            buf += struct.pack("!B", self.flags)
            buf += struct.pack("!III", self.prev_chain_len, self.ratchet_id, self.message_id)
            buf += self.ecdh_pub
            if self.dh_pub is not None:
                if len(self.dh_pub) != self.ECDH_LEN:
                    raise ValueError(f"DH key must be {self .ECDH_LEN } bytes")
                buf += b"\x01" + self.dh_pub
            else:
                buf += b"\x00"

            if self.kem_ek is not None:
                if len(self.kem_ek) != MLKEM1024BraceKEM.EK_BYTES:
                    raise ValueError(f"KEM ek must be {MLKEM1024BraceKEM .EK_BYTES } bytes")
                buf += b"\x01" + self.kem_ek
            else:
                buf += b"\x00"
            if self.kem_ct is not None:
                if len(self.kem_ct) != MLKEM1024BraceKEM.CT_BYTES:
                    raise ValueError(f"KEM ct must be {MLKEM1024BraceKEM .CT_BYTES } bytes")
                buf += b"\x01" + self.kem_ct
            else:
                buf += b"\x00"
            buf += self.nonce
            return bytes(buf)
        except (struct.error, TypeError, ValueError) as e:
            raise ValueError(f"Failed to build auth header: {e }")

    def auth_region(self) -> bytes:
        """The public bytes the outer MAC covers:
        auth_header || uint32(len(ciphertext)) || ciphertext."""
        try:
            ah = self._auth_header()
            return ah + struct.pack("!I", len(self.ciphertext)) + self.ciphertext
        except (TypeError, ValueError, struct.error) as e:
            raise ValueError(f"Failed to build MAC region: {e }")

    def compute_mac(self, mac_key) -> bytes:
        """SHA3-512(MKmac || auth_region), computed in Rust.

        `mac_key` is the ratchet's `MessageMacKey` handle: the key stays in
        Rust, and this only frames the public region it covers.
        """
        return bytes(mac_key.seal(self.auth_region()))

    def verify_mac(self, mac_key) -> bool:
        """Constant-time MAC check, in Rust, against the `MessageMacKey`."""
        try:
            if len(self.mac) != self.MAC_LEN:
                return False
            return bool(mac_key.verify(self.auth_region(), self.mac))
        except (TypeError, ValueError, AttributeError) as e:
            if DEBUG_MODE:
                print("[OTRv4DataMessage] MAC verification failed")
            return False
        except Exception:
            return False

    def encode(self) -> bytes:
        """Encode the complete DATA message to bytes for base64 transport."""
        try:
            ah = self._auth_header()
            ct_blk = struct.pack("!I", len(self.ciphertext)) + self.ciphertext
            mac = self.mac if len(self.mac) == self.MAC_LEN else b"\x00" * self.MAC_LEN
            if self.revealed_field is not None:
                return ah + ct_blk + mac + self.check_revealed_field(self.revealed_field)
            keys = struct.pack("!I", len(self.revealed_mac_keys))
            for k in self.revealed_mac_keys:
                # L1: 64 bytes per OTRv4 §4.4.2. Was 32, which silently
                # dropped every spec-sized key the engine produced.
                if len(k) != self.REVEALED_MAC_KEY_LEN:
                    raise ValueError(
                        f"Revealed MAC key must be {self .REVEALED_MAC_KEY_LEN } "
                        f"bytes, got {len (k )}")
                keys += k
            return ah + ct_blk + mac + keys
        except (struct.error, TypeError, ValueError) as e:
            raise ValueError(f"Failed to encode message: {e }")

    @classmethod
    def looks_like_data_frame(cls, decoded: bytes) -> bool:
        """True if `decoded` begins with this build's data-message header.

        Five call sites used to sniff the first three bytes as the literals
        0x00, 0x04, TYPE. When C1 moved PROTOCOL_VERSION from 0x0004 to
        0x0005 the encoder started emitting 00 05 03 and every one of those
        checks silently stopped matching -- so an encrypted data message fell
        through to the message-type branch, matched nothing, and was dropped
        with "unknown message type: 0" and no error to the user. SMP was the
        first thing to hit it because SMP is the first data message a session
        sends. Grepping for PROTOCOL_VERSION did not find them, because none
        of them referenced it.

        Deriving the bytes from the constant is what stops that recurring: a
        future revision changes one number and every classifier follows.
        """
        if len(decoded) < 3:
            return False
        return (decoded[0] == (cls.PROTOCOL_VERSION >> 8)
                and decoded[1] == (cls.PROTOCOL_VERSION & 0xFF)
                and decoded[2] == cls.TYPE)

    @classmethod
    def decode(cls, data: bytes) -> "OTRv4DataMessage":
        """Decode raw bytes into an OTRv4DataMessage.  Raises ValueError on errors."""
        try:
            r = BinaryReader(data)
            msg = cls()

            ver = r.read_uint16()
            if ver != cls.PROTOCOL_VERSION:
                # Checked before anything reads key material, so a mismatched
                # peer never reaches MAC verification and is never reported as
                # a forgery. Strict equality: no downgrade is accepted and the
                # pre-0x0005 MAC construction is never evaluated.
                raise ProtocolVersionError(
                    f"OTRv4+ wire revision mismatch: peer sent 0x{ver :04x}, "
                    f"this build speaks 0x{cls .PROTOCOL_VERSION :04x}. "
                    f"This is a version mismatch, NOT a forgery or replay. "
                    f"Both endpoints must run the same build."
                )
            mtype = r.read_uint8()
            if mtype != cls.TYPE:
                raise ValueError(
                    f"Wrong message type: 0x{mtype :02x} (expected 0x{cls .TYPE :02x})"
                )

            msg.sender_tag = r.read_uint32()
            msg.receiver_tag = r.read_uint32()
            msg.flags = r.read_uint8()
            msg.prev_chain_len = r.read_uint32()
            msg.ratchet_id = r.read_uint32()
            msg.message_id = r.read_uint32()
            msg.ecdh_pub = r.read_bytes(cls.ECDH_LEN)

            dh_flag = r.read_uint8()
            if dh_flag == 0x01:
                msg.dh_pub = r.read_bytes(cls.ECDH_LEN)
            elif dh_flag != 0x00:
                raise ValueError(f"Invalid DH flag byte: 0x{dh_flag :02x}")

            kem_ek_flag = r.read_uint8()
            if kem_ek_flag == 0x01:
                msg.kem_ek = r.read_bytes(MLKEM1024BraceKEM.EK_BYTES)
            elif kem_ek_flag != 0x00:
                raise ValueError(f"Invalid KEM ek flag: 0x{kem_ek_flag :02x}")

            kem_ct_flag = r.read_uint8()
            if kem_ct_flag == 0x01:
                msg.kem_ct = r.read_bytes(MLKEM1024BraceKEM.CT_BYTES)
            elif kem_ct_flag != 0x00:
                raise ValueError(f"Invalid KEM ct flag: 0x{kem_ct_flag :02x}")

            msg.nonce = r.read_bytes(cls.NONCE_LEN)
            ct_len = r.read_uint32()
            msg.ciphertext = r.read_bytes(ct_len)
            msg.mac = r.read_bytes(cls.MAC_LEN)

            num_keys = r.read_uint32()
            if num_keys > 2000:
                raise ValueError(f"Implausible revealed key count: {num_keys }")
            for _ in range(num_keys):
                msg.revealed_mac_keys.append(
                    r.read_bytes(cls.REVEALED_MAC_KEY_LEN))

            return msg
        except ProtocolVersionError:
            # C1: must NOT be re-wrapped. The whole point of the typed error is
            # that a caller can tell a wire-revision mismatch from a
            # cryptographic failure; flattening it back to a generic ValueError
            # here would restore exactly the ambiguity it exists to remove.
            raise
        except (ValueError, struct.error, TypeError) as e:
            raise ValueError(f"Failed to decode message: {e }")


VERSION = "OTRv4+ 10.31.0"

#: SMP passphrase length bounds, shared by both clients.
#:
#: They lived in otrv4plus_xmpp.py only, so the IRC client had no bounds at
#: all -- it took whatever was typed.  Defined here because the engine is
#: what both clients import, and two clients disagreeing about how long a
#: shared secret may be is a way for one side to store something the other
#: will refuse.
SMP_MIN_LEN = 8
SMP_MAX_LEN = 512

#: Every timestamp the client puts on screen.  Was "%H:%M:%S", which is
#: unreadable in a log kept overnight or across a reconnect: "02:14:07" does
#: not say whether it is this session or yesterday's, which is exactly the
#: question when the buffer has replayed something old at you.  One constant,
#: not four copies, so the next change is one edit.
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# --- OTRv4+ client identification over IRC -------------------------------
#
# CTCP VERSION is deliberately refused (see _CTCP_BLOCKED), so the realname
# ("gecos") field sent in the USER registration line is this client's only
# identification channel.  The server relays it verbatim in RPL_WHOREPLY
# (352) and RPL_WHOISUSER (311), which is where /names picks it up.
#
# THIS IS SELF-ASSERTED AND IS NOT AUTHENTICATION.  Any IRC user can put the
# tag plus a version in their own gecos; the server does not check it and
# neither can we.  It answers "is this peer likely to understand /otr" and
# nothing else.  It MUST NOT gate encryption, mark a peer trusted, satisfy
# TOFU, stand in for SMP verification, or enable voice -- see INV-20 and
# SECURITY.md.  The blue marker in /names is a hint about which peers are
# worth starting a DAKE with, and the DAKE is what authenticates them.
OTRV4_CLIENT_TAG = "OTRv4+"

# Matches the tag followed by a dotted version, as real_name() emits it.  A
# bare substring test would also fire on "I don't use OTRv4+" typed into a
# gecos, which is a lower bar than the format this project actually
# advertises.  Still trivially forgeable -- see above.
_OTRV4_CLIENT_RE = re.compile(r"OTRv4\+[ \t]+(\d+(?:\.\d+)+)")


def otrv4_client_version(realname: Optional[str]) -> Optional[str]:
    """Return the OTRv4+ version a realname advertises, or None.

    The value is remote-controlled text.  It is safe to display (callers
    sanitise it) and unsafe to believe.
    """
    if not realname:
        return None
    m = _OTRV4_CLIENT_RE.search(realname)
    return m.group(1) if m else None


def advertises_otrv4(realname: Optional[str]) -> bool:
    """Whether a realname claims to be an OTRv4+ client.  Not authentication."""
    return otrv4_client_version(realname) is not None


# IRC prefixes carried in RPL_NAMREPLY.  "multi-prefix" is negotiated (see
# IRCV3_CAPS), so a nick can arrive as "@+nick" with several of them.
NAMES_PREFIXES = "~&@%+"
_NAMES_OP_PREFIXES = "~&@"
_NAMES_VOICE_PREFIXES = "%+"


def split_names_entry(entry: str) -> Tuple[str, str]:
    """Split one RPL_NAMREPLY entry into (prefixes, nick).

    Returns ("", "") for anything that is not a usable entry, so a malformed
    or hostile NAMES line drops the entry rather than the whole render.
    """
    if not entry:
        return "", ""
    i = 0
    while i < len(entry) and entry[i] in NAMES_PREFIXES:
        i += 1
    prefixes, nick = entry[:i], entry[i:]
    if not nick or any(c in nick for c in " \r\n\x00"):
        return "", ""
    return prefixes, nick


def format_names_list(entries, otrv4_map=None, total=None, width=56,
                      selectable=False):
    """Render a channel user list.  Pure: builds lines, prints nothing.

    `entries` are raw RPL_NAMREPLY tokens ("@alice", "+bob", "carol").
    `otrv4_map` maps nick -> truthy when that nick's realname advertised
    OTRv4+ in RPL_WHOREPLY.  `total` is the server's count, which may exceed
    the number of entries when the local list was capped.

    OTRv4+ users are marked with a blue bullet and listed first within their
    privilege group.  The marker is CLIENT IDENTIFICATION ONLY -- see
    otrv4_client_version() for why it is not, and cannot be, authentication.

    With `selectable`, the first nine OTRv4+ nicks are numbered and returned
    alongside the lines as (lines, picks) so the pager can offer /otr on a
    keypress.  Without it, a bare list of lines is returned.
    """
    otrv4_map = otrv4_map or {}
    ops, voiced, regular = [], [], []
    seen = set()
    for entry in entries or []:
        prefixes, nick = split_names_entry(entry)
        if not nick or nick in seen:
            continue
        seen.add(nick)
        shown = prefixes[:1]
        if any(c in _NAMES_OP_PREFIXES for c in prefixes):
            ops.append((shown, nick))
        elif any(c in _NAMES_VOICE_PREFIXES for c in prefixes):
            voiced.append((shown, nick))
        else:
            regular.append((shown, nick))

    # OTRv4+ first, then alphabetical, so the actionable names are together
    # at the top of each group rather than scattered through it.
    def _order(group):
        group.sort(key=lambda pn: (not bool(otrv4_map.get(pn[1])), pn[1].lower()))

    for group in (ops, voiced, regular):
        _order(group)

    listed = ops + voiced + regular
    otr_count = sum(1 for _, nick in listed if otrv4_map.get(nick))
    shown_count = len(listed)
    if total is None:
        total = shown_count
    other = max(0, total - otr_count)

    picks = [nick for _, nick in listed if otrv4_map.get(nick)][:9] if selectable else []
    pick_index = {nick: i + 1 for i, nick in enumerate(picks)}

    lines = []
    summary = (
        colorize(f"\U0001F535 {otr_count } OTRv4+", "blue")
        + colorize("   \u2022   ", "dim")
        + colorize(f"{other } other client(s)", "white")
    )
    lines.append(summary)
    if otr_count:
        lines.append(
            colorize("  blue = advertises OTRv4+ in its realname; "
                     "identification only, not verified", "dim")
        )
        if picks:
            lines.append(
                colorize("  press 1-%d to /otr that user, or /otr <nick>"
                         % len(picks), "dim")
            )
        else:
            lines.append(colorize("  /otr <nick> starts an encrypted session", "dim"))
    if total > shown_count:
        lines.append(
            colorize(
                f"  \u26a0 {total } users in channel \u2014 showing the first {shown_count }",
                "yellow",
            )
        )
    lines.append("")

    col_width = 20
    cols = max(1, width // col_width)

    def _group(label, members, color):
        if not members:
            return
        lines.append(colorize(f"  {label } ({len (members )}):", color))
        row = []
        for prefix, nick in members:
            disp = _sanitise(f"{prefix }{nick }", col_width - 3)
            if otrv4_map.get(nick):
                n = pick_index.get(nick)
                tag = f"\U0001F535{n }" if n else "\U0001F535 "
                cell = colorize(f"{tag }{disp :<{col_width -3 }}", "blue")
            else:
                cell = colorize(f"   {disp :<{col_width -3 }}", color)
            row.append(cell)
            if len(row) >= cols:
                lines.append("".join(row))
                row = []
        if row:
            lines.append("".join(row))

    _group("Operators", ops, "bold_green")
    _group("Voiced", voiced, "yellow")
    _group("Users", regular, "white")

    if not listed:
        lines.append(colorize("  (no users reported)", "dim"))
    return (lines, picks) if selectable else lines

if not hasattr(hashlib, "sha3_512"):
    raise RuntimeError(
        "FATAL: SHA3-512 is required by OTRv4 §3.2 but is unavailable in "
        "this Python build.  Please upgrade to Python ≥ 3.6 with SHA3 support."
    )
DEBUG_MODE = "--debug" in sys.argv or "-d" in sys.argv
SMP_DEBUG = DEBUG_MODE or "--smp-debug" in sys.argv
TEST_MODE = "--test" in sys.argv

global IS_TERMUX
IS_TERMUX = "ANDROID_ROOT" in os.environ or "TERMUX_VERSION" in os.environ

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
    Prevents terminal escape injection and OSC title-hijack from malicious
    servers or peers.

    Strips (in order):
      1. OSC/DCS/PM/APC sequences  \x1b[P]X^_] ... (BEL or ST terminator)
      2. CSI sequences              \x1b[ ... final-byte
      3. Two-char Fe escapes        \x1b <any single char>
      4. mIRC/IRC colour codes      \x03 [fg[,bg]] … \x03
      5. Remaining C0/C1 controls   (\x00-\x1f, \x7f, \x80-\x9f)
    """

    text = re.sub(r"\x1b[P\]X\^_][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)

    text = re.sub(r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]", "", text)

    text = re.sub(r"\x1b[\x20-\x2f][\x30-\x7e]", "", text)

    text = re.sub(r"\x1b.", "", text, flags=re.DOTALL)

    text = re.sub(r"\x03(?:\d{1,2}(?:,\d{1,2})?)?", "", text)

    text = re.sub(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f\x80-\x9f]", "", text)
    return text[:max_len]


def _redact_secret(text: str, secret) -> str:
    """Remove *secret* from *text* wherever a diagnostic might carry it.

    Used on the one path where an error is reported while the passphrase is
    still in scope.  Nothing on that path is known to quote its argument --
    the storage and vault calls raise fixed messages -- but "known" is a
    property of today's code and this is the line where a future exception
    with a helpful repr would put a shared secret on the user's screen and
    into their scrollback.

    Redacts the passphrase and, for a `bytes` secret, its decoded form: a
    Python exception that formats a bytearray prints `bytearray(b'...')`, so
    matching only the exact object would miss it.  Short values are NOT
    redacted below SMP_MIN_LEN, because blanking every occurrence of a
    two-character string would corrupt unrelated text without protecting
    anything -- a passphrase that short is refused before it reaches here.
    """
    if not text or not secret:
        return text
    needles = []
    if isinstance(secret, (bytes, bytearray)):
        needles.append(secret.decode("utf-8", errors="replace"))
    else:
        needles.append(str(secret))
    for needle in needles:
        if len(needle) < SMP_MIN_LEN:
            continue
        text = text.replace(needle, "[redacted]")
    return text


def colorize(text: str, color: str) -> str:
    """Colorize text with ANSI colors"""
    return f"{UIConstants .COLORS .get (color ,'')}{text }{UIConstants .COLORS ['reset']}"


def colorize_username(username: str) -> str:
    """Colorize username - FNV-1a hash for colour, italic for server/bot nicks.

    Rules matching the screenshot aesthetic:
      - IRC server names (contain a '.') → dim italic dark_cyan
      - Service bots (ChanServ, NickServ, etc.) → dim italic dark_magenta
      - Normal users → one of 12 bright colours based on FNV-1a hash
    """
    if not username:
        return ""

    username = _sanitise(username, 64)
    if not username:
        return ""
    R = UIConstants.COLORS["reset"]
    DI = UIConstants.COLORS["dim_italic"]
    if "." in username and not username.startswith("#"):
        return f"{DI }{UIConstants .COLORS ['dark_cyan']}{username }{R }"
    _services = (
        "chanserv",
        "nickserv",
        "memoserv",
        "operserv",
        "botserv",
        "hostserv",
        "groupserv",
        "global",
        "alis",
    )
    if username.lower() in _services:
        return f"{DI }{UIConstants .COLORS ['dark_magenta']}{username }{R }"
    h = 2166136261
    for c in username:
        h = ((h ^ ord(c)) * 16777619) & 0xFFFFFFFF
    color = UIConstants.USERNAME_COLORS[h % len(UIConstants.USERNAME_COLORS)]
    return colorize(username, color)


_print_lock = threading.Lock()

_current_prompt: str = ""

_input_buffer: List[str] = []

#: Render the input line as dots instead of characters.
#:
#: The SMP passphrase is a shared secret and was being echoed like any
#: command: onto the terminal, into scrollback, and into any `script` capture
#: of the session. It reached a bug report that way. Set while a passphrase is
#: being typed; every redraw path below asks _display_buffer() rather than
#: joining the buffer itself, so a new redraw site cannot quietly leak it.
_mask_input: bool = False


def set_input_mask(on: bool) -> None:
    """Hide or show what is typed on the input line."""
    global _mask_input
    _mask_input = bool(on)


def _display_buffer() -> str:
    """What the input line should SHOW. Never what it should submit."""
    if _mask_input:
        return "\u2022" * len(_input_buffer)
    return "".join(_input_buffer)


_input_pos: int = 0

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

        new[3] &= ~(_tm.ECHO | _tm.ICANON | _tm.ECHOE | _tm.ECHOK | _tm.ECHONL)

        new[6][_tm.VMIN] = 1
        new[6][_tm.VTIME] = 0
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
        return None
    remaining = 1 if byte < 0xE0 else 2 if byte < 0xF0 else 3
    data = b
    for _ in range(remaining):
        b2 = os.read(_stdin_fd, 1)
        if not b2:
            break
        data += b2
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _consume_escape_seq() -> None:
    """Read ANSI escape sequence; handle arrow/home/end keys."""
    global _input_pos, _scroll_locked, _scroll_pos
    try:
        r, _, _ = select.select([_stdin_fd], [], [], 0.05)
        if not r:
            return
        b2 = os.read(_stdin_fd, 1)
        if not b2:
            return
        if b2 in (b"[", b"O"):
            seq = b""
            while True:
                r2, _, _ = select.select([_stdin_fd], [], [], 0.05)
                if not r2:
                    break
                b3 = os.read(_stdin_fd, 1)
                if not b3:
                    break
                seq += b3
                if 0x40 <= b3[0] <= 0x7E:
                    break
            with _print_lock:
                n = len(_input_buffer)
                if seq == b"D":
                    if _input_pos > 0:
                        _input_pos -= 1
                        sys.stdout.write("\x1b[D")
                        sys.stdout.flush()
                elif seq == b"C":
                    if _input_pos < n:
                        _input_pos += 1
                        sys.stdout.write("\x1b[C")
                        sys.stdout.flush()
                elif seq in (b"H", b"1~"):
                    if _input_pos > 0:
                        sys.stdout.write(f"\x1b[{_input_pos }D")
                        _input_pos = 0
                        sys.stdout.flush()
                elif seq in (b"F", b"4~"):
                    if _input_pos < n:
                        sys.stdout.write(f"\x1b[{n -_input_pos }C")
                        _input_pos = n
                        sys.stdout.flush()
                elif seq == b"5~":  # PgUp
                    _page = max(1, shutil.get_terminal_size(fallback=(80, 20)).lines - 3)
                    if _TUI_SCROLL_CALLBACK is not None:
                        _TUI_SCROLL_CALLBACK("pgup", _page)
                    else:
                        if not _scroll_locked:
                            _scroll_locked = True
                        _scroll_pos = min(_scroll_pos + _page, len(_scroll_history))
                        _show_scrollback(_scroll_pos, _page)
                elif seq == b"6~":  # PgDn
                    _page = max(1, shutil.get_terminal_size(fallback=(80, 20)).lines - 3)
                    if _TUI_SCROLL_CALLBACK is not None:
                        _TUI_SCROLL_CALLBACK("pgdn", _page)
                    else:
                        _scroll_pos = max(0, _scroll_pos - _page)
                        if _scroll_pos == 0:
                            _scroll_locked = False
                            _scroll_unlock()
                        else:
                            _show_scrollback(_scroll_pos, _page)
    except Exception:
        pass


_EOF_SENTINEL = object()


def _handle_input_char(ch: str):
    """Process one keystroke, updating _input_buffer and echoing to stdout."""
    global _input_pos, _scroll_locked, _scroll_pos

    if ch == "\r" or ch == "\n":
        with _print_lock:
            line = "".join(_input_buffer)
            _input_buffer.clear()
            _input_pos = 0
            _ansi_strip = re.compile(r"\x1b\[[0-9;]*m")
            _vis_prompt = _ansi_strip.sub("", _current_prompt)
            _total = len(_vis_prompt) + len(line)
            _tw = TERMINAL_WIDTH if TERMINAL_WIDTH > 0 else 80
            _lines = max(1, (_total + _tw - 1) // _tw)
            if _lines > 1:
                sys.stdout.write(f"\033[{_lines -1 }A")
            sys.stdout.write("\r")
            for _ in range(_lines):
                sys.stdout.write("\033[2K\n")
            sys.stdout.write(f"\033[{_lines }A\r")
            sys.stdout.flush()
        return line

    if ch == "\x04":
        with _print_lock:
            if not _input_buffer:
                return _EOF_SENTINEL
        return None

    if ch == "\x15":
        with _print_lock:
            _input_buffer.clear()
            _input_pos = 0
            sys.stdout.write("\r\033[2K" + _current_prompt)
            sys.stdout.flush()
        return None

    if ch == "\x17":
        with _print_lock:
            while _input_buffer and _input_buffer[-1] == " ":
                _input_buffer.pop()
            while _input_buffer and _input_buffer[-1] != " ":
                _input_buffer.pop()
            _input_pos = len(_input_buffer)
            sys.stdout.write("\r\033[2K" + _current_prompt + _display_buffer())
            sys.stdout.flush()
        return None

    if ch in ("\x7f", "\x08"):
        with _print_lock:
            if _input_buffer and _input_pos > 0:
                del _input_buffer[_input_pos - 1]
                _input_pos -= 1
                after = "".join(_input_buffer[_input_pos:])
                sys.stdout.write(f"\x1b[D{after } \x1b[{len (after )+1 }D")
                sys.stdout.flush()
        return None
    # Ctrl+B / Ctrl+F — TUI panel scroll (like `less`; work on Termux software keyboard)
    if ch in ("\x02", "\x06"):  # Ctrl+B = scroll up, Ctrl+F = scroll down
        if _TUI_SCROLL_CALLBACK is not None:
            _page = max(1, shutil.get_terminal_size(fallback=(80, 20)).lines - 3)
            _TUI_SCROLL_CALLBACK("pgup" if ch == "\x02" else "pgdn", _page)
            return None
    if ch in ("\x13", "\x10"):  # Ctrl+S or Ctrl+P - scroll lock toggle (non-TUI)
        if _scroll_locked:
            _scroll_pos = 0
            _scroll_unlock()
        else:
            _scroll_locked = True
            with _print_lock:
                sys.stdout.write("\r\033[2K")
                sys.stdout.write(
                    "\x1b[33m[PAUSED - PgUp/PgDn to scroll, Ctrl+P or Ctrl+S to resume]\x1b[0m\n"
                )
                sys.stdout.flush()
        return None

    if ch == "\x1b":
        _consume_escape_seq()
        return None

    if ch == "\t":
        return None

    if ch >= " ":
        with _print_lock:
            _input_buffer.insert(_input_pos, ch)
            _input_pos += 1
            _shown = "\u2022" if _mask_input else ch
            if _input_pos == len(_input_buffer):
                sys.stdout.write(_shown)
            else:
                _after_raw = "".join(_input_buffer[_input_pos:])
                after = ("\u2022" * len(_after_raw)) if _mask_input else _after_raw
                sys.stdout.write(f"{_shown }{after }\x1b[{len (after )}D")
            sys.stdout.flush()
        try:
            _c = getattr(__import__("builtins"), "_active_client", None)
            if _c:
                _ap = _c.panel_manager.active_panel
                _pp = _c.panel_manager.panels.get(_ap)
                if _pp and _pp.panel_type == "private":
                    _c.send_raw(f"@+typing=active TAGMSG {_ap }")
        except Exception:
            pass
        return None

    return None


def _set_prompt(prompt: str) -> None:
    """Write a prompt string, preserving the user's typed text."""
    global _current_prompt
    with _print_lock:
        buf = _display_buffer()
        if _current_prompt or buf:
            sys.stdout.write("\x1b[1G\x1b[2K")
        _current_prompt = prompt
        sys.stdout.write(prompt + buf)
        sys.stdout.flush()


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _visible_len(text: str) -> int:
    """Return the visible character count, ignoring ANSI colour codes."""
    return len(_ANSI_RE.sub("", text))


def _truncate_visible(text: str, width: int) -> str:
    """Truncate to *width* visible columns, keeping ANSI codes intact.

    Truncating by len() would count the escape bytes as visible characters,
    so a coloured line gets cut far too early -- and, worse, loses its reset
    sequence, bleeding the colour into everything printed afterwards.  The
    reset is re-appended here for that reason.
    """
    if width <= 0 or _visible_len(text) <= width:
        return text
    out = []
    seen = 0
    i = 0
    while i < len(text) and seen < width:
        m = _ANSI_RE.match(text, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        out.append(text[i])
        seen += 1
        i += 1
    return "".join(out) + UIConstants.COLORS["reset"]


def _word_wrap(text: str, width: int) -> str:
    """Word-wrap text at *width* visible columns, preserving ANSI codes.

    The first line uses the full width.  Continuation lines are indented
    to align with the message body (detected by finding the first '] '
    in the visible text - the end of the timestamp+tag prefix).

    If the text fits in one line, it is returned unchanged.
    """
    if width < 20 or _visible_len(text) <= width:
        return text

    vis = _ANSI_RE.sub("", text)
    _bracket_end = vis.find("] ")
    if _bracket_end != -1 and _bracket_end < width // 2:
        indent = _bracket_end + 2
    else:
        indent = 4

    indent_str = " " * indent

    parts = _ANSI_RE.split(text)
    codes = _ANSI_RE.findall(text)

    tokens = []
    for i, part in enumerate(parts):
        if part:
            tokens.append((part, False))
        if i < len(codes):
            tokens.append((codes[i], True))

    lines = []
    current_line = ""
    current_vis = 0
    first_line = True

    for token_str, is_ansi in tokens:
        if is_ansi:
            current_line += token_str
            continue

        words = token_str.split(" ")
        for wi, word in enumerate(words):

            if wi > 0:

                space_fits = current_vis + 1 + len(word) <= width
                if current_vis > 0 and not space_fits and len(word) > 0:

                    lines.append(current_line)
                    current_line = indent_str + word if not first_line else indent_str + word
                    first_line = False
                    current_vis = indent + len(word)
                else:
                    current_line += " " + word
                    current_vis += 1 + len(word)
            else:

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

    return "\n".join(lines)


_scroll_locked = False
_scroll_buffer: deque = deque(maxlen=500)
_scroll_pos: int = 0
_scroll_history: list = []
_TUI_SCROLL_CALLBACK = None  # set by TUI client; receives ("pgup"|"pgdn", page)


def _emit_line(text: str) -> None:
    """Print a message line from any thread, preserving user input.

    Word-wraps at TERMINAL_WIDTH so words are never split mid-word.
    Clears the current terminal line (prompt + typed text), writes the
    message, then restores the prompt and the user's in-progress buffer
    so their typing is never lost or corrupted.

    When scroll lock is active, messages are buffered instead of printed.
    """
    global _scroll_locked
    wrapped = _word_wrap(text, TERMINAL_WIDTH)

    if _scroll_locked:
        _scroll_buffer.append(wrapped)

        with _print_lock:
            buf = _display_buffer()
            sys.stdout.write("\r\033[2K")
            sys.stdout.write(
                f"\033[33m[PAUSED - {len (_scroll_buffer )} buffered]\033[0m "
                + _current_prompt
                + buf
            )
            sys.stdout.flush()
        return

    try:
        with _print_lock:
            buf = _display_buffer()
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.write(wrapped + "\n")
            _scroll_history.append(wrapped)
            if len(_scroll_history) > 500:
                _scroll_history.pop(0)
            if _current_prompt or buf:
                sys.stdout.write(_current_prompt + buf)
            sys.stdout.flush()
    except (RuntimeError, ValueError, OSError):
        pass


def _show_scrollback(pos: int, page: int) -> None:
    with _print_lock:
        try:
            rows = shutil.get_terminal_size(fallback=(80, 24)).lines
            body_h = max(1, rows - 3)
            total = len(_scroll_history)
            end = min(total, max(0, total - pos + page))
            start = max(0, end - body_h)
            shown = _scroll_history[start:end]
            sys.stdout.write("\033[2J\033[H")
            for ln in shown:
                sys.stdout.write(ln + "\n")
            _pct = int(100 * end / max(1, total))
            sys.stdout.write(
                colorize(f"── SCROLL [{_pct }%] PgUp=back PgDn=fwd Ctrl+P/S=live ──", "yellow")
                + "\n"
            )
            sys.stdout.write(_current_prompt + _display_buffer())
            sys.stdout.flush()
        except Exception:
            pass


def _scroll_unlock() -> None:
    """Flush all buffered messages and resume live display."""
    global _scroll_locked
    _scroll_locked = False
    with _print_lock:
        sys.stdout.write("\r\033[2K")
        while _scroll_buffer:
            sys.stdout.write(_scroll_buffer.popleft() + "\n")
        buf = _display_buffer()
        if _current_prompt or buf:
            sys.stdout.write(_current_prompt + buf)
        sys.stdout.flush()


_display_queue: deque = deque()


def _flush_display_queue() -> None:
    """Flush any queued messages to stdout (cooked-mode fallback only)."""
    if not _display_queue:
        return
    with _print_lock:
        buf = _display_buffer()
        sys.stdout.write("\r\033[2K")
        while _display_queue:
            sys.stdout.write(_display_queue.popleft() + "\n")
        if _current_prompt or buf:
            sys.stdout.write(_current_prompt + buf)
        sys.stdout.flush()


def safe_print(*args, **kwargs):
    """Thread-safe print with flush, preserving user input in raw mode."""
    kwargs["flush"] = True
    try:
        with _print_lock:
            buf = _display_buffer()
            if (_current_prompt or buf) and _raw_mode_active:
                sys.stdout.write("\x1b[1G\x1b[2K")
            print(*args, **kwargs)
            if (_current_prompt or buf) and _raw_mode_active:
                sys.stdout.write(_current_prompt + buf)
                sys.stdout.flush()
    except (RuntimeError, ValueError, OSError):
        pass


@dataclass
class OTRConfig:
    """Mutable configuration object"""

    trust_db_path: Optional[str] = None
    smp_secrets_path: Optional[str] = None
    key_storage_path: Optional[str] = None
    log_file_path: Optional[str] = None
    test_mode: bool = False
    i2p_proxy: Tuple[str, int] = ("127.0.0.1", 4447)
    i2p_sam: Tuple[str, int] = ("127.0.0.1", 7656)
    tor_proxy: Tuple[str, int] = ("127.0.0.1", 9050)
    server: str = "irc.postman.i2p"
    port: int = 0
    use_tls: bool = False
    sasl_user: Optional[str] = None
    # repr=False: a dataclass repr prints every field, and this one
    # ends up in debug output and exception text.
    sasl_pass: Optional[str] = field(default=None, repr=False)
    channel: str = "#otr"
    log_level: str = "INFO"
    dake_timeout: float = 120.0
    fragment_timeout: float = 120.0
    heartbeat_interval: int = 300
    rekey_interval: int = 100
    nickserv_login: bool = False
    nickserv_register: bool = False
    nickserv_nick: Optional[str] = None
    nickserv_pass: Optional[str] = field(default=None, repr=False)

    # -- Identity and trust persistence -----------------------------------
    #
    # Both default OFF, and that default is the IRC behaviour: a fresh Ed448
    # identity every process and no trust record that outlives it.  That is
    # deliberate (ROADMAP Phase 5.3g) and not a limitation to be fixed -- an
    # IRC nick is ephemeral, so pinning a fingerprint to one means pinning it
    # to nothing.
    #
    # XMPP turns both on.  A JID is a durable name, so an identity that changes
    # under it is a fact worth noticing, and TOFU is only meaningful once the
    # local identity stops changing too.
    #
    # These are separate switches because they fail independently: identity
    # persistence can be unavailable (no writable state directory) while trust
    # pinning is still wanted for the session, and a caller that wants neither
    # should not have to opt out of both by accident.
    persist_identity: bool = False
    persist_trust: bool = False
    #: Refuse a peer whose signed profile does not list both v2 capabilities
    #: (PQ_RATCHET_VERSION, PQ_AUTH_VERSION): no fallback to the v1 ratchet
    #: (A1) or v1 authentication (A2). Off only for interop tests.
    require_pq_v2: bool = True

    #: Sealed long-term identity record.  Only read when persist_identity.
    identity_path: Optional[str] = None
    #: Device-local key protecting `identity_path`.  Only read when
    #: persist_identity.  See TermuxFileDekProvider for what this does and,
    #: more importantly, what it does not do.
    identity_dek_path: Optional[str] = None


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

    def __init__(self, message: str, session: Optional["EnhancedOTRSession"] = None):
        super().__init__(message)
        self.session = session


class ProtocolVersionError(ValueError):
    """The peer speaks a different OTRv4+ wire revision.

    C1. Subclasses ValueError deliberately: every existing `except ValueError`
    handler around decode() keeps working, while callers that need to tell a
    version mismatch from a cryptographic failure can catch this specifically.

    This exists because the two failure modes were previously indistinguishable.
    A peer on an older build would pass the version check (the constant had not
    been incremented for a breaking change), then fail MAC verification, and the
    user would be shown "message may be forged or replayed" for what was really
    a version mismatch -- an alarming and wrong diagnosis on a security-relevant
    path.
    """


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
        log_dir = os.path.dirname(self.config.log_file_path or "~/.otrv4/logs/otrv4.log")
        log_dir = os.path.expanduser(log_dir)
        os.makedirs(log_dir, exist_ok=True)
        try:
            os.chmod(log_dir, 0o700)
        except Exception:
            pass

        log_file = self.config.log_file_path or os.path.join(log_dir, "otrv4plus.log")
        if not os.path.exists(log_file):
            try:
                with open(log_file, "a"):
                    pass
                os.chmod(log_file, 0o600)
            except Exception:
                pass

        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5
        )

        formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s")
        handler.setFormatter(formatter)

        self.security_logger = logging.getLogger("otrv4.security")
        self.network_logger = logging.getLogger("otrv4.network")
        self.ui_logger = logging.getLogger("otrv4.ui")
        self.session_logger = logging.getLogger("otrv4.session")

        for logger in [
            self.security_logger,
            self.network_logger,
            self.ui_logger,
            self.session_logger,
        ]:
            logger.addHandler(handler)
            logger.setLevel(getattr(logging, self.config.log_level.upper()))
            logger.propagate = False

    def security_event(self, event: str, session_id: str, peer: str, details: dict):
        """Log security events"""
        self.security_logger.info(
            f"EVENT={event } | SESSION={session_id } | PEER={peer } | {json .dumps (details )}"
        )

    def network_message(self, direction: str, peer: str, msg_type: str, length: int):
        """Log network I/O"""
        self.network_logger.debug(
            f"DIRECTION={direction } | PEER={peer } | TYPE={msg_type } | LENGTH={length }"
        )

    def ui_interaction(self, action: str, panel: str, user_input: str):
        """Log UI interactions (excluding secrets)"""
        self.ui_logger.info(f"ACTION={action } | PANEL={panel } | INPUT_LENGTH={len (user_input )}")

    def session_transition(self, old_state: str, new_state: str, peer: str, session_id: str):
        """Log session state transitions"""
        self.session_logger.info(
            f"TRANSITION={old_state }→{new_state } | PEER={peer } | SESSION={session_id }"
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
        self.enabled = enabled or DEBUG_MODE
        self.logger = logger
        self.peer_states: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()
        self._emit_cb = None

    def set_emit_callback(self, cb) -> None:
        """Register the client's debug-panel emit function."""
        self._emit_cb = cb

    def trace(
        self,
        peer: str,
        category: str,
        old_state: Any,
        new_state: Any,
        reason: Optional[str] = None,
        details: Optional[Dict] = None,
    ):
        """Record a state transition. Output goes ONLY to debug panel, never stdout."""
        if not self.enabled:
            return

        with self.lock:
            if peer not in self.peer_states:
                self.peer_states[peer] = {}
            self.peer_states[peer][category] = new_state

            old_str = (
                str(old_state)
                .replace("State.", "")
                .replace("SMPState.", "")
                .replace("DAKEState.", "")
            )
            new_str = (
                str(new_state)
                .replace("State.", "")
                .replace("SMPState.", "")
                .replace("DAKEState.", "")
            )

            msg = f"[OTR:{peer }] {category }: {old_str } → {new_str }"
            if reason:
                msg += f" | {reason }"

            if self.logger:
                self.logger.session_transition(old_str, new_str, peer, category)

            color = (
                "green"
                if "ESTABLISHED" in new_str or "ENCRYPTED" in new_str
                else (
                    "red"
                    if "FAILED" in new_str
                    else "yellow" if "SENT" in new_str or "RECEIVED" in new_str else "cyan"
                )
            )
            colored_msg = colorize(msg, color)

            if self._emit_cb:
                self._emit_cb(colored_msg)
                if details and DEBUG_MODE:
                    for k, v in details.items():
                        if k not in ("secret", "key", "nonce", "private", "password"):
                            self._emit_cb(f"  {k }: {v }")

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
                return f"No state tracked for {peer }"

            report = []
            report.append(f"OTR State Report for {colorize_username (peer )}:")
            for category, state in sorted(self.peer_states[peer].items()):
                state_str = (
                    str(state)
                    .replace("State.", "")
                    .replace("SMPState.", "")
                    .replace("DAKEState.", "")
                )
                report.append(f"  {category :12} : {state_str }")

            return "\n".join(report)


class SecureMemory:
    """Secure memory buffer with mlock protection and multi-pass zeroization."""

    def __init__(self, size: int):
        self._size = size
        self._locked = False
        self._buffer: Optional[bytearray] = None
        self._lock = threading.RLock()
        self._libc = None

        aligned_size = (
            (size + NetworkConstants.MLOCK_PAGE_SIZE - 1) // NetworkConstants.MLOCK_PAGE_SIZE
        ) * NetworkConstants.MLOCK_PAGE_SIZE
        with self._lock:
            self._buffer = bytearray(aligned_size)
            self._attempt_mlock()

    def _attempt_mlock(self):
        """Attempt to lock memory with proper error handling"""
        try:
            libc_names = ["libc.so.6", "libc.so", "libc.dylib", "libc"]

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

            if hasattr(self._libc, "mlock"):
                result = self._libc.mlock(buf_addr, buf_size)
                if result == 0:
                    self._locked = True
                else:
                    errno = ctypes.get_errno()
                    self._log_mlock_failure(f"mlock failed with errno: {errno }")
            else:
                self._log_mlock_failure("mlock function not found")

        except (OSError, AttributeError, ValueError, Exception) as e:
            self._log_mlock_failure(f"Exception: {e }")

    def _log_mlock_failure(self, reason: str):
        """Log mlock failure without exposing sensitive info"""
        if DEBUG_MODE:
            print(f"[SecureMemory] Warning: {reason } - memory not locked")

    def zeroize(self):
        """Securely zeroize memory.

        HARDENED: always uses OPENSSL_cleanse (C extension) or ctypes.memset.
        A pure-Python loop over the bytearray is NOT used because CPython's
        interpreter may re-order or batch writes in ways that are hard to
        reason about from a security standpoint.  If the C extension is
        unavailable, ctypes.memset provides the next-best guarantee.
        """
        if not acquire_lock_with_timeout(self._lock, timeout=5.0):
            raise RuntimeError("Failed to acquire lock for zeroize")

        try:
            if self._buffer is None:
                return

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
                    if hasattr(self._libc, "munlock"):
                        self._libc.munlock(buf_addr, buf_size)
                except (OSError, AttributeError, Exception) as e:
                    if DEBUG_MODE:
                        print("[SecureMemory] munlock failed")
                self._locked = False

            self._buffer = None

        except Exception as e:
            if DEBUG_MODE:
                print("[SecureMemory] zeroize error")
            raise
        finally:
            try:
                self._lock.release()
            except Exception:
                pass

    def write(self, data: bytes):
        """Write data to secure memory, zeroing all prior content first."""
        if not acquire_lock_with_timeout(self._lock, timeout=5.0):
            raise RuntimeError("Failed to acquire lock for write")

        try:
            if self._buffer is None:
                raise RuntimeError("SecureMemory buffer destroyed")

            if len(data) > self._size:
                raise ValueError(f"Data too large for SecureMemory")

            try:
                n = len(self._buffer)
                if n > 0:
                    addr = (ctypes.c_char * n).from_buffer(self._buffer)
                    ctypes.memset(addr, 0, n)
            except Exception:

                self._buffer[:] = bytearray(len(self._buffer))

            self._buffer[: len(data)] = data

        except Exception as e:
            raise RuntimeError(f"Write failed: {e }")
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
            return bytes(self._buffer[: self._size])
        except Exception as e:
            raise RuntimeError(f"Read failed: {e }")
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
            if hasattr(self, "_buffer") and self._buffer is not None:
                for i in range(len(self._buffer)):
                    self._buffer[i] = 0
        except Exception:
            pass


class SHA3_512:
    """SHA3-512 utility class (OTRv4 spec §3.2) - strict, no fallback.

    OTRv4 mandates SHA3-512.  Using SHA-512 instead is a spec violation
    and would break interoperability.  We require Python ≥ 3.6 where
    sha3_512 is always available; raise hard if it is not.
    """

    @staticmethod
    def _require() -> Any:
        if not hasattr(hashlib, "sha3_512"):
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


class ClientProfile:
    """OTRv4 Client Profile (spec §4.1). Handles encoding, decoding, and expiry."""

    VALIDITY_SECONDS = 14 * 24 * 3600

    def __init__(self, identity_key=None, prekey=None):
        """Create a fresh OTRv4 ClientProfile with ephemeral Ed448+X448 keys.

        v10.6.12 (Phase 5.3e): identity keys are now Rust-owned by default.
        Both `self.identity_key` and `self.prekey` are
        `otrv4_core.Ed448KeyHandle` / `X448KeyHandle` objects whose private
        bytes live inside Rust SecretBytes (ZeroizeOnDrop) for the session
        lifetime.  Python receives only public bytes through the handle's
        `.public_bytes()` method.

        For backward compatibility (test code that constructs a ClientProfile
        with specific cryptography library keypairs), the legacy
        `Ed448PrivateKey` / `X448PrivateKey` parameters are still accepted.
        When provided, they are converted to Rust handles by extracting the
        raw bytes via the `from_seed_bytes` / `from_priv_bytes` static
        constructors.  This conversion path does touch the Python heap
        briefly (the bytearray we pass in is wiped after handle construction),
        but is only exercised by test code.

        Keys are ALWAYS generated fresh - no saved profile file is consulted.
        This is intentional and correct for random/ephemeral IRC nicks: each
        session gets brand-new cryptographic identity.  The profile is signed
        with the identity key inside encode().

        Encoded size for versions=[4]:
            version(1) + num_versions(1) + version_byte(1)
            + Ed448_pub(57) + X448_pub(56) + expires(8) + Ed448_sig(114)
            = 238 bytes exactly.
        """

        if identity_key is None:
            self.identity_key = _RustDAKE_module.generate_ed448_keypair()
        else:
            self.identity_key = identity_key

        if prekey is None:
            self.prekey = _RustDAKE_module.generate_x448_keypair()
        else:
            self.prekey = prekey

        self.versions = [OTRConstants.PROTOCOL_VERSION, OTRConstants.PQ_RATCHET_VERSION,
                         OTRConstants.PQ_AUTH_VERSION]
        #: This identity's long-term ML-DSA-87 key (MLDSA87Auth), set by the
        #: session manager. None: each handshake makes its own (v1 only).
        self.mldsa_identity = None
        self.created = int(time.time())
        self.expires = self.created + self.VALIDITY_SECONDS
        self.signature = None

        self.identity_pub_bytes = bytes(self.identity_key.public_bytes())
        self.prekey_pub_bytes = bytes(self.prekey.public_bytes())

        if DEBUG_MODE:
            import sys as _sys

            _sys.stderr.write(
                f"[ClientProfile] Fresh Rust-owned identity keys - "
                f"expires {time .ctime (self .expires )}\n"
            )

    def encode_unsigned(self) -> bytes:
        """Phase 5.3a-cleanup (v10.6.7): return the unsigned profile body.

        Identical to encode() but without the trailing Ed448 signature.
        Used by RustDAKEAdapter.__init__ to hand off to
        RustDAKE.sign_profile_body_and_construct(), which signs AND
        constructs the RustDAKE in a single FFI call - eliminating the
        bytes(_ik_priv) snapshot that was created at the constructor
        boundary in v10.6.4/v10.6.5/v10.6.6.

        After Rust returns the signature, the caller appends it to
        produce the full signed profile and assigns it to
        self.signature.
        """

        identity_pub = self.identity_pub_bytes
        prekey_pub = self.prekey_pub_bytes
        if len(identity_pub) != OTRConstants.ED448_PUBLIC_KEY_SIZE:
            raise ValueError(f"Identity key wrong length: {len (identity_pub )}")
        if len(prekey_pub) != OTRConstants.X448_PUBLIC_KEY_SIZE:
            raise ValueError(f"Prekey wrong length: {len (prekey_pub )}")

        profile_data = bytearray()
        profile_data.append(OTRConstants.PROTOCOL_VERSION)
        profile_data.append(len(self.versions))
        for v in self.versions:
            profile_data.append(v)
        profile_data.extend(identity_pub)
        profile_data.extend(prekey_pub)
        profile_data.extend(struct.pack(">Q", self.expires))
        return bytes(profile_data)

    def encode(self) -> bytes:
        try:

            identity_pub = self.identity_pub_bytes
            prekey_pub = self.prekey_pub_bytes

            if len(identity_pub) != OTRConstants.ED448_PUBLIC_KEY_SIZE:
                raise ValueError(f"Identity key wrong length: {len (identity_pub )}")
            if len(prekey_pub) != OTRConstants.X448_PUBLIC_KEY_SIZE:
                raise ValueError(f"Prekey wrong length: {len (prekey_pub )}")

            profile_data = bytearray()
            profile_data.append(OTRConstants.PROTOCOL_VERSION)
            profile_data.append(len(self.versions))
            for v in self.versions:
                profile_data.append(v)
            profile_data.extend(identity_pub)
            profile_data.extend(prekey_pub)
            profile_data.extend(struct.pack(">Q", self.expires))

            self.signature = bytes(self.identity_key.sign(bytes(profile_data)))

            if len(self.signature) != OTRConstants.ED448_SIGNATURE_SIZE:
                raise ValueError(f"Signature wrong length: {len (self .signature )}")

            profile_data.extend(self.signature)
            result = bytes(profile_data)
            expected = (
                1
                + 1
                + len(self.versions)
                + OTRConstants.ED448_PUBLIC_KEY_SIZE
                + OTRConstants.X448_PUBLIC_KEY_SIZE
                + 8
                + OTRConstants.ED448_SIGNATURE_SIZE
            )
            if len(result) != expected:
                raise ValueError(
                    f"ClientProfile.encode() produced {len (result )} bytes, "
                    f"expected {expected }. OTRConstants key-size mismatch."
                )
            if DEBUG_MODE:
                print(f"[ClientProfile] encode() → {len (result )} bytes ✅ (🦀 Rust handle)")
            return result
        except (ValueError, TypeError, AttributeError) as e:
            raise ValueError(f"Client profile encoding failed: {e }")
        except Exception as e:
            raise RuntimeError(f"Unexpected error encoding profile: {e }")

    @classmethod
    def decode(cls, data: bytes) -> "ClientProfile":
        """Strict profile decoding - rejects any profile that fails validation.

        OTRv4 spec §4.1.2 requires signature verification before accepting
        identity keys.  Allowing truncated or unsigned profiles is a MITM
        vector (audit finding
        any deviation; callers must abort the DAKE on exception.
        """
        try:
            min_size = (
                1
                + 1
                + 1
                + OTRConstants.ED448_PUBLIC_KEY_SIZE
                + OTRConstants.X448_PUBLIC_KEY_SIZE
                + 8
                + OTRConstants.ED448_SIGNATURE_SIZE
            )

            if len(data) < min_size:
                raise ValueError(
                    f"ClientProfile too short: {len (data )} < {min_size } bytes. "
                    "Truncated profiles are rejected (OTRv4 §4.1.2)."
                )

            offset = 0
            version = data[offset]
            offset += 1
            if version != OTRConstants.PROTOCOL_VERSION:
                raise ValueError(
                    f"Unsupported protocol version {version } - expected "
                    f"{OTRConstants .PROTOCOL_VERSION }. Refusing potential downgrade."
                )

            num_versions = data[offset]
            offset += 1
            if num_versions == 0 or num_versions > 8:
                raise ValueError(f"Implausible version count: {num_versions }")

            versions = []
            for _ in range(num_versions):
                if offset >= len(data):
                    raise ValueError("Truncated during version list")
                versions.append(data[offset])
                offset += 1

            if 4 not in versions:
                raise ValueError(f"OTRv4 not in supported versions: {versions }")

            if len(data) < offset + OTRConstants.ED448_PUBLIC_KEY_SIZE:
                raise ValueError("Truncated identity public key")
            identity_pub_bytes = data[offset : offset + OTRConstants.ED448_PUBLIC_KEY_SIZE]
            offset += OTRConstants.ED448_PUBLIC_KEY_SIZE

            if len(data) < offset + OTRConstants.X448_PUBLIC_KEY_SIZE:
                raise ValueError("Truncated prekey public key")
            prekey_pub_bytes = data[offset : offset + OTRConstants.X448_PUBLIC_KEY_SIZE]
            offset += OTRConstants.X448_PUBLIC_KEY_SIZE

            if len(data) < offset + 8:
                raise ValueError("Truncated expiry timestamp")
            expires = struct.unpack(">Q", data[offset : offset + 8])[0]
            offset += 8

            now = int(time.time())
            if expires <= now:
                raise ValueError(
                    f"ClientProfile has expired (expires={time .ctime (expires )}). "
                    "Rejecting stale profile."
                )

            if len(data) < offset + OTRConstants.ED448_SIGNATURE_SIZE:
                raise ValueError(
                    "ClientProfile has no signature - rejecting unsigned profile. "
                    "OTRv4 §4.1.2 requires signature verification."
                )
            signature = data[offset : offset + OTRConstants.ED448_SIGNATURE_SIZE]

            signed_data = data[:offset]

            try:
                _sig_ok = _RustDAKE_module.verify_ed448_sig(
                    identity_pub_bytes, signed_data, signature
                )
            except ValueError as sig_err:

                raise ValueError(
                    f"ClientProfile signature verification FAILED: {sig_err }. "
                    "Rejecting profile - malformed identity key or signature "
                    "(OTRv4 §4.1.2)."
                ) from sig_err
            if not _sig_ok:
                raise ValueError(
                    "ClientProfile signature verification FAILED. "
                    "Rejecting profile - potential MITM/forged identity "
                    "(OTRv4 §4.1.2)."
                )

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
                print(
                    f"[ClientProfile] ✅ Strict decode OK - sig verified, expires {time .ctime (expires )}"
                )
                print(f"  versions: {versions }")

            return profile

        except ValueError:
            raise
        except (IndexError, struct.error, TypeError) as e:
            raise ValueError(f"ClientProfile decode failed due to malformed data: {e }") from e
        except Exception as e:
            raise RuntimeError(f"ClientProfile decode failed unexpectedly: {e }") from e

    def get_fingerprint(self) -> str:
        """Compute the OTRv4 fingerprint as SHA3-512 of the Ed448 public key.

        OTRv4 spec §4.1 mandates SHA3-512 for fingerprints.
        Using SHA-256 (previous implementation) produced fingerprints
        incompatible with all other OTRv4 clients (CoyIM, pidgin-otr4, etc.).
        Fingerprint is returned as 128 uppercase hex chars in 16 groups of 8.
        """
        try:

            if self.identity_pub_bytes:
                identity_pub = self.identity_pub_bytes
            elif self.identity_key:
                identity_pub = bytes(self.identity_key.public_bytes())
            else:
                return ""
            if identity_pub is None:
                return ""
            fp_bytes = hashlib.sha3_512(identity_pub).digest()
            hex_str = fp_bytes.hex().upper()
            groups = [hex_str[i : i + 8] for i in range(0, 128, 8)]
            return " ".join(groups)
        except (AttributeError, TypeError, ValueError) as e:
            if DEBUG_MODE:
                print("[ClientProfile] Error getting fingerprint")
            return ""
        except Exception:
            return ""

    def verify_fingerprint(self, fingerprint: str) -> bool:
        """Verify a fingerprint using constant-time comparison"""
        try:
            actual = self.get_fingerprint()
            if not actual or not fingerprint:
                return False
            return hmac.compare_digest(actual.encode("utf-8"), fingerprint.encode("utf-8"))
        except (TypeError, AttributeError, ValueError) as e:
            if DEBUG_MODE:
                print("[ClientProfile] Fingerprint verification failed")
            return False
        except Exception:
            return False

    def get_prekey_fingerprint(self) -> str:
        """Compute X448 prekey fingerprint as SHA3-512 per OTRv4 spec §4.1."""
        try:

            if self.prekey_pub_bytes:
                prekey_pub = self.prekey_pub_bytes
            elif self.prekey:
                prekey_pub = bytes(self.prekey.public_bytes())
            else:
                return ""
            if prekey_pub is None:
                return ""
            fp_bytes = hashlib.sha3_512(prekey_pub).digest()
            return fp_bytes.hex().upper()
        except (AttributeError, TypeError, ValueError) as e:
            if DEBUG_MODE:
                print("[ClientProfile] Error getting prekey fingerprint")
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
            self.expires = self.created + self.VALIDITY_SECONDS
            self.signature = None
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ClientProfile] Renew failed: {e }")


class TLVHandler:
    """TLV handler for OTRv4 (Spec §4.3.2)"""

    @staticmethod
    def encode_tlv(tlv_type: int, data: bytes) -> bytes:
        length = len(data)
        return struct.pack("!HH", tlv_type, length) + data

    @staticmethod
    def decode_tlv(data: bytes) -> Tuple[int, bytes, bytes]:
        """Decode one TLV record - strict: raises ValueError on truncated input.

        Returns (type, value, remaining_bytes).
        """
        if len(data) < 4:
            raise ValueError(f"TLV too short: need 4-byte header, have {len (data )}")
        try:
            tlv_type, length = struct.unpack("!HH", data[:4])
        except struct.error as e:
            raise ValueError(f"TLV header unpack failed: {e }")
        end = 4 + length
        if len(data) < end:
            raise ValueError(
                f"TLV value truncated: type=0x{tlv_type :04x} "
                f"declares {length } bytes but only {len (data )-4 } available"
            )
        return tlv_type, data[4:end], data[end:]

    @staticmethod
    def debug_tlv(data: bytes, description: str = "") -> None:
        """Debug TLV structure"""
        if len(data) < 4:
            print(f"TLV {description }: Too short ({len (data )} bytes)")
            return

        try:
            tlv_type, length = struct.unpack("!HH", data[:4])
            print(
                f"TLV {description }: type=0x{tlv_type :04x}, length={length }, data_len={len (data )}"
            )
            print(f"  Hex: {data [:min (32 ,len (data ))].hex ()}...")
        except struct.error as e:
            print(f"TLV {description }: Unpack error: {e }")
            print(f"  Hex: {data [:min (32 ,len (data ))].hex ()}...")


class RatchetHeader:
    """Ratchet header for Double Ratchet (Spec §4.4)"""

    def __init__(self, dh_pub: bytes, prev_chain_len: int, msg_num: int):
        self.dh_pub = dh_pub
        self.prev_chain_len = prev_chain_len
        self.msg_num = msg_num

    def encode(self) -> bytes:
        return self.dh_pub + struct.pack("!II", self.prev_chain_len, self.msg_num)

    @classmethod
    def decode(cls, data: bytes) -> "RatchetHeader":
        if len(data) != 56 + 8:
            raise ValueError(f"Invalid header length: {len (data )}")

        dh_pub = data[:56]
        prev_chain_len, msg_num = struct.unpack("!II", data[56:])
        return cls(dh_pub, prev_chain_len, msg_num)


class SkippedMessageKey:
    """Storage for skipped message keys"""

    def __init__(self, dh_pub: bytes, msg_num: int, message_key: bytes):
        self.dh_pub = dh_pub
        self.msg_num = msg_num
        self.message_key = bytearray(message_key)

    def zeroize(self):
        """Zeroize the message key (v10.7.2: ctypes.memset via _secure_wipe)."""
        if hasattr(self, "message_key") and self.message_key:
            _secure_wipe(self.message_key)
            self.message_key = bytearray()

    def __del__(self):
        self.zeroize()


class _RatchetKeyStore:
    """Lightweight SecureMemory-compatible wrapper for a 32-byte ratchet key.

    Provides .read() / .write() / .zeroize() so tests that previously called
    ``ratchet.chain_key_send.read()`` continue to work after the Python
    fallback was replaced by the Rust core.
    """

    __slots__ = ("_buf", "_lock")

    def __init__(self, initial: bytes = b"\x00" * 32):
        import threading

        self._lock = threading.Lock()
        self._buf = bytearray(initial[:32].ljust(32, b"\x00"))

    def read(self) -> bytes:
        with self._lock:
            return bytes(self._buf)

    def write(self, data: bytes) -> None:
        with self._lock:
            self._buf[:] = bytearray(data[:32].ljust(32, b"\x00"))

    def zeroize(self) -> None:
        with self._lock:
            for i in range(len(self._buf)):
                self._buf[i] = 0

    def __repr__(self):
        return f"<_RatchetKeyStore {self .read ()[:4 ].hex ()}\u2026>"


class RustBackedDoubleRatchet:
    """OTRv4 Double Ratchet - Rust crypto core.

    Python orchestrates; Rust owns every secret. The X448 ratchet keys are
    opaque `X448KeyHandle`s and the agreement happens inside
    `RustDoubleRatchet.send_ratchet` / `decrypt_new_dh`; the ML-KEM brace
    rotation holds its decapsulation key in an opaque `MlKem1024Keypair`
    and folds the shared secret in via `brace_encapsulate` /
    `brace_decapsulate`. No DH output, KEM shared secret, decapsulation key,
    root, chain or brace key is a Python object on the production path.

    `root_key`, `chain_key_send`, `chain_key_recv` and `_brace_key` are
    OBSERVATION MIRRORS: after every operation they hold one-way SHA3 tags
    of the corresponding Rust key (`RustDoubleRatchet.state_tags`), so a
    caller can see that a key moved, or that two ends agree, without
    holding it. They are not keys and cannot be used as keys.

    Deterministic zeroization: Rust's Zeroize trait guarantees all
    secret key material is overwritten on drop - unlike Python's GC
    which may leave copies in memory indefinitely.
    """

    def __init__(
        self,
        root_key,
        is_initiator: bool,
        ad: bytes = b"OTRv4-DATA",
        logger=None,
        chain_key_send=None,
        chain_key_recv=None,
        brace_key=None,
        rekey_interval: int = OTRConstants.REKEY_INTERVAL,
        rekey_timeout: int = OTRConstants.REKEY_TIMEOUT,
    ):

        self.lock = threading.RLock()
        self.is_initiator = is_initiator
        self.ad = ad
        self.logger = logger or NullLogger()
        self.rekey_interval = rekey_interval
        self.rekey_timeout = rekey_timeout
        self.last_rekey_time = time.time()

        self.dh_ratchet_local = _RustDAKE_module.generate_x448_keypair()
        self.dh_ratchet_local_pub = self.dh_ratchet_local.public_bytes()
        self.dh_ratchet_remote = None
        self.dh_ratchet_remote_pub = None
        self.last_remote_pub = None

        self._brace_kem_local = None
        self._brace_kem_ek_out = None
        self._brace_kem_ct_out = None
        self._brace_key = brace_key if brace_key else bytes(32)

        rk_bytes = root_key.read() if hasattr(root_key, "read") else bytes(root_key)
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
            raise ValueError("Chain keys zero - possible KDF failure")

        _rust_init = True
        self._rust = _RustRatchet(
            rk_bytes[:32],
            ck_s,
            ck_r,
            bk_bytes[:32],
            self.dh_ratchet_local_pub,
            _rust_init,
        )

        self.ratchet_id = 0
        self.message_counter_send = 0

        self._rks_send = _RatchetKeyStore(ck_s)
        self._rks_recv = _RatchetKeyStore(ck_r)
        self._rks_root = _RatchetKeyStore(rk_bytes[:32])

        self._rks_recv_init = _RatchetKeyStore(ck_r)
        self._rks_send_init = _RatchetKeyStore(ck_s)

        self._dh_epoch: int = 0

        self.message_num_recv: int = 0

        self.skipped_keys: dict = {}
        self._next_expected_recv_num: int = 0
        self._current_recv_dh_pub: Optional[bytes] = None

        self._sync_mirrors()
        self.logger.debug(f"RustBackedDoubleRatchet initialized (initiator={is_initiator })")

    @classmethod
    def from_dake_output(
        cls,
        dake_output,
        is_initiator: bool,
        ad: bytes = b"OTRv4-DATA",
        logger=None,
        rekey_interval: int = None,
        rekey_timeout: int = None,
    ) -> "RustBackedDoubleRatchet":
        """Construct a ratchet from a DakeOutput without ever materialising
        the session keys as Python bytes.

        The session keys (root, chain_send, chain_recv, brace) move directly
        from Rust's DakeOutput.inner: RefCell<Option<DakeSessionKeys>> into
        the RustDoubleRatchet's owned SecretBytes fields via
        output.consume_into_ratchet().  At no point are they marshalled into
        PyBytes.

        This closes audit findings C2 and C3 (Critical Exposure Window)
        completely: the session keys never become accessible to Python code,
        the GC, or anything that can dump Python heap.

        The DakeOutput is consumed by this call.  After return, the
        DakeOutput's secret-key slots are taken; its public fields
        (ssid, remote_identity_pub, etc.) remain readable but
        `output.consumed` becomes True.

        Test-API mirrors (`_rks_send`, `_rks_recv`, `_rks_root`) are set
        to zero placeholders because real key bytes are no longer
        accessible from Python.  Production crypto does not touch these
        mirrors; only the test suite and the session-persistence export
        read them.  Persistence export from a Phase-4 ratchet requires a
        Rust-side serialization API (planned for v10.6.4).
        """
        if rekey_interval is None:
            rekey_interval = OTRConstants.REKEY_INTERVAL
        if rekey_timeout is None:
            rekey_timeout = OTRConstants.REKEY_TIMEOUT
        if dake_output is None:
            raise ValueError("from_dake_output: dake_output is None")
        if getattr(dake_output, "consumed", False):
            raise ValueError("from_dake_output: DakeOutput already consumed")

        self = cls.__new__(cls)
        self.lock = threading.RLock()
        self.is_initiator = is_initiator
        self.ad = ad
        self.logger = logger or NullLogger()
        self.rekey_interval = rekey_interval
        self.rekey_timeout = rekey_timeout
        self.last_rekey_time = time.time()

        self.dh_ratchet_local = _RustDAKE_module.generate_x448_keypair()
        self.dh_ratchet_local_pub = self.dh_ratchet_local.public_bytes()
        self.dh_ratchet_remote = None
        self.dh_ratchet_remote_pub = None
        self.last_remote_pub = None

        self._brace_kem_local = None
        self._brace_kem_ek_out = None
        self._brace_kem_ct_out = None

        self._brace_key = bytes(32)
        self.pq = False
        self._v2_item = (None, None)

        if not RUST_RATCHET_AVAILABLE:
            raise RuntimeError(
                "otrv4_core Rust module not installed - Phase-4 ratchet " "requires the Rust core."
            )

        self._rust = dake_output.consume_into_ratchet(
            ad,
            self.dh_ratchet_local_pub,
            is_initiator,
        )

        self.ratchet_id = 0
        self.message_counter_send = 0

        _placeholder = b"\x00" * 32
        self._rks_send = _RatchetKeyStore(_placeholder)
        self._rks_recv = _RatchetKeyStore(_placeholder)
        self._rks_root = _RatchetKeyStore(_placeholder)
        self._rks_recv_init = _RatchetKeyStore(_placeholder)
        self._rks_send_init = _RatchetKeyStore(_placeholder)

        self._dh_epoch = 0
        self.message_num_recv = 0
        self.skipped_keys = {}
        self._next_expected_recv_num = 0
        self._current_recv_dh_pub = None

        self._dake_output_consumed = True
        self._sync_mirrors()

        self.logger.debug(
            f"RustBackedDoubleRatchet.from_dake_output (initiator={is_initiator }) "
            f"- Phase 4 path: session keys live ONLY in Rust"
        )
        return self

    @property
    def chain_key_send(self) -> "_RatchetKeyStore":
        """Send chain key (read() returns current bytes; write() accepted for import)."""
        return self._rks_send

    @chain_key_send.setter
    def chain_key_send(self, value):
        data = value.read() if hasattr(value, "read") else bytes(value or b"\x00" * 32)
        self._rks_send.write(data[:32])

    @property
    def chain_key_recv(self) -> "_RatchetKeyStore":
        """Recv chain key (read() returns current bytes)."""
        return self._rks_recv

    @chain_key_recv.setter
    def chain_key_recv(self, value):
        data = value.read() if hasattr(value, "read") else bytes(value or b"\x00" * 32)
        self._rks_recv.write(data[:32])

    @property
    def root_key(self) -> "_RatchetKeyStore":
        """Root key (read() returns current bytes)."""
        return self._rks_root

    @root_key.setter
    def root_key(self, value):
        data = value.read() if hasattr(value, "read") else bytes(value or b"\x00" * 32)
        self._rks_root.write(data[:32])

    @property
    def message_num_send(self) -> int:
        """Send counter (alias for message_counter_send; settable for import)."""
        return self.message_counter_send

    @message_num_send.setter
    def message_num_send(self, value: int):
        self.message_counter_send = int(value)

    @property
    def message_counter_recv(self) -> int:
        """Alias for message_num_recv (used by test_master_protocol_verifier,
        test_state_fork_attack, test_final_boss)."""
        return self.message_num_recv

    @message_counter_recv.setter
    def message_counter_recv(self, value: int):
        self.message_num_recv = int(value)

    @property
    def chain_key_recv_init(self) -> "_RatchetKeyStore":
        """Original recv chain key (set at construction, never advanced).
        Use this for session-persistence export so the restored Rust ratchet
        starts at counter=0 and naturally advances to the correct position."""
        return self._rks_recv_init

    @property
    def chain_key_send_init(self) -> "_RatchetKeyStore":
        """Original send chain key (set at construction, never advanced)."""
        return self._rks_send_init

    def enable_pq(self):
        """Switch this ratchet to v2 (SPEC §5.2) before its first message.

        Both ends must do it, which they do when both signed profiles list
        PQ_RATCHET_VERSION. From then on the Rust ratchet carries an ML-KEM
        item on every message, binds it into the AAD and folds each new
        shared secret into the root step; the v1 brace methods below stand
        down, because a rotation from outside would desynchronise the ends.
        """
        with self.lock:
            self._rust.enable_pq_ratchet()
            self.pq = True

    def encrypt_message(self, plaintext):
        """Encrypt a message (Spec §4.4.3). Same return signature as Python."""
        with self.lock:
            now = time.time()
            if (
                self.message_counter_send >= self.rekey_interval
                or now - self.last_rekey_time > self.rekey_timeout
            ):
                _rekey_target = self.dh_ratchet_remote_pub or self.last_remote_pub
                if _rekey_target:
                    self._ratchet(_rekey_target)
                self.last_rekey_time = now

            if isinstance(plaintext, str):
                plaintext = plaintext.encode("utf-8")

            enc = self._rust.encrypt(plaintext)
            return self._sent(enc)

    def _sent(self, enc):
        """One encrypted message, in the shape every caller expects. The
        sixth item is the encoded `revealed_mac_keys` wire field (L1): the
        retired MAC keys cross from Rust only as those wire bytes."""
        if getattr(self, "pq", False):
            self._v2_item = (enc.get("kem_ek"), enc.get("kem_ct"))
        self.message_counter_send += 1
        self._sync_mirrors()
        return (
            enc["ciphertext"],
            enc["header"],
            enc["nonce"],
            enc["tag"],
            self._dh_epoch,
            enc["reveal_field"],
            enc["mac_key"],
        )

    # -- L1: the end of the session (SPEC §5.8) --------------------------

    def retire_all(self) -> int:
        """Delete every skipped message key and retire its MAC key, in Rust;
        from now on this ratchet decrypts nothing. Returns the count of
        retired MAC keys waiting to be published -- never the keys."""
        with self.lock:
            return int(self._rust.retire_all())

    def encrypt_final(self, plaintext):
        """A closing message carrying retired MAC keys (up to the decoder's
        limit). Call while `retired_mac_key_count` is non-zero; the ratchet
        encrypts nothing once they are all out. No rekey: the session ends."""
        with self.lock:
            if isinstance(plaintext, str):
                plaintext = plaintext.encode("utf-8")
            return self._sent(self._rust.encrypt_final(plaintext))

    @property
    def retired_mac_key_count(self) -> int:
        return int(self._rust.retired_mac_key_count)

    @property
    def closing(self) -> bool:
        return bool(self._rust.closing)

    def decrypt_message(self, header_bytes, ciphertext, nonce, tag, kem_ek=None, kem_ct=None):
        """Decrypt a message (OTRv4 §4.4.4).

        `kem_ek` / `kem_ct` are the message's ML-KEM item. A v2 ratchet
        authenticates and acts on it; a v1 ratchet never sees it (v1 handles
        the brace exchange after decryption, in process_incoming_kem_*).

        Returns ``(plaintext, mac_key)`` where ``mac_key`` is a Rust
        ``MessageMacKey`` handle, not bytes: the caller verifies the outer
        OTRv4 MAC through it and the key never becomes a Python object. The
        engine has already queued its own copy for later revelation.
        """
        with self.lock:

            hdr_dh_pub = None
            hdr_msg_num = None
            try:
                _rh = RatchetHeader.decode(header_bytes)
                hdr_dh_pub = _rh.dh_pub
                hdr_msg_num = _rh.msg_num
            except Exception:
                pass

            try:
                is_new_dh = self._rust.is_new_dh(header_bytes)

                if is_new_dh and self.dh_ratchet_remote_pub is not None:

                    pt, _mkmac = self._decrypt_new_dh(
                        header_bytes, ciphertext, nonce, tag, kem_ek, kem_ct)
                else:

                    if self.dh_ratchet_remote_pub is None:
                        dh_pub_h = self._rust.header_dh_pub(header_bytes)
                        if dh_pub_h is not None:

                            self.dh_ratchet_remote = None
                            self.dh_ratchet_remote_pub = dh_pub_h

                    _res = self._rust.decrypt_same_dh(
                        header_bytes, ciphertext, nonce, tag, **self._item_args(kem_ek, kem_ct))
                    pt, _mkmac = _res["plaintext"], _res["mac_key"]

                _did_dh_ratchet_recv = (
                    is_new_dh and self.dh_ratchet_remote_pub is not None and pt is not None
                )
                # A late message from an older chain (its skipped key still
                # held: the Rust is_new_dh said so) leaves the epoch mirrors
                # where they are -- it is not the start of one.
                late_old_chain = (not is_new_dh and hdr_dh_pub is not None
                                  and self._current_recv_dh_pub is not None
                                  and hdr_dh_pub != self._current_recv_dh_pub)
                if late_old_chain:
                    self.skipped_keys.pop((hdr_dh_pub, hdr_msg_num), None)
                elif hdr_dh_pub is not None and hdr_msg_num is not None:
                    new_epoch = (
                        self._current_recv_dh_pub is None or hdr_dh_pub != self._current_recv_dh_pub
                    )
                    if new_epoch:

                        for k in list(self.skipped_keys):
                            if k[0] != hdr_dh_pub:
                                self.skipped_keys.pop(k, None)
                        self._current_recv_dh_pub = hdr_dh_pub
                        self._next_expected_recv_num = 0

                    if hdr_msg_num > self._next_expected_recv_num:

                        for skipped in range(self._next_expected_recv_num, hdr_msg_num):
                            self.skipped_keys[(hdr_dh_pub, skipped)] = True
                        self._next_expected_recv_num = hdr_msg_num + 1
                    elif hdr_msg_num == self._next_expected_recv_num:
                        self._next_expected_recv_num = hdr_msg_num + 1
                    else:

                        self.skipped_keys.pop((hdr_dh_pub, hdr_msg_num), None)

                self.message_num_recv += 1
                self._sync_mirrors()
                return pt, _mkmac

            except Exception as e:
                raise EncryptionError(f"Decryption failed: {e }")

    def knows_revealed_mac_key(self, key: bytes) -> bool:
        """C2: did this endpoint independently derive the MAC key `key`?

        Delegates to the engine, which fingerprints every MKmac it derives --
        send side, receive side, and the skipped-message path. True means the
        peer revealed a key that really did authenticate a message on a chain
        both sides share. False means only that this endpoint cannot account
        for it; see _record_revealed_mac_keys for why that is not proof of
        misbehaviour.

        Only public values cross the boundary: a revealed key in, one bit out.
        """
        if isinstance(key, (bytes, bytearray, memoryview)):
            return bool(self._rust.knows_revealed_mac_key(bytes(key)))
        return bool(self._rust.knows_mac_key_handle(key))

    def _item_args(self, kem_ek, kem_ct):
        """The ML-KEM item for Rust: v2 only."""
        if not getattr(self, "pq", False):
            return {}
        return {"kem_ek": kem_ek, "kem_ct": kem_ct}

    def _decrypt_new_dh(self, header_bytes, ciphertext, nonce, tag, kem_ek=None, kem_ct=None):
        """Handle decrypt with DH ratchet step.

        Called only when is_new_dh=True AND dh_ratchet_remote_pub is not None
        (i.e. a genuine second or later DH epoch, not the first message).

        Both agreements -- ours-current with the header key (receive chain)
        and ours-next with it (send chain) -- happen inside Rust from the two
        key handles. Python passes handles and receives plaintext.
        """
        dh_pub = self._rust.header_dh_pub(header_bytes)

        new_local = _RustDAKE_module.generate_x448_keypair()
        new_local_pub = new_local.public_bytes()

        _res = self._rust.decrypt_new_dh(
            header_bytes, ciphertext, nonce, tag, self.dh_ratchet_local, new_local,
            **self._item_args(kem_ek, kem_ct)
        )

        if self.dh_ratchet_remote_pub is not None:
            self.last_remote_pub = self.dh_ratchet_remote_pub

        self.dh_ratchet_remote = None
        self.dh_ratchet_remote_pub = dh_pub
        self.dh_ratchet_local = new_local
        self.dh_ratchet_local_pub = new_local_pub

        self._dh_epoch += 1
        self.ratchet_id = self._dh_epoch
        self.message_counter_send = 0

        self._sync_mirrors()
        self.prepare_brace_rotation()
        return _res["plaintext"], _res["mac_key"]

    def _ratchet(self, dh_pub):
        """Send-side forced DH ratchet step. The agreement is Rust's."""
        with self.lock:

            new_local = _RustDAKE_module.generate_x448_keypair()
            self._rust.send_ratchet(new_local, dh_pub)
            self.dh_ratchet_local = new_local
            self.dh_ratchet_local_pub = new_local.public_bytes()

            self._dh_epoch += 1
            self.ratchet_id = self._dh_epoch
            self.message_counter_send = 0

            self._sync_mirrors()
            self.prepare_brace_rotation()

    def _sync_mirrors(self):
        """Refresh the observation mirrors from Rust's one-way state tags.

        See the class docstring: tags, not keys. A core too old to provide
        `state_tags` leaves the mirrors as they were rather than inventing
        values for them.
        """
        tags_of = getattr(self._rust, "state_tags", None)
        if tags_of is None:
            return
        tags = tags_of()
        self._rks_root.write(bytes(tags["root"]))
        self._rks_send.write(bytes(tags["chain_send"]))
        self._rks_recv.write(bytes(tags["chain_recv"]))
        self._brace_key = bytes(tags["brace"])

    def prepare_brace_rotation(self):
        if getattr(self, "pq", False):
            return
        if self._brace_kem_local is not None:
            return
        if self._brace_kem_ct_out is not None:
            return
        self._brace_kem_local = _RustDAKE_module.MlKem1024Keypair()
        self._brace_kem_ek_out = bytes(self._brace_kem_local.encap_key)

    def consume_outgoing_kem_ek(self):
        if getattr(self, "pq", False):
            ek, self._v2_item = self._v2_item[0], (None, self._v2_item[1])
            return ek
        ek = self._brace_kem_ek_out
        self._brace_kem_ek_out = None
        return ek

    def consume_outgoing_kem_ct(self):
        if getattr(self, "pq", False):
            ct, self._v2_item = self._v2_item[1], (self._v2_item[0], None)
            return ct
        ct = self._brace_kem_ct_out
        self._brace_kem_ct_out = None
        return ct

    def process_incoming_kem_ek(self, ek):
        """Encapsulate to the peer's brace key; the shared secret stays in Rust."""
        if getattr(self, "pq", False):
            return  # v2: the ratchet already acted on it, authenticated
        if len(ek) != MLKEM1024BraceKEM.EK_BYTES:
            raise ValueError(
                f"ML-KEM-1024 encap key must be {MLKEM1024BraceKEM .EK_BYTES } bytes, got {len (ek )}"
            )
        self._brace_kem_ct_out = bytes(self._rust.brace_encapsulate(bytes(ek)))
        self._sync_mirrors()

    def process_incoming_kem_ct(self, ct):
        """Decapsulate with our pending keypair, inside Rust, consuming it."""
        if getattr(self, "pq", False):
            return  # v2: the ratchet already acted on it, authenticated
        if self._brace_kem_local is None:
            raise ValueError("Received KEM ct but no local keypair pending")
        if len(ct) != MLKEM1024BraceKEM.CT_BYTES:
            raise ValueError(
                f"ML-KEM-1024 ciphertext must be {MLKEM1024BraceKEM .CT_BYTES } bytes, got {len (ct )}"
            )
        keypair = self._brace_kem_local
        self._brace_kem_local = None
        try:
            self._rust.brace_decapsulate(keypair, bytes(ct))
        finally:
            keypair.zeroize()
        self._sync_mirrors()

    def zeroize(self):
        """Destroy every secret this ratchet holds, then drop the handles.

        EXPLICIT, not left to reference counting. `self._rust = None` frees
        the Rust ratchet only if nothing else holds it -- a traceback frame, a
        test, a debugger -- and a wipe must not depend on that. So the Rust
        objects are told to zeroize themselves first: the ratchet replaces its
        keys (ZeroizeOnDrop runs on the old ones), the X448 handle zeroes its
        scalar in place, the pending ML-KEM keypair drops its decapsulation
        key. Releasing the Python references afterwards is only tidying.
        """
        with self.lock:
            for holder in (self._rust, self.dh_ratchet_local):
                if holder is not None:
                    try:
                        holder.zeroize()
                    except Exception:
                        pass
            self._rust = None
            self.dh_ratchet_local = None
            self.dh_ratchet_remote = None
            self.dh_ratchet_remote_pub = None
            self.last_remote_pub = None
            if self._brace_kem_local is not None:
                self._brace_kem_local.zeroize()
                self._brace_kem_local = None
            self._brace_kem_ek_out = None
            self._brace_kem_ct_out = None

            for store in (self._rks_send, self._rks_recv, self._rks_root):
                try:
                    store.zeroize()
                except Exception:
                    pass

    def __del__(self):
        try:
            self.zeroize()
        except Exception:
            pass


DoubleRatchet = RustBackedDoubleRatchet


def determine_roles(local_id_pub: bytes, remote_id_pub: bytes) -> bool:
    """Determine DAKE roles according to OTRv4 spec §4.2"""
    return local_id_pub < remote_id_pub


def _safe_b64decode(data: str) -> bytes:
    """Safely decode base64 with padding.

    v10.7 (Phase 5.3h-D): rescued to module scope from the deleted
    pure-Python OTRv4DAKE class.  Every caller now uses the bare
    _safe_b64decode(...) function name.
    """
    try:
        data = str(data).strip()
        if not data:
            raise ValueError("Empty base64 data")

        data = "".join(data.split())

        if "[" in data and "]" in data:
            end_bracket = data.rfind("]")
            if end_bracket != -1:
                data = data[end_bracket + 1 :].strip()

        # OTRv4 DATA frames are terminated with a trailing '.' (the encode path
        # emits  "?OTRv4 <b64url>." ).  DAKE frames have no terminator.  Strip
        # any trailing dots here so every caller can pass the raw frame body
        # without having to know whether this particular message type is dotted.
        data = data.rstrip(".")

        # A url-safe base64 body stripped of '=' padding can only be 0, 2 or 3
        # (mod 4) characters long.  A length of 1 (mod 4) is impossible for any
        # valid encoding and is the fingerprint of a body that was decoded with
        # the STANDARD alphabet (which silently discards '-' and '_').  Fail
        # loudly instead of letting the b64decode fallback swallow real chars.
        if len(data) % 4 == 1:
            raise ValueError(
                f"corrupt base64: {len (data )} chars is 1 (mod 4); "
                "url-safe '-'/'_' were likely dropped by a standard-alphabet decode"
            )

        try:
            padding_needed = -len(data) % 4
            if padding_needed:
                data = data + "=" * padding_needed
            return base64.urlsafe_b64decode(data)
        except Exception:
            data = data.replace("-", "+").replace("_", "/")
            padding_needed = -len(data) % 4
            if padding_needed:
                data = data + "=" * padding_needed
            return base64.b64decode(data)
    except Exception as e:
        try:
            import re as _re

            # Normalise url-safe alphabet to standard BEFORE stripping, so that
            # '-'/'_' become '+'/'/' rather than being discarded by b64decode.
            data = data.replace("-", "+").replace("_", "/")
            data = _re.sub(r"[^A-Za-z0-9+/=]", "", data)
            padding_needed = -len(data) % 4
            if padding_needed:
                data = data + "=" * padding_needed
            return base64.b64decode(data)
        except Exception as e2:
            raise ValueError(f"Base64 decode failed: {e }, also: {e2 }")


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

    #: Distinct peers tracked before pruning evicts the least recently seen.
    #:
    #: NECESSARY BECAUSE THE BUCKETS BECAME PER-PEER. While every caller shared
    #: the default key there was exactly one bucket and the table could not
    #: grow; keying on the peer turns it into one deque per distinct sender,
    #: kept forever. Measured on the unbounded version: 5000 unique peers left
    #: 5000 buckets and the map never shed a key.
    #:
    #: That would have traded a lockout for a slow memory exhaustion, which is
    #: not a fix. `otrv4plus_voice.RateLimiter` already had this problem and
    #: already solved it; the same two-stage approach is used here rather than
    #: a second one invented.
    MAX_TRACKED: int = 512

    def __init__(self):
        self._lock = threading.Lock()
        self._attempts: Dict[str, deque] = defaultdict(deque)
        self._last_prune: float = 0.0

    @staticmethod
    def _canonical(peer_key: str) -> str:
        """One person, one bucket, however their address is spelled.

        A rate limiter keyed on an un-normalised string can be widened by the
        peer it is limiting. Measured on the raw version, one contact spelled
        four ways produced four buckets and therefore four times the
        allowance:

            alice@x.test  Alice@X.test  alice@x.test/phone  alice@x.test/laptop

        Resource stripped and case folded, which is how every other layer of
        this project already identifies a peer -- `msg["from"].bare` in the
        XMPP client, `str(stanza["from"]).split("/", 1)[0]` in the Android
        transport, `AccountScope.normalise` and `ChatState.bare` in Kotlin.

        Done HERE rather than at the call sites deliberately: a future caller
        that forgets cannot split a bucket, and normalising in one place
        cannot drift between two. Folding is always the safe direction -- it
        can only merge allowance, never multiply it.

        An empty or unusable key keeps the historical "unknown" bucket rather
        than becoming its own per-caller namespace.
        """
        key = str(peer_key or "").strip().split("/", 1)[0].casefold()
        return key or "unknown"

    def _prune(self, now: float) -> None:
        """Bound the tracking table.

        Expiry first: a bucket with nothing left inside the window is free to
        drop and costs an attacker nothing to avoid. Then a hard cap evicting
        the least recently seen, because a flood of distinct senders inside a
        single window is all current and expiry alone would keep every one.

        THE CAP IS A DELIBERATE TRADE, and the reasoning differs from the
        voice limiter's. There, reaching the limiter costs an attacker a full
        OTR session per identity. DAKE1 is pre-session, so anyone who can get
        a stanza to us can create a bucket -- eviction is cheaper to force
        here, and the cap matters more.

        What eviction actually costs is small: a real peer pushed out regains
        a fresh allowance, which is no worse than the behaviour this whole
        change replaces, where every peer permanently shared one allowance.
        Unbounded memory is the worse failure.
        """
        cutoff = now - self.WINDOW_SECONDS
        for key in [k for k, dq in self._attempts.items()
                    if not dq or dq[-1] < cutoff]:
            self._attempts.pop(key, None)
        if len(self._attempts) > self.MAX_TRACKED:
            ordered = sorted(self._attempts.items(),
                             key=lambda kv: kv[1][-1] if kv[1] else 0.0)
            for key, _dq in ordered[:len(self._attempts) - self.MAX_TRACKED]:
                self._attempts.pop(key, None)
        self._last_prune = now

    def is_allowed(self, peer_key: str) -> bool:
        """Return True and record the attempt if the peer is within quota."""
        now = time.monotonic()
        cutoff = now - self.WINDOW_SECONDS
        key = self._canonical(peer_key)
        with self._lock:
            if (now - self._last_prune > self.WINDOW_SECONDS
                    or len(self._attempts) > self.MAX_TRACKED):
                self._prune(now)
            dq = self._attempts[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.MAX_ATTEMPTS:
                return False
            dq.append(now)
            return True

    def reset(self, peer_key: str) -> None:
        """Clear the rate-limit bucket for a peer.

        NOT CALLED FROM PRODUCTION, AND DELIBERATELY STILL NOT. The
        parenthetical this docstring used to carry -- "call after DAKE
        success" -- described an intention that was never implemented, and
        implementing it now would weaken the control rather than complete it:
        a completed DAKE costs MORE responder CPU than a rejected DAKE1, so
        clearing the budget on success hands unlimited DAKE1 processing to any
        peer able to finish one handshake. Nothing in the tests, the
        changelog or the M-4 note establishes that as intended.

        Its real use is test hygiene -- `tests/test_otrv4_integration.py` and
        `tests/test_smp_android_interop.py` clear state between handshakes so
        they measure the protocol rather than the quota -- and it keeps that
        use unchanged.
        """
        with self._lock:
            self._attempts.pop(self._canonical(peer_key), None)


_dake1_rate_limiter = DAKE1RateLimiter()


class RustDAKEAdapter:
    """
    DAKE engine that uses Rust internals (otrv4_core.RustDAKE) when available.

    v10.7: the Rust otrv4_core.RustDAKE backend is mandatory.  The
    yet, behaviour is identical to the pre-migration version.

    When Rust IS available:
      - X448 ephemeral keys generated in Rust
      - DH exchanges (dh1/dh2/dh3) done in Rust, result never returned to Python
      - ML-KEM-1024 encaps/decaps done in Rust
      - KDF_1 session key derivation done in Rust
      - DAKE3 signed and verified in Rust over its own transcript

    Rust DAKE is the only DAKE implementation; there is no fallback.
    """

    def __init__(
        self,
        client_profile: Optional["ClientProfile"] = None,
        explicit_initiator: bool = False,
        tracer: Optional["OTRTracer"] = None,
        logger: Optional["OTRLogger"] = None,
    ):

        self._tracer = tracer
        self._logger = logger or NullLogger()
        self._is_initiator = explicit_initiator
        self.client_profile = client_profile or ClientProfile()

        self._rust = None

        if RUST_DAKE_AVAILABLE and _RustDAKE is not None:
            try:

                _profile_bytes = self.client_profile.encode()

                if (
                    self.client_profile.identity_pub_bytes is None
                    and self.client_profile.identity_key is not None
                ):
                    self.client_profile.identity_pub_bytes = bytes(
                        self.client_profile.identity_key.public_bytes()
                    )
                if (
                    self.client_profile.prekey_pub_bytes is None
                    and self.client_profile.prekey is not None
                ):
                    self.client_profile.prekey_pub_bytes = bytes(
                        self.client_profile.prekey.public_bytes()
                    )

                _mldsa_priv = None
                _mldsa_pub = None

                _unsigned_body = self.client_profile.encode_unsigned()

                self._rust, _sig_py = _RustDAKE.sign_profile_body_and_construct_with_handles(
                    explicit_initiator,
                    _profile_bytes,
                    _unsigned_body,
                    self.client_profile.identity_key,
                    self.client_profile.prekey,
                    _mldsa_priv,
                    _mldsa_pub,
                )

                _sig = bytes(_sig_py)
                if len(_sig) != OTRConstants.ED448_SIGNATURE_SIZE:
                    raise ValueError(
                        f"sign_profile_body_and_construct_with_handles returned "
                        f"signature of wrong length: {len (_sig )} "
                        f"(expected {OTRConstants .ED448_SIGNATURE_SIZE })"
                    )

                if self.client_profile.signature != _sig:
                    raise ValueError(
                        "sign_profile_body_and_construct_with_handles produced "
                        "a different signature than ClientProfile.encode() - "
                        "Ed448 determinism violated, refusing to construct adapter"
                    )

                if logger:
                    logger.debug(
                        "RustDAKEAdapter: using Rust DAKE backend "
                        "(Phase 5.3e: Rust-owned identity key handles, "
                        "single-call sign+construct, no Python-heap private bytes)"
                    )
            except Exception as _rust_err:

                if logger:
                    logger.debug(f"RustDAKEAdapter: Rust init failed ({_rust_err })")
                raise RuntimeError(
                    f"RustDAKEAdapter: Rust DAKE construction failed ({_rust_err }).  "
                    f"v10.6.11+ has no Python fallback - the Rust core must be "
                    f"functional for the protocol to operate."
                )

        self._state: DAKEState = DAKEState.IDLE
        self._session_created_at: float = 0.0
        self._session_max_age: float = 86400.0
        #: Seconds a handshake may stay half-open (is_expired). Monotonic
        #: clock: a wall-clock change cannot age or rejuvenate a handshake.
        self.timeout: float = UIConstants.DAKE_TIMEOUT
        self._handshake_started_at: float = 0.0

        self.remote_identity_pub_bytes: Optional[bytes] = None
        self.remote_identity_key = None
        self.remote_profile: Optional["ClientProfile"] = None

        # The profile's long-term ML-DSA key when the manager gave it one
        # (A2: a key made per handshake authenticates nothing), else a fresh
        # one for this handshake. Only a key made here is destroyed here.
        self._mldsa_auth: Optional["MLDSA87Auth"] = getattr(
            self.client_profile, "mldsa_identity", None)
        self._owns_mldsa = self._mldsa_auth is None
        self._remote_mldsa_pub: Optional[bytes] = None
        if self._mldsa_auth is None and MLDSA87_AVAILABLE:
            try:
                self._mldsa_auth = MLDSA87Auth()
            except Exception:
                self._mldsa_auth = None

        self._raw_dake1_bytes: Optional[bytes] = None
        self._raw_dake2_bytes: Optional[bytes] = None

        if tracer:
            tracer.trace(
                "DAKE",
                "INIT",
                None,
                "IDLE",
                f"DAKE engine initialized, initiator={explicit_initiator }",
            )

    def zeroize(self) -> None:
        """Destroy this handshake's secrets inside Rust. Idempotent.

        The ephemeral X448 scalar, the ML-KEM decapsulation key and the
        identity copies inside `RustDAKE`; any `DakeOutput` produced but not
        yet consumed into a ratchet (a handshake abandoned between DAKE2 and
        DAKE3); and the ML-DSA-87 signing key. `DakeOutput` is unsendable, so
        this must run on the thread that drove the handshake -- the caller is
        responsible for that, and `EnhancedSessionManager.wipe` documents it.
        """
        keys = getattr(self, "_session_keys", None)
        output = keys.get("_dake_output") if isinstance(keys, dict) else None
        if output is not None:
            try:
                output.discard()
            except Exception:
                pass
        self._session_keys = None
        rust = getattr(self, "_rust", None)
        if rust is not None and hasattr(rust, "zeroize"):
            try:
                rust.zeroize()
            except Exception:
                pass
        auth = getattr(self, "_mldsa_auth", None)
        if auth is not None and getattr(self, "_owns_mldsa", True):
            try:
                auth.zeroize()
            except Exception:
                pass
        self._mldsa_auth = None

    @property
    def state(self) -> DAKEState:
        return self._state

    @property
    def pq_auth(self) -> bool:
        """Both signed profiles list PQ_AUTH_VERSION (A2)."""
        return bool(getattr(self._rust, "pq_auth", False))

    @property
    def verified_peer_mldsa_pub(self) -> Optional[bytes]:
        """The peer's ML-DSA key, when it signed this handshake under v2."""
        if self.pq_auth and getattr(self._rust, "peer_mldsa_verified", False):
            return self._remote_mldsa_pub
        return None

    @property
    def is_initiator(self) -> bool:
        return self._is_initiator

    def is_established(self) -> bool:
        return self._state == DAKEState.ESTABLISHED

    def has_failed(self) -> bool:
        return self._state == DAKEState.FAILED

    def is_session_expired(self) -> bool:
        if self._state != DAKEState.ESTABLISHED:
            return False
        if self._session_created_at == 0.0:
            return False
        return (time.time() - self._session_created_at) > self._session_max_age

    def is_expired(self) -> bool:
        """Whether this handshake has been half-open longer than [timeout].

        Only a handshake in flight can expire: IDLE has not started, and an
        ESTABLISHED session's age is is_session_expired's question. FAILED is
        already over. tests/test_dake_timeout.py.
        """
        if self._state in (DAKEState.IDLE, DAKEState.ESTABLISHED, DAKEState.FAILED):
            return False
        if self._handshake_started_at == 0.0:
            return False
        return (time.monotonic() - self._handshake_started_at) > self.timeout

    def get_state(self) -> DAKEState:
        return self.state

    def _trace(self, *args):
        if self._tracer:
            try:
                self._tracer.trace(*args)
            except Exception:
                pass

    def _log_debug(self, msg: str):
        try:
            self._logger.debug(msg)
        except Exception:
            pass

    def _log_error(self, msg: str):
        try:
            self._logger.error(msg)
        except Exception:
            pass

    def _fail(self, reason: str) -> bool:
        _prior = self._state.name if hasattr(self, "_state") else "NONE"
        self._state = DAKEState.FAILED
        self._trace("DAKE", "STATE", _prior, "FAILED", reason)
        self._log_error(reason)
        return False

    def generate_dake1(self) -> str:
        """Generate DAKE1 as initiator. Rust path: X448 key generated in Rust."""

        try:

            raw = bytes(
                self._rust.generate_dake1(
                    mldsa_pub_bytes=self._mldsa_auth.pub_bytes if self._mldsa_auth else None
                )
            )
            self._raw_dake1_bytes = raw
            self._state = DAKEState.SENT_DAKE1
            self._handshake_started_at = time.monotonic()
            self._trace("DAKE", "STATE", "IDLE", "SENT_DAKE1", "generated DAKE1 (Identity)")
            encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
            return f"?OTRv4 {encoded }"
        except Exception as e:
            self._fail(f"generate_dake1 failed: {e }")
            raise

    def process_dake1(self, dake1_msg: str, peer_key: str = "unknown") -> bool:
        """Process DAKE1 as responder. Rust parses everything."""

        if not _dake1_rate_limiter.is_allowed(peer_key):
            self._log_debug(f"DAKE1 rate limit for {peer_key }")
            return False

        try:
            if not dake1_msg.startswith("?OTRv4 "):
                return self._fail("process_dake1: not an OTRv4 message")
            raw = _safe_b64decode(dake1_msg[7:].strip())
            self._raw_dake1_bytes = raw
            self._log_debug(
                f"process_dake1: raw={len (raw )} bytes, first4={raw [:4 ].hex () if len (raw )>=4 else raw .hex ()}"
            )

            result = self._rust.process_dake1(raw)
            if not result.success:
                return self._fail(f"process_dake1: {result .error }")

            self.remote_identity_pub_bytes = (
                bytes(result.remote_identity_pub) if result.remote_identity_pub else None
            )
            self._remote_mldsa_pub = (
                bytes(result.remote_mldsa_pub) if result.remote_mldsa_pub else None
            )

            if self.remote_identity_pub_bytes:

                self.remote_identity_key = self.remote_identity_pub_bytes

            if result.remote_profile_bytes:
                try:
                    self.remote_profile = ClientProfile.decode(bytes(result.remote_profile_bytes))
                except Exception:
                    self.remote_profile = None

            # ── Audit H3 (defense in depth): reject a DAKE1 whose initiator
            # ClientProfile does not verify.  This is already backstopped by
            # the remote_profile None-checks in generate_dake2 and
            # process_dake3, but failing here keeps the responder from doing
            # any further work on an unverified profile.
            if self.remote_profile is None:
                return self._fail(
                    "DAKE1: initiator ClientProfile verification failed "
                    "(bad signature, expiry, or downgrade)"
                )

            self._state = DAKEState.RECEIVED_DAKE1
            self._handshake_started_at = time.monotonic()
            self._trace("DAKE", "STATE", "IDLE", "RECEIVED_DAKE1", "received DAKE1 (Identity)")
            self._log_debug("DAKE1 (Identity) processed successfully")
            return True

        except Exception as e:
            return self._fail(f"process_dake1 exception: {e }")

    def generate_dake2(self) -> Optional[str]:
        """
        Generate DAKE2 as responder.
        Rust path:
          - generates own X448 ephemeral in Rust
          - performs dh1/dh2/dh3 in Rust (never returned)
          - encapsulates to initiator's ML-KEM ek in Rust
          - derives all session keys in Rust
          - returns (raw_dake2_bytes, session_keys_dict)
            where session_keys_dict contains only derived key material
            (root_key, chain_key_send, chain_key_recv, mac_key, brace_key, ssid)
        """

        try:

            output = self._rust.generate_dake2_output(
                our_prekey_priv_bytes=None,
                mldsa_pub_bytes=self._mldsa_auth.pub_bytes if self._mldsa_auth else None,
                mldsa_handle=self._mldsa_auth._priv if self._mldsa_auth else None,
            )
            raw = bytes(output.dake2_bytes)
            self._raw_dake2_bytes = raw

            self._session_keys = {
                "_dake_output": output,
                "session_id": bytes(output.ssid) + b"\x00" * 24,
                "is_initiator": False,
                "peer_long_term_pub": self.remote_identity_pub_bytes,
                "peer_long_term_key": self.remote_identity_key,
            }

            self._state = DAKEState.SENT_DAKE2
            self._trace("DAKE", "STATE", "RECEIVED_DAKE1", "SENT_DAKE2", "generated DAKE2 (Auth-R)")
            self._log_debug("DAKE2 (Auth-R) generated successfully")

            encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
            return f"?OTRv4 {encoded }"

        except Exception as e:
            return self._fail_str(f"generate_dake2 exception: {e }")

    def _fail_str(self, reason: str) -> None:
        self._fail(reason)
        return None

    def process_dake2(self, dake2_msg: str) -> bool:
        """
        Process DAKE2 as initiator. Rust parses everything.
        """

        try:
            if not dake2_msg.startswith("?OTRv4 "):
                return self._fail("process_dake2: not an OTRv4 message")
            raw = _safe_b64decode(dake2_msg[7:].strip())
            self._raw_dake2_bytes = raw

            output = self._rust.process_dake2_output(raw, None)

            self.remote_identity_pub_bytes = (
                bytes(output.remote_identity_pub) if output.remote_identity_pub else None
            )
            self._remote_mldsa_pub = (
                bytes(output.remote_mldsa_pub) if output.remote_mldsa_pub else None
            )

            if self.remote_identity_pub_bytes:

                self.remote_identity_key = self.remote_identity_pub_bytes

            if output.remote_profile_bytes:
                try:
                    self.remote_profile = ClientProfile.decode(
                        bytes(output.remote_profile_bytes)
                    )
                except Exception:
                    self.remote_profile = None

            self._session_keys = {
                "_dake_output": output,
                "session_id": bytes(output.ssid) + b"\x00" * 24,
                "is_initiator": True,
                "peer_long_term_pub": self.remote_identity_pub_bytes,
                "peer_long_term_key": self.remote_identity_key,
            }

            # ── Audit PY1/H3: never establish on an unverified responder
            # profile.  ClientProfile.decode (above) verifies the Ed448
            # self-signature, which covers the prekey, AND the expiry.  If it
            # raised, remote_profile is None and we MUST abort. The Rust DAKE
            # now enforces the same three things itself -- the signature
            # (H3), the expiry and a non-degenerate identity key (audit
            # 2026-09, dake.rs extract_identity_from_profile) -- so this is a
            # second, independent check, not the only one.
            if self.remote_profile is None:
                return self._fail(
                    "DAKE2: responder ClientProfile verification failed "
                    "(bad signature, expiry, or downgrade) - refusing to establish"
                )
            # Bind the trusted identity to the VERIFIED profile, not the
            # unverified Rust extraction, and confirm the two agree.
            _verified_id = self.remote_profile.identity_pub_bytes
            if (
                self.remote_identity_pub_bytes is not None
                and not hmac.compare_digest(self.remote_identity_pub_bytes, _verified_id)
            ):
                return self._fail(
                    "DAKE2: extracted identity key does not match the signed profile"
                )
            self.remote_identity_pub_bytes = _verified_id
            self.remote_identity_key = _verified_id

            self._state = DAKEState.ESTABLISHED
            self._session_created_at = time.time()
            self._trace(
                "DAKE",
                "STATE",
                "SENT_DAKE1",
                "ESTABLISHED",
                "DAKE2 (Auth-R) processed successfully",
            )
            self._log_debug("DAKE2 (Auth-R) processed successfully")
            return True

        except Exception as e:
            return self._fail(f"process_dake2 exception: {e }")

    def generate_dake3(self) -> Optional[str]:
        """Generate DAKE3 as initiator -- signed inside Rust.

        `RustDAKE.generate_dake3` computes the Auth-I message from the
        transcript it recorded itself (KDF_1(0x05, DAKE1 || DAKE2)), ring-signs
        it with the identity key it holds, adds the ML-DSA-87 signature
        through the handle when the responder committed an ML-DSA key, and
        assembles the wire bytes. Nothing here computes or signs anything, and
        there is no fallback: a DAKE3 Rust will not produce is not sent.
        """
        try:
            handle = self._mldsa_auth._priv if self._mldsa_auth is not None else None
            assembled = bytes(self._rust.generate_dake3(mldsa_handle=handle))
            encoded = base64.urlsafe_b64encode(assembled).decode("ascii").rstrip("=")
            self._log_debug(f"DAKE3 (Auth-I) generated: {len (assembled )}B total")
            return f"?OTRv4 {encoded }"
        except Exception as e:
            self._log_error(f"DAKE3 (Auth-I) generation failed: {e }")
            return None

    def process_dake3(self, dake3_msg: str) -> bool:
        """Process DAKE3 as responder -- verified inside Rust.

        `RustDAKE.process_dake3` checks the ring signature and, when the
        initiator committed an ML-DSA-87 key, the mandatory ML-DSA signature
        (refusing a stripped flag), both over its own transcript, and only
        then moves to established. This method decodes the frame and mirrors
        the outcome; it makes no security decision of its own.
        """
        try:
            if not dake3_msg.startswith("?OTRv4 "):
                return self._fail("process_dake3: not an OTRv4 message")
            decoded = _safe_b64decode(dake3_msg[7:].strip())
            try:
                hybrid = bool(self._rust.process_dake3(decoded))
            except Exception as e:
                return self._fail(f"DAKE3 refused: {e }")
            _pq_auth = ("hybrid (ring-sig ✓ + ML-DSA-87 ✓)" if hybrid
                        else "classical only (ring-sig ✓)")
            self._state = DAKEState.ESTABLISHED
            self._session_created_at = time.time()
            self._trace(
                "DAKE", "STATE", "SENT_DAKE2", "ESTABLISHED", f"DAKE3 verified - {_pq_auth }"
            )
            self._log_debug(f"DAKE3 (Auth-I) verified - {_pq_auth }")
            return True
        except Exception as e:
            return self._fail(f"process_dake3 exception: {e }")

    def get_session_keys(self) -> Optional[Dict[str, Any]]:
        if self._state != DAKEState.ESTABLISHED:
            return None
        keys = getattr(self, "_session_keys", None)
        if keys is None:
            return None
        return keys.copy()


def _remove_retired_key_storage(storage_dir: Optional[str]) -> None:
    """Remove what the retired `SecureKeyStorage` left behind.

    It wrote one record -- `profile.client.bin`, the PUBLIC client profile,
    AES-GCM sealed under a key derived in Python from `.device_seed` -- and
    nothing ever read it back. The store is gone, so the seed and the record
    protect nothing; leaving them would leave a key file on disk that the
    documentation no longer mentions. Only those two names are touched.
    """
    if not storage_dir:
        return
    for name in (".device_seed", "profile.client.bin"):
        path = os.path.join(storage_dir, name)
        try:
            if os.path.isfile(path) and not os.path.islink(path):
                _secure_file_destroy(path)
        except Exception:
            pass
    try:
        os.rmdir(storage_dir)        # only if now empty
    except OSError:
        pass


class SMPAutoRespondStorage:
    """Per-peer SMP auto-respond passphrases -- held by the Rust core.

    A thin handle on `otrv4_core.SmpSecretStore`. It used to be the store
    itself: it read `.smp_seed` into Python, derived the file key with
    argon2-cffi (or scrypt) in Python, decrypted a JSON file into a Python dict
    of `{peer: passphrase}` that lived as long as the process, and handed
    passphrases out through `get_secret()`. Now the seed, the key and the
    passphrases are Rust memory; this class can say WHETHER a passphrase is
    stored and bind it into a session, and has no way to return one.

    AUTO-RESPOND IS AN EXPLICIT USER CHOICE. A passphrase is only here because
    the terminal user stored it for that peer (`/smp-secret`, or `/smp` with a
    secret, on the clients that persist). Later sessions with that peer bind it
    because that is what the user asked for. The Android bridge never writes
    here (`bind_smp_secret`); tests/test_wipe_and_exit.py holds that.

    `secrets_path=None` keeps the store in memory only.
    """

    def __init__(self, secrets_path: Optional[str] = None, *, memory_only: bool = False):
        import otrv4_core as _core
        self._lock = threading.RLock()
        self.secrets_path = None if memory_only else (
            secrets_path or os.path.expanduser("~/.otrv4plus/smp_secrets.json"))
        if self.secrets_path:
            try:
                _smp_dir = os.path.dirname(self.secrets_path)
                if _smp_dir:
                    os.makedirs(_smp_dir, exist_ok=True)
                    os.chmod(_smp_dir, 0o700)
            except Exception:
                pass
        self._store = _core.SmpSecretStore(self.secrets_path)
        moved = self._store.legacy_unreadable
        if moved:
            print("[smp] WARNING: the stored auto-respond passphrases could not "
                  "be read and were moved aside to %s. Store them again with "
                  "/smp-secret." % moved, file=sys.stderr)

    def set_secret(self, peer: str, secret) -> None:
        """Store `secret` (str, or a bytearray this zeroes) for `peer`."""
        with self._lock:
            self._store.set(peer, secret)

    def has_secret(self, peer: str) -> bool:
        with self._lock:
            return self._store.has(peer)

    def remove_secret(self, peer: str) -> bool:
        with self._lock:
            return self._store.remove(peer)

    def peers(self) -> List[str]:
        with self._lock:
            return list(self._store.peers())

    def bind_into(self, peer: str, session) -> bool:
        """Bind `peer`'s stored passphrase into `session`'s Rust SMP engine.

        False when none is stored. The passphrase goes store -> vault -> SMP
        inside Rust.
        """
        with self._lock:
            if not self._store.has(peer):
                return False
            return bool(session.set_smp_secret_from_store(self._store, peer))

    def clear_memory(self) -> None:
        """Forget every passphrase in memory (the file is the wipe's job)."""
        with self._lock:
            self._store.clear_memory()

    def clear_all(self) -> None:
        """Forget every passphrase, in memory and on disk."""
        with self._lock:
            self._store.clear()


class TrustDatabase:
    """Persistent fingerprint trust database with TOFU and downgrade prevention.

    Security properties:
    - TOFU (Trust On First Use): first seen fingerprint is pinned.
    - Fingerprint mismatch raises FingerprintMismatchError - callers must abort.
    - Trust can only be *upgraded* (untrusted→trusted), never silently downgraded.
    - Atomic fsync'd writes prevent partial-state corruption.
    - All comparisons use constant-time operations.
    """

    class FingerprintMismatchError(ValueError):
        """Raised when a peer's fingerprint changes from the stored trusted value."""

        def __init__(self, peer: str, stored: str, received: str):
            self.peer = peer
            self.stored = stored
            self.received = received
            super().__init__(
                f"FINGERPRINT MISMATCH for {peer }! "
                f"Stored: {stored [:16 ]}… Got: {received [:16 ]}… "
                "This may indicate a MITM attack. Session aborted."
            )

    def __init__(self, db_path: Optional[str] = None, persistent: bool = True):
        """`persistent` false keeps the whole database in memory for this process.

        That is the IRC mode, and it is not a degraded version of the XMPP one.
        An IRC identity is regenerated every run by design, so a fingerprint
        written to disk can never match anything on a later run -- it can only
        accumulate, and worse, `add_trust` raises FingerprintMismatchError when
        it does not match, which turned every reconnect with a previously
        trusted nick into a "This may indicate a MITM attack" line.  Training a
        user to dismiss that message costs more than the record was ever worth.

        In-memory still means a `y` answer sticks for the rest of the session,
        so a reconnect inside one run does not re-prompt.  Nothing survives
        exit, which is the honest representation of what an ephemeral identity
        can promise.
        """
        self._lock = threading.RLock()
        self.persistent = bool(persistent)
        self.db_path = db_path or os.path.expanduser("~/.otrv4plus/trust.json")
        self._db: Dict[str, dict] = {}
        if self.persistent:
            self._load()

    def _load(self):
        """Load database from disk with error handling"""
        with self._lock:
            if not self.persistent:
                self._db = {}
                return
            if not os.path.exists(self.db_path):
                self._db = {}
                return
            try:
                with open(self.db_path, "r") as f:
                    raw = json.load(f)
                migrated = {}
                for k, v in raw.items():
                    if isinstance(v, str):
                        migrated[k] = {"fingerprint": v, "trusted": True}
                    elif isinstance(v, dict):
                        migrated[k] = v
                    else:
                        continue
                self._db = migrated
            except (json.JSONDecodeError, IOError, OSError) as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Error loading: {e }")
                self._db = {}
            except Exception as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Unexpected error loading: {e }")
                self._db = {}

    def _save(self):
        """Save database to disk atomically with error handling"""
        if not self.persistent:
            # In-memory mode: the trust map lives and dies with the
            # process. Writing here would recreate exactly the file
            # this mode exists to not create.
            return
        with self._lock:
            try:
                _db_dir = os.path.dirname(self.db_path) or "."
                os.makedirs(_db_dir, exist_ok=True)
                try:
                    os.chmod(_db_dir, 0o700)
                except Exception:
                    pass
                _tmp_path2 = None
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    dir=os.path.dirname(self.db_path) or ".",
                    delete=False,
                    encoding="utf-8",
                ) as f:
                    _tmp_path2 = f.name
                    json.dump(self._db, f, indent=2, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(_tmp_path2, 0o600)
                os.replace(_tmp_path2, self.db_path)
            except (IOError, OSError, PermissionError) as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Error saving: {e }")
                if _tmp_path2:
                    try:
                        os.unlink(_tmp_path2)
                    except Exception:
                        pass
            except Exception as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Unexpected error saving: {e }")
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
                    self._set_entry(peer, fingerprint, False)
                    self._save()
                    return False

                stored_fp = entry.get("fingerprint", "")
                if not stored_fp:
                    self._set_entry(peer, fingerprint, False)
                    self._save()
                    return False

                if not hmac.compare_digest(stored_fp.encode("utf-8"), fingerprint.encode("utf-8")):
                    raise TrustDatabase.FingerprintMismatchError(peer, stored_fp, fingerprint)

                return entry.get("trusted", False)

            except TrustDatabase.FingerprintMismatchError:
                raise
            except (KeyError, AttributeError, TypeError) as e:
                raise ValueError(f"Invalid trust database entry: {e }")
            except Exception as e:
                raise RuntimeError(f"Trust database error: {e }")

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
                stored_fp = entry.get("fingerprint", "")
                if not stored_fp:
                    return False
                if not hmac.compare_digest(stored_fp.encode("utf-8"), fingerprint.encode("utf-8")):
                    return False
                return entry.get("trusted", False)
            except (KeyError, AttributeError, TypeError):
                return False
            except Exception:
                return False

    def _set_entry(self, peer: str, fingerprint: str, trusted: bool) -> None:
        """Write the fingerprint pin, keeping the peer's ML-DSA pin (`pq`)."""
        entry = {"fingerprint": fingerprint, "trusted": trusted}
        pq = (self._db.get(peer) or {}).get("pq")
        if pq:
            entry["pq"] = pq
        self._db[peer] = entry

    class PqIdentityRefused(ValueError):
        """A peer that authenticated with ML-DSA before did not, or used
        another ML-DSA key, under the same Ed448 identity (audit A2).

        `code` is `pq_downgrade` or `pq_key_changed`. Either is what an active
        attacker able to forge Ed448 looks like, so the handshake is refused,
        not merely flagged: the Ed448 fingerprint the user checks would match.
        """

        def __init__(self, peer: str, code: str):
            self.peer = peer
            self.code = code
            what = ("did not authenticate with its post-quantum key"
                    if code == "pq_downgrade" else "used a different post-quantum key")
            super().__init__(
                f"{peer } {what } under an identity that has used one before. "
                "Handshake refused. If the contact reinstalled or went back to "
                "an older version, confirm with them and reset trust for them.")

    def check_or_pin_pq(self, peer: str, identity_pub: bytes,
                        mldsa_pub: Optional[bytes], pq_auth: bool) -> None:
        """Pin a peer's ML-DSA key on its first v2 handshake; refuse a later
        handshake under the same Ed448 identity that drops it or changes it.

        Keyed by the Ed448 identity: a peer with a new identity is the ordinary
        fingerprint change (check_or_pin) and gets a new ML-DSA pin from its
        next v2 handshake. Only a key that signed a v2 handshake is pinned; a
        v1 peer's key is made per handshake and pins nothing.
        """
        if not peer or not identity_pub:
            raise ValueError("Peer and identity cannot be empty")
        ident = hashlib.sha3_256(bytes(identity_pub)).hexdigest()
        key = hashlib.sha3_256(bytes(mldsa_pub)).hexdigest() if (pq_auth and mldsa_pub) else None
        with self._lock:
            entry = self._db.get(peer) or {}
            pin = entry.get("pq") or {}
            same_identity = hmac.compare_digest(pin.get("identity", "").encode(), ident.encode())
            if not pin or not same_identity:
                if key is not None:
                    entry = dict(entry)
                    entry["pq"] = {"identity": ident, "mldsa": key}
                    self._db[peer] = entry
                    self._save()
                return
            if key is None:
                raise TrustDatabase.PqIdentityRefused(peer, "pq_downgrade")
            if not hmac.compare_digest(pin.get("mldsa", "").encode(), key.encode()):
                raise TrustDatabase.PqIdentityRefused(peer, "pq_key_changed")

    def add_trust(self, peer: str, fingerprint: str) -> bool:
        """Mark a (peer, fingerprint) pair as trusted.

        If a different fingerprint is already stored, raises FingerprintMismatchError
        - we never silently replace a known fingerprint.
        """
        if not peer or not fingerprint:
            raise ValueError("Peer and fingerprint cannot be empty")

        if not isinstance(peer, str) or not isinstance(fingerprint, str):
            raise TypeError("Peer and fingerprint must be strings")

        with self._lock:
            try:
                entry = self._db.get(peer)
                if entry is not None:
                    stored_fp = entry.get("fingerprint", "")
                    if stored_fp and not hmac.compare_digest(
                        stored_fp.encode("utf-8"), fingerprint.encode("utf-8")
                    ):
                        raise TrustDatabase.FingerprintMismatchError(peer, stored_fp, fingerprint)
                self._set_entry(peer, fingerprint, True)
                self._save()
                return True
            except TrustDatabase.FingerprintMismatchError:
                raise
            except (KeyError, AttributeError, TypeError) as e:
                raise ValueError(f"Invalid trust database entry: {e }")
            except Exception as e:
                raise RuntimeError(f"Failed to add trust: {e }")

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
                    print(f"[TrustDatabase] Error removing trust: {e }")
                return False
            except Exception as e:
                if DEBUG_MODE:
                    print(f"[TrustDatabase] Unexpected error removing trust: {e }")
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
                if not entry.get("trusted", False):
                    return ""
                return entry.get("fingerprint", "")
            except (KeyError, AttributeError):
                return ""
            except Exception:
                return ""

    def list_trusted(self) -> Dict[str, str]:
        """List all trusted peers and their fingerprints"""
        with self._lock:
            try:
                return {p: e["fingerprint"] for p, e in self._db.items() if e.get("trusted")}
            except (KeyError, AttributeError, TypeError):
                return {}
            except Exception:
                return {}


class TabBar:
    """Visual tab bar at top of terminal with Termux optimization"""

    def __init__(self, terminal_width: int = TERMINAL_WIDTH):
        self.terminal_width = terminal_width
        self.visible_start = 0
        self.tab_data: Dict[str, dict] = {}

    def calculate_tab_width(self, tab_name: str, has_unread: int, is_active: bool) -> int:
        """Calculate width needed for a tab"""
        width = len(tab_name) + 2

        if "🔵" in tab_name or "🟢" in tab_name or "🟡" in tab_name or "🔴" in tab_name:
            width += 2

        if has_unread > 0:
            width += len(f"({has_unread })") + 1

        width += 1

        return width

    def render(self, panels: Dict[str, "ChatPanel"], active_panel_name: str) -> List[str]:
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
                display_name = f"{display_name }{icon }"

            is_active = panel_name == active_panel_name

            self.tab_data[panel_name] = {
                "display_name": display_name,
                "icon": icon,
                "unread": panel.unread_count,
                "active": is_active,
                "width": self.calculate_tab_width(display_name, panel.unread_count, is_active),
            }

            tabs.append(panel_name)

        total_tabs_width = sum(self.tab_data[tab]["width"] for tab in tabs)
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

                if current_width + tab_info["width"] > max_tabs_width - 6:
                    break

                visible_tabs.append(tab_name)
                current_width += tab_info["width"]

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
            display_name = tab_info["display_name"]
            unread = tab_info["unread"]
            is_active = tab_info["active"]

            if unread > 0:
                tab_display = f"{display_name }({unread })"
            else:
                tab_display = display_name

            if is_active:
                tab_str = f"{colorize ('['+tab_display +']','bg_green')}"
            elif unread > 0:

                _hl = "magenta" if not tab_name.startswith("#") else "cyan"
                tab_str = colorize(f"[{tab_display }]", _hl)
            else:
                tab_str = f"[{tab_display }]"

            tab_strings.append(tab_str)

        tab_line = " | ".join(tab_strings)
        if len(tab_line) > self.terminal_width - 2:
            tab_line = tab_line[: self.terminal_width - 4] + "…"
        return [tab_line]

    def _max_visible_tabs(self, tabs: List[str], max_width: int) -> int:
        """Calculate maximum number of visible tabs"""
        avg_width = 12
        return max(1, max_width // avg_width)


class Pager:
    """Non-destructive inline pager - never clears the screen.

    Prints paginated content inline in the terminal scrollback, so chat
    history above is preserved.  On quit, any messages that arrived while
    the pager was active are flushed to screen before the prompt returns.
    """

    def __init__(self, lines_per_page: int = 20):
        self.lines_per_page = lines_per_page if not IS_TERMUX else 15
        self.active = False

    def display(self, lines: List[str], header: str = "", footer: str = "",
                choices: Optional[List[str]] = None):
        """Display lines with inline pager controls.

        `choices` makes the page selectable: pressing 1-9 picks the matching
        entry, closes the pager and returns it.  Returns None otherwise, so
        callers that ignore the result behave exactly as before.
        """
        if not lines:
            safe_print(colorize("  (empty)", "dim"))
            return None
        choices = choices or []
        chosen = None

        self.active = True
        total_pages = (len(lines) + self.lines_per_page - 1) // self.lines_per_page
        page = 0

        try:
            while self.active:
                start = page * self.lines_per_page
                end = min(start + self.lines_per_page, len(lines))

                safe_print(
                    colorize(f"── {header } ", "cyan")
                    + colorize(f"({page +1 }/{total_pages })" if total_pages > 1 else "", "dim")
                    + colorize(" " + "─" * 30, "cyan")
                )

                for line in lines[start:end]:
                    # This printed the literal string "[IRC line suppressed]"
                    # from v10.11.0 until v10.14.0, discarding the line it had
                    # just measured and truncated.  Every pager consumer was
                    # affected -- /names, /list and /help alike -- which is why
                    # the channel user list looked like a suppression policy
                    # rather than a bug.
                    safe_print(_truncate_visible(line, TERMINAL_WIDTH))

                if footer:
                    safe_print(colorize(footer, "dim"))
                safe_print(colorize("─" * 42, "cyan"))

                if total_pages <= 1 and not choices:
                    self.active = False
                    break

                _keys = "  [n]ext  [p]rev  [q]uit" if total_pages > 1 else "  [q]uit"
                if choices:
                    _keys += "   [1-%d] /otr" % len(choices)
                safe_print(colorize(_keys, "dim"), end="  ", flush=True)
                try:
                    if _raw_mode_active:

                        b = os.read(_stdin_fd, 1)
                        ch = chr(b[0]).lower() if b else "q"
                        sys.stdout.write("\n")
                        sys.stdout.flush()
                    else:
                        ch = sys.stdin.readline().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ch = "q"

                if choices and ch.isdigit() and ch != "0" and int(ch) <= len(choices):
                    chosen = choices[int(ch) - 1]
                    self.active = False
                elif ch in ("n", "\r", "\n", " "):
                    page = min(page + 1, total_pages - 1)
                    if page >= total_pages - 1 and ch == "n":
                        self.active = False
                elif ch == "p":
                    page = max(0, page - 1)
                elif ch in ("q",):
                    self.active = False
        finally:
            try:
                import select as _sel

                while True:
                    r2, _, _ = _sel.select([_stdin_fd], [], [], 0.05)
                    if not r2:
                        break
                    os.read(_stdin_fd, 64)
            except Exception:
                pass
            global _input_pos
            _input_buffer.clear()
            _input_pos = 0
            _flush_display_queue()
            try:
                _cr = getattr(__import__("builtins"), "_active_client", None)
                if _cr and getattr(_cr, "_tui_enabled", False) and _cr._screen:
                    _cr._screen.redraw_full()
                elif _cr and _cr._prompt_refresh_cb:
                    _cr._prompt_refresh_cb()
            except Exception:
                pass
        return chosen


class Screen:
    """Region-based terminal renderer for the OTRv4+ TUI (Phase 5.5)."""

    def __init__(self, client):
        self.client = client
        self.scroll_offset = 0
        self.cols = TERMINAL_WIDTH if TERMINAL_WIDTH > 0 else 80
        self.rows = TERMINAL_HEIGHT if TERMINAL_HEIGHT > 0 else 24

    def _measure(self) -> None:
        sz = shutil.get_terminal_size(fallback=(80, 24))
        self.cols = max(20, sz.columns)
        self.rows = max(10, sz.lines)
        if IS_TERMUX and self.cols < 40:
            self.cols = 80

    def _sep(self) -> str:
        if self.scroll_offset > 0:
            tag = f" ↑ scrolled — PgDn to resume · PgUp for more "
            pad = max(0, self.cols - len(tag))
            left = colorize("-" * (pad // 2), "dim")
            right = colorize("-" * (pad - pad // 2), "dim")
            return left + colorize(tag, "yellow") + right
        return colorize("-" * self.cols, "dim")

    def _tabbar_lines(self) -> list:
        pm = self.client.panel_manager
        try:
            bar = TabBar(self.cols)
            lines = bar.render(pm.panels, pm.active_panel)
        except Exception as exc:
            lines = [colorize(f"[tabbar: {exc }]", "red")]
        if isinstance(lines, str):
            lines = [lines]
        return lines or [""]

    def _body_visual_lines(self) -> list:
        pm = self.client.panel_manager
        panel = pm.panels.get(pm.active_panel)
        if panel is None:
            return []
        out = []
        for entry in panel.history:
            ts = colorize(
                time.strftime(TIMESTAMP_FORMAT, time.localtime(entry.get("timestamp", time.time()))),
                "dim",
            )
            line = f"{ts } {entry ['message']}"
            wrapped = _word_wrap(line, self.cols)
            out.extend(wrapped.split("\n"))
        return out

    def _input_line(self) -> str:
        buf = _display_buffer()
        return (_current_prompt or "") + buf

    def _chrome(self, tabs):
        return 1 + len(tabs) + 1

    def _row_tab(self, tabs, i):
        return self.rows - 1 - (len(tabs) - 1 - i)

    def redraw_full(self) -> None:
        with _print_lock:
            self._measure()
            tabs = self._tabbar_lines()
            body_h = max(1, self.rows - self._chrome(tabs))
            vlines = self._body_visual_lines()
            if self.scroll_offset <= 0:
                shown = vlines[-body_h:]
            else:
                end = max(0, len(vlines) - self.scroll_offset)
                start = max(0, end - body_h)
                shown = vlines[start:end]
            if len(shown) < body_h:
                shown = [""] * (body_h - len(shown)) + shown
            k = "\033[K"
            rows = [ln + k for ln in shown]
            rows.append(self._sep() + k)
            rows += [t + k for t in tabs]
            rows.append(self._input_line() + k)
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write("\r\n".join(rows))
            sys.stdout.flush()

    def redraw_body(self) -> None:
        with _print_lock:
            self._measure()
            tabs = self._tabbar_lines()
            body_h = max(1, self.rows - self._chrome(tabs))
            vlines = self._body_visual_lines()
            if self.scroll_offset <= 0:
                shown = vlines[-body_h:]
            else:
                end = max(0, len(vlines) - self.scroll_offset)
                start = max(0, end - body_h)
                shown = vlines[start:end]
            if len(shown) < body_h:
                shown = [""] * (body_h - len(shown)) + shown
            out = ["\0337"]
            for i, ln in enumerate(shown):
                out.append(f"\033[{1 +i };1H\033[K")
                out.append(ln)
            _input_r = self.rows
            _buf = _display_buffer()
            out.append(f"\033[{_input_r };1H\033[2K")
            out.append((_current_prompt or "") + _buf)
            out.append("\0338")
            out.append(f"\033[{_input_r };1H")
            _vis = len(_ANSI_RE.sub("", (_current_prompt or "") + _buf))
            if _vis > 0:
                out.append(f"\033[{_vis +1 }G")
            sys.stdout.write("".join(out))
            sys.stdout.flush()

    def redraw_tabbar(self) -> None:
        with _print_lock:
            self._measure()
            tabs = self._tabbar_lines()
            out = ["\0337"]
            for i, t in enumerate(tabs):
                out.append(f"\033[{self ._row_tab (tabs ,i )};1H\033[K")
                out.append(t)
            out.append("\0338")
            sys.stdout.write("".join(out))
            sys.stdout.flush()

    def scroll_up(self, page: int) -> None:
        """Scroll the active panel up by page visual lines (away from bottom)."""
        self._measure()
        tabs = self._tabbar_lines()
        body_h = max(1, self.rows - self._chrome(tabs))
        vlines = self._body_visual_lines()
        max_offset = max(0, len(vlines) - body_h)
        self.scroll_offset = min(self.scroll_offset + page, max_offset)
        self.redraw_full()

    def scroll_down(self, page: int) -> None:
        """Scroll the active panel down by page visual lines (toward bottom)."""
        self.scroll_offset = max(0, self.scroll_offset - page)
        self.redraw_full()


class ChatPanel:
    """Chat panel for displaying messages.

    The history is what the tab replays when you switch to it, and until
    v10.19.0 it was unbounded and survived everything: a disconnect, a
    reconnect, a nick change.  A tester watched a whole evening's
    conversation reappear under a nick that had not sent any of it, with the
    unread badge climbing system(53) -> system(105) -> system(158) as each
    reconnect appended a fresh copy of the same connection chatter.

    That is a privacy problem before it is a cosmetic one.  This client runs
    over I2P, where the point is that a session is not linkable to the one
    before it; carrying the previous session's messages into the next one
    links them on the screen, in whatever the terminal has kept in its own
    scrollback, and in any core dump taken afterwards.

    So the history now has a ceiling, and it is emptied at every point where
    one connection ends and another begins.  See
    `OTRv4IRCClient._purge_scrollback`.
    """

    #: Hard ceiling on retained messages per panel.  Reached in a busy
    #: channel within an hour or two; the oldest are dropped first.  A cap
    #: is not a substitute for clearing on disconnect, it is the bound on
    #: how much there is to clear.
    MAX_HISTORY = 1000

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
        #: Monotonic message id.  Was `len(self.history)`, which stops being
        #: unique the moment pruning removes an entry.
        self._next_id = 0

    def add_message(self, message: str, metadata: Optional[dict] = None) -> int:
        """Add message to history, dropping the oldest past MAX_HISTORY.

        The returned id stays monotonic across pruning: it is a message
        identity, not an index into `history`, and `get_messages` slices the
        list rather than looking ids up.  Handing back a reused id after a
        prune would let a caller holding an old id address a different
        message.
        """
        msg_id = self._next_id
        self._next_id += 1
        self.history.append(
            {"id": msg_id, "message": message, "timestamp": time.time(), "metadata": metadata or {}}
        )
        if len(self.history) > self.MAX_HISTORY:
            overflow = len(self.history) - self.MAX_HISTORY
            for entry in self.history[:overflow]:
                entry["message"] = ""
                entry["metadata"] = {}
            del self.history[:overflow]
        self.last_activity = time.time()
        return msg_id

    def get_messages(self, start: int = 0, count: Optional[int] = None) -> List[str]:
        """Get messages from history as strings"""
        if not self.history:
            return []

        messages = [msg["message"] for msg in self.history]

        if count is None:
            return messages[start:]
        else:
            return messages[start : start + count]

    def clear_unread(self):
        """Clear unread count"""
        self.unread_count = 0
        self.recent_users.clear()

    def mark_secure(self, level: UIConstants.SecurityLevel = UIConstants.SecurityLevel.ENCRYPTED):
        """Mark panel as secure"""
        self.secure_session = True
        self.type = "secure"
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
            progress_chars = ["○", "◔", "◑", "◕", "●"]
            progress_index = min(int((step / total) * len(progress_chars)), len(progress_chars) - 1)
            return f"🔄 {progress_chars [progress_index ]} {step }/{total }"

    def clear_history(self) -> int:
        """Drop every retained message and return how many there were.

        Each entry's text is overwritten before the list is emptied.  Be
        precise about what that buys: a Python `str` is immutable and
        possibly interned, so this does not scrub the characters out of the
        process -- it drops the last reference the panel holds, which is the
        most a pure-Python buffer can do.  The bytes stay in freed heap until
        the allocator reuses them.  Secrets that must actually be destroyed
        do not live here at all; they live in Rust behind `zeroize()`.  What
        this does guarantee is that no later redraw, tab switch or reconnect
        can put the old conversation back on the screen.
        """
        count = len(self.history)
        for entry in self.history:
            entry["message"] = ""
            entry["metadata"] = {}
        self.history.clear()
        self.unread_count = 0
        self.recent_users.clear()
        return count


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

        self.add_panel("system", "system")

    def add_panel(self, name: str, panel_type: str) -> bool:
        """Add a new panel. Returns True if created, False if already exists."""
        with self.lock:
            if name not in self.panels:
                self.panels[name] = ChatPanel(name, panel_type)
                self.panel_order.append(name)
                if not self.active_panel:
                    self.active_panel = name
                    self.panels[name].active = True
                # Load encrypted session history for this channel/nick
                try:
                    cl = getattr(self.client, "channel_log", None)
                    if cl is not None:
                        history = cl.read_recent(name, n=50000)
                        if history:
                            self.panels[name].add_message("── history ─────────────────────────────")
                            for entry in history:
                                if "|" in entry:
                                    ts_str, body = entry.split("|", 1)
                                    try:
                                        orig_ts = time.mktime(
                                            time.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                                        )
                                    except Exception:
                                        orig_ts = time.time()
                                    self.panels[name].history.append({
                                        "id": len(self.panels[name].history),
                                        "message": body,
                                        "timestamp": orig_ts,
                                        "metadata": {},
                                    })
                                else:
                                    self.panels[name].add_message(entry)
                            self.panels[name].add_message("── live ─────────────────────────────────")
                except Exception:
                    pass
                self._render_ui()
                return True
            return False

    def get_or_create_panel(self, name: str, panel_type: str = "private") -> ChatPanel:
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
                # Snap to bottom when switching so latest messages show
                try:
                    scr = getattr(self.client, "_screen", None)
                    if scr is not None:
                        scr.scroll_offset = 0
                except Exception:
                    pass
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
                self.add_panel(target, "private")
            panel = self.panels[target]
            panel.add_message(message)
            if self.active_panel != target:
                panel.unread_count += 1
            try:
                cl = getattr(self.client, "channel_log", None)
                if cl is not None:
                    cl.append(target, message)
            except Exception:
                pass

    def update_panel_security(self, name: str, level: UIConstants.SecurityLevel) -> None:
        """Update the security level for a panel and re-render."""
        with self.lock:
            if name not in self.panels:
                self.add_panel(name, "private")
            panel = self.panels[name]
            panel.security_level = level
            if level in (
                UIConstants.SecurityLevel.ENCRYPTED,
                UIConstants.SecurityLevel.FINGERPRINT,
                UIConstants.SecurityLevel.SMP_VERIFIED,
            ):
                panel.mark_secure(level)
            self._render_ui()

    def update_smp_progress(self, name: str, step: int, total_steps: int) -> None:
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
        level = getattr(panel, "security_level", UIConstants.SecurityLevel.PLAINTEXT)
        icon = UIConstants.SECURITY_ICONS.get(level, "")
        name = colorize(panel.name, "cyan")
        sec_name = UIConstants.SECURITY_NAMES.get(level, "PLAINTEXT")

        color_map = {
            UIConstants.SecurityLevel.PLAINTEXT: "bold_red",
            UIConstants.SecurityLevel.ENCRYPTED: "bold_yellow",
            UIConstants.SecurityLevel.FINGERPRINT: "bold_green",
            UIConstants.SecurityLevel.SMP_VERIFIED: "blue",
        }
        sec_color = color_map.get(level, "white")
        sec_text = colorize(f"[{sec_name }]", sec_color)

        if panel.type in ("private", "secure"):
            return f"{icon } {name } {sec_text }"
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
            r"^\?OTRv4.*": self._route_otr_message,
            r"^PRIVMSG.*#[^:]+:.*": self._route_to_channel_tab,
            r"^PRIVMSG.*:.*": self._route_to_sender_tab,
            r"^JOIN.*": self._route_join,
            r"^PART.*": self._route_part,
            r"^QUIT.*": self._route_quit,
            r"^NICK.*": self._route_nick,
        }

    def route(
        self, message: str, prefix: Optional[str] = None, msg_type: Optional[str] = None
    ) -> str:
        """Route message to appropriate panel - returns panel name only"""
        sender_nick = prefix.split("!")[0] if prefix and "!" in prefix else prefix or "server"

        if msg_type == "OTR_STATUS":
            return sender_nick if sender_nick and sender_nick != "system" else "system"

        if msg_type == "SMP_STATUS":
            return sender_nick if sender_nick and sender_nick != "system" else "system"

        for pattern, handler in self.routes.items():
            if re.match(pattern, message):
                result = handler(message, sender_nick)
                if result:
                    return result

        return "system"

    def _route_otr_message(self, message: str, sender: str) -> Optional[str]:
        """Route OTR messages to peer tab"""
        if "?OTRv4" in message:
            return sender
        return None

    def _route_to_channel_tab(self, message: str, sender: str) -> Optional[str]:
        """Route channel messages"""
        match = re.match(r"PRIVMSG (\#[^\s]+) :", message)
        if match:
            channel = match.group(1)
            return channel
        return None

    def _route_to_sender_tab(self, message: str, sender: str) -> Optional[str]:
        """Route private messages to sender tab"""
        match = re.match(r"PRIVMSG ([^#][^\s]*) :", message)
        if match:
            target = match.group(1)
            if target == self.panel_manager.client.nick:
                return sender
        return None

    def _route_join(self, message: str, sender: str) -> Optional[str]:
        """Route JOIN messages"""
        match = re.match(r"JOIN :?(#[^\s]+)", message)
        if match:
            channel = match.group(1)
            return channel
        return None

    def _route_part(self, message: str, sender: str) -> Optional[str]:
        """Route PART messages"""
        match = re.match(r"PART :?(#[^\s]+)", message)
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

    def __init__(
        self, peer: str, is_initiator: bool, tracer: OTRTracer, logger: Optional[OTRLogger] = None
    ):
        self.peer = peer
        self.is_initiator = is_initiator
        self.tracer = tracer
        self.logger = logger or NullLogger()
        self.lock = threading.RLock()

        self.session_state = SessionState.PLAINTEXT
        self.dake_state = DAKEState.IDLE
        self.smp_state = UIConstants.SMPState.NONE

        self.dake_engine: Optional["RustDAKEAdapter"] = None
        self.ratchet: Optional[RustBackedDoubleRatchet] = None
        self.rust_smp = None
        self.smp_vault = None

        self.session_id: Optional[bytes] = None
        self.root_key: Optional[SecureMemory] = None
        self.remote_long_term_pub: Optional[bytes] = None
        self._remote_long_term_pub_bytes: Optional[bytes] = None
        self._dake_chain_key_send: Optional[bytes] = None
        self._dake_chain_key_recv: Optional[bytes] = None
        self._dake_brace_key: Optional[bytes] = None

        self._dake_output = None

        self.pending_messages: List[str] = []
        self.received_messages: List[bytes] = []

        self.created = time.time()
        self.last_activity = time.time()
        self.dake_start_time: Optional[float] = None

        self.security_level = UIConstants.SecurityLevel.PLAINTEXT

        self._sender_tag: int = _generate_instance_tag()
        self._receiver_tag: int = 0
        self._peer_disconnected: bool = False
        self._queued_smp_response: Optional[str] = None

        self.auto_smp_secret: bool = False
        self.auto_smp_scheduled: bool = False
        self.auto_smp_started: bool = False
        self.auto_smp_completed: bool = False

        self.smp_step: int = 0
        self.smp_total_steps: int = 4
        self.smp_start_time: float = 0.0

        self._smp_notify_cb = None
        # Whether the front end can run the guided verification flow -- ask
        # for consent, then for a passphrase, then answer a parked SMP1.
        # False means the old behaviour: an SMP1 with no secret is aborted
        # with a reason, because a front end that cannot ask must not leave
        # the peer waiting for an answer that will never come.
        self.smp_guided_prompt = False
        # Set when a peer's SMP1 is parked awaiting a local passphrase.  A
        # display/routing hint only: smp_secret_required() reads the engine.
        self._smp_secret_required = False

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
        """Transition session state with strict validation - rejects all illegal transitions."""
        if not self._acquire_lock():
            raise StateMachineError("Failed to acquire lock for state transition")

        try:
            old_state = self.session_state

            valid_transitions = {
                SessionState.PLAINTEXT: [SessionState.DAKE_IN_PROGRESS, SessionState.FAILED],
                SessionState.DAKE_IN_PROGRESS: [
                    SessionState.ENCRYPTED,
                    SessionState.FAILED,
                    SessionState.PLAINTEXT,
                ],
                SessionState.ENCRYPTED: [SessionState.FINISHED, SessionState.FAILED],
                SessionState.FAILED: [SessionState.PLAINTEXT],
                SessionState.FINISHED: [],
            }

            if new_state not in valid_transitions.get(old_state, []):
                raise StateMachineError(
                    f"REJECTED illegal session transition: {old_state .name } → {new_state .name }. "
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
                DAKEState.IDLE: [DAKEState.SENT_DAKE1, DAKEState.RECEIVED_DAKE1, DAKEState.FAILED],
                DAKEState.SENT_DAKE1: [DAKEState.ESTABLISHED, DAKEState.FAILED],
                DAKEState.RECEIVED_DAKE1: [DAKEState.SENT_DAKE2, DAKEState.FAILED],
                DAKEState.SENT_DAKE2: [DAKEState.ESTABLISHED, DAKEState.FAILED],
                DAKEState.ESTABLISHED: [],
                DAKEState.FAILED: [],
            }

            if new_state not in valid_transitions.get(old_state, []):
                raise StateMachineError(
                    f"Invalid DAKE transition: {old_state .name } → {new_state .name }"
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
                self.tracer.trace(
                    self.peer, "SECURITY", "ENCRYPTED", "SMP_VERIFIED", "SMP succeeded"
                )

        finally:
            self._release_lock()

    def initialize_dake(
        self, client_profile: ClientProfile, explicit_initiator: bool = False
    ) -> "RustDAKEAdapter":
        """Initialize DAKE engine - uses Rust backend when otrv4_core.RustDAKE
        is available, otherwise falls back to pure-Python OTRv4DAKE."""
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for DAKE initialization")

        try:
            if self.dake_engine is not None:
                raise RuntimeError("DAKE engine already initialized")

            self.dake_engine = RustDAKEAdapter(
                client_profile=client_profile,
                explicit_initiator=explicit_initiator,
                tracer=self.tracer,
                logger=self.logger,
            )

            return self.dake_engine
        finally:
            self._release_lock()

    def _initialize_ratchet(self):
        """Initialize double ratchet after DAKE completion.

        Prefers the chain keys derived by the DAKE engine (self._dake_chain_key_send /
        self._dake_chain_key_recv) because they are keyed with the full DH material.
        Falls back to deriving from the root key via _initialize_chains() when those
        are not available - both paths produce symmetric keys, but they differ in KDF
        inputs so mixing them between the two peers would break decryption.

        Phase 4 (v10.6.3+): when self._dake_output is set (DakeOutput from Rust),
        the ratchet is constructed via RustBackedDoubleRatchet.from_dake_output(),
        which moves session keys directly from Rust DakeOutput → RustDoubleRatchet
        without ever materialising them as Python bytes.  This closes audit
        findings C2 and C3 (Critical Exposure Window) fully.
        """
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for ratchet initialization")

        try:
            if self.ratchet is not None:
                raise RuntimeError("Ratchet already initialized")

            if not RUST_RATCHET_AVAILABLE:
                raise RuntimeError(
                    "otrv4_core Rust module not installed - cannot create encrypted session. "
                    "Build with: cd Rust && cargo test --release && maturin build --release && "
                    "pip install target/wheels/otrv4_core-*.whl"
                )

            dake_output = getattr(self, "_dake_output", None)
            if dake_output is not None and not getattr(dake_output, "consumed", True):
                self.ratchet = RustBackedDoubleRatchet.from_dake_output(
                    dake_output=dake_output,
                    is_initiator=self.is_initiator,
                    ad=b"OTRv4-DATA",
                    logger=self.logger,
                    rekey_interval=OTRConstants.REKEY_INTERVAL,
                    rekey_timeout=OTRConstants.REKEY_TIMEOUT,
                )
                self._ratchet_backend = "rust"
                if self._negotiated_pq_ratchet():
                    self.ratchet.enable_pq()

                self._dake_output = None
                _backend_label = "Rust (Phase-4 opaque handle; keys never in Python)"
                self.tracer.trace(
                    self.peer, "RATCHET", None, "ACTIVE", f"ratchet: {_backend_label }"
                )
                return

            # No fallback. There used to be one: build the ratchet from a
            # Python-held root key and chain keys (`self.root_key`,
            # `_dake_chain_key_*`), deriving any missing chain keys with the
            # Python SHAKE-256 KDF. Those values came only from the legacy
            # DAKE getters, which are not compiled into a production core
            # (`legacy-dake-keys`), and the branches that called them are
            # gone -- so the fallback could only ever run on keys that had
            # already crossed into Python. A session without a DakeOutput is
            # a session the DAKE did not establish.
            raise RuntimeError("no DAKE output to initialise the ratchet from")
        finally:
            self._release_lock()

    def _negotiated_pq_ratchet(self) -> bool:
        """v2 when both signed profiles list PQ_RATCHET_VERSION (SPEC §5.2).

        Both ends evaluate the same two profiles, so they agree. The profiles
        are signed by their identity keys and are in the DAKE transcript: a
        network attacker cannot strip the byte to force v1.
        """
        engine = getattr(self, "dake_engine", None)
        mine = getattr(getattr(engine, "client_profile", None), "versions", None) or ()
        theirs = getattr(getattr(engine, "remote_profile", None), "versions", None) or ()
        v2 = OTRConstants.PQ_RATCHET_VERSION
        return v2 in mine and v2 in theirs

    def initialize_smp(self):
        """Initialize the Rust SMP engine and secret vault (lazy, idempotent)."""
        if self.rust_smp is None:
            try:
                from otrv4_core import RustSMP, RustSMPVault

                self.rust_smp = RustSMP(self.is_initiator)
                self.smp_vault = RustSMPVault()
                self.tracer.trace(self.peer, "SMP", None, "READY", "Rust SMP engine initialized")
            except Exception as e:
                self.logger.debug("initialize_smp FAILED")
                raise RuntimeError(f"Failed to initialize Rust SMP engine: {e }") from e

    def queue_outgoing_message(self, message: str):
        """Queue outgoing message for later encryption"""
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for queueing")

        try:
            if self.session_state == SessionState.ENCRYPTED:
                return self.encrypt_message(message)

            elif self.session_state == SessionState.DAKE_IN_PROGRESS:
                self.pending_messages.append(message)
                self.tracer.trace(
                    self.peer,
                    "QUEUE",
                    "OUTGOING",
                    str(len(self.pending_messages)),
                    f"message queued (DAKE in progress)",
                )
                return None

            elif self.session_state == SessionState.PLAINTEXT:
                raise StateMachineError("Cannot send message: OTR not established")

            else:
                raise StateMachineError(
                    f"Cannot send message in state: {self .session_state .name }"
                )
        finally:
            self._release_lock()

    def _process_queued_messages(self):
        """Process any queued messages after encryption is ready"""
        if not self._acquire_lock():
            return

        try:
            if not self.pending_messages:
                return

            self.tracer.trace(
                self.peer,
                "QUEUE",
                "PROCESSING",
                str(len(self.pending_messages)),
                "processing queued messages",
            )

            for msg in self.pending_messages:
                self.tracer.trace(
                    self.peer, "QUEUE", "QUEUED", "PROCESSED", f"message: {msg [:50 ]}..."
                )

            self.pending_messages.clear()
        finally:
            self._release_lock()

    def encrypt_message(self, plaintext: str) -> Optional[str]:
        """Encrypt plaintext using the full OTRv4DataMessage wire format (spec §4.4.3)."""
        return self.encrypt_with_tlvs(plaintext, [])

    def encrypt_with_tlvs(self, plaintext: str, tlvs: List["OTRv4TLV"]) -> Optional[str]:
        """Encrypt a message carrying additional TLVs (SMP, disconnect, extra-sym-key)."""
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for encryption")

        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise StateMachineError("Cannot encrypt: session not in ENCRYPTED state")
            if self.ratchet is None:
                raise RuntimeError("Ratchet not initialized - DAKE may not be complete")

            if self.dake_engine is not None and self.dake_engine.is_session_expired():
                raise StateMachineError(
                    "OTR session has exceeded its maximum age (24 h). "
                    "Re-establish DAKE to continue communicating securely."
                )

            self.last_activity = time.time()

            payload_obj = OTRv4Payload(plaintext or "", tlvs)
            payload = payload_obj.encode(add_padding=True)
            result = self._seal_data_message(self.ratchet.encrypt_message(payload))

            self.tracer.trace(
                self.peer,
                "ENCRYPT",
                "PLAINTEXT",
                "ENCRYPTED",
                f"len={len (plaintext )} tlvs={[t .type for t in tlvs ]}",
            )
            return result

        except (EncryptionError, StateMachineError):
            raise
        except Exception as e:
            self.tracer.trace(self.peer, "ERROR", "ENCRYPT", "FAILED", str(e))
            raise EncryptionError(f"Encryption failed: {e }", self)
        finally:
            self._release_lock()

    def _seal_data_message(self, sent, flags: int = 0) -> str:
        """Frame one ratchet output as an OTRv4 DATA message on the wire."""
        ct, rh_bytes, nonce, tag, ratchet_id, reveal_field, mac_key = sent
        ct_with_tag = ct + tag

        rh = RatchetHeader.decode(rh_bytes)
        # L1: MKmac now comes from the ratchet chain (OTRv4 §4.4.2), not
        # from sha3_512(session_id || ratchet_id || msg_num). The old key
        # was a pure function of session_id and two CLEARTEXT wire fields,
        # so it authenticated nothing an attacker holding session_id could
        # not reproduce — and it was not the key that got revealed, which
        # is why revelation proved nothing.
        # MKmac stays in Rust: `mac_key` is a MessageMacKey handle with no
        # getter. It seals the public region below and is then destroyed.

        dmsg = OTRv4DataMessage()
        dmsg.sender_tag = self._sender_tag
        dmsg.receiver_tag = self._receiver_tag
        dmsg.flags = flags
        dmsg.prev_chain_len = rh.prev_chain_len
        dmsg.ratchet_id = ratchet_id
        dmsg.message_id = rh.msg_num
        dmsg.ecdh_pub = rh.dh_pub
        dmsg.nonce = nonce
        dmsg.ciphertext = ct_with_tag

        _kem_ct = self.ratchet.consume_outgoing_kem_ct()
        _kem_ek = self.ratchet.consume_outgoing_kem_ek() if _kem_ct is None else None
        dmsg.kem_ct = _kem_ct
        dmsg.kem_ek = _kem_ek

        try:
            dmsg.mac = dmsg.compute_mac(mac_key)
        finally:
            mac_key.zeroize()
        # L1: the retired MAC keys arrive as the encoded wire field and go
        # out as it is -- checked against its own count, never unpacked
        # into a list of keys here (SPEC §5.8).
        dmsg.revealed_field = OTRv4DataMessage.check_revealed_field(reveal_field)

        wire = dmsg.encode()
        encoded = base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")
        return f"?OTRv4 {encoded }."

    # -- L1: the end of a session (SPEC §5.8) ----------------------------

    #: Messages this session produced as it closed, each publishing retired
    #: MAC keys; taken by the manager (`take_final_revelations`) and sent by
    #: the client. Public by construction: what they carry is meant for the
    #: wire.
    final_revelation: List[str]

    def close_with_revelation(self, announce: bool = False) -> List[str]:
        """End this session's ratchet the deniable way. Idempotent.

        In Rust: every skipped message key is deleted and its MAC key retired
        (R3); the ratchet then decrypts nothing. Here: closing messages are
        built until every retired key is published (more than one only past
        the decoder's 2000-key limit), flagged IGNORE_UNREADABLE so a peer
        whose session is already gone drops them silently. With [announce]
        the last carries the DISCONNECTED TLV -- we are the side ending it.

        Runs whatever the state, before any key is wiped: a session ending
        by error, expiry or the peer's own DISCONNECTED reveals too. If the
        messages are never sent (no network), the keys are still retired and
        wiped in Rust; only their publication is lost.
        """
        if not hasattr(self, "final_revelation"):
            self.final_revelation = []
        ratchet = self.ratchet
        if ratchet is None or not hasattr(ratchet, "retire_all") or ratchet.closing:
            return []
        out: List[str] = []
        try:
            ratchet.retire_all()
            while True:
                last = ratchet.retired_mac_key_count <= OTRv4DataMessage.MAX_REVEALED_KEYS
                tlvs = [OTRv4TLV(OTRv4TLV.DISCONNECTED, b"")] if (announce and last) else []
                payload = OTRv4Payload("", tlvs).encode(add_padding=True)
                out.append(self._seal_data_message(
                    ratchet.encrypt_final(payload),
                    flags=OTRv4DataMessage.FLAG_IGNORE_UNREADABLE))
                if ratchet.retired_mac_key_count == 0:
                    break
        except Exception as e:
            # Never a reason to keep a session alive: whatever was built goes,
            # and _cleanup_resources wipes the rest.
            self.tracer.trace(self.peer, "ERROR", "REVEAL", "FAILED", type(e).__name__)
        self.final_revelation.extend(out)
        self.tracer.trace(self.peer, "REVEAL", "ACTIVE", "CLOSING", f"messages={len (out )}")
        return out

    def decrypt_message(self, encrypted_msg: str) -> bytes:
        """Decrypt an OTRv4 DATA message; return human-readable text as UTF-8 bytes.

        Only the current OTRv4DataMessage frame is accepted. The v5 "legacy"
        branch that used to sit here is gone: nothing has emitted that format
        since the data-message rewrite, it fed the ratchet without the outer
        MAC or instance-tag checks, and it no longer even ran (it treated the
        ratchet's (plaintext, mkmac) tuple as bytes). A second parser for a
        format no peer sends is attack surface and nothing else.
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

            # Single decoder of record: _safe_b64decode strips the trailing '.'
            # terminator, decodes url-safe, and rejects 1-mod-4 corruption.
            raw = encrypted_msg[7:].strip()
            decoded = _safe_b64decode(raw)

            if not OTRv4DataMessage.looks_like_data_frame(decoded):
                raise ValueError("unsupported data message format")
            text_bytes = self._enh_dec_v6(decoded)

            self.tracer.trace(
                self.peer, "DECRYPT", "ENCRYPTED", "PLAINTEXT", f"len={len (text_bytes )}"
            )
            return text_bytes

        except (EncryptionError, StateMachineError):
            raise
        except Exception as e:
            self.tracer.trace(self.peer, "ERROR", "DECRYPT", "FAILED", str(e))
            raise EncryptionError(f"Decryption failed: {e }", self)
        finally:
            self._release_lock()

    MAX_PEER_REVEALED_MAC_KEYS = 200

    def _record_revealed_mac_keys(self, keys, this_message_mac_key=None):
        """Cross-check and record the MAC keys the peer published (audit C2).

        OTRv4 §4.4.2 has each side publish the MKmac of messages it has
        finished with, so that anyone -- not just the two participants -- can
        forge a message bearing that MAC. That is the deniability mechanism.

        The keys are public by construction, so this store holds nothing
        secret. What it does is make the mechanism checkable:

        VERIFIED
            The engine independently derived the same MKmac, so the key really
            did authenticate a message on a chain both sides share. This is
            the property revelation is supposed to have, and it is now
            observed per key rather than assumed.

        UNACCOUNTED
            This endpoint cannot derive the key. That is NOT evidence of
            misbehaviour and is deliberately not fatal. A key legitimately
            lands here when the peer sent a message that never arrived and
            then rotated its DH key before we could derive the tail of the old
            chain, or when the fingerprint window (4096 entries) has rolled
            over. Tearing the session down on an unaccounted key would hand
            any attacker who can drop one packet a reliable way to kill every
            session -- a worse outcome than the one it would be defending
            against, because a peer that wants to defeat the check can simply
            reveal nothing at all. The count is kept so the condition is
            visible instead of silent.

        Fatal (fail closed):
            wrong length, all-zero, or the key that authenticated the very
            message carrying it. The last is the one revelation must never do:
            publishing the current message's MKmac would make that message
            forgeable at the instant it is accepted. The engine does not do it
            -- encrypt() takes the pending queue before installing the current
            key -- so this is a standing guard on that ordering.
        """
        # Each attribute guarded separately: a session object that predates one
        # of them must not leave the others uninitialised.
        if not hasattr(self, "peer_revealed_mac_keys"):
            self.peer_revealed_mac_keys = []
        if not hasattr(self, "revealed_mac_keys_verified"):
            self.revealed_mac_keys_verified = 0
        if not hasattr(self, "revealed_mac_keys_unaccounted"):
            self.revealed_mac_keys_unaccounted = 0
        if not hasattr(self, "revealed_mac_check_available"):
            self.revealed_mac_check_available = True

        for k in keys:
            if len(k) != OTRv4DataMessage.REVEALED_MAC_KEY_LEN:
                raise ValueError(
                    f"Peer revealed a {len (k )}-byte MAC key; expected "
                    f"{OTRv4DataMessage .REVEALED_MAC_KEY_LEN }")
            if not any(k):
                raise ValueError(
                    "Peer revealed an all-zero MAC key - revelation is "
                    "supposed to publish the key that authenticated a real "
                    "message")
            if this_message_mac_key is not None and this_message_mac_key.matches(bytes(k)):
                raise ValueError(
                    "Peer revealed the MAC key of the message carrying the "
                    "revelation - a key is only ever revealed once the "
                    "message it authenticated is finished with")

            if self.revealed_mac_check_available:
                try:
                    known = self.ratchet.knows_revealed_mac_key(bytes(k))
                except AttributeError:
                    # Engine predates the cross-check (stale extension build).
                    # Recorded once, not per message, and never silently: the
                    # keys are still stored, they just carry no verification.
                    self.revealed_mac_check_available = False
                    known = False
                if known:
                    self.revealed_mac_keys_verified += 1
                else:
                    self.revealed_mac_keys_unaccounted += 1

            self.peer_revealed_mac_keys.append(bytes(k))

        excess = len(self.peer_revealed_mac_keys) - self.MAX_PEER_REVEALED_MAC_KEYS
        if excess > 0:
            del self.peer_revealed_mac_keys[:excess]

    def _enh_dec_v6(self, decoded: bytes) -> bytes:
        """Decrypt v6 OTRv4DataMessage."""
        dmsg = OTRv4DataMessage.decode(decoded)

        if self._receiver_tag == 0 and dmsg.sender_tag >= 0x100:
            self._receiver_tag = dmsg.sender_tag
        if dmsg.receiver_tag != 0 and dmsg.receiver_tag != self._sender_tag:
            raise ValueError(
                f"Instance tag mismatch: 0x{self ._sender_tag :08x} vs "
                f"0x{dmsg .receiver_tag :08x}"
            )

        rh_bytes = RatchetHeader(dmsg.ecdh_pub, dmsg.prev_chain_len, dmsg.message_id).encode()
        if len(dmsg.ciphertext) < 16:
            raise ValueError("Ciphertext too short for GCM tag")
        ct, tag = dmsg.ciphertext[:-16], dmsg.ciphertext[-16:]

        # L1: MKmac is chain-derived, so it does not exist until the ratchet
        # has advanced. Order is decrypt-then-verify rather than the reverse.
        # That is safe: AES-256-GCM is the primary authentication and runs
        # first, rejecting any forgery before this point. The outer OTRv4 MAC
        # is a second, spec-mandated check whose key is later published.
        _rid_before = self.ratchet.ratchet_id
        plaintext, mac_key = self.ratchet.decrypt_message(
            rh_bytes, ct, dmsg.nonce, tag, kem_ek=dmsg.kem_ek, kem_ct=dmsg.kem_ct)
        _did_dh_ratchet = self.ratchet.ratchet_id != _rid_before

        try:
            if not dmsg.verify_mac(mac_key):
                raise ValueError("MAC verification failed - message may be forged or replayed")

            # Keys the peer revealed for previously-authenticated messages. They
            # are public by design; record them so the deniability property is
            # observable rather than nominal, and bound the store.
            if dmsg.revealed_mac_keys:
                self._record_revealed_mac_keys(dmsg.revealed_mac_keys,
                                               this_message_mac_key=mac_key)
        finally:
            mac_key.zeroize()

        if dmsg.kem_ct is not None:
            self.ratchet.process_incoming_kem_ct(dmsg.kem_ct)
        if dmsg.kem_ek is not None:
            self.ratchet.process_incoming_kem_ek(dmsg.kem_ek)

        if _did_dh_ratchet:
            self.ratchet.prepare_brace_rotation()

        payload_obj = OTRv4Payload.decode(plaintext)
        self._enh_route_tlvs(payload_obj.tlvs)
        return payload_obj.text.encode("utf-8")

    def _enh_route_tlvs(self, tlvs: List["OTRv4TLV"]) -> None:
        """Route TLVs from decrypted payload to protocol handlers."""
        for tlv in tlvs:
            try:
                if tlv.type == OTRv4TLV.DISCONNECTED:
                    self._peer_disconnected = True
                    self.tracer.trace(
                        self.peer, "DISCONNECT", "TLV", "RECEIVED", "peer ended session gracefully"
                    )
                    # L1 (d): the peer ended it; we still publish what we
                    # retired. Their side drops it unread, the wire has it.
                    self.close_with_revelation(announce=False)
                    if self.session_state == SessionState.ENCRYPTED:
                        try:
                            self.transition_session(
                                SessionState.FINISHED, "peer sent DISCONNECTED TLV"
                            )
                        except StateMachineError:
                            pass
                    # Ended: its keys go now, not when the table is next
                    # tidied. The closed ratchet used to linger here and was
                    # taken up again by the next DAKE with this peer.
                    self._cleanup_resources()

                elif tlv.type in OTRv4TLV.SMP_TYPES:
                    self._enh_handle_smp_tlv(tlv)

                elif tlv.type in _TLV_HANDLERS:
                    # A registered feature handler.  It runs on decrypted,
                    # authenticated payload from an established session, and
                    # its exceptions are contained here: a feature must not
                    # be able to break the session state machine.
                    try:
                        _TLV_HANDLERS[tlv.type](self.peer, tlv.value)
                    except Exception as exc:
                        self.tracer.trace(self.peer, "ERROR", "TLV-HANDLER",
                                          "0x%04x" % tlv.type, str(exc)[:80])

                elif tlv.type == OTRv4TLV.EXTRA_SYMMETRIC_KEY:
                    # Consumed and deliberately NOT turned into a key here.
                    #
                    # This used to derive SHA3-512(session_id || label ||
                    # tlv.value) in Python and kept it on the session. Two
                    # things were wrong with that:
                    # every input is visible to anyone who saw the session
                    # (the SSID is displayed for verification, the TLV value
                    # is the peer's plaintext context), so the "key" was not
                    # secret at all; and it was a Python object nothing ever
                    # read. The real OTRv4 extra symmetric key is derived in
                    # the DAKE and never leaves Rust -- it keys file transfer
                    # inside `RustDoubleRatchet.file_sender/file_receiver`.
                    self.tracer.trace(self.peer, "DEBUG", "TLV",
                                      "EXTRA_SYMMETRIC_KEY", "ignored")

            except Exception as e:
                self.tracer.trace(self.peer, "ERROR", "TLV", f"0x{tlv .type :04x}", str(e)[:80])

    def _enh_handle_smp_tlv(self, tlv: "OTRv4TLV") -> None:
        """Process an incoming SMP TLV and queue the encrypted response.

        Fully Rust-backed: all exponents and the shared secret reside in
        Rust memory with ZeroizeOnDrop.  Python only handles the TLV framing.
        """
        self.initialize_smp()
        if self._ping_refresh_cb is not None:
            try:
                self._ping_refresh_cb()
            except Exception:
                pass

        resp_bytes = None
        out_type = None

        try:
            if tlv.type in (OTRv4TLV.SMP_MSG_1, OTRv4TLV.SMP_MSG_1Q):

                phase = self.rust_smp.get_phase()
                # A FAILED run is over, not in progress. Treating it as a race
                # made every retry after one wrong passphrase either refused
                # ("SMP not Idle for SMP1") or, on the side with the lower
                # fingerprint, silently ignored -- the peer then waited out
                # its timeout. Rust leaves Failed for Idle and keeps the
                # attempt count and cooldown, which its guard still enforces.
                if phase in ("FAILED", "ABORTED"):
                    try:
                        self.rust_smp.restart_after_failure()
                    except Exception:
                        # The attempt limit is spent: this engine stays shut.
                        self.tracer.trace(self.peer, "SMP", "SMP1_RECEIVED",
                                          f"phase={phase }", "attempt limit reached - refused")
                        self._queued_smp_response = self.encrypt_with_tlvs(
                            "", [OTRv4TLV(OTRv4TLV.SMP_ABORT, b"")]
                        )
                        return
                    phase = self.rust_smp.get_phase()
                # Already verified this session: a second run is not started
                # by the peer. Refuse it with an abort and keep the result;
                # the old race path either ignored it or threw the
                # verification away, depending on whose fingerprint was lower.
                if phase == "VERIFIED":
                    self.tracer.trace(self.peer, "SMP", "SMP1_RECEIVED",
                                      "phase=VERIFIED", "already verified - refused")
                    self._queued_smp_response = self.encrypt_with_tlvs(
                        "", [OTRv4TLV(OTRv4TLV.SMP_ABORT, b"")]
                    )
                    return
                if phase != "IDLE":

                    local_fp = b""
                    try:
                        if self.dake_engine and self.dake_engine.client_profile:
                            cp = self.dake_engine.client_profile
                            if cp.identity_pub_bytes:
                                local_fp = cp.identity_pub_bytes
                            elif cp.identity_key:
                                local_fp = bytes(cp.identity_key.public_bytes())
                    except Exception:
                        pass
                    remote_fp = self._remote_long_term_pub_bytes or b""

                    if not local_fp or not remote_fp:

                        self.tracer.trace(
                            self.peer,
                            "SMP",
                            "SMP1_RECEIVED",
                            f"phase={phase }",
                            "race detected, no fingerprints to tie-break - aborting",
                        )
                        try:
                            self.rust_smp.abort()
                        except Exception:
                            pass
                        self._queued_smp_response = self.encrypt_with_tlvs(
                            "", [OTRv4TLV(OTRv4TLV.SMP_ABORT, b"")]
                        )
                        return

                    if local_fp < remote_fp:

                        self.tracer.trace(
                            self.peer,
                            "SMP",
                            "SMP1_RECEIVED",
                            f"phase={phase }",
                            "race detected, local_fp < remote_fp - keeping our role as initiator",
                        )
                        return

                    self.tracer.trace(
                        self.peer,
                        "SMP",
                        "SMP1_RECEIVED",
                        f"phase={phase }",
                        "race detected, local_fp > remote_fp - yielding initiator role",
                    )
                    try:
                        self.rust_smp.abort()
                    except Exception:
                        pass

                    # Keep the vault across the rebuild.
                    #
                    # initialize_smp() constructs a NEW RustSMPVault whenever
                    # rust_smp is None, so clearing rust_smp threw away the
                    # "smp_secret" entry this path is about to read back --
                    # and the rebind below therefore failed every single time.
                    # It surfaced on two real phones as
                    #
                    #     SMP race-recovery: vault rebind failed
                    #
                    # whenever both sides ran /smp at once, which over I2P is
                    # not rare: it is what happens when two people are told to
                    # verify and both do.  The vault is a separate Rust object
                    # holding a secret this session already owns; there is no
                    # reason for a new engine to mean a new vault.
                    preserved_vault = self.smp_vault
                    self.rust_smp = None
                    self.initialize_smp()
                    if preserved_vault is not None:
                        self.smp_vault = preserved_vault
                    if self.rust_smp is None or self.smp_vault is None:
                        raise RuntimeError("SMP race-recovery: re-init failed")
                    sid_recover = self.session_id or b""
                    ok = self.rust_smp.set_secret_from_vault(
                        self.smp_vault, "smp_secret", sid_recover, local_fp, remote_fp
                    )
                    if not ok:
                        # No secret to rebind: this side has not been given a
                        # passphrase at all, so yielding the initiator role
                        # leaves nothing to answer with.  Fall through to the
                        # no-secret handling below rather than raising, which
                        # would report a setup problem as an internal error.
                        self.tracer.trace(
                            self.peer, "SMP", "SMP1_RECEIVED", "RACE_NO_SECRET",
                            "yielded initiator role but no stored passphrase "
                            "to rebind",
                        )

                if not self.rust_smp.check_secret_set():
                    # HOLD the SMP1 rather than abort.
                    #
                    # Aborting made a setup problem look like a protocol
                    # failure: the peer was told "SMP aborted" when the truth
                    # was that this side had never been given the passphrase.
                    # The engine parks the message in SECRET_REQUIRED instead,
                    # so once the user supplies the passphrase the SMP1 that
                    # already arrived can be answered -- no restart, no second
                    # round trip over I2P.
                    #
                    # What this does NOT do, and must never do, is arm input
                    # capture.  Holding a message is a state in the SMP engine;
                    # it does not decide what the user's next keystroke means.
                    # The front end asks for consent first and only a local
                    # answer opens the passphrase prompt -- see
                    # otrv4plus_smpflow.py and docs/SECURITY_INVARIANTS.md INV-06.
                    held = False
                    try:
                        if self.smp_guided_prompt:
                            self.rust_smp.hold_smp1(bytes(tlv.value))
                            held = True
                    except Exception as _he:
                        # An older core without hold_smp1, or a message it
                        # would not park.  Fall back to the previous
                        # behaviour rather than losing the run silently.
                        self.logger.debug("hold_smp1 unavailable or refused")

                    self.tracer.trace(
                        self.peer,
                        "SMP",
                        "SMP1_RECEIVED",
                        "SECRET_REQUIRED" if held else "NO_SECRET",
                        "SMP1 held pending local passphrase" if held
                        else "SMP1 received but no secret set - aborting",
                    )

                    if held:
                        # No response goes out yet.  The peer waits while the
                        # user is asked; if they decline or the request times
                        # out, decline_held_smp1() sends the abort.
                        self._smp_secret_required = True
                        self._smp_progress_notify(
                            0, 4,
                            "Your peer asked to verify this session. A shared "
                            "passphrase is needed to answer.",
                            role=None, color="yellow",
                        )
                        return

                    self._smp_progress_notify(
                        0, 4,
                        "SMP requested by peer, but no passphrase is stored "
                        "for them. Run  /smp  to enter the passphrase you "
                        "both agreed.",
                        role=None, color="yellow",
                    )
                    self._queued_smp_response = self.encrypt_with_tlvs(
                        "", [OTRv4TLV(OTRv4TLV.SMP_ABORT,
                                      OTRv4TLV.SMP_ABORT_NO_SECRET)]
                    )
                    return
                self._smp_progress_notify(
                    1,
                    4,
                    "Challenge received - computing response (ML-KEM encaps + ML-DSA-87 + ZKP)…",
                    color="yellow",
                )
                resp_bytes = self.rust_smp.process_smp1_generate_smp2(tlv.value)
                out_type = OTRv4TLV.SMP_MSG_2
                self.smp_step = 2
                self._smp_progress_notify(2, 4, "Response computed - sending…", role="responder")

            elif tlv.type == OTRv4TLV.SMP_MSG_2:
                self.smp_step = 2
                self._smp_progress_notify(
                    2, 4, "Response received - verifying ML-DSA-87 + ZKP…", role="initiator"
                )
                resp_bytes = self.rust_smp.process_smp2_generate_smp3(tlv.value)
                out_type = OTRv4TLV.SMP_MSG_3
                self.smp_step = 3
                self._smp_progress_notify(
                    3,
                    4,
                    "PQ proof verified - sending confirmation (ML-DSA-87 + ZKP)…",
                    role="initiator",
                )

            elif tlv.type == OTRv4TLV.SMP_MSG_3:
                resp_bytes = self.rust_smp.process_smp3_generate_smp4(tlv.value)
                out_type = OTRv4TLV.SMP_MSG_4
                self.smp_step = 4
                self._smp_progress_notify(4, 4, "Final step - sending verdict…", role="responder")

                if self.rust_smp.is_verified():
                    self.auto_smp_completed = True
                    self.auto_smp_started = False
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                    self.tracer.trace(
                        self.peer, "SMP", "VERIFIED", "STATE_UPDATED", "role=responder"
                    )
                    self._smp_progress_notify(
                        4,
                        4,
                        "🔵✅ SMP VERIFIED - identity confirmed! (ML-KEM-1024 + ML-DSA-87 + ZKP)",
                        role=None,
                        color="blue",
                        final=True,
                    )
                elif self.rust_smp.is_failed():
                    self.auto_smp_started = False
                    self.auto_smp_completed = False
                    self.smp_step = 0
                    self.tracer.trace(
                        self.peer,
                        "SMP",
                        "FAILED",
                        "STATE_UPDATED",
                        "secrets did not match (responder)",
                    )
                    self._smp_progress_notify(
                        0,
                        4,
                        "🔴❌ SMP FAILED - secrets did not match",
                        role=None,
                        color="red",
                        final=True,
                    )

            elif tlv.type == OTRv4TLV.SMP_MSG_4:
                verified = self.rust_smp.process_smp4(tlv.value)
                self.smp_step = 4
                if verified:
                    self.auto_smp_completed = True
                    self.auto_smp_started = False
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                    self.tracer.trace(
                        self.peer,
                        "SMP",
                        "VERIFIED",
                        "STATE_UPDATED",
                        f"role={'initiator'if self .is_initiator else 'responder'}",
                    )
                    self._smp_progress_notify(
                        4,
                        4,
                        "🔵✅ SMP VERIFIED - identity confirmed! (ML-KEM-1024 + ML-DSA-87 + ZKP)",
                        role=None,
                        color="blue",
                        final=True,
                    )
                else:
                    self.auto_smp_started = False
                    self.auto_smp_completed = False
                    self.smp_step = 0
                    self.tracer.trace(
                        self.peer, "SMP", "FAILED", "STATE_UPDATED", "secrets did not match"
                    )
                    self._smp_progress_notify(
                        0,
                        4,
                        "🔴❌ SMP FAILED - secrets did not match",
                        role=None,
                        color="red",
                        final=True,
                    )
                return

            elif tlv.type == OTRv4TLV.SMP_ABORT and self.rust_smp.get_phase() == "VERIFIED":
                # A finished run cannot be aborted. A stale or refused-run
                # abort must not throw away a verification both sides reached.
                self.tracer.trace(self.peer, "SMP", "ABORTED", "IGNORED",
                                  "abort after verification ignored")
            elif tlv.type == OTRv4TLV.SMP_ABORT:
                self.rust_smp.abort()
                self.auto_smp_started = False
                self.auto_smp_completed = False
                self.smp_step = 0
                # The reason, if the peer sent one, only chooses the wording of
                # a local line. It is peer-controlled text and is never trusted
                # as a security predicate: either way the SMP session is over
                # and nothing is verified.
                reason_bytes = bytes(getattr(tlv, "value", b"") or b"")
                no_secret = reason_bytes == OTRv4TLV.SMP_ABORT_NO_SECRET
                declined = reason_bytes == OTRv4TLV.SMP_ABORT_DECLINED
                self.tracer.trace(
                    self.peer, "SMP", "ABORTED",
                    "PEER_DECLINED" if declined
                    else "PEER_NO_SECRET" if no_secret else "PEER_ABORT",
                    "Remote peer declined the verification request" if declined
                    else "Remote peer has no SMP secret configured" if no_secret
                    else "Remote peer aborted SMP",
                )
                if declined:
                    self._smp_progress_notify(
                        0, 4,
                        "SMP stopped: your peer declined the verification "
                        "request. Nothing is verified, and this is not a "
                        "wrong-passphrase failure.",
                        role=None, color="yellow",
                    )
                elif no_secret:
                    self._smp_progress_notify(
                        0, 4,
                        "SMP stopped: your peer has not stored the passphrase "
                        "yet. Ask them to run  /smp-secret <secret>  and try "
                        "again. This is not a wrong-passphrase failure.",
                        role=None, color="yellow",
                    )
                else:
                    self._smp_progress_notify(
                        0, 4, "⚠ SMP aborted by remote peer", role=None, color="red"
                    )
                return

        except Exception as e:
            self.tracer.trace(self.peer, "ERROR", "SMP", f"0x{tlv .type :04x}", str(e)[:120])
            if self.rust_smp:
                self.rust_smp.abort()
            self.auto_smp_started = False
            self.auto_smp_completed = False
            self.smp_step = 0
            # A version mismatch is the one SMP failure that is NOT about the
            # passphrase, and it is the whole reason SMP carries a version
            # byte.  The generic handler truncates to 60 characters, which
            # would cut the message off before it says what to do about it.
            if _is_smp_version_mismatch(e):
                self._smp_progress_notify(
                    0, 4, SMP_VERSION_MISMATCH_HELP,
                    role=None, color="yellow", final=True,
                )
            else:
                self._smp_progress_notify(
                    0, 4, f"❌ SMP error: {str (e )[:60 ]}", role=None, color="red"
                )
            return

        if resp_bytes is not None and out_type is not None:
            try:
                self._queued_smp_response = self.encrypt_with_tlvs(
                    "", [OTRv4TLV(out_type, bytes(resp_bytes))]
                )
            except Exception as e:
                self.tracer.trace(self.peer, "ERROR", "SMP_RESP", "ENCRYPT", str(e)[:80])

    _SMP_STEP_LABELS = {
        1: "Sending challenge",
        2: "Challenge sent → awaiting response",
        3: "Response received → sending verification",
        4: "Finalising",
    }

    def _smp_progress_notify(
        self,
        step: int,
        total: int,
        detail: str,
        role: Optional[str] = None,
        color: str = "yellow",
        final: bool = False,
    ) -> None:
        """Emit a visible SMP progress line with dynamic ETA and block bar.

        Each call produces one timestamped line like:

            🔐 SMP [████████░░] 2/4 · 50% · ⏱ 0:02 elapsed · ETA ~0:03

        Timing is derived from smp_start_time and per-step wall-clock
        measurements accumulated in _smp_step_times.
        """
        now = time.time()

        if not hasattr(self, "_smp_step_times"):
            self._smp_step_times: list = []
        if step > 0 and (not self._smp_step_times or self._smp_step_times[-1][0] != step):
            self._smp_step_times.append((step, now))

        t0 = getattr(self, "smp_start_time", 0) or now
        elapsed = max(0.0, now - t0)

        def _fmt(s: float) -> str:
            return f"{int (s //60 )}:{int (s %60 ):02d}"

        elapsed_str = _fmt(elapsed)
        eta_str = ""
        if step > 0 and elapsed > 0 and not final:
            avg_per_step = elapsed / step
            remaining = (total - step) * avg_per_step
            if remaining > 0:
                eta_str = f" · ETA ~{_fmt (remaining )}"

        SEGS = total if total > 0 else 4
        if step > 0 and total > 0:
            seg_w = 3
            filled = "█" * seg_w
            empty_s = "░" * seg_w
            partial = "▒" * seg_w
            bar_segs = []
            for i in range(SEGS):
                if i < step - 1:
                    bar_segs.append(filled)
                elif i == step - 1:
                    bar_segs.append(filled)
                else:
                    bar_segs.append(empty_s)
            bar_body = " ".join(bar_segs)
            pct = int((step / total) * 100)
            bar = f"[{bar_body }]"
            step_str = f"step {step }/{total }"
            if final:
                time_str = f" · ✓ {elapsed_str }"
            elif elapsed > 5:
                time_str = f" · {elapsed_str } elapsed{eta_str }"
            else:
                time_str = ""
            label = f"🔐 SMP {bar } {step_str }{time_str } · {detail }"
        else:
            label = f"🔐 SMP · {detail }"

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
        """End the session gracefully: the closing message(s) of
        close_with_revelation, the last carrying DISCONNECTED (L1). Returns
        the first; any further ones wait in `final_revelation`."""
        out = self.close_with_revelation(announce=True)
        if not out:
            return None
        self.final_revelation.remove(out[0])
        return out[0]

    def start_dake(self) -> Optional[str]:
        """Start DAKE as initiator (opportunistic)"""
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire lock for DAKE start")

        try:
            if self.session_state != SessionState.PLAINTEXT:
                raise StateMachineError(f"Cannot start DAKE in state: {self .session_state .name }")

            if self.dake_state != DAKEState.IDLE:
                raise StateMachineError(f"Cannot start DAKE: state is {self .dake_state .name }")

            if not self.is_initiator:
                raise StateMachineError("Only initiator can start DAKE")

            if self.dake_engine is None:
                raise RuntimeError("DAKE engine not initialized")

            self.transition_session(SessionState.DAKE_IN_PROGRESS, "starting DAKE")

            dake1 = self.dake_engine.generate_dake1()
            self.dake_start_time = time.time()

            self.transition_dake(DAKEState.SENT_DAKE1, "opportunistic start")

            self.tracer.trace(
                self.peer, "OPPORTUNISTIC", "IDLE", "STARTED", "first outgoing message"
            )

            return dake1

        except Exception as e:
            self.transition_session(SessionState.FAILED, f"DAKE start failed: {e }")
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
        # L1: every path that destroys the ratchet -- terminate, failure,
        # wipe, logout, reset -- publishes its retired MAC keys first.
        self.close_with_revelation(announce=False)
        try:
            # A handshake that produced session keys but never built a ratchet
            # from them leaves them here. Destroy them explicitly.
            pending = getattr(self, "_dake_output", None)
            if pending is not None:
                try:
                    pending.discard()
                except Exception:
                    pass
                self._dake_output = None

            if self.ratchet:
                self.ratchet.zeroize()
                self.ratchet = None

            if self.root_key:
                self.root_key.zeroize()
                self.root_key = None

            if self.rust_smp is not None:
                self.rust_smp.abort()
                self.rust_smp = None

            if self.smp_vault is not None:
                self.smp_vault.clear()
                self.smp_vault = None

            self.auto_smp_secret = False

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

                    pub_bytes = bytes(self.remote_long_term_pub)
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
        """Start SMP verification using the Rust SMP engine.

        Generates SMP1, encrypts it, and returns the OTR message ready to send.
        The secret is bound to the session (session_id + fingerprints) inside Rust.
        """
        if not self._acquire_lock():
            raise RuntimeError("start_smp: could not acquire session lock (timeout)")
        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise RuntimeError(
                    f"start_smp: session not encrypted (state={self .session_state !r })"
                )
            self.initialize_smp()
            if self.rust_smp is None:
                raise RuntimeError("start_smp: RustSMP is None after initialize_smp")
            phase = self.rust_smp.get_phase()
            if phase == "VERIFIED":
                raise RuntimeError("start_smp: this session is already verified")
            if phase not in ("IDLE", "FAILED", "ABORTED"):
                raise RuntimeError(f"start_smp: SMP already in progress (phase={phase })")
            if phase in ("FAILED", "ABORTED"):
                # A new run after a failed or cancelled one. Rust keeps the
                # cooldown and refuses once the attempt limit is spent.
                self.rust_smp.restart_after_failure()

            if secret:
                self.set_smp_secret(secret)

            if not self.rust_smp.check_secret_set():
                raise RuntimeError(
                    "start_smp: secret not set in Rust SMP engine - "
                    "call set_smp_secret() first or pass secret explicitly"
                )

            smp1_bytes = self.rust_smp.generate_smp1(question)
            self.smp_step = 1
            self._smp_progress_notify(
                1, 4, "Challenge sent - awaiting response (Rust ZKP)…", color="yellow"
            )
            return self.encrypt_with_tlvs("", [OTRv4TLV(OTRv4TLV.SMP_MSG_1, bytes(smp1_bytes))])
        except Exception as e:
            import traceback as _tb

            msg = f"start_smp: Error: {e }"
            self.logger.debug("start_smp FAILED")

            raise RuntimeError(f"SMP start failed: {e }") from e
        finally:
            self._release_lock()

    # ─── held SMP1: the responder-with-no-passphrase path ────────────────────
    #
    # Three methods, and the split between them is the security boundary.
    # `smp_secret_required` is set by a REMOTE message arriving.  The other two
    # are called only after the local user has answered a prompt.  Nothing here
    # reads input; the front end owns that and hands down a result.

    def smp_secret_required(self) -> bool:
        """True while an SMP1 from the peer is parked awaiting a passphrase."""
        if self.rust_smp is None:
            return False
        try:
            return self.rust_smp.get_phase() == "SECRET_REQUIRED"
        except Exception:
            return False

    def resume_held_smp1(self) -> Optional[str]:
        """Answer the parked SMP1 now that a passphrase has been stored.

        Returns the encrypted SMP2 to send, or raises.  The caller must have
        called set_smp_secret() first -- the engine refuses otherwise, which is
        the fail-closed half of "only local input can supply the secret".
        """
        if not self._acquire_lock():
            raise RuntimeError("resume_held_smp1: could not acquire session lock")
        try:
            if self.rust_smp is None:
                raise RuntimeError("no SMP engine")
            # The engine is the authority on whether the message is still
            # held; ask it before consuming so a resume that cannot succeed
            # says so plainly rather than as a generic engine error.
            if not self.rust_smp.has_held_smp1():
                raise RuntimeError(
                    "no SMP1 is being held for this session")
            smp2 = self.rust_smp.resume_held_smp1_generate_smp2()
            # Cleared only now.  Setting it before the call meant a failed
            # resume left the session claiming no request was outstanding
            # while the engine was still holding one.
            self._smp_secret_required = False
            self.smp_step = 2
            self._smp_progress_notify(
                2, 4, "Passphrase accepted - answering the challenge…",
                role="responder",
            )
            return self.encrypt_with_tlvs(
                "", [OTRv4TLV(OTRv4TLV.SMP_MSG_2, bytes(smp2))])
        finally:
            self._release_lock()

    def abort_smp(self) -> Optional[str]:
        """Cancel an SMP run in either direction, at any stage, and tell the peer.

        The local user pressed Cancel. The Rust run is aborted, any parked
        SMP1 is discarded, the bound passphrase is dropped from the vault, and
        the returned OTR message carries SMP_ABORT so the peer stops waiting.
        None when there is nothing to abort. An aborted run proves nothing,
        so it leaves the session unverified.
        """
        if not self._acquire_lock():
            return None
        try:
            if self.rust_smp is None:
                return None
            try:
                self.rust_smp.abort()
            except Exception:
                self.logger.debug("rust_smp.abort failed")
            try:
                self.rust_smp.discard_held_smp1()
            except Exception:
                pass
            if self.smp_vault is not None:
                try:
                    self.smp_vault.remove("smp_secret")
                except Exception:
                    pass
            self._smp_secret_required = False
            self.smp_step = 0
            return self.encrypt_with_tlvs("", [OTRv4TLV(OTRv4TLV.SMP_ABORT, b"")])
        finally:
            self._release_lock()

    def decline_held_smp1(self, reason: bytes = b"") -> Optional[str]:
        """Drop the parked SMP1 and tell the peer.

        Used for an explicit decline, for a consent request that timed out, and
        for teardown while one was open.  Storing nothing is the point: a
        declined request must leave no passphrase and no state behind.
        """
        if not self._acquire_lock():
            return None
        try:
            if self.rust_smp is None:
                return None
            self._smp_secret_required = False
            try:
                self.rust_smp.discard_held_smp1()
            except Exception:
                self.logger.debug("discard_held_smp1 failed")
            self.smp_step = 0
            return self.encrypt_with_tlvs(
                "", [OTRv4TLV(OTRv4TLV.SMP_ABORT,
                              reason or OTRv4TLV.SMP_ABORT_DECLINED)])
        finally:
            self._release_lock()

    def process_smp_message(self, data: bytes) -> Optional[str]:
        """Process a raw SMP TLV (type+len+value) using the Rust engine.

        Used by the SessionManager-level dispatch path.  For the session-level
        TLV handler see _enh_handle_smp_tlv.
        """
        if not self._acquire_lock():
            return None
        try:
            if len(data) < 4:
                return None
            self.initialize_smp()
            tlv_type = struct.unpack_from("!H", data, 0)[0]
            tlv_len = struct.unpack_from("!H", data, 2)[0]
            tlv_val = data[4 : 4 + tlv_len]
            out_type = None
            resp = None
            if tlv_type in (OTRv4TLV.SMP_MSG_1, OTRv4TLV.SMP_MSG_1Q):
                if self.rust_smp.get_phase() in ("FAILED", "ABORTED"):
                    self.rust_smp.restart_after_failure()
                resp = self.rust_smp.process_smp1_generate_smp2(tlv_val)
                out_type = OTRv4TLV.SMP_MSG_2
            elif tlv_type == OTRv4TLV.SMP_MSG_2:
                resp = self.rust_smp.process_smp2_generate_smp3(tlv_val)
                out_type = OTRv4TLV.SMP_MSG_3
            elif tlv_type == OTRv4TLV.SMP_MSG_3:
                resp = self.rust_smp.process_smp3_generate_smp4(tlv_val)
                out_type = OTRv4TLV.SMP_MSG_4

                if self.rust_smp.is_verified():
                    self.auto_smp_completed = True
                    self.auto_smp_started = False
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                elif self.rust_smp.is_failed():
                    self.auto_smp_started = False
                    self.auto_smp_completed = False
            elif tlv_type == OTRv4TLV.SMP_MSG_4:
                verified = self.rust_smp.process_smp4(tlv_val)
                if verified:
                    self.auto_smp_completed = True
                    self.auto_smp_started = False
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                    self.tracer.trace(
                        self.peer, "SMP", "VERIFIED", "STATE_UPDATED", "role=initiator"
                    )
                    self._smp_progress_notify(
                        4,
                        4,
                        "🔵✅ SMP VERIFIED - identity confirmed!",
                        role=None,
                        color="blue",
                        final=True,
                    )
                else:
                    self.auto_smp_started = False
                    self.auto_smp_completed = False
                    self.smp_step = 0
                    self.tracer.trace(
                        self.peer,
                        "SMP",
                        "FAILED",
                        "STATE_UPDATED",
                        "secrets did not match (initiator)",
                    )
                    self._smp_progress_notify(
                        0,
                        4,
                        "🔴❌ SMP FAILED - secrets did not match",
                        role=None,
                        color="red",
                        final=True,
                    )
                return None
            elif tlv_type == OTRv4TLV.SMP_ABORT:
                if self.rust_smp.get_phase() != "VERIFIED":
                    self.rust_smp.abort()
                return None
            if resp is not None and out_type is not None:
                return self.encrypt_with_tlvs("", [OTRv4TLV(out_type, bytes(resp))])
            return None
        except Exception as e:
            import traceback as _tb

            self.logger.debug("process_smp_message FAILED")
            return None
        finally:
            self._release_lock()

    def get_smp_status(self) -> Dict[str, Any]:
        """Return SMP status from the Rust engine."""
        if not self._acquire_lock():
            return {
                "state": "NONE",
                "verified": False,
                "failed": False,
                "progress": "0/4",
                "can_start_smp": False,
                "secret_set": False,
            }
        try:
            if self.rust_smp is None:
                return {
                    "state": "NONE",
                    "verified": False,
                    "failed": False,
                    "progress": "0/4",
                    "has_question": False,
                    "question": "",
                    "can_start_smp": self.session_state == SessionState.ENCRYPTED,
                    "can_retry": False,
                    "retry_count": 0,
                    "expired": False,
                    "secret_set": False,
                }
            phase = self.rust_smp.get_phase()
            verified = self.rust_smp.is_verified()
            failed = phase == "FAILED"
            step_map = {
                "IDLE": 0,
                "AWAITING_MSG2": 1,
                "AWAITING_MSG3": 2,
                "AWAITING_MSG4": 3,
                "VERIFIED": 4,
                "FAILED": 0,
            }
            step = step_map.get(phase, 0)
            return {
                "state": phase,
                "verified": verified or self.auto_smp_completed,
                "failed": failed,
                "failure_reason": "" if not failed else "secrets did not match",
                "progress": f"{step }/4",
                "has_question": False,
                "question": "",
                "can_start_smp": phase in ("IDLE", "FAILED")
                and self.session_state == SessionState.ENCRYPTED,
                "can_retry": failed,
                "retry_count": 0,
                "expired": False,
                "secret_set": self.rust_smp.check_secret_set(),
            }
        except Exception as e:
            self.logger.debug("get_smp_status FAILED")
            return {
                "state": "NONE",
                "verified": False,
                "failed": False,
                "progress": "0/4",
                "can_start_smp": self.session_state == SessionState.ENCRYPTED,
            }
        finally:
            self._release_lock()

    def get_smp_progress(self) -> Tuple[int, int]:
        """Get SMP progress as (step, total_steps)."""
        if self.rust_smp is None:
            return (0, 4)
        phase = self.rust_smp.get_phase()
        step_map = {
            "IDLE": 0,
            "AWAITING_MSG2": 1,
            "AWAITING_MSG3": 2,
            "AWAITING_MSG4": 3,
            "VERIFIED": 4,
            "FAILED": 0,
        }
        return (step_map.get(phase, 0), 4)

    def set_smp_secret(self, secret: str):
        """Bind the SMP secret to the current session via the Rust vault.

        Flow:
          1. Encode secret to a bytearray (mutable, can be wiped).
          2. Store bytes in RustSMPVault (Rust-owned, ZeroizeOnDrop).
          3. Call rust_smp.set_secret_from_vault() - bytes never leave Rust
             as a Python object on the SHAKE-256/HMAC path.
          4. Overwrite the bytearray and delete it.
          5. Set auto_smp_secret = True (flag only - plaintext is NOT stored).

        Raises:
            ValueError:   secret shorter than 8 characters.
            RuntimeError: SMP protocol run already active (never rebind mid-run).
        """
        _MIN_LEN = 8
        if len(secret) < _MIN_LEN:
            raise ValueError(f"SMP secret must be at least {_MIN_LEN } characters.")

        def _fill(vault):
            raw = bytearray(secret.encode("utf-8"))
            try:
                # store_from_bytearray, not store(bytes(raw)).
                #
                # The bytearray exists so it can be wiped -- but `bytes(raw)`
                # would make an immutable copy that nothing can overwrite.
                # Handing the bytearray straight down means Rust copies it into
                # a ZeroizeOnDrop entry and zeroes our buffer before returning.
                vault.store_from_bytearray("smp_secret", raw)
            finally:
                # Belt and braces: store_from_bytearray already zeroed it, and
                # this still runs if the call raised before reaching Rust.
                for i in range(len(raw)):
                    raw[i] = 0
                del raw

        self._bind_smp_secret(_fill)

    def set_smp_secret_from_store(self, store, peer: str) -> bool:
        """Bind `peer`'s passphrase from a Rust `SmpSecretStore`.

        The auto-respond path. The passphrase goes store -> this session's
        `RustSMPVault` -> `RustSMP` without becoming a Python object; there is
        no way for this method to see it. Returns False when none is stored.
        """
        if not store.has(peer):
            return False

        def _fill(vault):
            if not store.bind_into(peer, vault, "smp_secret"):
                raise RuntimeError("the stored passphrase disappeared while binding")

        self._bind_smp_secret(_fill)
        return True

    def _bind_smp_secret(self, fill) -> None:
        """Phase checks, then `fill(vault)`, then bind the vault entry into SMP
        with this session's id and both fingerprints. Shared by both setters."""
        if not self._acquire_lock():
            return
        try:

            if self.rust_smp is not None:
                phase = self.rust_smp.get_phase()
                # SECRET_REQUIRED is included deliberately: it means a peer's
                # SMP1 is parked waiting for exactly this call.  The others are
                # states with no run in flight.  AWAITING_MSG2/3/4 are not, and
                # rebinding under those would change the secret mid-proof.
                if phase not in ("IDLE", "FAILED", "VERIFIED", "ABORTED",
                                 "SECRET_REQUIRED"):
                    raise RuntimeError(
                        f"Cannot rebind SMP secret while SMP is active "
                        f"(current phase: {phase }). Abort the current run first."
                    )
            self.initialize_smp()
            if self.rust_smp is None or self.smp_vault is None:
                raise RuntimeError("Rust SMP engine not initialized")

            sid = self.session_id or b""
            local_fp = b""
            try:
                if self.dake_engine and self.dake_engine.client_profile:
                    cp = self.dake_engine.client_profile

                    if cp.identity_pub_bytes:
                        local_fp = cp.identity_pub_bytes
                    elif cp.identity_key:
                        local_fp = bytes(cp.identity_key.public_bytes())
            except Exception:
                pass
            remote_fp = self._remote_long_term_pub_bytes or b""

            fill(self.smp_vault)
            ok = self.rust_smp.set_secret_from_vault(
                self.smp_vault, "smp_secret", sid, local_fp, remote_fp
            )
            if not ok:
                raise RuntimeError("Vault key not found after store - internal error")

            if not self.rust_smp.check_secret_set():
                raise RuntimeError("Rust SMP secret not stored after set_secret_from_vault")

            self.auto_smp_secret = True
        finally:
            self._release_lock()

    def can_start_smp(self) -> bool:
        """Check if SMP can be started."""
        if not self._acquire_lock():
            return False
        try:
            if self.session_state != SessionState.ENCRYPTED:
                return False
            if self.rust_smp is None:
                return True
            phase = self.rust_smp.get_phase()
            return phase in ("IDLE", "FAILED")
        finally:
            self._release_lock()

    def get_state_summary(self) -> Dict[str, Any]:
        """Get comprehensive state summary"""
        if not self._acquire_lock():
            return {}

        try:
            smp_status = self.get_smp_status() if hasattr(self, "get_smp_status") else {}

            return {
                "peer": self.peer,
                "session_state": self.session_state.name,
                "dake_state": self.dake_state.name,
                "smp_state": smp_status.get("state", "NONE"),
                "security_level": self.security_level.name,
                "is_initiator": self.is_initiator,
                "session_id": self.session_id.hex()[:16] if self.session_id else None,
                "created": time.ctime(self.created),
                "last_activity": time.ctime(self.last_activity),
                "queued_messages": len(self.pending_messages),
                "has_ratchet": self.ratchet is not None,
                "has_smp": self.rust_smp is not None,
                "is_encrypted": self.session_state == SessionState.ENCRYPTED,
                "is_active": self.session_state not in [SessionState.FINISHED, SessionState.FAILED],
                "fingerprint": self.get_fingerprint(),
                "smp_verified": smp_status.get("verified", False),
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
        return (
            self.session_state == SessionState.PLAINTEXT
            and self.dake_state == DAKEState.IDLE
            and self.is_initiator
        )

    def __del__(self):
        """Destructor - ensure cleanup"""
        try:
            if hasattr(self, "session_state") and self.session_state != SessionState.FINISHED:
                self.terminate("session destroyed")
        except Exception:
            pass


def _ephemeral_mldsa_identity() -> Optional["MLDSA87Auth"]:
    """One ML-DSA key for an ephemeral identity's lifetime, like its Ed448
    key: per process, not per handshake, so a peer's pin holds for the run."""
    if not MLDSA87_AVAILABLE:
        return None
    try:
        return MLDSA87Auth()
    except Exception:
        return None


def _note_pq_refusal(manager, peer: str, code: str, detail: str) -> bool:
    manager.__dict__.setdefault("pq_refusals", {})[peer] = code
    tracer = getattr(manager, "tracer", None)
    if tracer is not None:
        tracer.trace(peer, "ERROR", "DAKE", "PQ_REFUSED", f"{code }: {detail }")
    return True


def _refuse_old_protocol(manager, peer: str, dake) -> bool:
    """Refuse a peer whose signed profile lacks either v2 capability.

    Checked by the responder on DAKE1, before it answers, and by the initiator
    on DAKE2, before anything is encrypted. The profile is signed and in the
    transcript, so what it lists is what the peer runs.
    """
    config = getattr(manager, "config", None)
    if not getattr(config, "require_pq_v2", True):
        return False
    versions = getattr(getattr(dake, "remote_profile", None), "versions", None) or ()
    needed = (OTRConstants.PQ_RATCHET_VERSION, OTRConstants.PQ_AUTH_VERSION)
    if all(v in versions for v in needed):
        return False
    return _note_pq_refusal(
        manager, peer, "pq_v2_required",
        f"peer lists versions {list (versions )}; this build requires "
        f"{[hex (v ) for v in needed ]} (A1, A2 fixed). Connection refused.")


def _refuse_pq_identity(manager, peer: str, dake) -> bool:
    """A2: the version policy, then the peer's ML-DSA pin, once its DAKE
    message has verified.

    True means refused: the caller abandons the handshake, and the code is
    kept for `take_pq_refusal` so the app can say why.
    """
    if _refuse_old_protocol(manager, peer, dake):
        return True
    trust = getattr(manager, "trust_db", None)
    identity = getattr(dake, "remote_identity_pub_bytes", None)
    if trust is None or not identity:
        return False
    try:
        trust.check_or_pin_pq(peer, identity, dake.verified_peer_mldsa_pub, dake.pq_auth)
    except TrustDatabase.PqIdentityRefused as refused:
        return _note_pq_refusal(manager, peer, refused.code, str(refused))
    return False


class SessionManager:
    """Session manager - owns DAKE engines and delegates to EnhancedOTRSession."""

    def __init__(self, config: Optional[OTRConfig] = None, logger: Optional[OTRLogger] = None):
        self.config = config or OTRConfig(test_mode=True)
        self.logger = logger or NullLogger()

        self.trust_db = TrustDatabase(self.config.trust_db_path,
                                      persistent=self.config.persist_trust)
        self.smp_storage = SMPAutoRespondStorage(self.config.smp_secrets_path)
        _remove_retired_key_storage(self.config.key_storage_path)

        # Identity.  Ephemeral unless the caller explicitly asked otherwise,
        # because ephemeral is the IRC contract and IRC must not acquire a
        # persistent identity by inheriting a default.
        self.identity_is_persistent = False
        self.client_profile = self._build_client_profile()

        self.lock = threading.RLock()

        self.sessions: Dict[str, EnhancedOTRSession] = {}
        self.pending_dakes: Dict[str, RustDAKEAdapter] = {}
        self._disconnect_callbacks: list = []


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

    def _build_client_profile(self):
        """Return the ClientProfile this manager will use.

        Two behaviours, chosen by config and never by guesswork:

        * ``persist_identity`` false -- a fresh Ed448 identity, as OTRv4+ has
          always done (ROADMAP Phase 5.3g).  This is the IRC contract: a nick
          is ephemeral, so an identity pinned to one is pinned to nothing.
        * ``persist_identity`` true -- the same identity every run, loaded from
          a sealed record.  This is the XMPP contract: a JID is durable, so an
          identity that changed under it every launch made TOFU meaningless and
          made every reconnect look like a MITM.

        Failure is closed.  If persistence was asked for and cannot be
        delivered this raises, rather than quietly handing back an ephemeral
        identity -- a silent fallback would change the local fingerprint with no
        indication, and every peer holding a pin would see the change TOFU
        exists to report.
        """
        if not self.config.persist_identity:
            profile = ClientProfile()
            profile.mldsa_identity = _ephemeral_mldsa_identity()
            return profile

        # Imported here, not at module scope: the IRC client must never load
        # the persistence machinery at all, and an import that only happens on
        # the opted-in path makes that checkable rather than a promise.
        from otrv4plus_identity import (load_or_create_identity, load_or_create_mldsa,
                                        IdentityUnavailable)

        try:
            identity, prekey, _pub = load_or_create_identity(
                self.config.identity_path, self.config.identity_dek_path)
            mldsa = load_or_create_mldsa(
                self.config.identity_path, self.config.identity_dek_path)
        except IdentityUnavailable:
            self._trace_identity("FAILED",
                                 "persistent identity unavailable - failing closed")
            raise

        self.identity_is_persistent = True
        self._trace_identity("READY", "persistent identity loaded")
        profile = ClientProfile(identity_key=identity, prekey=prekey)
        profile.mldsa_identity = MLDSA87Auth(handle=mldsa)
        return profile

    def _trace_identity(self, state: str, detail: str) -> None:
        """Trace without assuming this manager has a tracer (SessionManager does not)."""
        tracer = getattr(self, "tracer", None)
        if tracer is not None:
            try:
                tracer.trace("SYSTEM", "IDENTITY", None, state, detail)
            except Exception:
                pass
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

            dake = RustDAKEAdapter(
                client_profile=self.client_profile, explicit_initiator=True, logger=self.logger
            )

            try:
                dake1 = dake.generate_dake1()
                self.pending_dakes[peer] = dake
                return dake1
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to start session: {e }")
                return None
        finally:
            self._release_lock()

    def handle_dake1(self, peer: str, dake1_msg: str) -> Optional[str]:
        """Handle incoming DAKE1 message"""
        if not self._acquire_lock():
            return None

        try:
            dake = RustDAKEAdapter(
                client_profile=self.client_profile, explicit_initiator=False, logger=self.logger
            )

            try:
                # `peer`, not the default. Omitting it put every peer in one
                # bucket, so the "per-peer" limit was process-wide and one
                # sender could lock out DAKE1 from everybody else.
                success = dake.process_dake1(dake1_msg, peer)
                if success and _refuse_old_protocol(self, peer, dake):
                    return None
                if success:
                    dake2 = dake.generate_dake2()
                    self.pending_dakes[peer] = dake
                    return dake2
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to handle DAKE1: {e }")
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
                if success and _refuse_pq_identity(self, peer, dake):
                    del self.pending_dakes[peer]
                    return None
                if success:
                    dake3 = dake.generate_dake3()

                    session = EnhancedOTRSession(
                        peer=peer,
                        is_initiator=True,
                        tracer=OTRTracer(enabled=DEBUG_MODE),
                        logger=self.logger,
                    )
                    if getattr(self, "smp_notify_factory", None):
                        session._smp_notify_cb = self.smp_notify_factory(peer)
                    if getattr(self, "ping_refresh_cb", None):
                        session._ping_refresh_cb = self.ping_refresh_cb

                    session_keys = dake.get_session_keys()
                    if session_keys:
                        session.session_id = session_keys.get("session_id")
                        session.root_key = session_keys.get("root_key")
                        session.remote_long_term_pub = session_keys.get("peer_long_term_pub")

                    session.smp_guided_prompt = getattr(
                        self, "smp_guided_prompt", False)
                    self.sessions[peer] = session
                    del self.pending_dakes[peer]

                    return dake3
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to handle DAKE2: {e }")
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
                if success and _refuse_pq_identity(self, peer, dake):
                    del self.pending_dakes[peer]
                    return False
                if success:
                    session = EnhancedOTRSession(
                        peer=peer,
                        is_initiator=False,
                        tracer=OTRTracer(enabled=DEBUG_MODE),
                        logger=self.logger,
                    )
                    if getattr(self, "smp_notify_factory", None):
                        session._smp_notify_cb = self.smp_notify_factory(peer)
                    if getattr(self, "ping_refresh_cb", None):
                        session._ping_refresh_cb = self.ping_refresh_cb

                    session_keys = dake.get_session_keys()
                    if session_keys:
                        session.session_id = session_keys.get("session_id")
                        session.root_key = session_keys.get("root_key")
                        session.remote_long_term_pub = session_keys.get("peer_long_term_pub")

                    session.smp_guided_prompt = getattr(
                        self, "smp_guided_prompt", False)
                    self.sessions[peer] = session
                    del self.pending_dakes[peer]
                    return True
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to handle DAKE3: {e }")
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
                print(f"Encryption failed: {e }")
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
            raise ValueError(f"No session with {peer }")

        try:
            session = self.sessions[peer]
            plaintext = session.decrypt_message(encrypted_msg)

            queued = getattr(session, "_queued_smp_response", None)
            if queued:
                session._queued_smp_response = None
                return queued.encode("utf-8") if isinstance(queued, str) else queued

            return plaintext
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e }", session=self.sessions.get(peer))

    def get_session_info(self, peer: str) -> Dict[str, Any]:
        """Get session information"""
        if peer not in self.sessions:
            return {}

        session = self.sessions[peer]
        return session.get_state_summary() if hasattr(session, "get_state_summary") else {}

    def display_fingerprints(self, peer: str) -> str:
        """Display fingerprints for session"""
        if peer not in self.sessions:
            return ""

        session = self.sessions[peer]
        local_fp = self.get_fingerprint()
        remote_fp = session.get_fingerprint() if hasattr(session, "get_fingerprint") else ""

        return f"Local: {local_fp }\nRemote: {remote_fp }"

    def set_smp_secret(self, peer: str, secret: str) -> bool:
        """Set SMP secret for auto-respond"""
        try:
            self.smp_storage.set_secret(peer, secret)
            self.logger.debug("set_smp_secret: stored")
        except Exception as e:
            self.logger.debug("set_smp_secret: storage FAILED")

        if peer in self.sessions:
            try:
                session = self.sessions[peer]
                if hasattr(session, "set_smp_secret"):
                    session.set_smp_secret(secret)
                    self.logger.debug("set_smp_secret: session bound")
            except Exception as e:
                self.logger.debug("set_smp_secret: session bind FAILED")

        return True

    def start_smp(self, peer: str, secret: str, question: Optional[str] = None) -> Optional[str]:
        """Start SMP verification - returns encrypted message ready to send."""
        self.logger.debug("start_smp: called")

        if peer not in self.sessions:
            self.logger.debug("start_smp: no session")
            return None

        session = self.sessions[peer]

        if hasattr(session, "start_smp"):
            self.logger.debug("start_smp: calling session")
            result = session.start_smp(secret, question)
            self.logger.debug("start_smp: returned")
            return result

        self.logger.debug(f"start_smp: Session has no start_smp method")
        return None

    def process_smp_message(self, peer: str, smp_tlv: bytes) -> Optional[str]:
        """Process SMP message and return encrypted response"""
        if peer not in self.sessions:
            return None

        try:
            session = self.sessions[peer]

            self.smp_storage.bind_into(peer, session)

            if hasattr(session, "process_smp_message"):
                return session.process_smp_message(smp_tlv)

        except Exception as e:
            if DEBUG_MODE:
                print("SMP message processing failed")

        return None

    def get_smp_status(self, peer: str) -> Dict[str, Any]:
        """Get SMP status for session."""
        if peer not in self.sessions:
            self.logger.debug("get_smp_status: no session")
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
                "auto_smp_secret": self.smp_storage.has_secret(peer),
                "auto_smp_started": False,
                "auto_smp_completed": False,
                "can_retry": False,
                "retry_count": 0,
                "expired": False,
            }

        session = self.sessions[peer]

        if hasattr(session, "get_smp_status"):
            status = session.get_smp_status()
            if "is_initiator" not in status:
                status["is_initiator"] = getattr(session, "is_initiator", False)
            status["auto_smp_secret"] = self.smp_storage.has_secret(peer)
            status["auto_smp_started"] = getattr(session, "auto_smp_started", False)
            status["auto_smp_completed"] = getattr(session, "auto_smp_completed", False)
            status["should_auto_start_smp"] = False
            status["can_start_smp"] = status.get(
                "can_start_smp",
                session.can_start_smp() if hasattr(session, "can_start_smp") else False,
            )

            self.logger.debug("get_smp_status: returned")
            return status

        return {
            "state": "NONE",
            "verified": False,
            "failed": False,
            "progress": "0/4",
            "is_initiator": getattr(session, "is_initiator", False),
            "can_start_smp": hasattr(session, "can_start_smp") and session.can_start_smp(),
            "should_auto_start_smp": False,
            "has_question": False,
            "question": "",
            "auto_smp_secret": self.smp_storage.has_secret(peer),
            "auto_smp_started": False,
            "auto_smp_completed": False,
            "can_retry": False,
            "retry_count": 0,
            "expired": False,
        }

    def get_smp_progress(self, peer: str) -> Tuple[int, int]:
        """Get SMP progress"""
        if peer not in self.sessions:
            return (0, 4)

        session = self.sessions[peer]
        if hasattr(session, "get_smp_progress"):
            return session.get_smp_progress()
        return (0, 4)

    def get_smp_question(self, peer: str) -> str:
        """Get SMP question if any"""
        if peer not in self.sessions:
            return ""

        session = self.sessions[peer]
        if hasattr(session, "get_smp_question"):
            return session.get_smp_question()
        return ""

    def is_smp_verified(self, peer: str) -> bool:
        """Check if SMP is verified"""
        if peer not in self.sessions:
            return False

        session = self.sessions[peer]
        if hasattr(session, "is_smp_verified"):
            return session.is_smp_verified()
        status = self.get_smp_status(peer)
        return status.get("verified", False)

    def abort_smp(self, peer: str) -> bool:
        """Abort SMP for a peer"""
        if peer not in self.sessions:
            return False

        session = self.sessions[peer]
        if hasattr(session, "abort_smp"):
            return session.abort_smp()
        return False

    def process_auto_smp(self, peer: str, smp_tlv: bytes) -> Optional[str]:
        """Process SMP message with auto-respond"""
        if peer not in self.sessions:
            return None

        try:
            session = self.sessions[peer]
            if hasattr(session, "process_auto_smp_response"):
                return session.process_auto_smp_response(smp_tlv)
        except Exception as e:
            if DEBUG_MODE:
                print("Auto-SMP processing failed")
        return None

    def check_and_start_auto_smp(self, peer: str) -> Optional[str]:
        """Check and start auto-SMP if configured and appropriate"""
        return None

    def end_session(self, peer: str):
        """End session with peer - sends TLV_TYPE_DISCONNECTED per OTRv4 spec §3.6"""
        if not self._acquire_lock():
            return

        try:
            if peer in self.sessions:
                session = self.sessions[peer]
                try:
                    if hasattr(session, "send_disconnect"):
                        encrypted = session.send_disconnect()
                        if encrypted:
                            self._disconnect_callbacks.append((peer, encrypted))
                except Exception:
                    pass
                session.terminate("session ended")
                del self.sessions[peer]
                self.logger.debug("end_session: ended")
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

    def __init__(
        self,
        config: Optional[OTRConfig] = None,
        tracer: Optional[OTRTracer] = None,
        logger: Optional[OTRLogger] = None,
    ):
        self.config = config or OTRConfig(test_mode=True)
        self.tracer = tracer or OTRTracer(enabled=True)
        self.logger = logger or NullLogger()

        self.trust_db = TrustDatabase(self.config.trust_db_path,
                                      persistent=self.config.persist_trust)
        self.smp_storage = SMPAutoRespondStorage(self.config.smp_secrets_path)
        _remove_retired_key_storage(self.config.key_storage_path)

        # Identity.  Ephemeral unless the caller explicitly asked otherwise,
        # because ephemeral is the IRC contract and IRC must not acquire a
        # persistent identity by inheriting a default.
        self.identity_is_persistent = False
        self.client_profile = self._build_client_profile()

        self.sessions: Dict[str, EnhancedOTRSession] = {}
        self.dake_engines: Dict[str, RustDAKEAdapter] = {}
        # A handshake answering a DAKE1 that arrived on an ENCRYPTED session.
        # The live session keeps working until this one completes; see
        # `_handle_dake1`.
        self._pending_sessions: Dict[str, "EnhancedOTRSession"] = {}
        # The DAKE1 we last sent each peer, for glare resolution.
        self._sent_dake1: Dict[str, str] = {}
        # Peers whose DATA frame arrived with no encrypted session here.
        self._orphan_data: set = set()
        # The DAKE1 each in-flight responder run is answering: a duplicate of
        # it (a glare resend, a re-delivered stanza) is not a new handshake.
        self._answering_dake1: Dict[str, bytes] = {}

        self.lock = threading.RLock()

        self.smp_notify_factory = None


        self.tracer.trace("SYSTEM", "MANAGER", None, "READY", "session manager initialized")

    def _build_client_profile(self):
        """Return the ClientProfile this manager will use.

        Two behaviours, chosen by config and never by guesswork:

        * ``persist_identity`` false -- a fresh Ed448 identity, as OTRv4+ has
          always done (ROADMAP Phase 5.3g).  This is the IRC contract: a nick
          is ephemeral, so an identity pinned to one is pinned to nothing.
        * ``persist_identity`` true -- the same identity every run, loaded from
          a sealed record.  This is the XMPP contract: a JID is durable, so an
          identity that changed under it every launch made TOFU meaningless and
          made every reconnect look like a MITM.

        Failure is closed.  If persistence was asked for and cannot be
        delivered this raises, rather than quietly handing back an ephemeral
        identity -- a silent fallback would change the local fingerprint with no
        indication, and every peer holding a pin would see the change TOFU
        exists to report.
        """
        if not self.config.persist_identity:
            profile = ClientProfile()
            profile.mldsa_identity = _ephemeral_mldsa_identity()
            return profile

        # Imported here, not at module scope: the IRC client must never load
        # the persistence machinery at all, and an import that only happens on
        # the opted-in path makes that checkable rather than a promise.
        from otrv4plus_identity import (load_or_create_identity, load_or_create_mldsa,
                                        IdentityUnavailable)

        try:
            identity, prekey, _pub = load_or_create_identity(
                self.config.identity_path, self.config.identity_dek_path)
            mldsa = load_or_create_mldsa(
                self.config.identity_path, self.config.identity_dek_path)
        except IdentityUnavailable:
            self._trace_identity("FAILED",
                                 "persistent identity unavailable - failing closed")
            raise

        self.identity_is_persistent = True
        self._trace_identity("READY", "persistent identity loaded")
        profile = ClientProfile(identity_key=identity, prekey=prekey)
        profile.mldsa_identity = MLDSA87Auth(handle=mldsa)
        return profile

    def _trace_identity(self, state: str, detail: str) -> None:
        """Trace without assuming this manager has a tracer (SessionManager does not)."""
        tracer = getattr(self, "tracer", None)
        if tracer is not None:
            try:
                tracer.trace("SYSTEM", "IDENTITY", None, state, detail)
            except Exception:
                pass
    def get_or_create_session(self, peer: str, is_initiator: bool = False) -> EnhancedOTRSession:
        """Get existing session or create new one"""
        with self.lock:
            self._refuse_if_wiped()
            ended = self.sessions.get(peer)
            if ended is not None and ended.session_state in (SessionState.FINISHED,
                                                             SessionState.FAILED):
                # An ended session is never taken up again: a new handshake
                # gets a new session, with nothing of the old one -- not its
                # ratchet, not its instance tags (L1: "no cryptographic link
                # to the previous transcript"). What it published goes first.
                self._collect_revelation(peer, ended)
                try:
                    ended._cleanup_resources()
                except Exception:
                    pass
                self._collect_revelation(peer, ended)
                del self.sessions[peer]
            if peer in self.sessions:
                session = self.sessions[peer]

                if session.is_initiator != is_initiator:
                    self.tracer.trace(
                        peer,
                        "ROLE",
                        "INITIATOR" if session.is_initiator else "RESPONDER",
                        "INITIATOR" if is_initiator else "RESPONDER",
                        "role updated",
                    )
                    session.is_initiator = is_initiator

                if session._smp_notify_cb is None and self.smp_notify_factory is not None:
                    try:
                        session._smp_notify_cb = self.smp_notify_factory(peer)
                    except Exception:
                        pass
                if session._ping_refresh_cb is None and getattr(self, "ping_refresh_cb", None):
                    session._ping_refresh_cb = self.ping_refresh_cb

                return session

            session = self._new_session(peer, is_initiator)
            self.sessions[peer] = session

            self.tracer.trace(
                peer,
                "SESSION",
                None,
                "CREATED",
                f"new session (role: {'initiator'if is_initiator else 'responder'})",
            )

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

    def send_tlv(self, peer: str, tlv_type: int, value: bytes) -> Optional[str]:
        """Encrypt a bare TLV for `peer`.  Returns the wire frame, or None.

        Fail-closed and deliberately narrower than `handle_outgoing_message`:
        it will NOT open a session, queue for later, or fall back to
        plaintext.  There must already be an ENCRYPTED session, or the caller
        gets None and is expected to say so.  A feature TLV that quietly
        started a DAKE would send a peer a handshake they never asked for; one
        that fell back to plaintext would put its payload on the wire in the
        clear, which is exactly what the OTR channel exists to prevent.

        The empty text is not padding waste -- OTRv4Payload adds a random
        PADDING TLV, so a TLV-only message is not distinguishable by length
        from a short chat message.
        """
        if tlv_type not in _HANDLER_TLV_TYPES:
            raise ValueError("TLV type 0x%04x is not open to callers"
                             % tlv_type)
        with self.lock:
            session = self.sessions.get(peer)
            if session is None or not session.is_encrypted():
                return None
            try:
                return session.encrypt_with_tlvs("", [OTRv4TLV(tlv_type, value)])
            except Exception as e:
                self.tracer.trace(peer, "ERROR", "SEND-TLV", "FAILED", str(e)[:80])
                return None

    def send_text_with_tlv(self, peer: str, text: str, tlv_type: int,
                           value: bytes) -> Optional[str]:
        """Encrypt [text] with one feature TLV attached. Returns the wire
        frame, or None.

        `send_tlv` with a body: the same fail-closed rules (an ENCRYPTED
        session must already exist; nothing is queued, nothing falls back to
        plaintext) and the same allow-list of types. Used for a typed message
        that carries its MESSAGE_META (its id, or the message it corrects or
        replies to): the text and its meta are one authenticated payload.
        """
        if tlv_type not in _HANDLER_TLV_TYPES:
            raise ValueError("TLV type 0x%04x is not open to callers"
                             % tlv_type)
        with self.lock:
            session = self.sessions.get(peer)
            if session is None or not session.is_encrypted():
                return None
            try:
                return session.encrypt_with_tlvs(text, [OTRv4TLV(tlv_type, value)])
            except Exception as e:
                self.tracer.trace(peer, "ERROR", "SEND-TLV", "FAILED", str(e)[:80])
                return None

    def handle_outgoing_message(self, peer: str, message: str) -> Tuple[Optional[str], bool]:
        """
        Handle outgoing message with opportunistic OTR.
        Returns: (encrypted_message_or_dake_message, should_send)
        """
        with self.lock:
            self._refuse_if_wiped()
            session = self.get_or_create_session(peer, is_initiator=True)

            if session.is_encrypted():
                try:
                    encrypted = session.encrypt_message(message)
                    self.tracer.trace(
                        peer,
                        "SEND",
                        "ENCRYPTED",
                        "READY",
                        f"message encrypted ({len (message )} chars)",
                    )
                    return encrypted, True
                except Exception as e:
                    self.tracer.trace(peer, "ERROR", "ENCRYPT", "FAILED", str(e))
                    return None, False

            elif session.session_state == SessionState.PLAINTEXT:
                if session.should_start_dake():
                    self.tracer.trace(
                        peer, "OPPORTUNISTIC", "IDLE", "STARTING", f"first message to {peer }"
                    )

                    dake_engine = session.initialize_dake(
                        self.client_profile, explicit_initiator=True
                    )
                    self.dake_engines[peer] = dake_engine

                    dake1 = session.start_dake()
                    if dake1:
                        self._sent_dake1[peer] = dake1
                        session.queue_outgoing_message(message)

                        self.tracer.trace(
                            peer,
                            "QUEUE",
                            "MESSAGE",
                            "QUEUED",
                            f"message queued for later encryption",
                        )

                        return dake1, True
                    else:
                        self.tracer.trace(peer, "ERROR", "DAKE", "FAILED", "could not start DAKE")
                        return None, False
                else:
                    self.tracer.trace(
                        peer, "ERROR", "SEND", "BLOCKED", f"plaintext session but DAKE not started"
                    )
                    return None, False

            elif session.session_state == SessionState.DAKE_IN_PROGRESS:
                session.queue_outgoing_message(message)

                self.tracer.trace(
                    peer, "QUEUE", "MESSAGE", "QUEUED", f"DAKE in progress, message queued"
                )

                return None, False

            else:
                self.tracer.trace(
                    peer,
                    "ERROR",
                    "SEND",
                    "BLOCKED",
                    f"session in state: {session .session_state .name }",
                )
                return None, False

    def handle_incoming_message(self, peer: str, message: str) -> Optional[bytes]:
        """
        Handle incoming message, routing to DAKE or decryption as appropriate.
        Returns decrypted plaintext if applicable.
        """
        with self.lock:
            self._refuse_if_wiped()
            if message.startswith("?OTRv4 "):
                return self._handle_otr_message(peer, message)

            session = self.get_session(peer)
            if session and session.is_encrypted():
                self.tracer.trace(
                    peer,
                    "ERROR",
                    "RECEIVE",
                    "PLAINTEXT",
                    f"encrypted session but received plaintext - possible downgrade attack",
                )
                return None

            return message.encode("utf-8") if isinstance(message, str) else message

    def _handle_otr_message(self, peer: str, message: str) -> Optional[bytes]:
        """Handle OTRv4 protocol message"""
        with self.lock:
            try:
                # NB: route through _safe_b64decode rather than a bespoke
                # decoder here.  DATA frames carry a trailing '.' terminator and
                # the body uses the URL-SAFE alphabet ('-'/'_'); _safe_b64decode
                # strips the dot and decodes url-safe correctly.  The previous
                # inline decoder left the '.' in place, so urlsafe_b64decode hit
                # "Incorrect padding" and the standard-b64decode fallback then
                # silently dropped every '-'/'_' (and the dot), yielding a
                # 1-mod-4 length and the "cannot be 1 more than a multiple of 4"
                # crash on the very first plaintext DATA message.
                payload = message[7:].strip()
                decoded = _safe_b64decode(payload)

                if len(decoded) < 1:
                    return None

                if (
                    OTRv4DataMessage.looks_like_data_frame(decoded)
                ):
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
                    self.tracer.trace(
                        peer, "ERROR", "PARSE", "UNKNOWN", f"unknown message type: {msg_type }"
                    )
                    return None

            except Exception as e:
                self.tracer.trace(peer, "ERROR", "PARSE", "FAILED", str(e))
                return None

    @staticmethod
    def _flagged_ignore_unreadable(data_msg: str) -> bool:
        """Whether a DATA frame says IGNORE_UNREADABLE: a peer's closing
        message (L1, SPEC §5.8) arriving after our side of the session is
        gone. Such a frame is dropped quietly -- never taken as a session we
        lost, which would start a handshake for a session both sides ended.
        Read from the public header only; nothing is decrypted."""
        try:
            raw = str(data_msg)[len("?OTRv4 "):].strip()
            decoded = _safe_b64decode(raw)
            if not OTRv4DataMessage.looks_like_data_frame(decoded):
                return False
            return bool(OTRv4DataMessage.decode(decoded).flags
                        & OTRv4DataMessage.FLAG_IGNORE_UNREADABLE)
        except Exception:
            return False

    def take_orphan_data(self, peer: str) -> bool:
        """Whether `peer` sent a DATA frame we had no session for, since asked.

        The peer holds a session this side does not: we restarted (every
        launch is a new identity), or their DAKE3 never arrived. Nothing can
        be decrypted until a new handshake runs, and the peer has no reason to
        start one. The caller decides whether to; this only reports it.
        """
        with self.lock:
            if peer in self._orphan_data:
                self._orphan_data.discard(peer)
                return True
            return False

    def _new_session(self, peer: str, is_initiator: bool) -> "EnhancedOTRSession":
        """A session object configured like `get_or_create_session` makes one,
        NOT entered in `self.sessions`."""
        session = EnhancedOTRSession(
            peer=peer, is_initiator=is_initiator, tracer=self.tracer, logger=self.logger
        )
        if self.smp_notify_factory is not None:
            try:
                session._smp_notify_cb = self.smp_notify_factory(peer)
            except Exception:
                pass
        if getattr(self, "ping_refresh_cb", None):
            session._ping_refresh_cb = self.ping_refresh_cb
        session.smp_guided_prompt = getattr(
            self, "smp_guided_prompt", False)
        return session

    @staticmethod
    def _dake1_key(dake1_msg: str) -> bytes:
        """What glare is decided on: the decoded DAKE1, compared as bytes."""
        try:
            return _safe_b64decode(dake1_msg[7:].strip())
        except Exception:
            return b""

    def _reset_handshake(self, peer: str, session: "EnhancedOTRSession") -> None:
        """Forget a half-finished handshake on `session`, zeroizing its engine."""
        engine = self.dake_engines.pop(peer, None)
        if engine is not None:
            try:
                engine.zeroize()
            except Exception:
                pass
        self._answering_dake1.pop(peer, None)
        session.session_state = SessionState.PLAINTEXT
        if hasattr(session, "dake_state"):
            session.dake_state = DAKEState.IDLE
        session.dake_engine = None
        self._sent_dake1.pop(peer, None)

    def _handle_dake1(self, peer: str, dake1_msg: str) -> Optional[bytes]:
        """Answer a DAKE1 -- in every state, which is what makes recovery work.

        THE DEFECT THIS FIXES
        ---------------------
        A DAKE1 was answered only from PLAINTEXT, FAILED or FINISHED. In any
        other state it was dropped, and each of those states is one a real
        network produces (measured through two bridges, and reported from
        handsets after a VPN switch):

          * DAKE2 lost: the responder sat in DAKE_IN_PROGRESS waiting for a
            DAKE3 that could never come, and refused the initiator's retry.
          * DAKE3 lost: the initiator was ENCRYPTED, the responder waiting.
            Neither side's retry was accepted by the other.
          * Peer restarted: every launch is a new identity, so the restarted
            peer starts from PLAINTEXT and sends DAKE1 -- to a side still
            ENCRYPTED with the old keys, which refused it for good.

        WHAT HAPPENS NOW, BY STATE
        --------------------------
          * Waiting for DAKE3 (responder): the new DAKE1 supersedes the old
            run. That run's keys are zeroized and this one is answered.
          * Waiting for DAKE2 (initiator), i.e. GLARE -- both sent DAKE1: the
            two DAKE1s are compared as bytes. The side whose own DAKE1 is
            greater keeps the initiator role and resends it; the other yields
            and answers. Both run the same comparison on the same two values,
            so exactly one yields. No JID is needed, which is why this lives
            here and not in each client.
          * ENCRYPTED: answered by a PENDING session. The live one keeps
            encrypting and decrypting until DAKE3 verifies; only then is it
            replaced, and its keys destroyed. There is no plaintext gap and a
            DAKE1 that goes nowhere changes nothing. The replacement is a new
            session: its SMP state starts unverified, so a verification never
            carries over to keys it did not check.

        The per-peer DAKE1 rate limit in `process_dake1` still applies in
        every case, so none of this makes a DAKE1 flood any cheaper to send.
        """
        if len(self.sessions) >= getattr(self, "MAX_SESSIONS", 50) and peer not in self.sessions:
            self.debug("session limit reached - dropping DAKE1")
            return None
        with self.lock:
            # Looked at before anything is changed: `get_or_create_session`
            # rewrites the role flag, and a live ENCRYPTED session's role must
            # not move because somebody sent a DAKE1.
            existing = self.sessions.get(peer)
            if existing is not None and existing.session_state.name == "ENCRYPTED":
                return self._answer_dake1_pending(peer, dake1_msg)
            if existing is not None and existing.session_state.name == "DAKE_IN_PROGRESS":
                session = existing
            else:
                session = self.get_or_create_session(peer, is_initiator=False)
            state = session.session_state.name

            if state == "DAKE_IN_PROGRESS":
                ours = self._sent_dake1.get(peer)
                if session.is_initiator and ours and peer not in self._pending_sessions:
                    if self._dake1_key(ours) > self._dake1_key(dake1_msg):
                        self.tracer.trace(peer, "DAKE", "DAKE1", "GLARE_KEEP",
                                          "keeping initiator role; resending DAKE1")
                        return ours.encode("utf-8")
                    self.tracer.trace(peer, "DAKE", "DAKE1", "GLARE_YIELD",
                                      "yielding initiator role")
                else:
                    self.tracer.trace(peer, "DAKE", "DAKE1", "RESTART",
                                      "new DAKE1 supersedes the handshake in progress")
                self._reset_handshake(peer, session)
                session.is_initiator = False
            elif state not in ("PLAINTEXT", "FAILED", "FINISHED"):
                self.tracer.trace(peer, "ERROR", "DAKE1", "REJECTED",
                                  f"session in state: {state }")
                return None

            if (
                session.dake_engine is not None
                and self._answering_dake1.get(peer) == self._dake1_key(dake1_msg)
            ):
                # Already answered. Restarting on a duplicate is what made a
                # glare resend cross two runs and leave one side stranded.
                self.tracer.trace(peer, "DAKE", "DAKE1", "DUPLICATE", "already answered")
                return None
            if (
                session.session_state.name in ("FAILED", "FINISHED")
                or session.dake_engine is not None
            ):
                self._reset_handshake(peer, session)
            self._answering_dake1[peer] = self._dake1_key(dake1_msg)
            dake_engine = session.initialize_dake(self.client_profile, explicit_initiator=False)
            self.dake_engines[peer] = dake_engine

            # `peer`, not the default. This is the live path -- both terminal
            # clients and the Android bridge reach DAKE1 through
            # EnhancedSessionManager -- and without the key every sender
            # shared one allowance.
            success = dake_engine.process_dake1(dake1_msg, peer)
            if not success:
                return None
            if _refuse_old_protocol(self, peer, dake_engine):
                self.dake_engines.pop(peer, None)
                return None

            dake2 = dake_engine.generate_dake2()
            if dake2:
                self.tracer.trace(peer, "DAKE", "DAKE1_PROCESSED", "DAKE2_READY", "")
                return dake2.encode("utf-8")

            return None

    def _answer_dake1_pending(self, peer: str, dake1_msg: str) -> Optional[bytes]:
        """Answer a DAKE1 on an ENCRYPTED session without touching it."""
        previous = self._pending_sessions.pop(peer, None)
        if previous is not None:
            try:
                previous.terminate("superseded by a newer DAKE1")
            except Exception:
                pass
        engine = self.dake_engines.pop(peer, None)
        if engine is not None:
            try:
                engine.zeroize()
            except Exception:
                pass
        pending = self._new_session(peer, is_initiator=False)
        dake_engine = pending.initialize_dake(self.client_profile, explicit_initiator=False)
        if not dake_engine.process_dake1(dake1_msg, peer) or _refuse_old_protocol(
                self, peer, dake_engine):
            try:
                pending.terminate("DAKE1 rejected")
            except Exception:
                pass
            return None
        dake2 = dake_engine.generate_dake2()
        if not dake2:
            return None
        self._pending_sessions[peer] = pending
        self.dake_engines[peer] = dake_engine
        self.tracer.trace(peer, "DAKE", "DAKE1_PROCESSED", "PENDING_DAKE2_READY",
                          "live session kept until the new handshake completes")
        return dake2.encode("utf-8")

    def _handle_dake2(self, peer: str, dake2_msg: str) -> Optional[bytes]:
        """
        Handle incoming DAKE2 (initiator side).
        """
        with self.lock:
            if peer not in self.sessions:
                self.tracer.trace(peer, "ERROR", "DAKE2", "NO_SESSION", "")
                return None
            session = self.sessions[peer]
            dake_engine = self.dake_engines.get(peer)
            if dake_engine is None:
                self.tracer.trace(peer, "ERROR", "DAKE2", "NO_ENGINE", "")
                return None
            try:
                if not dake_engine.process_dake2(dake2_msg):
                    self.tracer.trace(peer, "ERROR", "DAKE2", "PROCESS_FAILED", "")
                    return None
                if _refuse_pq_identity(self, peer, dake_engine):
                    self.dake_engines.pop(peer, None)
                    return None

                dake3_msg = dake_engine.generate_dake3()
                if not dake3_msg:
                    self.tracer.trace(peer, "ERROR", "DAKE3", "GEN_FAILED", "")
                    return None

                session_keys = dake_engine.get_session_keys()
                if not session_keys:
                    self.tracer.trace(peer, "ERROR", "DAKE2", "NO_KEYS", "")
                    return None

                session.session_id = session_keys.get("session_id") or secrets.token_bytes(32)
                session.root_key = session_keys.get("root_key")
                session._dake_chain_key_send = session_keys.get("chain_key_send")
                session._dake_chain_key_recv = session_keys.get("chain_key_recv")
                session._dake_brace_key = session_keys.get("brace_key")

                session._dake_output = session_keys.get("_dake_output")

                pub_key_data = session_keys.get("peer_long_term_pub")
                if isinstance(pub_key_data, bytes):
                    session._remote_long_term_pub_bytes = pub_key_data

                    session.remote_long_term_pub = None
                    self.tracer.trace(
                        peer, "KEY", "PUBKEY", "PARSED", "Successfully parsed remote pubkey (bytes)"
                    )
                elif pub_key_data is not None:

                    session.remote_long_term_pub = pub_key_data
                    try:
                        session._remote_long_term_pub_bytes = bytes(pub_key_data)
                    except Exception as e:
                        self.tracer.trace(peer, "ERROR", "PUBKEY", "BYTES_FAILED", str(e))
                        session._remote_long_term_pub_bytes = None

                self._establish_session(session, peer, "DAKE2→DAKE3 initiator")

                self.dake_engines.pop(peer, None)
                self._sent_dake1.pop(peer, None)
                self.tracer.trace(peer, "DAKE", "COMPLETE", "INITIATOR_ENCRYPTED", "")
                return dake3_msg.encode("utf-8")

            except Exception as exc:
                self.tracer.trace(peer, "ERROR", "DAKE2", "EXCEPTION", str(exc))
                pass
                return None

    def _handle_dake3(self, peer: str, dake3_msg: str) -> Optional[bytes]:
        """
        Handle incoming DAKE3 (responder side).
        """
        with self.lock:
            pending = self._pending_sessions.get(peer)
            if peer not in self.sessions and pending is None:
                self.tracer.trace(peer, "ERROR", "DAKE3", "NO_SESSION", "")
                return None
            session = pending if pending is not None else self.sessions[peer]
            dake_engine = self.dake_engines.get(peer)
            if dake_engine is None:
                self.tracer.trace(peer, "ERROR", "DAKE3", "NO_ENGINE", "")
                return None
            try:
                if not dake_engine.process_dake3(dake3_msg):
                    self.tracer.trace(peer, "ERROR", "DAKE3", "PROCESS_FAILED", "")
                    return None
                if _refuse_pq_identity(self, peer, dake_engine):
                    self.dake_engines.pop(peer, None)
                    return None

                session_keys = dake_engine.get_session_keys()
                if not session_keys:
                    self.tracer.trace(peer, "ERROR", "DAKE3", "NO_KEYS", "")
                    return None

                session.session_id = session_keys.get("session_id") or secrets.token_bytes(32)
                session.root_key = session_keys.get("root_key")
                session._dake_chain_key_send = session_keys.get("chain_key_send")
                session._dake_chain_key_recv = session_keys.get("chain_key_recv")
                session._dake_brace_key = session_keys.get("brace_key")

                session._dake_output = session_keys.get("_dake_output")

                pub_key_data = session_keys.get("peer_long_term_pub")
                if isinstance(pub_key_data, bytes):
                    session._remote_long_term_pub_bytes = pub_key_data

                    session.remote_long_term_pub = None
                    self.tracer.trace(
                        peer, "KEY", "PUBKEY", "PARSED", "Successfully parsed remote pubkey (bytes)"
                    )
                elif pub_key_data is not None:

                    session.remote_long_term_pub = pub_key_data
                    try:
                        session._remote_long_term_pub_bytes = bytes(pub_key_data)
                    except Exception as e:
                        self.tracer.trace(peer, "ERROR", "PUBKEY", "BYTES_FAILED", str(e))
                        session._remote_long_term_pub_bytes = None

                self._establish_session(session, peer, "DAKE3 responder")
                self._answering_dake1.pop(peer, None)

                if pending is not None:
                    # The new handshake is complete and authenticated: only
                    # now does it replace the live session, whose keys go.
                    self._pending_sessions.pop(peer, None)
                    old = self.sessions.get(peer)
                    self.sessions[peer] = pending
                    if old is not None and old is not pending:
                        try:
                            old.terminate("replaced by a completed DAKE")
                        except Exception:
                            pass
                    self.tracer.trace(peer, "DAKE", "COMPLETE", "SESSION_REPLACED", "")

                self.dake_engines.pop(peer, None)
                self.tracer.trace(peer, "DAKE", "COMPLETE", "RESPONDER_ENCRYPTED", "")
                return None

            except Exception as exc:
                self.tracer.trace(peer, "ERROR", "DAKE3", "EXCEPTION", str(exc))
                pass
                return None

    def take_pq_refusal(self, peer: str) -> Optional[str]:
        """The A2 refusal code for the last handshake with `peer`, once."""
        return self.__dict__.get("pq_refusals", {}).pop(peer, None)

    def _establish_session(self, session: "EnhancedOTRSession", peer: str, reason: str) -> None:
        """
        Drive EnhancedOTRSession from PLAINTEXT/DAKE_IN_PROGRESS → ENCRYPTED
        and initialise the double ratchet.
        """
        if session.session_state == SessionState.PLAINTEXT:
            try:
                session.transition_session(
                    SessionState.DAKE_IN_PROGRESS, f"{reason }: fast-path to DAKE_IN_PROGRESS"
                )
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

        if session.ratchet is None:
            try:
                session._initialize_ratchet()
            except Exception as e:
                self.tracer.trace(peer, "ERROR", "RATCHET", "INIT_FAILED", str(e))

    def _handle_data_message(self, peer: str, data_msg: str) -> Optional[bytes]:
        """Decrypt a DATA message and return the human-readable text bytes.

        Ensures the SMP secret is loaded from persistent storage into the
        active RustSMP instance *before* decryption so that any SMP TLV
        embedded in the payload (SMP1 in particular) is handled correctly
        rather than being aborted with NO_SECRET.
        """
        with self.lock:
            unreadable_ok = self._flagged_ignore_unreadable(data_msg)
            if peer not in self.sessions:
                self.tracer.trace(peer, "ERROR", "DATA", "NO_SESSION", "")
                if not unreadable_ok:
                    self._orphan_data.add(peer)
                return None
            session = self.sessions[peer]
            if not session.is_encrypted():
                self.tracer.trace(
                    peer, "ERROR", "DATA", "NOT_ENCRYPTED", session.session_state.name
                )
                if not unreadable_ok:
                    self._orphan_data.add(peer)
                return None

            try:
                if self.smp_storage.has_secret(peer):
                    needs_bind = session.rust_smp is None or not session.rust_smp.check_secret_set()
                    if needs_bind:
                        self.smp_storage.bind_into(peer, session)
            except Exception as _se:
                self.logger.debug(
                    f"_handle_data_message: smp_storage pre-load failed for {peer }: {_se }"
                )
            try:
                text_bytes = session.decrypt_message(data_msg)

                self.tracer.trace(
                    peer, "RECEIVE", "ENCRYPTED", "DECRYPTED", f"len={len (text_bytes )}"
                )

                queued = session._queued_smp_response
                session._queued_smp_response = None
                if queued:
                    return queued.encode("utf-8") if isinstance(queued, str) else queued

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
            if session.rust_smp is None:
                session.initialize_smp()

            try:
                if self.smp_storage.has_secret(peer):
                    if not session.rust_smp.check_secret_set():
                        self.smp_storage.bind_into(peer, session)
            except Exception as _se:
                self.logger.debug(
                    f"_handle_smp_message: smp_storage pre-load failed for {peer }: {_se }"
                )

            if len(smp_tlv) < 4:
                return None
            tlv_type = struct.unpack_from("!H", smp_tlv, 0)[0]
            tlv_len = struct.unpack_from("!H", smp_tlv, 2)[0]
            tlv_value = smp_tlv[4 : 4 + tlv_len]
            tlv_obj = OTRv4TLV(tlv_type, tlv_value)

            session._enh_handle_smp_tlv(tlv_obj)

            self.tracer.trace(peer, "SMP", "RECEIVED", "ROUTED", f"type=0x{tlv_type :04x}")

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

    # -- L1: closing messages (SPEC §5.8) --------------------------------

    def _collect_revelation(self, peer: str, session) -> None:
        """Keep what an ended session produced for the wire."""
        out = getattr(session, "final_revelation", None) or []
        if out:
            if not hasattr(self, "_final_revelations"):
                self._final_revelations = []
            self._final_revelations.extend((peer, wire) for wire in out)
            session.final_revelation = []

    def take_final_revelations(self) -> List[Tuple[str, str]]:
        """Every closing message waiting to be sent, as (peer, wire), oldest
        first; each is handed out once. Includes those of sessions still in
        the table (a peer that ended it, an IRC `terminate_session`)."""
        with self.lock:
            for peer, session in list(self.sessions.items()):
                self._collect_revelation(peer, session)
            out = list(getattr(self, "_final_revelations", []))
            self._final_revelations = []
            return out

    def make_deniable(self, peer: str) -> bool:
        """"Make Chat Deniable": publish every MAC key of this session, tell
        the peer it has ended (DISCONNECTED) and forget it, so a fresh
        session with no cryptographic link to this transcript can start.
        The closing messages wait in `take_final_revelations`. False when
        there is no encrypted session to close."""
        with self.lock:
            session = self.sessions.get(peer)
            if session is None or not session.is_encrypted():
                return False
            session.close_with_revelation(announce=True)
            self.end_session(peer, "made deniable")
            return True

    def end_session(self, peer: str, reason: str = "session ended",
                    announce: bool = False) -> bool:
        """Forget everything about this peer's session so a fresh DAKE can run.

        L1: an encrypted session publishes its retired MAC keys first
        (`close_with_revelation`); with [announce] -- sign-out, quit -- the
        last closing message also says DISCONNECTED. The reset callers below
        do not announce, for the reasons given.

        This method did not exist until v10.18.1, and three call sites in the
        XMPP client had been calling it since they were written -- clearing an
        offline peer's session, yielding the initiator role on DAKE glare, and
        `/otr` force-resetting a stuck handshake. All three raised
        AttributeError into an `except` that printed it and carried on, so
        none of them ever tore anything down. "`/otr` can always unstick a
        hung handshake" was simply untrue, and stayed untrue until a device
        got wedged and said so.

        `terminate_session` is NOT the same thing and cannot stand in for it:
        it terminates the session object but leaves the entry in
        `self.sessions`, so the next `get_or_create_session` hands back the
        dead one and the handshake stays stuck.

        **No DISCONNECTED TLV is sent.** This is a local teardown, and all
        three callers want exactly that. Announcing it would be wrong in two
        of the three cases: a stuck handshake has no encrypted session to send
        through, and on glare we are about to answer the peer's DAKE1 as
        responder -- telling them we disconnected first is the opposite of
        what is happening. `SessionManager.end_session` does emit one, because
        it is the graceful-goodbye path; this is the reset path.

        The trust database is untouched. A pinned fingerprint is long-term
        identity, and forgetting it here would turn every reset into a fresh
        trust-on-first-use decision -- which is the failure mode TOFU exists
        to make visible.

        Returns True if there was something to end.
        """
        with self.lock:
            session = self.sessions.pop(peer, None)
            engine = self.dake_engines.pop(peer, None)
            pending = self._pending_sessions.pop(peer, None)
            self._sent_dake1.pop(peer, None)
            self._answering_dake1.pop(peer, None)
            if pending is not None:
                try:
                    pending.terminate(reason)
                except Exception:
                    pass
            if engine is not None:
                try:
                    engine.zeroize()
                except Exception:
                    pass
            if session is None and engine is None and pending is None:
                return False
            if session is not None:
                if announce:
                    try:
                        session.close_with_revelation(announce=True)
                    except Exception:
                        pass
                try:
                    session.terminate(reason)
                except Exception as exc:            # pragma: no cover
                    # A half-built session from an interrupted DAKE may not
                    # terminate cleanly. It is already out of the table, which
                    # is what the caller needed; failing here would put us
                    # back to the reset not working.
                    self.logger.debug("end_session: terminate raised: %s" % exc)
                self._collect_revelation(peer, session)
            self.tracer.trace(peer, "END_SESSION", "ACTIVE", "ENDED", reason)
            return True

    #: Set by `wipe`. Checked by every entry point that could create or use
    #: session state, so nothing -- a late inbound frame, a queued send, a UI
    #: retry -- can bring a wiped engine back.
    _wiped = False

    class EngineWiped(RuntimeError):
        """The engine was wiped; it will not create or use sessions again."""

    def _refuse_if_wiped(self) -> None:
        if self._wiped:
            raise EnhancedSessionManager.EngineWiped("engine wiped")

    @property
    def wiped(self) -> bool:
        return self._wiped

    def rotate_identity(self, reason: str = "account changed") -> str:
        """A new identity for the next account (F2, SPEC §3.1).

        For an engine whose identity is NOT persisted (Android, desktop: one
        per process): the Ed448 and ML-DSA identity it would present next is
        replaced by freshly generated ones -- by the same generation code as
        at start-up -- and the old handles are zeroized in Rust. Every
        session and handshake that used the old identity is ended first
        (deniably, L1), and in-memory trust pins go with it: nothing of the
        previous account reaches the next one. Without this, signing out of
        one account and into another in the same process presented the same
        long-term key -- in every DAKE1, readable by the server -- for both,
        linking them.

        A persisted identity is per account by its path instead
        (`identity_path_for`); asking to rotate one is a programming error.
        Returns the new fingerprint (public).
        """
        if self.config.persist_identity:
            raise RuntimeError("a persisted identity is per account by its path")
        return self._replace_identity(self._build_client_profile, reason)

    def adopt_identity(self, identity_key, prekey, mldsa, reason: str = "account changed") -> str:
        """F3: present [account]'s own stored identity from now on.

        The handles come from `otrv4plus_identity.AccountIdentities.load`:
        opened inside Rust from the account's sealed record, so the private
        keys never reach Python. Everything else is `rotate_identity`: the
        sessions of the identity presented until now end (deniably, L1), its
        handles are zeroized -- its sealed record stays where it is -- and
        in-memory pins go. Returns the fingerprint (public)."""
        if self.config.persist_identity:
            raise RuntimeError("a persisted identity is per account by its path")

        def stored():
            profile = ClientProfile(identity_key=identity_key, prekey=prekey)
            profile.mldsa_identity = MLDSA87Auth(handle=mldsa)
            return profile
        fingerprint = self._replace_identity(stored, reason)
        self.identity_is_persistent = True
        return fingerprint

    def _replace_identity(self, build, reason: str) -> str:
        with self.lock:
            self._refuse_if_wiped()
            for peer in list(self.sessions):
                self.end_session(peer, reason, announce=True)
            for peer, engine in list(self.dake_engines.items()):
                try:
                    engine.zeroize()
                except Exception:
                    pass
            for peer, session in list(self._pending_sessions.items()):
                try:
                    session.terminate(reason)
                except Exception:
                    pass
            self.dake_engines.clear()
            self._pending_sessions.clear()
            self._sent_dake1.clear()
            self._answering_dake1.clear()
            self._orphan_data.clear()
            old = self.client_profile
            self.client_profile = build()
            self.identity_is_persistent = False
            for name in ("identity_key", "prekey", "mldsa_identity"):
                handle = getattr(old, name, None)
                if handle is not None and hasattr(handle, "zeroize"):
                    try:
                        handle.zeroize()
                    except Exception:
                        pass
            if not self.config.persist_trust:
                try:
                    with self.trust_db._lock:
                        self.trust_db._db.clear()
                except Exception:
                    pass
            self.tracer.trace("SYSTEM", "IDENTITY", "OLD", "ROTATED", reason)
            return self.client_profile.get_fingerprint()

    def wipe(self, reason: str = "wipe") -> Dict[str, int]:
        """Destroy every secret this engine holds, then refuse all further use.

        The authoritative teardown for Wipe & Exit, distinct from
        `clear_all_sessions` (a logout: sessions go, the engine stays usable)
        in three ways:

          * EXPLICIT RUST DESTRUCTION. Every Rust object that holds a secret
            is told to zeroize before its Python reference is dropped: each
            ratchet (keys, DH handle, pending brace keypair), each SMP state
            machine and vault, each in-flight DAKE (ephemeral scalar, ML-KEM
            key, ML-DSA key, any unconsumed `DakeOutput`), and the long-term
            identity and prekey handles. Python garbage collection is not the
            wipe; it only frees wrappers around keys that are already zero.
          * NO RESURRECTION. `_wiped` is set FIRST, so a frame arriving while
            this runs cannot create a session behind it, and every entry point
            (`get_or_create_session`, `handle_incoming_message`,
            `handle_outgoing_message`, `start_smp`) raises `EngineWiped` from
            then on.
          * IN-MEMORY TRUST AND SMP SECRETS GO TOO. Logout keeps pinned
            fingerprints deliberately; a wipe does not.

        THREAD. `DakeOutput` is unsendable: PyO3 lets only the creating thread
        touch it, and a drop from any other thread LEAKS it rather than
        zeroizing it. Call this on the thread that processes inbound OTR
        (the transport loop on Android), which is where DAKE outputs are made.

        Idempotent. Returns counts for the caller's report.
        """
        with self.lock:
            already = self._wiped
            self._wiped = True
            report = {"sessions": 0, "handshakes": 0, "identity_keys": 0,
                      "already_wiped": int(already)}

            for peer, engine in list(self.dake_engines.items()):
                try:
                    engine.zeroize()
                    report["handshakes"] += 1
                except Exception:
                    pass
            for peer, session in (list(self.sessions.items())
                                  + list(self._pending_sessions.items())):
                # L1 (c): every live session publishes and announces before
                # any of its keys is destroyed.
                try:
                    session.close_with_revelation(announce=True)
                except Exception:
                    pass
                try:
                    session.terminate(reason)
                    report["sessions"] += 1
                except Exception:
                    try:
                        session._cleanup_resources()
                    except Exception:
                        pass
                self._collect_revelation(peer, session)
            self.sessions.clear()
            self.dake_engines.clear()
            self._pending_sessions.clear()
            self._sent_dake1.clear()
            self._orphan_data.clear()
            self._answering_dake1.clear()

            profile = getattr(self, "client_profile", None)
            for name in ("identity_key", "prekey"):
                handle = getattr(profile, name, None) if profile else None
                if handle is not None and hasattr(handle, "zeroize"):
                    try:
                        handle.zeroize()
                        report["identity_keys"] += 1
                    except Exception:
                        pass

            try:
                with self.trust_db._lock:
                    self.trust_db._db.clear()
            except Exception:
                pass
            try:
                self.smp_storage.clear_memory()
            except Exception:
                pass

            self.tracer.trace("SYSTEM", "WIPE", "LIVE", "WIPED", reason)
            return report

    def clear_all_sessions(self, reason: str = "cleanup"):
        """Forget every session. Used only on shutdown and logout paths.

        IT DID NOT CLEAR THEM. This looped over `terminate_session`, and that
        method's limitation is written down thirty lines above: it "terminates
        the session object but leaves the entry in `self.sessions`, so the
        next `get_or_create_session` hands back the dead one". So the table
        survived, and with it the security level -- measured through the
        Android facade:

            after OtrApp.shutdown()          : ENCRYPTED
            engine has_session('bob@x.test') : True

        Every production caller is a teardown -- `android_bridge.app.shutdown`,
        the XMPP client's shutdown, the IRC client's shutdown -- and all three
        mean it. On Android the consequence was the worst of the three:
        nothing tears the engine down on logout either, so a second account
        signing in on the same device inherited the first account's live OTR
        session with any shared peer.

        `end_session` is the method that actually forgets, and it is used here
        for that reason. L1 (2026-10-26): each encrypted session now ends
        deniably -- its retired MAC keys are published and the last closing
        message says DISCONNECTED -- and the messages wait in
        `take_final_revelations` for the client to send before it closes the
        transport. Without a network they are dropped; the keys are retired
        and wiped in Rust all the same.

        The trust database is untouched, deliberately. A pinned fingerprint is
        long-term identity and survives a session ending; forgetting it here
        would turn every shutdown into a fresh trust-on-first-use decision,
        which is the failure mode TOFU exists to make visible.
        """
        with self.lock:
            held = len(self.sessions)
            for peer in list(self.sessions.keys()):
                # L1 (c): sign-out and quit end every session deniably.
                self.end_session(peer, reason, announce=True)

            self.sessions.clear()
            self.dake_engines.clear()

            self.tracer.trace(
                "SYSTEM",
                "CLEANUP",
                # The count BEFORE, which is the number that tells a reader
                # whether anything was actually torn down. Reading it after
                # the loop used to print the unchanged total, which looked
                # like a successful cleanup of nothing.
                str(held),
                str(len(self.sessions)),
                f"all sessions cleared: {reason }",
            )

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
                self.tracer.trace(peer, "TRUST", "VERIFY", "FAILED", f"fingerprint mismatch")
                return False

            success = self.trust_db.add_trust(peer, fingerprint)
            if success:
                self.tracer.trace(
                    peer, "TRUST", "UNTRUSTED", "TRUSTED", f"fingerprint: {fingerprint [:16 ]}..."
                )
            else:
                self.tracer.trace(
                    peer, "ERROR", "TRUST", "FAILED", "could not add to trust database"
                )

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
                self.tracer.trace(
                    "SYSTEM",
                    "CLEANUP",
                    "ACTIVE",
                    "EXPIRED",
                    f"cleaned {len (expired )} expired sessions",
                )

    def get_security_level(self, peer: str) -> "UIConstants.SecurityLevel":
        """Return current security level for peer."""
        with self.lock:
            sess = self.sessions.get(peer)
            if sess is None:
                return UIConstants.SecurityLevel.PLAINTEXT
            return getattr(sess, "security_level", UIConstants.SecurityLevel.PLAINTEXT)

    def get_session_info(self, peer: str) -> dict:
        """Return session info dict."""
        state = self.get_session_state(peer)
        return state or {"peer": peer, "state": "no session"}

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
                    plaintext = plaintext.decode("utf-8", errors="replace")
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

        SMP pre-load: before decrypting we ensure the Rust SMP engine has the
        shared secret bound.  This covers the responder path - set_smp_secret
        persists the secret to disk; if the in-memory Rust binding was lost
        (new RustSMP instance, restart, etc.) we re-bind from storage now so
        that any SMP1 TLV embedded in this payload can be answered immediately.
        """
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                raise EncryptionError(f"No session for {peer }")

            try:
                smp_phase = sess.rust_smp.get_phase() if sess.rust_smp is not None else "IDLE"
                needs_bind = smp_phase in ("IDLE", "FAILED") and (
                    sess.rust_smp is None or not sess.rust_smp.check_secret_set()
                )
                if needs_bind:

                    self.smp_storage.bind_into(peer, sess)
            except Exception as _pe:
                self.logger.debug("decrypt_message: SMP pre-load failed")
            plaintext = sess.decrypt_message(encrypted_msg)

            queued = getattr(sess, "_queued_smp_response", None)
            if queued:
                sess._queued_smp_response = None
                return queued.encode("utf-8") if isinstance(queued, str) else queued

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
                return {"state": "no_session", "verified": False, "failed": False}
            try:
                return sess.get_smp_status()
            except Exception:
                return {"state": "unknown", "verified": False, "failed": False}

    def start_smp(self, peer: str, secret: str, question: str = "") -> Optional[str]:
        """Start SMP verification on the session."""
        with self.lock:
            self._refuse_if_wiped()
            sess = self.sessions.get(peer)
            if not sess:
                raise RuntimeError(f"start_smp: no session for {peer }")

            return sess.start_smp(secret, question if question else None)

    def process_smp_message(self, peer: str, data: bytes) -> Optional[str]:
        """DEAD CODE - do not call.

        SMP ingress runs exclusively through decrypt_message() → sess.decrypt_message()
        → _enh_route_tlvs() → _enh_handle_smp_tlv().  Calling this method
        directly would double-advance the Rust SMP state machine and cause
        guaranteed ZKP verification failures.
        """
        raise RuntimeError(
            "process_smp_message is disabled.  SMP messages are processed "
            "automatically inside decrypt_message via _enh_handle_smp_tlv."
        )

    # ─── held SMP1, manager level ────────────────────────────────────────────

    def smp_secret_required(self, peer: str) -> bool:
        with self.lock:
            sess = self.sessions.get(peer)
        return bool(sess is not None and sess.smp_secret_required())

    def abort_smp(self, peer: str) -> Optional[str]:
        """Cancel *peer*'s SMP run. Returns the SMP_ABORT message to send.

        The Android bridge's Cancel called this for a year of tests against a
        fake engine that had it; the real one did not, so Cancel raised
        `smp_abort_unsupported` on a device.
        """
        with self.lock:
            sess = self.sessions.get(peer)
        if sess is None:
            return None
        return sess.abort_smp()

    def resume_held_smp1(self, peer: str) -> Optional[str]:
        """Answer a parked SMP1 for *peer*.  Returns the SMP2 to send."""
        with self.lock:
            sess = self.sessions.get(peer)
        if sess is None:
            raise RuntimeError(f"resume_held_smp1: no session for {peer}")
        return sess.resume_held_smp1()

    def decline_held_smp1(self, peer: str, reason: bytes = b"") -> Optional[str]:
        """Drop a parked SMP1 for *peer*.  Returns the abort to send, if any."""
        with self.lock:
            sess = self.sessions.get(peer)
        if sess is None:
            return None
        return sess.decline_held_smp1(reason)

    def set_smp_secret(self, peer: str, secret: str) -> bool:
        """Store SMP secret for peer in persistent storage AND bind it into
        the active Rust SMP engine so the responder can answer SMP1 correctly.

        Two-layer write:
          1. smp_storage (file-backed) - survives restarts, read back on every
             incoming DATA message by decrypt_message's pre-load guard.
          2. session.set_smp_secret - pushes secret into RustSMP immediately
             so any SMP1 that arrives before the next DATA message is handled.

        The manager RLock is released before the Rust key-stretch (SHAKE-256
        × 10k) to avoid blocking recv_loop or any concurrent session op for
        the several hundred milliseconds the stretch can take.
        """

        try:
            self.smp_storage.set_secret(peer, secret)
        except Exception as _se:
            self.logger.debug("set_smp_secret: storage write FAILED")

        with self.lock:
            sess = self.sessions.get(peer)

        if sess is not None and hasattr(sess, "set_smp_secret"):
            try:
                sess.set_smp_secret(secret)
            except Exception as _se:
                self.logger.debug("set_smp_secret: session bind FAILED")
        return True

    def has_stored_smp_secret(self, peer: str) -> bool:
        """Whether an auto-respond passphrase is stored for *peer*."""
        return self.smp_storage.has_secret(peer)

    def bind_stored_smp_secret(self, peer: str) -> bool:
        """Bind *peer*'s stored auto-respond passphrase into its live session.

        Store -> vault -> SMP inside Rust; the passphrase is never returned
        to Python. False when none is stored or there is no session.
        """
        with self.lock:
            self._refuse_if_wiped()
            sess = self.sessions.get(peer)
        if sess is None:
            return False
        return self.smp_storage.bind_into(peer, sess)

    def start_smp_with_stored_secret(self, peer: str, question: str = "") -> Optional[str]:
        """Start SMP using the stored passphrase. None when none is stored."""
        if not self.bind_stored_smp_secret(peer):
            return None
        return self.start_smp(peer, "", question)

    def bind_smp_secret(self, peer: str, secret: str) -> None:
        """Bind an SMP secret to *peer*'s live session, and nothing else.

        `set_smp_secret` is the terminal clients' AUTO-RESPOND setter: it also
        writes the secret to `smp_storage` (a file, and a Python dict for the
        life of the process), and the DATA/SMP handlers re-bind that stored
        secret into every later session -- so a later SMP1 from the peer is
        answered without anybody being asked. That is the feature on a
        terminal. It is not acceptable for a one-off answer typed into a
        dialog: the Android bridge used `set_smp_secret`, so answering one
        challenge silently persisted the passphrase and pre-answered every
        future one. This goes to the Rust vault only, and raises rather than
        swallowing a failure.
        """
        with self.lock:
            self._refuse_if_wiped()
            sess = self.sessions.get(peer)
        if sess is None:
            raise RuntimeError("bind_smp_secret: no session for this peer")
        sess.set_smp_secret(secret)

    def display_fingerprints(self, peer: str) -> str:
        """Return remote fingerprint string."""
        return self.get_peer_fingerprint(peer) or ""

    def handle_dake1(self, peer: str, payload: str) -> Optional[str]:
        result = self.handle_incoming_message(peer, payload)
        if result and isinstance(result, (bytes, str)):
            r = result if isinstance(result, str) else result.decode("utf-8", errors="replace")
            return r if r.startswith("?OTRv4 ") else None
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
        super().__init__(
            "ERROR",
            {"error_type": error_type, "peer": peer, "error": str(error)[:100], "context": context},
        )


class SMPEvent(Event):
    """SMP event"""

    def __init__(self, smp_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        super().__init__(
            "SMP",
            {"smp_type": smp_type, "peer": peer, "session_id": session_id, "details": details},
        )


class SecurityEvent(Event):
    """Security event"""

    def __init__(self, security_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        super().__init__(
            "SECURITY",
            {
                "security_type": security_type,
                "peer": peer,
                "session_id": session_id,
                "details": details,
            },
        )


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

        panel = self.panel_manager.panels.get(peer, self.panel_manager.panels["system"])
        panel.add_message(f"🔴 {error_type }: {str (error )[:50 ]}")

    def emit_smp_event(self, smp_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        """Emit an SMP event"""
        event = SMPEvent(smp_type, peer, session_id, details)
        with self.lock:
            self.events.append(event)

    def emit_security_event(
        self, security_type: str, peer: str, session_id: str, details: Dict[str, Any]
    ):
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
        r"^\?OTRv4"
        r"\|([0-9A-Fa-f]{8})"
        r"\|([0-9A-Fa-f]{8})"
        r"\|(\d{5})"
        r"\|(\d{5})"
        r"\|(.*?)\.?$",
        re.DOTALL,
    )

    _LEGACY_RE = re.compile(r"^\?OTRv4\s*" r"(?:\[(\d+)/(\d+)\])?" r"(.*?)(?:\.?)$", re.DOTALL)

    def __init__(self, timeout: float = UIConstants.FRAGMENT_TIMEOUT):

        self._buffers: Dict[tuple, Dict] = {}
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
                idx = int(k_s)
                total = int(n_s)
                if total < 1 or not (1 <= idx <= total):
                    raise ValueError(f"invalid spec fragment index {idx }/{total }")
                return self._buffer(sender, idx, total, chunk.strip(), now)

            while msg.startswith("?OTRv4 ?OTRv4"):
                msg = "?OTRv4 " + msg[len("?OTRv4 ?OTRv4 ") :]
            if msg.startswith("?OTRv4[") and not msg.startswith("?OTRv4 ["):
                msg = "?OTRv4 [" + msg[7:]
            if msg.endswith("."):
                msg = msg[:-1]

            m_leg = self._LEGACY_RE.match(msg)
            if not m_leg:
                return raw

            idx_s, total_s, chunk = m_leg.groups()
            chunk = chunk.strip()

            if idx_s is None:
                return f"?OTRv4 {chunk }"

            idx = int(idx_s)
            total = int(total_s)
            if total < 1 or not (1 <= idx <= total):
                raise ValueError(f"invalid legacy fragment index {idx }/{total }")
            return self._buffer(sender, idx, total, chunk, now)

    def _buffer(self, sender: str, idx: int, total: int, chunk: str, now: float) -> Optional[str]:
        """Insert chunk into the reassembly buffer and return full message when done.

        Buffer key is ``(sender_nick, total)`` so concurrent in-flight messages
        with different fragment counts (e.g. a 10-frag SMP1 alongside a 2-frag
        ratchet advance) coexist without corrupting each other.

        When fragment 1 of a new sequence arrives for a ``(sender, total)`` slot
        that already contains a partial assembly, the slot is reset - this safely
        handles the edge case of two sequential messages with the same total count.
        """

        if total > self.max_fragments_per_sender:
            raise ValueError(
                f"Fragment total {total } from {sender } exceeds max "
                f"{self .max_fragments_per_sender }. Discarding."
            )
        _ABSOLUTE_MAX_FRAGMENTS = 1000
        if total > _ABSOLUTE_MAX_FRAGMENTS:
            raise ValueError(
                f"Fragment total {total } from {sender } exceeds absolute "
                f"maximum of {_ABSOLUTE_MAX_FRAGMENTS }. Discarding."
            )

        key = (sender, total)

        if idx == 1 or key not in self._buffers:
            self._buffers[key] = {
                "total": total,
                "parts": {},
                "first_ts": now,
                "last_ts": now,
            }
            if total > 1 and idx == 1 and self.first_fragment_cb is not None:
                try:
                    self.first_fragment_cb(sender, total, chunk)
                except Exception:
                    pass

        state = self._buffers[key]

        if len(state["parts"]) >= self.max_fragments_per_sender:
            self._buffers.pop(key, None)
            raise ValueError(
                f"Fragment flood from {sender } (total={total }): exceeded "
                f"{self .max_fragments_per_sender } in-flight fragments. Buffer evicted."
            )

        if idx not in state["parts"]:

            _MAX_REASSEMBLED_BYTES = 1_048_576
            _current_bytes = sum(len(c) for c in state["parts"].values())
            if _current_bytes + len(chunk) > _MAX_REASSEMBLED_BYTES:
                self._buffers.pop(key, None)
                raise ValueError(
                    f"Fragment payload from {sender } exceeds 1 MiB limit - discarding."
                )
            state["parts"][idx] = chunk
            state["last_ts"] = now

            if DEBUG_MODE:
                _c = getattr(__import__("builtins"), "_active_client", None)
                if _c:
                    _c._emit("debug", "[OTRFragment] fragment received")
                else:
                    _emit_line(f"[OTRFragment] {idx }/{total } for {sender }")

            if total > 1:
                try:
                    got = len(state["parts"])
                    _rb = "█" * got + "░" * (total - got)
                    _set_prompt(f"\x1b[36m⟳ RX {sender } [{got }/{total }] {_rb }\x1b[0m ")
                except Exception:
                    pass

        if len(state["parts"]) == total:
            payload_parts = []
            for i in range(1, total + 1):
                if i not in state["parts"]:
                    self._buffers.pop(key, None)
                    return None
                payload_parts.append(state["parts"][i])

            combined = "".join(payload_parts)
            self._buffers.pop(key, None)

            if DEBUG_MODE:
                _c = getattr(__import__("builtins"), "_active_client", None)
                if _c:
                    _c._emit(
                        "debug", "[OTRFragment] fragment reassembled"
                    )
                else:
                    _emit_line(f"[OTRFragment] reassembled {len (combined )} chars from {sender }")

            try:
                _cr = getattr(__import__("builtins"), "_active_client", None)
                if _cr and _cr._prompt_refresh_cb:
                    _cr._prompt_refresh_cb()
            except Exception:
                pass
            return f"?OTRv4 {combined }"

        return None

    def clear_sender(self, sender: str) -> None:
        with self._lock:
            keys = [k for k in self._buffers if k[0] == sender]
            for k in keys:
                self._buffers.pop(k, None)

    def clear_all(self) -> None:
        with self._lock:
            self._buffers.clear()

    def get_pending_count(self) -> int:
        with self._lock:
            return len(self._buffers)

    def get_pending_for(self, sender: str) -> int:
        """Return total fragment count across all in-progress assemblies for sender."""
        with self._lock:
            return sum(
                len(state["parts"]) for (s, _t), state in self._buffers.items() if s == sender
            )

    def _expire(self, now: float) -> None:
        if len(self._buffers) > self.max_total_senders:
            oldest = sorted(self._buffers.items(), key=lambda x: x[1].get("first_ts", 0))
            for key, _ in oldest[: len(self._buffers) - self.max_total_senders]:
                if DEBUG_MODE:
                    _emit_line(
                        f"[fragment] buffer evict: too many senders, dropping {key [0 ]}/{key [1 ]}"
                    )
                del self._buffers[key]
        cutoff = now - self.timeout
        expired = [
            k
            for k, st in self._buffers.items()
            if st.get("last_ts", st.get("first_ts", 0)) < cutoff
        ]
        for k in expired:
            sender_nick, frag_total = k
            state = self._buffers.pop(k, None)
            if state is None:
                continue
            got = len(state.get("parts", {}))
            if DEBUG_MODE:
                _emit_line(
                    f"[fragment] timeout: {sender_nick } {got }/{frag_total } frags - type /otr {sender_nick } to retry"
                )

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

    _SPEC_OVERHEAD = len("?OTRv4|00000000|00000000|00001|00001|.")
    _LEGACY_PREFIX = "?OTRv4 "

    @classmethod
    def fragment(
        cls,
        otr_message: str,
        max_line: int = UIConstants.OTR_FRAGMENT_SIZE,
        sender_tag: int = 0,
        receiver_tag: int = 0,
    ) -> List[str]:
        """Fragment an OTRv4 message for IRC/I2P transmission.

        Unfragmented (fits in max_line): returned as-is (``?OTRv4 <base64>``).
        Fragmented: emits spec-compliant ``?OTRv4|stag|rtag|k|n|data.`` lines.

        NOT anti-fingerprinting.  This docstring used to claim that every
        multi-fragment message was padded to a uniform fragment count so an
        observer could not tell DAKE1 from DAKE3 by counting IRC lines.  No
        such padding is implemented here, and no MIN_FRAGMENTS constant
        exists anywhere in the file -- the claim described an intention, and
        a reader checking whether the traffic pattern is protected would have
        found the answer and been wrong.

        The fragment count is therefore a reliable signal of which protocol
        message is in flight, to anyone who can see the lines: the IRC server
        always, and on I2P nobody else.  Fixing it means padding every
        message to the largest (48 fragments for SMP2/SMP3), which would cost
        more time than the whole pacing change in v10.25.0 saves.  Recorded
        as a known limitation rather than silently implied to be solved.
        """
        if not otr_message.startswith(cls._LEGACY_PREFIX):
            return [otr_message]

        payload = otr_message[len(cls._LEGACY_PREFIX) :]
        if payload.endswith("."):
            payload = payload[:-1]

        if not payload:
            return [otr_message]

        if len(otr_message) <= max_line:
            return [otr_message]

        stag_hex = f"{sender_tag :08X}"
        rtag_hex = f"{receiver_tag :08X}"
        overhead = len(f"?OTRv4|{stag_hex }|{rtag_hex }|00001|00001|.")

        chunk_size = max_line - overhead
        if chunk_size < 4:
            chunk_size = 4

        chunk_size = (chunk_size // 4) * 4
        if chunk_size < 4:
            chunk_size = 4

        total = math.ceil(len(payload) / chunk_size)

        fragments: List[str] = []
        for i in range(total):
            start = i * chunk_size
            end = min(start + chunk_size, len(payload))
            chunk = payload[start:end]
            k_str = f"{i +1 :05d}"
            n_str = f"{total :05d}"
            frag = f"?OTRv4|{stag_hex }|{rtag_hex }|{k_str }|{n_str }|{chunk }."
            fragments.append(frag)

        if DEBUG_MODE:
            _c = getattr(__import__("builtins"), "_active_client", None)
            _msg = f"[OTRMessageFragmenter] {len (fragments )} frags from {len (payload )} chars"
            if _c:
                _c._emit("debug", _msg)
            else:
                _emit_line(_msg)

        return fragments

    @staticmethod
    def fragment_otr_message(
        otr_message: str, fragment_size: int = UIConstants.OTR_FRAGMENT_SIZE
    ) -> List[str]:
        return OTRMessageFragmenter.fragment(otr_message, fragment_size)


class DebugPanel(ChatPanel):
    """Enhanced panel for debugging with detailed OTR/SMP logging"""

    def __init__(self, name: str):
        super().__init__(name, "debug")
        self.debug_level = "FULL"
        self.categories = {
            "OTR": True,
            "SMP": True,
            "DAKE": True,
            "RATCHET": True,
            "NETWORK": True,
            "SECURITY": True,
            "TRUST": True,
            "FINGERPRINT": True,
            "UI": True,
        }
        self.max_debug_lines = 50000

    def log(self, category: str, message: str, data: Optional[dict] = None):
        """Log debug message with category"""
        if not self.categories.get(category, False):
            return

        # `%f` is a datetime directive, not a strftime one: time.strftime
        # left it verbatim, so [:-3] was trimming "%f" off and every debug
        # line read "12:34:56." with nothing after the dot.
        import datetime as _dt_module
        timestamp = _dt_module.datetime.now().strftime(TIMESTAMP_FORMAT + ".%f")[:-3]
        colored_cat = colorize(category, "magenta")
        msg = f"[{timestamp }] [{colored_cat }] {message }"

        if data:
            data_str = json.dumps(data, default=str)[:200]
            if len(json.dumps(data, default=str)) > 200:
                data_str += "..."
            msg += f" | {data_str }"

        self.add_message(msg)

        if len(self.history) > self.max_debug_lines:
            self.history = self.history[-self.max_debug_lines :]

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

        full_message = f"{component }.{method }: {message }"

        if self.debug_panel:
            self.debug_panel.log(component, full_message, data)
        else:
            print(f"[DEBUG] [{component }] {full_message }")
            if data:
                print(f"  Data: {data }")


if __name__ == "__main__":
    # `python otrv4+.py` is the IRC client (otrv4plus_irc.py). This file is
    # also the engine that client imports, so it is registered under the
    # engine's names first: the client then gets this module, not a second
    # copy of it.
    sys.modules.setdefault("otrv4plus", sys.modules[__name__])
    sys.modules.setdefault("otrv4_", sys.modules[__name__])
    import otrv4plus_irc
    otrv4plus_irc.run()
