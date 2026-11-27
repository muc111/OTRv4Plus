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
import otrv4plus_smpflow as _smpflow  # noqa: F401  (the IRC client imports it from here)
# Moved out of this file (2026-11-11) and re-exported under the same names.
from otrv4plus_states import (  # noqa: E402,F401
    DAKEState, SessionState, StateMachineError, UIConstants, colorize)
from otrv4plus_tlv import OTRv4TLV, _safe_b64decode  # noqa: E402,F401
from otrv4plus_manager_dake import ManagerDakeMixin  # noqa: E402
from otrv4plus_session_smp import (  # noqa: E402,F401
    SMP_VERSION_MISMATCH_HELP, ManagerSmpMixin, SessionSmpMixin,
    _is_smp_version_mismatch)
# Address rules shared with the Android app, including the project server's
# shipped address (SHIPPED_SERVERS). Standard library only.
# I2P: the alias file for short names and the SAM v3.1 client.
from otrv4plus_i2p import (  # noqa: E402,F401  (re-exported for callers)
    I2P_HOSTS_FILENAME,
    I2P_NAME_UNKNOWN_RESULTS,
    SHIPPED_SERVERS,
    I2P_KEY_NOT_FOUND_RESULTS,
    KEY_LOOKUP_INSTANT_S,
    KEY_LOOKUP_SETTLE_S,
    KEY_LOOKUP_PAUSES_S,
    KEY_LOOKUP_SLOW_RETRIES,
    remember_i2p_alias,
    i2p_hosts_path,
    _valid_i2p_destination,
    LEARNED_MARKER,
    I2P_HOSTS_DEFAULTS,
    i2p_hosts_defaults_path,
    i2p_aliases,
    resolve_i2p_aliases,
    SamError,
    _I2P_NAME_RE,
    _B32_RE,
    _I2P_DEST_RE,
    SAM_MAX_REPLY,
    i2p_target_error,
    I2PSAMConnection,
)
import otrv4plus_i2p as _i2p  # noqa: E402
import otrv4plus_repo  # noqa: F401  (android_bridge importable from client/: sealed trust pins)

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
import hashlib
import json
import re
import hmac
import struct
import base64
import ctypes
import ctypes.util
import tempfile
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass
from collections import defaultdict, deque

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


# Pass patterns for a spinning disk: zeros, ones, then CSPRNG bytes, each
# written over the whole file and fsync'd before the next. On a magnetic disk
# the overwrite lands on the same sectors, so the passes reach the old data.
_HDD_PASSES = (b"\x00", b"\xff", None)
_SYSFS_BLOCK = "/sys/dev/block"


def _on_rotational_disk(filepath: str) -> bool:
    """True only when Linux says the file's block device spins.

    Read from /sys/dev/block/MAJOR:MINOR (a partition's own queue/ is its
    parent's). Anything unknown -- Android, Termux, macOS, Windows, a
    network or overlay filesystem -- answers False: treated as flash, where
    extra passes go to new blocks and buy nothing.
    """
    try:
        dev = os.stat(filepath).st_dev
        node = os.path.join(_SYSFS_BLOCK, "%d:%d" % (os.major(dev), os.minor(dev)))
        for queue in (os.path.join(node, "queue"), os.path.join(node, "..", "queue")):
            flag = os.path.join(queue, "rotational")
            if os.path.exists(flag):
                with open(flag) as fh:
                    return fh.read().strip() == "1"
    except (OSError, ValueError, AttributeError):
        pass
    return False


def _overwrite_passes(filepath: str):
    """The patterns to write: three on a spinning disk, one random on flash."""
    return _HDD_PASSES if _on_rotational_disk(filepath) else (None,)


def _secure_file_destroy(filepath: str) -> None:
    """Overwrite a file, fsync every pass, unlink it, and check it is gone.

    On a spinning disk (desktop HDD): three passes -- zeros, ones, random.
    On flash (phones, Termux, SSDs, anything not known to spin): one pass
    of CSPRNG bytes. Raises OSError if the file still exists afterwards, so
    a caller can never count a survivor as destroyed.

    WHAT THIS DOES NOT DO: guarantee the old contents are gone from flash.
    On flash storage the controller's wear-levelling writes the overwrite to
    NEW physical blocks and leaves the old ones -- holding the old
    plaintext -- to be erased whenever it chooses. No number of passes, and
    no file-level call, can reach them; that is why flash gets one pass and
    not three. NIST SP 800-88's purge for flash is cryptographic erase
    (destroy the key the data was sealed under), which is what the Android
    vault does with its AndroidKeyStore key; this function is the file-level
    clear for what Python wrote. What it achieves: the file's logical
    contents are replaced before unlink, so the data is not recoverable
    through the file system, by undelete tools, or from a journal.
    """
    size = os.path.getsize(filepath)
    if size:
        with open(filepath, "r+b") as f:
            for pattern in _overwrite_passes(filepath):
                f.seek(0)
                written = 0
                while written < size:
                    n = min(65536, size - written)
                    f.write(os.urandom(n) if pattern is None else pattern * n)
                    written += n
                f.flush()
                os.fsync(f.fileno())
    os.remove(filepath)
    if os.path.lexists(filepath):
        raise OSError("%s survived its unlink" % filepath)


# The data message's wire format, instance tags and TLV handlers are
# otrv4plus_wire.
from otrv4plus_wire import (  # noqa: E402,F401  (re-exported)
    BinaryReader, MLKEM1024BraceKEM, OTRv4DataMessage, OTRv4Payload,
    ProtocolVersionError, _HANDLER_TLV_TYPES, _TLV_HANDLERS,
    _generate_instance_tag, clear_tlv_handlers, register_tlv_handler)


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
    TIMEOUT_I2P = _i2p.I2P_TIMEOUT_S

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

    I2P_SAM_HOST = _i2p.SAM_HOST
    I2P_SAM_PORT = _i2p.SAM_PORT




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
from otrv4plus_tty import TIMESTAMP_FORMAT  # noqa: E402,F401

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
# The debug switches are otrv4plus_debug.FLAGS (DEBUG_MODE and SMP_DEBUG
# below still read them).
import otrv4plus_debug as _debug  # noqa: E402
TEST_MODE = "--test" in sys.argv

from otrv4plus_tty import IS_TERMUX, TERMINAL_HEIGHT, TERMINAL_WIDTH  # noqa: E402,F401


# Untrusted text on the terminal: one implementation, shared with the XMPP
# client (otrv4plus_sanitise says what it removes and why).
from otrv4plus_sanitise import sanitise as _sanitise  # noqa: E402


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


from otrv4plus_tty import colorize_username  # noqa: E402,F401


# The raw-mode terminal (input line, prompt, scrollback) is otrv4plus_tty;
# its state is one object, otrv4plus_tty.TTY.
import otrv4plus_tty as _tty  # noqa: E402
from otrv4plus_tty import (  # noqa: E402,F401  (re-exported for callers)
    _ANSI_RE, _EOF_SENTINEL, _consume_escape_seq, _display_buffer, _emit_line,
    _flush_display_queue, _handle_input_char, _read_one_char,
    _restore_terminal, _scroll_unlock, _set_prompt, _setup_raw_mode,
    _show_scrollback, _truncate_visible, _visible_len, _word_wrap,
    safe_print, set_input_mask)

#: The terminal state's old module-level names, still readable here
#: (`otrv4+._mask_input`). Assign to `otrv4plus_tty.TTY` instead: a name
#: assigned on this module would shadow the real value without changing it.
_TTY_FIELDS = {
    "_print_lock": "lock", "_current_prompt": "prompt",
    "_input_buffer": "buffer", "_input_pos": "pos", "_mask_input": "masked",
    "_raw_mode_active": "raw", "_stdin_fd": "fd",
    "_orig_termios": "saved_termios", "_scroll_locked": "paused",
    "_scroll_buffer": "held", "_scroll_pos": "scroll_pos",
    "_scroll_history": "history", "_TUI_SCROLL_CALLBACK": "scroll_callback",
    "_display_queue": "queue",
}


#: The debug switches' old names, read from otrv4plus_debug.FLAGS.
_FLAG_FIELDS = {"DEBUG_MODE": "debug", "SMP_DEBUG": "smp"}


def __getattr__(name):
    if name in _TTY_FIELDS:
        return getattr(_tty.TTY, _TTY_FIELDS[name])
    if name in _FLAG_FIELDS:
        return getattr(_debug.FLAGS, _FLAG_FIELDS[name])
    raise AttributeError("module %r has no attribute %r" % (__name__, name))


# Settings are otrv4plus_config.
from otrv4plus_config import OTRConfig  # noqa: E402,F401


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


class EncryptionError(Exception):
    """Encryption error with context"""

    def __init__(self, message: str, session: Optional["EnhancedOTRSession"] = None):
        super().__init__(message)
        self.session = session


class TypeValidationError(Exception):
    """Type validation error"""

    pass


# Logging and the protocol trace are otrv4plus_logging.
from otrv4plus_logging import NullLogger, OTRLogger, OTRTracer  # noqa: E402,F401


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
                except (OSError, TypeError):
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
        if _debug.FLAGS.debug:
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
                except (OSError, AttributeError, Exception):
                    if _debug.FLAGS.debug:
                        print("[SecureMemory] munlock failed")
                self._locked = False

            self._buffer = None

        except Exception:
            if _debug.FLAGS.debug:
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
                raise ValueError("Data too large for SecureMemory")

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

        if _debug.FLAGS.debug:
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
            if _debug.FLAGS.debug:
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

            if _debug.FLAGS.debug:
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
        except (AttributeError, TypeError, ValueError):
            if _debug.FLAGS.debug:
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
        except (TypeError, AttributeError, ValueError):
            if _debug.FLAGS.debug:
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
        except (AttributeError, TypeError, ValueError):
            if _debug.FLAGS.debug:
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
            if _debug.FLAGS.debug:
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
                # P2 (SECURITY_ISSUES.md): one forced step per remote key. A
                # second step toward a key the peer has not replaced yet is
                # one the peer cannot follow -- its receive step uses the
                # key it made after our first -- and every later message
                # fails to decrypt. The next step comes from the peer's reply
                # (`_decrypt_new_dh`), as in the double ratchet.
                if _rekey_target and _rekey_target != getattr(self, "_forced_toward", None):
                    self._ratchet(_rekey_target)
                    self._forced_toward = _rekey_target
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
        # P2: this step already made our sending chain toward `dh_pub`; a
        # forced step toward it as well would be a second one.
        self._forced_toward = dh_pub

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
        objects are told to zeroize themselves first: the ratchet wipes its keys
        in place and refuses every later call, the X448 handle zeroes its
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
        self._store = None
        self._unsaved = False
        if self.persistent:
            self._load()

    class StoreUnavailable(RuntimeError):
        """The trust pins are there and will not open. Not replaced: the
        client refuses to start, as it does for an identity (P1)."""

    class StoreFailed(RuntimeError):
        """The sealed trust store (P1) could not be written. Raised, not
        swallowed: a pin that is not kept would make the next start a first
        contact again, so the handshake that made it fails instead."""

    def use_store(self, store) -> None:
        """P1: keep this database in [store], one account's sealed record
        (`android_bridge.account_trust.AccountTrustRecord`): `load()` gives
        its pins, or raises when the record will not open -- then nothing
        here changes -- and every change is `save(db)`d. Replaces whatever
        was held, which belonged to the account before. Only an in-memory
        database takes a store: a persistent one keeps its own file."""
        if self.persistent:
            raise ValueError("a persistent trust database keeps its own file")
        data = store.load()
        with self._lock:
            self._db = self._migrated(data or {})
            self._store = store
            self._unsaved = False

    def where(self) -> str:
        """Where the pins are kept, for the user."""
        if self._store is not None:
            describe = getattr(self._store, "where", None)
            return describe() if callable(describe) else "a sealed store"
        if self.persistent:
            return "%s (plaintext)" % self.db_path
        return "IN MEMORY ONLY"

    def detach_store(self) -> None:
        """Stop writing to the store (another account, or a wipe). The pins
        held go with it."""
        with self._lock:
            self._store = None
            self._unsaved = False
            self._db.clear()

    def _save_to_store(self) -> None:
        with self._lock:
            snapshot = json.loads(json.dumps(self._db))
            try:
                self._store.save(snapshot)
            except Exception as e:
                self._unsaved = True
                raise TrustDatabase.StoreFailed(
                    "trust store not written: %s" % e.__class__.__name__) from None
            self._unsaved = False

    @staticmethod
    def _migrated(raw) -> Dict[str, dict]:
        out = {}
        for k, v in dict(raw).items():
            if isinstance(v, str):
                out[k] = {"fingerprint": v, "trusted": True}
            elif isinstance(v, dict):
                out[k] = v
        return out

    def _load(self):
        """Load database from disk with error handling"""
        with self._lock:
            if not self.persistent:
                self._db = {}
                return
            if not os.path.exists(self.db_path):
                self._db = {}
                return
            # A file that is there and will not open is refused, never read
            # as empty: an empty database in its place makes every pinned
            # contact a first contact, the failure P1 fixed in the apps.
            # Writes are atomic (`_save`), so a torn file is not an ordinary
            # crash either.
            try:
                with open(self.db_path, "r") as f:
                    raw = json.load(f)
                if not isinstance(raw, dict):
                    raise ValueError("not a table")
                self._db = self._migrated(raw)
            except Exception as e:
                raise TrustDatabase.StoreUnavailable(
                    "the trust pins in %s would not open (%s). They have NOT "
                    "been replaced: starting with none would make every "
                    "pinned contact a first contact. If you know why, move "
                    "the file aside and expect to check your contacts again."
                    % (self.db_path, e.__class__.__name__)) from None

    def _save(self):
        """Save database to disk atomically with error handling"""
        if not self.persistent:
            # In-memory mode: never this file -- writing here would recreate
            # exactly the file this mode exists to not create. The one place
            # an in-memory database writes is a sealed store given to it
            # (P1, `use_store`); without one the map lives and dies with the
            # process.
            if self._store is not None:
                self._save_to_store()
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
                if _debug.FLAGS.debug:
                    print(f"[TrustDatabase] Error saving: {e }")
                if _tmp_path2:
                    try:
                        os.unlink(_tmp_path2)
                    except Exception:
                        pass
            except Exception as e:
                if _debug.FLAGS.debug:
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
            if self._unsaved:
                self._save()                 # P1: a pin made but not kept yet
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
            if self._unsaved:
                self._save()                 # P1: a pin made but not kept yet
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

    def accept_new_key(self, peer: str, fingerprint: str) -> None:
        """Reset trust after a changed key was checked (P1): pin [fingerprint]
        in place of the old pin, unconfirmed, keeping the ML-DSA pin the
        same handshake made under the new identity, so neither half is left
        for the next handshake to fill."""
        if not peer or not fingerprint:
            raise ValueError("Peer and fingerprint cannot be empty")
        with self._lock:
            self._set_entry(peer, fingerprint, False)
            self._save()

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
                if _debug.FLAGS.debug:
                    print(f"[TrustDatabase] Error removing trust: {e }")
                return False
            except Exception as e:
                if _debug.FLAGS.debug:
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


# The full-screen UI (tabs, panels, pager) is otrv4plus_panels.
import otrv4plus_panels as _panels  # noqa: E402,F401  (tests patch the pager through it)
from otrv4plus_panels import (  # noqa: E402,F401  (re-exported for callers)
    ChatPanel, Pager, PanelManager, Screen, TabBar)


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


class EnhancedOTRSession(SessionSmpMixin):
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
                    "message queued (DAKE in progress)",
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


def _open_trust_db(config) -> "TrustDatabase":
    """The trust database [config] asks for.

    In memory unless persist_trust (the IRC contract: nothing written). With
    persist_trust and a `trust_dek_path`, the pins are sealed (P1); the
    import happens only on that path, as the identity's does, so IRC never
    loads the persistence machinery. A record that will not open raises,
    and the client does not start.
    """
    if not config.persist_trust:
        return TrustDatabase(config.trust_db_path, persistent=False)
    if not getattr(config, "trust_dek_path", None):
        return TrustDatabase(config.trust_db_path, persistent=config.persist_trust)
    from android_bridge.account_trust import for_terminal
    db = TrustDatabase(config.trust_db_path, persistent=False)
    db.use_store(for_terminal(
        config.trust_dek_path, legacy_path=config.trust_db_path,
        read_legacy=lambda path: TrustDatabase(path, persistent=config.persist_trust)._db))
    return db


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

        self.trust_db = _open_trust_db(self.config)
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
                if _debug.FLAGS.debug:
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
                if _debug.FLAGS.debug:
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
                        tracer=OTRTracer(enabled=_debug.FLAGS.debug),
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
                if _debug.FLAGS.debug:
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
                        tracer=OTRTracer(enabled=_debug.FLAGS.debug),
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
                if _debug.FLAGS.debug:
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
        """Get security level for session with peer. A session that is not
        ENCRYPTED now (finished, failed, or a new handshake under way) is
        PLAINTEXT, whatever level it reached before: nothing can be sent in
        it (`has_encrypted_session`)."""
        session = self.sessions.get(peer)
        if session is None or not session.is_encrypted():
            return UIConstants.SecurityLevel.PLAINTEXT
        return session.security_level

    def encrypt_message(self, peer: str, plaintext: str) -> Optional[str]:
        """Encrypt message for peer"""
        if peer not in self.sessions:
            return None

        try:
            session = self.sessions[peer]
            return session.encrypt_message(plaintext)
        except Exception as e:
            if _debug.FLAGS.debug:
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
        except Exception:
            self.logger.debug("set_smp_secret: storage FAILED")

        if peer in self.sessions:
            try:
                session = self.sessions[peer]
                if hasattr(session, "set_smp_secret"):
                    session.set_smp_secret(secret)
                    self.logger.debug("set_smp_secret: session bound")
            except Exception:
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

        self.logger.debug("start_smp: Session has no start_smp method")
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

        except Exception:
            if _debug.FLAGS.debug:
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
        except Exception:
            if _debug.FLAGS.debug:
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


class EnhancedSessionManager(ManagerDakeMixin, ManagerSmpMixin):
    """Session manager with opportunistic DAKE and secure key storage."""

    # The refusal checks the DAKE handlers (otrv4plus_manager_dake.py) call.
    # Kept here, beside the trust database they consult.
    def _refused_old_protocol(self, peer: str, dake) -> bool:
        return _refuse_old_protocol(self, peer, dake)

    def _refused_pq_identity(self, peer: str, dake) -> bool:
        return _refuse_pq_identity(self, peer, dake)

    def __init__(
        self,
        config: Optional[OTRConfig] = None,
        tracer: Optional[OTRTracer] = None,
        logger: Optional[OTRLogger] = None,
    ):
        self.config = config or OTRConfig(test_mode=True)
        self.tracer = tracer or OTRTracer(enabled=True)
        self.logger = logger or NullLogger()

        self.trust_db = _open_trust_db(self.config)
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
                            "message queued for later encryption",
                        )

                        return dake1, True
                    else:
                        self.tracer.trace(peer, "ERROR", "DAKE", "FAILED", "could not start DAKE")
                        return None, False
                else:
                    self.tracer.trace(
                        peer, "ERROR", "SEND", "BLOCKED", "plaintext session but DAKE not started"
                    )
                    return None, False

            elif session.session_state == SessionState.DAKE_IN_PROGRESS:
                session.queue_outgoing_message(message)

                self.tracer.trace(
                    peer, "QUEUE", "MESSAGE", "QUEUED", "DAKE in progress, message queued"
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
                    "encrypted session but received plaintext - possible downgrade attack",
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
                    # P1: the pins (and the store they were kept in) were
                    # the previous account's; the caller attaches the new
                    # account's store.
                    self.trust_db.detach_store()
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
                self.trust_db.detach_store()     # nothing is written after a wipe
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
        transport. Without a network the client keeps them in memory only,
        never on disk, and sends them when it is back if it is still running;
        if it ends first they are lost. The keys are retired and wiped in Rust
        all the same.

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
                self.tracer.trace(peer, "TRUST", "VERIFY", "FAILED", "fingerprint mismatch")
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
            # Not ENCRYPTED now (finished -- the peer published its keys or
            # ended it --, failed, or re-keying): PLAINTEXT. The level the
            # session reached is kept on it and was reported as current, so
            # the apps showed a lock and the group code went ahead to send
            # into a session that no longer existed (terminal report,
            # 2026-10-27: "accept failed: otr_required").
            if sess is None or not sess.is_encrypted():
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

    # ─── held SMP1, manager level ────────────────────────────────────────────

    def display_fingerprints(self, peer: str) -> str:
        """Return remote fingerprint string."""
        return self.get_peer_fingerprint(peer) or ""

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


# The IRC fragment format is otrv4plus_irc_fragment; the debug panel and
# logger are with the rest of the full-screen UI in otrv4plus_panels.
from otrv4plus_irc_fragment import (  # noqa: E402,F401  (re-exported)
    OTRFragmentBuffer, OTRMessageFragmenter)
from otrv4plus_panels import DebugLogger, DebugPanel  # noqa: E402,F401


if __name__ == "__main__":
    # `python otrv4+.py` is the IRC client (otrv4plus_irc.py). This file is
    # also the engine that client imports, so it is registered under the
    # engine's names first: the client then gets this module, not a second
    # copy of it.
    sys.modules.setdefault("otrv4plus", sys.modules[__name__])
    sys.modules.setdefault("otrv4_", sys.modules[__name__])
    import otrv4plus_irc
    otrv4plus_irc.run()
