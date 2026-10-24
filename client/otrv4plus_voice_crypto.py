# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The voice subsystem's cryptography: the hybrid X448 + ML-KEM-1024 key
agreement, the media-frame cipher and replay window, and the rekey
schedule. Every primitive is the Rust core's; this is the protocol
around it.

Split out of otrv4plus_voice.py, which re-exports every name here.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import socket as _socket
import struct
import threading
import time

from otrv4plus_voice_params import (  # noqa: F401
    VOICE_PROTOCOL_VERSION, VOICE_SYNC, FRAME_TYPE_AUDIO, _FRAME_TYPES,
    VOICE_HDR_LEN, VOICE_HDR_FMT, VOICE_SEALED_LEN, VOICE_MIN_FRAME,
    VOICE_MAX_FRAME, DIR_INITIATOR, DIR_RESPONDER,
)


# ---------------------------------------------------------------------------
# ML-KEM-1024 provider
# ---------------------------------------------------------------------------
# Production uses the Rust core's bindings, which wrap the same pqcrypto-mlkem
# code path as the DAKE.  No ML-KEM is implemented here: the audit forbids a
# second copy of a cryptographic primitive, and a hand-rolled lattice KEM
# would be the single worst thing in this file.
#
# The Rust binding returns (ciphertext, shared_secret) from encaps.  The
# underlying pqcrypto call returns (shared_secret, ciphertext) — the opposite
# order.  Getting that backwards silently desynchronises the key agreement
# and presents as "media keys did not agree", so the provider normalises it
# in exactly one place and the test suite pins the order.

MLKEM_EK_LEN = 1568          # FIPS 203 ML-KEM-1024 encapsulation key
MLKEM_CT_LEN = 1568          # ciphertext
MLKEM_SS_LEN = 32            # shared secret
MLKEM_DK_LEN = 3168          # decapsulation key


class KemUnavailable(RuntimeError):
    """No ML-KEM-1024 implementation is available."""


class _RustKem:
    """ML-KEM-1024 capability of the Rust core. The only provider.

    A CAPABILITY, not a key API: it answers "can this device do a hybrid
    exchange", by running one inside Rust. The call path never asks it for
    keys -- `VoiceKeyExchange` owns its ML-KEM keypair inside `RustVoiceKex`
    and gets back an opaque `RustVoiceAgreement`.

    There used to be a second provider, `kyber-py`: pure Python, not
    constant-time, and holding keys in Python objects. It was reachable only
    with an environment variable set, and it was a duplicate implementation of
    a primitive the Rust core owns. It is gone; a device without the Rust core
    has no voice, which is the honest answer.
    """

    name = "otrv4_core/pqcrypto-mlkem"
    post_quantum = True

    def __init__(self, module):
        self._m = module


_KEM = None
_KEM_RESOLVED = False


def _kem_self_test(module) -> bool:
    """One full hybrid exchange inside Rust. False if anything is wrong.

    Both ends must agree on both secrets, which also catches the
    (ct, ss)/(ss, ct) inversion that otherwise presents much later as "media
    keys did not agree". Compared by the agreement's one-way digests: no
    secret leaves Rust to be compared.
    """
    try:
        initiator = module.RustVoiceKex(True)
        responder = module.RustVoiceKex(False)
        ek = bytes(initiator.mlkem_ek)
        if len(ek) != MLKEM_EK_LEN:
            return False
        from_responder, ct = responder.responder_agree(bytes(initiator.public), ek)
        if len(bytes(ct)) != MLKEM_CT_LEN:
            return False
        from_initiator = initiator.initiator_agree(bytes(responder.public), bytes(ct))
        ok = from_initiator.digests() == from_responder.digests()
        from_initiator.zeroize()
        from_responder.zeroize()
        return ok
    except Exception:
        return False


def _resolve_kem():
    global _KEM, _KEM_RESOLVED
    if _KEM_RESOLVED:
        return _KEM
    _KEM_RESOLVED = True
    try:
        import otrv4_core                                   # type: ignore
        # Prove it works before trusting it. Attribute presence is not
        # evidence: a partially built core, or a stub installed by another
        # module, satisfies hasattr and then fails at call time -- during a
        # call, after the user has already dialled.
        if hasattr(otrv4_core, "RustVoiceKex") and _kem_self_test(otrv4_core):
            _KEM = _RustKem(otrv4_core)
            return _KEM
    except Exception:
        pass
    _KEM = None
    return None


def kem_provider():
    """Return the ML-KEM capability, or raise KemUnavailable.

    Voice refuses to run without one.  Falling back to X448-only would give
    a call that reports itself as hybrid while carrying no post-quantum
    protection whatsoever, which is worse than refusing.
    """
    kem = _resolve_kem()
    if kem is None:
        raise KemUnavailable(
            "ML-KEM-1024 unavailable -- the Rust core (otrv4_core) is not "
            "loaded or failed its self-test.  Voice requires a hybrid exchange "
            "and will not fall back to X448 alone.")
    return kem


def set_kem_provider_for_testing(provider) -> None:
    """Install a KEM provider explicitly.  Test seam — never used in the app."""
    global _KEM, _KEM_RESOLVED
    _KEM, _KEM_RESOLVED = provider, True


# ---------------------------------------------------------------------------
# Canonical encoding
# ---------------------------------------------------------------------------

def _lp(value) -> bytes:
    """Length-prefix one field.

    Unprefixed concatenation is re-partitionable: a short ssid followed by a
    long fingerprint hashes identically to a long ssid followed by a short
    fingerprint.  Every field in every transcript in this module goes through
    here.
    """
    if value is None:
        raw = b""
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raise TypeError("transcript fields must be bytes or str, got %r"
                        % type(value).__name__)
    if len(raw) > 0xFFFFFFFF:
        raise ValueError("transcript field too long")
    return struct.pack(">I", len(raw)) + raw


def _u64(n: int) -> bytes:
    if not (0 <= n < (1 << 64)):
        raise ValueError("value out of range for u64: %r" % (n,))
    return struct.pack(">Q", n)


def normalise_fingerprint(fp) -> str:
    """Canonical fingerprint form: uppercase hex, no separators."""
    if fp is None:
        return ""
    if isinstance(fp, (bytes, bytearray)):
        fp = fp.hex()
    return str(fp).upper().replace(" ", "").replace(":", "").replace("-", "")


def sorted_fingerprints(local_fp, remote_fp):
    """Return (low, high).

    Each endpoint sees its own fingerprint as "local", so an unsorted pair
    differs between the two sides and silently produces two different media
    roots.  Sorting is what makes the transcript symmetric.
    """
    return tuple(sorted([normalise_fingerprint(local_fp),
                         normalise_fingerprint(remote_fp)]))


# ---------------------------------------------------------------------------
# Hybrid KDF
# ---------------------------------------------------------------------------

_LABEL_SALT = b"OTRv4+Voice/Salt/v3"
_LABEL_INITIAL = b"OTRv4+Voice/Initial/v1"
_LABEL_REKEY = b"OTRv4+Voice/Rekey/v1"
# ---------------------------------------------------------------------------
# Rust-owned media cryptography
# ---------------------------------------------------------------------------
#
# Hard requirement, not a preference.  There is no Python fallback: media keys
# living in Python is the defect this replaced, so falling back to it on an
# import error would silently restore the thing being fixed.  A missing core
# means no voice, which is the correct failure.

try:
    from otrv4_core import RustVoiceCipher as _RustVoiceCipher
    from otrv4_core import RustVoiceKex as _RustVoiceKex
    from otrv4_core import RustVoiceRoot as _RustVoiceRoot
    RUST_VOICE_AVAILABLE = True
except ImportError:                                            # pragma: no cover
    _RustVoiceCipher = None
    _RustVoiceKex = None
    _RustVoiceRoot = None
    RUST_VOICE_AVAILABLE = False


def _as_root_handle(root):
    """Accept a `RustVoiceRoot`, or wrap raw bytes into one.

    Production always passes a handle: the root is derived inside Rust by
    `RustVoiceRoot.from_initial_agreement` and never becomes a Python object.
    Raw bytes are accepted so tests can build a schedule from a fixed root
    without a full hybrid agreement -- that path copies the bytes into Rust
    immediately, which is the best that can be done with material Python has
    already seen.
    """
    _require_rust_voice()
    if isinstance(root, _RustVoiceRoot):
        return root
    if root is None:
        raise ValueError("epoch root must be %d bytes" % ROOT_LEN)
    raw = bytes(root)
    if len(raw) != ROOT_LEN:
        raise ValueError("epoch root must be %d bytes" % ROOT_LEN)
    return _RustVoiceRoot.from_bytes(raw)


def _require_rust_voice():
    if not RUST_VOICE_AVAILABLE:
        raise RuntimeError(
            "otrv4_core does not provide RustVoiceCipher/RustVoiceKex. "
            "Voice media keys are Rust-owned as of v10.13.2 and there is no "
            "Python fallback. Rebuild the core:\n"
            "  cd Rust && maturin build --release "
            "--features pyo3/extension-module\n"
            "  pip install --force-reinstall Rust/target/wheels/otrv4_core-*.whl")


_LABEL_MEDIA = b"OTRv4+Voice/Media/v1"
_LABEL_CONFIRM = b"OTRv4+Voice/Confirm/v1"
_LABEL_RATCHET = b"OTRv4+Voice/Ratchet/v1"
_LABEL_ENDPOINT = b"OTRv4+Voice/Endpoint/v1"
_LABEL_AAD = b"OTRv4+Voice/AAD/v3"
_LABEL_VERSION = b"OTRv4+Voice/v3"

ROOT_LEN = 64
MEDIA_KEY_LEN = 32
CONFIRM_LEN = 32


def build_transcript(call_id: bytes, otr_binding: bytes,
                     local_fp, remote_fp,
                     initiator_x448_pub: bytes, responder_x448_pub: bytes,
                     mlkem_ek: bytes, mlkem_ct: bytes, epoch: int) -> bytes:
    """Canonical, length-prefixed transcript for one epoch.

    Both endpoints must produce identical bytes.  Every field here is either
    symmetric by construction (sorted fingerprints, call_id) or role-ordered
    rather than local/remote-ordered (the X448 publics are always initiator
    first), which is what removes the v2 class of "the exchange succeeded but
    the keys did not agree" failures.
    """
    low, high = sorted_fingerprints(local_fp, remote_fp)
    return b"".join((
        _lp(_LABEL_VERSION),
        _lp(call_id),
        _lp(otr_binding),
        _lp(low), _lp(high),
        _lp(initiator_x448_pub),
        _lp(responder_x448_pub),
        _lp(mlkem_ek),
        _lp(mlkem_ct),
        _u64(epoch),
    ))


def _salt_for(transcript: bytes) -> bytes:
    return hashlib.sha512(_LABEL_SALT + transcript).digest()


def derive_voice_root(x448_shared, mlkem_shared, transcript: bytes):
    """Hybrid root from the initial exchange.  Both secrets are mandatory.

    Returns a `RustVoiceRoot` handle, not bytes.  The root is the input every
    media key for the epoch derives from, so a copy of it is a copy of every
    key -- and it used to sit in a Python bytearray for the whole call.  It is
    now derived inside Rust and never becomes a Python object at all.

    The two shared secrets are consumed: Rust zeroes the caller's buffers
    before returning, so the `finally: _wipe(...)` at the call sites is belt
    and braces rather than the only wipe.
    """
    _require_rust_voice()
    return _RustVoiceRoot.from_initial_agreement(x448_shared, mlkem_shared,
                                                 transcript)


def derive_rekey_root(old_root, x448_shared, mlkem_shared,
                      transcript: bytes) -> bytearray:
    """Hybrid root for a rekey, chained onto the root it replaces.

    Chaining onto the old root is what makes a rekey an upgrade rather than a
    replacement: an attacker who compromised neither the old root nor the new
    ephemerals gains nothing, and one who holds only the old root is locked
    out by the fresh X448 and ML-KEM secrets.
    """
    # Chains inside Rust, where neither root is ever a Python object. Raw root
    # bytes (a test building a schedule from a fixed root) are moved INTO a
    # Rust handle first -- the safe direction -- and never derived from here.
    return _as_root_handle(old_root).derive_rekey(
        bytes(x448_shared), bytes(mlkem_shared), transcript)


# `derive_media_key` and `ratchet_key` are GONE. They re-implemented the
# Rust key schedule in Python -- HKDF-SHA512 through the `cryptography`
# package -- and returned media keys as bytearrays. Production never called
# them (every cipher is built from a root handle by `make_cipher`); only
# tests did, which kept a duplicate implementation of a secret-bearing
# derivation in the shipped module. The tests now check Rust against a
# reference written from the spec, inside the test suite.


def derive_confirmations(root, call_id: bytes, epoch: int):
    """Return (confirm_initiator, confirm_responder) for this root.

    Two distinct tags rather than one shared value, so a tag observed from
    one side cannot simply be reflected back to satisfy the other.  Each side
    computes both, transmits its own and checks the peer's.
    """
    ci, cr = _as_root_handle(root).confirmations(call_id, epoch)
    return bytes(ci), bytes(cr)


def derive_endpoint_tag(root, call_id: bytes, epoch: int, seq: int,
                       destination: str, from_initiator: bool) -> bytes:
    """Authenticate one media-endpoint announcement.

    A peer whose local I2P session is replaced gets a new transient
    destination, and the other side has to be told where to send. That
    announcement travels the XMPP control channel, so arriving over it proves
    nothing on its own: the same channel carries anything the server or a
    peer's compromised account can put there.

    The tag is derived from the committed epoch root, which exists only
    because the hybrid X448 + ML-KEM agreement succeeded, so producing one
    requires the media secret rather than access to the signalling path. It
    is the same key hierarchy and the same construction as
    derive_confirmations -- deliberately, because a second trust model for
    endpoints would be a second thing to get wrong.

    Everything that decides whether the announcement should be acted on is
    inside the tag:

      call_id      the exact call instance, so a tag cannot cross calls
      epoch        the media generation, so it cannot outlive a rekey
      seq          strictly increasing, so an older announcement cannot
                   replace a newer endpoint or roll one back
      destination  the endpoint itself, so it cannot be substituted
      direction    which side sent it, so it cannot be reflected back
    """
    return bytes(_as_root_handle(root).endpoint_tag(
        call_id, epoch, seq, destination, from_initiator))


# ---------------------------------------------------------------------------
# Ephemeral hybrid key exchange
# ---------------------------------------------------------------------------

class VoiceKeyExchange:
    """One side's ephemeral X448 + ML-KEM-1024 material for one epoch.

    The initiator generates both an X448 keypair and an ML-KEM keypair and
    publishes both public parts.  The responder generates an X448 keypair,
    encapsulates to the initiator's encapsulation key, and publishes its
    X448 public plus the ciphertext.

    Private material is single-use and released as soon as the shared secrets
    exist.  Holding an ephemeral private key any longer only widens the
    window in which a memory compromise decrypts the call.
    """

    PUB_LEN = 56          # X448 public key

    def __init__(self, is_initiator: bool, kem=None):
        self.is_initiator = bool(is_initiator)
        self._kem = kem if kem is not None else kem_provider()

        # The X448 private scalar is Rust-owned as of v10.13.2.
        #
        # It was a `cryptography` X448PrivateKey: an OpenSSL object Python
        # could neither wipe nor reach, so the one private value in the voice
        # path with no cleanup at all.  `RustVoiceKex` holds it as
        # `SecretBytes<56>`, zeroizes on drop, and is single-use -- an
        # ephemeral scalar that has been offered to a peer is spent, and
        # retrying with a different peer key is the shape of a small-subgroup
        # probe.
        _require_rust_voice()
        # With the initiator's ML-KEM keypair inside the same Rust object: the
        # decapsulation key, and both shared secrets, never become Python
        # objects. What this class hands back is a `RustVoiceAgreement`,
        # which can only turn into a root.
        self._kex = _RustVoiceKex(self.is_initiator)
        self.public = bytes(self._kex.public)
        self._private = self._kex        # legacy attribute name, same object

        # Initiator only: the encapsulation key it publishes. Public.
        self.mlkem_ek = bytes(self._kex.mlkem_ek) if self.is_initiator else b""
        if self.is_initiator and len(self.mlkem_ek) != MLKEM_EK_LEN:
            raise ValueError("ML-KEM encapsulation key must be %d bytes, "
                             "got %d" % (MLKEM_EK_LEN, len(self.mlkem_ek)))

    # -- checks both roles make before agreeing ---------------------------

    def _check_peer_x448(self, peer_public: bytes) -> None:
        if self._private is None:
            raise RuntimeError("X448 private key already consumed")
        if not peer_public or len(peer_public) != self.PUB_LEN:
            raise ValueError("peer X448 public key must be %d bytes"
                             % self.PUB_LEN)
        if peer_public == self.public:
            # Reflection: a peer echoing our own key back would make both
            # sides derive a value the reflector can also compute.
            raise ValueError("peer echoed our own X448 public key")
        if peer_public == b"\x00" * self.PUB_LEN:
            raise ValueError("peer sent an all-zero X448 public key")
        # The same checks run again inside Rust (`raw_agree`), together with
        # the on-curve test and RFC 7748's abort on a degenerate shared
        # secret. A check that runs twice costs nothing.

    # -- initiator --------------------------------------------------------

    def initiator_agree(self, peer_x448_pub: bytes, mlkem_ct: bytes):
        """Complete both halves as the initiator.

        Returns a `RustVoiceAgreement`: the X448 and ML-KEM shared secrets,
        held in Rust, usable only via `into_root` / `into_rekey_root`.
        """
        if not self.is_initiator:
            raise RuntimeError("initiator_agree called on a responder exchange")
        if self._private is None:
            raise RuntimeError("ML-KEM decapsulation key already consumed")
        if not mlkem_ct or len(mlkem_ct) != MLKEM_CT_LEN:
            raise ValueError("ML-KEM ciphertext must be %d bytes" % MLKEM_CT_LEN)
        try:
            self._check_peer_x448(peer_x448_pub)
            return self._kex.initiator_agree(bytes(peer_x448_pub), bytes(mlkem_ct))
        finally:
            self._private = None

    # -- responder --------------------------------------------------------

    def responder_agree(self, peer_x448_pub: bytes, peer_mlkem_ek: bytes):
        """Complete both halves as the responder.

        Returns ``(agreement, mlkem_ct)``. The ciphertext must be sent to the
        initiator and is part of the transcript on both sides; the agreement
        holds the secrets, in Rust.
        """
        if self.is_initiator:
            raise RuntimeError("responder_agree called on an initiator exchange")
        if not peer_mlkem_ek or len(peer_mlkem_ek) != MLKEM_EK_LEN:
            raise ValueError("ML-KEM encapsulation key must be %d bytes"
                             % MLKEM_EK_LEN)
        try:
            self._check_peer_x448(peer_x448_pub)
            agreement, ct = self._kex.responder_agree(bytes(peer_x448_pub),
                                                      bytes(peer_mlkem_ek))
        finally:
            self._private = None
        ct = bytes(ct)
        if len(ct) != MLKEM_CT_LEN:
            agreement.zeroize()
            raise ValueError("ML-KEM encapsulation produced wrong-sized output")
        return agreement, ct

    def destroy(self) -> None:
        """Release any private material still held.  Idempotent."""
        self._private = None
        try:
            self._kex.zeroize()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

class ReplayWindow:
    """Sliding-window replay rejection bound to one (call, direction, epoch).

    A bitmap rather than a set: the v2 code kept every counter it had seen in
    a Python set and pruned at 20 000 entries, which is both unbounded within
    that limit and O(n log n) to prune.  A 1024-frame window is 41 s of audio
    at 40 ms per frame, far beyond any reordering a jitter buffer will pass
    through, and costs 128 bytes regardless of call length.

    Reordering and replay are different things and are tested separately: a
    frame inside the window that has not been seen is ACCEPTED (reordered),
    the same frame a second time is REJECTED (replay).
    """

    WINDOW = 1024

    __slots__ = ("_highest", "_bits", "accepted", "rejected")

    def __init__(self):
        self._highest = -1
        self._bits = 0
        self.accepted = 0
        self.rejected = 0

    def check_and_set(self, counter: int) -> bool:
        """True if this counter is fresh.  False on replay or too-old."""
        if counter < 0 or counter >= (1 << 64):
            self.rejected += 1
            return False
        if counter > self._highest:
            shift = counter - self._highest
            if shift >= self.WINDOW:
                self._bits = 1
            else:
                self._bits = ((self._bits << shift) | 1) & ((1 << self.WINDOW) - 1)
            self._highest = counter
            self.accepted += 1
            return True
        offset = self._highest - counter
        if offset >= self.WINDOW:
            self.rejected += 1
            return False
        mask = 1 << offset
        if self._bits & mask:
            self.rejected += 1
            return False
        self._bits |= mask
        self.accepted += 1
        return True

    def seen(self, counter: int) -> bool:
        """Non-mutating query, for tests and diagnostics."""
        if counter > self._highest:
            return False
        offset = self._highest - counter
        if offset >= self.WINDOW:
            return True                    # outside the window: treat as seen
        return bool(self._bits & (1 << offset))


# ---------------------------------------------------------------------------
# Media framing
# ---------------------------------------------------------------------------

class FrameError(ValueError):
    """A media frame failed parsing, authentication or replay checks.

    `reason` says WHICH, and that distinction is operational, not cosmetic.
    Every rejection used to be counted as `auth_fail` unless its message text
    happened to contain the word "replay", so a live call reporting
    `authfail=87` could mean any of:

      * the peer rekeyed and we have no key for the epoch it is sending on
        (a state-machine problem, and the one that actually happened);
      * a frame arrived from an epoch we have already retired (ordinary, and
        expected around every rekey);
      * a forged or corrupted frame failed its AES-256-GCM tag (an attack, or
        a broken path);
      * the header did not parse at all (a desynchronised byte stream).

    Only the third is an authentication failure.  Reading them as one number
    is what made the rekey divergence take a 69-minute call to notice.

    Classifying a rejection does NOT soften it: every reason below still
    discards the frame.  Nothing here accepts unauthenticated media.
    """

    #: Header did not parse: bad sync, version, type or length.
    MALFORMED = "malformed"
    #: We hold no cipher for the epoch the frame claims.  Usually means the
    #: peer has moved ahead of us, or is behind and we have retired it.
    NO_KEY = "no_key"
    #: The epoch is one we hold, but the frame belongs to a retired sub-epoch.
    RETIRED = "retired"
    #: The counter has been seen, or is below the replay window.
    REPLAY = "replay"
    #: The AES-256-GCM tag did not verify.  This one is an attack signal.
    AUTH = "auth"
    #: Structurally valid, but not for this call.
    FOREIGN = "foreign"

    #: reason -> the counter in MEDIA_STAT_KEYS that owns it.
    STAT_FOR_REASON = {
        MALFORMED: "rej_malformed",
        NO_KEY:    "rej_no_key",
        RETIRED:   "rej_retired",
        REPLAY:    "replay",
        AUTH:      "auth_fail",
        FOREIGN:   "foreign",
    }

    def __init__(self, message, reason=None):
        super().__init__(message)
        #: Defaults to MALFORMED so a raise site that forgets to classify is
        #: counted as "we could not even parse it" rather than silently
        #: inflating the authentication-failure count.
        self.reason = reason or self.MALFORMED


def pack_media_header(epoch: int, counter: int, length: int,
                      frame_type: int = FRAME_TYPE_AUDIO) -> bytes:
    return struct.pack(VOICE_HDR_FMT, VOICE_SYNC, VOICE_PROTOCOL_VERSION,
                       frame_type, epoch, counter, length)


def parse_media_header(raw: bytes):
    """Return (epoch, counter, length, frame_type) or raise FrameError.

    Structural validation only — nothing here is trusted until the AEAD tag
    over the whole header verifies.
    """
    if len(raw) < VOICE_HDR_LEN:
        raise FrameError("short header", FrameError.MALFORMED)
    sync, version, ftype, epoch, counter, length = struct.unpack(
        VOICE_HDR_FMT, raw[:VOICE_HDR_LEN])
    if sync != VOICE_SYNC:
        raise FrameError("bad sync byte", FrameError.MALFORMED)
    if version != VOICE_PROTOCOL_VERSION:
        raise FrameError("unsupported protocol version %d" % version, FrameError.MALFORMED)
    if ftype not in _FRAME_TYPES:
        raise FrameError("unsupported frame type 0x%02x" % ftype, FrameError.MALFORMED)
    # Mute, silence and speech are all AUDIO, so the field still says nothing
    # about what the microphone is doing. PING/PONG are the only exceptions
    # and they are the same 199 bytes on the same cadence, so an observer
    # learns that a probe happened, not anything about the conversation.
    if not (VOICE_MIN_FRAME <= length <= VOICE_MAX_FRAME):
        raise FrameError("implausible sealed length %d" % length, FrameError.MALFORMED)
    return epoch, counter, length, ftype


def media_aad(call_id: bytes, direction: int, header: bytes) -> bytes:
    """Additional authenticated data for one frame.

    Everything security-relevant is in here: protocol label, call, direction,
    and the complete header (version, frame type, epoch, counter, length).
    Direction is NOT on the wire — the receiver supplies the peer's value
    locally, so a frame reflected back at its own sender fails the tag.
    """
    return _LABEL_AAD + _lp(call_id) + struct.pack(">B", direction) + header


def media_nonce(epoch: int, counter: int) -> bytes:
    """96-bit GCM nonce, derived rather than transmitted.

    The key is already unique per (root, epoch, direction), so the counter
    alone guarantees uniqueness; the epoch is folded in as a second line of
    defence against a key-reuse bug elsewhere ever becoming nonce reuse.
    """
    return struct.pack(">I", epoch & 0xFFFFFFFF) + struct.pack(">Q", counter)


class VoiceFrameCrypto:
    """AES-256-GCM media protection for one epoch, one call, both directions.

    Independent send and receive keys derived from the epoch root, so the two
    endpoints never share an encryption key and both counters may start at
    zero.  A single bidirectional key with two counters starting at zero
    would give identical key+nonce on different plaintexts, which leaks the
    XOR of the plaintexts and GHASH's H — that is, it breaks authentication
    as well as confidentiality.

    Within the epoch, the key advances by a one-way hash every
    RATCHET_INTERVAL frames.  That is forward secrecy only; post-compromise
    recovery comes from the hybrid rekey that begins the next epoch.
    """

    RATCHET_INTERVAL = 500          # 20 s at 40 ms per frame
    _EPOCH_GRACE = 1                # sub-epochs of the ratchet kept for reorder
    _MAX_SUBEPOCH_JUMP = 16         # bound forced hashing from one bad frame
    MAX_COUNTER = (1 << 62)

    def __init__(self, root, call_id: bytes, epoch: int, is_initiator: bool):
        if not call_id or len(call_id) < 16:
            raise ValueError("call_id must be at least 16 bytes")
        if epoch < 0 or epoch >= (1 << 64):
            raise ValueError("epoch out of range")

        self.call_id = bytes(call_id)
        self.epoch = int(epoch)
        self.is_initiator = bool(is_initiator)
        self.send_dir = DIR_INITIATOR if is_initiator else DIR_RESPONDER
        self.recv_dir = DIR_RESPONDER if is_initiator else DIR_INITIATOR

        # The media keys live in Rust from here on.
        #
        # They used to be Python bytearrays, wiped on each ratchet step -- and
        # then handed to OpenSSL as `AESGCM(bytes(key))`, an immutable copy
        # that could not be wiped and that the AESGCM object kept anyway.  One
        # such copy per direction per sub-epoch: about 276 of them over a
        # 69-minute call, all waiting on the garbage collector.
        #
        # `RustVoiceCipher` holds the keys as `SecretBytes<32>`, rebuilds its
        # AES-256-GCM instance from the one copy that exists, and zeroizes on
        # drop.  There is no getter for a key and adding one would defeat it.
        #
        # The derivation is byte-identical -- same HKDF-SHA512, same labels,
        # same length prefixes -- and `tests/test_voice_rust_parity.py` runs
        # both implementations against each other to keep it that way.
        _require_rust_voice()
        self._rust = _as_root_handle(root).make_cipher(
            self.call_id, self.epoch, self.is_initiator)

        self._send_counter = 0
        self._replay = ReplayWindow()
        self.last_frame_type = FRAME_TYPE_AUDIO
        self._zeroized = False

    @property
    def _recv_sub(self) -> int:
        """Receive-chain sub-epoch.  A counter, so it stays readable.

        Kept under the old private name because the security tests that
        assert a forged frame cannot advance the chain were written against
        it, and re-pointing them at a new name would have obscured that the
        property is unchanged.
        """
        return int(self._rust.recv_sub)

    @property
    def _send_sub(self) -> int:
        return int(self._rust.send_sub)

    @property
    def ratchet_steps(self) -> int:
        """Sub-epoch advances, counted Rust-side where they happen."""
        try:
            return int(self._rust.ratchet_steps)
        except Exception:
            return 0

    # -- send -------------------------------------------------------------

    def seal(self, plaintext: bytes, frame_type: int = FRAME_TYPE_AUDIO) -> bytes:
        """Encrypt one padded frame.  Returns the complete wire packet."""
        if self._zeroized:
            raise FrameError("media cipher already zeroized",
                             FrameError.NO_KEY)
        if self._send_counter >= self.MAX_COUNTER:
            raise FrameError("frame counter exhausted")

        counter = self._send_counter
        header = pack_media_header(self.epoch, counter, VOICE_SEALED_LEN,
                                   frame_type=frame_type)
        aad = media_aad(self.call_id, self.send_dir, header)
        try:
            _counter, sealed = self._rust.seal(plaintext, aad)
        except RuntimeError as exc:
            raise FrameError(str(exc), FrameError.NO_KEY)
        except ValueError as exc:
            raise FrameError(str(exc), FrameError.MALFORMED)
        if len(sealed) != VOICE_SEALED_LEN:
            raise FrameError("sealed frame has the wrong length", FrameError.MALFORMED)
        self._send_counter += 1
        return header + sealed

    # -- receive ----------------------------------------------------------

    def open(self, header: bytes, sealed: bytes) -> bytes:
        """Authenticate and decrypt one frame.

        Ordering is deliberate: cheap structural checks, then the bounded
        replay test, then authentication, and only then any state mutation.
        A forged frame can neither push the ratchet forward nor consume a
        counter, because nothing commits until the tag verifies.

        The sub-epoch handling moved into Rust with the keys; the speculative
        advance is still speculative there, committing only after the frame
        authenticates.  Everything above the AEAD -- header parsing, the
        epoch check, the replay window -- stays here, because none of it
        touches key material and all of it is already tested here.
        """
        if self._zeroized:
            raise FrameError("media cipher already zeroized",
                             FrameError.NO_KEY)
        epoch, counter, length, ftype = parse_media_header(header)
        if epoch != self.epoch:
            raise FrameError("frame epoch %d is not this cipher's epoch %d"
                             % (epoch, self.epoch), FrameError.NO_KEY)
        if length != len(sealed):
            raise FrameError("declared length does not match the frame", FrameError.MALFORMED)
        if self._replay.seen(counter):
            raise FrameError("replayed or stale frame counter %d" % counter, FrameError.REPLAY)

        aad = media_aad(self.call_id, self.recv_dir, header)
        try:
            plaintext = self._rust.open(sealed, aad, counter)
        except RuntimeError as exc:
            raise FrameError(str(exc), FrameError.NO_KEY)
        except ValueError as exc:
            text = str(exc)
            if "sub-epoch" in text:
                raise FrameError(text, FrameError.RETIRED)
            raise FrameError(text, FrameError.AUTH)

        # Committed only now, after authentication.
        self._replay.check_and_set(counter)
        self.last_frame_type = ftype
        return plaintext

    # -- lifecycle --------------------------------------------------------

    @property
    def send_counter(self) -> int:
        return self._send_counter

    def zeroize(self) -> None:
        """Destroy every key this epoch holds.  Idempotent, never raises."""
        self._zeroized = True
        rust = getattr(self, "_rust", None)
        if rust is not None:
            try:
                rust.zeroize()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Call state machine
# ---------------------------------------------------------------------------

class CallState:
    IDLE = "IDLE"
    INVITING = "INVITING"            # initiator: INVITE sent
    RINGING = "RINGING"              # responder: INVITE received, not answered
    CONNECTING = "CONNECTING"        # responder: answered, deriving keys
    KEY_CONFIRMING = "KEY_CONFIRMING"
    MEDIA_CONNECTING = "MEDIA_CONNECTING"
    ACTIVE = "ACTIVE"
    ENDING = "ENDING"
    ENDED = "ENDED"

    # Every legal transition, explicitly.  v2 scattered `session.state = ...`
    # across eight call sites with no validation, so an ACCEPT arriving in the
    # wrong state, or a callback firing after teardown, could move the call
    # anywhere at all.
    ALLOWED = {
        IDLE:             {INVITING, RINGING, ENDING, ENDED},
        INVITING:         {KEY_CONFIRMING, ENDING, ENDED},
        RINGING:          {CONNECTING, ENDING, ENDED},
        CONNECTING:       {KEY_CONFIRMING, ENDING, ENDED},
        KEY_CONFIRMING:   {MEDIA_CONNECTING, ENDING, ENDED},
        MEDIA_CONNECTING: {ACTIVE, ENDING, ENDED},
        ACTIVE:           {ENDING, ENDED},
        ENDING:           {ENDED},
        ENDED:            set(),      # absorbing: nothing resurrects a call
    }

    LIVE = (INVITING, RINGING, CONNECTING, KEY_CONFIRMING,
            MEDIA_CONNECTING, ACTIVE)


class IllegalTransition(RuntimeError):
    """A state transition that the protocol does not permit."""


# ---------------------------------------------------------------------------
# Two-phase key schedule
# ---------------------------------------------------------------------------

class VoiceKeySchedule:
    """Epoch roots and ciphers, with a two-phase rekey commit.

    CURRENT -> PENDING -> CONFIRMED -> COMMITTED

    A pending epoch is derived and its cipher built, but nothing is sent
    under it and the current root is untouched until the peer's confirmation
    verifies.  If it does not, the pending material is wiped and the call
    continues on the epoch it was already using.  v2 destroyed the current
    root inside rekey() before comparing confirmations, so a rekey that
    failed for any reason — a dropped REKEYACK, a replay, an injected
    message — killed a working call.

    The previous epoch's cipher is retained for one epoch so frames already
    in flight when the rekey completed still decrypt, then wiped.
    """

    RETAIN_EPOCHS = 1
    MAX_EPOCH = (1 << 63)
    #: A responder that missed one or more REKEYCOMMITs is behind the
    #: initiator and must be able to rejoin; a peer claiming to be
    #: arbitrarily far ahead must not be able to make us derive forever.
    #: Mirrors VOICE_REKEY_MAX_CATCHUP, which bounds the same jump at the
    #: signalling layer.
    MAX_CATCHUP = 64

    def __init__(self, call_id: bytes, is_initiator: bool):
        self.call_id = bytes(call_id)
        self.is_initiator = bool(is_initiator)
        self._root = None                 # committed root (bytearray)
        self._epoch = -1                  # committed epoch
        self._ciphers = {}                # epoch -> VoiceFrameCrypto
        self._pending = None              # dict for the in-flight rekey
        self.rekeys_committed = 0
        self.rekeys_failed = 0

    # -- state ------------------------------------------------------------

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def ready(self) -> bool:
        return self._root is not None and self._epoch in self._ciphers

    @property
    def pending_epoch(self):
        return None if self._pending is None else self._pending["epoch"]

    @property
    def pending_age(self):
        """Seconds since the pending epoch was derived, or None if idle."""
        if self._pending is None:
            return None
        return max(0.0, time.monotonic() - self._pending["started"])

    def current_root(self):
        """The committed root.  Internal: callers must not retain it."""
        if self._root is None:
            raise RuntimeError("no committed root")
        return self._root

    def cipher_for_send(self):
        return self._ciphers.get(self._epoch)

    def cipher_for_epoch(self, epoch: int):
        return self._ciphers.get(epoch)

    def live_epochs(self):
        return sorted(self._ciphers)

    # -- epoch 0 ----------------------------------------------------------

    def install_initial(self, root) -> tuple:
        """Commit epoch 0.  Returns (confirm_initiator, confirm_responder)."""
        if self._root is not None:
            raise RuntimeError("initial epoch already installed")
        self._root = _as_root_handle(root)
        self._epoch = 0
        self._ciphers[0] = VoiceFrameCrypto(self._root, self.call_id, 0,
                                            self.is_initiator)
        return self._root.confirmations(self.call_id, 0)

    # -- rekey ------------------------------------------------------------

    def begin_rekey(self, epoch: int, root) -> tuple:
        """Derive a pending epoch without disturbing the current one.

        Returns (confirm_initiator, confirm_responder) over the pending root.
        """
        if self._root is None:
            raise RuntimeError("cannot rekey before the initial agreement")
        if epoch <= self._epoch:
            # The epoch counter only ever moves forward.  Re-deriving one we
            # already hold would replace a key the peer may still be using.
            raise ValueError(
                "rekey epoch must be ahead of the committed one (%d), got %d"
                % (self._epoch, epoch))
        if epoch > self._epoch + self.MAX_CATCHUP:
            # A gap this large is not a peer that missed a few commits.
            raise ValueError(
                "rekey epoch %d is more than %d ahead of %d"
                % (epoch, self.MAX_CATCHUP, self._epoch))
        if epoch >= self.MAX_EPOCH:
            raise ValueError("epoch space exhausted")
        if self._pending is not None:
            raise RuntimeError("a rekey is already pending for epoch %d"
                               % self._pending["epoch"])
        pending_root = _as_root_handle(root)
        confirms = pending_root.confirmations(self.call_id, epoch)

        # Build the pending cipher NOW and register it for RECEIVE, while
        # leaving _epoch alone so we keep sending on the committed epoch.
        #
        # The initiator commits one round trip before the responder does: it
        # verifies REKEYACK, switches its send epoch, and only then sends
        # REKEYCOMMIT. Media travels the direct I2P tunnel while REKEYCOMMIT
        # goes via the XMPP server, so the new-epoch audio reliably overtakes
        # it. The responder was rejecting every one of those frames with
        # "no live key for epoch N+1" — which lands in the authfail bucket.
        # Live call: authfail=87 on the responder, 0 on the initiator, across
        # 5 rekeys.
        #
        # Accepting inbound frames on the pending epoch is safe. REKEY arrives
        # inside the authenticated OTR channel, so only the real peer can
        # start one, and the pending root is derived from secrets only the two
        # of us hold. Anything encrypted under the wrong key still fails its
        # AEAD tag. What REKEYCOMMIT proves is that the peer agrees on the
        # root — which is a precondition for SENDING, not for receiving.
        pending_cipher = VoiceFrameCrypto(pending_root, self.call_id, epoch,
                                          self.is_initiator)
        self._ciphers[epoch] = pending_cipher
        self._pending = {"epoch": epoch, "root": pending_root,
                         "confirms": confirms, "cipher": pending_cipher,
                         "started": time.monotonic()}
        return confirms

    def expected_peer_confirm(self) -> bytes:
        """The confirmation tag the peer must produce for the pending epoch."""
        if self._pending is None:
            raise RuntimeError("no pending rekey")
        ci, cr = self._pending["confirms"]
        return cr if self.is_initiator else ci

    def our_confirm(self) -> bytes:
        if self._pending is None:
            raise RuntimeError("no pending rekey")
        ci, cr = self._pending["confirms"]
        return ci if self.is_initiator else cr

    def commit_rekey(self, epoch: int, peer_confirm: bytes) -> bool:
        """Verify the peer's tag and promote the pending epoch.

        Returns True on commit.  On any failure the pending material is wiped
        and the committed epoch is left exactly as it was — a failed rekey
        never costs a working call.
        """
        if self._pending is None or self._pending["epoch"] != epoch:
            self.rekeys_failed += 1
            return False
        expected = self.expected_peer_confirm()
        if not hmac.compare_digest(bytes(peer_confirm or b""), expected):
            # A tag that does not verify is evidence, not silence: nothing
            # legitimate will ever be encrypted under this root.
            self.abort_rekey(discard_receive=True)
            return False

        pending = self._pending
        self._pending = None
        # The cipher has been receiving since begin_rekey; committing only
        # promotes it to the send epoch as well.
        cipher = pending.get("cipher")
        if cipher is None:
            cipher = VoiceFrameCrypto(pending["root"], self.call_id, epoch,
                                      self.is_initiator)
        self._ciphers[epoch] = cipher
        self._root.zeroize()
        self._root = pending["root"]
        self._epoch = epoch
        self.rekeys_committed += 1
        self._retire_old_epochs()
        return True

    def abort_rekey(self, discard_receive: bool = False) -> None:
        """Stop sending on the pending epoch.  Idempotent.

        `discard_receive` decides whether the pending cipher is also removed
        from the RECEIVE set, and the distinction is the whole point.

        A rekey can end for two very different reasons.

        *The peer's confirmation tag did not verify.*  That is evidence: the
        material is wrong, or the message was forged.  Nothing legitimate
        will ever be encrypted under that root, so the cipher goes -- pass
        `discard_receive=True`.

        *Nothing arrived before the timeout, or a newer REKEY superseded it.*
        That is the ABSENCE of evidence, and treating it as failure is what
        broke long calls.  The initiator commits the moment the responder's
        tag verifies and only then sends REKEYCOMMIT; if that message is lost
        the initiator is already SENDING on the new epoch while the responder
        still has it merely pending.  A responder that then discarded the
        receive cipher could no longer decrypt anything the peer sent, and
        every frame landed in `auth_fail` -- one-way audio that reads exactly
        like a broken tunnel.  So by default the receive cipher STAYS, under
        the normal retirement policy, and only the intent to send is dropped.

        Retaining it costs nothing: a frame still has to pass its AEAD tag,
        and `_retire_old_epochs` drops the key once the epoch moves on.
        """
        if self._pending is None:
            return
        self._pending["root"].zeroize()
        cipher = self._pending.get("cipher")
        if cipher is not None and discard_receive:
            self._ciphers.pop(self._pending["epoch"], None)
            cipher.zeroize()
        self._pending = None
        self.rekeys_failed += 1

    def _retire_old_epochs(self) -> None:
        keep = {self._epoch}
        for back in range(1, self.RETAIN_EPOCHS + 1):
            keep.add(self._epoch - back)
        for epoch in [e for e in self._ciphers if e not in keep]:
            try:
                self._ciphers.pop(epoch).zeroize()
            except Exception:
                self._ciphers.pop(epoch, None)

    # -- teardown ---------------------------------------------------------

    def zeroize(self) -> None:
        """Destroy every root and cipher.  Idempotent, never raises."""
        try:
            self.abort_rekey(discard_receive=True)
        except Exception:
            self._pending = None
        for epoch in list(self._ciphers):
            try:
                self._ciphers.pop(epoch).zeroize()
            except Exception:
                self._ciphers.pop(epoch, None)
        if self._root is not None:
            self._root.zeroize()
            self._root = None
        self._epoch = -1
