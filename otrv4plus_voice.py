"""OTRv4+ encrypted voice subsystem — protocol v3 (hybrid X448 + ML-KEM-1024).

This module replaces the v2 voice code that lived inline in
``otrv4plus_xmpp.py``.  It is a separate module for one reason: the v2 code
could not be tested.  It was reachable only by importing a 6 200-line file
that pulls in slixmpp, opuslib and PulseAudio at import time, so the key
agreement, the rekey state machine and the replay window had no test
coverage at all.  Everything security-relevant in here imports nothing
beyond the standard library and ``cryptography``, and is exercised by
``test_voice_security.py``.

The audio/SAM host helpers are injected by ``bind_host()`` rather than
duplicated.


WHAT CHANGED FROM v2, AND WHY
=============================

v2 derived the media root from X448 alone.  ML-KEM-1024 existed in the Rust
core and was bound into Python, but the voice path never called it: the OTR
*session* had post-quantum components while the *voice payload* did not.  A
recorded call was recoverable by an adversary with a CRQC.  v3 derives the
voice root from X448 **and** ML-KEM-1024, both mandatory.

v2 also:
  * identified calls solely by bare JID — ACCEPT/REKEY/END carried no
    call_id, so a message from a previous call terminated or rekeyed the
    current one;
  * used a constant AEAD AAD (b"OTRv4+voice"), leaving the wire header
    (generation, length) unauthenticated;
  * used an 8-bit wrapping generation with no ordering check, so a replayed
    REKEY was accepted and installed;
  * destroyed the current root *before* the rekey was confirmed, so a failed
    rekey killed a working call;
  * confirmed keys in one direction only — the callee started sending audio
    before it had any evidence the caller held the same key;
  * gated calls on a set populated by substring-matching printed log lines.

All of the above are fixed here.  See the engineering report for the full
list with file/function references.


PROTOCOL v3
===========

Roles are fixed by who sent the INVITE.  INITIATOR == caller == the side that
publishes a SAM destination and parks in STREAM ACCEPT.  RESPONDER == callee.

Control messages travel inside the established, DAKE-authenticated,
SMP-verified OTR channel.  Every one of them carries the call_id.

    INVITE      call_id | dest_b64 | x448_pub | mlkem_ek
    ACCEPT      call_id | x448_pub | mlkem_ct | confirm_responder
    CONFIRM     call_id | confirm_initiator
    REJECT      call_id | reason
    REKEY       call_id | epoch | x448_pub | mlkem_ek
    REKEYACK    call_id | epoch | x448_pub | mlkem_ct | confirm_responder
    REKEYCOMMIT call_id | epoch | confirm_initiator
    END         call_id

The initiator generates the ephemeral ML-KEM keypair and is the
decapsulator; the responder encapsulates.  That direction is chosen so the
1568-byte encapsulation key rides the INVITE, which the initiator is sending
anyway, and the 1568-byte ciphertext rides the ACCEPT.  Neither side has to
send both.

Key confirmation is two-way and role-labelled.  The responder proves
possession first (ACCEPT), the initiator second (CONFIRM).  Neither side
starts audio before the exchange completes, so a key mismatch never results
in a frame being emitted under a key the peer does not hold.


HYBRID KEY DERIVATION
=====================

    transcript = LP("OTRv4+Voice/v3")
              || LP(call_id)
              || LP(otr_binding)
              || LP(fp_low) || LP(fp_high)          # sorted, symmetric
              || LP(initiator_x448_pub)
              || LP(responder_x448_pub)
              || LP(mlkem_ek) || LP(mlkem_ct)
              || u64(epoch)

    ikm  = LP(x448_shared) || LP(mlkem_shared)      # BOTH mandatory
    salt = SHA-512("OTRv4+Voice/Salt/v3" || transcript)
    root = HKDF-SHA512(ikm, salt, info="OTRv4+Voice/Initial/v1" || transcript)

LP(x) is a 4-byte big-endian length prefix followed by x.  Every field is
length-prefixed, so no two distinct field sets can serialise to the same
byte string.  The hybrid is a concatenation KDF: an adversary must break
X448 *and* ML-KEM-1024 to recover the root, and is not weakened if either
primitive is later broken.

Directional media keys:

    K_dir = HKDF-SHA512(root, salt=call_id,
                        info="OTRv4+Voice/Media/v1" || LP(call_id)
                             || u64(epoch) || dir_byte)

dir_byte is 0x01 for initiator->responder and 0x02 for responder->initiator,
so the two endpoints never share an encryption key and their counters can
both start at zero.


MEDIA FRAME
===========

    off  0  sync        u8    0xA7
    off  1  version     u8    0x03
    off  2  frame_type  u8    0x01 (AUDIO — the only value ever sent)
    off  3  epoch       u64 BE
    off 11  counter     u64 BE
    off 19  length      u16 BE   (sealed length; constant for the call)
    off 21  ciphertext || GCM tag

    AAD   = "OTRv4+Voice/AAD/v3" || LP(call_id) || dir_byte || header[0:21]
    nonce = u32BE(epoch mod 2^32) || u64BE(counter)          # not transmitted

The nonce is derived from authenticated header fields rather than sent, so
it costs no bytes and cannot be tampered with independently of the header.
dir_byte is not on the wire — the receiver supplies the peer's direction
locally, so a frame reflected back at its own sender fails authentication.

Every security-relevant header field is inside the AAD.  Flipping the epoch,
the counter, the length or the frame type causes a tag failure.


SECURITY CLAIMS
===============

Claimed:
  * Confidentiality and integrity of media against a classical adversary,
    contingent on X448.
  * Confidentiality against a store-now-decrypt-later quantum adversary,
    contingent on ML-KEM-1024.  Both are required; neither alone suffices.
  * Forward secrecy within a call from the symmetric media ratchet, and
    across rekeys from the ephemeral hybrid exchange.
  * Post-compromise recovery at each successful hybrid rekey (not from the
    symmetric ratchet, which cannot provide it).
  * Media is bound to the call, epoch, direction and counter by the AEAD.

Not claimed:
  * Post-quantum *authentication* of the voice exchange.  The public keys
    are authenticated by the surrounding OTR channel; whether that channel's
    authentication is post-quantum depends on the DAKE, which this module
    does not audit.  A quantum adversary able to forge OTR authentication in
    real time could MITM a call.  Recorded calls remain protected.
  * Metadata protection beyond application-layer constant-rate traffic
    shaping.  Call timing, duration, tunnel behaviour, loss and congestion
    remain observable to a network adversary.  The XMPP server still sees
    that two parties exchanged encrypted stanzas.
  * Anything about the security of the OTR session itself.
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

import otrv4plus_audio as _audio

# ---------------------------------------------------------------------------
# Host bindings
# ---------------------------------------------------------------------------
# otrv4plus_xmpp.py owns the terminal, the SAM helpers and the audio process
# plumbing.  Importing it from here would be circular, and copying those
# helpers would duplicate code the audit says must not be duplicated, so the
# host injects them once at startup.  The defaults below are real, working
# implementations of the few things that can be done without the host, which
# is what makes this module importable (and testable) on its own.

_HOST = {
    "print": print,
    "sanitise": lambda text, max_len=1024: str(text)[:max_len],
    "ossl_cleanse": None,       # set below
    "which": None,
    "load_opus": lambda: False,
    "voice_available": lambda: (False, "host not bound"),
    "sam_open": None,
    "sam_read_line": None,
    "sam_parse": None,
    "sam_release": None,
    "pipe_read_exact": None,
    "pipe_write_all": None,
    "opus": None,
    "termux_prefix": "/data/data/com.termux/files/usr",
    "is_termux": False,
}


def _default_cleanse(buf) -> None:
    for i in range(len(buf)):
        buf[i] = 0


_HOST["ossl_cleanse"] = _default_cleanse


def bind_host(**kwargs) -> None:
    """Inject the host's helpers.  Called once from otrv4plus_xmpp.py."""
    for key, value in kwargs.items():
        if key in _HOST and value is not None:
            _HOST[key] = value


def _print(*args):
    _HOST["print"](*args)


def _san(text, max_len=1024):
    return _HOST["sanitise"](text, max_len)


def _wipe(buf) -> None:
    """Overwrite a mutable buffer in place.  Never raises."""
    if buf is None:
        return
    try:
        _HOST["ossl_cleanse"](buf)
    except Exception:
        try:
            _default_cleanse(buf)
        except Exception:
            pass


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
    """ML-KEM-1024 via otrv4_core (the production path)."""

    name = "otrv4_core/pqcrypto-mlkem"
    post_quantum = True

    def __init__(self, module):
        self._m = module

    def keygen(self):
        ek, dk = self._m.mlkem1024_keygen()
        return bytes(ek), bytearray(dk)

    def encaps(self, ek: bytes):
        ct, ss = self._m.mlkem1024_encaps(ek)      # already (ct, ss)
        return bytes(ct), bytearray(ss)

    def decaps(self, ct: bytes, dk) -> bytearray:
        return bytearray(self._m.mlkem1024_decaps(ct, bytes(dk)))


class _PurePythonKem:
    """ML-KEM-1024 via the pure-Python kyber-py package.

    A real FIPS 203 implementation, used when the Rust core is not loaded —
    on a workstation running the test suite, for example.  It is orders of
    magnitude slower than the Rust path and is not constant-time, so it is
    refused for live calls unless OTRV4PLUS_ALLOW_PYTHON_MLKEM=1 is set.
    """

    name = "kyber-py (pure Python)"
    post_quantum = True

    def __init__(self, cls):
        self._c = cls

    def keygen(self):
        ek, dk = self._c.keygen()
        return bytes(ek), bytearray(dk)

    def encaps(self, ek: bytes):
        ss, ct = self._c.encaps(ek)                # (ss, ct) — inverted here
        return bytes(ct), bytearray(ss)

    def decaps(self, ct: bytes, dk) -> bytearray:
        return bytearray(self._c.decaps(bytes(dk), ct))


_KEM = None
_KEM_RESOLVED = False


def _kem_self_test(provider) -> bool:
    """One keygen/encaps/decaps round trip. False if anything is wrong."""
    try:
        ek, dk = provider.keygen()
        if len(ek) != MLKEM_EK_LEN or len(dk) != MLKEM_DK_LEN:
            return False
        ct, ss = provider.encaps(bytes(ek))
        if len(ct) != MLKEM_CT_LEN or len(ss) != MLKEM_SS_LEN:
            return False
        # Also catches the (ct, ss) vs (ss, ct) inversion, which is otherwise
        # silent and presents much later as "media keys did not agree".
        return bytes(provider.decaps(bytes(ct), dk)) == bytes(ss)
    except Exception:
        return False


def _resolve_kem():
    global _KEM, _KEM_RESOLVED
    if _KEM_RESOLVED:
        return _KEM
    _KEM_RESOLVED = True
    try:
        import otrv4_core                                   # type: ignore
        if all(hasattr(otrv4_core, n) for n in
               ("mlkem1024_keygen", "mlkem1024_encaps", "mlkem1024_decaps")):
            candidate = _RustKem(otrv4_core)
            # Prove it works before trusting it. Attribute presence is not
            # evidence: a partially built core, or a stub installed by another
            # module, satisfies hasattr and then fails at call time — during a
            # call, after the user has already dialled. One round trip here
            # costs microseconds and turns that into a clean fallback.
            if _kem_self_test(candidate):
                _KEM = candidate
                return _KEM
    except Exception:
        pass
    try:
        from kyber_py.ml_kem import ML_KEM_1024              # type: ignore
        _KEM = _PurePythonKem(ML_KEM_1024)
        return _KEM
    except Exception:
        pass
    _KEM = None
    return None


def kem_provider():
    """Return the ML-KEM provider, or raise KemUnavailable.

    Voice refuses to run without one.  Falling back to X448-only would give
    a call that reports itself as hybrid while carrying no post-quantum
    protection whatsoever, which is worse than refusing.
    """
    kem = _resolve_kem()
    if kem is None:
        raise KemUnavailable(
            "ML-KEM-1024 unavailable — otrv4_core is not loaded and kyber-py "
            "is not installed.  Voice requires a hybrid exchange and will "
            "not fall back to X448 alone.")
    if isinstance(kem, _PurePythonKem) and not os.environ.get(
            "OTRV4PLUS_ALLOW_PYTHON_MLKEM"):
        raise KemUnavailable(
            "only the pure-Python ML-KEM is available; it is not "
            "constant-time and is refused for live calls.  Load otrv4_core, "
            "or set OTRV4PLUS_ALLOW_PYTHON_MLKEM=1 for testing.")
    return kem


def set_kem_provider_for_testing(provider) -> None:
    """Install a KEM provider explicitly.  Test seam — never used in the app."""
    global _KEM, _KEM_RESOLVED
    _KEM, _KEM_RESOLVED = provider, True


# ---------------------------------------------------------------------------
# Media / codec constants
# ---------------------------------------------------------------------------

# Voice frame wire revision.
#
# 3 -> 4 (C1): the latency work changed the frame PLAINTEXT layout. Eight bytes
# of the fixed padding slot now carry the sender's monotonic timestamp
# (VOICE_TS_LEN), so VOICE_PLAIN_LEN and the pad_opus/unpad_opus framing differ
# from revision 3.
#
# The packet is still 199 bytes and the header is unchanged, so a revision-3
# peer and a revision-4 peer would BOTH pass the header version check if this
# were left at 3. Worse, the timestamp sits inside the AEAD, so GCM would
# authenticate successfully and the mismatch would only appear as unpad_opus
# misreading Opus data -- garbled audio or a FrameError, with nothing pointing
# at a version mismatch.
#
# Incrementing it moves that failure to parse_media_header, which raises
# FrameError("unsupported protocol version N") before any key material is used.
VOICE_PROTOCOL_VERSION = 4

# Frame geometry is DERIVED from otrv4plus_audio, never redeclared.
#
# These used to be independent literals in both modules. Nothing linked them,
# so changing one produced a silent mismatch: read_frame() handed back
# FRAME_BYTES of PCM while the encoder was told to consume
# VOICE_FRAME_SAMPLES, and at 40/60 that is Opus reading 1920 bytes out of a
# 1280-byte buffer on every single frame. Deriving them means the mismatch
# cannot be expressed.
VOICE_SAMPLE_RATE = _audio.SAMPLE_RATE
VOICE_FRAME_MS = _audio.FRAME_MS
VOICE_FRAME_SAMPLES = _audio.FRAME_SAMPLES
VOICE_CHANNELS = _audio.CHANNELS
VOICE_FRAME_BYTES = _audio.FRAME_BYTES
FRAME_INTERVAL_S = VOICE_FRAME_MS / 1000.0
# 24 kbit/s. 16k was chosen while the stream transport was collapsing and
# the priority was offering the path less; on datagrams the same path now
# runs drop=0 with rx tracking tx, so the constraint that forced it is gone.
#
# The extra bytes are close to free here, which is the part worth stating
# plainly: I2P moves data in ~1 KB tunnel messages, and a 199-byte datagram
# and a 279-byte one each occupy exactly one. The packet RATE is what costs
# tunnel messages, and that is unchanged at 16.7/s. On the wire this is
# 37.2 kbit/s against 26.5, but in the currency the path actually charges in
# it is the same 16.7 messages per second either way.
#
# 60 ms at 24 kbit/s is 180 bytes nominal, 225 at the VBR peak, so the slot
# below had to grow with it. The import-time check enforces the relationship.
VOICE_BITRATE = 24000
# 8 rather than 5: the extra CPU is affordable at 16.7 frames/s on aarch64 and
# buys audible quality, which matters more here than on a low-latency path.
VOICE_COMPLEXITY = 8
# In-band FEC repairs a ONE-frame gap only; longer gaps fall through to
# concealment. The observed failure mode is multi-second starvation, which
# FEC cannot touch, so 20% of the bitrate was being spent on redundancy that
# never applied. 5% keeps single-frame repair, which does work.
VOICE_LOSS_PCT = 5

# Constant-rate shaping.  Opus at 16 kbit/s and 60 ms is exactly 120 bytes in
# CBR; the slot is sized for the VBR peak so a build that refuses vbr=0
# degrades to 8 kbit/s of padding overhead rather than replacing every single
# frame with silence and producing a call that carries no audio at all.
# 8 bytes of the fixed slot carry the sender's monotonic timestamp, used for
# one-way latency. Taken from padding that was already being transmitted, so
# the packet stays 199 bytes and the constant-rate property is untouched:
# 16 kbit/s at 60 ms is 120 bytes, exactly filling the remaining 152 slot
# minus VBR headroom.
VOICE_TS_LEN = 8
# Sized for the VBR peak at VOICE_BITRATE and VOICE_FRAME_MS, plus margin.
# This is a WIRE FORMAT constant: it sets VOICE_PLAIN_LEN and so the packet
# length, and two peers with different values reject each other's frames.
VOICE_OPUS_SLOT = 232
VOICE_PLAIN_LEN = 2 + VOICE_TS_LEN + VOICE_OPUS_SLOT

# ── Configuration invariants, checked at import ──────────────────────────────
#
# Every one of these has already been violated in practice, and each failed
# silently rather than loudly:
#
#   frame geometry   the two modules held independent literals and drifted
#   slot vs bitrate  an Opus frame larger than the slot makes pad_opus return
#                    None, so _capture_worker substitutes silence and counts
#                    "oversize" -- a call that connects, reports healthy, and
#                    transmits nothing
#   Opus frame size  libopus accepts only 2.5/5/10/20/40/60 ms; anything else
#                    fails per frame at runtime
#
# Raising here means a bad combination cannot reach a call.
_OPUS_VALID_FRAME_MS = (10, 20, 40, 60)

if VOICE_FRAME_MS not in _OPUS_VALID_FRAME_MS:
    raise RuntimeError(
        "VOICE_FRAME_MS is %d ms; libopus accepts only %s. It is derived from "
        "otrv4plus_audio.FRAME_MS -- change it there."
        % (VOICE_FRAME_MS, list(_OPUS_VALID_FRAME_MS)))

if (VOICE_FRAME_SAMPLES != VOICE_SAMPLE_RATE * VOICE_FRAME_MS // 1000
        or VOICE_FRAME_BYTES != VOICE_FRAME_SAMPLES * VOICE_CHANNELS * 2):
    raise RuntimeError(
        "frame geometry is inconsistent: %d ms, %d samples, %d bytes"
        % (VOICE_FRAME_MS, VOICE_FRAME_SAMPLES, VOICE_FRAME_BYTES))

#: Bytes one Opus frame occupies at the configured bitrate, plus headroom for
#: the VBR peak that a build refusing vbr=0 will produce.
VOICE_OPUS_PEAK_BYTES = (VOICE_BITRATE * VOICE_FRAME_MS // 8000) * 5 // 4

if VOICE_OPUS_PEAK_BYTES > VOICE_OPUS_SLOT:
    raise RuntimeError(
        "VOICE_BITRATE %d at %d ms needs up to %d bytes but VOICE_OPUS_SLOT "
        "is %d. Every frame would exceed the slot, be replaced with silence, "
        "and the call would carry no audio. Lower the bitrate, shorten the "
        "frame, or raise the slot (raising it changes the wire format and "
        "both peers must match)."
        % (VOICE_BITRATE, VOICE_FRAME_MS, VOICE_OPUS_PEAK_BYTES,
           VOICE_OPUS_SLOT))

VOICE_SYNC = 0xA7
FRAME_TYPE_AUDIO = 0x01
FRAME_TYPE_PING = 0x02          # latency probe, echoed as PONG
FRAME_TYPE_PONG = 0x03
_FRAME_TYPES = (FRAME_TYPE_AUDIO, FRAME_TYPE_PING, FRAME_TYPE_PONG)

# sync | version | frame_type | epoch(8) | counter(8) | length(2)
VOICE_HDR_LEN = 21
VOICE_HDR_FMT = ">BBBQQH"

VOICE_SEALED_LEN = VOICE_PLAIN_LEN + 16          # ct || GCM tag; nonce derived
VOICE_PACKET_LEN = VOICE_HDR_LEN + VOICE_SEALED_LEN

VOICE_MIN_FRAME = VOICE_SEALED_LEN
VOICE_MAX_FRAME = VOICE_SEALED_LEN

DIR_INITIATOR = 0x01        # caller -> callee
DIR_RESPONDER = 0x02        # callee -> caller

# Jitter buffer.  Sequence-aware and bounded: an attacker who can inject must
# not be able to grow it, and a stalled playout device must not accumulate
# audio nobody will ever hear.
# Expressed in MILLISECONDS and converted, because these are depths in frames
# and a frame is not a fixed duration. Changing VOICE_FRAME_MS from 40 to 60
# silently stretched a 6-frame floor from 240 ms to 360 ms -- 120 ms of added
# latency that no constant mentioned and nobody asked for.
VOICE_JITTER_PREFILL_MS = 240       # before playout starts
VOICE_JITTER_MAX_MS = 2000          # hard cap
VOICE_JITTER_DRIFT_HIGH_MS = 600    # above this, claw latency back

VOICE_JITTER_PREFILL = max(2, VOICE_JITTER_PREFILL_MS // VOICE_FRAME_MS)
VOICE_JITTER_MAX = max(4, VOICE_JITTER_MAX_MS // VOICE_FRAME_MS)
# Latency ceiling. Without this the buffer keeps whatever depth a burst pushed
# it to for the rest of the call: playout is paced by the audio device, so it
# never catches up on its own. Observed at 46/50 and 27/50 on live calls —
# nearly two seconds parked on top of I2P's own delay. Shedding one 60 ms
# frame is a click; holding two seconds makes conversation impossible.
VOICE_JITTER_DRIFT_HIGH = max(VOICE_JITTER_PREFILL + 1,
                              VOICE_JITTER_DRIFT_HIGH_MS // VOICE_FRAME_MS)
VOICE_JITTER_LATE_TOLERANCE = 2     # frames older than this are discarded

#: Bytes of kernel send buffer to allow on the media socket.
#:
#: This is the queue that actually caused a live call to run 24 seconds
#: behind.  The SAM bridge is a loopback TCP connection, and Linux autotunes
#: a loopback socket's send buffer up to net.ipv4.tcp_wmem[2] -- 4 MiB on a
#: stock Android kernel.  At 199 bytes per frame that is over twenty thousand
#: frames, i.e. about twenty minutes of audio the kernel will accept without
#: ever telling us, while asyncio's own write buffer reads as empty and every
#: backpressure check we make passes.  i2pd applies real backpressure at the
#: far end (SAMSocket does not re-arm its read until the stream has taken the
#: previous chunk), so the buffer fills and simply stays full.
#:
#: Calling setsockopt at all disables autotuning and pins the value.  The
#: kernel enforces a floor (SOCK_MIN_SNDBUF, ~4.6 KiB) and doubles what is
#: asked for, so the effective floor is a little over a second of audio; that
#: is the tightest bound available without leaving SOCK_STREAM behind.
VOICE_SEND_BUFFER_BYTES = VOICE_PACKET_LEN * 8


def limit_media_send_buffer(sock) -> int:
    """Pin the media socket's kernel send buffer small.  Returns the result.

    Best-effort: a platform that refuses SO_SNDBUF leaves the socket usable,
    just bloated, so this never raises.  The returned size is what the kernel
    actually granted, which is what the caller should log -- asking for 1592
    bytes and being given 4608 is normal and worth seeing.
    """
    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF,
                        VOICE_SEND_BUFFER_BYTES)
        return sock.getsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF)
    except Exception:
        return -1

# ── Media transport selection ────────────────────────────────────────────────
#
# Media used to ride the same SAM STYLE=STREAM connection as everything else.
# That is a reliable, ordered, retransmitting transport, and for real-time
# audio those three properties are defects rather than features: congestion
# cannot show up as loss, so it shows up as unbounded delay instead.
#
# Measured on a live call, with drop=0/late=0/authfail=0 throughout:
#
#   * one 5 s window received 381 frames against the ~83 sent in it -- a
#     stream unblocking after a stall, not a network recovering
#   * one-way delay reached 24 s and RTT 22 s
#   * recovery was a clean monotonic decay (19320 -> 17344 -> 12697 -> 8018
#     -> 3666 -> 1472 ms over ~30 s), which is a standing queue draining at a
#     constant rate
#   * in between, the same path sustained rtt=1269ms oneway=536ms rx=83/83
#
# i2pd fixes INITIAL_RTO at 9000 ms at compile time (libi2pd/Streaming.h) and
# exposes no I2CP or SAM knob for it, so a single lost segment stalls every
# frame behind it for nine seconds no matter how the sender is tuned. Bounding
# our own queues (see _SEND_DEADLINE_S) caps the damage; it cannot remove
# head-of-line blocking, because the blocking is not in a queue we own.
#
# Datagrams remove it at the source: no retransmission, no ordering guarantee,
# no window. Loss stays loss, which is exactly what Opus concealment and the
# sequence-aware jitter buffer are already built to absorb.
#
# The wire format needs no change. Every media packet is already
# self-contained -- VOICE_SYNC, an authenticated header carrying epoch,
# counter, length and type, then the sealed body -- and every property that
# made it safe over a stream (AEAD authentication, per-epoch replay windows,
# sequence-aware reordering) is exactly what a datagram transport requires.
# ── I2P destinations ─────────────────────────────────────────────────────────
#
# SAM v3 answers SESSION CREATE with
#
#     SESSION STATUS RESULT=OK DESTINATION=$privkey
#
# and $privkey is NOT the destination. Per the SAM v3 specification it is the
# base64 of
#
#     Destination || PrivateKey || SigningPrivateKey
#
# -- 679 bytes for SIGNATURE_TYPE=7, which is 908 base64 characters against
# the 524 of the destination alone. Two things followed from treating that
# string as if it were a destination:
#
#   * it was published to the peer in every INVITE, so the session's own
#     private keys went out over the wire. The destination is TRANSIENT and
#     per-call and the INVITE travels inside the established OTR channel, so
#     only the authenticated peer ever saw it -- but a private key belongs on
#     one device and it was on two.
#   * the repliable-datagram source filter compared SAM's reported source, a
#     524-character destination, against a 908-character private key blob.
#     They never matched, so the callee dropped every media datagram the
#     caller sent: rx=0 with drop climbing at the frame rate.
#
# Everything that needs a destination -- the INVITE, STREAM CONNECT, the
# datagram filter -- wants the Destination alone, so it is parsed out once
# here and the blob is never retained.
_I2P_B64_TO_STD = str.maketrans("-~", "+/")
_I2P_B64_FROM_STD = str.maketrans("+/", "-~")

#: KeysAndCert before the certificate body: 256 public + 128 signing public
#: + 1 certificate type + 2 certificate length.
_KEYS_AND_CERT_PREFIX = 387


def i2p_b64decode(text: str) -> bytes:
    """Decode I2P's base64 alphabet (+ and / replaced by - and ~)."""
    import base64
    padded = text + "=" * (-len(text) % 4)
    return base64.b64decode(padded.translate(_I2P_B64_TO_STD))


def i2p_b64encode(raw: bytes) -> str:
    """Encode to I2P's base64 alphabet."""
    import base64
    return base64.b64encode(raw).decode("ascii").translate(_I2P_B64_FROM_STD)


def i2p_public_destination(text: str) -> str:
    """Return the Destination alone from a destination or a SAM private key.

    Idempotent: handed a bare destination it returns an equivalent string, so
    it is safe to apply to anything arriving from a peer whether that peer
    sends the destination or, as this code used to, the whole private blob.

    Raises ValueError on anything that does not parse as a KeysAndCert, which
    is what a caller wants for a field that came off the wire.
    """
    raw = i2p_b64decode(text)
    if len(raw) < _KEYS_AND_CERT_PREFIX:
        raise ValueError("destination is %d bytes, too short for a KeysAndCert"
                         % len(raw))
    cert_len = int.from_bytes(raw[385:387], "big")
    total = _KEYS_AND_CERT_PREFIX + cert_len
    if len(raw) < total:
        raise ValueError("certificate claims %d bytes but only %d remain"
                         % (cert_len, len(raw) - _KEYS_AND_CERT_PREFIX))
    return i2p_b64encode(raw[:total])


VOICE_TRANSPORT_DATAGRAM = "datagram"
VOICE_TRANSPORT_STREAM = "stream"

#: UDP port the SAM bridge listens on for outbound datagrams. i2pd's default
#: is 7655 (sam.udpport); a router that moved it needs this overridden.
SAM_UDP_PORT = 7655

#: Largest forwarded datagram we will read. A media packet is 199 bytes; the
#: SAM forwarding header prepends the sender's base64 destination, which is
#: ~520 bytes for an Ed25519 destination. 4 KiB is generous for both and still
#: refuses anything that could only be an attempt to make us allocate.
SAM_DATAGRAM_MAX = 4096


def voice_transport_mode() -> str:
    """Which media transport to use.  Datagram unless explicitly overridden.

    ``OTRV4PLUS_VOICE_TRANSPORT=stream`` restores the old behaviour, which is
    worth keeping reachable: a router with SAM UDP disabled cannot do
    datagrams at all, and the stream path is the one with years of use behind
    it.
    """
    choice = os.environ.get("OTRV4PLUS_VOICE_TRANSPORT", "").strip().lower()
    if choice == VOICE_TRANSPORT_STREAM:
        return VOICE_TRANSPORT_STREAM
    return VOICE_TRANSPORT_DATAGRAM


def sam_udp_port() -> int:
    """SAM bridge UDP port, overridable for a router that moved it."""
    raw = os.environ.get("OTRV4PLUS_SAM_UDP_PORT", "").strip()
    if raw.isdigit():
        port = int(raw)
        if 1 <= port <= 65535:
            return port
    return SAM_UDP_PORT


def build_datagram_send_header(session_id: str, peer_dest: str) -> bytes:
    """SAM v3 datagram send header: ``3.0 <session> <destination>\n``.

    The payload follows immediately with no length prefix -- the UDP datagram
    boundary is the frame boundary, which is the entire point of moving here.
    """
    return ("3.0 %s %s\n" % (session_id, peer_dest)).encode("ascii")


def split_datagram_receive(data: bytes):
    """Split a forwarded SAM datagram into (source_destination, payload).

    A repliable datagram arrives as ``<base64 destination>\n<payload>``.
    Returns (None, data) if there is no header, so a router configured for RAW
    forwarding still delivers audio -- the payload authenticates either way,
    and the destination is only ever used as a cheap pre-AEAD filter.
    """
    idx = data.find(b"\n")
    if idx <= 0:
        return None, data
    head = data[:idx]
    try:
        source = head.decode("ascii")
    except Exception:
        return None, data
    if len(source) < 64 or any(c.isspace() for c in source):
        return None, data
    return source, data[idx + 1:]

VOICE_REKEY_SECONDS = 120
VOICE_REKEY_TIMEOUT = 45

# Control-plane DoS bounds.
VOICE_MAX_CONCURRENT_CALLS = 1
VOICE_MIN_INVITE_INTERVAL = 10.0    # seconds between accepted INVITEs per peer
VOICE_MAX_CONTROL_PER_MIN = 60      # control messages accepted per peer/minute
VOICE_MAX_REKEY_PER_MIN = 6

SAM_HELLO_TIMEOUT = 30
SAM_SESSION_TIMEOUT = 300
SAM_ACCEPT_TIMEOUT = 300
SAM_CONNECT_TIMEOUT = 240


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
_LABEL_MEDIA = b"OTRv4+Voice/Media/v1"
_LABEL_CONFIRM = b"OTRv4+Voice/Confirm/v1"
_LABEL_RATCHET = b"OTRv4+Voice/Ratchet/v1"
_LABEL_AAD = b"OTRv4+Voice/AAD/v3"
_LABEL_VERSION = b"OTRv4+Voice/v3"

ROOT_LEN = 64
MEDIA_KEY_LEN = 32
CONFIRM_LEN = 32


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA512(), length=length,
                salt=salt, info=info).derive(ikm)


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


def derive_voice_root(x448_shared, mlkem_shared, transcript: bytes) -> bytearray:
    """Hybrid root from the initial exchange.  Both secrets are mandatory."""
    if not x448_shared or len(x448_shared) != 56:
        raise ValueError("X448 shared secret must be 56 bytes")
    if not mlkem_shared or len(mlkem_shared) != MLKEM_SS_LEN:
        raise ValueError("ML-KEM shared secret must be %d bytes" % MLKEM_SS_LEN)
    ikm = bytearray()
    ikm += _lp(bytes(x448_shared))
    ikm += _lp(bytes(mlkem_shared))
    try:
        return bytearray(_hkdf(bytes(ikm), _salt_for(transcript),
                               _LABEL_INITIAL + transcript, ROOT_LEN))
    finally:
        _wipe(ikm)


def derive_rekey_root(old_root, x448_shared, mlkem_shared,
                      transcript: bytes) -> bytearray:
    """Hybrid root for a rekey, chained onto the root it replaces.

    Chaining onto the old root is what makes a rekey an upgrade rather than a
    replacement: an attacker who compromised neither the old root nor the new
    ephemerals gains nothing, and one who holds only the old root is locked
    out by the fresh X448 and ML-KEM secrets.
    """
    if not old_root or len(old_root) != ROOT_LEN:
        raise ValueError("old root must be %d bytes" % ROOT_LEN)
    if not x448_shared or len(x448_shared) != 56:
        raise ValueError("X448 shared secret must be 56 bytes")
    if not mlkem_shared or len(mlkem_shared) != MLKEM_SS_LEN:
        raise ValueError("ML-KEM shared secret must be %d bytes" % MLKEM_SS_LEN)
    ikm = bytearray()
    ikm += _lp(bytes(old_root))
    ikm += _lp(bytes(x448_shared))
    ikm += _lp(bytes(mlkem_shared))
    try:
        return bytearray(_hkdf(bytes(ikm), _salt_for(transcript),
                               _LABEL_REKEY + transcript, ROOT_LEN))
    finally:
        _wipe(ikm)


def derive_media_key(root, call_id: bytes, epoch: int, direction: int) -> bytearray:
    """One directional AES-256-GCM key for one epoch."""
    if direction not in (DIR_INITIATOR, DIR_RESPONDER):
        raise ValueError("direction must be DIR_INITIATOR or DIR_RESPONDER")
    info = (_LABEL_MEDIA + _lp(call_id) + _u64(epoch)
            + struct.pack(">B", direction))
    return bytearray(_hkdf(bytes(root), call_id, info, MEDIA_KEY_LEN))


def derive_confirmations(root, call_id: bytes, epoch: int):
    """Return (confirm_initiator, confirm_responder) for this root.

    Two distinct tags rather than one shared value, so a tag observed from
    one side cannot simply be reflected back to satisfy the other.  Each side
    computes both, transmits its own and checks the peer's.
    """
    info = _LABEL_CONFIRM + _lp(call_id) + _u64(epoch)
    raw = _hkdf(bytes(root), call_id, info, CONFIRM_LEN * 2)
    return raw[:CONFIRM_LEN], raw[CONFIRM_LEN:]


def ratchet_key(key) -> bytearray:
    """One irreversible step of the symmetric media chain.

    Gives forward secrecy for audio already sent.  It does NOT give
    post-compromise recovery: an attacker holding the current chain key can
    step it forward indefinitely.  Recovery comes only from the periodic
    hybrid rekey.
    """
    return bytearray(_hkdf(bytes(key), b"", _LABEL_RATCHET, MEDIA_KEY_LEN))


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
        from cryptography.hazmat.primitives.asymmetric import x448
        from cryptography.hazmat.primitives import serialization

        self._x448 = x448
        self._ser = serialization
        self.is_initiator = bool(is_initiator)
        self._kem = kem if kem is not None else kem_provider()

        self._private = x448.X448PrivateKey.generate()
        self.public = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        # Initiator only: the ML-KEM keypair it will decapsulate with.
        self.mlkem_ek = b""
        self._mlkem_dk = None
        if self.is_initiator:
            ek, dk = self._kem.keygen()
            if len(ek) != MLKEM_EK_LEN:
                raise ValueError("ML-KEM encapsulation key must be %d bytes, "
                                 "got %d" % (MLKEM_EK_LEN, len(ek)))
            self.mlkem_ek, self._mlkem_dk = ek, dk

    # -- X448 -------------------------------------------------------------

    def _agree_x448(self, peer_public: bytes) -> bytearray:
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
        try:
            peer_key = self._x448.X448PublicKey.from_public_bytes(peer_public)
            shared = bytearray(self._private.exchange(peer_key))
        finally:
            self._private = None
        # X448 outputs all-zero for low-order input; RFC 7748 requires the
        # exchange be aborted rather than the result used.
        if len(shared) != 56 or shared == bytearray(56):
            _wipe(shared)
            raise ValueError("degenerate X448 shared secret — aborting")
        return shared

    # -- initiator --------------------------------------------------------

    def initiator_agree(self, peer_x448_pub: bytes, mlkem_ct: bytes):
        """Complete both halves as the initiator.  Returns (x448_ss, kem_ss)."""
        if not self.is_initiator:
            raise RuntimeError("initiator_agree called on a responder exchange")
        if self._mlkem_dk is None:
            raise RuntimeError("ML-KEM decapsulation key already consumed")
        if not mlkem_ct or len(mlkem_ct) != MLKEM_CT_LEN:
            raise ValueError("ML-KEM ciphertext must be %d bytes" % MLKEM_CT_LEN)

        x_ss = self._agree_x448(peer_x448_pub)
        try:
            kem_ss = self._kem.decaps(bytes(mlkem_ct), self._mlkem_dk)
        except Exception:
            _wipe(x_ss)
            raise
        finally:
            _wipe(self._mlkem_dk)
            self._mlkem_dk = None
        if len(kem_ss) != MLKEM_SS_LEN:
            _wipe(x_ss)
            _wipe(kem_ss)
            raise ValueError("ML-KEM shared secret has the wrong length")
        return x_ss, kem_ss

    # -- responder --------------------------------------------------------

    def responder_agree(self, peer_x448_pub: bytes, peer_mlkem_ek: bytes):
        """Complete both halves as the responder.

        Returns (x448_ss, kem_ss, mlkem_ct).  The ciphertext must be sent to
        the initiator and is part of the transcript on both sides.
        """
        if self.is_initiator:
            raise RuntimeError("responder_agree called on an initiator exchange")
        if not peer_mlkem_ek or len(peer_mlkem_ek) != MLKEM_EK_LEN:
            raise ValueError("ML-KEM encapsulation key must be %d bytes"
                             % MLKEM_EK_LEN)

        x_ss = self._agree_x448(peer_x448_pub)
        try:
            ct, kem_ss = self._kem.encaps(bytes(peer_mlkem_ek))
        except Exception:
            _wipe(x_ss)
            raise
        if len(ct) != MLKEM_CT_LEN or len(kem_ss) != MLKEM_SS_LEN:
            _wipe(x_ss)
            _wipe(kem_ss)
            raise ValueError("ML-KEM encapsulation produced wrong-sized output")
        return x_ss, kem_ss, bytes(ct)

    def destroy(self) -> None:
        """Release any private material still held.  Idempotent."""
        self._private = None
        if self._mlkem_dk is not None:
            _wipe(self._mlkem_dk)
            self._mlkem_dk = None


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
    """A media frame failed parsing, authentication or replay checks."""


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
        raise FrameError("short header")
    sync, version, ftype, epoch, counter, length = struct.unpack(
        VOICE_HDR_FMT, raw[:VOICE_HDR_LEN])
    if sync != VOICE_SYNC:
        raise FrameError("bad sync byte")
    if version != VOICE_PROTOCOL_VERSION:
        raise FrameError("unsupported protocol version %d" % version)
    if ftype not in _FRAME_TYPES:
        raise FrameError("unsupported frame type 0x%02x" % ftype)
    # Mute, silence and speech are all AUDIO, so the field still says nothing
    # about what the microphone is doing. PING/PONG are the only exceptions
    # and they are the same 199 bytes on the same cadence, so an observer
    # learns that a probe happened, not anything about the conversation.
    if not (VOICE_MIN_FRAME <= length <= VOICE_MAX_FRAME):
        raise FrameError("implausible sealed length %d" % length)
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
        if not root or len(root) != ROOT_LEN:
            raise ValueError("epoch root must be %d bytes" % ROOT_LEN)
        if not call_id or len(call_id) < 16:
            raise ValueError("call_id must be at least 16 bytes")
        if epoch < 0 or epoch >= (1 << 64):
            raise ValueError("epoch out of range")

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self._AESGCM = AESGCM

        self.call_id = bytes(call_id)
        self.epoch = int(epoch)
        self.is_initiator = bool(is_initiator)
        self.send_dir = DIR_INITIATOR if is_initiator else DIR_RESPONDER
        self.recv_dir = DIR_RESPONDER if is_initiator else DIR_INITIATOR

        self._send_key = derive_media_key(root, self.call_id, self.epoch,
                                          self.send_dir)
        self._send_gcm = AESGCM(bytes(self._send_key))
        self._send_counter = 0
        self._send_sub = 0

        self._recv_key = derive_media_key(root, self.call_id, self.epoch,
                                          self.recv_dir)
        self._recv_gcm = AESGCM(bytes(self._recv_key))
        self._recv_sub = 0
        self._recv_prev_key = None
        self._recv_prev_gcm = None

        self._replay = ReplayWindow()
        self.ratchet_steps = 0
        self.last_frame_type = FRAME_TYPE_AUDIO
        self._zeroized = False

    # -- send -------------------------------------------------------------

    def _advance_send(self, sub: int) -> None:
        while self._send_sub < sub:
            new_key = ratchet_key(self._send_key)
            _wipe(self._send_key)
            self._send_key = new_key
            self._send_sub += 1
            self.ratchet_steps += 1
        self._send_gcm = self._AESGCM(bytes(self._send_key))

    def seal(self, plaintext: bytes, frame_type: int = FRAME_TYPE_AUDIO) -> bytes:
        """Encrypt one padded frame.  Returns the complete wire packet."""
        if self._zeroized:
            raise FrameError("media cipher already zeroized")
        if self._send_counter >= self.MAX_COUNTER:
            raise FrameError("frame counter exhausted")

        sub = self._send_counter // self.RATCHET_INTERVAL
        if sub != self._send_sub:
            self._advance_send(sub)

        counter = self._send_counter
        header = pack_media_header(self.epoch, counter, VOICE_SEALED_LEN,
                                   frame_type=frame_type)
        aad = media_aad(self.call_id, self.send_dir, header)
        sealed = self._send_gcm.encrypt(media_nonce(self.epoch, counter),
                                        plaintext, aad)
        if len(sealed) != VOICE_SEALED_LEN:
            raise FrameError("sealed frame has the wrong length")
        self._send_counter += 1
        return header + sealed

    # -- receive ----------------------------------------------------------

    def _advance_recv(self, sub: int) -> None:
        while self._recv_sub < sub:
            if self._recv_prev_key is not None:
                _wipe(self._recv_prev_key)
            self._recv_prev_key = self._recv_key
            self._recv_prev_gcm = self._recv_gcm
            self._recv_key = ratchet_key(self._recv_key)
            self._recv_gcm = self._AESGCM(bytes(self._recv_key))
            self._recv_sub += 1
            self.ratchet_steps += 1

    def open(self, header: bytes, sealed: bytes) -> bytes:
        """Authenticate and decrypt one frame.

        Ordering is deliberate: cheap structural checks, then the bounded
        replay test, then authentication, and only then any state mutation.
        A forged frame can neither push the ratchet forward nor consume a
        counter, because nothing commits until the tag verifies.
        """
        if self._zeroized:
            raise FrameError("media cipher already zeroized")
        epoch, counter, length, ftype = parse_media_header(header)
        if epoch != self.epoch:
            raise FrameError("frame epoch %d is not this cipher's epoch %d"
                             % (epoch, self.epoch))
        if length != len(sealed):
            raise FrameError("declared length does not match the frame")
        if self._replay.seen(counter):
            raise FrameError("replayed or stale frame counter %d" % counter)

        sub = counter // self.RATCHET_INTERVAL
        if sub > self._recv_sub + self._MAX_SUBEPOCH_JUMP:
            raise FrameError("sub-epoch too far ahead")

        aad = media_aad(self.call_id, self.recv_dir, header)
        nonce = media_nonce(epoch, counter)

        if sub == self._recv_sub:
            plaintext = self._recv_gcm.decrypt(nonce, sealed, aad)
        elif (sub == self._recv_sub - self._EPOCH_GRACE
              and self._recv_prev_gcm is not None):
            plaintext = self._recv_prev_gcm.decrypt(nonce, sealed, aad)
        elif sub > self._recv_sub:
            # Speculative: derive forward on a scratch copy and commit the
            # ratchet only once the frame authenticates, so a forged frame
            # cannot advance our chain and lock the genuine peer out.
            probe = bytearray(self._recv_key)
            try:
                for _ in range(sub - self._recv_sub):
                    nxt = ratchet_key(probe)
                    _wipe(probe)
                    probe = nxt
                plaintext = self._AESGCM(bytes(probe)).decrypt(
                    nonce, sealed, aad)
            finally:
                _wipe(probe)
            self._advance_recv(sub)
        else:
            raise FrameError("frame from an expired sub-epoch")

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
        self._send_gcm = None
        self._recv_gcm = None
        self._recv_prev_gcm = None
        for name in ("_send_key", "_recv_key", "_recv_prev_key"):
            key = getattr(self, name, None)
            if key is not None:
                _wipe(key)
                setattr(self, name, None)


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
        if len(root) != ROOT_LEN:
            raise ValueError("root must be %d bytes" % ROOT_LEN)
        self._root = bytearray(root)
        self._epoch = 0
        self._ciphers[0] = VoiceFrameCrypto(self._root, self.call_id, 0,
                                            self.is_initiator)
        return derive_confirmations(self._root, self.call_id, 0)

    # -- rekey ------------------------------------------------------------

    def begin_rekey(self, epoch: int, root) -> tuple:
        """Derive a pending epoch without disturbing the current one.

        Returns (confirm_initiator, confirm_responder) over the pending root.
        """
        if self._root is None:
            raise RuntimeError("cannot rekey before the initial agreement")
        if epoch != self._epoch + 1:
            raise ValueError(
                "rekey epoch must be exactly current+1 (%d), got %d"
                % (self._epoch + 1, epoch))
        if epoch >= self.MAX_EPOCH:
            raise ValueError("epoch space exhausted")
        if self._pending is not None:
            raise RuntimeError("a rekey is already pending for epoch %d"
                               % self._pending["epoch"])
        if len(root) != ROOT_LEN:
            raise ValueError("root must be %d bytes" % ROOT_LEN)

        pending_root = bytearray(root)
        confirms = derive_confirmations(pending_root, self.call_id, epoch)

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
                         "confirms": confirms, "cipher": pending_cipher}
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
            self.abort_rekey()
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
        _wipe(self._root)
        self._root = pending["root"]
        self._epoch = epoch
        self.rekeys_committed += 1
        self._retire_old_epochs()
        return True

    def abort_rekey(self) -> None:
        """Discard pending material.  Idempotent."""
        if self._pending is None:
            return
        _wipe(self._pending["root"])
        cipher = self._pending.get("cipher")
        if cipher is not None:
            # Registered for receive by begin_rekey; a failed rekey must take
            # it back out so a stale epoch cannot keep decrypting.
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
            self.abort_rekey()
        except Exception:
            self._pending = None
        for epoch in list(self._ciphers):
            try:
                self._ciphers.pop(epoch).zeroize()
            except Exception:
                self._ciphers.pop(epoch, None)
        if self._root is not None:
            _wipe(self._root)
            self._root = None
        self._epoch = -1


# ---------------------------------------------------------------------------
# Jitter buffer
# ---------------------------------------------------------------------------

class JitterBuffer:
    """Bounded, sequence-aware reorder buffer for decoded PCM.

    v2 used a plain FIFO Queue, so a frame that arrived out of order was
    played out of order and there was no notion of "late".  This orders on
    (epoch, counter), rejects frames older than the last one played, rejects
    duplicates, and caps depth so neither network input nor a stalled
    playback device can grow memory.

    Gap concealment is reported rather than performed here: the caller owns
    the Opus decoder and is the only thing that can run PLC.
    """

    def __init__(self, prefill=VOICE_JITTER_PREFILL, maxlen=VOICE_JITTER_MAX,
                 late_tolerance=VOICE_JITTER_LATE_TOLERANCE,
                 drift_high=VOICE_JITTER_DRIFT_HIGH, adaptive=True):
        import heapq
        self._heapq = heapq
        self._heap = []
        self._seqs = set()
        self._lock = threading.Lock()
        self._prefill = int(prefill)
        self._maxlen = int(maxlen)
        self._late_tolerance = int(late_tolerance)
        self._drift_high = max(int(prefill) + 1, int(drift_high))
        self._primed = False
        self._last_played = -1

        # Adaptive depth. A fixed cushion is a bad trade on I2P: too small and
        # every tunnel hiccup is a dropout, too large and the whole call
        # carries the worst-case delay even when the path is behaving. So the
        # target tracks measured arrival jitter and moves with the path.
        self._adaptive = bool(adaptive)
        self._target = float(prefill)
        self._jitter_est = 0.0          # seconds, RFC 3550 style smoothing
        self._last_arrival = None
        self._last_seq = None
        self.stats = {"queued": 0, "late": 0, "duplicate": 0,
                      "overflow": 0, "gaps": 0, "drift": 0}

    @staticmethod
    def sequence(epoch: int, counter: int) -> int:
        """A single monotonic ordering key across epoch boundaries.

        Counters restart at zero each epoch, so ordering on the counter alone
        would replay the whole epoch's worth of audio backwards at every
        rekey.  62 bits of counter space is 5.9 billion years at 40 ms.
        """
        return (int(epoch) << 62) | (int(counter) & ((1 << 62) - 1))

    def _observe_arrival(self, seq: int, now: float) -> None:
        """Update the jitter estimate and the target depth.

        RFC 3550's interarrival jitter, with the frame counter standing in for
        a sender timestamp: consecutive frames are 40 ms apart by
        construction, so the expected spacing is known exactly and any
        deviation is transit jitter.

            D = (arrival_delta) - (expected_delta)
            J += (|D| - J) / 16

        The target is three standard-ish deviations of that, plus one frame of
        slack, clamped so it can never collapse below the floor or run away to
        the hard cap. Three is the usual choice: it absorbs nearly every
        spike without paying for the very worst one permanently.
        """
        if not self._adaptive:
            return
        if self._last_arrival is not None and self._last_seq is not None:
            seq_delta = seq - self._last_seq
            if 0 < seq_delta < 200:            # ignore reorder and huge gaps
                expected = seq_delta * (FRAME_INTERVAL_S)
                observed = now - self._last_arrival
                d = abs(observed - expected)
                self._jitter_est += (d - self._jitter_est) / 16.0
                frames = (3.0 * self._jitter_est) / FRAME_INTERVAL_S
                self._target = max(
                    float(self._prefill),
                    min(float(self._drift_high), frames + 1.0))
        if seq > (self._last_seq or -1):
            self._last_arrival = now
            self._last_seq = seq

    @property
    def target_depth(self) -> int:
        return int(self._target + 0.5)

    @property
    def jitter_ms(self) -> float:
        return self._jitter_est * 1000.0

    def push(self, epoch: int, counter: int, pcm) -> bool:
        """Offer one decoded frame.  False if it was dropped."""
        seq = self.sequence(epoch, counter)
        with self._lock:
            self._observe_arrival(seq, time.monotonic())
            if seq <= self._last_played - self._late_tolerance:
                self.stats["late"] += 1
                return False
            if seq <= self._last_played:
                self.stats["late"] += 1
                return False
            if seq in self._seqs:
                self.stats["duplicate"] += 1
                return False
            if len(self._heap) >= self._maxlen:
                # Playout is behind.  Drop the OLDEST rather than the newest:
                # stale audio is worthless and keeping it only grows latency.
                try:
                    stale_seq, stale_pcm = self._heapq.heappop(self._heap)
                    self._seqs.discard(stale_seq)
                    _wipe(stale_pcm)
                except Exception:
                    pass
                self.stats["overflow"] += 1
            self._heapq.heappush(self._heap, (seq, pcm))
            self._seqs.add(seq)
            self.stats["queued"] += 1
            return True

    def pop(self):
        """Return (pcm, gap_frames) or None if playout should wait.

        gap_frames is how many frames were lost between the previous playout
        and this one, so the caller can run packet-loss concealment.
        """
        with self._lock:
            if not self._primed:
                if len(self._heap) < self.target_depth:
                    return None
                self._primed = True
            if not self._heap:
                # Re-arm the cushion: resuming instantly after a stall makes
                # the next burst choppy.
                self._primed = False
                return None

            # Shed the oldest while we are above the latency ceiling. One
            # frame per pop, so depth converges over a second or so instead
            # of jumping — a gradual trim is far less audible than a jump,
            # and the gap counter below reports it as concealment anyway.
            # Shed against the adaptive target rather than a fixed ceiling,
            # so a call that starts on a congested path and then settles gets
            # its latency back instead of carrying the bad minute all night.
            # Margin of at least 4 frames (160 ms) beyond target before we
            # reclaim anything. Proportional-to-prefill was too tight on a
            # small cushion: four frames arriving out of order looked like
            # accumulated latency and the oldest got shed, reordering the
            # audio it was there to fix.
            if len(self._heap) > self.target_depth + max(self._prefill, 4):
                stale_seq, stale_pcm = self._heapq.heappop(self._heap)
                self._seqs.discard(stale_seq)
                _wipe(stale_pcm)
                self.stats["drift"] += 1

            seq, pcm = self._heapq.heappop(self._heap)
            self._seqs.discard(seq)
            gap = 0
            if self._last_played >= 0:
                gap = max(0, seq - self._last_played - 1)
                if gap:
                    self.stats["gaps"] += gap
            self._last_played = seq
            return pcm, gap

    def depth(self) -> int:
        with self._lock:
            return len(self._heap)

    def clear(self) -> None:
        """Wipe and discard everything queued.  Never raises."""
        with self._lock:
            while self._heap:
                try:
                    _, pcm = self._heapq.heappop(self._heap)
                    _wipe(pcm)
                except Exception:
                    break
            self._seqs.clear()
            self._primed = False


# ---------------------------------------------------------------------------
# Opus padding
# ---------------------------------------------------------------------------

def pad_opus(opus_frame: bytes, send_ts_ms: int = 0):
    """Pad to the fixed slot, carrying the sender's timestamp.

    Layout: len(2) || send_ts_ms(8) || opus || zero padding.

    The timestamp sits INSIDE the AEAD, so it is encrypted and authenticated
    rather than exposed in the header. It is milliseconds since the sender's
    call started, not wall-clock: a relative value leaks nothing about the
    sender's clock, and one-way latency only needs the difference.
    """
    if len(opus_frame) > VOICE_OPUS_SLOT:
        return None
    return (struct.pack(">HQ", len(opus_frame), int(send_ts_ms) & 0xFFFFFFFFFFFFFFFF)
            + bytes(opus_frame)
            + b"\x00" * (VOICE_OPUS_SLOT - len(opus_frame)))


def unpad_frame(plain: bytes):
    """Recover (opus_frame, send_ts_ms) from a padded plaintext."""
    if len(plain) != VOICE_PLAIN_LEN:
        raise FrameError("padded frame has the wrong length")
    length, send_ts = struct.unpack(">HQ", plain[:2 + VOICE_TS_LEN])
    if length > VOICE_OPUS_SLOT:
        raise FrameError("declared Opus length exceeds the slot")
    off = 2 + VOICE_TS_LEN
    return bytes(plain[off:off + length]), send_ts


def unpad_opus(plain: bytes) -> bytes:
    """Recover just the Opus frame.  Kept for callers that ignore timing."""
    return unpad_frame(plain)[0]


# ---------------------------------------------------------------------------
# Control-plane rate limiting
# ---------------------------------------------------------------------------

class LatencyTracker:
    """RTT and one-way latency over the media stream.

    Two measurements, because they answer different questions and fail
    differently.

    **RTT (ping/pong).** Needs no shared clock, so it is the number to trust.
    A PING carries an id and the sender's t1; the peer echoes it with its own
    t2 (receive) and t3 (send). Then, exactly as NTP does:

        rtt    = (t4 - t1) - (t3 - t2)
        offset = ((t2 - t1) + (t3 - t4)) / 2

    Subtracting the peer's turnaround means a slow responder inflates neither
    number.

    **One-way (frame timestamps).** Each audio frame carries the sender's
    milliseconds-since-call-start. Raw, the difference between that and our
    own clock is latency PLUS the offset between two unsynchronised phone
    clocks, which can be seconds — larger than the thing being measured. The
    offset from the ping/pong exchange is subtracted to correct it, so one-way
    is only reported once at least one RTT sample exists.

    Rolling windows: 10 RTT samples, 20 one-way. Medians, not means — a single
    I2P tunnel stall would drag a mean for the rest of the call.
    """

    RTT_WINDOW = 10
    ONEWAY_WINDOW = 20
    PING_INTERVAL = 5.0
    PING_TIMEOUT = 30.0

    def __init__(self):
        import collections
        # Per-call random origin. Frame stamps and ping/pong must share ONE
        # clock or the offset corrects nothing — that was the first version's
        # bug: frames were stamped call-relative while pings used raw
        # monotonic, so the two were in different units.
        #
        # The mask also keeps time.monotonic() off the wire. On Linux that is
        # time since boot, so a raw stamp would leak approximate uptime as a
        # weak device fingerprint. A constant per-call offset is absorbed
        # entirely by the ping/pong offset calculation, so it costs nothing.
        self._base = int.from_bytes(secrets.token_bytes(4), "big")
        self._rtt = collections.deque(maxlen=self.RTT_WINDOW)
        self._oneway = collections.deque(maxlen=self.ONEWAY_WINDOW)
        self._pending = {}                 # ping_id -> t1
        self._offset_ms = None             # peer clock minus ours
        self._lock = threading.Lock()
        self._next_ping = 0.0
        self._seq = 0
        self.sent = 0
        self.answered = 0
        self.timed_out = 0

    # -- clocks -----------------------------------------------------------

    @staticmethod
    def now_ms() -> int:
        return int(time.monotonic() * 1000)

    def stamp(self) -> int:
        """The single clock used for every measurement, masked per call."""
        return (self._base + self.now_ms()) & 0xFFFFFFFFFFFFFFFF

    def call_ms(self, _t0=None) -> int:
        """Frame timestamp.  Same clock as the probes, by construction."""
        return self.stamp()

    # -- ping/pong --------------------------------------------------------

    def due(self) -> bool:
        return time.monotonic() >= self._next_ping

    def build_ping(self):
        """Return (ping_id, payload) and arm the timeout."""
        with self._lock:
            self._next_ping = time.monotonic() + self.PING_INTERVAL
            self._seq = (self._seq + 1) & 0xFFFFFFFFFFFFFFFF
            ping_id = self._seq
            t1 = self.stamp()
            self._pending[ping_id] = t1
            self.sent += 1
            # Bound: a peer that never answers must not grow this.
            if len(self._pending) > 64:
                for stale in sorted(self._pending)[:len(self._pending) - 64]:
                    self._pending.pop(stale, None)
                    self.timed_out += 1
            cutoff = t1 - int(self.PING_TIMEOUT * 1000)
            for stale in [k for k, v in self._pending.items() if v < cutoff]:
                self._pending.pop(stale, None)
                self.timed_out += 1
        return ping_id, struct.pack(">QQ", ping_id, t1)

    def build_pong_stamped(self, ping_payload: bytes) -> bytes:
        """Echo a PING, stamping our receive and send times on OUR clock."""
        if len(ping_payload) < 16:
            raise FrameError("PING payload too short")
        ping_id, t1 = struct.unpack(">QQ", ping_payload[:16])
        t2 = self.stamp()
        t3 = t2                              # turnaround is immediate
        return struct.pack(">QQQQ", ping_id, t1, t2, t3)

    @staticmethod
    def build_pong(ping_payload: bytes) -> bytes:
        """Echo a PING as a PONG, stamping receive and send times."""
        if len(ping_payload) < 16:
            raise FrameError("PING payload too short")
        ping_id, t1 = struct.unpack(">QQ", ping_payload[:16])
        t2 = t3 = 0
        return struct.pack(">QQQQ", ping_id, t1, t2, t3)

    def handle_pong(self, payload: bytes) -> bool:
        """Record an RTT sample and update the clock offset."""
        if len(payload) < 32:
            raise FrameError("PONG payload too short")
        ping_id, _t1_echo, t2, t3 = struct.unpack(">QQQQ", payload[:32])
        t4 = self.stamp()
        with self._lock:
            t1 = self._pending.pop(ping_id, None)
            if t1 is None:
                return False               # unknown, replayed or timed out
            rtt = (t4 - t1) - (t3 - t2)
            if rtt < 0 or rtt > 120000:
                return False               # implausible; drop rather than skew
            self._rtt.append(rtt)
            self._offset_ms = ((t2 - t1) + (t3 - t4)) / 2.0
            self.answered += 1
        return True

    # -- one-way ----------------------------------------------------------

    def observe_frame(self, peer_send_ms: int, _t0=None) -> None:
        """Record a one-way sample from an audio frame's timestamp."""
        with self._lock:
            if self._offset_ms is None:
                return                     # no clock correction yet
            arrival = self.stamp()
            # offset = peer_clock - our_clock, so the peer's send instant on
            # OUR clock is (peer_send_ms - offset) and the one-way delay is
            # arrival - (peer_send_ms - offset). Subtracting the offset
            # instead of adding it doubles the skew rather than removing it.
            delta = arrival - peer_send_ms + self._offset_ms
            if -1000.0 < delta < 120000.0:
                self._oneway.append(delta)

    # -- readout ----------------------------------------------------------

    @staticmethod
    def _median(values):
        if not values:
            return None
        ordered = sorted(values)
        mid = len(ordered) // 2
        if len(ordered) % 2:
            return ordered[mid]
        return (ordered[mid - 1] + ordered[mid]) / 2.0

    @property
    def rtt_ms(self):
        with self._lock:
            return self._median(self._rtt)

    @property
    def oneway_ms(self):
        with self._lock:
            return self._median(self._oneway)

    def summary(self) -> str:
        rtt, ow = self.rtt_ms, self.oneway_ms
        return "rtt=%s oneway=%s" % (
            "%.0fms" % rtt if rtt is not None else "-",
            "%.0fms" % ow if ow is not None else "-")


class RateLimiter:
    """Per-peer token bucket for control messages.

    An INVITE costs an I2P tunnel build on both sides.  Without a limit a
    peer inside an established OTR session can force unbounded tunnel
    construction, which is a cheap remote resource-exhaustion attack against
    a phone.
    """

    MAX_TRACKED = 512          # distinct peers held before pruning kicks in

    def __init__(self, per_minute: int):
        self._per_minute = max(1, int(per_minute))
        self._events = {}
        self._last_prune = 0.0

    def _prune(self, now: float) -> None:
        """Bound the tracking table.

        Without this the dict grows one list per peer that has ever sent a
        call signal and never shrinks. handle_signal() rate-limits BEFORE the
        OTR and SMP gates — deliberately, so the gates cannot themselves be
        used as a workload — so the key set is driven by whoever talks to us,
        not by whoever we accept.

        Two stages. Expiry first: anything with nothing inside the window is
        free to drop and costs an attacker nothing to avoid. Then a hard cap,
        evicting least-recently-seen, because a flood of distinct JIDs inside
        a single window is all current and expiry alone would keep every one.

        The cap is a deliberate trade. Eviction resets a peer's budget, so a
        sufficiently wide flood can push a real peer out and buy itself a
        fresh allowance. That is acceptable: reaching this function at all
        requires an established OTR session, which costs the attacker an
        ML-KEM exchange, an ML-DSA signature and a ring signature per JID —
        far more than it costs us. Unbounded memory is the worse failure.
        """
        cutoff = now - 60.0
        for key in [k for k, w in self._events.items()
                    if not w or w[-1] < cutoff]:
            self._events.pop(key, None)
        if len(self._events) > self.MAX_TRACKED:
            ordered = sorted(self._events.items(),
                             key=lambda kv: kv[1][-1] if kv[1] else 0.0)
            for key, _w in ordered[:len(self._events) - self.MAX_TRACKED]:
                self._events.pop(key, None)
        self._last_prune = now

    def allow(self, key: str, now=None) -> bool:
        now = time.monotonic() if now is None else now
        if now - self._last_prune > 60.0 or len(self._events) > self.MAX_TRACKED:
            self._prune(now)
        window = self._events.setdefault(key, [])
        cutoff = now - 60.0
        while window and window[0] < cutoff:
            window.pop(0)
        if len(window) >= self._per_minute:
            return False
        window.append(now)
        return True

    def forget(self, key: str) -> None:
        self._events.pop(key, None)


# ---------------------------------------------------------------------------
# Call session
# ---------------------------------------------------------------------------

class VoiceCallSession:
    """One encrypted call carried over a single bidirectional SAM stream.

    TRANSPORT
    ---------
    Exactly one SAM stream, used full-duplex.  Both peers opening an outbound
    stream deadlocks, because each only begins listening after its own
    connect returns.  Roles are therefore fixed by who initiated: the
    initiator publishes a TRANSIENT destination and parks in STREAM ACCEPT
    before the INVITE is sent, so the responder's connect always finds a
    listener.

    THREADING
    ---------
    capture thread : AAudio/parec -> Opus -> AEAD -> event loop
    asyncio reader : socket -> AEAD -> Opus -> jitter buffer
    playback thread: jitter buffer -> AAudio/pacat

    Blocking device I/O never touches the event loop.  The key schedule is
    read from the capture thread and mutated from the loop, so it is guarded
    by a lock — v2 read `self._crypto` and `self._send_gen` unsynchronised
    and could label a frame with one epoch while sealing it under another.
    """

    ROLE_INITIATOR = "initiator"
    ROLE_RESPONDER = "responder"

    def __init__(self, peer, loop, call_id, is_initiator,
                 sam_host="127.0.0.1", sam_port=7656):
        if not call_id or len(call_id) != 16:
            raise ValueError("call_id must be exactly 16 bytes")

        self.peer = peer
        self.loop = loop
        self.call_id = bytes(call_id)
        self.is_initiator = bool(is_initiator)
        self.role = (self.ROLE_INITIATOR if is_initiator
                     else self.ROLE_RESPONDER)
        self.sam_host = sam_host
        self.sam_port = sam_port

        self.state = CallState.IDLE
        self._state_lock = threading.Lock()
        self._key_lock = threading.Lock()

        self.kex = VoiceKeyExchange(self.is_initiator)
        self.schedule = VoiceKeySchedule(self.call_id, self.is_initiator)
        self.our_confirm = None            # tag we send
        self.peer_confirm_expected = None  # tag the peer must send
        self.keys_confirmed = asyncio.Event()

        self.otr_material = None           # (otr_binding, local_fp, remote_fp)
        self._peer_dest = None
        self._peer_x448 = None
        self._peer_mlkem_ek = None
        self._mlkem_ct = None              # responder's ciphertext (transcript)
        self._rekey_kex = None
        self._rekey_waiter = None          # (epoch, Future) while in flight

        self._sam_control = None
        self._sam_session_id = None
        self._transport_mode = voice_transport_mode()
        self._dgram_sock = None          # our bound UDP receive socket
        self._dgram_transport = None     # asyncio datagram transport
        self._dgram_send_addr = None     # (host, port) of the SAM UDP bridge
        self._dgram_send_header = None   # cached "3.0 <session> <dest>\n"
        self._foreign_warned = False
        # Level control. Two devices on one call measured 4090 and 31226 for
        # the same microphone self-test, so the far end heard one of them as
        # a quiet, thin call regardless of the codec settings.
        self._mic_gain = _audio.make_mic_gain()
        self._speaker_gain = _audio.make_speaker_gain()
        self._our_dest = None
        self._media_sock = None
        self._accept_sock = None
        self._writer = None
        self._reader = None

        self._capture = None      # otrv4plus_audio capture stream
        self._playback = None     # otrv4plus_audio playback stream
        self.audio_backend = None
        self._audio_env = None
        self._opus_enc = None
        self._opus_dec = None
        self._silence_frame = None
        self.constant_rate = False

        self._capture_thread = None
        self._playback_thread = None
        self._reader_task = None
        self._accept_task = None
        self._prewarm = None

        self.jitter = JitterBuffer()
        self.latency = LatencyTracker()
        self._call_t0 = time.monotonic()   # frame-timestamp origin
        self._muted = False
        self._running = False
        self._closing = False
        self.on_stream_lost = None
        self._loss_signalled = False
        self.debug_binding = False

        self.stats = {"sent": 0, "recv": 0, "dropped": 0, "late": 0,
                      "oversize": 0, "backpressure": 0, "auth_fail": 0,
                      "replay": 0, "resync": 0, "fec_recovered": 0,
                      "stale": 0, "foreign": 0}

    # -- state machine ----------------------------------------------------

    def transition(self, new_state: str) -> None:
        """Move to a new state or raise.  ENDED is absorbing."""
        with self._state_lock:
            current = self.state
            if new_state == current:
                return
            if new_state not in CallState.ALLOWED.get(current, set()):
                raise IllegalTransition(
                    "illegal call transition %s -> %s" % (current, new_state))
            self.state = new_state

    def try_transition(self, new_state: str) -> bool:
        """Transition if legal.  For async callbacks that may race teardown."""
        try:
            self.transition(new_state)
            return True
        except IllegalTransition:
            return False

    @property
    def is_live(self) -> bool:
        return self.state in CallState.LIVE

    @property
    def is_ended(self) -> bool:
        return self.state in (CallState.ENDING, CallState.ENDED)

    # -- key agreement ----------------------------------------------------

    def _transcript(self, epoch: int, initiator_pub: bytes,
                    responder_pub: bytes, mlkem_ek: bytes,
                    mlkem_ct: bytes) -> bytes:
        otr_binding, local_fp, remote_fp = self.otr_material
        return build_transcript(self.call_id, otr_binding, local_fp, remote_fp,
                                initiator_pub, responder_pub, mlkem_ek,
                                mlkem_ct, epoch)

    def responder_derive(self, peer_x448_pub: bytes, peer_mlkem_ek: bytes):
        """Responder: complete the hybrid exchange for epoch 0.

        Returns (our_confirm, peer_confirm_expected, mlkem_ct).
        """
        if self.is_initiator:
            raise RuntimeError("responder_derive called on the initiator")
        if self.schedule.ready:
            raise RuntimeError("media keys already derived")

        x_ss, kem_ss, mlkem_ct = self.kex.responder_agree(
            peer_x448_pub, peer_mlkem_ek)
        try:
            transcript = self._transcript(0, peer_x448_pub, self.kex.public,
                                          peer_mlkem_ek, mlkem_ct)
            self._debug_transcript(x_ss, kem_ss, transcript)
            root = derive_voice_root(x_ss, kem_ss, transcript)
        finally:
            _wipe(x_ss)
            _wipe(kem_ss)
            self.kex.destroy()

        try:
            confirm_i, confirm_r = self.schedule.install_initial(root)
        finally:
            _wipe(root)

        self._mlkem_ct = mlkem_ct
        self._peer_x448 = peer_x448_pub
        self._peer_mlkem_ek = peer_mlkem_ek
        self.our_confirm = confirm_r
        self.peer_confirm_expected = confirm_i
        return confirm_r, confirm_i, mlkem_ct

    def initiator_derive(self, peer_x448_pub: bytes, mlkem_ct: bytes):
        """Initiator: complete the hybrid exchange for epoch 0.

        Returns (our_confirm, peer_confirm_expected).
        """
        if not self.is_initiator:
            raise RuntimeError("initiator_derive called on the responder")
        if self.schedule.ready:
            raise RuntimeError("media keys already derived")

        x_ss, kem_ss = self.kex.initiator_agree(peer_x448_pub, mlkem_ct)
        try:
            transcript = self._transcript(0, self.kex.public, peer_x448_pub,
                                          self.kex.mlkem_ek, mlkem_ct)
            self._debug_transcript(x_ss, kem_ss, transcript)
            root = derive_voice_root(x_ss, kem_ss, transcript)
        finally:
            _wipe(x_ss)
            _wipe(kem_ss)
            self.kex.destroy()

        try:
            confirm_i, confirm_r = self.schedule.install_initial(root)
        finally:
            _wipe(root)

        self._mlkem_ct = mlkem_ct
        self._peer_x448 = peer_x448_pub
        self.our_confirm = confirm_i
        self.peer_confirm_expected = confirm_r
        return confirm_i, confirm_r

    def verify_peer_confirm(self, peer_confirm: bytes) -> bool:
        """Constant-time check of the peer's epoch-0 confirmation tag."""
        if self.peer_confirm_expected is None:
            return False
        return hmac.compare_digest(bytes(peer_confirm or b""),
                                   self.peer_confirm_expected)

    def mark_keys_confirmed(self) -> None:
        try:
            self.loop.call_soon_threadsafe(self.keys_confirmed.set)
        except Exception:
            self.keys_confirmed.set()

    def _debug_transcript(self, x_ss, kem_ss, transcript) -> None:
        """Digests only, never raw secrets.

        Comparing these five lines across the two devices names precisely
        which input differs when a confirmation mismatch occurs — that is the
        whole diagnosis, and it costs nothing.
        """
        if not self.debug_binding:
            return

        def d(label, value):
            raw = value if isinstance(value, (bytes, bytearray)) \
                else str(value).encode()
            return "%s=%s" % (label, hashlib.sha256(bytes(raw)).hexdigest()[:12])

        _print("[voice-bind] role=%s %s %s %s %s"
               % (self.role, d("x448", x_ss), d("mlkem", kem_ss),
                  d("transcript", transcript), d("callid", self.call_id)))

    # -- rekey ------------------------------------------------------------

    def begin_rekey_initiator(self):
        """Initiator: fresh ephemerals for epoch+1.  Returns (epoch, kex)."""
        epoch = self.schedule.epoch + 1
        kex = VoiceKeyExchange(True)
        self._rekey_kex = kex
        return epoch, kex

    def rekey_responder(self, epoch: int, peer_x448_pub: bytes,
                        peer_mlkem_ek: bytes):
        """Responder: derive the pending epoch and return (our_confirm, ct).

        Nothing is committed here.  The current epoch keeps encrypting and
        decrypting until REKEYCOMMIT verifies.
        """
        kex = VoiceKeyExchange(False)
        try:
            x_ss, kem_ss, mlkem_ct = kex.responder_agree(peer_x448_pub,
                                                         peer_mlkem_ek)
        finally:
            kex.destroy()
        try:
            transcript = self._transcript(epoch, peer_x448_pub, kex.public,
                                          peer_mlkem_ek, mlkem_ct)
            with self._key_lock:
                new_root = derive_rekey_root(self.schedule.current_root(), x_ss,
                                             kem_ss, transcript)
                try:
                    self.schedule.begin_rekey(epoch, new_root)
                finally:
                    _wipe(new_root)
                our_confirm = self.schedule.our_confirm()
        finally:
            _wipe(x_ss)
            _wipe(kem_ss)
        return our_confirm, mlkem_ct, kex.public

    def rekey_initiator_finish(self, epoch: int, peer_x448_pub: bytes,
                               mlkem_ct: bytes):
        """Initiator: derive the pending epoch from the REKEYACK.

        Returns (our_confirm, peer_confirm_expected).
        """
        kex = self._rekey_kex
        if kex is None:
            raise RuntimeError("no rekey in progress")
        try:
            x_ss, kem_ss = kex.initiator_agree(peer_x448_pub, mlkem_ct)
        finally:
            kex.destroy()
            self._rekey_kex = None
        try:
            transcript = self._transcript(epoch, kex.public, peer_x448_pub,
                                          kex.mlkem_ek, mlkem_ct)
            with self._key_lock:
                new_root = derive_rekey_root(self.schedule.current_root(), x_ss,
                                             kem_ss, transcript)
                try:
                    self.schedule.begin_rekey(epoch, new_root)
                finally:
                    _wipe(new_root)
                return (self.schedule.our_confirm(),
                        self.schedule.expected_peer_confirm())
        finally:
            _wipe(x_ss)
            _wipe(kem_ss)

    def commit_rekey(self, epoch: int, peer_confirm: bytes) -> bool:
        with self._key_lock:
            return self.schedule.commit_rekey(epoch, peer_confirm)

    def abort_rekey(self) -> None:
        with self._key_lock:
            self.schedule.abort_rekey()

    # -- SAM transport ----------------------------------------------------

    async def create_session(self) -> str:
        """Create a TRANSIENT SAM session.  Returns our base64 destination."""
        sam_open = _HOST["sam_open"]
        sam_read_line = _HOST["sam_read_line"]
        sam_parse = _HOST["sam_parse"]
        if not all((sam_open, sam_read_line, sam_parse)):
            raise RuntimeError("SAM helpers not bound — call bind_host()")

        # In datagram mode the router forwards inbound datagrams to a UDP
        # port of our choosing, so the socket has to exist -- and its port be
        # known -- before SESSION CREATE is sent.
        forward_port = 0
        if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
            try:
                forward_port = self._bind_datagram_socket()
            except Exception as exc:
                _print("[voice] datagram transport unavailable (%s); "
                       "falling back to the stream transport"
                       % _san(str(exc), 120))
                self._transport_mode = VOICE_TRANSPORT_STREAM

        def _create():
            ctrl = sam_open(self.sam_host, self.sam_port, SAM_HELLO_TIMEOUT)
            try:
                session_id = "otrv4voice_%s" % secrets.token_hex(6)
                if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
                    # STYLE=DATAGRAM is repliable: the sender's destination
                    # arrives with every packet, which gives a cheap pre-AEAD
                    # filter and lets the initiator learn the callee's
                    # destination without extra signalling. PORT/HOST ask the
                    # router to forward inbound datagrams straight to us
                    # rather than multiplexing them onto the control socket.
                    create = ("SESSION CREATE STYLE=DATAGRAM ID=%s "
                              "DESTINATION=TRANSIENT SIGNATURE_TYPE=7 "
                              "PORT=%d HOST=127.0.0.1\n"
                              % (session_id, forward_port))
                else:
                    create = ("SESSION CREATE STYLE=STREAM ID=%s "
                              "DESTINATION=TRANSIENT SIGNATURE_TYPE=7\n"
                              % session_id)
                ctrl.sendall(create.encode("ascii"))
                # i2pd builds a full tunnel set before answering, so this is
                # minutes rather than seconds on a busy phone.
                fields = sam_parse(sam_read_line(ctrl, SAM_SESSION_TIMEOUT),
                                   "SESSION STATUS ")
                dest = fields.get("DESTINATION")
                if not dest:
                    raise RuntimeError("SESSION STATUS carried no DESTINATION")
                ctrl.settimeout(None)
                return ctrl, session_id, dest
            except Exception:
                try:
                    ctrl.close()
                except Exception:
                    pass
                raise

        self._sam_control, self._sam_session_id, blob = (
            await self.loop.run_in_executor(None, _create))
        # SESSION STATUS hands back the private key blob. Nothing after this
        # point needs it -- the session is bound to the control socket, not to
        # the key -- so derive the destination and let the blob go.
        try:
            self._our_dest = i2p_public_destination(blob)
        except ValueError as exc:
            raise RuntimeError("SAM returned an unparseable DESTINATION: %s"
                               % exc)
        return self._our_dest

    # -- datagram transport ------------------------------------------------

    def _bind_datagram_socket(self) -> int:
        """Bind the UDP socket the router will forward our media to.

        Returns the port, which SESSION CREATE has to carry.  Bound to
        loopback only: this socket accepts anything the host can send it, and
        the AEAD is the only thing standing behind it, so it must not be
        reachable off the device.
        """
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", 0))
            sock.setblocking(False)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise
        self._dgram_sock = sock
        return sock.getsockname()[1]

    def _datagram_ready(self) -> bool:
        return (self._transport_mode == VOICE_TRANSPORT_DATAGRAM
                and self._dgram_transport is not None)

    async def open_datagram_endpoint(self) -> None:
        """Attach the bound UDP socket to the event loop and arm sending."""
        if self._transport_mode != VOICE_TRANSPORT_DATAGRAM:
            return
        if self._dgram_sock is None:
            raise RuntimeError("datagram socket was never bound")

        session = self

        class _MediaDatagramProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                session._on_datagram(data)

            def error_received(self, exc):
                # ICMP port-unreachable from the SAM bridge arrives here.  It
                # is per-packet and recoverable, so it must not tear the call
                # down; the stats already show the result as silence.
                session.stats["dropped"] += 1

        transport, _proto = await self.loop.create_datagram_endpoint(
            _MediaDatagramProtocol, sock=self._dgram_sock)
        self._dgram_transport = transport
        self._dgram_send_addr = (self.sam_host, sam_udp_port())
        self._refresh_datagram_header()

    def _refresh_datagram_header(self) -> None:
        """Cache the SAM send header once the peer destination is known."""
        if self._sam_session_id and self._peer_dest:
            self._dgram_send_header = build_datagram_send_header(
                self._sam_session_id, self._peer_dest)
        else:
            self._dgram_send_header = None

    def _on_datagram(self, data: bytes) -> None:
        """One forwarded SAM datagram -> AEAD -> jitter buffer.

        A datagram boundary is a frame boundary, so unlike the stream path
        there is no reassembly and no resynchronisation across packets: a
        corrupt datagram costs exactly itself.
        """
        if not self._running:
            return
        source, payload = split_datagram_receive(data)
        if not payload:
            return
        # Cheap pre-AEAD filter.  Not a security boundary -- the AEAD is --
        # but it keeps an unrelated sender from reaching the cipher at all.
        #
        # Counted separately from "dropped". When this filter was comparing a
        # destination against a private key blob it discarded every packet of
        # the call, and folded into the general drop counter that was
        # indistinguishable from a path losing frames.
        if (source is not None and self._peer_dest
                and source != self._peer_dest):
            self.stats["foreign"] += 1
            if not self._foreign_warned:
                self._foreign_warned = True
                _print("[voice] media datagrams are arriving from a "
                       "destination other than the peer's and are being "
                       "discarded — if the call is silent, the two sides "
                       "disagree about the peer's destination")
            return
        before = self.stats["recv"]
        buf = bytearray(payload)
        try:
            self._drain_buffer(buf)
        except Exception:
            self.stats["dropped"] += 1
        finally:
            _wipe(buf)
        # The initiator never learns the callee's destination from signalling:
        # it published one and waited to be connected to.  Latching it from
        # the first datagram that actually authenticates is safe -- an
        # attacker cannot produce one -- and saves a signalling round trip.
        if (source is not None and self._peer_dest is None
                and self.stats["recv"] > before):
            self._peer_dest = source
            self._refresh_datagram_header()

    def _send_datagram(self, packet: bytes) -> bool:
        """Send one media packet through the SAM UDP bridge."""
        header = self._dgram_send_header
        if header is None or self._dgram_transport is None:
            return False
        try:
            self._dgram_transport.sendto(header + packet,
                                         self._dgram_send_addr)
            return True
        except Exception:
            return False

    async def accept_media_stream(self) -> None:
        """Park in STREAM ACCEPT until the peer connects (initiator role)."""
        if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
            # Nothing to accept: datagrams need no connection.  The initiator
            # cannot send until the callee's first packet arrives and
            # _on_datagram latches its destination, which happens within one
            # frame of the callee starting audio.
            await self.open_datagram_endpoint()
            return
        sam_open = _HOST["sam_open"]
        sam_read_line = _HOST["sam_read_line"]
        sam_parse = _HOST["sam_parse"]

        def _accept():
            sock = sam_open(self.sam_host, self.sam_port, SAM_HELLO_TIMEOUT)
            # Published before blocking: cancelling the future does NOT
            # interrupt an executor thread parked in recv().  Closing the
            # socket from outside is the only thing that releases it, so the
            # handle must be reachable while the thread is blocked.
            self._accept_sock = sock
            try:
                sock.sendall(("STREAM ACCEPT ID=%s SILENT=false\n"
                              % self._sam_session_id).encode("ascii"))
                # Line 1: accept registered.
                sam_parse(sam_read_line(sock, SAM_SESSION_TIMEOUT),
                          "STREAM STATUS ")
                # Line 2: blocks until a peer connects, then carries their
                # destination.  Consuming it exactly is essential — one
                # over-read here is misparsed as audio and every subsequent
                # frame boundary is wrong.
                sam_read_line(sock, SAM_ACCEPT_TIMEOUT)
                sock.settimeout(None)
                limit_media_send_buffer(sock)
                sock.setblocking(False)
                return sock
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                self._accept_sock = None
                raise

        try:
            self._media_sock = await self.loop.run_in_executor(None, _accept)
        finally:
            self._accept_sock = None
        self._reader, self._writer = await asyncio.open_connection(
            sock=self._media_sock)

    async def connect_media_stream(self, peer_dest: str) -> None:
        """STREAM CONNECT to the initiator's destination (responder role)."""
        if not peer_dest or len(peer_dest) < 64:
            raise RuntimeError("peer destination missing or implausibly short")
        if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
            self._peer_dest = peer_dest
            await self.open_datagram_endpoint()
            return
        sam_open = _HOST["sam_open"]
        sam_read_line = _HOST["sam_read_line"]
        sam_parse = _HOST["sam_parse"]

        def _connect():
            sock = sam_open(self.sam_host, self.sam_port, SAM_CONNECT_TIMEOUT)
            try:
                sock.sendall(
                    ("STREAM CONNECT ID=%s DESTINATION=%s SILENT=false\n"
                     % (self._sam_session_id, peer_dest)).encode("ascii"))
                sam_parse(sam_read_line(sock, SAM_CONNECT_TIMEOUT),
                          "STREAM STATUS ")
                sock.settimeout(None)
                limit_media_send_buffer(sock)
                sock.setblocking(False)
                return sock
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                raise

        self._media_sock = await self.loop.run_in_executor(None, _connect)
        self._reader, self._writer = await asyncio.open_connection(
            sock=self._media_sock)

    # -- codec and audio processes ----------------------------------------

    def _build_codec(self) -> None:
        """Instantiate and tune the Opus encoder/decoder.

        Each CTL is applied individually: a libopus build lacking one must not
        prevent the others from being applied.
        """
        if not _HOST["load_opus"]():
            raise RuntimeError("opuslib unavailable")
        opus = _HOST["opus"]
        if opus is None:
            raise RuntimeError("opus module not bound")

        self._opus_enc = opus.Encoder(VOICE_SAMPLE_RATE, VOICE_CHANNELS,
                                      opus.APPLICATION_VOIP)
        self._opus_dec = opus.Decoder(VOICE_SAMPLE_RATE, VOICE_CHANNELS)

        applied, failed = [], []
        for name, value in (
            ("bitrate", VOICE_BITRATE),
            ("vbr", 0),
            ("dtx", 0),
            ("inband_fec", 1),
            ("packet_loss_perc", VOICE_LOSS_PCT),
            ("complexity", VOICE_COMPLEXITY),
            ("signal", opus.SIGNAL_VOICE),
            ("bandwidth", opus.BANDWIDTH_WIDEBAND),
        ):
            try:
                setattr(self._opus_enc, name, value)
                applied.append(name)
            except Exception:
                failed.append(name)

        # VBR and DTX are the two settings that leak conversation rhythm.  If
        # either could not be disabled the constant-rate property does not
        # hold and the user is told plainly rather than left believing in
        # protection they do not have.
        self.constant_rate = ("vbr" in applied) and ("dtx" in applied)

        _print("[voice] codec: Opus %d Hz mono, %d ms frames, %d kbit/s %s"
               % (VOICE_SAMPLE_RATE, VOICE_FRAME_MS, VOICE_BITRATE // 1000,
                  "CBR" if self.constant_rate else "VBR"))
        _print("[voice] levels: mic gain %.2f%s, speaker gain %.2f%s — "
               "OTRV4PLUS_MIC_GAIN / OTRV4PLUS_SPEAKER_GAIN to change, "
               "output is limited so neither can clip"
               % (self._mic_gain.gain,
                  " + auto" if self._mic_gain.auto else "",
                  self._speaker_gain.gain,
                  " + auto" if self._speaker_gain.auto else ""))
        if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
            _print("[voice] transport: I2P datagrams — no retransmission, so "
                   "congestion arrives as loss (concealed) rather than as "
                   "delay that accumulates.")
        else:
            _print("[voice] transport: I2P streams — reliable and ordered, so "
                   "a lost segment stalls everything behind it for one 9 s "
                   "retransmit timeout. Unset OTRV4PLUS_VOICE_TRANSPORT for "
                   "datagrams.")
        if self.constant_rate:
            _print("[voice] application-layer constant-rate shaping active — "
                   "packet size and timing carry no speech information. Call "
                   "timing, duration and tunnel behaviour remain observable.")
        else:
            _print("[voice] WARNING: could not disable VBR/DTX (%s); packet "
                   "size and timing may leak conversation rhythm"
                   % ", ".join(failed))

        try:
            self._silence_frame = bytes(self._opus_enc.encode(
                b"\x00" * VOICE_FRAME_BYTES, VOICE_FRAME_SAMPLES))
        except Exception:
            self._silence_frame = None

    def _open_audio_devices(self) -> None:
        """Open the microphone and speaker through otrv4plus_audio.

        Replaces the parec/pacat pair.  On Android this is AAudio talking
        straight to the platform audio framework: no PulseAudio, no
        module-sles-source, no ALSA, no /dev/snd, no root, and nothing
        written to disk.  PulseAudio remains selectable via
        OTRV4PLUS_AUDIO_BACKEND=pulseaudio.

        A fallback from AAudio to PulseAudio is reported, never silent.  On
        this hardware PulseAudio exposes only auto_null, so a call placed
        through it would establish keys, encrypt and transmit pure silence
        while every indicator showed a healthy call.  The user is told which
        device is actually open.
        """
        env = dict(os.environ)
        libdir = os.path.join(_HOST["termux_prefix"], "lib")
        if _HOST["is_termux"] and libdir not in env.get("LD_LIBRARY_PATH", ""):
            env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get(
                "LD_LIBRARY_PATH", "")

        self._audio_env = env
        self._capture, cap_notes = _audio.open_capture(
            which=_HOST["which"], read_exact=_HOST["pipe_read_exact"], env=env)
        try:
            # Pinned to whichever backend capture actually opened.  Letting
            # playback fall back on its own gives a one-way call: AAudio
            # capture with PulseAudio playback means the peer hears us and we
            # hear auto_null, with nothing anywhere reporting a fault.
            self._playback, play_notes = _audio.open_playback(
                preferred=self._capture.name,
                which=_HOST["which"], write_all=_HOST["pipe_write_all"],
                env=env)
        except Exception:
            self._capture.stop()
            self._capture = None
            raise

        for note in list(cap_notes) + list(play_notes):
            _print("[voice] %s" % _san(note, 200))

        self.audio_backend = self._capture.name
        cap = self._capture.diagnostics()
        _print("[voice] audio: %s capture %s Hz / %s ch, playback %s — "
               "PCM_16BIT%s"
               % (self.audio_backend, cap.get("device_rate"),
                  cap.get("device_channels"), self._playback.name,
                  ", resampling to %d Hz" % VOICE_SAMPLE_RATE
                  if cap.get("resampling") else ""))

    async def start_audio(self) -> None:
        """Bring the media path up.

        Refuses unless the keys have been mutually confirmed.  This is the
        single check that makes "no audio before confirmation" structural
        rather than a property of the call ordering.
        """
        if self._writer is None and not self._datagram_ready():
            raise RuntimeError("media stream not established")
        if not self.schedule.ready:
            raise RuntimeError("refusing to start audio: no media keys")
        if not self.keys_confirmed.is_set():
            raise RuntimeError("refusing to start audio: keys not confirmed "
                               "by the peer")
        if self.state != CallState.MEDIA_CONNECTING:
            raise IllegalTransition(
                "start_audio requires MEDIA_CONNECTING, state is %s"
                % self.state)

        self._build_codec()
        self._open_audio_devices()

        self._running = True
        self.transition(CallState.ACTIVE)

        self._capture_thread = threading.Thread(
            target=self._capture_worker, name="voice-capture", daemon=True)
        self._capture_thread.start()
        self._playback_thread = threading.Thread(
            target=self._playback_worker, name="voice-playback", daemon=True)
        self._playback_thread.start()
        if self._writer is not None:
            self._reader_task = asyncio.ensure_future(self._network_reader())

    # -- capture ----------------------------------------------------------

    def _seal_frame(self, padded: bytes):
        """Seal under the committed epoch, holding the key lock.

        The lock is what stops a rekey commit landing between choosing the
        epoch and sealing under it.  v2 read the cipher and the generation
        byte separately and could label a frame with one epoch while sealing
        it under another, which the peer then dropped.
        """
        with self._key_lock:
            cipher = self.schedule.cipher_for_send()
            if cipher is None:
                return None
            return cipher.seal(padded)

    def _capture_worker(self) -> None:
        """Mic -> Opus -> AEAD -> event loop.  Runs on its own thread.

        Muting RELEASES the capture device rather than reading and discarding.
        A soft mute leaves the microphone open: Android's recording indicator
        stays lit, the OS still routes audio into this process, and anything
        that compromised the process could read it. Closing the stream makes
        the mute observable at the OS level, which is the only place a mute is
        worth anything.

        Constant-rate output is preserved regardless. While muted we transmit
        the cached silence frame on the same 40 ms cadence, so packet size and
        timing are identical to speech and the mute is invisible on the wire.
        """
        capture = self._capture
        if capture is None:
            return

        next_frame = time.monotonic()
        while self._running:
            if self._muted:
                if capture is not None:
                    try:
                        capture.stop()
                    except Exception:
                        pass
                    capture = None
                    self._capture = None
                    _print("[voice] microphone RELEASED — the OS recording "
                           "indicator should go out")
                # Keep the wire cadence with the cached silence frame.
                next_frame += VOICE_FRAME_MS / 1000.0
                delay = next_frame - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                else:
                    next_frame = time.monotonic()
                if self._silence_frame is not None:
                    self._emit(pad_opus(self._silence_frame))
                continue

            if capture is None:
                # Unmuted: take the device back.
                try:
                    # Pinned to the backend the call started on. Letting the
                    # reopen fall through to PulseAudio would put the second
                    # half of the call on auto_null — transmitting silence
                    # with every indicator healthy, which is the failure mode
                    # this whole path is built to avoid.
                    capture, _notes = _audio.open_capture(
                        preferred=self.audio_backend,
                        which=_HOST["which"],
                        read_exact=_HOST["pipe_read_exact"],
                        env=self._audio_env)
                    self._capture = capture
                    next_frame = time.monotonic()
                    _print("[voice] microphone live")
                except Exception as exc:
                    self._muted = True
                    _print("[voice] could not reopen the microphone (%s) — "
                           "staying muted" % _san(str(exc), 120))
                    continue

            try:
                raw = capture.read_frame(timeout_ms=200)
            except _audio.AudioError as exc:
                if exc.code == _audio.AUDIO_DEVICE_DISCONNECTED:
                    # AAudio's ERROR_DEAD_OBJECT: route change, headset
                    # unplug, or audioserver restart.  The stream is dead and
                    # must never be re-read; end the call rather than spin.
                    self._signal_stream_lost("audio device disconnected")
                else:
                    self._signal_stream_lost("microphone error: %s" % exc.code)
                break
            except Exception:
                self._signal_stream_lost("microphone stopped")
                break

            if raw is None:
                # A timeout, not end-of-stream.  read_frame already blocked
                # inside the device for up to timeout_ms, so this loop cannot
                # busy-spin.
                continue
            if not self._running:
                break

            # Gain before Opus, not after: the encoder allocates bits by
            # what it is given, so encoding a -18 dBFS signal and amplifying
            # at the far end amplifies the coding noise with it.
            pcm = self._mic_gain.process(raw)
            opus_frame = None
            try:
                opus_frame = bytearray(
                    self._opus_enc.encode(bytes(pcm), VOICE_FRAME_SAMPLES))
                _wipe(pcm)
                padded = pad_opus(bytes(opus_frame),
                                  self.latency.call_ms(self._call_t0))
                _wipe(opus_frame)
                opus_frame = None
                if padded is None:
                    # Encoder exceeded the fixed slot.  Substitute silence
                    # rather than emit an odd-sized packet: a lost 40 ms is
                    # inaudible, a size leak is permanent.
                    self.stats["oversize"] += 1
                    if self._silence_frame is None:
                        continue
                    padded = pad_opus(
                        self._silence_frame,
                        self.latency.call_ms(self._call_t0))
                self._emit(padded)
            except Exception:
                self.stats["dropped"] += 1
            finally:
                _wipe(pcm)
                if opus_frame is not None:
                    _wipe(opus_frame)

            # Outside the try: a probe must still go out on a frame that
            # failed to encode, or a codec hiccup would also stop latency
            # measurement.
            self._maybe_ping()

    def _emit_probe(self, frame_type: int, payload: bytes) -> None:
        """Send a PING or PONG as a full-size frame.

        Padded to VOICE_PLAIN_LEN so a probe is indistinguishable from audio
        by length; only the authenticated frame_type byte differs.
        """
        if len(payload) > VOICE_PLAIN_LEN:
            return
        plain = payload + b"\x00" * (VOICE_PLAIN_LEN - len(payload))
        try:
            with self._key_lock:
                cipher = self.schedule.cipher_for_send()
                if cipher is None:
                    return
                packet = cipher.seal(plain, frame_type=frame_type)
        except Exception:
            return
        try:
            # Probes are exempt from the staleness deadline below: they are
            # rare, and a probe that waited in the queue is measuring exactly
            # the delay we want reported.
            self.loop.call_soon_threadsafe(self._write_packet, packet, None)
        except Exception:
            pass

    def _maybe_ping(self) -> None:
        """Emit a latency probe if one is due."""
        if not self.latency.due():
            return
        try:
            _pid, payload = self.latency.build_ping()
            self._emit_probe(FRAME_TYPE_PING, payload)
        except Exception:
            pass

    def _emit(self, padded) -> None:
        """Seal one padded frame and hand it to the event loop."""
        if padded is None:
            return
        try:
            packet = self._seal_frame(padded)
        except FrameError as exc:
            # Counter exhaustion is unreachable in practice (2^62 frames) but
            # it is permanent when it happens: every later frame fails the
            # same way. Counting it as a drop would present as a call that
            # silently stopped transmitting.
            if "exhausted" in str(exc):
                self._signal_stream_lost("frame counter exhausted")
                self._running = False
            else:
                self.stats["dropped"] += 1
            return
        except Exception:
            self.stats["dropped"] += 1
            return
        if packet is None:
            return
        self.loop.call_soon_threadsafe(self._write_packet, packet,
                                       time.monotonic())

    # Every queue between here and the peer's speaker has to be bounded in
    # TIME, because audio that arrives late is not late audio, it is noise.
    #
    # This one is asyncio's write buffer.  50 packets is 3 s at 60 ms — long
    # enough that a call could sound three seconds behind purely on our own
    # backlog.  8 packets is ~480 ms, which is the same order as the jitter
    # buffer's own ceiling and therefore the most that can be useful.
    _MAX_WRITE_BACKLOG = VOICE_PACKET_LEN * 8

    #: A frame still unwritten this long after capture is discarded rather
    #: than transmitted.  It bounds the queue that call_soon_threadsafe builds
    #: when the event loop is busy, independently of any socket buffer.
    _SEND_DEADLINE_S = 0.25

    def _signal_stream_lost(self, why: str) -> None:
        """Report a media failure exactly once, on the loop."""
        if self._loss_signalled or self._closing:
            return
        self._loss_signalled = True
        callback = self.on_stream_lost
        if callback is None:
            return
        try:
            self.loop.call_soon_threadsafe(callback, self.peer, self.call_id,
                                           why)
        except Exception:
            pass

    def _write_packet(self, packet: bytes, queued_at=None) -> None:
        """Write one framed packet.  Event-loop thread only.

        ``queued_at`` is the ``time.monotonic()`` reading taken when the
        capture thread handed this frame over.  A frame that has been waiting
        longer than ``_SEND_DEADLINE_S`` is dropped: transmitting it would
        push a fresher frame further behind, and it is already too late to be
        played in sequence.  Pass ``None`` to exempt a frame (probes).
        """
        if not self._running:
            return
        if self._writer is None and not self._datagram_ready():
            return
        if queued_at is not None:
            if (time.monotonic() - queued_at) > self._SEND_DEADLINE_S:
                self.stats["stale"] += 1
                return
        if self._datagram_ready():
            if self._dgram_send_header is None:
                # Initiator, still waiting to learn the callee's destination.
                # Counted rather than silently discarded so a peer that never
                # sends is visible in the stats rather than looking like loss.
                self.stats["backpressure"] += 1
                return
            if self._send_datagram(packet):
                self.stats["sent"] += 1
            else:
                self.stats["dropped"] += 1
            return
        try:
            if self._writer.is_closing():
                return
            transport = self._writer.transport
            if transport is not None:
                try:
                    if transport.get_write_buffer_size() > self._MAX_WRITE_BACKLOG:
                        self.stats["backpressure"] += 1
                        return
                except Exception:
                    pass
            self._writer.write(packet)
            self.stats["sent"] += 1
        except Exception:
            self.stats["dropped"] += 1

    # -- network ----------------------------------------------------------

    def open_packet(self, header: bytes, sealed: bytes) -> tuple:
        """Authenticate one packet against a live epoch.

        Returns (epoch, counter, plaintext).  Raises FrameError otherwise.
        Only epochs the schedule still holds are tried, and each is tried by
        its own cipher, so a frame claiming an epoch we never committed —
        or one already retired — is rejected without touching any key.
        """
        epoch, counter, length, ftype = parse_media_header(header)
        with self._key_lock:
            cipher = self.schedule.cipher_for_epoch(epoch)
            if cipher is None:
                raise FrameError("no live key for epoch %d" % epoch)
            plaintext = cipher.open(header, sealed)
        return epoch, counter, plaintext, ftype

    async def _network_reader(self) -> None:
        """Stream -> AEAD -> Opus -> jitter buffer."""
        buf = bytearray()
        try:
            while self._running:
                try:
                    chunk = await asyncio.wait_for(self._reader.read(8192),
                                                   timeout=2.0)
                except asyncio.TimeoutError:
                    continue
                except (asyncio.CancelledError, GeneratorExit):
                    raise
                except Exception:
                    break
                if not chunk:
                    break
                buf += chunk

                # Drain BEFORE bounding.  read(8192) returns up to 41 packets
                # in one go and I2P delivers in bursts, so trimming first
                # discarded every complete frame in the burst and cut the
                # survivor at an arbitrary offset — destroying byte alignment
                # and forcing the parser to hunt for sync afterwards.  That
                # showed up on a live call as dropped and resync climbing in
                # lockstep with authfail=0: nothing was failing to decrypt,
                # the frames were being shredded before they could be read.
                self._drain_buffer(buf)

                # Only unparseable residue can reach here: a drained buffer
                # holds at most one partial frame.  Anything larger is a peer
                # sending bytes that never form a frame, so this is the DoS
                # guard it was meant to be rather than a data shredder.
                if len(buf) > VOICE_PACKET_LEN * 8:
                    del buf[:]
                    self.stats["dropped"] += 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _print("[voice] media stream error: %s" % _san(str(exc), 200))
        finally:
            _wipe(buf)
        if self._running:
            self._signal_stream_lost("peer closed the media stream")

    def _drain_buffer(self, buf: bytearray) -> None:
        """Parse, authenticate and enqueue every complete frame in buf.

        Resynchronisation is authenticated, not structural: a candidate whose
        tag fails is treated as a false sync and the parser advances exactly
        one byte.  Because every genuine frame is authenticated, a false sync
        can never be mistaken for real audio, and a stray byte cannot make
        the parser swallow a plausible-looking length of valid frames.
        """
        while len(buf) >= VOICE_HDR_LEN:
            if buf[0] != VOICE_SYNC:
                idx = buf.find(bytes([VOICE_SYNC]), 1)
                if idx == -1:
                    self.stats["dropped"] += 1
                    buf.clear()
                    return
                del buf[:idx]
                self.stats["resync"] += 1
                continue

            header = bytes(buf[:VOICE_HDR_LEN])
            try:
                _, _, length, _ = parse_media_header(header)
            except FrameError:
                del buf[:1]
                self.stats["resync"] += 1
                continue
            if len(buf) < VOICE_HDR_LEN + length:
                return                       # genuine partial frame

            sealed = bytes(buf[VOICE_HDR_LEN:VOICE_HDR_LEN + length])
            opus_frame = None
            pcm = None
            try:
                epoch, counter, plaintext, ftype = self.open_packet(
                    header, sealed)
                del buf[:VOICE_HDR_LEN + length]

                if ftype == FRAME_TYPE_PING:
                    # Authenticated before we answer, so a forged PING cannot
                    # make us transmit.
                    try:
                        self._emit_probe(FRAME_TYPE_PONG,
                                         self.latency.build_pong_stamped(plaintext))
                    except Exception:
                        pass
                    continue
                if ftype == FRAME_TYPE_PONG:
                    try:
                        self.latency.handle_pong(plaintext)
                    except Exception:
                        pass
                    continue
                # Queue the Opus payload, not decoded PCM. Decoding at
                # playout is what makes Opus in-band FEC usable: recovering a
                # lost frame requires the NEXT packet, which does not exist
                # yet at receive time. It also cuts the buffer's memory by
                # 12x, since 152 bytes of Opus replaces 1920 of PCM.
                _opus, _send_ms = unpad_frame(plaintext)
                self.latency.observe_frame(_send_ms, self._call_t0)
                opus_frame = bytearray(_opus)
                if self.jitter.push(epoch, counter, opus_frame):
                    self.stats["recv"] += 1
                    opus_frame = None        # ownership passed to playback
                else:
                    self.stats["late"] += 1
            except FrameError as exc:
                text = str(exc)
                if "replay" in text:
                    self.stats["replay"] += 1
                else:
                    self.stats["auth_fail"] += 1
                self.stats["dropped"] += 1
                del buf[:1]
                self.stats["resync"] += 1
            except Exception:
                self.stats["dropped"] += 1
                del buf[:1]
            finally:
                if opus_frame is not None:
                    _wipe(opus_frame)
                if pcm is not None:
                    _wipe(pcm)

    # -- playback ---------------------------------------------------------

    def _decode(self, opus_frame, fec: bool = False):
        """Decode one Opus frame.  Returns PCM or None.

        fec=True asks Opus to extract the redundant copy of the PREVIOUS
        frame carried inside this one. That is what in-band FEC is: the
        encoder spends a few bits describing the frame before, so a single
        lost packet can be reconstructed once its successor arrives.
        """
        if self._opus_dec is None:
            return None
        try:
            if fec:
                return bytearray(self._opus_dec.decode(
                    bytes(opus_frame), VOICE_FRAME_SAMPLES, decode_fec=True))
            return bytearray(self._opus_dec.decode(bytes(opus_frame),
                                                   VOICE_FRAME_SAMPLES))
        except Exception:
            return None

    def _conceal(self, gap: int):
        """Synthesise PCM for a detected gap.

        Bounded: a large gap means the far end went away, and synthesising
        seconds of concealment audio helps nobody.
        """
        out = []
        for _ in range(min(gap, 3)):
            try:
                plc = self._opus_dec.decode(None, VOICE_FRAME_SAMPLES)
            except Exception:
                return out
            out.append(bytearray(plc))
        return out

    def _playback_worker(self) -> None:
        """Jitter buffer -> decode -> the playback device.

        A one-frame gap is repaired from the next packet's FEC copy, which is
        the common case on a lossy path and is genuinely recovered audio
        rather than synthesised. Longer gaps fall back to packet-loss
        concealment.
        """
        while self._running:
            item = self.jitter.pop()
            if item is None:
                time.sleep(VOICE_FRAME_MS / 2000.0)
                continue
            opus_frame, gap = item
            playback = self._playback
            recovered = []
            try:
                if gap == 1:
                    pcm_fec = self._decode(opus_frame, fec=True)
                    if pcm_fec is not None:
                        recovered.append(pcm_fec)
                        self.stats["fec_recovered"] += 1
                    else:
                        recovered.extend(self._conceal(gap))
                elif gap > 1:
                    recovered.extend(self._conceal(gap))

                pcm = self._decode(opus_frame)
                if pcm is not None:
                    recovered.append(pcm)

                for chunk in recovered:
                    loud = None
                    try:
                        if playback is not None:
                            loud = self._speaker_gain.process(chunk)
                            playback.write_frame(bytes(loud))
                    except _audio.AudioError as exc:
                        if exc.code == _audio.AUDIO_DEVICE_DISCONNECTED:
                            self._signal_stream_lost(
                                "audio device disconnected")
                            return
                    except Exception:
                        pass
                    finally:
                        if loud is not None:
                            _wipe(loud)
                        _wipe(chunk)
                recovered = []
            except Exception:
                pass
            finally:
                for chunk in recovered:
                    _wipe(chunk)
                _wipe(opus_frame)

    # -- control ----------------------------------------------------------

    def toggle_mute(self) -> bool:
        """Toggle the microphone.

        Muting closes the capture stream; the device is genuinely released,
        not merely ignored. Unmuting reopens it, which takes a moment on
        AAudio, so the first frame or two after unmute may be silence.
        """
        self._muted = not self._muted
        return self._muted

    def describe(self) -> str:
        with self._key_lock:
            epoch = self.schedule.epoch
            pending = self.schedule.pending_epoch
            rekeys = self.schedule.rekeys_committed
            failed = self.schedule.rekeys_failed
            cipher = self.schedule.cipher_for_send()
            ratchets = getattr(cipher, "ratchet_steps", 0)
        rate = "constant-rate" if self.constant_rate else "VARIABLE-RATE"
        transport = self._transport_mode
        audio = self.audio_backend or "-"
        return ("state=%s role=%s audio=%s %s transport=%s keys=%s epoch=%d "
                "pending=%s sent=%d "
                "recv=%d dropped=%d late=%d authfail=%d replay=%d resync=%d "
                "backpressure=%d stale=%d foreign=%d oversize=%d fec=%d "
                "jitter=%d/%d (%.0fms) %s ratchets=%d rekeys=%d/%d"
                % (self.state, self.role, audio, rate, transport,
                   "confirmed" if self.keys_confirmed.is_set() else "pending",
                   epoch, "-" if pending is None else pending,
                   self.stats["sent"], self.stats["recv"],
                   self.stats["dropped"], self.stats["late"],
                   self.stats["auth_fail"], self.stats["replay"],
                   self.stats["resync"],
                   self.stats["backpressure"], self.stats["stale"],
                   self.stats["foreign"], self.stats["oversize"],
                   self.stats["fec_recovered"],
                   self.jitter.depth(), self.jitter.target_depth,
                   self.jitter.jitter_ms, self.latency.summary(),
                   ratchets, rekeys, failed))

    # -- teardown ---------------------------------------------------------

    def force_close_sync(self) -> None:
        """Loop-independent emergency teardown.

        Runs on interpreter-shutdown paths where the loop may already be
        closed, so it awaits nothing and must survive a partially constructed
        session — if __init__ raised part-way, an AttributeError here would
        abort teardown and leave the microphone recording.
        """
        self._running = False
        self._closing = True
        self.state = CallState.ENDED       # bypasses the table by design

        for name in ("_capture", "_playback"):
            stream = getattr(self, name, None)
            if stream is None:
                continue
            try:
                stream.stop()
            except Exception:
                pass
            setattr(self, name, None)

        dgram = getattr(self, "_dgram_transport", None)
        if dgram is not None:
            try:
                dgram.close()
            except Exception:
                pass
        self._dgram_transport = None
        self._dgram_send_header = None
        # create_datagram_endpoint takes ownership of the socket and closes it
        # with the transport; closing it again here would hit an unrelated fd.
        if getattr(self, "_dgram_sock", None) is not None and dgram is None:
            try:
                self._dgram_sock.close()
            except Exception:
                pass
        self._dgram_sock = None

        release = _HOST["sam_release"]
        for name in ("_accept_sock", "_media_sock", "_sam_control"):
            sock = getattr(self, name, None)
            if sock is not None and release is not None:
                try:
                    release(sock)
                except Exception:
                    pass
            setattr(self, name, None)
        self._writer = None
        self._reader = None

        jitter = getattr(self, "jitter", None)
        if jitter is not None:
            try:
                jitter.clear()
            except Exception:
                pass

        schedule = getattr(self, "schedule", None)
        if schedule is not None:
            try:
                schedule.zeroize()
            except Exception:
                pass
        for name in ("kex", "_rekey_kex"):
            kex = getattr(self, name, None)
            if kex is not None:
                try:
                    kex.destroy()
                except Exception:
                    pass
                setattr(self, name, None)
        self.our_confirm = None
        self.peer_confirm_expected = None

    async def end(self) -> dict:
        """Tear the call down completely.  Idempotent and exception-safe.

        Order matters: the microphone is released first, then the network,
        then the keys, so nothing can still need a key that has been wiped
        and no callback can resurrect a call that has ended.
        """
        if self._closing:
            return self.stats
        self._closing = True
        self._running = False
        try:
            self.transition(CallState.ENDING)
        except IllegalTransition:
            pass

        # 1. Release the microphone before anything else.  stop() is
        #    idempotent on every backend, and for AAudio it issues
        #    requestStop + close so the AudioRecord-equivalent handle is
        #    returned to the platform rather than left held by a dead call.
        for name in ("_capture", "_playback"):
            stream = getattr(self, name, None)
            if stream is None:
                continue
            try:
                stream.stop()
            except Exception:
                pass
            setattr(self, name, None)

        # 2. Join the audio threads.
        for thread in (self._capture_thread, self._playback_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=2.0)
        self._capture_thread = None
        self._playback_thread = None

        # 3. A parked STREAM ACCEPT is blocked inside an executor thread that
        #    cancellation cannot reach; closing its socket is what releases it.
        release = _HOST["sam_release"]
        if release is not None and self._accept_sock is not None:
            try:
                release(self._accept_sock)
            except Exception:
                pass
        self._accept_sock = None

        # 4. Cancel every asyncio task this session owns.
        for name in ("_prewarm", "_reader_task", "_accept_task"):
            task = getattr(self, name, None)
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except BaseException:
                    pass
            setattr(self, name, None)

        # 5. Wipe queued PCM.
        try:
            self.jitter.clear()
        except Exception:
            pass

        # 6. Close the media transport, then the SAM session.
        if self._dgram_transport is not None:
            try:
                self._dgram_transport.close()
            except Exception:
                pass
            self._dgram_transport = None
            self._dgram_sock = None       # closed with the transport
        elif self._dgram_sock is not None:
            try:
                self._dgram_sock.close()
            except Exception:
                pass
            self._dgram_sock = None
        self._dgram_send_header = None
        if self._writer is not None:
            try:
                self._writer.close()
                await asyncio.wait_for(self._writer.wait_closed(), timeout=3)
            except Exception:
                pass
        self._writer = None
        self._reader = None
        if release is not None:
            for sock in (self._media_sock, self._sam_control):
                if sock is not None:
                    try:
                        release(sock)
                    except Exception:
                        pass
        self._media_sock = None
        self._sam_control = None

        # 7. Destroy every key last.
        try:
            self.schedule.zeroize()
        except Exception:
            pass
        for name in ("kex", "_rekey_kex"):
            kex = getattr(self, name, None)
            if kex is not None:
                try:
                    kex.destroy()
                except Exception:
                    pass
                setattr(self, name, None)
        self.our_confirm = None
        self.peer_confirm_expected = None
        self._opus_enc = None
        self._opus_dec = None

        self.state = CallState.ENDED
        return self.stats


# ---------------------------------------------------------------------------
# Signalling
# ---------------------------------------------------------------------------

CALL_PREFIX = "?OTRv4-CALL:"

# Bound so a peer cannot force megabyte allocations through the OTR channel.
# INVITE is the largest: destination (~520) + call_id (32) + X448 (112) +
# ML-KEM ek (3136) hex characters, plus separators.
MAX_SIGNAL_LEN = 8192
MAX_FIELDS = 6


class SignalError(ValueError):
    """A control message was malformed, or not for the call it claims."""


def parse_signal(body: str):
    """Split one control message into (verb, fields).

    Structural only.  Nothing here decides anything; the caller matches the
    call_id and the state before acting on any of it.
    """
    if not isinstance(body, str) or not body.startswith(CALL_PREFIX):
        raise SignalError("not a call signal")
    if len(body) > MAX_SIGNAL_LEN:
        raise SignalError("control message too long")
    remainder = body[len(CALL_PREFIX):]
    verb, _, payload = remainder.partition(":")
    verb = verb.strip().upper()
    if not verb or not verb.isalpha():
        raise SignalError("malformed verb")
    fields = [f.strip() for f in payload.split("|")] if payload else []
    if len(fields) > MAX_FIELDS:
        raise SignalError("too many fields")
    return verb, fields


def _hex_field(text: str, expect_len=None) -> bytes:
    # bytes.fromhex("") returns b"" rather than raising, so an empty
    # field would otherwise pass as valid hex.  Every call site here
    # passes expect_len, but a future one might not.
    if not text:
        raise SignalError("field is empty")
    try:
        raw = bytes.fromhex(text)
    except Exception:
        raise SignalError("field is not valid hex")
    if expect_len is not None and len(raw) != expect_len:
        raise SignalError("field must be %d bytes, got %d"
                          % (expect_len, len(raw)))
    return raw


def _epoch_field(text: str) -> int:
    try:
        epoch = int(text, 10)
    except Exception:
        raise SignalError("epoch is not an integer")
    if epoch < 0 or epoch >= VoiceKeySchedule.MAX_EPOCH:
        raise SignalError("epoch out of range")
    return epoch


class VoiceCallManager:
    """Voice-call lifecycle, signalling and policy.

    SIGNALLING
    ----------
    Control messages ride inside ordinary <message><body> stanzas with a
    distinctive prefix, always through the established OTR session.  IQ
    round-trips were deliberately avoided: over a 3-hop I2P path an IQ
    frequently exceeds slixmpp's reply timeout, whereas a <message> is
    fire-and-forget and traverses reliably.

    Every control message carries the call_id and is rejected unless it
    matches the live call.  v2 identified calls by bare JID alone, so an END
    or a REKEY from a previous call acted on the current one.

    POLICY
    ------
    A call requires an OTR session that is ENCRYPTED and cryptographically
    SMP-verified.  Verification is read only from the engine's own predicate
    — never from printed text, badge state or a set populated by matching
    substrings in log lines, which is what v2 did and which meant a peer
    could satisfy the voice gate by getting a string rendered to a panel.
    Media is never sent in the clear under any circumstance.
    """

    INVITE_TIMEOUT = SAM_SESSION_TIMEOUT + 120

    # Mirrors the module-level constant.  otrv4plus_xmpp.py reaches for
    # VoiceCallManager.CALL_PREFIX in three places to decide whether a
    # decrypted body is call signalling; v2 defined it on the class and v3
    # moved it to module scope, which turned every inbound INVITE into an
    # AttributeError inside the OTR receive path.  Both spellings resolve.
    CALL_PREFIX = CALL_PREFIX

    def __init__(self, xmpp_client, loop, sam_host="127.0.0.1", sam_port=7656):
        self.client = xmpp_client
        self.loop = loop
        self.sam_host = sam_host
        self.sam_port = sam_port
        self._calls = {}
        self._timeouts = {}
        self._stats_tasks = {}
        self._rekey_tasks = {}
        self._last_invite = {}
        self._ringers = {}
        self._control_limiter = RateLimiter(VOICE_MAX_CONTROL_PER_MIN)
        self._rekey_limiter = RateLimiter(VOICE_MAX_REKEY_PER_MIN)
        self.debug = False
        self._debug_t0 = {}

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _bare(jid: str) -> str:
        return (jid or "").split("/", 1)[0]

    def _vdbg(self, peer: str, message: str) -> None:
        if not self.debug:
            return
        elapsed = time.time() - self._debug_t0.get(peer, time.time())
        _print("[voice-dbg %6.2fs] %s: %s"
               % (elapsed, _san(peer, 40), _san(message, 200)))

    def _signal(self, peer: str, verb: str, fields=()) -> None:
        """Send one control message INSIDE the OTR channel.

        Call setup is never sent as plaintext.  An eavesdropper on the XMPP
        link — including the server operator — would otherwise learn who
        called whom and when, and would see the initiator's I2P destination.
        If OTR is unavailable the signal is dropped rather than downgraded.
        """
        payload = "|".join(str(f) for f in fields)
        body = CALL_PREFIX + verb + ((":" + payload) if payload else "")
        try:
            frame, should_send = self.client.otr.handle_outgoing_message(
                peer, body)
        except Exception as exc:
            _print("[voice] could not encrypt call signal: %s"
                   % _san(str(exc), 120))
            return
        if not (should_send and frame):
            _print("[voice] call signal dropped — OTR channel unavailable "
                   "(signalling is never sent in the clear)")
            return
        self.client.send_otr_fragmented(
            peer, frame if isinstance(frame, str) else frame.decode())

    # -- policy -----------------------------------------------------------

    def _smp_verified(self, peer: str) -> bool:
        """True only when the OTR engine cryptographically says so.

        This consults `_smp_query`, which reads the engine's published
        predicates — is_smp_verified(peer), get_smp_status(peer)["verified"],
        and the session-level is_smp_verified().  Nothing else.

        Explicitly NOT consulted, and why:
          * client._smp_reported — populated by the TUI matching substrings
            such as "SMP VERIFIED" and "IDENTITY VERIFIED" in printed lines.
            Peer-influenced text reaching a panel could insert an entry, so
            reading it here made a log string sufficient to unlock a call.
          * Name-token heuristics on the state string.  v2 treated
            "STATE_UPDATED" as success, which is a generic state-change
            notification and says nothing about the outcome.
          * Session attributes named *_complete.  SMP completes on failure
            too; completion is not verification.
        """
        query = getattr(self.client, "_smp_query_fn", None)
        try:
            if callable(query):
                verified, _ = query(self.client.otr, peer)
            else:
                verified, _ = _smp_query_default(self.client.otr, peer)
            return bool(verified)
        except Exception:
            return False

    def _smp_state_name(self, peer: str) -> str:
        query = getattr(self.client, "_smp_query_fn", None)
        try:
            if callable(query):
                return query(self.client.otr, peer)[1]
            return _smp_query_default(self.client.otr, peer)[1]
        except Exception:
            return ""

    def _explain_unverified(self, peer: str) -> None:
        name = self._smp_state_name(peer) or "unavailable"
        _print("[voice] refusing: identity of %s is not SMP-verified"
               % _san(peer, 64))
        _print("[voice] engine reports SMP state: %s" % _san(name, 60))
        _print("[voice] encryption alone proves nobody is listening, not who "
               "is on the line. Run  /smp <shared-secret>  on both sides.")

    def _otr_material(self, peer: str):
        """Collect the OTR-side inputs to the media transcript.

        Returns (otr_binding, local_fp, remote_fp) or None.

        The engine's session id is used ONLY when it can be shown to be
        shared.  It cannot be shown to be shared locally: the engine assigns
            session.session_id = session_keys.get("session_id")
                                 or secrets.token_bytes(32)
        so when the DAKE does not populate it each side invents its own
        random 32 bytes, and mixing that in guarantees the two endpoints
        derive different roots — the "media keys did not agree" failure.

        The binding therefore rests on values provably identical on both
        sides: the sorted fingerprint pair, the per-call salt, and above all
        the fresh hybrid exchange, which is where the security actually
        lives.  A fixed label stands in for the session id so the transcript
        shape is stable.
        """
        try:
            if not self.client.otr.has_encrypted_session(peer):
                return None
        except Exception:
            return None

        local_fp = normalise_fingerprint(self.client._local_fp(peer))
        remote_fp = normalise_fingerprint(self.client._remote_fp(peer))
        if (not local_fp or not remote_fp
                or "UNAVAILABLE" in (local_fp, remote_fp)):
            return None
        if local_fp == remote_fp:
            # Both fingerprints identical means we are looking at ourselves,
            # or the engine returned the same value twice.  Either way the
            # sorted pair carries no binding at all.
            return None
        return b"OTRv4+Voice/session/v3", local_fp, remote_fp

    # -- call bookkeeping -------------------------------------------------

    def _call_for(self, peer: str, call_id_hex: str):
        """Return the live session iff it matches this call_id.

        Every inbound control message goes through here.  A message whose
        call_id does not match the live call is not for this call: it is a
        replay from a previous one, a message crossing a teardown, or an
        injection, and in all three cases the right answer is to ignore it.
        """
        session = self._calls.get(peer)
        if session is None:
            return None
        try:
            call_id = _hex_field(call_id_hex, 16)
        except SignalError:
            return None
        if not hmac.compare_digest(call_id, session.call_id):
            self._vdbg(peer, "control message for a different call_id — ignored")
            return None
        if session.state == CallState.ENDED:
            return None
        return session

    def has_active_call(self, peer: str = None) -> bool:
        if peer:
            session = self._calls.get(self._bare(peer))
            return session is not None and session.is_live
        return any(s.is_live for s in self._calls.values())

    def _live_call_count(self) -> int:
        return sum(1 for s in self._calls.values() if s.is_live)

    def status_line(self) -> str:
        if not self._calls:
            return "[voice] no calls"
        return "\n".join("[voice] %s: %s" % (_san(p, 64), s.describe())
                         for p, s in self._calls.items())

    def any_active_peer(self):
        for peer, session in self._calls.items():
            if session.state != CallState.ENDED:
                return peer
        return None

    def _cancel_timeout(self, peer: str) -> None:
        handle = self._timeouts.pop(peer, None)
        if handle is not None:
            try:
                handle.cancel()
            except Exception:
                pass

    def _arm_timeout(self, peer: str, call_id: bytes) -> None:
        self._cancel_timeout(peer)

        def _expire():
            session = self._calls.get(peer)
            # Bound to the call_id: a timer armed for a previous call must
            # never terminate the one that replaced it.
            if session is None or session.call_id != call_id:
                return
            if session.state in (CallState.INVITING, CallState.RINGING,
                                 CallState.CONNECTING,
                                 CallState.KEY_CONFIRMING,
                                 CallState.MEDIA_CONNECTING):
                _print("[voice] no answer from %s — cancelling" % _san(peer, 64))
                asyncio.ensure_future(self.end_call(peer))

        self._timeouts[peer] = self.loop.call_later(self.INVITE_TIMEOUT, _expire)

    # -- outbound ---------------------------------------------------------

    async def start_call(self, peer: str) -> bool:
        """Place a call.  Initiator role: publish a destination, then accept."""
        peer = self._bare(peer)
        ok, reason = _HOST["voice_available"]()
        if not ok:
            _print("[voice] unavailable: %s" % reason)
            return False
        try:
            kem_provider()
        except KemUnavailable as exc:
            _print("[voice] unavailable: %s" % _san(str(exc), 300))
            return False
        if self._live_call_count() >= VOICE_MAX_CONCURRENT_CALLS:
            _print("[voice] already in a call")
            return False

        material = self._otr_material(peer)
        if material is None:
            _print("[voice] refusing: no usable encrypted OTR session with %s"
                   % _san(peer, 64))
            _print("[voice] run /otr first — voice is never sent unencrypted")
            return False
        if not self._smp_verified(peer):
            self._explain_unverified(peer)
            return False

        now = time.monotonic()
        last = self._last_invite.get(peer, 0.0)
        if now - last < VOICE_MIN_INVITE_INTERVAL:
            _print("[voice] slow down — one call attempt every %ds"
                   % int(VOICE_MIN_INVITE_INTERVAL))
            return False
        self._last_invite[peer] = now

        # Fresh per-call salt.  It is what stops a second call inside the
        # same OTR session from reusing the first call's key while the frame
        # counters restart at zero.  It is a salt, not a secret.
        call_id = secrets.token_bytes(16)
        self._debug_t0[peer] = time.time()
        self._vdbg(peer, "placing call, call_id=%s" % call_id.hex()[:16])

        try:
            session = VoiceCallSession(peer, self.loop, call_id, True,
                                       self.sam_host, self.sam_port)
        except Exception as exc:
            _print("[voice] could not start the key exchange: %s"
                   % _san(str(exc), 200))
            return False
        session.on_stream_lost = self._handle_stream_lost
        session.otr_material = material
        session.debug_binding = self.debug
        session.transition(CallState.INVITING)
        self._calls[peer] = session

        _print("[voice] building I2P tunnels for the call — this takes "
               "30-120 s and can be longer on a busy phone; the client is "
               "not stuck")
        try:
            our_dest = await session.create_session()
        except Exception as exc:
            _print("[voice] could not create SAM session: %s"
                   % _san(str(exc), 200))
            await self.end_call(peer, notify_peer=False)
            return False

        # Park in ACCEPT *before* the invite goes out, so the responder's
        # connect always finds a listener.  This ordering is what makes the
        # handshake deterministic; the reverse deadlocks.
        session._accept_task = asyncio.ensure_future(
            self._await_media(peer, session))

        self._signal(peer, "INVITE", (call_id.hex(), our_dest,
                                      session.kex.public.hex(),
                                      session.kex.mlkem_ek.hex()))
        self._vdbg(peer, "sent INVITE (dest %d B, x448 %d B, mlkem ek %d B)"
                   % (len(our_dest), len(session.kex.public),
                      len(session.kex.mlkem_ek)))
        self._arm_timeout(peer, call_id)
        _print("[voice] calling %s — waiting for an answer" % _san(peer, 64))
        return True

    async def _await_media(self, peer: str, session) -> None:
        """Initiator side: bring the media transport up, then start audio.

        On the stream transport this blocks in STREAM ACCEPT.  On datagrams
        there is nothing to accept, so it returns at once and the session
        simply cannot send until the callee's first packet authenticates and
        its destination is latched.  Either way the media path can come up
        before the ACCEPT has been processed, so this waits for mutual key
        confirmation before any audio starts.
        """
        try:
            await session.accept_media_stream()
        except asyncio.CancelledError:
            return
        except Exception as exc:
            _print("[voice] media stream failed: %s" % _san(str(exc), 200))
            await self.end_call(peer, notify_peer=True)
            return

        if session.is_ended:
            return

        if not session.keys_confirmed.is_set():
            self._vdbg(peer, "media stream up, waiting for key confirmation")
            try:
                await asyncio.wait_for(session.keys_confirmed.wait(),
                                       timeout=120)
            except asyncio.TimeoutError:
                _print("[voice] key confirmation never completed — ending call")
                await self.end_call(peer, notify_peer=True)
                return

        self._cancel_timeout(peer)
        if not session.try_transition(CallState.MEDIA_CONNECTING):
            return
        try:
            await session.start_audio()
        except Exception as exc:
            _print("[voice] audio failed to start: %s" % _san(str(exc), 200))
            await self.end_call(peer, notify_peer=True)
            return
        self._start_stats(peer)
        self._start_rekey(peer)
        _print("[voice] call active with %s — /hangup to end, /mute to toggle mic"
               % _san(peer, 64))

    async def answer_call(self, peer: str) -> None:
        """Responder role: derive keys, then create our session and connect."""
        peer = self._bare(peer)
        session = self._calls.get(peer)
        if session is None or session.state != CallState.RINGING:
            _print("[voice] no incoming call to answer")
            return

        # Before anything opens a playback stream, so the two never contend.
        self._stop_ringing(peer)

        if not session.try_transition(CallState.CONNECTING):
            return
        self._cancel_timeout(peer)

        try:
            our_confirm, _, mlkem_ct = session.responder_derive(
                session._peer_x448, session._peer_mlkem_ek)
        except Exception as exc:
            _print("[voice] key agreement failed: %s" % _san(str(exc), 200))
            self._signal(peer, "REJECT", (session.call_id.hex(), "bad-kex"))
            await self.end_call(peer, notify_peer=False)
            return

        session.transition(CallState.KEY_CONFIRMING)
        self._vdbg(peer, "hybrid agreed, confirm=%s" % our_confirm.hex()[:16])

        # ACCEPT carries our X448 public, the ML-KEM ciphertext, and our
        # confirmation tag, so the initiator can complete the agreement and
        # prove it matched.  We do NOT start audio yet: the initiator's
        # CONFIRM is what proves it derived the same root.
        self._signal(peer, "ACCEPT", (session.call_id.hex(),
                                      session.kex.public.hex(),
                                      mlkem_ct.hex(), our_confirm.hex()))

        # Build the tunnel while waiting for CONFIRM — it is the slow step
        # and overlapping it removes almost all of the post-answer delay.
        try:
            prewarm = session._prewarm
            if prewarm is not None:
                try:
                    await asyncio.wait_for(asyncio.shield(prewarm), timeout=150)
                except asyncio.TimeoutError:
                    pass
            if session._sam_session_id is None:
                _print("[voice] building I2P tunnel (30-120 s is normal)…")
                await session.create_session()
            else:
                self._vdbg(peer, "reusing pre-warmed SAM session")
        except Exception as exc:
            _print("[voice] call failed: %s" % _san(str(exc), 200))
            await self.end_call(peer, notify_peer=True)
            return

        try:
            await asyncio.wait_for(session.keys_confirmed.wait(), timeout=120)
        except asyncio.TimeoutError:
            _print("[voice] the caller never confirmed the keys — ending call")
            await self.end_call(peer, notify_peer=True)
            return

        if not session.try_transition(CallState.MEDIA_CONNECTING):
            return
        try:
            await session.connect_media_stream(session._peer_dest)
            await session.start_audio()
        except Exception as exc:
            _print("[voice] call failed: %s" % _san(str(exc), 200))
            await self.end_call(peer, notify_peer=True)
            return

        self._start_stats(peer)
        self._start_rekey(peer)
        _print("[voice] call active with %s — /hangup to end, /mute to toggle mic"
               % _san(peer, 64))

    # -- inbound ----------------------------------------------------------

    async def handle_signal(self, peer: str, body: str) -> None:
        peer = self._bare(peer)
        try:
            verb, fields = parse_signal(body)
        except SignalError:
            return

        # Rate-limit before doing any work.  Every verb below either allocates
        # or performs public-key operations, so an unbounded stream of them is
        # a cheap remote CPU and tunnel-exhaustion attack.
        if not self._control_limiter.allow(peer):
            self._vdbg(peer, "control message rate limit hit — dropped")
            return

        handlers = {
            "INVITE": self._on_invite,
            "ACCEPT": self._on_accept,
            "CONFIRM": self._on_confirm,
            "REJECT": self._on_reject,
            "REKEY": self._on_rekey,
            "REKEYACK": self._on_rekey_ack,
            "REKEYCOMMIT": self._on_rekey_commit,
            "END": self._on_end,
        }
        handler = handlers.get(verb)
        if handler is None:
            return
        try:
            await handler(peer, fields)
        except SignalError as exc:
            self._vdbg(peer, "malformed %s ignored: %s"
                       % (verb, _san(str(exc), 120)))
        except Exception as exc:
            self._vdbg(peer, "%s handler error: %s"
                       % (verb, _san(str(exc), 120)))

    async def _on_invite(self, peer: str, fields) -> None:
        ok, reason = _HOST["voice_available"]()
        if not ok:
            self._signal(peer, "REJECT", ("00" * 16, "unsupported"))
            _print("[voice] rejected call from %s (%s)" % (_san(peer, 64), reason))
            return
        if len(fields) != 4:
            raise SignalError("INVITE takes 4 fields")

        call_id = _hex_field(fields[0], 16)
        caller_dest = fields[1]
        caller_x448 = _hex_field(fields[2], VoiceKeyExchange.PUB_LEN)
        caller_ek = _hex_field(fields[3], MLKEM_EK_LEN)

        # Policy checks first, so a peer we will never talk to cannot make us
        # allocate a session or build a tunnel.
        material = self._otr_material(peer)
        if material is None:
            self._signal(peer, "REJECT", (call_id.hex(), "no-otr"))
            _print("[voice] rejected call from %s (no encrypted OTR session)"
                   % _san(peer, 64))
            return
        if not self._smp_verified(peer):
            self._signal(peer, "REJECT", (call_id.hex(), "unverified"))
            _print("[voice] rejected call from %s — identity not SMP-verified"
                   % _san(peer, 64))
            return
        try:
            kem_provider()
        except KemUnavailable:
            self._signal(peer, "REJECT", (call_id.hex(), "no-pq"))
            _print("[voice] rejected call from %s — no ML-KEM available; "
                   "voice will not fall back to X448 alone" % _san(peer, 64))
            return
        if self._live_call_count() >= VOICE_MAX_CONCURRENT_CALLS:
            self._signal(peer, "REJECT", (call_id.hex(), "busy"))
            return
        if not caller_dest or len(caller_dest) < 64 or len(caller_dest) > 2048:
            self._signal(peer, "REJECT", (call_id.hex(), "bad-destination"))
            return
        # Normalise to the Destination alone. A peer running the older code
        # sends the whole SAM private key blob; the datagram source filter
        # compares against SAM's reported source, which is always the
        # destination, so the two have to be in the same form or every media
        # packet is discarded.
        try:
            caller_dest = i2p_public_destination(caller_dest)
        except ValueError as exc:
            self._vdbg(peer, "INVITE destination did not parse: %s"
                       % _san(str(exc), 120))
            self._signal(peer, "REJECT", (call_id.hex(), "bad-destination"))
            return

        now = time.monotonic()
        if now - self._last_invite.get(peer, 0.0) < VOICE_MIN_INVITE_INTERVAL:
            self._vdbg(peer, "INVITE rate limit hit — dropped")
            return
        self._last_invite[peer] = now

        try:
            session = VoiceCallSession(peer, self.loop, call_id, False,
                                       self.sam_host, self.sam_port)
        except Exception as exc:
            self._signal(peer, "REJECT", (call_id.hex(), "internal"))
            self._vdbg(peer, "could not build session: %s" % _san(str(exc), 120))
            return
        session.on_stream_lost = self._handle_stream_lost
        session.otr_material = material
        session.debug_binding = self.debug
        session._peer_dest = caller_dest
        session._peer_x448 = caller_x448
        session._peer_mlkem_ek = caller_ek
        session.transition(CallState.RINGING)

        self._debug_t0[peer] = time.time()
        self._vdbg(peer, "invite received, call_id=%s" % call_id.hex()[:16])

        # Build our SAM session now rather than on /answer: an I2P tunnel
        # takes 30-120 s, so overlapping it with the ring costs one tunnel if
        # the call is declined and removes almost all of the post-answer wait.
        session._prewarm = asyncio.ensure_future(
            self._prewarm_session(peer, session))
        self._calls[peer] = session
        self._arm_timeout(peer, call_id)

        self._start_ringing(peer)
        _print("\n[voice] incoming call from %s" % _san(peer, 64))
        _print("[voice] /answer to accept, /reject to decline\n")

    def _start_ringing(self, peer: str) -> None:
        """Ring, notify and vibrate for an incoming call."""
        self._stop_ringing(peer)
        try:
            ringer = _audio.Ringer()
            ringer.start(peer=peer, which=_HOST["which"],
                         write_all=_HOST["pipe_write_all"])
            self._ringers[peer] = ringer
        except Exception as exc:
            # Never let a ringtone failure stop a call arriving.
            self._vdbg(peer, "ringer failed: %s" % _san(str(exc), 120))

    def _stop_ringing(self, peer: str) -> None:
        """Silence the ringer.  Must run before the call opens playback."""
        ringer = self._ringers.pop(peer, None)
        if ringer is None:
            return
        try:
            ringer.stop()
        except Exception:
            pass

    async def _on_accept(self, peer: str, fields) -> None:
        if len(fields) != 4:
            raise SignalError("ACCEPT takes 4 fields")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        if not session.is_initiator or session.state != CallState.INVITING:
            self._vdbg(peer, "ACCEPT in state %s — ignored" % session.state)
            return

        peer_x448 = _hex_field(fields[1], VoiceKeyExchange.PUB_LEN)
        mlkem_ct = _hex_field(fields[2], MLKEM_CT_LEN)
        peer_confirm = _hex_field(fields[3], CONFIRM_LEN)

        try:
            our_confirm, _ = session.initiator_derive(peer_x448, mlkem_ct)
        except Exception as exc:
            _print("[voice] key agreement failed: %s" % _san(str(exc), 200))
            await self.end_call(peer)
            return

        if not session.verify_peer_confirm(peer_confirm):
            # Comparing in constant time costs nothing and avoids leaking,
            # through timing, how much of the tag matched.
            _print("[voice] ABORTING: media keys did not agree with %s."
                   % _san(peer, 64))
            _print("[voice] the OTR sessions differ or the exchange was "
                   "tampered with — no audio will be sent")
            self._signal(peer, "REJECT", (session.call_id.hex(), "key-mismatch"))
            await self.end_call(peer, notify_peer=False)
            return

        session.transition(CallState.KEY_CONFIRMING)
        self._signal(peer, "CONFIRM", (session.call_id.hex(),
                                       our_confirm.hex()))
        session.mark_keys_confirmed()
        self._vdbg(peer, "hybrid agreed and confirmed, confirm=%s"
                   % our_confirm.hex()[:16])
        _print("[voice] %s answered — keys confirmed, establishing media…"
               % _san(peer, 64))

    async def _on_confirm(self, peer: str, fields) -> None:
        """Responder side: the initiator's proof that it derived the same root."""
        if len(fields) != 2:
            raise SignalError("CONFIRM takes 2 fields")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        if session.is_initiator or session.state != CallState.KEY_CONFIRMING:
            return
        peer_confirm = _hex_field(fields[1], CONFIRM_LEN)
        if not session.verify_peer_confirm(peer_confirm):
            _print("[voice] ABORTING: the caller's key confirmation did not "
                   "match — no audio will be sent")
            await self.end_call(peer, notify_peer=True)
            return
        session.mark_keys_confirmed()
        self._vdbg(peer, "caller confirmed — media may start")

    async def _on_reject(self, peer: str, fields) -> None:
        if not fields:
            raise SignalError("REJECT takes at least 1 field")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        reason = _san(fields[1] if len(fields) > 1 else "", 40)
        explain = {
            "busy": "already on a call",
            "no-otr": "no encrypted OTR session on their side",
            "unsupported": "voice support unavailable on their device",
            "no-pq": "no ML-KEM available on their device",
            "bad-destination": "malformed invite",
            "bad-kex": "malformed key exchange",
            "key-mismatch": "media keys did not agree",
            "unverified": "your identity is not SMP-verified on their side",
            "internal": "internal error on their side",
        }.get(reason, reason or "declined")
        _print("[voice] %s declined: %s" % (_san(peer, 64), _san(explain, 64)))
        await self.end_call(peer, notify_peer=False)

    async def _on_end(self, peer: str, fields) -> None:
        if not fields:
            raise SignalError("END takes 1 field")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        await self.end_call(peer, notify_peer=False)
        _print("[voice] %s ended the call" % _san(peer, 64))

    # -- rekey ------------------------------------------------------------

    async def _initiate_rekey(self, peer: str, session) -> None:
        """Initiator: run one two-phase hybrid rekey.

        CURRENT -> PENDING -> CONFIRMED -> COMMITTED.  Nothing about the
        committed epoch changes until the responder's confirmation verifies,
        so a lost, replayed, delayed or forged REKEYACK costs one rekey and
        never the call.
        """
        if session.state != CallState.ACTIVE:
            return
        try:
            epoch, kex = session.begin_rekey_initiator()
        except Exception as exc:
            self._vdbg(peer, "rekey setup failed: %s" % _san(str(exc), 120))
            return

        waiter = self.loop.create_future()
        session._rekey_waiter = (epoch, waiter)
        self._vdbg(peer, "rekey %d: sending fresh X448 + ML-KEM" % epoch)
        self._signal(peer, "REKEY", (session.call_id.hex(), epoch,
                                     kex.public.hex(), kex.mlkem_ek.hex()))

        try:
            peer_x448, mlkem_ct, peer_confirm = await asyncio.wait_for(
                waiter, timeout=VOICE_REKEY_TIMEOUT)
        except asyncio.TimeoutError:
            # A failed rekey must never drop a working call.  The committed
            # epoch stays in force and the next attempt runs on schedule.
            self._vdbg(peer, "rekey %d timed out — continuing on epoch %d"
                       % (epoch, session.schedule.epoch))
            session._rekey_waiter = None
            session._rekey_kex = None
            session.abort_rekey()
            return
        except asyncio.CancelledError:
            session._rekey_waiter = None
            session.abort_rekey()
            raise
        finally:
            session._rekey_waiter = None

        try:
            our_confirm, expected = session.rekey_initiator_finish(
                epoch, peer_x448, mlkem_ct)
        except Exception as exc:
            self._vdbg(peer, "rekey %d derivation failed: %s"
                       % (epoch, _san(str(exc), 120)))
            session.abort_rekey()
            return

        if not hmac.compare_digest(bytes(peer_confirm), expected):
            # Discard the pending key, retain the current one, wipe the
            # temporary material.  The call continues on the old epoch.
            self._vdbg(peer, "rekey %d confirmation mismatch — pending key "
                       "discarded, call continues on epoch %d"
                       % (epoch, session.schedule.epoch))
            session.abort_rekey()
            return

        if not session.commit_rekey(epoch, peer_confirm):
            session.abort_rekey()
            return
        self._signal(peer, "REKEYCOMMIT", (session.call_id.hex(), epoch,
                                           our_confirm.hex()))
        self._vdbg(peer, "rekey %d committed" % epoch)

    async def _on_rekey(self, peer: str, fields) -> None:
        """Responder: derive the pending epoch and confirm it.  No commit yet."""
        if len(fields) != 4:
            raise SignalError("REKEY takes 4 fields")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        if session.is_initiator:
            # Only the initiator drives rekeys, so the two can never collide.
            self._vdbg(peer, "REKEY from the responder — ignored")
            return
        if session.state != CallState.ACTIVE:
            self._vdbg(peer, "REKEY in state %s — ignored" % session.state)
            return
        if not self._rekey_limiter.allow(peer):
            self._vdbg(peer, "rekey rate limit hit — dropped")
            return

        epoch = _epoch_field(fields[1])
        peer_x448 = _hex_field(fields[2], VoiceKeyExchange.PUB_LEN)
        peer_ek = _hex_field(fields[3], MLKEM_EK_LEN)

        if epoch != session.schedule.epoch + 1:
            # Old, duplicate, skipped and implausible-future epochs all land
            # here.  An unauthenticated REKEY must not be able to move the
            # epoch counter at all.
            self._vdbg(peer, "REKEY epoch %d rejected (expected %d)"
                       % (epoch, session.schedule.epoch + 1))
            return
        if session.schedule.pending_epoch is not None:
            self._vdbg(peer, "REKEY while epoch %d already pending — ignored"
                       % session.schedule.pending_epoch)
            return

        try:
            our_confirm, mlkem_ct, our_x448 = session.rekey_responder(
                epoch, peer_x448, peer_ek)
        except Exception as exc:
            self._vdbg(peer, "rekey %d rejected: %s"
                       % (epoch, _san(str(exc), 120)))
            session.abort_rekey()
            return

        self._signal(peer, "REKEYACK", (session.call_id.hex(), epoch,
                                        our_x448.hex(), mlkem_ct.hex(),
                                        our_confirm.hex()))
        self._vdbg(peer, "rekey %d derived and acknowledged (pending)" % epoch)

    async def _on_rekey_ack(self, peer: str, fields) -> None:
        if len(fields) != 5:
            raise SignalError("REKEYACK takes 5 fields")
        session = self._call_for(peer, fields[0])
        if session is None or not session.is_initiator:
            return
        waiter = getattr(session, "_rekey_waiter", None)
        if waiter is None:
            return
        epoch_expected, future = waiter
        epoch = _epoch_field(fields[1])
        if epoch != epoch_expected or future.done():
            # A REKEYACK for any other epoch — including a replay of the
            # previous one — is not an answer to the question we asked.
            self._vdbg(peer, "REKEYACK for epoch %d ignored (awaiting %d)"
                       % (epoch, epoch_expected))
            return
        peer_x448 = _hex_field(fields[2], VoiceKeyExchange.PUB_LEN)
        mlkem_ct = _hex_field(fields[3], MLKEM_CT_LEN)
        peer_confirm = _hex_field(fields[4], CONFIRM_LEN)
        future.set_result((peer_x448, mlkem_ct, peer_confirm))

    async def _on_rekey_commit(self, peer: str, fields) -> None:
        """Responder: the initiator verified our tag, so commit the epoch."""
        if len(fields) != 3:
            raise SignalError("REKEYCOMMIT takes 3 fields")
        session = self._call_for(peer, fields[0])
        if session is None or session.is_initiator:
            return
        epoch = _epoch_field(fields[1])
        peer_confirm = _hex_field(fields[2], CONFIRM_LEN)
        if session.schedule.pending_epoch != epoch:
            self._vdbg(peer, "REKEYCOMMIT for epoch %d with none pending"
                       % epoch)
            return
        if session.commit_rekey(epoch, peer_confirm):
            self._vdbg(peer, "rekey %d committed" % epoch)
        else:
            self._vdbg(peer, "rekey %d commit rejected — staying on epoch %d"
                       % (epoch, session.schedule.epoch))

    async def _rekey_loop(self, peer: str) -> None:
        """Initiator-side timer driving periodic hybrid rekeys."""
        try:
            while True:
                await asyncio.sleep(VOICE_REKEY_SECONDS)
                session = self._calls.get(peer)
                if session is None or session.state != CallState.ACTIVE:
                    return
                await self._initiate_rekey(peer, session)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            self._vdbg(peer, "rekey loop stopped: %s" % _san(str(exc), 120))

    def _start_rekey(self, peer: str) -> None:
        session = self._calls.get(peer)
        if session is None or not session.is_initiator:
            return
        task = self._rekey_tasks.get(peer)
        if task is None or task.done():
            self._rekey_tasks[peer] = asyncio.ensure_future(
                self._rekey_loop(peer))

    # -- background -------------------------------------------------------

    async def _prewarm_session(self, peer: str, session) -> None:
        try:
            await session.create_session()
            self._vdbg(peer, "SAM session pre-warmed while ringing")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._vdbg(peer, "pre-warm failed (%s), will retry on answer"
                       % _san(str(exc), 120))

    async def _stats_loop(self, peer: str) -> None:
        session = self._calls.get(peer)
        last = dict(session.stats) if session else {}
        try:
            while self.debug:
                await asyncio.sleep(5)
                session = self._calls.get(peer)
                if session is None or session.state != CallState.ACTIVE:
                    return
                cur = session.stats
                delta = {k: cur.get(k, 0) - last.get(k, 0) for k in cur}
                last = dict(cur)
                # backpressure and stale are the two counters that tell a
                # congested path apart from a lossy one: a path that is simply
                # dropping shows rx far below tx with both at zero, whereas a
                # path whose queues are full shows them climbing while rx
                # arrives in bursts. Without them in this line the two look
                # identical, which is how a 24-second send queue went
                # undiagnosed across several calls.
                self._vdbg(peer, "5s: tx=%d rx=%d drop=%d bp=%d stale=%d "
                           "foreign=%d late=%d authfail=%d replay=%d "
                           "jitter=%d/%d epoch=%d %s"
                           % (delta.get("sent", 0), delta.get("recv", 0),
                              delta.get("dropped", 0),
                              delta.get("backpressure", 0),
                              delta.get("stale", 0),
                              delta.get("foreign", 0),
                              delta.get("late", 0),
                              delta.get("auth_fail", 0), delta.get("replay", 0),
                              session.jitter.depth(), VOICE_JITTER_MAX,
                              session.schedule.epoch,
                              session.latency.summary()))
                # A call can run its whole length with rtt=- and oneway=-,
                # which says only that no probe completed -- not whether the
                # PINGs went out, whether they were answered, or whether the
                # answers timed out. Those three are already tracked; printing
                # them is what turns "no measurement" into a measurement.
                # Levels. "Hard to hear on one phone, clear on the other"
                # is a measurable statement and was left unmeasured for
                # several calls; the two devices differed by 17 dB at the
                # microphone.
                try:
                    self._vdbg(peer, "levels: %s | %s"
                               % (session._mic_gain.summary(),
                                  session._speaker_gain.summary()))
                except Exception:
                    pass
                lat = session.latency
                if lat.sent and not lat.answered:
                    self._vdbg(peer,
                               "probes: %d sent, 0 answered, %d timed out — "
                               "latency cannot be reported until one "
                               "completes" % (lat.sent, lat.timed_out))
                # 5000 // FRAME_MS, not (1000 // FRAME_MS) * 5: at 60 ms the
                # latter truncates 16.67 to 16 and reports the expectation as
                # 80 frames instead of 83.
                expect = 5000 // VOICE_FRAME_MS
                if delta.get("recv", 0) == 0:
                    self._vdbg(peer, "WARNING: no audio received in 5 s")
                elif delta.get("recv", 0) < expect // 2:
                    self._vdbg(peer, "WARNING: receiving %d/%d expected frames "
                               "— the I2P path may not sustain the bitrate"
                               % (delta.get("recv", 0), expect))
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    def _start_stats(self, peer: str) -> None:
        if not self.debug:
            return
        task = self._stats_tasks.get(peer)
        if task is None or task.done():
            self._stats_tasks[peer] = asyncio.ensure_future(
                self._stats_loop(peer))

    def _handle_stream_lost(self, peer: str, call_id: bytes, why: str) -> None:
        """Media path died by itself.

        Bound to the call_id: a callback fired by a dying session must never
        tear down the call that replaced it.
        """
        session = self._calls.get(peer)
        if session is None or session.call_id != call_id:
            return
        _print("[voice] call with %s lost: %s"
               % (_san(peer, 64), _san(why, 80)))
        asyncio.ensure_future(self.end_call(peer, notify_peer=True))

    # -- teardown ---------------------------------------------------------

    async def end_call(self, peer: str, notify_peer: bool = True) -> None:
        peer = self._bare(peer)
        self._stop_ringing(peer)
        session = self._calls.pop(peer, None)
        self._cancel_timeout(peer)
        for registry in (self._stats_tasks, self._rekey_tasks):
            task = registry.pop(peer, None)
            if task is not None and not task.done():
                task.cancel()
        if session is None:
            _print("[voice] no active call")
            return
        waiter = getattr(session, "_rekey_waiter", None)
        if waiter is not None and not waiter[1].done():
            waiter[1].cancel()
        if notify_peer:
            try:
                self._signal(peer, "END", (session.call_id.hex(),))
            except Exception:
                pass
        stats = await session.end()
        _print("[voice] call ended — sent %d, received %d, dropped %d, "
               "auth-failed %d, replayed %d; every media key zeroized"
               % (stats["sent"], stats["recv"], stats["dropped"],
                  stats["auth_fail"], stats["replay"]))

    async def reject_call(self, peer: str) -> None:
        peer = self._bare(peer)
        self._stop_ringing(peer)
        session = self._calls.pop(peer, None)
        self._cancel_timeout(peer)
        if session is None:
            _print("[voice] no incoming call to reject")
            return
        self._signal(peer, "REJECT", (session.call_id.hex(), "declined"))
        await session.end()
        _print("[voice] call rejected")

    def toggle_mute(self, peer: str) -> None:
        session = self._calls.get(self._bare(peer))
        if session is not None and session.state == CallState.ACTIVE:
            _print("[voice] microphone %s"
                   % ("MUTED" if session.toggle_mute() else "live"))
        else:
            _print("[voice] no active call")

    async def cleanup(self) -> None:
        """End every call gracefully and destroy every media key."""
        for peer in list(self._calls.keys()):
            try:
                await self.end_call(peer, notify_peer=True)
            except Exception:
                session = self._calls.pop(peer, None)
                if session is not None:
                    session.force_close_sync()

    def cleanup_sync(self) -> int:
        """Synchronous teardown for paths with no usable event loop."""
        for peer in list(self._ringers):
            self._stop_ringing(peer)
        count = 0
        for peer in list(self._calls.keys()):
            session = self._calls.pop(peer, None)
            self._cancel_timeout(peer)
            if session is None:
                continue
            try:
                session.force_close_sync()
                count += 1
            except Exception:
                pass
        return count


# ---------------------------------------------------------------------------
# SMP verification
# ---------------------------------------------------------------------------

def _smp_query_default(manager, peer):
    """Ask the OTR engine whether SMP has cryptographically verified a peer.

    Returns (verified, state_name).  The boolean is authoritative and comes
    only from the engine's published predicates.  state_name is best-effort
    and is used for display only — no decision anywhere in this module is
    taken on the strength of it.

    Earlier revisions inferred verification from the state NAME, treating
    "STATE_UPDATED" and anything containing "COMPLETE" as success.
    STATE_UPDATED is a generic state-change notification, and SMP completes
    on failure as readily as on success, so both readings could report an
    unverified — or actively failed — session as verified.
    """
    if manager is None or not peer:
        return False, ""

    verified = False
    state = ""

    try:
        if manager.is_smp_verified(peer):
            verified = True
    except Exception:
        pass

    try:
        status = manager.get_smp_status(peer)
        if isinstance(status, dict):
            if status.get("verified") is True:
                verified = True
            raw = status.get("state")
            if raw:
                state = str(getattr(raw, "name", raw)).upper().strip()
    except Exception:
        pass

    if not verified:
        try:
            session = manager.get_session(peer)
            checker = getattr(session, "is_smp_verified", None)
            if callable(checker) and checker() is True:
                verified = True
        except Exception:
            pass

    return verified, state


__all__ = [
    "bind_host", "kem_provider", "set_kem_provider_for_testing",
    "KemUnavailable", "VoiceKeyExchange", "VoiceFrameCrypto",
    "VoiceKeySchedule", "VoiceCallSession", "VoiceCallManager",
    "CallState", "IllegalTransition", "ReplayWindow", "JitterBuffer",
    "RateLimiter", "FrameError", "SignalError", "parse_signal",
    "build_transcript", "derive_voice_root", "derive_rekey_root",
    "derive_media_key", "derive_confirmations", "ratchet_key",
    "pack_media_header", "parse_media_header", "media_aad", "media_nonce",
    "pad_opus", "unpad_opus", "sorted_fingerprints", "normalise_fingerprint",
    "CALL_PREFIX", "DIR_INITIATOR", "DIR_RESPONDER",
    "VOICE_PROTOCOL_VERSION", "VOICE_HDR_LEN", "VOICE_SEALED_LEN",
    "VOICE_PACKET_LEN", "VOICE_PLAIN_LEN", "VOICE_OPUS_SLOT",
    "MLKEM_EK_LEN", "MLKEM_CT_LEN", "MLKEM_SS_LEN", "ROOT_LEN",
    "CONFIRM_LEN", "_smp_query_default",
]
