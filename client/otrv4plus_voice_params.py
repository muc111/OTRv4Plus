# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The voice subsystem's parameters: frame geometry, codec, jitter and
protocol constants (several tunable by environment for benchmarks), the
latency colours, and the host bindings (`bind_host`).

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

import otrv4plus_audio as _audio


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    """Read an integer override, ignoring anything outside its safe range."""
    raw = os.environ.get(name, "").strip()
    if raw.isdigit():
        value = int(raw)
        if lo <= value <= hi:
            return value
    return default


def _env_ms(name: str, default_ms: int, lo: int, hi: int) -> int:
    """Read a millisecond override, ignoring anything implausible.

    Out-of-range and non-numeric values fall back to the default rather than
    raising: a typo in an environment variable must not stop a call, and a
    silently clamped value would be worse than an ignored one.
    """
    raw = os.environ.get(name, "").strip()
    if raw.isdigit():
        value = int(raw)
        if lo <= value <= hi:
            return value
    return default_ms


# -- latency colour bands --------------------------------------------------
#
# Mouth-to-ear delay is the number that decides whether a call is usable, and
# it is checked more often than anything else in the telemetry. Colouring it
# turns a reading into a verdict at a glance.
#
# These are calibrated for I2P, NOT for a telephone network, and the
# difference is the whole point.
#
# ITU-T G.114 puts one-way delay under 400 ms in the range "acceptable for
# most user applications", and until v10.28.1 those were the numbers used
# here: green under 400, amber to 800, red beyond. G.114 is a standard about
# TERRESTRIAL telephony, where propagation is nearly free and 400 ms means
# something has gone wrong. It says so itself: it carves out links with
# unavoidable long propagation -- a geostationary satellite hop is about
# 250-280 ms each way -- as outside its range and in daily use anyway.
#
# A call here crosses three I2P hops in each direction through garlic-routed
# tunnels, plus the jitter buffer that has to absorb the variance of each
# one. This project's own soak measured a median mouth-to-ear of 917 ms, and
# a live two-handset call measured 914 ms with 96.5% of its audio delivered:
# a conversation both people completed. On the old scale that call was
# reported RED, "quality was poor".
#
# That is a broken instrument, not a bad call. A scale whose own transport
# cannot reach the top band says only "this is I2P", which the user already
# knows, and it says it in the colour reserved for "something is wrong" --
# so the day something IS wrong it has no way left to tell them.
#
# So the bands are set against what this transport can actually deliver:
#
#   green  <= 1000 ms  at or near the floor of the path -- as good as I2P gets
#   amber  <= 1500 ms  noticeably worse than the floor; still a conversation,
#                      with the pauses of a satellite call
#   red     > 1500 ms  turn-taking breaks down; people start talking over
#                      each other and repeating themselves
#
# Both remain overridable, which is how a clearnet or LAN deployment gets the
# strict G.114 scale back: OTRV4PLUS_M2E_GOOD_MS=400 OTRV4PLUS_M2E_WARN_MS=800.
M2E_GOOD_MS = _env_ms("OTRV4PLUS_M2E_GOOD_MS", 1000, 50, 10000)
M2E_WARN_MS = max(M2E_GOOD_MS,
                  _env_ms("OTRV4PLUS_M2E_WARN_MS", 1500, 50, 20000))

#: The strict terrestrial scale, for anyone who wants it back.
#: Named rather than written into a comment so the docs and the tests refer
#: to one pair of numbers instead of three copies that can drift.
G114_GOOD_MS, G114_WARN_MS = 400, 800

_ANSI_GREEN = "\033[92m"
_ANSI_YELLOW = "\033[93m"
_ANSI_RED = "\033[91m"
_ANSI_RESET = "\033[0m"


def _colour_state():
    """(enabled, reason).  The reason is printed once so it is diagnosable.

    Colour is on for a terminal and off for a redirect, so a piped transcript
    does not fill with escape sequences; the session transcript strips ANSI
    itself, so it stays plain either way.

    The reason exists because this silently did the wrong thing on a real
    device: no latency colour reached the terminal for a whole call, while
    the engine's own colouring -- which does no tty check at all -- came
    through in the same log. That left nothing to look at but the absence of
    output. A decision this cheap should say what it decided.
    """
    if os.environ.get("NO_COLOR"):
        return False, "NO_COLOR is set"
    if os.environ.get("OTRV4PLUS_FORCE_COLOR"):
        return True, "OTRV4PLUS_FORCE_COLOR is set"
    try:
        import sys
        if sys.stdout.isatty():
            return True, "stdout is a terminal"
        return False, ("stdout is not a terminal — set OTRV4PLUS_FORCE_COLOR=1 "
                       "if this is a pty that does not report as one")
    except Exception as exc:
        return False, "stdout could not be inspected (%s)" % type(exc).__name__


def _colour_enabled() -> bool:
    return _colour_state()[0]


def latency_band(ms) -> str:
    """"good", "warn" or "bad" for a millisecond reading."""
    if ms is None:
        return "unknown"
    if ms <= M2E_GOOD_MS:
        return "good"
    if ms <= M2E_WARN_MS:
        return "warn"
    return "bad"


def colour_latency(ms, text=None) -> str:
    """Render a latency reading in its band's colour.

    ``text`` overrides the rendered label when the caller has already
    formatted it. An unmeasured value is never coloured -- "-" in red would
    read as a bad measurement rather than no measurement.
    """
    label = text if text is not None else (
        "-" if ms is None else "%.0fms" % ms)
    if ms is None or not _colour_enabled():
        return label
    band = latency_band(ms)
    colour = {"good": _ANSI_GREEN, "warn": _ANSI_YELLOW,
              "bad": _ANSI_RED}.get(band, "")
    if not colour:
        return label
    return "%s%s%s" % (colour, label, _ANSI_RESET)


def latency_legend() -> str:
    """The scale, and what it is a scale OF.

    Saying the numbers without saying they are I2P numbers invites the
    reading these bands exist to prevent: that 900 ms is fine in general.
    It is fine HERE, on a path with three garlic-routed hops each way, and
    it would be a fault on a LAN.
    """
    enabled, reason = _colour_state()
    return ("mouth-to-ear colour: %s good (<=%dms) %s workable (<=%dms) "
            "%s poor (>%dms) — calibrated for I2P, not for a telephone "
            "network (G.114's terrestrial scale is %d/%d) [colour %s: %s]"
            % (colour_latency(0, "green"), M2E_GOOD_MS,
               colour_latency(M2E_WARN_MS, "yellow"), M2E_WARN_MS,
               colour_latency(M2E_WARN_MS + 1, "red"), M2E_WARN_MS,
               G114_GOOD_MS, G114_WARN_MS,
               "on" if enabled else "OFF", reason))


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
# Raising this is the obvious way to improve audio quality, and the tempting
# argument is that on I2P the extra bytes are free: the router moves the media
# packet plus a 455-byte repliable-datagram header inside one ~960-byte tunnel
# message, so at 24 kbit/s the 734-byte datagram leaves 226 bytes of every
# tunnel message paid for and empty. 32 kbit/s fills 806 B at the same 16.7
# packets/s, for the same tunnel-message count.
#
# That argument is a THEORY, and there is DATA against it: a live call starved
# at 39.8 kbit/s -- 8 frames received where ~125 were expected -- which
# `tests/test_voice_frame_geometry.py` pins as a regression bound. That
# starvation happened at 25 packets/s rather than 16.7, so it may well have
# been the packet rate and not the byte rate, but "may well have been" is not
# evidence and a live call is what settles it.
#
# So the default stays where it was measured to work. To try more, set this on
# BOTH phones and watch `rx` against `tx` in --voice-debug:
#
#     OTRV4PLUS_OPUS_BITRATE=32000     806 B datagram, 46.8 kbit/s offered
#     OTRV4PLUS_OPUS_BITRATE=40000     878 B datagram, 56.4 kbit/s offered
#
# 48000 reaches 958 B, close enough to the tunnel-message limit that one
# unexpected byte of overhead fragments the datagram and doubles the messages.
# If 32000 holds up on a real path, this default and that test bound should
# move together, with the log that justifies it.
#
# WIRE FORMAT: both peers must use the same value.
VOICE_BITRATE = _env_int("OTRV4PLUS_OPUS_BITRATE", 24000, 6000, 64000)
# 8 rather than 5: the extra CPU is affordable at 16.7 frames/s on aarch64 and
# buys audible quality, which matters more here than on a low-latency path.
VOICE_COMPLEXITY = _env_int("OTRV4PLUS_OPUS_COMPLEXITY", 8, 0, 10)
# In-band FEC repairs a ONE-frame gap only; longer gaps fall through to
# concealment. The observed failure mode is multi-second starvation, which
# FEC cannot touch, so 20% of the bitrate was being spent on redundancy that
# never applied. 5% keeps single-frame repair, which does work.
VOICE_LOSS_PCT = _env_int("OTRV4PLUS_OPUS_FEC_PCT", 5, 0, 50)

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
# DERIVED from VOICE_BITRATE and VOICE_FRAME_MS, not hand-set.
#
# A hand-set literal was safe only while both were literals too. Now that
# either can be overridden for benchmarking, a fixed slot would silently
# either waste bandwidth or -- far worse -- be too small, in which case
# pad_opus returns None, the capture worker substitutes silence, and the call
# connects, reports healthy and carries no audio.
#
# Nominal bytes per frame is bitrate * ms / 8000; the 5/4 covers the VBR peak
# a build that refuses vbr=0 will produce; rounding to 8 keeps the packet
# length tidy. The import-time check below still verifies the result.
#
# WIRE FORMAT: set by VOICE_BITRATE and VOICE_FRAME_MS, so both peers must
# agree on those two.
def _derive_opus_slot(bitrate: int, frame_ms: int) -> int:
    peak = (bitrate * frame_ms // 8000) * 5 // 4
    return ((peak + 7) // 8) * 8


VOICE_OPUS_SLOT = _derive_opus_slot(VOICE_BITRATE, VOICE_FRAME_MS)
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

#: OPUS_BANDWIDTH_* by sample rate (fixed by the Opus spec, RFC 6716): the
#: widest band the rate carries. Numeric fallbacks so a codec binding that
#: names only WIDEBAND (the APK's core before rc.61) still gets the right
#: band -- the encoder CTL takes the number either way.
_OPUS_BANDWIDTH = {16000: ("BANDWIDTH_WIDEBAND", 1103),
                   24000: ("BANDWIDTH_SUPERWIDEBAND", 1104),
                   48000: ("BANDWIDTH_FULLBAND", 1105)}


def opus_bandwidth(opus) -> int:
    name, number = _OPUS_BANDWIDTH.get(VOICE_SAMPLE_RATE, ("BANDWIDTH_WIDEBAND", 1103))
    return int(getattr(opus, name, number))


def configure_encoder(enc, opus):
    """The ONE encoder configuration, for 1:1 and group calls alike.

    Constant bitrate (VOICE_BITRATE): every frame is the same size (180
    bytes at 24 kbit/s, 60 ms), fits the fixed padding slot, and says
    nothing about when someone speaks. Group calls used to create a bare
    encoder -- libopus defaults: VARIABLE rate, so frame sizes followed
    speech (measured 152-185 bytes; under the slot, but nothing guaranteed
    that), and none of the speech tuning below.

    Each CTL is applied on its own, so a build lacking one still gets the
    rest. Returns (applied, failed) names."""
    applied, failed = [], []
    for name, value in (
        ("bitrate", VOICE_BITRATE),
        ("vbr", 0),
        ("dtx", 0),
        ("inband_fec", 1),
        ("packet_loss_perc", VOICE_LOSS_PCT),
        ("complexity", VOICE_COMPLEXITY),
        ("signal", getattr(opus, "SIGNAL_VOICE", 3001)),
        ("bandwidth", opus_bandwidth(opus)),
    ):
        try:
            setattr(enc, name, value)
            applied.append(name)
        except Exception:
            failed.append(name)
    return applied, failed


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

#: What the router prepends to a repliable datagram: the sender's
#: Destination and its signature. Ed25519 (SIGNATURE_TYPE=7) is 391 + 64.
SAM_REPLIABLE_OVERHEAD = 455

#: Usable payload in one I2P tunnel message. A tunnel message is 1024 bytes;
#: the delivery instructions and checksum take the rest.
I2P_TUNNEL_MESSAGE_PAYLOAD = 960

#: What a full media datagram costs the router.
VOICE_DATAGRAM_LEN = VOICE_PACKET_LEN + SAM_REPLIABLE_OVERHEAD

if VOICE_DATAGRAM_LEN >= I2P_TUNNEL_MESSAGE_PAYLOAD:
    raise RuntimeError(
        "a media datagram is %d bytes and would be fragmented across I2P "
        "tunnel messages (payload %d). Fragmentation multiplies both the "
        "loss probability and the delivery latency, because every fragment "
        "must arrive before any of the frame can be used. Lower "
        "OTRV4PLUS_OPUS_BITRATE or OTRV4PLUS_OPUS_FRAME_MS."
        % (VOICE_DATAGRAM_LEN, I2P_TUNNEL_MESSAGE_PAYLOAD))

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
#
# Every one of these is a LOCAL playout decision. Unlike VOICE_OPUS_SLOT they
# are not wire format, so two peers may run different values safely and a
# device on a worse path can buy itself more cushion without breaking calls.
#: The depth the target can never fall below.
#:
#: 180 ms until v10.29.0, and on the measured path it WAS the target: the
#: mean-deviation estimator asked for about 1.7 frames on a p50 lateness of
#: 9 ms, so the floor decided the buffer's depth for the whole call and the
#: adaptive machinery above it never once bound.
#:
#: A hand-set floor is a guess about the worst path the client will ever run
#: on, paid on every frame of every call including the good ones. It is now
#: 120 ms, two frames, because the buffer earns depth back from evidence --
#: the lateness tail below, and a frame per underrun -- rather than being
#: insured by a constant. If that mechanism is wrong the floor is one
#: variable away from where it was: OTRV4PLUS_JITTER_MIN_MS=180.
VOICE_JITTER_PREFILL_MS = _env_ms("OTRV4PLUS_JITTER_MIN_MS", 120, 60, 1000)
VOICE_JITTER_DRIFT_HIGH_MS = _env_ms("OTRV4PLUS_JITTER_TARGET_MS", 480,
                                     120, 2000)
#: Hard cap on queued audio. Not a target -- the adaptive target and the shed
#: threshold decide steady state -- but the point past which a burst is
#: discarded outright rather than queued.
#:
#: 2000 ms before. A burst that filled it parked two seconds of stale audio
#: on top of the path's own delay, which for conversation is worse than
#: having lost it: nothing in a two-second-old frame is worth hearing.
VOICE_JITTER_MAX_MS = _env_ms("OTRV4PLUS_JITTER_MAX_MS", 1000, 240, 4000)

#: How fast the buffer returns to target after a burst.
#:
#: The shed was one frame per pop, which drains at exactly the playout rate:
#: a 30-frame burst took ~26 pops, 1.5 s, and the whole of that time was
#: spent at high latency. Observed on a live call as jitter=32/3, buf=1920ms
#: -- three times the shed threshold, for over a second. Shedding is now
#: proportional so convergence takes this long regardless of burst size.
VOICE_JITTER_DRAIN_MS = _env_ms("OTRV4PLUS_JITTER_DRAIN_MS", 400, 100, 2000)

#: Hysteresis above the target before a frame is shed.
#:
#: This used to be max(prefill, 4) FRAMES, which at 60 ms was 240 ms of pure
#: hysteresis stacked on top of a target that already carries its own slack.
#: Steady-state depth is exactly this threshold -- arrivals and playout run at
#: the same rate, so nothing else pulls the buffer down -- which made the
#: observed 840 ms floor (target pinned at 10, plus 4) the design rather than
#: an accident.
#:
#: 180 ms until v10.29.0, now 120 ms. This is the cheapest 60 ms in the
#: budget, because the shed margin does NOT protect against underruns -- the
#: target does. The margin is hysteresis above the target, and its only job
#: is to stop the shedder firing on every pop; lowering it lowers the band
#: the buffer settles in without moving the depth that guards against a
#: dropout by a single frame.
VOICE_JITTER_SHED_MARGIN_MS = _env_ms("OTRV4PLUS_JITTER_MARGIN_MS", 120,
                                      60, 1000)

#: Multiplier on the smoothed arrival deviation when sizing the target.
#:
#: RFC 3550's J is a smoothed mean absolute deviation. 3x J is roughly 3.75
#: sigma -- effectively every spike, paid for on every frame for the whole
#: call. 2x is about 2.5 sigma: a concealed frame now and then, in exchange
#: for a third less delay on every single frame. For conversation that is the
#: better side of the trade, and it is a trade rather than a free win.
VOICE_JITTER_SAFETY_FACTOR = 2.0

#: Which percentile of arrival lateness the target is sized to cover.
#:
#: RFC 3550's J -- the smoothed estimate above -- is a MEAN absolute
#: deviation, and this path is not remotely symmetric.  The v10.15.1 soak
#: measured inter-arrival spacing of p50 69 ms, p95 128 ms, p99 211 ms and
#: max 281 ms against a 60 ms expected spacing: the median frame is 9 ms
#: late, the p99 frame is 151 ms late.  The tail is sixteen times the median.
#:
#: 2xJ on that distribution asks for about two frames, so the target pinned
#: at the hand-set floor and never moved, while the frames that actually
#: empty the buffer are two and a half frames late.  The result is in the
#: soak's own counters: `underrun=27 shed=313`.  Both at once is not a buffer
#: that is too big or too small, it is a buffer that never settles.
#:
#: The distribution was already being collected -- `self.spacing` exists for
#: exactly this reason and its comment says a mean deviation "cannot
#: distinguish a steadily late path from a punctual one with a long tail,
#: and only the second is worth buffering for" -- and then only ever printed.
#: This closes that loop.
#:
#: p95 rather than p99: p99 on this path is 2.5 frames and buying it costs
#: 150 ms on every frame for the whole call, to save one dropout in a
#: hundred. p95 costs about one frame and the underrun feedback below picks
#: up whatever it misses.
VOICE_JITTER_TAIL_PCT = _env_int("OTRV4PLUS_JITTER_TAIL_PCT", 95, 50, 100)

#: How many recent arrivals the tail is measured over.
#:
#: A lifetime percentile cannot recover: one bad tunnel minute would hold the
#: buffer deep for the rest of the call, which is the failure the adaptive
#: target exists to avoid. 200 frames is about 12 s at 60 ms -- long enough
#: to contain the tail, short enough to forget a tunnel that has been
#: replaced.
VOICE_JITTER_TAIL_WINDOW = _env_int("OTRV4PLUS_JITTER_TAIL_WINDOW",
                                    200, 20, 2000)

#: Frames added to the target each time the buffer runs dry.
#:
#: An underrun is the only DIRECT evidence that the buffer was too shallow --
#: everything else is inference from arrival times. Nothing in the previous
#: design used it: the soak underran 27 times and the target was the same
#: after the 27th as before the first. A buffer that cannot learn from the
#: one measurement that matters is not adaptive, whatever it computes.
VOICE_JITTER_UNDERRUN_STEP = _env_int("OTRV4PLUS_JITTER_UNDERRUN_STEP",
                                      1, 0, 8)

#: Consecutive clean pops before one learned frame is given back.
#:
#: Asymmetric on purpose: rise fast, fall slowly. A dropout is immediate and
#: audible; the latency it costs to avoid the next one is paid quietly. 300
#: pops is about 18 s at 60 ms, so a path that has genuinely improved gets
#: its latency back within a minute, and one that is merely between hiccups
#: does not.
VOICE_JITTER_UNDERRUN_DECAY = _env_int("OTRV4PLUS_JITTER_UNDERRUN_DECAY",
                                       300, 10, 10000)


VOICE_JITTER_PREFILL = max(2, VOICE_JITTER_PREFILL_MS // VOICE_FRAME_MS)
VOICE_JITTER_MAX = max(4, VOICE_JITTER_MAX_MS // VOICE_FRAME_MS)
VOICE_JITTER_SHED_MARGIN = max(1, VOICE_JITTER_SHED_MARGIN_MS // VOICE_FRAME_MS)
# Latency ceiling. Without this the buffer keeps whatever depth a burst pushed
# it to for the rest of the call: playout is paced by the audio device, so it
# never catches up on its own. Observed at 46/50 and 27/50 on live calls —
# nearly two seconds parked on top of I2P's own delay. Shedding one 60 ms
# frame is a click; holding two seconds makes conversation impossible.
#
# OTRV4PLUS_JITTER_MAX_MS raises or lowers this ceiling at runtime. It is the
# one knob worth having: on a path whose measured jitter genuinely warrants a
# deep buffer, no amount of tuning elsewhere buys latency back, and the choice
# between a dropout and a delay belongs to whoever is on the call. The 5 s
# debug line reports the measured jitter and the target so the choice can be
# made from data.
VOICE_JITTER_DRIFT_HIGH = max(
    VOICE_JITTER_PREFILL + 1,
    _env_ms("OTRV4PLUS_JITTER_MAX_MS", VOICE_JITTER_DRIFT_HIGH_MS,
            120, VOICE_JITTER_MAX_MS) // VOICE_FRAME_MS)
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
#: How far ahead of us a peer's REKEY may be and still be accepted as a
#: catch-up rather than rejected as implausible.  At one rekey per
#: VOICE_REKEY_SECONDS this is over two hours of missed rounds, which is
#: longer than any control-plane outage that leaves the media path alive.
VOICE_REKEY_MAX_CATCHUP = 64

# -- inbound media liveness -------------------------------------------------
#
# A datagram transport has no EOF. When media moved from SAM STYLE=STREAM to
# STYLE=DATAGRAM (892ef7a) the reader task became conditional on the stream
# writer, and that task was the ONLY caller of _signal_stream_lost for the
# receive path. Datagram calls have therefore had no inbound liveness
# detection at all: a receive path that stops delivering cannot be noticed,
# because nothing is watching and nothing can fail.
#
# Observed on a 33-minute call: inbound audio AND inbound probe replies both
# stopped at t=1418s, ~15 s into a 70 s reconnect (an outlier among ten, the
# WiFi-to-mobile transition), and never resumed. The call stayed ACTIVE and
# kept transmitting for the remaining 9.5 minutes. Rekeys 11-14 committed
# normally throughout, so the peer and the control plane were healthy; only
# the media receive path was dead.
#
# Thresholds are anchored to constants that already exist rather than picked
# fresh. The check runs at the media probe cadence; the warning needs three
# consecutive probe intervals of complete silence; the call is declared dead
# at VOICE_REKEY_TIMEOUT, which is this project's existing "this is not
# coming back" horizon. At a 60 ms frame interval that is ~750 consecutive
# frames, so no plausible loss burst reaches it -- the worst measured stall
# on the old stream transport was 24 s and would not have tripped this.
VOICE_RX_CHECK_S = _env_ms("OTRV4PLUS_RX_CHECK_MS", 5000, 1000, 30000) / 1000.0
VOICE_RX_WARN_S = _env_ms("OTRV4PLUS_RX_WARN_MS", 15000, 3000, 120000) / 1000.0
VOICE_RX_DEAD_S = max(
    VOICE_RX_WARN_S,
    _env_ms("OTRV4PLUS_RX_DEAD_MS", VOICE_REKEY_TIMEOUT * 1000, 5000, 600000)
    / 1000.0)

# -- media endpoint recovery ------------------------------------------------
#
# Replacing a SAM datagram session means building new I2P tunnels, which the
# call banner already describes as "30-120 s and can be longer on a busy
# phone". The per-attempt bound is the one the call-setup path already uses
# for exactly this operation (the prewarm shield), so recovery is not given a
# budget the original connection was never given.
#
# Attempts are bounded because an unbounded retry is a tunnel-build storm on
# a device that is probably already struggling. When they are exhausted the
# call is torn down through the same path a call with no recovery would take:
# recovery can extend the deadline, never remove it.
#: How long the FIRST inbound frame of a call is allowed to take.
#:
#: The steady-state thresholds assume a path that has already carried audio,
#: and a path that has never carried any is a different question. Measured on
#: a live call: media first flowed at t=96 s, while the watchdog fired at
#: 26.6 s and spent ~70 s rebuilding an endpoint that was merely still coming
#: up. The tunnels are built before start_audio, but the peer still has to
#: learn our destination and the first datagram still has to traverse.
#:
#: 120 s is what call setup already allows the media path elsewhere -- the
#: key-confirmation wait uses it, and the call banner tells the user that
#: 30-120 s is normal -- so this is the budget the rest of the code already
#: agreed on rather than a new number.
VOICE_RX_START_GRACE_S = _env_ms("OTRV4PLUS_RX_START_GRACE_MS",
                                 120000, 5000, 600000) / 1000.0

#: Extra time to wait before replacing an endpoint while the SAM session
#: that owns it is still alive.
#:
#: Our destination is bound to the SAM session, not to the tunnels beneath
#: it. Measured on a real WiFi-to-mobile switch: inbound died instantly, the
#: watchdog fired 10.6 s later, and the diagnosis read "SAM control socket
#: open" -- the router had never dropped our session, it was rebuilding its
#: own tunnels underneath a destination that was still ours. We replaced it
#: anyway: 21.2 s to build a new session and announce it, ~20 s during which
#: our own tx fell to 0 because the transport was closed, and the peer had to
#: adopt a new address it did not need.
#:
#: So a live session earns the router a chance to finish. A dead one earns
#: nothing -- if the control socket has closed, the session is gone and only
#: a rebuild can help, so that case is unchanged and immediate.
#:
#: 30 s is the low end of the 30-120 s the call banner already quotes for a
#: tunnel build, and it is bounded: when it expires the rebuild happens
#: exactly as before, so the cost of guessing wrong is 30 s once.
VOICE_RX_SESSION_HOLD_S = _env_ms("OTRV4PLUS_RX_SESSION_HOLD_MS",
                                  30000, 0, 300000) / 1000.0

VOICE_RECOVER_ATTEMPTS = _env_int("OTRV4PLUS_RECOVER_ATTEMPTS", 2, 0, 5)
VOICE_RECOVER_TIMEOUT_S = _env_ms("OTRV4PLUS_RECOVER_TIMEOUT_MS",
                                  150000, 10000, 300000) / 1000.0
VOICE_MAX_MEDIAPATH_PER_MIN = 4

# Control-plane DoS bounds.
VOICE_MAX_CONCURRENT_CALLS = 1
VOICE_MIN_INVITE_INTERVAL = 10.0    # seconds between accepted INVITEs per peer
VOICE_MAX_CONTROL_PER_MIN = 60      # control messages accepted per peer/minute
VOICE_MAX_REKEY_PER_MIN = 6

SAM_HELLO_TIMEOUT = 30
SAM_SESSION_TIMEOUT = 300
SAM_ACCEPT_TIMEOUT = 300
SAM_CONNECT_TIMEOUT = 240
