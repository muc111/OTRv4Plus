#!/usr/bin/env python3
"""
otrv4plus_i2p.py — I2P tunnel options for SAM sessions
======================================================

What this module is for
-----------------------
Both SAM sessions this application creates -- the XMPP transport in
`otrv4+.py::I2PSAMConnection` and the media stream in
`otrv4plus_voice.py::VoiceCallSession.create_session` -- issued

    SESSION CREATE STYLE=STREAM ID=... DESTINATION=TRANSIENT SIGNATURE_TYPE=7

with no tunnel options at all. Every tunnel property was therefore whatever
the local router happened to default to, which is **not the same between
routers**: i2pd defaults to 5 inbound and 5 outbound tunnels, Java I2P to 2.
The same code on two machines was getting materially different resilience,
and neither was a decision anyone had made.

This module makes the choice explicit and states the evidence for it.

Verified, not assumed
---------------------
Option names and defaults were read from i2pd's own source rather than from
documentation or memory:

  libi2pd_client/SAM.cpp    ExtractParams() parses every key=value pair on the
                            SESSION CREATE line into a Mapping and passes the
                            whole mapping to CreateSession(), so unrecognised
                            keys reach the I2CP destination layer rather than
                            being rejected.
  libi2pd/Destination.h     option name -> default
                              inbound.length            3
                              outbound.length           3
                              inbound.quantity          5
                              outbound.quantity         5
                              inbound.lengthVariance    0
                              outbound.lengthVariance   0
                              latency.min               0
                              latency.max               0

Two things are deliberately absent:

* **inbound.backupQuantity / outbound.backupQuantity.** A Java I2P option.
  i2pd's Destination.cpp does not read it, so on the bundled router it would
  be silently ignored -- configuration that looks like resilience and is not.
* **i2p.streaming.\\* options.** i2pd's Streaming.h defines its window, RTO and
  pacing behaviour as compile-time constants and exposes no I2CP option
  strings for them. There is no supported way to ask i2pd for a smaller ACK
  delay or a different initial window through SAM. Stated here because the
  absence is a real limit on what transport tuning can achieve, not an
  oversight.

Hop count is not a latency knob
-------------------------------
`inbound.length` and `outbound.length` stay at 3. Shortening tunnels is the
single most effective latency change available and it is not on the table:
hop count is the anonymity parameter, and trading it for milliseconds would
change what the product is. They are set explicitly so that a router whose
default differs cannot quietly give a call fewer hops than intended.

What is actually being changed
------------------------------
* quantity pinned to 4 in and 4 out. Above Java I2P's default of 2, which is
  where the resilience gain is; slightly below i2pd's 5, so on the bundled
  router this is marginally *less* build overhead rather than more. Spare
  tunnels are what make an expiring tunnel a non-event instead of a stall.
* lengthVariance pinned to 0. Variance adds hops at random, so a tunnel built
  with variance 1 can be 4 hops and slower, and the call's latency then
  depends on which tunnel a message took. Pinned to 0, latency stops moving
  for that reason. It never reduces hops below `length`, so this costs no
  anonymity.

INFERRED, not measured: that 4 tunnels absorbs expiry better than 2. It
follows from tunnel expiry being staggered across a pool, but this build has
had no access to an I2P router, so no measurement supports it here.
"""

__all__ = [
    "TUNNEL_OPTION_DEFAULTS", "VOICE_TUNNEL_OPTIONS", "XMPP_TUNNEL_OPTIONS",
    "SUPPORTED_OPTIONS", "UNSUPPORTED_OPTIONS", "session_options",
    "format_options", "describe",
    "SAM_CHUNK", "SAM_RATE_BPS", "SAM_BURST_BYTES", "SamWritePacer",
    "set_nodelay",
]

import asyncio
import os
import time


#: Router defaults, read from i2pd libi2pd/Destination.h. Present so a reader
#: can see what each setting below is changing, and by how much.
TUNNEL_OPTION_DEFAULTS = {
    "inbound.length": 3,
    "outbound.length": 3,
    "inbound.quantity": 5,          # i2pd; Java I2P defaults to 2
    "outbound.quantity": 5,         # i2pd; Java I2P defaults to 2
    "inbound.lengthVariance": 0,
    "outbound.lengthVariance": 0,
    "latency.min": 0,
    "latency.max": 0,
}

#: Every option this module will emit. An option not in this set is refused
#: rather than passed through: sending a key the router does not implement is
#: indistinguishable, from the application's side, from sending one it does.
SUPPORTED_OPTIONS = frozenset(TUNNEL_OPTION_DEFAULTS)

#: Options that exist in Java I2P or in documentation but that i2pd does not
#: implement. Named so nobody adds them back believing they do something.
UNSUPPORTED_OPTIONS = {
    "inbound.backupQuantity":
        "Java I2P only; i2pd Destination.cpp never reads it",
    "outbound.backupQuantity":
        "Java I2P only; i2pd Destination.cpp never reads it",
    "i2p.streaming.initialWindowSize":
        "i2pd fixes this at compile time (Streaming.h INITIAL_WINDOW_SIZE)",
    "i2p.streaming.initialAckDelay":
        "i2pd fixes this at compile time (Streaming.h MIN_SEND_ACK_TIMEOUT)",
    "i2p.streaming.connectDelay":
        "i2pd exposes no I2CP option for it",
    "i2p.streaming.maxWindowSize":
        "i2pd fixes this at compile time (Streaming.h MAX_WINDOW_SIZE)",
}


def _profile(quantity):
    return {
        # Anonymity parameter. Explicit so a router default cannot lower it.
        "inbound.length": 3,
        "outbound.length": 3,
        # Resilience: spare tunnels so an expiry is not a stall.
        "inbound.quantity": quantity,
        "outbound.quantity": quantity,
        # Latency stability: never build a longer tunnel than asked for.
        "inbound.lengthVariance": 0,
        "outbound.lengthVariance": 0,
    }


#: The media stream. Latency and tail latency matter most here.
VOICE_TUNNEL_OPTIONS = _profile(4)

#: The XMPP transport. Carries signalling, including call INVITEs and voice
#: rekeys, both of which have deadlines. Same profile: the traffic is lighter
#: but a stall on it is just as visible.
XMPP_TUNNEL_OPTIONS = _profile(4)


def session_options(overrides=None, base=None) -> dict:
    """Merge `overrides` onto `base`, refusing anything unsupported.

    Raises ValueError rather than dropping an unknown key. A silently ignored
    tunnel option is worse than a crash: it reads as configuration that is in
    force when it is not.
    """
    merged = dict(base if base is not None else VOICE_TUNNEL_OPTIONS)
    if overrides:
        for key, value in overrides.items():
            if key in UNSUPPORTED_OPTIONS:
                raise ValueError(
                    "I2P option %r is not implemented by i2pd (%s); setting it "
                    "would look like configuration but do nothing"
                    % (key, UNSUPPORTED_OPTIONS[key]))
            if key not in SUPPORTED_OPTIONS:
                raise ValueError(
                    "unknown I2P tunnel option %r; add it to "
                    "TUNNEL_OPTION_DEFAULTS with a source reference first"
                    % (key,))
            merged[key] = value
    for key, value in merged.items():
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("I2P option %r must be an int, got %r"
                             % (key, type(value).__name__))
        if value < 0:
            raise ValueError("I2P option %r must not be negative" % (key,))
    return merged


def format_options(options) -> str:
    """Render options for the SESSION CREATE line.

    Sorted so the command is byte-identical for identical settings, which
    makes two sessions comparable in a log without exposing anything about
    either: these are tunnel parameters, not identity.
    """
    if not options:
        return ""
    return " ".join("%s=%d" % (key, options[key]) for key in sorted(options))


def describe(options) -> str:
    """A one-line human summary for the status display."""
    return "%dh x%d in / %dh x%d out, variance %d" % (
        options.get("inbound.length", 3),
        options.get("inbound.quantity", 0),
        options.get("outbound.length", 3),
        options.get("outbound.quantity", 0),
        options.get("inbound.lengthVariance", 0),
    )


def set_nodelay(sock_or_transport) -> bool:
    """Disable Nagle on a SAM-facing socket. Returns True if it took effect.

    LATENCY (audit T2). Every SAM socket in this application is a loopback TCP
    connection to the local router, and the traffic on it is small and
    periodic: 199-byte media frames every 40 ms, and short control lines.
    That is precisely the shape Nagle's algorithm was designed to coalesce --
    it holds a small segment until the previous one is acknowledged -- and
    coalescing is the wrong trade for real-time audio, where a frame held back
    to be combined with its successor is a frame delivered late.

    No socket in the transport set this. Nothing here changes what is sent,
    only when: the same bytes leave in the same order, without waiting to be
    packed with the next frame.

    Best-effort by design. A platform that refuses the option must not prevent
    a call from being placed, so the result is returned for telemetry rather
    than raised.
    """
    import socket as _socket

    sock = sock_or_transport
    if sock is None:
        return False
    # asyncio transports expose the underlying socket via get_extra_info.
    getter = getattr(sock, "get_extra_info", None)
    if getter is not None:
        sock = getter("socket") or sock
    try:
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        return True
    except (OSError, AttributeError, NameError):
        return False


# ── SAM write pacing ─────────────────────────────────────────────────────────
#
# I2P tunnels can drop a stream when a large message is written as one burst,
# so writes toward SAM are chunked and the long-run rate is capped. This is a
# token bucket rather than a fixed sleep after every chunk.
#
# LATENCY (audit T1). The previous form slept SAM_CHUNK_DELAY = 20 ms after
# every chunk unconditionally, including after the last one. A 6000-byte OTR
# fragment -- the size send_otr_fragmented emits, and the size a voice INVITE
# or a rekey reaches once an ML-KEM-1024 encapsulation is base64'd into it --
# therefore cost 6 x 20 ms = 120 ms of pure sleep. Worse, this is a single
# pump task over the one XMPP stream, so that sleep also delayed every
# unrelated stanza queued behind it: sending a chat message could push a voice
# rekey 120 ms later, and a rekey has a deadline.
#
# The token bucket preserves both protections that mattered:
#   * no single write exceeds SAM_CHUNK, and drain() still applies
#     backpressure between writes;
#   * no burst exceeds SAM_BURST_BYTES, half the observed cliff;
#   * the sustained ceiling is unchanged at 1024 B / 20 ms = 51200 B/s.
# What it removes is the fixed cost paid by traffic that was never near the
# cliff. A message inside the burst allowance now pays nothing.
#
# MEASURED (tools/transport_bench.py): 1500 B 40 ms -> 0 ms, 4096 B 80 ms ->
# 0 ms, 6000 B 120 ms -> 37 ms. Sustained rate 49.8 -> 51.0 KiB/s, i.e.
# unchanged within the granularity of the old integer-chunk model.
SAM_CHUNK = 1024              # bytes per write toward I2P (unchanged)
SAM_RATE_BPS = 51200.0        # identical long-run ceiling to the old pacing

# REGRESSION (2026-08-21). This was 4096, and that was wrong.
#
# The old code's actual guarantee was: **never more than 1024 bytes toward SAM
# without a 20 ms gap**. It was arrived at empirically against real tunnels.
# The 4096-byte burst allowance was reasoned from a comment that mentioned an
# "~8 KB cliff", on the argument that half of it must be safe -- but the cliff
# figure describes a single large write, not the amount that may be sent
# back-to-back, and no measurement here could test the difference. It was a
# guess dressed as a margin, and it was made worse by TCP_NODELAY, which was
# added in the same pass and removes the coalescing delay that used to spread
# those writes out.
#
# Reported symptom: SMP -- whose messages are large enough to fragment --
# broke on a real I2P path, with the peer dropping mid-fragment.
#
# 1024 reproduces the old spacing exactly: the first chunk goes out
# immediately, every chunk after it waits 1024/51200 = 20 ms, which is what
# the fixed sleep produced. The part of T1 that survives is the removal of the
# TRAILING sleep after the final chunk, which delayed the next stanza and
# nothing else.
#
# Override only for experiment, and only against a real tunnel:
#   OTRV4PLUS_SAM_BURST_BYTES=4096 python3 otrv4plus_xmpp.py ...
SAM_BURST_BYTES = 1024

try:
    _burst_override = int(os.environ.get("OTRV4PLUS_SAM_BURST_BYTES", "") or 0)
    if _burst_override >= SAM_CHUNK:
        SAM_BURST_BYTES = _burst_override
except ValueError:
    pass


class SamWritePacer:
    """Token bucket over the bytes written toward a SAM stream."""

    __slots__ = ("tokens", "last", "paced_writes", "paced_seconds",
                 "rate_bps", "burst_bytes", "_clock")

    def __init__(self, rate_bps=SAM_RATE_BPS, burst_bytes=SAM_BURST_BYTES,
                 clock=time.monotonic):
        self.rate_bps = float(rate_bps)
        self.burst_bytes = float(burst_bytes)
        self._clock = clock
        self.tokens = self.burst_bytes
        self.last = clock()
        self.paced_writes = 0
        self.paced_seconds = 0.0

    def delay_for(self, count):
        """Seconds this write must wait. Consumes the tokens it charges for.

        Split out from take() so the policy is testable without a running
        event loop, and so a caller can account for the delay before it is
        slept.
        """
        now = self._clock()
        self.tokens = min(self.burst_bytes,
                          self.tokens + (now - self.last) * self.rate_bps)
        self.last = now
        if self.tokens >= count:
            self.tokens -= count
            return 0.0
        wait = (count - self.tokens) / self.rate_bps
        self.tokens = 0.0
        # Charge the wait to the clock here rather than after the sleep. If
        # `last` stayed at `now`, the bucket would refill during the very
        # sleep this call is asking for and every second write would come out
        # free -- doubling the effective rate. Doing it here also makes
        # delay_for() correct for a caller that sleeps on its own.
        self.last = now + wait
        self.paced_writes += 1
        self.paced_seconds += wait
        return wait

    async def take(self, count):
        wait = self.delay_for(count)
        if wait > 0:
            await asyncio.sleep(wait)
