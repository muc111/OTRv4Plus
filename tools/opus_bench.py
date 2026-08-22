#!/usr/bin/env python3
"""Measure the Opus encode/decode cost in this project's exact configuration.

The question is narrow: does Opus contribute materially to the media
pipeline's latency, or is it noise against a ~1 s I2P path? A codec that
costs 2 ms per 60 ms frame is 3% of the frame budget and cannot be the
problem, however tempting it is to optimise.

Two things are measured separately, because they answer different questions:

  * **libopus** via ctypes -- what the codec itself costs.
  * **opuslib** if installed -- what the production path costs, wrapper
    included. The difference between them IS the Python wrapper overhead,
    which is Step 5's question and cannot be answered by timing either alone.

RUN THIS ON THE PHONE. Numbers from an x86 container say nothing about an
aarch64 handset under thermal load, and the handset is where the calls
happen.

    python3 tools/opus_bench.py
    python3 tools/opus_bench.py --frames 20 40 60 --complexity 0 5 8 10

No audio is captured, transmitted or written anywhere: the input is
synthetic. Nothing here touches keys, the network, or a live call.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import math
import struct
import sys
import time

# libopus constants (opus_defines.h). Spelled out rather than imported so
# this runs without opuslib.
OPUS_APPLICATION_VOIP = 2048
OPUS_SIGNAL_VOICE = 3001
OPUS_BANDWIDTH_WIDEBAND = 1103
SET_BITRATE = 4002
SET_VBR = 4006
SET_BANDWIDTH = 4008
SET_COMPLEXITY = 4010
SET_INBAND_FEC = 4012
SET_PACKET_LOSS_PERC = 4014
SET_DTX = 4016
SET_SIGNAL = 4024

SAMPLE_RATE = 16000
CHANNELS = 1


def load_libopus():
    name = ctypes.util.find_library("opus")
    for candidate in [n for n in (name, "libopus.so.0", "libopus.so",
                                  "libopus.0.dylib") if n]:
        try:
            return ctypes.CDLL(candidate)
        except OSError:
            continue
    return None


class RawOpus:
    """Minimal ctypes binding, configured exactly as _build_codec does."""

    def __init__(self, lib, bitrate, complexity, fec=1, loss_pct=5, dtx=0,
                 vbr=0):
        self.lib = lib
        err = ctypes.c_int()
        lib.opus_encoder_create.restype = ctypes.c_void_p
        lib.opus_decoder_create.restype = ctypes.c_void_p
        self.enc = lib.opus_encoder_create(SAMPLE_RATE, CHANNELS,
                                           OPUS_APPLICATION_VOIP,
                                           ctypes.byref(err))
        if err.value != 0 or not self.enc:
            raise RuntimeError("opus_encoder_create failed: %d" % err.value)
        self.dec = lib.opus_decoder_create(SAMPLE_RATE, CHANNELS,
                                           ctypes.byref(err))
        if err.value != 0 or not self.dec:
            raise RuntimeError("opus_decoder_create failed: %d" % err.value)

        # Same order and values as otrv4plus_voice._build_codec.
        for request, value in ((SET_BITRATE, bitrate),
                               (SET_VBR, vbr),
                               (SET_DTX, dtx),
                               (SET_INBAND_FEC, fec),
                               (SET_PACKET_LOSS_PERC, loss_pct),
                               (SET_COMPLEXITY, complexity),
                               (SET_SIGNAL, OPUS_SIGNAL_VOICE),
                               (SET_BANDWIDTH, OPUS_BANDWIDTH_WIDEBAND)):
            lib.opus_encoder_ctl(ctypes.c_void_p(self.enc),
                                 ctypes.c_int(request), ctypes.c_int(value))

    def encode(self, pcm: bytes, frame_samples: int, out_cap: int = 4000):
        out = (ctypes.c_ubyte * out_cap)()
        n = self.lib.opus_encode(ctypes.c_void_p(self.enc), pcm,
                                 ctypes.c_int(frame_samples), out,
                                 ctypes.c_int32(out_cap))
        if n < 0:
            raise RuntimeError("opus_encode: %d" % n)
        return bytes(bytearray(out[:n]))

    def decode(self, data: bytes, frame_samples: int, fec: int = 0):
        pcm = (ctypes.c_int16 * (frame_samples * CHANNELS))()
        n = self.lib.opus_decode(ctypes.c_void_p(self.dec), data,
                                 ctypes.c_int32(len(data) if data else 0),
                                 pcm, ctypes.c_int(frame_samples),
                                 ctypes.c_int(fec))
        if n < 0:
            raise RuntimeError("opus_decode: %d" % n)
        return bytes(bytearray(pcm))[:n * 2 * CHANNELS]


def speech_like(frame_samples: int, seed: int = 1):
    """Synthetic voiced/unvoiced alternation. Not audio, just a workload."""
    rng = _Rand(seed)
    out = []
    for i in range(frame_samples):
        voiced = (i // 400) % 2 == 0
        base = math.sin(i / 4.0) * (0.7 if voiced else 0.15)
        out.append(int(max(-32000, min(32000,
                                       9000 * base + rng.next() * 900))))
    return struct.pack("<%dh" % frame_samples, *out)


class _Rand:
    """Deterministic, so two runs are comparable."""

    def __init__(self, seed):
        self.s = seed or 1

    def next(self):
        self.s = (1103515245 * self.s + 12345) & 0x7FFFFFFF
        return (self.s / 0x7FFFFFFF) * 2.0 - 1.0


def pct(values, q):
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, min(int(round(q * (len(ordered) - 1))),
                              len(ordered) - 1))]


def stat_line(label, values, budget_ms):
    if not values:
        return "%-22s no samples" % label
    p95 = pct(values, 0.95)
    return ("%-22s n=%-5d p50=%6.3f p95=%6.3f p99=%6.3f max=%6.3f ms"
            "   (%4.1f%% of a %d ms frame)"
            % (label, len(values), pct(values, .50), p95, pct(values, .99),
               max(values), 100.0 * p95 / budget_ms, budget_ms))


def bench(codec, frame_ms, bitrate, iterations, label, wrapper):
    frame_samples = SAMPLE_RATE * frame_ms // 1000
    pcm = speech_like(frame_samples)

    enc_t, dec_t, sizes = [], [], []
    packet = None
    for _ in range(iterations):
        t0 = time.monotonic()
        packet = codec.encode(pcm, frame_samples)
        enc_t.append((time.monotonic() - t0) * 1000.0)
        sizes.append(len(packet))

        t0 = time.monotonic()
        codec.decode(packet, frame_samples)
        dec_t.append((time.monotonic() - t0) * 1000.0)

    print()
    print("  %s  %d ms @ %d bit/s  [%s]" % (label, frame_ms, bitrate, wrapper))
    print("   ", stat_line("encode", enc_t, frame_ms))
    print("   ", stat_line("decode", dec_t, frame_ms))
    print("    %-22s p50=%d B  max=%d B   -> %.1f frames/s, %.1f kbit/s payload"
          % ("packet", int(pct(sizes, .50)), max(sizes),
             1000.0 / frame_ms,
             pct(sizes, .50) * 8 * (1000.0 / frame_ms) / 1000.0))
    return {"frame_ms": frame_ms, "enc_p95": pct(enc_t, .95),
            "dec_p95": pct(dec_t, .95), "bytes": int(pct(sizes, .50))}


def bench_python_overhead(frame_samples, iterations):
    """The copies otrv4plus_voice makes around each encode/decode call.

    otrv4plus_voice.py:3263 `self._opus_enc.encode(bytes(pcm), ...)` copies the
    PCM frame; :3604/:3606 `bytearray(self._opus_dec.decode(...))` copies the
    decoded frame back. Step 5 asks whether that matters against libopus
    itself.
    """
    pcm = bytearray(speech_like(frame_samples))
    decoded = bytes(frame_samples * 2)
    copies = []
    for _ in range(iterations):
        t0 = time.monotonic()
        _a = bytes(pcm)
        _b = bytearray(decoded)
        copies.append((time.monotonic() - t0) * 1000.0)
    return copies


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--frames", type=int, nargs="+", default=[20, 40, 60],
                    help="frame durations in ms")
    ap.add_argument("--bitrate", type=int, default=24000)
    ap.add_argument("--complexity", type=int, nargs="+", default=[8],
                    help="complexity levels to sweep")
    ap.add_argument("--iterations", type=int, default=2000)
    args = ap.parse_args(argv)

    lib = load_libopus()
    have_opuslib = False
    try:
        import opuslib                                   # noqa: F401
        have_opuslib = True
    except Exception:
        pass

    print("=" * 76)
    print(" OPUS PERFORMANCE")
    print("=" * 76)
    print("  platform           %s / %s" % (sys.platform, _machine()))
    print("  libopus (ctypes)   %s" % ("yes" if lib else "NOT FOUND"))
    print("  opuslib (wrapper)  %s" % ("yes" if have_opuslib else "not installed"))
    print("  sample_rate        %d Hz" % SAMPLE_RATE)
    print("  channels           %d" % CHANNELS)
    print("  application        VOIP")
    print("  signal             VOICE")
    print("  bandwidth          WIDEBAND")
    print("  vbr                0  (constant rate; privacy requirement)")
    print("  dtx                0  (constant rate; privacy requirement)")
    print("  inband_fec         1")
    print("  iterations         %d per configuration" % args.iterations)

    if lib is None and not have_opuslib:
        print("\n  Neither libopus nor opuslib is available; nothing to measure.")
        return 1

    for complexity in args.complexity:
        print()
        print("-" * 76)
        print(" complexity %d" % complexity)
        print("-" * 76)
        for frame_ms in args.frames:
            if lib is not None:
                codec = RawOpus(lib, args.bitrate, complexity)
                bench(codec, frame_ms, args.bitrate, args.iterations,
                      "libopus", "ctypes, no wrapper")
            if have_opuslib:
                import opuslib
                enc = opuslib.Encoder(SAMPLE_RATE, CHANNELS,
                                      opuslib.APPLICATION_VOIP)
                dec = opuslib.Decoder(SAMPLE_RATE, CHANNELS)
                for name, value in (("bitrate", args.bitrate), ("vbr", 0),
                                    ("dtx", 0), ("inband_fec", 1),
                                    ("packet_loss_perc", 5),
                                    ("complexity", complexity)):
                    try:
                        setattr(enc, name, value)
                    except Exception:
                        pass

                class _Wrap:
                    def encode(self, pcm, n, out_cap=4000):
                        return enc.encode(pcm, n)

                    def decode(self, data, n, fec=0):
                        return dec.decode(data, n)

                bench(_Wrap(), frame_ms, args.bitrate, args.iterations,
                      "opuslib", "production path")

    print()
    print("-" * 76)
    print(" PYTHON COPY OVERHEAD  (otrv4plus_voice.py:3263, :3604, :3606)")
    print("-" * 76)
    for frame_ms in args.frames:
        samples = SAMPLE_RATE * frame_ms // 1000
        copies = bench_python_overhead(samples, args.iterations)
        print("   ", stat_line("bytes()+bytearray() %dms" % frame_ms,
                               copies, frame_ms))
    print()
    print("  If these are a small fraction of encode/decode above, the")
    print("  wrapper and the copies are not worth optimising, and a native")
    print("  or Rust Opus would move a number that is already noise.")
    print()
    return 0


def _machine():
    try:
        import platform
        return platform.machine()
    except Exception:
        return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
