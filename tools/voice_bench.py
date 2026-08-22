#!/usr/bin/env python3
"""Summarise a --voice-debug call log into one comparable row.

Phase 19 of the optimisation brief asks for a repeatable comparison between
packetisation settings. The comparison has to happen on the real I2P path --
no simulation reproduces its burst behaviour -- so the measurement is a real
call and this turns its log into numbers.

Usage
-----
Capture a call on BOTH phones, at least five minutes, ideally ten to fifteen:

    OTRV4PLUS_OPUS_FRAME_MS=60 python3 otrv4plus_xmpp.py ... --voice-debug \\
        2>&1 | tee bench-A-60ms.log

Then:

    python3 tools/voice_bench.py bench-A-60ms.log
    python3 tools/voice_bench.py bench-*.log --compare

Both peers must run the same OTRV4PLUS_OPUS_FRAME_MS and
OTRV4PLUS_OPUS_BITRATE: they set the packet length, and mismatched peers
reject each other's frames.

Reads only what the log already prints. Nothing here talks to the running
client, so it cannot perturb the thing it is measuring.
"""

from __future__ import annotations

import argparse
import glob
import re
import statistics
import sys


STATS = re.compile(
    r"5s: tx=(?P<tx>\d+) rx=(?P<rx>\d+) drop=(?P<drop>\d+) bp=(?P<bp>\d+) "
    r"stale=(?P<stale>\d+) foreign=(?P<foreign>\d+) late=(?P<late>\d+) "
    r"authfail=(?P<authfail>\d+) replay=(?P<replay>\d+) "
    r"jitter=(?P<depth>\d+)/(?P<target>\d+) jit=(?P<jit>[\d.]+)ms "
    r"buf=(?P<buf>\d+)ms epoch=(?P<epoch>\d+) "
    r"rtt=(?P<rtt>[\d-]+)m?s? oneway=(?P<oneway>[\d-]+)m?s?")

SPACING = re.compile(
    r"spacing: n=\d+ p50=(?P<p50>[\d.]+) p95=(?P<p95>[\d.]+) "
    r"p99=(?P<p99>[\d.]+) max=(?P<max>[\d.]+)ms.*?"
    r"underrun=(?P<underrun>\d+) overrun=(?P<overrun>\d+) "
    r"discard=(?P<discard>\d+) bursts=(?P<bursts>\d+)")

RTTPCT = re.compile(
    r"rtt: n=\d+ p50=(?P<p50>[\d.]+) p95=(?P<p95>[\d.]+) "
    r"p99=(?P<p99>[\d.]+) max=(?P<max>[\d.]+)ms")

CODEC = re.compile(r"codec: Opus (\d+) Hz mono, (\d+) ms frames, (\d+) kbit/s (\w+)")
LEVELS = re.compile(r"levels: speaker peak (\d+)->(\d+) rms (\d+)->(\d+)")


def _num(text):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def parse(path):
    row = {"path": path, "windows": 0, "codec": None,
           "tx": 0, "rx": 0, "drop": 0, "late": 0, "authfail": 0,
           "replay": 0, "foreign": 0, "stale": 0, "bp": 0,
           "buf": [], "jit": [], "rtt": [], "oneway": [],
           "spacing_p95": [], "spacing_p99": [],
           "rtt_p95": [], "rtt_p99": [],
           "underrun": 0, "overrun": 0, "discard": 0, "bursts": 0,
           "speaker_rms": []}

    with open(path, "r", errors="replace") as handle:
        for line in handle:
            m = CODEC.search(line)
            if m and row["codec"] is None:
                row["codec"] = "%s Hz / %s ms / %s kbit/s %s" % m.groups()
                row["frame_ms"] = int(m.group(2))
                continue

            m = STATS.search(line)
            if m:
                row["windows"] += 1
                for key in ("tx", "rx", "drop", "late", "authfail",
                            "replay", "foreign", "stale", "bp"):
                    row[key] += int(m.group(key))
                row["buf"].append(float(m.group("buf")))
                row["jit"].append(float(m.group("jit")))
                for key in ("rtt", "oneway"):
                    value = _num(m.group(key))
                    if value is not None:
                        row[key].append(value)
                continue

            m = SPACING.search(line)
            if m:
                row["spacing_p95"].append(float(m.group("p95")))
                row["spacing_p99"].append(float(m.group("p99")))
                for key in ("underrun", "overrun", "discard", "bursts"):
                    row[key] = int(m.group(key))     # cumulative
                continue

            m = RTTPCT.search(line)
            if m:
                row["rtt_p95"].append(float(m.group("p95")))
                row["rtt_p99"].append(float(m.group("p99")))
                continue

            m = LEVELS.search(line)
            if m:
                row["speaker_rms"].append(float(m.group(4)))

    return row


def _pct(values, q):
    if not values:
        return None
    ordered = sorted(values)
    idx = int(round(q * (len(ordered) - 1)))
    return ordered[max(0, min(idx, len(ordered) - 1))]


def _fmt(value, unit=""):
    return "-" if value is None else "%.0f%s" % (value, unit)


def report(row):
    minutes = row["windows"] * 5 / 60.0
    print("=" * 68)
    print("%s" % row["path"])
    print("=" * 68)
    print("  codec              %s" % (row["codec"] or "unknown"))
    print("  duration           %.1f min (%d windows)"
          % (minutes, row["windows"]))
    if minutes < 5:
        print("  WARNING            under 5 minutes; the brief asks for 5 "
              "minimum, 10-15 preferred.")
        print("                     I2P tunnel behaviour over a short call "
              "is not representative.")
    print()
    print("  TRANSPORT")
    print("    tx / rx          %d / %d" % (row["tx"], row["rx"]))
    if row["tx"]:
        delivered = 100.0 * row["rx"] / row["tx"]
        print("    delivered        %.1f%%  (rx/tx; the peer's tx is not in "
              "this log, so this is indicative, not a loss rate)" % delivered)
    print("    late             %d" % row["late"])
    print("    jitter discard   %d   (shed to hold latency, not transport "
          "loss)" % row["discard"])
    print("    burst drains     %d" % row["bursts"])
    print("    underrun         %d" % row["underrun"])
    print("    overrun          %d   (hit the hard cap)" % row["overrun"])
    print("    authfail/replay  %d / %d" % (row["authfail"], row["replay"]))
    print("    foreign/stale    %d / %d" % (row["foreign"], row["stale"]))
    print()
    print("  LATENCY  (RTT is measured; one-way is an ESTIMATE and depends")
    print("            on the ping/pong clock offset)")
    print("    rtt   p50/p95/p99  %s / %s / %s"
          % (_fmt(_pct(row["rtt"], .50), "ms"),
             _fmt(_pct(row["rtt_p95"], .50), "ms"),
             _fmt(_pct(row["rtt_p99"], .50), "ms")))
    print("    oneway p50/p95     %s / %s"
          % (_fmt(_pct(row["oneway"], .50), "ms"),
             _fmt(_pct(row["oneway"], .95), "ms")))
    print()
    print("  JITTER / BUFFER")
    print("    arrival jitter     p50 %s  p95 %s"
          % (_fmt(_pct(row["jit"], .50), "ms"),
             _fmt(_pct(row["jit"], .95), "ms")))
    print("    spacing p95/p99    %s / %s"
          % (_fmt(_pct(row["spacing_p95"], .50), "ms"),
             _fmt(_pct(row["spacing_p99"], .50), "ms")))
    print("    buffer delay       p50 %s  p95 %s  max %s"
          % (_fmt(_pct(row["buf"], .50), "ms"),
             _fmt(_pct(row["buf"], .95), "ms"),
             _fmt(max(row["buf"]) if row["buf"] else None, "ms")))
    print()
    print("  AUDIO")
    print("    speaker rms        p50 %s   (above ~4000 is a comfortable "
          "call)" % _fmt(_pct(row["speaker_rms"], .50)))
    print()
    if row["buf"] and row["rtt"]:
        mouth_to_ear = (_pct(row["oneway"], .50) or 0) + (_pct(row["buf"], .50) or 0)
        print("  MOUTH-TO-EAR       ~%.0f ms  (one-way estimate + buffer; "
              "excludes\n                     device capture and playout "
              "latency)" % mouth_to_ear)
    print()


def compare(rows):
    print()
    print("COMPARISON  (each row is one call; compare like durations only)")
    print("-" * 108)
    print("%-22s %8s %9s %9s %9s %9s %8s %8s %7s"
          % ("config", "min", "rtt p50", "jit p50", "buf p50", "buf p95",
             "late", "discard", "under"))
    print("-" * 108)
    for row in rows:
        label = (row["codec"] or row["path"])[:22]
        print("%-22s %8.1f %9s %9s %9s %9s %8d %8d %7d"
              % (label, row["windows"] * 5 / 60.0,
                 _fmt(_pct(row["rtt"], .50)),
                 _fmt(_pct(row["jit"], .50)),
                 _fmt(_pct(row["buf"], .50)),
                 _fmt(_pct(row["buf"], .95)),
                 row["late"], row["discard"], row["underrun"]))
    print("-" * 108)
    print("Lower buf p50 with comparable late/underrun is the better")
    print("configuration. A low buffer bought with rising underruns is not an")
    print("improvement -- it is the same latency moved into dropouts.")
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+", help="--voice-debug log files (globs ok)")
    ap.add_argument("--compare", action="store_true",
                    help="one row per log instead of a full report")
    args = ap.parse_args(argv)

    paths = []
    for pattern in args.logs:
        paths.extend(sorted(glob.glob(pattern)) or [pattern])

    rows = []
    for path in paths:
        try:
            rows.append(parse(path))
        except OSError as exc:
            print("cannot read %s: %s" % (path, exc), file=sys.stderr)

    if not rows:
        return 1
    if args.compare:
        compare(rows)
    else:
        for row in rows:
            report(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
