#!/usr/bin/env python3
"""
tools/transport_report.py — read transport telemetry, print the comparison
=========================================================================

Turns one or two JSONL files written by `OTRV4PLUS_TRANSPORT_LOG` into the
table the soak comparison is scored on: p50 / p95 / p99 / max for every
latency series, plus the counters and the health-state accounting.

    # one run
    python3 tools/transport_report.py optimised.jsonl

    # baseline vs optimised, side by side with deltas
    python3 tools/transport_report.py --baseline baseline.jsonl optimised.jsonl

Reads the last `session_close` record if there is one, otherwise the last
`session_snapshot` — so a call that was killed rather than hung up still
reports everything up to its final interim snapshot.

With `--all-calls`, each call tag is reported separately instead of only the
most recent.
"""

import argparse
import json
import sys

SERIES_ORDER = [
    ("rtt", "round trip (ping/pong)"),
    ("oneway", "one way (frame stamp)"),
    ("jitter", "jitter |gap - 40 ms|"),
    ("interarrival", "frame interarrival"),
    ("send_queue", "seal -> event loop"),
    ("socket_write", "transport.write"),
    ("jitter_depth", "jitter buffer depth (frames)"),
    ("xmpp_stanza", "xmpp bridge write"),
    ("recv_to_decode", "socket read -> queued"),
]

COUNTER_ORDER = [
    "frames_sent", "frames_received", "late_frames", "backpressure_drops",
]

HEALTH_FIELDS = [
    "transitions", "seconds_healthy", "seconds_degraded",
    "seconds_recovering", "seconds_disconnected",
]


def load(path):
    """Return {call_tag: {"summary": record, "events": [...]}}."""
    calls = {}
    with open(path, encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                print("  ! skipping malformed line %d" % line_no,
                      file=sys.stderr)
                continue
            tag = record.get("call", "unknown")
            entry = calls.setdefault(tag, {"summary": None, "events": [],
                                           "close": None})
            event = record.get("event")
            if event in ("session_close", "session_snapshot") and \
                    "counters" in record:
                # A close record supersedes any snapshot; snapshots supersede
                # each other in order.
                if event == "session_close" or entry["summary"] is None or \
                        entry["summary"].get("event") != "session_close":
                    entry["summary"] = record
            else:
                entry["events"].append(record)
                if event == "session_close":
                    entry["close"] = record
    return calls


def pick(calls, all_calls):
    """The call(s) to report on, newest last."""
    usable = [(tag, data) for tag, data in calls.items()
              if data["summary"] is not None]
    if not usable:
        return []
    usable.sort(key=lambda item: item[1]["summary"].get("elapsed_s", 0.0))
    return usable if all_calls else usable[-1:]


def _fmt(value, width=9, digits=1):
    if value is None:
        return " " * (width - 1) + "-"
    return ("%%%d.%df" % (width, digits)) % value


def _delta(new, old, lower_is_better=True):
    if new is None or old is None:
        return ""
    if old == 0:
        return ""
    change = (new - old) / old * 100.0
    arrow = "better" if (change < 0) == lower_is_better else "worse"
    if abs(change) < 1.0:
        arrow = "same"
    return "  %+7.1f%%  %s" % (change, arrow)


def report_one(tag, data, baseline=None):
    summary = data["summary"]
    base = baseline["summary"] if baseline else None

    print("=" * 78)
    print("call %s   peer %s   role %-9s   %.0f s   (%s)"
          % (tag, summary.get("peer", "?"), summary.get("role", "?"),
             summary.get("elapsed_s", 0.0),
             summary.get("event", "session_close")))
    print("=" * 78)

    print("\nLATENCY DISTRIBUTIONS (ms)")
    header = "  %-28s %9s %9s %9s %9s %8s" % (
        "series", "p50", "p95", "p99", "max", "n")
    print(header)
    print("  " + "-" * (len(header) - 2))
    for key, label in SERIES_ORDER:
        series = summary.get(key)
        if not series:
            continue
        print("  %-28s %s %s %s %s %8d"
              % (label,
                 _fmt(series.get("p50_ms")), _fmt(series.get("p95_ms")),
                 _fmt(series.get("p99_ms")), _fmt(series.get("max_ms")),
                 series.get("count", 0)))
        if base and base.get(key):
            old = base[key]
            print("  %-28s %s %s %s %s"
                  % ("  baseline",
                     _fmt(old.get("p50_ms")), _fmt(old.get("p95_ms")),
                     _fmt(old.get("p99_ms")), _fmt(old.get("max_ms"))))
            for name, field in (("p50", "p50_ms"), ("p95", "p95_ms"),
                                ("p99", "p99_ms"), ("max", "max_ms")):
                line = _delta(series.get(field), old.get(field))
                if line:
                    print("  %-28s %s%s" % ("", name, line))

    print("\nCOUNTERS")
    counters = summary.get("counters", {})
    base_counters = base.get("counters", {}) if base else {}
    for name in COUNTER_ORDER:
        if name not in counters and name not in base_counters:
            continue
        value = counters.get(name, 0)
        if base_counters:
            print("  %-28s %12d   baseline %12d"
                  % (name, value, base_counters.get(name, 0)))
        else:
            print("  %-28s %12d" % (name, value))
    for name in sorted(set(counters) - set(COUNTER_ORDER)):
        print("  %-28s %12d" % (name, counters[name]))

    sent = counters.get("frames_sent", 0)
    received = counters.get("frames_received", 0)
    if sent and received:
        print("  %-28s %11.3f%%   (received/sent, this direction only --"
              % ("apparent delivery", received / sent * 100.0))
        print("  %-28s            loss is only meaningful when compared with"
              % "")
        print("  %-28s            the PEER's frames_sent)" % "")

    close = data.get("close")
    if close:
        print("\nTRANSPORT HEALTH")
        for field in HEALTH_FIELDS:
            if field in close:
                print("  %-28s %12s" % (field, close[field]))

    changes = [e for e in data["events"] if e.get("event") == "health_change"]
    if changes:
        print("\n  health transitions (%d):" % len(changes))
        for event in changes[:40]:
            print("    t=%8.1fs  %-12s -> %s"
                  % (event.get("t", 0.0), event.get("from_state", "?"),
                     event.get("to_state", "?")))
        if len(changes) > 40:
            print("    ... %d more" % (len(changes) - 40))

    lost = [e for e in data["events"] if e.get("event") == "stream_lost"]
    if lost:
        print("\n  stream_lost events: %d" % len(lost))


def main():
    parser = argparse.ArgumentParser(
        description="Report OTRv4Plus transport telemetry.")
    parser.add_argument("log", help="JSONL written by OTRV4PLUS_TRANSPORT_LOG")
    parser.add_argument("--baseline", help="a second JSONL to compare against")
    parser.add_argument("--all-calls", action="store_true",
                        help="report every call in the file, not just the last")
    args = parser.parse_args()

    calls = load(args.log)
    chosen = pick(calls, args.all_calls)
    if not chosen:
        print("No session_close or session_snapshot record with distributions "
              "was found in %s.\n"
              "The call must end through /hangup (or run past its first 60 s "
              "interim snapshot) for the histograms to be written."
              % args.log, file=sys.stderr)
        return 1

    baseline = None
    if args.baseline:
        base_calls = pick(load(args.baseline), False)
        baseline = base_calls[0][1] if base_calls else None
        if baseline is None:
            print("  ! no usable record in the baseline file; "
                  "reporting without comparison", file=sys.stderr)

    for tag, data in chosen:
        report_one(tag, data, baseline)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
