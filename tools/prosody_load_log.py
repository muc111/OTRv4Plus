#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Prosody's CPU and memory, once a minute, for a stress test whose bots run
on ANOTHER machine (owner, 2026-10-21: the bots on the server laptop took
the CPU they were meant to measure; they now run on a phone in Termux).

Run on the SERVER, in its own terminal, before starting the bots:

    cd ~/OTRv4Plus && python3 tools/prosody_load_log.py --csv server-400.csv

It samples Prosody's process every 5 s (the same reader the stress test uses
when it runs on the server) and prints one line a minute: Prosody's average
and peak CPU (% of one core -- Prosody uses one), its memory, and the
machine's load average. Ctrl-C stops it and prints the peak. Reads /proc
only; changes nothing.
"""
import argparse
import csv
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from otrv4plus_stresstest import ServerSampler                      # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--csv", help="also write the per-minute rows here")
    ap.add_argument("--every", type=float, default=5.0, help="seconds between samples")
    args = ap.parse_args(argv)

    s = ServerSampler()
    if s.pid is None:
        print("Prosody's process is not visible here: run this on the server.")
        return 2
    print("[prosody-log] watching Prosody (pid %d); one line a minute, Ctrl-C to stop" % s.pid)
    fh = open(args.csv, "w", newline="") if args.csv else None
    writer = None
    start = time.time()
    next_row = start + 60
    try:
        while True:
            s.sample()
            if time.time() >= next_row:
                row = {"elapsed_min": round((time.time() - start) / 60, 1)}
                row.update(s.minute())
                row["load_1m"] = round(os.getloadavg()[0], 2)
                print("[prosody-log] %(elapsed_min)5.1f min  prosody cpu %(prosody_cpu_avg_pct)s%% "
                      "(peak %(prosody_cpu_peak_pct)s%%)  mem %(prosody_rss_mib)s MiB  "
                      "load %(load_1m)s" % row, flush=True)
                if fh is not None:
                    if writer is None:
                        writer = csv.DictWriter(fh, fieldnames=list(row))
                        writer.writeheader()
                    writer.writerow(row)
                    fh.flush()
                next_row += 60
            time.sleep(args.every)
    except KeyboardInterrupt:
        pass
    finally:
        if fh is not None:
            fh.close()
    print("[prosody-log] peak: %.0f%% of one core, %.0f MiB" % (s.peak_cpu, s.peak_rss))
    return 0


if __name__ == "__main__":
    sys.exit(main())
