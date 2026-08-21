#!/usr/bin/env python3
"""
tools/transport_bench.py — deterministic measurement of the transport changes
=============================================================================

What this measures, and what it does not
----------------------------------------
This host has no I2P router, no XMPP server and no peer, so **nothing here is
a measurement of I2P latency**. What it does measure is the part of the delay
budget that lives in this process and on the local loopback socket to the SAM
bridge — which is exactly where the changes in this pass were made.

Read every number below as: "the transport adds this much, before I2P adds
anything." That is a real quantity, it was previously unmeasured, and it is
the only part of the path this build can change.

Benchmarks
----------
1. SAM write pacing        old fixed per-chunk sleep vs the token bucket
2. Loopback Nagle          199-byte frames every 40 ms, TCP_NODELAY on/off
3. Send-queue backlog      how much stale audio the old and new bounds admit
4. Histogram accuracy      percentile error against an exact sort

Run:  python3 tools/transport_bench.py
"""

import asyncio
import os
import random
import socket
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import otrv4plus_telemetry as telemetry     # noqa: E402


def _fmt(name, value, unit="ms"):
    print("    %-34s %10.3f %s" % (name, value, unit))


# ── 1. SAM write pacing ──────────────────────────────────────────────────────

OLD_CHUNK = 1024
OLD_DELAY = 0.020
NEW_CHUNK = 1024
NEW_RATE = 51200.0
NEW_BURST = 1024        # see otrv4plus_i2p: 4096 broke SMP on a real path


def old_pacing_seconds(nbytes):
    """The delay the previous implementation imposed, by construction.

    for i in range(0, len(data), 1024):
        write(chunk); await drain(); await sleep(0.02)

    One sleep per chunk, including after the last one.
    """
    if nbytes <= OLD_CHUNK:
        return 0.0
    chunks = (nbytes + OLD_CHUNK - 1) // OLD_CHUNK
    return chunks * OLD_DELAY


def new_pacing_seconds(nbytes, tokens=NEW_BURST):
    """Wall-clock delay the token bucket imposes on a single message.

    The clock advances as each charged wait is slept, which is what take()
    does -- summing the raw delays instead would compound them and overstate
    the cost several-fold.
    """
    total = 0.0
    remaining = nbytes
    while remaining > 0:
        piece = min(NEW_CHUNK, remaining)
        remaining -= piece
        if tokens >= piece:
            tokens -= piece
            continue
        total += (piece - tokens) / NEW_RATE
        tokens = 0.0                       # refilled during the sleep itself
    return total


def bench_pacing():
    print("\n1. SAM write pacing (delay added by the bridge, per message)")
    print("   sizes chosen from real traffic: an OTR data frame, a voice")
    print("   INVITE/rekey carrying an ML-KEM-1024 encapsulation, and the")
    print("   6000-byte fragment send_otr_fragmented emits.")
    print()
    print("    %-12s %12s %12s %10s" % ("size", "old", "new", "saved"))
    for size in (200, 900, 1500, 2500, 4096, 6000, 12000, 24000):
        old = old_pacing_seconds(size) * 1000.0
        new = new_pacing_seconds(size) * 1000.0
        print("    %-12s %10.1fms %10.1fms %9.1fms"
              % ("%d B" % size, old, new, old - new))

    print()
    print("   sustained rate check (must be unchanged):")
    # Drive 200 KB through both models and compare the long-run ceiling.
    total_old = old_pacing_seconds(200000)
    tokens = float(NEW_BURST)
    total_new = 0.0
    remaining = 200000
    while remaining > 0:
        piece = min(NEW_CHUNK, remaining)
        remaining -= piece
        if tokens >= piece:
            tokens -= piece
            continue
        total_new += (piece - tokens) / NEW_RATE
        tokens = 0.0
    _fmt("200 KB, old pacing", total_old * 1000.0)
    _fmt("200 KB, token bucket", total_new * 1000.0)
    _fmt("effective rate, old", 200000 / total_old / 1024.0, "KiB/s")
    _fmt("effective rate, new", 200000 / total_new / 1024.0, "KiB/s")


# ── 2. Loopback Nagle ────────────────────────────────────────────────────────

async def _nagle_trial(nodelay, frames=150, interval=0.040, size=199):
    """One-way delivery delay for 199-byte frames on loopback TCP.

    199 bytes every 40 ms is exactly the media shape: small, periodic, and
    the case Nagle exists to coalesce.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    host, port = server_sock.getsockname()

    samples = []
    stamps = {}

    async def serve():
        loop = asyncio.get_running_loop()
        conn, _ = await loop.sock_accept(server_sock)
        conn.setblocking(False)
        if nodelay:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        got = bytearray()
        # A trivial echo: the sender times the round trip, which is what the
        # PING/PONG probe does on a real call.
        while len(samples) < frames:
            try:
                data = await asyncio.wait_for(loop.sock_recv(conn, 65536), 2.0)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            got += data
            while len(got) >= size:
                frame = bytes(got[:size])
                del got[:size]
                await loop.sock_sendall(conn, frame)
        conn.close()

    async def send():
        loop = asyncio.get_running_loop()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setblocking(False)
        if nodelay:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        await loop.sock_connect(client, (host, port))

        async def reader():
            got = bytearray()
            while len(samples) < frames:
                try:
                    data = await asyncio.wait_for(
                        loop.sock_recv(client, 65536), 2.0)
                except asyncio.TimeoutError:
                    break
                if not data:
                    break
                got += data
                while len(got) >= size:
                    seq = int.from_bytes(got[:4], "big")
                    del got[:size]
                    t0 = stamps.pop(seq, None)
                    if t0 is not None:
                        samples.append((time.perf_counter() - t0) * 1000.0)

        task = asyncio.ensure_future(reader())
        next_at = time.perf_counter()
        for seq in range(frames):
            next_at += interval
            sleep_for = next_at - time.perf_counter()
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            payload = seq.to_bytes(4, "big") + bytes(size - 4)
            stamps[seq] = time.perf_counter()
            await loop.sock_sendall(client, payload)
        await task
        client.close()

    server_task = asyncio.ensure_future(serve())
    await send()
    server_task.cancel()
    server_sock.close()
    return samples


async def _burst_trial(nodelay, bursts=40, per_burst=25, size=199):
    """Frames written back to back, as when a stalled send queue drains.

    This is the pattern Nagle actually engages on: several small writes with
    an unacknowledged segment already outstanding. On a real call it happens
    every time the path stalls and then recovers -- which is precisely the
    moment tail latency is being measured.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    host, port = server_sock.getsockname()

    samples = []
    stamps = {}
    total = bursts * per_burst
    loop = asyncio.get_running_loop()

    async def serve():
        conn, _ = await loop.sock_accept(server_sock)
        conn.setblocking(False)
        if nodelay:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        got = bytearray()
        while len(samples) < total:
            try:
                data = await asyncio.wait_for(loop.sock_recv(conn, 65536), 2.0)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            got += data
            while len(got) >= size:
                frame = bytes(got[:size])
                del got[:size]
                await loop.sock_sendall(conn, frame)
        conn.close()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setblocking(False)
    if nodelay:
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    server_task = asyncio.ensure_future(serve())
    await loop.sock_connect(client, (host, port))

    async def reader():
        got = bytearray()
        while len(samples) < total:
            try:
                data = await asyncio.wait_for(loop.sock_recv(client, 65536),
                                              2.0)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            got += data
            while len(got) >= size:
                seq = int.from_bytes(got[:4], "big")
                del got[:size]
                t0 = stamps.pop(seq, None)
                if t0 is not None:
                    samples.append((time.perf_counter() - t0) * 1000.0)

    read_task = asyncio.ensure_future(reader())
    seq = 0
    for _ in range(bursts):
        for _ in range(per_burst):
            stamps[seq] = time.perf_counter()
            await loop.sock_sendall(client,
                                    seq.to_bytes(4, "big") + bytes(size - 4))
            seq += 1
        await asyncio.sleep(0.05)
    await read_task
    server_task.cancel()
    client.close()
    server_sock.close()
    return samples


def _report(label, samples):
    if not samples:
        print("    %-22s no samples" % label)
        return
    ordered = sorted(samples)
    print("    %-22s n=%-5d p50=%8.3fms p95=%8.3fms max=%8.3fms"
          % (label, len(ordered), statistics.median(ordered),
             ordered[int(len(ordered) * 0.95) - 1], ordered[-1]))


def bench_nagle():
    print("\n2a. Steady cadence: 199-byte frames every 40 ms")
    print("    (the normal media shape. Nagle cannot engage here: the ACK")
    print("     returns in microseconds, long before the next frame is due.)")
    for label, nodelay in (("Nagle on (previous)", False),
                           ("TCP_NODELAY (now)", True)):
        _report(label, asyncio.new_event_loop().run_until_complete(
            _nagle_trial(nodelay)))

    print("\n2b. Burst drain: 25 frames back to back, 40 times")
    print("    (what happens when a stalled send queue empties after an I2P")
    print("     hiccup -- the moment that decides the tail.)")
    for label, nodelay in (("Nagle on (previous)", False),
                           ("TCP_NODELAY (now)", True)):
        _report(label, asyncio.new_event_loop().run_until_complete(
            _burst_trial(nodelay)))


# ── 3. Send-queue backlog ────────────────────────────────────────────────────

def bench_backlog():
    print("\n3. Send-queue bound (stale audio admitted before dropping)")
    packet = 21 + 178          # VOICE_HDR_LEN + VOICE_SEALED_LEN
    for label, packets in (("old: 50 packets", 50), ("new: 400 ms", 10)):
        print("    %-18s %6d bytes  %7.0f ms of audio"
              % (label, packet * packets, packets * 40))
    print("    A frame admitted at the old bound is delivered up to 2 s late;")
    print("    the receiver's jitter buffer claws back above 600 ms anyway, so")
    print("    those frames cost bandwidth and delay the frames behind them.")


# ── 4. Histogram accuracy ────────────────────────────────────────────────────

def bench_histogram():
    print("\n4. Histogram percentile error vs an exact sort")
    random.seed(20260821)
    exact = []
    hist = telemetry.Histogram()
    for _ in range(200000):
        # Shaped like the observed path: ~1.3 s body with a heavy tail.
        v = random.gauss(1300, 130) if random.random() > 0.02 \
            else random.uniform(2000, 9000)
        exact.append(v)
        hist.observe(v)
    exact.sort()

    def pct(q):
        return exact[min(len(exact) - 1, int(len(exact) * q / 100.0))]

    print("    %-8s %12s %12s %10s" % ("q", "exact", "histogram", "error"))
    for q in (50, 95, 99, 100):
        e = exact[-1] if q == 100 else pct(q)
        h = hist.percentile(q)
        print("    %-8s %10.1fms %10.1fms %9.2fms" % ("p%d" % q, e, h, h - e))
    print("    memory: %d buckets, independent of sample count" % 164)


def main():
    print("=" * 72)
    print("OTRv4Plus transport benchmark")
    print("Measures this process and the loopback socket to SAM.")
    print("NOT a measurement of I2P: no router, no peer on this host.")
    print("=" * 72)
    bench_pacing()
    bench_nagle()
    bench_backlog()
    bench_histogram()
    print()


if __name__ == "__main__":
    main()
