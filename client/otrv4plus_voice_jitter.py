# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The voice subsystem's playout timing: the jitter buffer and the latency
measurements the call summary reports.

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
    colour_latency, _wipe, VOICE_FRAME_MS, FRAME_INTERVAL_S, VOICE_TS_LEN,
    VOICE_OPUS_SLOT, VOICE_PLAIN_LEN, VOICE_JITTER_DRAIN_MS,
    VOICE_JITTER_SAFETY_FACTOR, VOICE_JITTER_TAIL_PCT,
    VOICE_JITTER_TAIL_WINDOW, VOICE_JITTER_UNDERRUN_STEP,
    VOICE_JITTER_UNDERRUN_DECAY, VOICE_JITTER_PREFILL, VOICE_JITTER_MAX,
    VOICE_JITTER_SHED_MARGIN, VOICE_JITTER_DRIFT_HIGH,
    VOICE_JITTER_LATE_TOLERANCE,
)
from otrv4plus_voice_crypto import (  # noqa: F401
    FrameError,
)


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
                 drift_high=VOICE_JITTER_DRIFT_HIGH, adaptive=True,
                 shed_margin=VOICE_JITTER_SHED_MARGIN,
                 safety_factor=VOICE_JITTER_SAFETY_FACTOR,
                 drain_ms=VOICE_JITTER_DRAIN_MS):
        import heapq
        self._heapq = heapq
        self._heap = []
        self._seqs = set()
        self._lock = threading.Lock()
        self._prefill = int(prefill)
        self._maxlen = int(maxlen)
        self._late_tolerance = int(late_tolerance)
        self._drift_high = max(int(prefill) + 1, int(drift_high))
        self._shed_margin = max(1, int(shed_margin))
        self._safety_factor = float(safety_factor)
        # Pops needed to return to target after a burst. Proportional
        # shedding divides the excess across this many pops, so convergence
        # takes the same wall-clock time whether the burst was 5 frames or
        # 50.
        self._drain_pops = max(1, int(drain_ms) // max(1, VOICE_FRAME_MS))
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
        # Rolling window of how LATE each frame was against its expected
        # arrival, in seconds. The smoothed estimate above is a mean and this
        # path's tail is sixteen times its median, so the mean alone sizes
        # the buffer for a distribution the path does not have.
        import collections as _c
        self._late = _c.deque(maxlen=VOICE_JITTER_TAIL_WINDOW)
        # Frames of depth bought with evidence rather than arithmetic: one
        # per underrun, given back after a long clean run.
        self._learned = 0
        self._clean_pops = 0
        # depth_min/depth_max are held across a reporting window, like the
        # level meters: an instantaneous depth says nothing about whether the
        # buffer is stable or swinging between empty and full.
        self._depth_min = None
        self._depth_max = 0
        # Inter-arrival spacing. The smoothed estimate above drives the
        # target; this records the distribution behind it, because a mean
        # deviation cannot distinguish a steadily late path from a punctual
        # one with a long tail, and only the second is worth buffering for.
        self.spacing = Percentiles()
        #: Measured arrival-to-playout dwell per frame. This is the jitter
        #: buffer's real contribution to mouth-to-ear delay.
        self.dwell = Percentiles()
        # See otrv4plus_mediapath.COUNTER_DEFINITIONS for what each means.
        # `queued` is frames ACCEPTED, not played: a queued frame may still
        # be shed (`drift`), evicted (`overflow`) or cleared at teardown.
        # `played` is the one that counts what reached the decoder.
        self.stats = {"queued": 0, "late": 0, "duplicate": 0,
                      "overflow": 0, "gaps": 0, "drift": 0,
                      "underrun": 0, "burst_drain": 0,
                      "played": 0, "reordered": 0, "cleared": 0}
        #: Highest sequence key accepted, so an in-time frame that arrived
        #: behind a later one is counted as reordered.
        self._highest = -1

    #: How far the epoch is shifted in a sequence key.
    #:
    #: Named rather than repeated, because two places have to agree about it:
    #: [sequence] builds the key and [epoch_of] takes it apart, and a
    #: disagreement between them is invisible until a rekey.
    EPOCH_SHIFT = 62

    @staticmethod
    def sequence(epoch: int, counter: int) -> int:
        """A single monotonic ordering key across epoch boundaries.

        Counters restart at zero each epoch, so ordering on the counter alone
        would replay the whole epoch's worth of audio backwards at every
        rekey.  62 bits of counter space is 5.9 billion years at 40 ms.

        NOTE FOR ANYONE SUBTRACTING TWO OF THESE: the difference is only a
        frame count WITHIN one epoch.  Across a rekey it is about 4.6e18,
        because that is what the epoch field is worth -- see [epoch_of] and
        the guard in [pop].
        """
        return (int(epoch) << JitterBuffer.EPOCH_SHIFT) | (
            int(counter) & ((1 << JitterBuffer.EPOCH_SHIFT) - 1))

    @staticmethod
    def epoch_of(seq: int) -> int:
        """Which epoch a sequence key belongs to."""
        return int(seq) >> JitterBuffer.EPOCH_SHIFT

    def _observe_arrival(self, seq: int, now: float) -> None:
        """Update the jitter estimate and the target depth.

        RFC 3550's interarrival jitter, with the frame counter standing in for
        a sender timestamp: consecutive frames are 40 ms apart by
        construction, so the expected spacing is known exactly and any
        deviation is transit jitter.

            D = (arrival_delta) - (expected_delta)
            J += (|D| - J) / 16

        The target is VOICE_JITTER_SAFETY_FACTOR deviations of that, plus one
        frame of slack, clamped so it can never collapse below the floor or
        run away to the hard cap.
        """
        if not self._adaptive:
            return
        if self._last_arrival is not None and self._last_seq is not None:
            seq_delta = seq - self._last_seq
            if 0 < seq_delta < 200:            # ignore reorder and huge gaps
                expected = seq_delta * (FRAME_INTERVAL_S)
                observed = now - self._last_arrival
                d = abs(observed - expected)
                self.spacing.add(observed * 1000.0)
                self._jitter_est += (d - self._jitter_est) / 16.0
                # Only LATE counts. A frame that arrives early costs the
                # buffer nothing -- it simply waits -- while `d` above is
                # symmetric and so charges earliness as if it were a risk.
                self._late.append(max(0.0, observed - expected))
                mean_frames = ((self._safety_factor * self._jitter_est)
                               / FRAME_INTERVAL_S)
                # The larger of the two estimators wins. The mean responds
                # within a frame or two and is what catches a path that has
                # just got worse; the tail is slower but is the only one that
                # sees the arrivals that actually empty the buffer.
                frames = max(mean_frames, self._tail_frames())
                self._target = max(
                    float(self._prefill),
                    min(float(self._drift_high), frames + 1.0))
        # `self._last_seq or -1` treated a legitimate sequence 0 as -1, since
        # 0 is falsy. sequence(0, 0) is exactly 0, so the first frame of a
        # call hit it every time.
        if self._last_seq is None or seq > self._last_seq:
            self._last_arrival = now
            self._last_seq = seq

    def _tail_frames(self) -> float:
        """Frames of depth needed to cover the measured lateness tail.

        Nearest-rank over the rolling window, so the figure is always an
        arrival that really happened rather than one interpolated between
        two that did.
        """
        if len(self._late) < 8:
            # Too few samples for a percentile to mean anything. Returning 0
            # leaves the mean estimator and the floor in charge, which is
            # what governed the whole call before this existed.
            return 0.0
        ordered = sorted(self._late)
        idx = int(round((VOICE_JITTER_TAIL_PCT / 100.0) * len(ordered) + 0.5)) - 1
        idx = max(0, min(len(ordered) - 1, idx))
        return ordered[idx] / FRAME_INTERVAL_S

    def note_underrun(self) -> None:
        """The buffer ran dry: buy a frame of depth, up to the ceiling.

        This is the ONLY direct evidence that the target was too shallow.
        Everything else here is inference from arrival times, and the v10.15.1
        soak shows what inference alone achieved: 27 underruns, and a target
        that was identical after the 27th to what it had been before the
        first. Rise on evidence, fall on time.
        """
        headroom = int(self._drift_high) - int(self._prefill)
        if headroom > 0:
            self._learned = min(self._learned + VOICE_JITTER_UNDERRUN_STEP,
                                headroom)
        self._clean_pops = 0

    def _note_clean_pop(self) -> None:
        if self._learned <= 0:
            return
        self._clean_pops += 1
        if self._clean_pops >= VOICE_JITTER_UNDERRUN_DECAY:
            self._clean_pops = 0
            self._learned -= 1

    @property
    def target_depth(self) -> int:
        # The learned frames are added to the computed target and the CEILING
        # applies to the sum: a path bad enough to underrun repeatedly must
        # not be able to walk the buffer past the latency cap one dropout at
        # a time. OTRV4PLUS_JITTER_MAX_MS is still the last word on depth.
        return int(min(self._target + self._learned,
                       float(self._drift_high)) + 0.5)

    @property
    def learned_frames(self) -> int:
        """Frames of depth currently held because of past underruns."""
        return int(self._learned)

    @property
    def jitter_ms(self) -> float:
        return self._jitter_est * 1000.0

    def push(self, epoch: int, counter: int, pcm) -> bool:
        """Offer one decoded frame.  False if it was dropped."""
        seq = self.sequence(epoch, counter)
        with self._lock:
            self._observe_arrival(seq, time.monotonic())
            # Anything at or before the last frame played is late by
            # definition -- playout cannot be undone -- so there is no
            # tolerance to apply. The guard that tried to
            # (seq <= last_played - late_tolerance) was strictly subsumed by
            # this one and never changed an outcome.
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
                    stale_seq, stale_pcm, _t = self._heapq.heappop(self._heap)
                    self._seqs.discard(stale_seq)
                    _wipe(stale_pcm)
                except Exception:
                    pass
                self.stats["overflow"] += 1
            # Arrival time rides with the frame so dwell is measured per
            # frame rather than inferred from depth. Depth times frame
            # duration assumes playout is running exactly on time, and the
            # moment that assumption breaks is precisely when the number
            # matters.
            self._heapq.heappush(self._heap, (seq, pcm, time.monotonic()))
            self._seqs.add(seq)
            self.stats["queued"] += 1
            if seq < self._highest:
                self.stats["reordered"] += 1
            else:
                self._highest = seq
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
                self.stats["underrun"] += 1
                self.note_underrun()
                return None

            # Shed the oldest while we are above the latency ceiling. One
            # frame per pop, so depth converges over a second or so instead
            # of jumping — a gradual trim is far less audible than a jump,
            # and the gap counter below reports it as concealment anyway.
            # Shed against the adaptive target rather than a fixed ceiling,
            # so a call that starts on a congested path and then settles gets
            # its latency back instead of carrying the bad minute all night.
            #
            # This threshold IS the call's steady-state latency: arrivals and
            # playout run at the same rate, so nothing else pulls the buffer
            # down and it settles exactly here. That makes the margin a
            # latency decision, not a tuning detail, which is why it is
            # expressed in milliseconds rather than in frames.
            excess = len(self._heap) - (self.target_depth + self._shed_margin)
            if excess > 0:
                # Proportional, not one-per-pop. One-per-pop drains at exactly
                # the playout rate, so a 30-frame burst spent 1.5 s at high
                # latency before recovering -- and every one of those frames
                # was played late. Dividing the excess across _drain_pops
                # makes recovery time independent of burst size.
                #
                # Discarding is correct here rather than regrettable: a frame
                # this far back in the queue is already past the point where
                # it could have been played in sequence, and the gap counter
                # below hands it to concealment.
                shed = max(1, -(-excess // self._drain_pops))
                shed = min(shed, len(self._heap) - 1)
                for _ in range(max(0, shed)):
                    stale_seq, stale_pcm, _t = self._heapq.heappop(self._heap)
                    self._seqs.discard(stale_seq)
                    _wipe(stale_pcm)
                    self.stats["drift"] += 1
                    # Do NOT let our own shedding look like transit loss.
                    #
                    # `gap` below is computed from the sequence numbers, so a
                    # shed frame left a hole and the playback worker answered
                    # it with FEC or concealment -- writing TWO frames to the
                    # device for one pop. Each write blocks about a frame
                    # period, so the pop rate halved, the buffer grew, and the
                    # shedder fired harder: measured at 13.0 pops/s against
                    # 16.2 arriving, shedding 19.8% and synthesising
                    # replacements for the very frames it had just discarded.
                    #
                    # Concealment exists for frames that never arrived. These
                    # arrived and were dropped deliberately to cut latency, so
                    # spending more device time reconstructing them is exactly
                    # backwards. Advancing the marker says "consumed, not
                    # lost".
                    if stale_seq > self._last_played:
                        self._last_played = stale_seq
                if shed > 1:
                    self.stats["burst_drain"] += 1

            seq, pcm, arrived = self._heapq.heappop(self._heap)
            self._seqs.discard(seq)
            self.dwell.add((time.monotonic() - arrived) * 1000.0)
            gap = 0
            # A REKEY IS NOT A GAP.
            #
            # `sequence()` packs the epoch into the top bits, so subtracting
            # two keys is a frame count only while the epoch is the same.
            # Across a rekey the difference is 2**62 -- about 4.6e18 -- and
            # without this guard every rekey charged the call that many lost
            # frames.  Two consequences, one cosmetic and one not:
            #
            #   * the hangup summary computes delivery as
            #     queued/(queued+gaps), so a single rekey drove it to
            #     "0.0% of audio delivered" on a call whose audio was working
            #     in both directions -- the defect that started this
            #     investigation;
            #   * `gap` is handed to concealment, which is bounded to three
            #     frames, so the audible cost was ~180 ms of synthetic audio
            #     per rekey rather than a stall.
            #
            # `_observe_arrival` already refused deltas >= 200 for exactly
            # this reason; this is the same rule in the place that missed it.
            # Counting zero across the boundary is honest rather than
            # convenient: the counter restarted, so how many frames were lost
            # in the changeover is genuinely unknown, and zero is off by at
            # most a handful where the old value was off by 4.6e18.
            if (self._last_played >= 0
                    and self.epoch_of(seq) == self.epoch_of(self._last_played)):
                gap = max(0, seq - self._last_played - 1)
                if gap:
                    self.stats["gaps"] += gap
            self._last_played = seq
            self._note_clean_pop()
            self.stats["played"] += 1
            return pcm, gap

    def depth(self) -> int:
        with self._lock:
            depth = len(self._heap)
            self._depth_max = max(self._depth_max, depth)
            self._depth_min = (depth if self._depth_min is None
                               else min(self._depth_min, depth))
            return depth

    def sample_depth(self):
        """Latch (min, max) depth for the window and start a new one."""
        with self._lock:
            lo = 0 if self._depth_min is None else self._depth_min
            hi = self._depth_max
            self._depth_min = None
            self._depth_max = len(self._heap)
            return lo, hi

    def clear(self) -> None:
        """Wipe and discard everything queued.  Never raises."""
        with self._lock:
            while self._heap:
                try:
                    _, pcm, _t = self._heapq.heappop(self._heap)
                    _wipe(pcm)
                    self.stats["cleared"] += 1
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

class Percentiles:
    """Bounded sample window with percentile readout.

    A mean hides exactly what matters for real-time media. A path that
    delivers at 60 ms with a 900 ms tail and one that delivers steadily at
    120 ms have similar means and completely different conversations; the
    tail is what sets the jitter buffer and therefore the delay. p95 and p99
    are the numbers to engineer against.

    Fixed window rather than all-time: a bad first minute must not describe
    the call for the next ten.
    """

    __slots__ = ("_samples", "_n")

    def __init__(self, window=512):
        import collections
        self._samples = collections.deque(maxlen=int(window))
        self._n = 0

    def add(self, value: float) -> None:
        self._samples.append(float(value))
        self._n += 1

    def __len__(self) -> int:
        return len(self._samples)

    def percentile(self, q: float) -> float:
        if not self._samples:
            return 0.0
        ordered = sorted(self._samples)
        if len(ordered) == 1:
            return ordered[0]
        # Nearest-rank. With a few hundred samples the interpolation choice
        # is noise, and nearest-rank never invents a value between two real
        # observations.
        idx = int(round(q * (len(ordered) - 1)))
        return ordered[max(0, min(idx, len(ordered) - 1))]

    def summary(self, scale=1.0, unit="ms") -> str:
        if not self._samples:
            return "n=0"
        return ("n=%d p50=%.0f p95=%.0f p99=%.0f max=%.0f%s"
                % (len(self._samples),
                   self.percentile(0.50) * scale,
                   self.percentile(0.95) * scale,
                   self.percentile(0.99) * scale,
                   max(self._samples) * scale, unit))

    def clear(self) -> None:
        self._samples.clear()


class StageTimers:
    """Per-stage pipeline timings, in milliseconds, with percentiles.

    The question this exists to answer: a 700-1000 ms one-way reading is
    either I2P or it is us, and the aggregate number cannot tell them apart.
    The send stamp goes on right after Opus encode and is read right after
    AEAD decrypt, so everything between -- seal, the hop to the event loop,
    the wait for the loop to run the callback, sendto, I2P, receive, verify
    -- is inside that one figure.

    Timing every stage separately makes the split explicit. If `queue` is
    300 ms then a third of the one-way delay is our own scheduling and no
    amount of I2P tuning will touch it. If `queue` is 2 ms then the path
    really is that slow and the only lever left is the jitter buffer.

    Cheap enough for the real-time path: a monotonic read and a deque append
    per stage per frame, at 16.7 frames/s.
    """

    #: Stages, in pipeline order.
    NAMES = ("encode", "seal", "queue", "decrypt", "dwell", "decode",
             "conv", "write", "play")

    def __init__(self, window=256):
        self.t = {name: Percentiles(window) for name in self.NAMES}

    def record(self, name: str, seconds: float) -> None:
        bucket = self.t.get(name)
        if bucket is not None and seconds >= 0.0:
            bucket.add(seconds * 1000.0)

    def record_since(self, name: str, start: float) -> None:
        self.record(name, time.monotonic() - start)

    def summary(self) -> str:
        parts = []
        for name in self.NAMES:
            bucket = self.t[name]
            if len(bucket):
                parts.append("%s %.1f/%.1f" % (name,
                                               bucket.percentile(0.50),
                                               bucket.percentile(0.95)))
        return " ".join(parts) if parts else "no samples"

    def local_send_ms(self, q=0.50) -> float:
        """What the sender adds inside the one-way figure."""
        return (self.t["seal"].percentile(q) + self.t["queue"].percentile(q))

    def pipeline_ms(self, q=0.50) -> float:
        """Everything this device adds, both directions, excluding network."""
        return sum(self.t[n].percentile(q) for n in self.NAMES)


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
        #: Every RTT sample of the call, for the tail. The rolling median
        #: above is what the buffer reacts to; this is what a benchmark
        #: reports.
        self.rtt_pct = Percentiles()
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
            self.rtt_pct.add(rtt)
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
        # Only the one-way figure is banded. RTT is a diagnostic; one-way is
        # the half of it the listener actually waits through.
        return "rtt=%s oneway=%s" % (
            "%.0fms" % rtt if rtt is not None else "-",
            colour_latency(ow))
