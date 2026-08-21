#!/usr/bin/env python3
"""
otrv4plus_telemetry.py — structured transport diagnostics for the voice path
============================================================================

Why this module exists
----------------------
The existing latency instrumentation (`LatencyTracker` in otrv4plus_voice.py)
keeps a 10-sample rolling window and reports the median. That is the right
choice for a status line — one tunnel stall must not drag the displayed number
for the rest of the call — but it means the implementation has never been able
to report a p95, a p99 or a maximum. The 4-hour soak's "occasional significant
latency spikes" is an impression from watching a median move, not a
measurement of the tail, because the tail was discarded by construction.

Tail latency is the thing worth optimising on I2P. A median of 1.3 s that
occasionally becomes 8 s is a different product from a median of 1.3 s that
never exceeds 2 s, and the old instrumentation cannot tell those apart.

Design
------
* **Bounded memory.** Percentiles come from a fixed-bucket histogram, not a
  sample list. A 4-hour call is ~360,000 frames; keeping them would be
  ~3 MB per series and unbounded for a longer call. 164 buckets is 2 KB
  regardless of duration.
* **Numeric only.** Every value that enters this module is an int, a float, or
  a name from a fixed enum. `_check_value` enforces it at runtime, so a later
  edit cannot start logging a message body, a JID or key material by mistake:
  it raises instead. `tests/test_voice_transport.py` asserts that.
* **No print scraping.** The old diagnostics worked by parsing lines the
  application printed. Nothing here goes near stdout; a caller that wants a
  file gets JSONL through an explicit sink it opened itself.
* **Opaque identifiers.** Peers and calls appear as an 8-hex-digit tag derived
  by truncated SHA3-256 over a per-process random salt. Stable within a run so
  events correlate, meaningless across runs, and not reversible to a JID.

What must never appear here
---------------------------
voice plaintext, message plaintext, cryptographic keys, MKenc, MKmac, ratchet
secrets, Ed448/X448 private material, SMP secrets, DEKs, passwords, JIDs,
I2P destinations. The value guard rejects `bytes` and rejects any string that
is not a registered enum name, which covers all of these by type.
"""

import hashlib
import json
import os
import secrets
import threading
import time

__all__ = [
    "Histogram", "TransportMetrics", "TransportHealth", "JsonlSink",
    "opaque_tag", "HEALTHY", "DEGRADED", "RECOVERING", "DISCONNECTED",
    "EVENT_NAMES", "TelemetryValueError",
]


# ── Value guard ──────────────────────────────────────────────────────────────

class TelemetryValueError(TypeError):
    """A non-numeric, non-enum value was offered to the telemetry layer.

    Deliberately a hard error rather than a coerce-and-continue. The whole
    point of this module is that it cannot become a channel for plaintext or
    key material, and that property is only worth anything if violating it
    fails loudly in a test rather than quietly at runtime.
    """


# Every string that may legitimately appear in a telemetry record. Anything
# else is rejected: an unbounded string field is exactly how a message body or
# a JID ends up in a log file.
EVENT_NAMES = frozenset({
    # transport health
    "health_change", "stall_begin", "stall_end",
    # session lifecycle
    "session_open", "session_close", "stream_lost",
    # SAM / I2P
    "sam_session_create", "sam_accept", "sam_connect", "sam_error",
    "sam_session_recreate",
    # XMPP
    "xmpp_connect", "xmpp_disconnect", "xmpp_reconnect", "xmpp_keepalive_fail",
    # media
    "rekey_begin", "rekey_commit", "rekey_fail",
    "backpressure_drop", "resync", "auth_fail", "replay",
})

_ENUM_VALUES = frozenset({
    "HEALTHY", "DEGRADED", "RECOVERING", "DISCONNECTED",
    "initiator", "responder", "unknown",
})


def _check_value(key, value):
    """Return `value` if telemetry may carry it; raise otherwise."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    if value is None:
        return None
    if isinstance(value, str):
        if value in EVENT_NAMES or value in _ENUM_VALUES:
            return value
        if _OPAQUE_RE_OK(value):
            return value
        raise TelemetryValueError(
            "telemetry field %r: %r is not a number, a known enum name or an "
            "opaque tag. Free-form strings are refused because that is how a "
            "message body, a JID or a destination ends up in a log."
            % (key, value[:32]))
    raise TelemetryValueError(
        "telemetry field %r: %s is not a permitted telemetry type"
        % (key, type(value).__name__))


def _OPAQUE_RE_OK(value):
    """True for the 8-lowercase-hex form produced by opaque_tag()."""
    if len(value) != 8:
        return False
    return all(c in "0123456789abcdef" for c in value)


# ── Opaque identifiers ───────────────────────────────────────────────────────

_TAG_SALT = secrets.token_bytes(16)


def opaque_tag(value) -> str:
    """An 8-hex-digit, per-process-random tag for a peer, call or destination.

    Correlates records inside one run and is meaningless outside it. Not a
    fingerprint: the salt is discarded when the process exits, so nothing
    persisted can be linked back to a JID or an I2P destination.
    """
    if value is None:
        return "00000000"
    if isinstance(value, str):
        raw = value.encode("utf-8", errors="replace")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raw = repr(value).encode("utf-8", errors="replace")
    return hashlib.sha3_256(_TAG_SALT + raw).hexdigest()[:8]


# ── Histogram ────────────────────────────────────────────────────────────────

def _default_edges():
    """Bucket upper bounds in milliseconds.

    Resolution follows where the interesting numbers are: 5 ms up to 200 ms
    covers jitter and queue delay, 25 ms up to 2 s covers the observed ~1.3 s
    I2P RTT closely enough to compare two configurations, and the coarse tail
    exists only so an 8-second spike lands somewhere rather than being clamped
    into the top bucket alongside a 2-second one.
    """
    edges = []
    edges += [5.0 * i for i in range(1, 41)]              # 5..200 ms
    edges += [200.0 + 25.0 * i for i in range(1, 73)]     # 225..2000 ms
    edges += [2000.0 + 250.0 * i for i in range(1, 33)]   # 2250..10000 ms
    edges += [10000.0 + 2500.0 * i for i in range(1, 21)]  # 12500..60000 ms
    return tuple(edges)


_DEFAULT_EDGES = _default_edges()


class Histogram:
    """Fixed-bucket distribution with exact count/min/max/sum.

    Percentiles are interpolated inside the containing bucket, so they carry
    that bucket's width as error: 5 ms below 200 ms, 25 ms around the observed
    I2P RTT. min and max are exact and are not subject to bucketing, which
    matters because "maximum spike" is one of the numbers being optimised.
    """

    __slots__ = ("_edges", "_counts", "_over", "count", "_min", "_max", "_sum",
                 "_lock")

    def __init__(self, edges=_DEFAULT_EDGES):
        self._edges = tuple(edges)
        self._counts = [0] * len(self._edges)
        self._over = 0
        self.count = 0
        self._min = None
        self._max = None
        self._sum = 0.0
        self._lock = threading.Lock()

    def observe(self, value_ms) -> None:
        v = float(value_ms)
        if v != v:                       # NaN
            return
        with self._lock:
            self.count += 1
            self._sum += v
            if self._min is None or v < self._min:
                self._min = v
            if self._max is None or v > self._max:
                self._max = v
            edges = self._edges
            lo, hi = 0, len(edges)
            while lo < hi:                # bisect_left without the import
                mid = (lo + hi) // 2
                if edges[mid] < v:
                    lo = mid + 1
                else:
                    hi = mid
            if lo >= len(edges):
                self._over += 1
            else:
                self._counts[lo] += 1

    def percentile(self, q):
        """q in [0, 100]. None when nothing has been observed."""
        with self._lock:
            if self.count == 0:
                return None
            if q <= 0:
                return self._min
            if q >= 100:
                return self._max
            target = self.count * (q / 100.0)
            running = 0
            prev_edge = 0.0
            for i, c in enumerate(self._counts):
                if c:
                    if running + c >= target:
                        edge = self._edges[i]
                        # Linear inside the bucket. Clamped to the exact
                        # min/max so a percentile can never be reported
                        # outside the range actually observed.
                        frac = (target - running) / c
                        value = prev_edge + (edge - prev_edge) * frac
                        return min(max(value, self._min), self._max)
                    running += c
                prev_edge = self._edges[i]
            return self._max

    def snapshot(self) -> dict:
        with self._lock:
            count, mn, mx, total = self.count, self._min, self._max, self._sum
            over = self._over
        return {
            "count": count,
            "min_ms": mn,
            "max_ms": mx,
            "mean_ms": (total / count) if count else None,
            "p50_ms": self.percentile(50),
            "p95_ms": self.percentile(95),
            "p99_ms": self.percentile(99),
            "over_range": over,
        }

    def reset(self) -> None:
        with self._lock:
            self._counts = [0] * len(self._edges)
            self._over = 0
            self.count = 0
            self._min = self._max = None
            self._sum = 0.0


# ── JSONL sink ───────────────────────────────────────────────────────────────

class JsonlSink:
    """Append-only newline-delimited JSON, opened by the caller.

    Off unless a path is supplied. Created 0600: even numeric transport
    telemetry is traffic analysis material — frame counts and RTTs describe
    when a call happened and how long it lasted — so it is not world-readable
    and it is not written anywhere by default.
    """

    def __init__(self, path=None):
        self._fh = None
        self._lock = threading.Lock()
        self.path = path
        if path:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                         0o600)
            self._fh = os.fdopen(fd, "a", encoding="utf-8")

    @property
    def enabled(self) -> bool:
        return self._fh is not None

    def write(self, record: dict) -> None:
        if self._fh is None:
            return
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        with self._lock:
            try:
                self._fh.write(line + "\n")
                self._fh.flush()
            except OSError:
                pass

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None


# ── Transport health ─────────────────────────────────────────────────────────

HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
RECOVERING = "RECOVERING"
DISCONNECTED = "DISCONNECTED"


class TransportHealth:
    """Four-state transport health with hysteresis.

    The property that matters is the one stated in the brief: **one latency
    spike must not trigger reconnection.** I2P routinely delivers a single
    frame seconds late — a tunnel is being replaced, a peer is congested — and
    a transport that reconnects on that will reconnect during every call,
    each reconnect costing a fresh tunnel build (tens of seconds) and a
    guaranteed audio gap. Reconnecting is far more expensive than riding out
    the spike.

    So degradation is measured as *sustained* by construction:

      HEALTHY      -> DEGRADED      after `degrade_samples` consecutive bad
                                    observations, or `stall_seconds` with
                                    nothing received at all
      DEGRADED     -> RECOVERING    on the first good observation
      RECOVERING   -> HEALTHY       after `recover_samples` consecutive good
                                    ones (more than it took to degrade, so
                                    flapping settles into DEGRADED rather
                                    than oscillating)
      RECOVERING   -> DEGRADED      on a single bad observation
      any          -> DISCONNECTED  only on an explicit transport failure the
                                    caller reports; never inferred from
                                    latency

    Only DISCONNECTED is a reconnect trigger. DEGRADED is a signal to the UI
    and to the jitter buffer, not an instruction to tear down a working
    session.
    """

    def __init__(self, degrade_samples=5, recover_samples=10,
                 rtt_threshold_ms=4000.0, stall_seconds=6.0,
                 on_change=None, clock=time.monotonic):
        self.degrade_samples = int(degrade_samples)
        self.recover_samples = int(recover_samples)
        self.rtt_threshold_ms = float(rtt_threshold_ms)
        self.stall_seconds = float(stall_seconds)
        self._on_change = on_change
        self._clock = clock
        self._lock = threading.Lock()

        self.state = HEALTHY
        self._bad = 0
        self._good = 0
        self._last_progress = clock()
        self.transitions = 0
        self.time_in_state = {HEALTHY: 0.0, DEGRADED: 0.0,
                              RECOVERING: 0.0, DISCONNECTED: 0.0}
        self._state_since = self._last_progress

    # -- observations --------------------------------------------------

    def observe_rtt(self, rtt_ms) -> str:
        """One RTT sample. Returns the state after processing it."""
        if rtt_ms is None:
            return self.state
        return self._observe(float(rtt_ms) > self.rtt_threshold_ms)

    def note_progress(self) -> None:
        """Called whenever a frame arrives; resets the stall timer."""
        with self._lock:
            self._last_progress = self._clock()

    def tick(self) -> str:
        """Time-based check. A stream that has gone silent degrades even
        though no RTT sample will ever arrive to say so."""
        with self._lock:
            silent_for = self._clock() - self._last_progress
        if silent_for > self.stall_seconds:
            return self._observe(True)
        return self.state

    def note_failure(self) -> str:
        """An actual transport failure: socket closed, SAM error, EOF.

        This is the only path to DISCONNECTED. Latency, however bad, never
        reaches it.
        """
        return self._set(DISCONNECTED)

    def note_reconnected(self) -> str:
        with self._lock:
            self._bad = 0
            self._good = 0
            self._last_progress = self._clock()
        return self._set(RECOVERING)

    # -- machine -------------------------------------------------------

    def _observe(self, bad: bool) -> str:
        with self._lock:
            if bad:
                self._bad += 1
                self._good = 0
            else:
                self._good += 1
                self._bad = 0
            state = self.state
            bad_count, good_count = self._bad, self._good

        if state == DISCONNECTED:
            return state                       # only note_reconnected leaves

        if bad:
            if state == RECOVERING:
                return self._set(DEGRADED)
            if state == HEALTHY and bad_count >= self.degrade_samples:
                return self._set(DEGRADED)
            return state

        if state == DEGRADED:
            return self._set(RECOVERING)
        if state == RECOVERING and good_count >= self.recover_samples:
            return self._set(HEALTHY)
        return state

    def _set(self, new_state: str) -> str:
        with self._lock:
            if new_state == self.state:
                return self.state
            now = self._clock()
            self.time_in_state[self.state] = (
                self.time_in_state.get(self.state, 0.0)
                + (now - self._state_since))
            old = self.state
            self.state = new_state
            self._state_since = now
            self.transitions += 1
            # Counters are NOT reset here. The observation that caused this
            # transition still counts toward the next one: zeroing here made
            # DEGRADED -> RECOVERING -> HEALTHY need recover_samples + 1
            # consecutive good samples rather than recover_samples.
            callback = self._on_change
        if callback is not None:
            try:
                callback(old, new_state)
            except Exception:
                pass
        return new_state

    @property
    def should_reconnect(self) -> bool:
        """DEGRADED is not a reconnect trigger. Only real failure is."""
        return self.state == DISCONNECTED

    def snapshot(self) -> dict:
        with self._lock:
            now = self._clock()
            in_state = dict(self.time_in_state)
            in_state[self.state] = (in_state.get(self.state, 0.0)
                                    + (now - self._state_since))
            return {
                "state": self.state,
                "transitions": self.transitions,
                "seconds_healthy": round(in_state.get(HEALTHY, 0.0), 3),
                "seconds_degraded": round(in_state.get(DEGRADED, 0.0), 3),
                "seconds_recovering": round(in_state.get(RECOVERING, 0.0), 3),
                "seconds_disconnected": round(
                    in_state.get(DISCONNECTED, 0.0), 3),
            }


# ── Metrics container ────────────────────────────────────────────────────────

class TransportMetrics:
    """Counters, latency distributions and an event log for one call.

    Every method here is safe to call from any thread and from the event loop;
    the hot paths (`observe`, `incr`) take one uncontended lock and do no
    allocation beyond a float.
    """

    #: Series recorded as distributions rather than single numbers.
    SERIES = (
        "rtt",              # ping/pong round trip
        "oneway",           # frame timestamp to arrival, clock-corrected
        "interarrival",     # gap between consecutive received frames
        "jitter",           # |interarrival - 40 ms|
        "send_queue",       # seal -> handed to the event loop
        "socket_write",     # event loop callback -> transport.write returned
        "recv_to_decode",   # socket read -> authenticated and queued
        "jitter_depth",     # frames resident in the jitter buffer
        "xmpp_stanza",      # local bridge write -> drained toward SAM
    )

    def __init__(self, call_tag="00000000", peer_tag="00000000", role="unknown",
                 sink=None, clock=time.monotonic):
        self.call_tag = call_tag
        self.peer_tag = peer_tag
        self.role = role if role in _ENUM_VALUES else "unknown"
        self.sink = sink if sink is not None else JsonlSink(None)
        self._clock = clock
        self._t0 = clock()
        self._lock = threading.Lock()
        self._counters = {}
        self._hist = {name: Histogram() for name in self.SERIES}
        self.events = []
        self._max_events = 512

    # -- counters ------------------------------------------------------

    def incr(self, name: str, by: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + int(by)

    def get(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    # -- distributions -------------------------------------------------

    def observe(self, series: str, value_ms) -> None:
        hist = self._hist.get(series)
        if hist is None:
            raise KeyError("unknown telemetry series %r" % (series,))
        hist.observe(value_ms)

    def histogram(self, series: str) -> Histogram:
        return self._hist[series]

    # -- events --------------------------------------------------------

    def event(self, name: str, **fields) -> None:
        """Record one transport event. `name` must be in EVENT_NAMES.

        Field values pass through the same guard as everything else, so an
        event cannot smuggle a string past the numeric-only rule.
        """
        if name not in EVENT_NAMES:
            raise TelemetryValueError(
                "unknown telemetry event %r; add it to EVENT_NAMES "
                "deliberately rather than passing a free-form string" % (name,))
        record = {
            "t": round(self._clock() - self._t0, 3),
            "event": name,
            "call": self.call_tag,
            "peer": self.peer_tag,
        }
        for key, value in fields.items():
            record[str(key)] = _check_value(key, value)
        with self._lock:
            self.events.append(record)
            if len(self.events) > self._max_events:
                del self.events[:len(self.events) - self._max_events]
        self.sink.write(record)

    # -- readout -------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            counters = dict(self._counters)
        out = {
            "call": self.call_tag,
            "peer": self.peer_tag,
            "role": self.role,
            "elapsed_s": round(self._clock() - self._t0, 3),
            "counters": counters,
        }
        for name in self.SERIES:
            snap = self._hist[name].snapshot()
            if snap["count"]:
                out[name] = snap
        return out

    def write_snapshot(self) -> None:
        if self.sink.enabled:
            record = self.snapshot()
            record["event"] = "session_close"
            self.sink.write(record)
