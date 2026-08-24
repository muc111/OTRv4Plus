"""Inbound media that stops must be noticed, classified, and acted on.

Media rode SAM STYLE=STREAM until 892ef7a. That commit made the reader task
conditional on the stream writer:

    -   self._reader_task = asyncio.ensure_future(self._network_reader())
    +   if self._writer is not None:
    +       self._reader_task = asyncio.ensure_future(self._network_reader())

_network_reader was the only caller of _signal_stream_lost for the receive
path, and it got its liveness signal for free from stream EOF. A datagram has
no EOF, so datagram calls have had no inbound liveness detection at all --
not a weak one, none. A receive path that stopped delivering could not be
noticed, because nothing was watching.

Observed on a 33-minute live call: inbound audio and inbound probe replies
both stopped at t=1418s and never resumed, while the call stayed ACTIVE and
transmitted for another 9.5 minutes. `sent` kept climbing because a datagram
handed to the local SAM bridge is accepted whether or not the session behind
it still exists -- so the transmit side can never detect this.

These tests cover the watchdog, the counter that makes the failure
classifiable, and the boundaries either side of "act".
"""

import asyncio
import socket
import types

import pytest

import otrv4plus_voice as V


def _run(coro, timeout=5.0):
    return asyncio.run(asyncio.wait_for(coro, timeout))


class _Session:
    """The real liveness methods over the minimum state they touch."""

    _rx_watchdog = V.VoiceCallSession._rx_watchdog
    _rx_idle_seconds = V.VoiceCallSession._rx_idle_seconds
    _rx_diagnosis = V.VoiceCallSession._rx_diagnosis
    _sam_control_state = V.VoiceCallSession._sam_control_state
    _signal_stream_lost = V.VoiceCallSession._signal_stream_lost
    _on_datagram = V.VoiceCallSession._on_datagram

    def __init__(self, sam_control=None):
        self._running = True
        self.stats = V.new_media_stats()
        self._rx_last_datagram = None
        self._rx_last_frame = None
        self._rx_degraded = False
        self._sam_control = sam_control
        self._peer_dest = None
        self._foreign_warned = True
        self._loss_signalled = False
        self._closing = False
        self.on_stream_lost = None
        self.peer = "alice@example.i2p"
        self.call_id = bytes(range(16))
        self.lost = []
        # The real _signal_stream_lost dispatches through the loop, so the
        # fake loop must actually invoke the callback rather than record the
        # arguments -- otherwise the test asserts on a tuple and would pass
        # even if the reason were never built.
        self.loop = types.SimpleNamespace(
            call_soon_threadsafe=lambda cb, *a: cb(*a))

    def _drain_buffer(self, buf):
        pass                       # parsing is covered elsewhere

    def age_rx(self, seconds):
        """Backdate both stamps so the path looks idle for `seconds`."""
        now = asyncio.get_event_loop().time
        base = V.time.monotonic() - seconds
        self._rx_last_frame = base
        self._rx_last_datagram = base


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    """Run the watchdog at test speed without changing its logic."""
    monkeypatch.setattr(V, "VOICE_RX_CHECK_S", 0.01)


def _session(**kw):
    s = _Session(**kw)
    s.on_stream_lost = lambda peer, call_id, why: s.lost.append(why)
    return s


async def _tick(session, rounds=4):
    task = asyncio.ensure_future(session._rx_watchdog())
    for _ in range(rounds):
        await asyncio.sleep(V.VOICE_RX_CHECK_S * 1.5)
        if task.done():
            break
    if not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    return task


# ---------------------------------------------------------------------------
# 1. thresholds
# ---------------------------------------------------------------------------

class TestThresholds:

    def test_the_dead_horizon_matches_the_projects_existing_one(self):
        assert V.VOICE_RX_DEAD_S == float(V.VOICE_REKEY_TIMEOUT)

    def test_warn_comes_before_dead(self):
        assert V.VOICE_RX_WARN_S < V.VOICE_RX_DEAD_S

    def test_the_worst_measured_stall_would_not_trip_it(self):
        # The old stream transport stalled to 24 s one-way and recovered.
        # Ending a call on that would be a regression, not a fix.
        assert V.VOICE_RX_DEAD_S > 24.0

    def test_a_normal_loss_burst_is_far_below_the_warning(self):
        # The jitter buffer's own ceiling is the scale of a tolerable burst.
        assert V.VOICE_RX_WARN_S * 1000.0 > V.VOICE_JITTER_MAX_MS * 3


# ---------------------------------------------------------------------------
# 2. healthy media is left alone
# ---------------------------------------------------------------------------

class TestHealthyMediaIsUntouched:

    def test_a_live_path_is_never_declared_lost(self):
        async def _drive():
            s = _session()
            s._rx_last_frame = V.time.monotonic()
            s._rx_last_datagram = s._rx_last_frame
            await _tick(s)
            return s

        s = _run(_drive())
        assert s.lost == []
        assert s._rx_degraded is False

    def test_a_short_gap_does_not_warn(self):
        async def _drive():
            s = _session()
            s.age_rx(V.VOICE_RX_WARN_S - 1.0)
            await _tick(s)
            return s

        assert _run(_drive()).lost == []

    def test_before_audio_starts_there_is_nothing_to_judge(self):
        async def _drive():
            s = _session()                     # stamps still None
            await _tick(s)
            return s

        s = _run(_drive())
        assert s.lost == []
        assert s._rx_degraded is False


# ---------------------------------------------------------------------------
# 3. sustained loss is noticed, then acted on
# ---------------------------------------------------------------------------

class TestSustainedLoss:

    def test_a_sustained_gap_warns(self):
        async def _drive():
            s = _session()
            s.age_rx(V.VOICE_RX_WARN_S + 1.0)
            await _tick(s)
            return s

        s = _run(_drive())
        assert s._rx_degraded is True
        assert s.lost == [], "warned and ended on the same gap"

    def test_the_warning_is_issued_once_not_per_tick(self):
        # The old debug-only message printed 116 times in one outage.
        async def _drive():
            s = _session()
            s.age_rx(V.VOICE_RX_WARN_S + 1.0)
            printed = []
            V._HOST["print"] = lambda *a: printed.append(" ".join(map(str, a)))
            try:
                await _tick(s, rounds=6)
            finally:
                V._HOST["print"] = print
            return [p for p in printed if "no inbound audio" in p]

        assert len(_run(_drive())) == 1

    def test_a_dead_path_is_declared_lost(self):
        async def _drive():
            s = _session()
            s.age_rx(V.VOICE_RX_DEAD_S + 1.0)
            await _tick(s)
            return s

        s = _run(_drive())
        assert len(s.lost) == 1
        assert "no media received" in s.lost[0]

    def test_the_watchdog_stops_once_it_has_acted(self):
        # Otherwise it would signal loss on every subsequent tick.
        async def _drive():
            s = _session()
            s.age_rx(V.VOICE_RX_DEAD_S + 1.0)
            task = await _tick(s, rounds=6)
            return s, task

        s, task = _run(_drive())
        assert task.done() and not task.cancelled()
        assert len(s.lost) == 1

    def test_recovery_clears_the_degraded_state(self):
        async def _drive():
            s = _session()
            s.age_rx(V.VOICE_RX_WARN_S + 1.0)
            task = asyncio.ensure_future(s._rx_watchdog())
            await asyncio.sleep(V.VOICE_RX_CHECK_S * 2)
            degraded = s._rx_degraded
            s._rx_last_frame = V.time.monotonic()      # media returns
            await asyncio.sleep(V.VOICE_RX_CHECK_S * 2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return degraded, s._rx_degraded

        was, now = _run(_drive())
        assert was is True and now is False

    def test_no_false_recovery_while_packets_are_still_absent(self):
        async def _drive():
            s = _session()
            s.age_rx(V.VOICE_RX_WARN_S + 1.0)
            await _tick(s, rounds=3)
            return s

        assert _run(_drive())._rx_degraded is True


# ---------------------------------------------------------------------------
# 4. the counter that makes the failure classifiable
# ---------------------------------------------------------------------------

class TestRawArrivalCounter:

    def _datagram(self, session, data):
        session._on_datagram(data)

    def test_every_arrival_is_counted_before_any_filter(self):
        s = _session()
        self._datagram(s, b"anything at all")
        assert s.stats["dgram_in"] == 1

    def test_an_arrival_after_shutdown_is_still_counted(self):
        s = _session()
        s._running = False
        self._datagram(s, b"late one")
        assert s.stats["dgram_in"] == 1
        assert s.stats["dgram_closed"] == 1

    def test_an_empty_payload_is_counted_rather_than_vanishing(self):
        s = _session()
        self._datagram(s, b"")
        assert s.stats["dgram_in"] == 1
        assert s.stats["dgram_empty"] == 1

    def test_a_foreign_source_is_still_counted_as_an_arrival(self):
        s = _session()
        s._peer_dest = "B" * 80
        self._datagram(s, ("A" * 80).encode() + b"\npayload")
        assert s.stats["dgram_in"] == 1
        assert s.stats["foreign"] == 1

    def test_arrival_stamps_the_transport_clock(self):
        s = _session()
        self._datagram(s, b"x")
        assert s._rx_last_datagram is not None

    def test_an_arrival_does_not_stamp_the_authenticated_clock(self):
        # Only a frame that opens counts as media. Otherwise a flood of junk
        # would keep a dead call looking alive.
        s = _session()
        self._datagram(s, b"junk that never authenticates")
        assert s._rx_last_frame is None


# ---------------------------------------------------------------------------
# 4b. the authenticated clock, driven through the real receive path
# ---------------------------------------------------------------------------

CALL_ID = bytes(range(16))
ROOT = bytes(range(32)) * (V.ROOT_LEN // 32)
PEER_DEST = "A" * 516


def _real_receiver():
    """A session with a real key schedule, real jitter buffer, real parser.

    The fakes above stub _drain_buffer, so nothing in them can prove that an
    authenticated frame advances the media clock -- a test over that fake
    passes whether or not the stamp exists. This drives the genuine path:
    split -> source filter -> parse -> AEAD -> stamp -> unpad -> jitter.
    """
    import threading

    s = object.__new__(V.VoiceCallSession)
    s._running = True
    s.stats = V.new_media_stats()
    s._peer_dest = PEER_DEST
    s._foreign_warned = True
    s._rx_last_datagram = None
    s._rx_last_frame = None
    s._rx_degraded = False
    s._key_lock = threading.RLock()
    s._call_t0 = V.time.monotonic()
    s.stages = V.StageTimers()
    s.latency = V.LatencyTracker()
    s.jitter = V.JitterBuffer()
    s.schedule = V.VoiceKeySchedule(CALL_ID, False)      # we are the responder
    s.schedule.install_initial(ROOT)
    # The peer's cipher: same root and epoch, opposite role, so its send keys
    # are the ones our receive keys expect.
    s._peer_cipher = V.VoiceFrameCrypto(bytearray(ROOT), CALL_ID, 0, True)
    return s


def _peer_datagram(session, frame_type=V.FRAME_TYPE_AUDIO, opus=b"\x01\x02\x03"):
    padded = V.pad_opus(opus, send_ts_ms=1)
    packet = session._peer_cipher.seal(padded, frame_type=frame_type)
    return PEER_DEST.encode() + b"\n" + packet


class TestTheAuthenticatedClock:

    def test_a_genuine_frame_advances_the_media_clock(self):
        s = _real_receiver()
        s._on_datagram(_peer_datagram(s))
        assert s.stats["recv"] == 1, "the real receive path did not accept it"
        assert s._rx_last_frame is not None

    def test_an_authenticated_probe_also_counts_as_liveness(self):
        # PONGs are inbound media too. During the live failure the probe
        # replies died in the same instant as the audio, so a watchdog that
        # only watched audio would be watching half the evidence.
        s = _real_receiver()
        s.latency.handle_pong = lambda payload: None
        s._on_datagram(_peer_datagram(s, frame_type=V.FRAME_TYPE_PONG))
        assert s._rx_last_frame is not None
        assert s.stats["recv"] == 0, "a PONG is not audio"

    def test_junk_never_advances_the_media_clock(self):
        s = _real_receiver()
        s._on_datagram(PEER_DEST.encode() + b"\n" + b"\xa7" + b"\x00" * 300)
        assert s._rx_last_frame is None
        assert s.stats["dgram_in"] == 1

    def test_a_frame_that_fails_authentication_does_not_advance_it(self):
        s = _real_receiver()
        data = bytearray(_peer_datagram(s))
        data[-1] ^= 0xFF                       # corrupt the GCM tag
        s._on_datagram(bytes(data))
        assert s._rx_last_frame is None
        assert s.stats["auth_fail"] == 1
        assert s.stats["dgram_in"] == 1

    def test_a_foreign_source_does_not_advance_it(self):
        s = _real_receiver()
        data = _peer_datagram(s)
        s._on_datagram(("B" * 516).encode() + b"\n" + data.split(b"\n", 1)[1])
        assert s._rx_last_frame is None
        assert s.stats["foreign"] == 1

    def test_the_clock_advances_again_on_the_next_frame(self):
        s = _real_receiver()
        s._on_datagram(_peer_datagram(s))
        first = s._rx_last_frame
        s._rx_last_frame = first - 10.0        # pretend time passed
        s._on_datagram(_peer_datagram(s))
        assert s._rx_last_frame > first - 10.0

    def test_a_stream_of_junk_cannot_keep_a_dead_call_looking_alive(self):
        # The transport clock moves, the media clock does not, and the
        # watchdog judges on the media clock.
        s = _real_receiver()
        for _ in range(20):
            s._on_datagram(PEER_DEST.encode() + b"\n" + b"garbage")
        assert s._rx_last_datagram is not None
        assert s._rx_last_frame is None
        assert s._rx_idle_seconds() is None


# ---------------------------------------------------------------------------
# 5. classification -- the first failing stage, named
# ---------------------------------------------------------------------------

class TestDiagnosis:

    def test_nothing_arriving_is_named_as_such(self):
        s = _session()
        s._rx_last_frame = V.time.monotonic() - 60
        s._rx_last_datagram = s._rx_last_frame
        assert "no media datagrams are arriving" in s._rx_diagnosis()

    def test_arriving_but_not_authenticating_is_named_differently(self):
        s = _session()
        s._rx_last_frame = V.time.monotonic() - 60
        s._rx_last_datagram = V.time.monotonic()
        text = s._rx_diagnosis()
        assert "arriving but none authenticate" in text
        assert "no media datagrams are arriving" not in text

    def test_a_closed_sam_session_is_reported(self):
        a, b = socket.socketpair()
        b.close()                                  # peer hangs up
        s = _session(sam_control=a)
        s._rx_last_frame = V.time.monotonic() - 60
        s._rx_last_datagram = s._rx_last_frame
        try:
            assert "SAM session is gone" in s._rx_diagnosis()
        finally:
            a.close()

    def test_an_open_sam_session_is_reported_as_open(self):
        a, b = socket.socketpair()
        s = _session(sam_control=a)
        s._rx_last_frame = V.time.monotonic() - 60
        s._rx_last_datagram = s._rx_last_frame
        try:
            assert "SAM control socket open" in s._rx_diagnosis()
        finally:
            a.close()
            b.close()

    def test_the_probe_never_blocks_and_never_consumes(self):
        a, b = socket.socketpair()
        b.send(b"HELLO REPLY\n")
        s = _session(sam_control=a)
        try:
            assert s._sam_control_state() == "open"
            assert a.recv(11) == b"HELLO REPLY", "the probe ate the stream"
        finally:
            a.close()
            b.close()

    def test_a_broken_socket_is_unknown_not_an_exception(self):
        s = _session(sam_control=types.SimpleNamespace())
        assert s._sam_control_state() == "unknown"

    def test_no_sam_control_is_unknown(self):
        assert _session()._sam_control_state() == "unknown"


# ---------------------------------------------------------------------------
# 6. wiring and resource safety
# ---------------------------------------------------------------------------

class TestWiring:

    def test_the_watchdog_starts_in_both_transport_modes(self):
        import inspect
        src = inspect.getsource(V.VoiceCallSession.start_audio)
        assert "_rx_watchdog()" in src
        # It must NOT be inside the stream-only branch that hid the reader.
        head, _, tail = src.partition("if self._writer is not None:")
        assert "_rx_watchdog()" in tail.split("\n", 2)[2] or \
            "_rx_watchdog()" in tail, "watchdog is stream-only"
        for line in tail.split("\n"):
            if "_rx_watchdog()" in line:
                assert not line.startswith("            "), \
                    "watchdog is nested under the stream-only branch"

    def test_the_stamps_are_primed_when_audio_starts(self):
        # Left at None the watchdog would never judge anything.
        import inspect
        src = inspect.getsource(V.VoiceCallSession.start_audio)
        assert "_rx_last_frame = now" in src
        assert "_rx_last_datagram = now" in src

    def test_teardown_cancels_the_watchdog(self):
        import inspect
        src = inspect.getsource(V.VoiceCallSession.end)
        assert "_rx_watchdog_task" in src

    def test_loss_goes_through_the_existing_signal(self):
        # _handle_stream_lost already ends the call and tells the peer, and
        # is already bound to the call_id. A second teardown path would be a
        # second thing to get wrong.
        import inspect
        src = inspect.getsource(V.VoiceCallSession._rx_watchdog)
        assert "_signal_stream_lost" in src

    def test_the_watchdog_exits_when_the_session_stops(self):
        async def _drive():
            s = _session()
            s._rx_last_frame = V.time.monotonic()
            s._rx_last_datagram = s._rx_last_frame
            task = asyncio.ensure_future(s._rx_watchdog())
            await asyncio.sleep(V.VOICE_RX_CHECK_S)
            s._running = False
            await asyncio.sleep(V.VOICE_RX_CHECK_S * 3)
            done = task.done()
            if not done:
                task.cancel()
            return done

        assert _run(_drive()) is True, "the watchdog outlived the call"

    def test_cancellation_is_not_swallowed(self):
        async def _drive():
            s = _session()
            s._rx_last_frame = V.time.monotonic()
            s._rx_last_datagram = s._rx_last_frame
            task = asyncio.ensure_future(s._rx_watchdog())
            await asyncio.sleep(V.VOICE_RX_CHECK_S)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                return True
            return False

        assert _run(_drive()) is True

    def test_the_counters_reach_the_telemetry(self):
        import inspect
        src = inspect.getsource(V.VoiceCallManager._stats_loop)
        assert "dg=%d" in src
        assert 'delta.get("dgram_in", 0)' in src


class TestStatKeys:

    def test_a_session_carries_every_declared_counter(self):
        assert set(V.new_media_stats()) == set(V.MEDIA_STAT_KEYS)

    def test_the_new_counters_are_declared(self):
        for name in ("dgram_in", "dgram_empty", "dgram_closed"):
            assert name in V.MEDIA_STAT_KEYS
