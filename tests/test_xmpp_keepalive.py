"""Keepalive must notice a stream that is dead but still writable.

`send_raw(" ")` writes into the local socket buffer. It succeeds whether or
not anything is still listening at the far end, and over I2P that is not a
corner case: the SAM stream can be gone while the local socket keeps
accepting writes indefinitely.

A whitespace-only keepalive therefore reports a healthy stream forever. The
failure counter never moves, `_on_disconnected` never fires, reconnect never
runs, and the session dies silently -- the first symptom being the peer
appearing to go offline while this side still believes it is connected.
That is the failure observed on a long call.

A XEP-0199 ping requires the server to answer, so it proves the whole path
rather than the first hop of it. These tests cover the distinction and the
consequences.
"""

import asyncio
import sys
import types

import pytest


def _client_class():
    """Import the client without requiring slixmpp to be installed."""
    slix = pytest.importorskip("slixmpp")          # noqa: F841
    import otrv4plus_xmpp
    return otrv4plus_xmpp


xmpp = _client_class()


class _FakeClient:
    """Only the surface `_keepalive_loop` and `_probe_stream` touch."""

    KEEPALIVE_WHITESPACE_S = xmpp.OTRv4PlusXMPP.KEEPALIVE_WHITESPACE_S
    KEEPALIVE_PING_S = xmpp.OTRv4PlusXMPP.KEEPALIVE_PING_S
    KEEPALIVE_PING_TIMEOUT_S = xmpp.OTRv4PlusXMPP.KEEPALIVE_PING_TIMEOUT_S
    KEEPALIVE_PING_FAILS = xmpp.OTRv4PlusXMPP.KEEPALIVE_PING_FAILS
    KEEPALIVE_QUIET_S = xmpp.OTRv4PlusXMPP.KEEPALIVE_QUIET_S

    _probe_stream = xmpp.OTRv4PlusXMPP._probe_stream
    _declare_stream_dead = xmpp.OTRv4PlusXMPP._declare_stream_dead
    _keepalive_loop = xmpp.OTRv4PlusXMPP._keepalive_loop
    _note_inbound = xmpp.OTRv4PlusXMPP._note_inbound
    _stream_quiet_for = xmpp.OTRv4PlusXMPP._stream_quiet_for

    def __init__(self, ping_result="ok", writable=True, delivering=False):
        self._shutting_down = False
        # A dead stream delivers nothing, so by default the fake is silent
        # and the probe path is reachable. `delivering=True` models a stream
        # that is carrying traffic, which is what a live call looks like.
        self._delivering = delivering
        self._last_inbound = (xmpp.time.monotonic() if delivering
                              else xmpp.time.monotonic() - 10_000)
        self._connected = True
        self._keepalive_ticks = 0
        self._keepalive_last_ok = None
        self._keepalive_degraded = False
        self._keepalive_pings = 0
        self._keepalive_ping_fails = 0
        self._keepalive_timeouts = 0        # lifetime, survives reconnects
        self._reconnects_started = 0
        self._reconnects_completed = 0
        self.raw_writes = 0
        self.disconnected = 0
        self._ping_result = ping_result
        self._writable = writable
        self.boundjid = types.SimpleNamespace(host="example.i2p")

    # -- surface used by the loop --------------------------------------
    def is_connected(self):
        return self._connected

    def send_raw(self, data):
        if not self._writable:
            raise OSError("socket is gone")
        self.raw_writes += 1
        if self._delivering:
            # Stand-in for the server's own traffic arriving between ticks.
            self._last_inbound = xmpp.time.monotonic()

    def disconnect(self):
        self.disconnected += 1
        self._connected = False
        return None

    def __getitem__(self, key):
        assert key == "xep_0199"
        outer = self

        class _Ping:
            async def async_ping(self, jid, timeout=None):
                outer._keepalive_ping_calls = getattr(
                    outer, "_keepalive_ping_calls", 0) + 1
                if outer._ping_result == "ok":
                    return 0.05
                if outer._ping_result == "timeout":
                    raise xmpp.IqTimeout(None)
                if outer._ping_result == "error":
                    # IqError.__init__ reads condition, text AND type. A
                    # partial stub raises KeyError from the constructor
                    # instead, which the probe would classify as dead -- so
                    # the fixture has to supply all three.
                    raise xmpp.IqError({"error": {
                        "condition": "service-unavailable",
                        "text": "",
                        "type": "cancel"}})
                raise RuntimeError("boom")

        return _Ping()


def _run(coro, timeout=5.0):
    return asyncio.run(asyncio.wait_for(coro, timeout))


class TestProbeDistinguishesAliveFromDead:
    def test_a_reply_means_alive(self):
        client = _FakeClient(ping_result="ok")
        assert _run(client._probe_stream()) is True

    def test_an_iq_error_still_means_alive(self):
        # A server answering `service-unavailable` has proven the stream
        # works, which is the only thing being asked. Treating it as death
        # would reconnect against a perfectly good session.
        client = _FakeClient(ping_result="error")
        assert _run(client._probe_stream()) is True

    def test_a_timeout_means_dead(self):
        client = _FakeClient(ping_result="timeout")
        assert _run(client._probe_stream()) is False

    def test_an_unexpected_failure_means_dead(self):
        client = _FakeClient(ping_result="boom")
        assert _run(client._probe_stream()) is False


class TestDeadButWritableStreamIsDetected:
    """The whole point. Whitespace succeeds; the server is gone anyway."""

    def _drive(self, client, monkeypatch, ticks):
        """Run the loop with sleeps and the clock collapsed."""
        now = {"t": 1000.0}

        async def _sleep(_seconds):
            now["t"] += client.KEEPALIVE_WHITESPACE_S
            if client._keepalive_ticks >= ticks:
                client._shutting_down = True

        monkeypatch.setattr(asyncio, "sleep", _sleep)
        monkeypatch.setattr(xmpp.time, "monotonic", lambda: now["t"])
        _run(client._keepalive_loop())

    def test_whitespace_alone_would_never_notice(self, monkeypatch):
        # Establishes the premise: the socket takes every write happily even
        # though the far end is answering nothing.
        client = _FakeClient(ping_result="timeout", writable=True)
        self._drive(client, monkeypatch, ticks=40)
        assert client.raw_writes > 0, "the socket accepted writes throughout"

    def test_the_round_trip_declares_the_stream_dead(self, monkeypatch):
        client = _FakeClient(ping_result="timeout", writable=True)
        self._drive(client, monkeypatch, ticks=200)
        assert client._keepalive_ping_fails >= client.KEEPALIVE_PING_FAILS
        assert client.disconnected == 1, (
            "a dead stream must actually be taken down, or reconnect never "
            "runs and the session dies silently")

    def test_a_healthy_stream_is_never_taken_down(self, monkeypatch):
        client = _FakeClient(ping_result="ok", writable=True)
        self._drive(client, monkeypatch, ticks=200)
        assert client.disconnected == 0
        assert client._keepalive_ping_fails == 0
        assert client._keepalive_last_ok is not None

    def test_a_server_returning_errors_is_never_taken_down(self, monkeypatch):
        client = _FakeClient(ping_result="error", writable=True)
        self._drive(client, monkeypatch, ticks=200)
        assert client.disconnected == 0

    def test_a_socket_that_stops_accepting_writes_is_taken_down(self, monkeypatch):
        client = _FakeClient(ping_result="ok", writable=False)
        self._drive(client, monkeypatch, ticks=40)
        assert client.disconnected == 1


class TestCadence:
    def test_the_round_trip_is_less_frequent_than_the_whitespace(self):
        # Whitespace is cheap and only keeps the tunnel warm; a round trip
        # costs a server exchange and does not need to be as frequent.
        cls = xmpp.OTRv4PlusXMPP
        assert cls.KEEPALIVE_PING_S > cls.KEEPALIVE_WHITESPACE_S

    def test_the_stream_is_declared_dead_before_a_rekey_would_be_missed(self):
        # Rekeys ride XMPP every VOICE_REKEY_SECONDS. Detection has to be
        # quicker than that or a call loses an epoch before anyone notices.
        import otrv4plus_voice as voice
        cls = xmpp.OTRv4PlusXMPP
        worst_case = cls.KEEPALIVE_PING_S * cls.KEEPALIVE_PING_FAILS
        assert worst_case <= voice.VOICE_REKEY_SECONDS * 2, (
            "worst-case detection %ds against a %ds rekey interval"
            % (worst_case, voice.VOICE_REKEY_SECONDS))

    def test_the_ping_timeout_tolerates_a_busy_event_loop(self):
        # Media shares this loop, so a reply can be late because the loop is
        # busy rather than because the server is gone. Treating a busy loop
        # as a dead server would drop a healthy call.
        cls = xmpp.OTRv4PlusXMPP
        assert cls.KEEPALIVE_PING_TIMEOUT_S >= 10


class TestCallsSurviveTheControlPlane:
    def test_declaring_the_stream_dead_does_not_touch_calls(self, capsys):
        # Media rides its own I2P datagram session. Only rekey signalling
        # uses XMPP, and an undeliverable rekey already fails safe by keeping
        # the committed epoch.
        client = _FakeClient()
        client._voice_manager = object()          # must not be consulted
        client._declare_stream_dead("test")
        assert client.disconnected == 1
        out = capsys.readouterr().out
        assert "call" in out.lower(), (
            "the operator needs to be told the call keeps running")


# ---------------------------------------------------------------------------
# Regression: the live call on da691d1
# ---------------------------------------------------------------------------

class TestFailureCountIsPerSession:
    """The tolerance of three must survive a reconnect.

    Measured on a live I2P call: the counter is cleared only by a SUCCESSFUL
    probe, so after the first genuine detection it stayed at the threshold.
    Every reconnect then began one failure away from the limit and a single
    missed ping disconnected immediately -- three became one.

    The trace showed 3, then 4, then 5 unanswered round trips, with a
    reconnect roughly every 96 s. That period is the ping interval plus the
    timeout plus the sleep granularity, i.e. ONE failed probe: the pattern
    was the loop's own signature rather than anything the network did.
    """

    def _drive(self, client, monkeypatch, budget_s):
        """Run one loop instance on a virtual clock until it disconnects."""
        now = {"t": getattr(client, "_sim_now", 0.0)}
        deadline = now["t"] + budget_s

        async def _sleep(seconds):
            now["t"] += seconds
            if now["t"] > deadline:
                client._shutting_down = True

        monkeypatch.setattr(asyncio, "sleep", _sleep)
        monkeypatch.setattr(xmpp.time, "monotonic", lambda: now["t"])
        _run(client._keepalive_loop())
        client._sim_now = now["t"]
        return now["t"]

    def test_a_reconnect_restores_the_full_tolerance(self, monkeypatch):
        client = _FakeClient(ping_result="timeout")
        client._sim_now = 0.0

        self._drive(client, monkeypatch, budget_s=600)
        first = client._keepalive_ping_fails
        assert first == client.KEEPALIVE_PING_FAILS, (
            "first detection should take the full tolerance")

        # Reconnect: _on_start builds a fresh loop against a fresh stream.
        client._connected = True
        client._shutting_down = False
        probes_before = client._keepalive_pings
        self._drive(client, monkeypatch, budget_s=600)

        assert client._keepalive_ping_fails == client.KEEPALIVE_PING_FAILS, (
            "counter carried over: %d" % client._keepalive_ping_fails)
        assert client._keepalive_pings - probes_before >= 2, (
            "second detection used only %d probe(s) -- the tolerance "
            "collapsed" % (client._keepalive_pings - probes_before))

    def test_the_counter_does_not_climb_across_reconnects(self, monkeypatch):
        # The live signature: 3, 4, 5. It must stay 3, 3, 3.
        client = _FakeClient(ping_result="timeout")
        client._sim_now = 0.0
        seen = []
        for _ in range(3):
            client._connected = True
            client._shutting_down = False
            self._drive(client, monkeypatch, budget_s=600)
            seen.append(client._keepalive_ping_fails)
        assert seen == [client.KEEPALIVE_PING_FAILS] * 3, seen

    def test_the_degraded_flag_also_starts_clean(self, monkeypatch):
        # Otherwise the "responding again" notice is suppressed on the
        # session that actually recovered.
        client = _FakeClient(ping_result="timeout")
        client._sim_now = 0.0
        self._drive(client, monkeypatch, budget_s=600)
        assert client._keepalive_degraded is True

        client._connected = True
        client._shutting_down = False
        client._ping_result = "ok"
        self._drive(client, monkeypatch, budget_s=200)
        assert client._keepalive_degraded is False


class TestNoDuplicateLoops:
    def test_starting_the_keepalive_cancels_any_predecessor(self):
        # Two loops probing one stream reach the threshold in half the time,
        # because they share the counter.
        source = open(xmpp.__file__, encoding="utf-8").read()
        start = source.index("Whitespace keepalive to maintain")
        window = source[start:start + 700]
        assert "existing.cancel()" in window

    def test_every_path_schedules_through_one_guarded_entry_point(self):
        # Behavioural, not a source grep: _on_disconnected and
        # _on_connection_failed both fire during a failed reconnect attempt,
        # and _on_connection_failed used to schedule WITHOUT recording the
        # task -- invisible to the other's guard. Two loops with independent
        # backoffs then both called connect(), and on I2P built two SAM
        # forwarders for one session.
        import asyncio as _a

        class Sched:
            _schedule_reconnect = xmpp.OTRv4PlusXMPP._schedule_reconnect
            _has_transport_params = xmpp.OTRv4PlusXMPP._has_transport_params
            _on_disconnected = xmpp.OTRv4PlusXMPP._on_disconnected
            _on_connection_failed = xmpp.OTRv4PlusXMPP._on_connection_failed
            _clear_peer_gone = xmpp.OTRv4PlusXMPP._clear_peer_gone

            def __init__(self):
                self._shutting_down = False
                self._sam_params = {"server_b32": "x.b32.i2p"}
                self._tor_params = None
                self._reconnect_task = None
                self._password_prompt = None
                self._keepalive_task = None
                self._password_prompt = None
                self._peer_gone_at = {}
                self.started = 0

            async def _reconnect(self):
                self.started += 1
                await _a.sleep(3600)      # still running

        async def _drive():
            s = Sched()
            s._on_disconnected(None)          # first: schedules
            s._on_connection_failed(None)     # second: must NOT duplicate
            s._on_disconnected(None)          # third: must NOT duplicate
            await _a.sleep(0)
            task = s._reconnect_task
            task.cancel()
            return s.started

        assert _run(_drive()) == 1

    def test_a_reconnect_is_scheduled_once_the_previous_one_finished(self):
        # The guard must not wedge the client permanently after a completed
        # attempt.
        import asyncio as _a

        class Sched:
            _schedule_reconnect = xmpp.OTRv4PlusXMPP._schedule_reconnect
            _has_transport_params = xmpp.OTRv4PlusXMPP._has_transport_params

            def __init__(self):
                self._shutting_down = False
                self._sam_params = {"server_b32": "x.b32.i2p"}
                self._tor_params = None
                self._reconnect_task = None
                self._password_prompt = None
                self.started = 0

            async def _reconnect(self):
                self.started += 1

        async def _drive():
            s = Sched()
            s._schedule_reconnect("first")
            await _a.sleep(0)
            await _a.sleep(0)
            s._schedule_reconnect("second")
            await _a.sleep(0)
            await _a.sleep(0)
            return s.started

        assert _run(_drive()) == 2

    def test_shutdown_stops_any_further_reconnect(self):
        class Sched:
            _schedule_reconnect = xmpp.OTRv4PlusXMPP._schedule_reconnect
            _has_transport_params = xmpp.OTRv4PlusXMPP._has_transport_params

            def __init__(self):
                self._shutting_down = True
                self._sam_params = {"server_b32": "x.b32.i2p"}
                self._tor_params = None
                self._reconnect_task = None
                self._password_prompt = None

            async def _reconnect(self):
                raise AssertionError("scheduled during shutdown")

        Sched()._schedule_reconnect("quit")

    def test_no_transport_parameters_means_no_reconnect(self):
        # "We do not know how to reconnect" must mean "stay down", never
        # "reconnect somehow" -- the direct-connect branch would expose the
        # address of an I2P or Tor session.
        class Sched:
            _schedule_reconnect = xmpp.OTRv4PlusXMPP._schedule_reconnect
            _has_transport_params = xmpp.OTRv4PlusXMPP._has_transport_params

            def __init__(self):
                self._shutting_down = False
                self._sam_params = None
                self._tor_params = None
                self._reconnect_task = None
                self._password_prompt = None

            async def _reconnect(self):
                raise AssertionError("scheduled with no transport")

        Sched()._schedule_reconnect("no params")


class TestMediaSurvivesTheWholeCycle:
    """The live call's most valuable result: audio continued through
    reconnects. Nothing in this fix may change that."""

    def test_declaring_dead_and_reconnecting_never_touches_the_voice_manager(self):
        source = open(xmpp.__file__, encoding="utf-8").read()
        for name in ("def _declare_stream_dead", "def _on_disconnected",
                     "async def _reconnect"):
            start = source.index(name)
            body = source[start:start + 1600]
            assert "_voice_manager" not in body, (
                "%s must not touch the voice manager -- media rides its own "
                "I2P datagram session" % name)

    def test_the_keepalive_loop_never_touches_media_state(self):
        # Checked against the parsed body, not the text. A first attempt
        # grepped the source and tripped over the docstring, which mentions
        # SMP legitimately -- prose is not a control-flow property.
        import ast
        import inspect
        import textwrap
        # getsource returns the method still indented inside its class.
        tree = ast.parse(textwrap.dedent(
            inspect.getsource(xmpp.OTRv4PlusXMPP._keepalive_loop)))
        touched = {node.attr for node in ast.walk(tree)
                   if isinstance(node, ast.Attribute)}
        for name in touched:
            assert "voice" not in name.lower(), name
            assert "ratchet" not in name.lower(), name
            assert "epoch" not in name.lower(), name


# ---------------------------------------------------------------------------
# Traffic outranks a slow ping
# ---------------------------------------------------------------------------

def _run_loop(client, ticks, monkeypatch=None):
    """Run the real keepalive loop with sleeps and the clock collapsed.

    The clock advances by one whitespace interval per tick, so the quiet
    window and the probe cadence are exercised at their real proportions.
    """
    import asyncio as _a
    now = {"t": 1000.0}
    real_sleep = _a.sleep
    real_monotonic = xmpp.time.monotonic
    # Rebase whatever the caller set onto the collapsed clock, rather than
    # overwriting it: a test that fed the client a stanza must keep that
    # evidence, or it proves nothing about _note_inbound.
    age = max(0.0, real_monotonic() - client._last_inbound)
    client._last_inbound = now["t"] - age

    async def _sleep(_seconds):
        now["t"] += client.KEEPALIVE_WHITESPACE_S
        if client._keepalive_ticks >= ticks:
            client._shutting_down = True

    _a.sleep = _sleep
    xmpp.time.monotonic = lambda: now["t"]
    try:
        _run(client._keepalive_loop())
    finally:
        _a.sleep = real_sleep
        xmpp.time.monotonic = real_monotonic


class TestALiveStreamIsNeverDeclaredDead:
    """The regression that produced ten self-inflicted disconnects.

    The first version of this keepalive probed every 60 s and scored a slow
    reply as a failure. Measured on a 33-minute call: in one case a rekey
    completed a full REKEY -> REKEYACK -> REKEYCOMMIT round trip through the
    server 3.2 s before the keepalive declared that same stream dead on "3
    round trips in a row went unanswered" -- a verdict that needs about three
    minutes of failed pings to accumulate. The stream was carrying
    bidirectional traffic for the whole window in which it was scored dead.

    The cause was already written down in this project before the keepalive
    existed, in VoiceCallManager's docstring: an IQ round trip over three I2P
    hops frequently exceeds the reply timeout. XEP-0199 is an IQ round trip.

    So traffic is the evidence and the probe is the fallback. These tests pin
    that ordering.
    """

    def test_a_stream_delivering_traffic_is_never_probed(self):
        # The probe is what was producing false verdicts, so on a healthy
        # stream it must not even be reached.
        client = _FakeClient(ping_result="timeout", delivering=True)
        _run_loop(client, ticks=40)
        assert client._keepalive_pings == 0, "probed a stream that was live"
        assert client.disconnected == 0

    def test_traffic_arriving_clears_an_outstanding_failure(self):
        client = _FakeClient(ping_result="timeout")
        client._keepalive_ping_fails = client.KEEPALIVE_PING_FAILS - 1
        client._keepalive_degraded = True
        client._delivering = True
        client._last_inbound = xmpp.time.monotonic()
        _run_loop(client, ticks=6)
        assert client._keepalive_ping_fails == 0
        assert client._keepalive_degraded is False
        assert client.disconnected == 0

    def test_a_rekey_round_trip_would_have_saved_the_stream(self):
        """Exactly the live sequence: probes failing, then a rekey lands.

        The evidence goes in through _note_inbound, the real filter, so this
        fails if inbound stanzas stop being recorded at all.
        """
        client = _FakeClient(ping_result="timeout")
        client._keepalive_ping_fails = client.KEEPALIVE_PING_FAILS - 1
        client._keepalive_degraded = True
        client._note_inbound(object())          # REKEYACK arrives
        _run_loop(client, ticks=4)
        assert client.disconnected == 0, (
            "a stream that had just carried a rekey was declared dead")
        assert client._keepalive_ping_fails == 0, (
            "the rekey did not clear the outstanding failure")

    def test_the_filter_is_what_supplies_the_evidence(self):
        # Without _note_inbound updating the clock, a stream carrying traffic
        # looks silent and the probe path is reached anyway.
        client = _FakeClient(ping_result="timeout")
        client._last_inbound = xmpp.time.monotonic() - 10_000
        for _ in range(5):
            client._note_inbound(object())
        assert client._stream_quiet_for() < 1.0, (
            "inbound stanzas are not being recorded")

    def test_a_genuinely_silent_stream_is_still_taken_down(self):
        # The other half: this must not become a keepalive that never fires.
        client = _FakeClient(ping_result="timeout")
        _run_loop(client, ticks=200)
        assert client.disconnected == 1
        assert client._keepalive_ping_fails >= client.KEEPALIVE_PING_FAILS

    def test_the_quiet_window_sits_above_the_rekey_interval(self):
        # A call rekeys every VOICE_REKEY_SECONDS, and that signalling is
        # inbound traffic. If the window were shorter, a healthy call would
        # probe -- and probing is what went wrong.
        import otrv4plus_voice as voice
        assert xmpp.OTRv4PlusXMPP.KEEPALIVE_QUIET_S > voice.VOICE_REKEY_SECONDS

    def test_the_ping_timeout_is_sized_for_i2p_not_a_lan(self):
        assert xmpp.OTRv4PlusXMPP.KEEPALIVE_PING_TIMEOUT_S >= 60

    def test_the_filter_never_drops_a_stanza(self):
        # slixmpp DROPS any stanza an inbound filter returns None for, so a
        # careless filter here would silently eat the conversation it exists
        # to protect.
        client = _FakeClient()
        for stanza in (object(), "presence", 0, "", None):
            assert client._note_inbound(stanza) is stanza

    def test_the_filter_is_registered_for_inbound_stanzas(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.__init__)
        assert 'add_filter("in", self._note_inbound)' in src

    def test_an_unanswered_probe_during_traffic_is_not_counted(self):
        # The narrow race: the probe times out, but something arrived while
        # we were waiting for it.
        client = _FakeClient(ping_result="timeout")
        client._last_inbound = xmpp.time.monotonic() - 10_000

        async def _probe_then_traffic():
            client._last_inbound = xmpp.time.monotonic()
            return False

        client._probe_stream = _probe_then_traffic
        _run_loop(client, ticks=30)
        assert client._keepalive_ping_fails == 0
        assert client.disconnected == 0
