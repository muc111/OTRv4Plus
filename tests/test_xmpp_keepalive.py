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

    _probe_stream = xmpp.OTRv4PlusXMPP._probe_stream
    _declare_stream_dead = xmpp.OTRv4PlusXMPP._declare_stream_dead
    _keepalive_loop = xmpp.OTRv4PlusXMPP._keepalive_loop

    def __init__(self, ping_result="ok", writable=True):
        self._shutting_down = False
        self._connected = True
        self._keepalive_ticks = 0
        self._keepalive_last_ok = None
        self._keepalive_degraded = False
        self._keepalive_pings = 0
        self._keepalive_ping_fails = 0
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
