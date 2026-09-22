# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Being logged in is not the same as being present.

REPORTED FROM A HANDSET
-----------------------
A Termux user logged in as alice watched `[presence] bob@... went offline`
repeat while bob was sitting in the app, connected and authenticated. Her
message never left: `[queued] will send once OTR with bob is ready`.

Three separate faults, all of them omissions rather than mistakes:

1. **No initial presence.** RFC 6121 §4.2: a client becomes an available
   resource by SENDING presence. Until it does, the server neither broadcasts
   it to contacts nor delivers theirs. The app authenticated and stayed
   invisible -- to everyone, permanently, with nothing on either side saying
   why. The terminal client has sent it from `_on_start` since the beginning.

2. **No roster fetch.** `OtrApp.contacts()` reads
   `transport.roster()`, which reads `client_roster`, which slixmpp fills from
   the reply to `get_roster()`. Nobody called it, so the contact list was
   empty and adding somebody appeared to do nothing.

3. **No presence wiring.** `XmppTransport` has always emitted `on_presence`;
   `ConnectionController` never passed a callback, so `OtrApp._presence`
   stayed empty and every contact rendered "offline" regardless of what the
   server said.

And a fourth that would have undone the first three within minutes:

4. **No keepalive.** The terminal client's own comment on this is exact:
   writing to the socket succeeds whether or not anything is listening at the
   far end, so over I2P "a whitespace-only keepalive reports a healthy stream
   forever ... the session dies silently and the first symptom is the peer
   appearing to go offline". The app had neither whitespace nor a round trip.
"""

import asyncio
import time

import pytest

import android_bridge.transport as transport_module
from android_bridge.settings import ConnectionProfile
from android_bridge.transport import (
    KEEPALIVE_PING_FAILS,
    KEEPALIVE_PING_S,
    KEEPALIVE_PING_TIMEOUT_S,
    KEEPALIVE_WHITESPACE_S,
    XmppTransport,
)

JID = "alice@xmpp-elite.i2p"
SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"
PEER = "bob@xmpp-elite.i2p"


class FakePing:
    """slixmpp's xep_0199 plugin, as much of it as the probe uses.

    The method is `ping`, which is what slixmpp 1.17 has. It used to be
    `async_ping`, and THAT IS WHY THE BUG SURVIVED THIS FILE: the production
    code called `async_ping`, the real plugin had no such method, and the fake
    obligingly provided one. Every test here passed against an API that does
    not exist.

    `test_the_fake_matches_the_real_plugin` now pins the two together.
    """

    def __init__(self, answer=True):
        self.answer = answer
        self.calls = []

    async def ping(self, target, timeout=None):
        self.calls.append((target, timeout))
        if self.answer is True:
            return 0.01
        if self.answer == "error":
            raise IqErrorLookalike()
        raise asyncio.TimeoutError()


class IqErrorLookalike(Exception):
    """Named IqError, because that is what the probe checks for.

    It checks the NAME rather than importing slixmpp's class, so that a
    transport module which must not import slixmpp at module scope can still
    tell "the server said no" from "the server said nothing". This stands in
    for it without dragging slixmpp into the test.
    """


IqErrorLookalike.__name__ = "IqError"


class FakeBoundJid:
    host = "xmpp-elite.i2p"
    full = JID + "/resource"


class FakeClient:
    def __init__(self, jid, password, *, ping=None):
        self.handlers = {}
        #: (direction, fn) pairs, as slixmpp's add_filter records them. The
        #: transport installs an "in" filter to note that the stream
        #: delivered something, which is the keepalive's primary evidence.
        self.filters = []
        self.presence_sent = 0
        self.roster_requested = 0
        self.raw = []
        self.disconnects = 0
        #: `_abandon` prefers `abort()` -- the call that also ends slixmpp's
        #: retry loop -- and falls back to `disconnect()`. Both are counted so
        #: these tests can ask "was the stream stopped?" rather than pinning
        #: whichever call the teardown happens to make.
        self.aborts = 0
        self.boundjid = FakeBoundJid()
        self.client_roster = {}
        self._plugins = {"xep_0199": ping if ping is not None else FakePing()}

    def __getitem__(self, key):
        return self._plugins[key]

    def add_event_handler(self, name, fn):
        self.handlers.setdefault(name, []).append(fn)

    def add_filter(self, direction, fn, order=None):
        self.filters.append((direction, fn))

    def fire(self, name, arg=None):
        for fn in list(self.handlers.get(name, [])):
            fn(arg)

    def connect(self, host=None, port=None):
        self.fire("session_start", None)

    def send_presence(self, **_kw):
        self.presence_sent += 1

    def get_roster(self, **_kw):
        self.roster_requested += 1

    def send_raw(self, data):
        self.raw.append(data)

    def send_message(self, **_kw):
        pass

    def disconnect(self, *_a, **_kw):
        self.disconnects += 1

    def abort(self, *_a, **_kw):
        self.aborts += 1

    @property
    def stopped(self):
        """Whether the stream was ended, by either route."""
        return (self.disconnects + self.aborts) > 0


def build(*, ping=None, connect_now=True):
    made = {}

    def factory(jid, password):
        made["client"] = FakeClient(jid, password, ping=ping)
        return made["client"]

    async def forwarder(*_a, **_kw):
        return ("127.0.0.1", 41234)

    made["presence"] = []
    transport = XmppTransport(
        ConnectionProfile(jid=JID, server=SERVER), "pw",
        on_payload=lambda *a: None,
        on_presence=lambda peer, online: made["presence"].append((peer, online)),
        client_factory=factory,
        forwarder=forwarder,
    )
    made["transport"] = transport
    if connect_now:
        transport.connect()
    return transport, made


class TestTheAppAnnouncesItself:
    """Fault 1. The whole reported symptom is downstream of this."""

    def test_initial_presence_is_sent(self):
        transport, made = build()
        assert made["client"].presence_sent == 1, (
            "no initial presence, so the server never marks this resource "
            "available and every contact sees the account as offline -- "
            "permanently, which is exactly what was reported")
        transport.close()

    def test_the_roster_is_requested(self):
        transport, made = build()
        assert made["client"].roster_requested == 1, (
            "without this client_roster stays empty, so the contact list is "
            "empty and adding someone appears to do nothing")
        transport.close()

    def test_presence_comes_before_the_roster(self):
        """Cheap ordering, and the order the terminal client uses: presence is
        one stanza and is what makes the account visible; the roster is a
        round trip."""
        import inspect

        source = inspect.getsource(XmppTransport._announce)
        assert source.index("send_presence") < source.index("get_roster")

    def test_a_server_that_refuses_the_roster_does_not_fail_the_connection(self):
        """A roster fetch that fails has not ended the session, and treating
        it as a connection failure throws away a stream that works."""
        transport, made = build(connect_now=False)

        def explode(**_kw):
            raise RuntimeError("no roster for you")

        original_factory = transport._client_factory

        def factory(jid, password):
            client = original_factory(jid, password)
            client.get_roster = explode
            return client

        transport._client_factory = factory
        transport.connect()
        assert transport.is_connected
        transport.close()

    def test_announcing_is_survivable_without_a_client(self):
        transport, _made = build(connect_now=False)
        transport._announce()          # must not raise
        transport.close()


class TestPresenceReachesTheApp:
    """Fault 3. The transport always emitted this; nobody listened."""

    def test_an_available_presence_is_reported(self):
        transport, made = build()
        made["client"].fire("presence_available", {"from": PEER + "/phone"})
        assert made["presence"] == [(PEER, True)]
        transport.close()

    def test_an_unavailable_presence_is_reported(self):
        transport, made = build()
        made["client"].fire("presence_unavailable", {"from": PEER + "/phone"})
        assert made["presence"] == [(PEER, False)]
        transport.close()

    def test_the_controller_wires_it_to_the_app(self):
        """The gap was here: XmppTransport took `on_presence` and
        ConnectionController never passed one."""
        import inspect

        from android_bridge.connection import ConnectionController

        source = inspect.getsource(ConnectionController._connect)
        assert "on_presence=" in source, (
            "the controller builds a transport with no presence callback, so "
            "OtrApp._presence stays empty and every contact renders offline")
        assert "note_presence" in source

    def test_otrapp_still_has_the_method_the_controller_hands_over(self):
        from android_bridge.app import OtrApp

        assert callable(getattr(OtrApp, "note_presence", None))


class TestTheKeepalive:
    """Fault 4. Without it the other three fixes last until the tunnel idles."""

    def test_it_starts_when_the_session_does(self):
        transport, _made = build()
        assert transport._keepalive_task is not None
        assert not transport._keepalive_task.done()
        transport.close()

    def test_it_stops_on_teardown(self):
        transport, _made = build()
        task = transport._keepalive_task
        transport.close()
        _settle(lambda: task.cancelled() or task.done())
        assert task.cancelled() or task.done(), (
            "a keepalive outliving its session probes a stream that is gone")

    def test_a_second_session_does_not_leave_two_loops(self):
        """Reassigning instead of cancelling orphans a live loop; two then
        probe the same stream and count the same failures, hitting the
        threshold in half the time. Documented in the terminal client.

        Driven through a real reconnect rather than by calling `_announce`
        from here. The first version of this test called it directly from the
        test thread, which is not where it runs -- `ensure_future` then reached
        for a loop that did not exist and the task sat in `cancelling` because
        nothing was running to deliver the cancellation. Two artefacts of a
        test doing something production never does.
        """
        transport, _made = build()
        first = transport._keepalive_task
        transport.disconnect()
        transport.connect()               # a second session, on the loop thread
        second = transport._keepalive_task
        assert first is not second, "the keepalive task was reused"
        assert _settle(lambda: first.cancelled() or first.done()), (
            "the first loop is still running alongside the second")
        transport.close()

    def test_whitespace_goes_out_on_the_tick(self, monkeypatch):
        monkeypatch.setattr(transport_module, "KEEPALIVE_WHITESPACE_S", 0.01)
        monkeypatch.setattr(transport_module, "KEEPALIVE_PING_S", 999)
        transport, made = build()
        assert _settle(lambda: len(made["client"].raw) >= 3), (
            "no whitespace, so an idle I2P tunnel is torn down mid-DAKE")
        assert all(chunk == " " for chunk in made["client"].raw)
        transport.close()

    def test_a_round_trip_is_made(self, monkeypatch):
        monkeypatch.setattr(transport_module, "KEEPALIVE_WHITESPACE_S", 0.01)
        monkeypatch.setattr(transport_module, "KEEPALIVE_PING_S", 0.0)
        monkeypatch.setattr(transport_module, "KEEPALIVE_QUIET_S", 0.0)
        ping = FakePing(answer=True)
        transport, _made = build(ping=ping)
        assert _settle(lambda: ping.calls), (
            "whitespace only. Writing to the socket succeeds whether or not "
            "anything is listening, so this reports a healthy stream forever")
        assert ping.calls[0][0] == "xmpp-elite.i2p"
        transport.close()

    def test_a_server_that_answers_an_error_counts_as_alive(self, monkeypatch):
        """`service-unavailable` proves the stream works, which is the only
        thing being asked. Treating it as death reconnects a good session."""
        monkeypatch.setattr(transport_module, "KEEPALIVE_WHITESPACE_S", 0.01)
        monkeypatch.setattr(transport_module, "KEEPALIVE_PING_S", 0.0)
        monkeypatch.setattr(transport_module, "KEEPALIVE_QUIET_S", 0.0)
        ping = FakePing(answer="error")
        transport, made = build(ping=ping)
        assert _settle(lambda: len(ping.calls) >= 3)
        assert not made["client"].stopped, (
            "an IqError was treated as a dead stream")
        transport.close()

    def test_repeated_silence_takes_the_stream_down(self, monkeypatch):
        """Breaking out of the loop only stops pinging. Something has to end
        the session, or the UI shows a connection that cannot carry a
        message and the user retries into silence."""
        monkeypatch.setattr(transport_module, "KEEPALIVE_WHITESPACE_S", 0.01)
        monkeypatch.setattr(transport_module, "KEEPALIVE_PING_S", 0.0)
        monkeypatch.setattr(transport_module, "KEEPALIVE_QUIET_S", 0.0)
        ping = FakePing(answer="timeout")
        transport, made = build(ping=ping)
        assert _settle(lambda: made["client"].stopped), (
            "the stream never answered and was never declared dead")
        assert not transport.is_connected
        transport.close()

    def test_one_missed_ping_is_tolerated(self, monkeypatch):
        """A single missed round trip over I2P is ordinary."""
        assert KEEPALIVE_PING_FAILS >= 2

    def test_a_missing_ping_plugin_does_not_manufacture_a_disconnect(
            self, monkeypatch):
        monkeypatch.setattr(transport_module, "KEEPALIVE_WHITESPACE_S", 0.01)
        monkeypatch.setattr(transport_module, "KEEPALIVE_PING_S", 0.0)
        monkeypatch.setattr(transport_module, "KEEPALIVE_QUIET_S", 0.0)
        transport, made = build()
        made["client"]._plugins.clear()
        time.sleep(0.2)
        assert not made["client"].stopped, (
            "a missing plugin was reported as a dead stream")
        transport.close()

    def test_the_default_client_registers_the_ping_plugin(self):
        """Without it `_probe_stream` has nothing to ping with and reports
        alive unconditionally -- which is the failure the round trip exists
        to detect."""
        import inspect

        source = inspect.getsource(transport_module._default_client_factory)
        assert 'register_plugin("xep_0199")' in source


class TestTheIntervalsMatchTheTerminalClient:
    """Bound to the originals so the two clients cannot drift into
    disagreeing about how long a silent I2P tunnel may stay silent."""

    @staticmethod
    @pytest.fixture(scope="class")
    def terminal():
        xmpp = pytest.importorskip(
            "otrv4plus_xmpp", reason="slixmpp not installed")
        return xmpp.OTRv4PlusXMPP

    def test_whitespace(self, terminal):
        assert KEEPALIVE_WHITESPACE_S == terminal.KEEPALIVE_WHITESPACE_S

    def test_ping_interval(self, terminal):
        assert KEEPALIVE_PING_S == terminal.KEEPALIVE_PING_S

    def test_ping_timeout(self, terminal):
        assert KEEPALIVE_PING_TIMEOUT_S == terminal.KEEPALIVE_PING_TIMEOUT_S

    def test_failure_threshold(self, terminal):
        assert KEEPALIVE_PING_FAILS == terminal.KEEPALIVE_PING_FAILS


class TestTheKeepaliveIsQuiet:
    """A heartbeat line every 8s reports nothing after the second one and
    buries the conversation it exists to protect."""

    def test_nothing_is_printed(self, monkeypatch, capsys):
        monkeypatch.setattr(transport_module, "KEEPALIVE_WHITESPACE_S", 0.01)
        monkeypatch.setattr(transport_module, "KEEPALIVE_PING_S", 0.0)
        monkeypatch.setattr(transport_module, "KEEPALIVE_QUIET_S", 0.0)
        transport, _made = build()
        time.sleep(0.2)
        transport.close()
        assert capsys.readouterr().out == ""

    def test_the_peer_is_not_logged(self, monkeypatch, caplog):
        """Who this device pings is its own server, but a subscription
        request names a peer and logcat is world-readable."""
        import logging

        from android_bridge.connection import ConnectionController

        caplog.set_level(logging.DEBUG)
        ConnectionController._on_subscription_request(
            object(), "mallory@elsewhere.i2p")
        assert "mallory" not in caplog.text


class TestTheFakeCannotDriftFromSlixmppAgain:
    """The reason the handset bug reached a user.

    `FakePing` exposed `async_ping`. The real `XEP_0199` does not have it --
    it was removed upstream in favour of `ping`. Production called the absent
    method, the fake supplied it, and every keepalive test in this file passed
    while the shipped code could not ping at all.

    A fake that offers an API the real thing lacks does not test anything; it
    tests itself.
    """

    def test_the_fake_only_offers_methods_the_real_plugin_has(self):
        slixmpp = pytest.importorskip("slixmpp")
        from slixmpp.plugins.xep_0199.ping import XEP_0199

        offered = {name for name in dir(FakePing)
                   if not name.startswith("_") and name != "answer"
                   and callable(getattr(FakePing, name, None))}
        missing = {name for name in offered if not hasattr(XEP_0199, name)}
        assert not missing, (
            "FakePing offers %s, which slixmpp's XEP_0199 does not have. "
            "A probe written against it would fail on a real handset."
            % ", ".join(sorted(missing)))

    def test_the_probe_reaches_the_real_plugin_api(self):
        """Executed, not asserted about: the shared helper must find a method
        on the REAL class and it must be awaitable."""
        import inspect

        import otrv4plus_ping as _ping
        pytest.importorskip("slixmpp")
        from slixmpp.plugins.xep_0199.ping import XEP_0199

        name, fn = _ping.ping_method(XEP_0199)
        assert name is not None
        assert inspect.iscoroutinefunction(fn)


class TestTrafficOutranksAPing:
    """The gate the terminal client had and this transport did not.

    Anything the stream delivers proves the whole path end to end, without
    asking the server for something. While it is arriving there is nothing
    worth probing -- and a probe whose reply is merely slow, ordinary over
    three I2P hops, must not be read as silence.

    Its absence is why the broken ping killed Android sessions and never
    Termux ones: an active Termux conversation never reached the probe.
    """

    def test_a_delivering_stream_is_not_probed_at_all(self, monkeypatch):
        monkeypatch.setattr(transport_module, "KEEPALIVE_WHITESPACE_S", 0.01)
        monkeypatch.setattr(transport_module, "KEEPALIVE_PING_S", 0.0)
        # The gate left at its real value, so recent traffic suppresses it.
        ping = FakePing(answer="timeout")
        transport, made = build(ping=ping)
        time.sleep(0.3)
        assert not ping.calls, (
            "the stream was delivering and got probed anyway")
        assert not made["client"].stopped
        transport.close()

    def test_a_quiet_stream_is_probed(self, monkeypatch):
        monkeypatch.setattr(transport_module, "KEEPALIVE_WHITESPACE_S", 0.01)
        monkeypatch.setattr(transport_module, "KEEPALIVE_PING_S", 0.0)
        monkeypatch.setattr(transport_module, "KEEPALIVE_QUIET_S", 0.0)
        ping = FakePing(answer=True)
        transport, _made = build(ping=ping)
        assert _settle(lambda: ping.calls), (
            "silence is the one case the round trip exists for")
        transport.close()

    def test_an_inbound_stanza_resets_the_quiet_clock(self):
        transport, _made = build()
        transport._last_inbound -= 500
        assert transport._stream_quiet_for() > 400
        transport._note_inbound(object())
        assert transport._stream_quiet_for() < 1
        transport.close()

    def test_the_filter_returns_the_stanza_unchanged(self):
        """A slixmpp inbound filter that returns None DISCARDS the stanza.
        Getting this wrong would drop every message on the floor."""
        transport, _made = build()
        stanza = object()
        assert transport._note_inbound(stanza) is stanza
        transport.close()

    def test_the_filter_is_installed_on_the_client(self):
        transport, made = build()
        assert any(direction == "in"
                   for direction, _fn in made["client"].filters), (
            "nothing records inbound traffic, so the keepalive is back to "
            "probing a busy stream")
        transport.close()


def _settle(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(0.02)
    return False
