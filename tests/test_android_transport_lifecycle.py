# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What a connection attempt owns, and whether it gives it back.

Every test here was written against a reproduction first. The four faults, all
verified on this branch before the fix:

1. **A connect that timed out kept everything.** slixmpp's `_connect_loop`
   reschedules a failed connection rather than giving up, so the client went on
   dialling; the SAM tunnel and the local listening socket stayed open because
   the forwarder parks them on `loop._i2p_keep`, which has no release. Pressing
   Connect again built a second set on top. Measured: `abort` 0, `disconnect`
   0, sockets open, `_client` still set.

2. **A closed transport could be reopened by accident.** `close()` cleared
   `_loop` but left `_client`, so the next call went through `_ensure_loop` and
   got a brand new worker thread that nothing would ever join. Measured: one
   live `otrv4plus-transport` thread after a `disconnect()` following a
   `close()`. On Android there is always a next call -- the chat screen polls
   every 500ms and shutdown races it.

3. **Cancellation was reported as an unexpected error.** `asyncio.CancelledError`
   and `concurrent.futures.CancelledError` are different classes on 3.12, and
   only one of them derives from `Exception`. Catching either alone gets the
   wrong half.

4. **There was no way to cancel at all.** The Kotlin coroutine wrapping the
   connect can be cancelled, but the call into Python is a blocking JNI call
   and the thread stays inside it. A rotation during a cold tunnel build left
   the old attempt running while the recreated screen started a second one.

None of this is theoretical on a handset: a cold I2P tunnel is 30-90 seconds,
which is long enough for a user to rotate the phone, press Back, or give up and
press Connect again.
"""

import asyncio
import threading
import time

import pytest

from android_bridge.settings import ConnectionProfile
from android_bridge.transport import (
    CLOSE_TIMEOUT,
    TransportError,
    XmppTransport,
    _accepts,
    _forwarder_log,
)
import android_bridge.transport as transport_module

JID = "alice@xmpp-elite.i2p"
SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"
PASSWORD = "correct-horse-battery-staple"

#: How long to let a background thread finish before calling it stuck. The
#: work is all local and event-driven; this is slack, not a rate.
SETTLE = 5.0


class FakeSocket:
    """Something the forwarder handed over that must be closed again."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeClient:
    """A slixmpp client that records how it was stopped.

    `completes` decides whether `connect` reaches `session_start`. False models
    the real hang: slixmpp keeps retrying and neither `session_start` nor
    `failed_auth` ever fires.
    """

    completes = False

    def __init__(self, jid, password):
        self.jid = jid
        self.password = password
        self.handlers = {}
        self.aborted = 0
        self.disconnected = 0
        self.client_roster = {}

    def add_event_handler(self, name, fn):
        self.handlers.setdefault(name, []).append(fn)

    def fire(self, name, arg=None):
        for fn in list(self.handlers.get(name, [])):
            fn(arg)

    def connect(self, host=None, port=None):
        self.connected_to = (host, port)
        if self.completes:
            self.fire("session_start", None)

    def abort(self, *_a, **_kw):
        self.aborted += 1

    def disconnect(self, *_a, **_kw):
        self.disconnected += 1

    def send_message(self, **_kw):
        pass


class CompletingClient(FakeClient):
    completes = True


class Harness:
    """A transport plus what its forwarder handed over."""

    def __init__(self, *, completes=False, forwarder=None):
        self.clients = []
        self.tunnels = []
        self.logged = []
        cls = CompletingClient if completes else FakeClient

        def factory(jid, password):
            client = cls(jid, password)
            self.clients.append(client)
            return client

        async def forward(dest, port, sam_host, sam_port,
                          resources=None, log=None):
            sockets = [FakeSocket() for _ in range(3)]
            self.tunnels.append(sockets)
            if resources is not None:
                resources.extend(sockets)
            if log is not None:
                log("[i2p] opening SAM stream to %s "
                    "(a cold tunnel can take 30-90s)..." % dest)
            return ("127.0.0.1", 41234)

        self.transport = XmppTransport(
            ConnectionProfile(jid=JID, server=SERVER), PASSWORD,
            on_payload=lambda *a: None,
            client_factory=factory,
            forwarder=forwarder if forwarder is not None else forward,
        )

    @property
    def client(self):
        return self.clients[-1]

    def tunnel_closed(self, index=-1):
        return all(s.closed for s in self.tunnels[index])

    def stopped(self):
        """Whether the client was told to stop dialling, by either route."""
        return (self.client.aborted + self.client.disconnected) > 0


def worker_threads():
    return [t for t in threading.enumerate()
            if t.name == "otrv4plus-transport" and t.is_alive()]


@pytest.fixture
def no_leaked_threads():
    """Fail a test that leaves a worker behind, rather than the next one."""
    before = set(worker_threads())
    yield
    deadline = time.time() + SETTLE
    while time.time() < deadline:
        leaked = set(worker_threads()) - before
        if not leaked:
            return
        time.sleep(0.05)
    leaked = set(worker_threads()) - before
    assert not leaked, "left %d worker thread(s) running" % len(leaked)


@pytest.fixture
def short_connect_timeout():
    """A connect budget measured in a test's patience, not a tunnel's."""
    original = transport_module.CONNECT_TIMEOUT
    transport_module.CONNECT_TIMEOUT = 1.0
    yield
    transport_module.CONNECT_TIMEOUT = original


class TestAFailedAttemptGivesEverythingBack:
    """Fault 1. The state after a failure decides whether a retry can work."""

    def test_a_timed_out_connect_stops_the_client_dialling(
            self, short_connect_timeout, no_leaked_threads):
        h = Harness()
        with pytest.raises(TransportError) as caught:
            h.transport.connect()
        assert caught.value.code == "timeout"
        _settle(lambda: h.stopped())
        assert h.stopped(), (
            "slixmpp was left retrying: _connect_loop reschedules a failed "
            "connection, so a client nobody stops dials for the life of the "
            "process")
        h.transport.close()

    def test_a_timed_out_connect_closes_the_tunnel(
            self, short_connect_timeout, no_leaked_threads):
        h = Harness()
        with pytest.raises(TransportError):
            h.transport.connect()
        _settle(lambda: h.tunnel_closed())
        assert h.tunnel_closed(), (
            "the I2P tunnel and the local listening socket were left open; "
            "the next Connect would build a second set on top")
        h.transport.close()

    def test_a_timed_out_connect_forgets_the_client(
            self, short_connect_timeout, no_leaked_threads):
        """A half-dead client that a later call could find and believe."""
        h = Harness()
        with pytest.raises(TransportError):
            h.transport.connect()
        _settle(lambda: h.transport._client is None)
        assert h.transport._client is None
        assert not h.transport.is_connected
        h.transport.close()

    def test_a_second_attempt_does_not_stack_on_the_first(
            self, short_connect_timeout, no_leaked_threads):
        """The point of all of the above, stated as the behaviour it buys."""
        h = Harness()
        for _ in range(2):
            with pytest.raises(TransportError):
                h.transport.connect()
        _settle(lambda: len(h.tunnels) == 2 and h.tunnel_closed(0))
        assert len(h.tunnels) == 2, "expected one tunnel per attempt"
        assert h.tunnel_closed(0), "the first attempt's tunnel outlived it"
        _settle(lambda: h.tunnel_closed(1))
        assert h.tunnel_closed(1)
        h.transport.close()

    def test_a_forwarder_that_fails_is_still_a_clean_failure(
            self, no_leaked_threads):
        async def refuses(*_a, **_kw):
            raise OSError("no router")

        h = Harness(forwarder=refuses)
        with pytest.raises(TransportError) as caught:
            h.transport.connect()
        assert caught.value.code == "sam_unavailable"
        assert not h.transport.is_connected
        h.transport.close()

    def test_the_failure_detail_still_carries_no_exception_message(
            self, no_leaked_threads):
        """The teardown path must not become a new way to leak one."""
        async def refuses(*_a, **_kw):
            raise OSError("connect to 127.0.0.1:7656 failed for alice")

        h = Harness(forwarder=refuses)
        with pytest.raises(TransportError) as caught:
            h.transport.connect()
        assert "alice" not in caught.value.detail
        assert "7656" not in caught.value.detail
        assert "OSError" in caught.value.detail
        h.transport.close()


class TestCancellingAnAttempt:
    """Faults 3 and 4. A cold tunnel is long enough to change your mind in."""

    def test_a_cancelled_connect_reports_cancelled(self, no_leaked_threads):
        h = Harness()
        outcome = _connect_in_background(h.transport)
        _settle(lambda: len(h.tunnels) == 1)
        h.transport.cancel()
        outcome.thread.join(timeout=SETTLE)
        assert not outcome.thread.is_alive(), "connect never returned"
        assert outcome.code == "cancelled", (
            "cancelled came back as %r. asyncio.CancelledError and "
            "concurrent.futures.CancelledError are different classes and only "
            "one derives from Exception, so catching either alone gets the "
            "wrong half." % outcome.code)
        h.transport.close()

    def test_cancelling_closes_the_tunnel(self, no_leaked_threads):
        h = Harness()
        outcome = _connect_in_background(h.transport)
        _settle(lambda: len(h.tunnels) == 1)
        h.transport.cancel()
        outcome.thread.join(timeout=SETTLE)
        _settle(lambda: h.tunnel_closed())
        assert h.tunnel_closed(), (
            "backing out of a tunnel build left the tunnel building")
        h.transport.close()

    def test_cancelling_stops_the_client_dialling(self, no_leaked_threads):
        h = Harness()
        outcome = _connect_in_background(h.transport)
        _settle(lambda: len(h.tunnels) == 1)
        h.transport.cancel()
        outcome.thread.join(timeout=SETTLE)
        _settle(lambda: h.stopped())
        assert h.stopped()
        h.transport.close()

    def test_cancelling_when_nothing_is_running_is_harmless(self):
        h = Harness()
        h.transport.cancel()          # never connected
        h.transport.close()
        h.transport.cancel()          # and after close

    def test_the_two_cancelled_errors_really_are_different_classes(self):
        """The fact the fix turns on, asserted so a refactor cannot forget it.

        If these ever became the same class this test would fail and the
        tuple in the transport could be simplified. Until then, naming one is
        a bug that only shows up as a mislabelled outcome.
        """
        import concurrent.futures

        assert asyncio.CancelledError is not concurrent.futures.CancelledError
        assert not issubclass(asyncio.CancelledError, Exception)
        assert transport_module._CANCELLED == (
            asyncio.CancelledError, concurrent.futures.CancelledError)


class TestAClosedTransportStaysClosed:
    """Fault 2. On Android something always calls back after shutdown."""

    def test_close_stops_the_worker(self, no_leaked_threads):
        h = Harness(completes=True)
        h.transport.connect()
        assert worker_threads(), "nothing was running to stop"
        h.transport.close()
        _settle(lambda: not h.transport.is_connected)
        assert not h.transport.is_connected

    def test_no_public_call_after_close_starts_a_new_worker(
            self, no_leaked_threads):
        """The exact race: the chat screen polls every 500ms, and shutdown
        happens while a poll is in flight.

        Every public entry point, not a sample. Each one reaches `_run` by a
        different route and each has its own early return, so testing three of
        them proves three of them.
        """
        h = Harness(completes=True)
        h.transport.connect()
        h.transport.close()
        before = len(worker_threads())

        calls = (
            ("disconnect", lambda: h.transport.disconnect()),
            ("roster", lambda: h.transport.roster()),
            ("send", lambda: h.transport.send("bob@example.i2p", "hi")),
            ("add_contact", lambda: h.transport.add_contact("bob@example.i2p")),
            ("remove_contact",
             lambda: h.transport.remove_contact("bob@example.i2p")),
            ("answer_subscription",
             lambda: h.transport.answer_subscription("bob@example.i2p", True)),
            ("cancel", lambda: h.transport.cancel()),
            ("close", lambda: h.transport.close()),
        )
        for name, call in calls:
            try:
                call()
            except TransportError:
                pass          # refusing is fine; starting a thread is not
            time.sleep(0.05)
            assert len(worker_threads()) == before, (
                "%s() after close resurrected the event loop thread" % name)

    def test_the_loop_itself_refuses_to_restart_after_close(
            self, no_leaked_threads):
        """The guard that makes the early returns above defence in depth
        rather than the only line.

        Asserted directly because the behavioural test cannot reach it: every
        public method has its own reason to return before `_ensure_loop`, so
        deleting this guard leaves them all still passing. It did -- planting
        that fault changed nothing until this test existed.
        """
        h = Harness(completes=True)
        h.transport.connect()
        h.transport.close()
        with pytest.raises(TransportError) as caught:
            h.transport._ensure_loop()
        assert caught.value.code == "closed"
        time.sleep(0.05)
        assert not worker_threads(), "_ensure_loop started one anyway"

    def test_close_is_idempotent(self, no_leaked_threads):
        h = Harness(completes=True)
        h.transport.connect()
        h.transport.close()
        h.transport.close()
        h.transport.close()

    def test_close_closes_the_tunnel(self, no_leaked_threads):
        h = Harness(completes=True)
        h.transport.connect()
        h.transport.close()
        _settle(lambda: h.tunnel_closed())
        assert h.tunnel_closed()

    def test_close_without_a_connection_is_harmless(self, no_leaked_threads):
        h = Harness()
        h.transport.close()

    def test_roster_after_close_is_empty_rather_than_an_error(
            self, no_leaked_threads):
        h = Harness(completes=True)
        h.transport.connect()
        h.transport.close()
        assert h.transport.roster() == []

    def test_disconnect_after_close_does_not_raise(self, no_leaked_threads):
        """Lifecycle callbacks call this. Raising would turn a tidy shutdown
        into a crash report."""
        h = Harness(completes=True)
        h.transport.connect()
        h.transport.close()
        h.transport.disconnect()

    def test_close_is_bounded(self, no_leaked_threads):
        """Teardown runs from Android lifecycle callbacks, which must return."""
        h = Harness(completes=True)
        h.transport.connect()
        started = time.time()
        h.transport.close()
        assert time.time() - started < CLOSE_TIMEOUT * 2 + 1


class TestADisconnectReleasesTheTunnel:
    """A tunnel outliving the session it carried holds an I2P lease."""

    def test_disconnecting_closes_the_tunnel(self, no_leaked_threads):
        h = Harness(completes=True)
        h.transport.connect()
        h.transport.disconnect()
        _settle(lambda: h.tunnel_closed())
        assert h.tunnel_closed()
        h.transport.close()

    def test_reconnecting_after_a_disconnect_builds_a_fresh_tunnel(
            self, no_leaked_threads):
        h = Harness(completes=True)
        h.transport.connect()
        h.transport.disconnect()
        h.transport.connect()
        assert len(h.tunnels) == 2
        assert h.transport.is_connected
        h.transport.close()


class TestTheForwarderHandover:
    """Reuse, not a second implementation. The Android transport asks the
    terminal client's forwarder for its sockets instead of copying it."""

    def test_the_real_forwarder_accepts_the_handover(self):
        """Binds against the real signature, so the transport and the function
        it calls cannot drift apart silently."""
        pytest.importorskip("slixmpp")
        import otrv4plus_xmpp

        fn = otrv4plus_xmpp.start_i2p_sam_forwarder
        assert _accepts(fn, "resources"), (
            "the forwarder no longer takes `resources`, so the transport "
            "cannot close what it opens")
        assert _accepts(fn, "log")

    def test_the_transport_asks_before_passing(self):
        """A forwarder without the keywords still works.

        Checked by signature rather than by calling and catching TypeError: a
        TypeError raised INSIDE the forwarder looks identical from outside,
        and retrying on one would open a second tunnel while the first was
        still building.
        """
        seen = {}

        async def old_style(dest, port, sam_host, sam_port):
            seen["called"] = True
            return ("127.0.0.1", 1234)

        h = Harness(completes=True, forwarder=old_style)
        h.transport.connect()
        assert seen["called"]
        assert h.transport.is_connected
        h.transport.close()

    def test_accepts_recognises_kwargs(self):
        def anything(**_kw):
            pass

        assert _accepts(anything, "resources")

    def test_accepts_says_no_for_a_plain_signature(self):
        def plain(a, b):
            pass

        assert not _accepts(plain, "resources")

    def test_the_default_forwarder_behaviour_is_unchanged(self):
        """The terminal client passes neither keyword and must be unaffected.

        Its call site is `start_i2p_sam_forwarder(server, port,
        sam_host=..., sam_port=...)`, so both new parameters have to be
        keyword-only with defaults that reproduce the old behaviour.
        """
        pytest.importorskip("slixmpp")
        import inspect

        import otrv4plus_xmpp

        params = inspect.signature(
            otrv4plus_xmpp.start_i2p_sam_forwarder).parameters
        for name in ("resources", "log"):
            assert params[name].kind is inspect.Parameter.KEYWORD_ONLY
            assert params[name].default is None, (
                "%s must default to the terminal client's behaviour" % name)


class TestTheDestinationStaysOutOfTheLog:
    """Chaquopy routes stdout into logcat, which `adb logcat` reads.

    The forwarder's progress lines name the I2P destination. In a terminal
    that is feedback to the person who typed the address; in a system log it
    is a record of who this device talks to, and CONTRIBUTING.md's rejection
    list puts destinations alongside keys and plaintext.
    """

    def test_the_transport_passes_a_log_that_is_not_print(self):
        h = Harness(completes=True)
        h.transport.connect()
        h.transport.close()
        # The harness's forwarder calls `log` with a line naming the server.

    def test_the_forwarder_log_drops_the_destination(self, caplog):
        import logging

        caplog.set_level(logging.DEBUG)
        _forwarder_log("[i2p] opening SAM stream to %s "
                       "(a cold tunnel can take 30-90s)..." % SERVER)
        _forwarder_log("[i2p] local bridge ready at 127.0.0.1:41234 -> %s"
                       % SERVER)
        _forwarder_log("[i2p] SAM stream established.")
        text = caplog.text
        assert SERVER not in text, "the destination reached the log"
        assert "127.0.0.1:41234" not in text
        assert "opening a SAM stream" in text
        assert "established" in text

    def test_it_says_nothing_about_a_line_it_does_not_recognise(self, caplog):
        """Fail closed. An unrecognised line might carry anything."""
        import logging

        caplog.set_level(logging.DEBUG)
        _forwarder_log("[i2p] some new message mentioning %s" % SERVER)
        assert SERVER not in caplog.text


class TestTheCredentialStillDoesNotLeak:
    """The new teardown paths are new places for it to escape."""

    def test_it_is_absent_from_a_cancelled_failure(self, no_leaked_threads):
        h = Harness()
        outcome = _connect_in_background(h.transport)
        _settle(lambda: len(h.tunnels) == 1)
        h.transport.cancel()
        outcome.thread.join(timeout=SETTLE)
        assert PASSWORD not in str(outcome.error)
        assert PASSWORD not in repr(outcome.error)
        h.transport.close()

    def test_it_is_absent_from_a_timed_out_failure(
            self, short_connect_timeout, no_leaked_threads):
        h = Harness()
        with pytest.raises(TransportError) as caught:
            h.transport.connect()
        assert PASSWORD not in str(caught.value)
        assert PASSWORD not in caught.value.detail
        h.transport.close()

    def test_it_is_absent_from_repr_after_close(self, no_leaked_threads):
        h = Harness(completes=True)
        h.transport.connect()
        h.transport.close()
        assert PASSWORD not in repr(h.transport)
        assert PASSWORD not in str(h.transport)


# ── helpers ──────────────────────────────────────────────────────────────────

def _settle(predicate, timeout=SETTLE):
    """Wait for *predicate*, polling. Returns whether it came true.

    Teardown happens on the loop thread, so the caller's assertion can run
    before it has. Polling rather than sleeping a fixed time keeps the tests
    fast when it is quick and reliable when the machine is loaded.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(0.02)
    return False


class _Outcome:
    def __init__(self):
        self.code = None
        self.error = None
        self.thread = None


def _connect_in_background(transport):
    """Start a connect on another thread, the way Kotlin does."""
    outcome = _Outcome()

    def run():
        try:
            transport.connect()
        except TransportError as exc:
            outcome.code = exc.code
            outcome.error = exc

    outcome.thread = threading.Thread(target=run, name="test-connect")
    outcome.thread.daemon = True
    outcome.thread.start()
    return outcome
