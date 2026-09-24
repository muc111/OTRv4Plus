#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Connecting twice must not leave two of everything behind.

TWO DEFECTS, ONE SHAPE
======================
`_connect_inner` builds a slixmpp client and assigns `self._client`
unconditionally. Nothing checked whether there already was one.

1. **A second `connect()` on a live transport.** Measured:

       after 1st connect: clients=1 tunnels=1 connected=True
       after 2nd connect: clients=2 tunnels=2 connected=True
       the FIRST client was told to stop: False
       tunnel 0 sockets closed          : False

2. **A reconnect after the keepalive declared the stream dead.**
   `_declare_stream_dead` called `client.disconnect()` and stopped there --
   the reference stayed and the tunnel stayed open:

       connected             : clients=1 tunnels=1
       after the stream died : tunnel 0 sockets closed: False
       after the reconnect   : clients=2 tunnels=2, sockets still open: 6

WHY AN ORPHAN IS NOT JUST A LEAK
================================
The abandoned client is still wired to `on_payload`, so inbound stanzas
arrive twice. It is still authenticated, so the account stays present on a
stream nobody is watching. Its I2P tunnel stays up for the life of the
process, and on a handset "the stream died and came back" is every walk out
of coverage.

`_abandon` already gave all three back for a FAILED attempt -- its own
comment says a timed-out connect "left all three running ... so pressing
Connect a second time built a second tunnel on top of the first". Neither
path above was a failed attempt, so neither reached it.
"""

import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytest.importorskip("android_bridge.transport")

from test_android_transport_lifecycle import Harness       # noqa: E402


@pytest.fixture
def live():
    """A transport with one established stream, torn down afterwards."""
    harness = Harness(completes=True)
    harness.transport.connect()
    assert harness.transport.is_connected, "the fixture did not connect"
    assert len(harness.clients) == 1 and len(harness.tunnels) == 1
    try:
        yield harness
    finally:
        harness.transport.close()


def _open_sockets(harness):
    return sum(1 for tunnel in harness.tunnels
               for socket in tunnel if not socket.closed)


class TestConnectingAgainOnALiveStream:
    """`connect()` is "bring the stream up". If it is up, that is done."""

    def test_it_does_not_build_a_second_client(self, live):
        live.transport.connect()
        assert len(live.clients) == 1, (
            "a second XMPP client was built on top of a live one; the first "
            "is still authenticated and still delivering")

    def test_it_does_not_build_a_second_tunnel(self, live):
        live.transport.connect()
        assert len(live.tunnels) == 1, (
            "a second SAM tunnel was opened and nothing will close the first")

    def test_pressing_connect_repeatedly_changes_nothing(self, live):
        for _ in range(5):
            live.transport.connect()
        assert (len(live.clients), len(live.tunnels)) == (1, 1)
        assert live.transport.is_connected

    def test_the_stream_is_still_usable_afterwards(self, live):
        """Idempotent must mean "already done", not "quietly broken"."""
        live.transport.connect()
        assert live.transport.is_connected
        assert live.transport._client is live.clients[0]


class TestReconnectingAfterTheStreamDied:
    """The keepalive's own path. Guarded on `is_connected` rather than on the
    client reference precisely so this still works: the keepalive clears that
    flag when the link stops answering."""

    @staticmethod
    def _declare_dead(harness):
        harness.transport._run(harness.transport._declare_stream_dead(), 5)

    def test_the_dead_client_is_stopped(self, live):
        self._declare_dead(live)
        first = live.clients[0]
        assert (first.aborted + first.disconnected) > 0, (
            "the dead client was dereferenced without being stopped, so "
            "slixmpp's retry loop keeps dialling for the life of the process")

    def test_the_dead_client_is_dereferenced(self, live):
        self._declare_dead(live)
        assert live.transport._client is None, (
            "a later call can find a half-dead client and believe it usable")

    def test_the_tunnel_is_closed(self, live):
        self._declare_dead(live)
        assert live.tunnel_closed(0), (
            "the I2P tunnel and its local socket outlived the stream")

    def test_a_reconnect_is_still_possible(self, live):
        """The half that must NOT be broken by the guard above."""
        self._declare_dead(live)
        live.transport.connect()
        assert live.transport.is_connected
        assert len(live.clients) == 2

    def test_a_reconnect_leaves_exactly_one_live_tunnel(self, live):
        self._declare_dead(live)
        live.transport.connect()
        assert _open_sockets(live) == len(live.tunnels[-1]), (
            "a death-and-reconnect cycle left a tunnel behind; on a handset "
            "that is every walk out of coverage")

    def test_repeated_cycles_do_not_accumulate(self, live):
        """The consequence that made this worth fixing: it is not one leak,
        it is one per cycle."""
        for _ in range(4):
            self._declare_dead(live)
            live.transport.connect()
        assert _open_sockets(live) == len(live.tunnels[-1])
        assert live.transport._client is live.clients[-1]


class TestTheKeepaliveDoesNotCancelItself:
    """`_declare_stream_dead` runs inside the keepalive loop and tears down
    through `_abandon`, which stops the keepalive. Cancelling the current task
    there would raise at the next await INSIDE the teardown, so which of the
    three resources came back would depend on where that await fell."""

    def test_the_teardown_completes_from_inside_the_loop(self, live):
        """Driven by calling it the way the loop does: on the loop thread,
        with the keepalive task running."""
        assert live.transport._keepalive_task is not None, (
            "this test is about the keepalive cancelling itself and there is "
            "no keepalive task; re-establish what it is protecting")
        live.transport._run(live.transport._declare_stream_dead(), 5)
        # All three, not "whichever happened before the cancellation".
        assert live.transport._client is None
        assert live.tunnel_closed(0)
        assert not live.transport.is_connected

    def test_the_keepalive_is_released_either_way(self, live):
        """The half the self-cancel guard must not take away.

        Driven on the LOOP THREAD, because that is the only place
        `_stop_keepalive` is ever reached from -- its single caller is
        `_abandon`, which is a coroutine. (`Task.cancel` is not thread-safe,
        so a cross-thread caller would be a defect in the caller rather than
        a case to test for here.)

        Whichever branch runs, the transport must not go on holding the task:
        a keepalive left attached to a stream that has gone is a loop pinging
        a client nobody can reach.
        """
        assert live.transport._keepalive_task is not None
        live.transport._run(live.transport._abandon(), 5)
        assert live.transport._keepalive_task is None

    def test_the_guard_only_spares_the_task_that_is_asking(self, live):
        """Stated directly, because the guard is the kind of thing a later
        reader deletes as redundant: it compares against the RUNNING task, so
        outside a task there is nothing to spare and everything is cancelled.
        """
        source = inspect.getsource(type(live.transport)._stop_keepalive)
        assert "current_task" in source
        assert "task is not current" in source
