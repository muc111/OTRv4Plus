"""A transfer must not be throttled, dropped, or run on the event loop.

The first real `/sendfile` between two phones failed three ways at once, and
each of the three would have killed it alone:

  1. `on_accept` is reached from inside the inbound message handler, which
     runs on the asyncio loop, and the engine's pump sent every chunk in one
     unbroken run. A 340 KB file therefore encrypted and pushed about a
     hundred stanzas with nothing else getting a turn — keepalives could not
     run, the stream was declared dead, and the transfer took the connection
     down with it.
  2. Nothing paced the sender, so it went as fast as the loop could encrypt.
  3. The receiver's rate limiter is 20 messages per 5 s. Four fifths of the
     transfer was dropped as if it were a flood, and because the chunk AEAD
     is a sequence, the first gap ended it: `chunk 10 arrived out of order`.

These pin the fixes at the seams rather than through a live client.
"""

import asyncio
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ft = pytest.importorskip("otrv4plus_filetransfer")
xmpp = pytest.importorskip("otrv4plus_xmpp")


class _Transport:
    """Counts what the engine asks for, and can refuse."""

    def __init__(self, fail_at=None):
        self.controls = []
        self.chunks = []
        self.fail_at = fail_at

    def send_control(self, peer, verb, payload):
        self.controls.append(verb)
        return True

    def send_chunk(self, peer, transfer_id, index, sealed):
        if self.fail_at is not None and index == self.fail_at:
            return False
        self.chunks.append(index)
        return True


class _Transfer:
    """The shape `pump_step` needs, without a real sealed file."""

    def __init__(self, chunks=5):
        self.peer = "bob@example.i2p"
        self.cancelled = False
        self.chunks_sent = 0
        self._sealed = [b"chunk-%d" % i for i in range(chunks)]

        class _Offer:
            transfer_id = b"\x01" * 16
            filename = "photo.png"
        self.offer = _Offer()
        self.accepted = False


def _manager(transport, spawn=None):
    return ft.FileTransferManager(transport=transport, notify=lambda _m: None,
                                  verified=lambda _p: True, spawn=spawn)


class TestThePumpIsSteppable:
    """One chunk per call, so the caller owns the pace."""

    def test_each_step_sends_exactly_one_chunk(self):
        t = _Transport()
        mgr = _manager(t)
        transfer = _Transfer(chunks=3)
        assert mgr.pump_step(transfer) is True
        assert t.chunks == [0]
        assert mgr.pump_step(transfer) is True
        assert t.chunks == [0, 1]

    def test_it_reports_when_it_is_done_and_sends_done_once(self):
        t = _Transport()
        mgr = _manager(t)
        transfer = _Transfer(chunks=2)
        steps = 0
        while mgr.pump_step(transfer):
            steps += 1
            assert steps < 10, "pump_step never finished"
        assert t.chunks == [0, 1]
        assert t.controls.count("DONE") == 1

    def test_a_cancelled_transfer_stops(self):
        t = _Transport()
        mgr = _manager(t)
        transfer = _Transfer(chunks=5)
        mgr.pump_step(transfer)
        transfer.cancelled = True
        assert mgr.pump_step(transfer) is False
        assert t.chunks == [0]
        assert "DONE" not in t.controls

    def test_a_transport_failure_stops_rather_than_looping(self):
        t = _Transport(fail_at=1)
        mgr = _manager(t)
        transfer = _Transfer(chunks=4)
        mgr.outgoing[mgr._key(transfer.offer.transfer_id)] = transfer
        assert mgr.pump_step(transfer) is True
        assert mgr.pump_step(transfer) is False
        assert t.chunks == [0]

    def test_the_old_whole_file_pump_still_works(self):
        """It is the default `spawn`, and tests and synchronous transports
        rely on it."""
        t = _Transport()
        mgr = _manager(t)
        transfer = _Transfer(chunks=4)
        mgr._pump(transfer)
        assert t.chunks == [0, 1, 2, 3]
        assert t.controls.count("DONE") == 1


class TestAcceptDoesNotSendInline:
    """The whole point: `on_accept` must hand the sending to the caller."""

    def test_on_accept_uses_the_injected_spawn(self):
        t = _Transport()
        spawned = []
        mgr = _manager(t, spawn=spawned.append)
        transfer = _Transfer(chunks=3)
        key = mgr._key(transfer.offer.transfer_id)
        mgr.outgoing[key] = transfer
        mgr.on_accept(transfer.peer, key)
        assert spawned == [transfer], "on_accept did not delegate"
        assert t.chunks == [], (
            "chunks were sent inside on_accept, which runs on the event loop")

    def test_without_a_spawn_it_still_sends(self):
        """The default must not silently do nothing."""
        t = _Transport()
        mgr = _manager(t)
        transfer = _Transfer(chunks=3)
        key = mgr._key(transfer.offer.transfer_id)
        mgr.outgoing[key] = transfer
        mgr.on_accept(transfer.peer, key)
        assert t.chunks == [0, 1, 2]

    def test_the_client_passes_one(self):
        """Reading the client, not running it: the wiring is the fix."""
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._on_start)
        assert "spawn=self._start_file_pump" in src, (
            "the client no longer hands the engine a pump, so accepting a "
            "transfer sends the whole file on the event loop again")


class TestTheRateLimiterKnowsAboutTransfers:

    def _client(self):
        client = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)
        client._rate_limit = {}
        client._file_manager = None
        return client

    def test_an_ordinary_peer_gets_the_chat_budget(self):
        client = self._client()
        assert client._rate_budget("bob@example.i2p") == xmpp._RATE_MAX

    def test_an_accepted_transfer_raises_the_budget(self):
        client = self._client()

        class _Mgr:
            def transfer_in_flight(self, peer):
                return peer == "bob@example.i2p"

        client._file_manager = _Mgr()
        assert client._rate_budget("bob@example.i2p") == xmpp._RATE_MAX_BULK
        assert client._rate_budget("eve@example.i2p") == xmpp._RATE_MAX

    def test_the_raised_budget_is_bounded(self):
        """Raised, not lifted.  An accepted transfer is not a licence to
        send anything at any rate."""
        assert xmpp._RATE_MAX_BULK > xmpp._RATE_MAX
        assert xmpp._RATE_MAX_BULK < 10_000

    def test_a_transfer_actually_fits_in_the_raised_budget(self):
        """The number that matters.  A 340 KB file is ~21 chunks of five
        fragments; at the chat rate the receiver drops four fifths of them."""
        fragments = (340 * 1024 // ft.WIRE_CHUNK_PLAIN + 1) * 5
        chat_capacity = xmpp._RATE_MAX / xmpp._RATE_WINDOW
        bulk_capacity = xmpp._RATE_MAX_BULK / xmpp._RATE_WINDOW
        assert xmpp._FILE_FRAGMENTS_PER_SEC > chat_capacity, (
            "pacing is at or below the chat rate, so the fix is moot")
        assert xmpp._FILE_FRAGMENTS_PER_SEC < bulk_capacity, (
            "the sender fills the whole budget, starving chat and keepalives")
        assert fragments > xmpp._RATE_MAX, (
            "the test file no longer exceeds one window; pick a bigger one")

    def test_a_broken_manager_falls_back_to_the_chat_budget(self):
        """Fail closed: if the transfer tables cannot be read, throttle."""
        client = self._client()

        class _Angry:
            def transfer_in_flight(self, peer):
                raise RuntimeError("boom")

        client._file_manager = _Angry()
        assert client._rate_budget("bob@example.i2p") == xmpp._RATE_MAX

    def test_the_limiter_uses_the_budget(self):
        client = self._client()
        peer = "bob@example.i2p"
        allowed = 0
        while client._check_rate_limit(peer):
            allowed += 1
            assert allowed < 1000
        assert allowed == xmpp._RATE_MAX

    def test_the_limiter_honours_the_raised_budget(self):
        """Not just that `_rate_budget` returns a bigger number -- that the
        limiter asks it.  Reading the budget and then throttling to the chat
        rate anyway is the bug with extra steps."""
        client = self._client()

        class _Mgr:
            def transfer_in_flight(self, peer):
                return True

        client._file_manager = _Mgr()
        peer = "bob@example.i2p"
        allowed = 0
        while client._check_rate_limit(peer):
            allowed += 1
            assert allowed < 10_000
        assert allowed == xmpp._RATE_MAX_BULK, (
            "the limiter still throttles an accepted transfer to %d" % allowed)


class TestOnlyAnAcceptedTransferCounts:

    def test_an_offer_alone_buys_nothing(self):
        """Any verified peer can send an offer unprompted.  If that raised
        the budget, the limiter could be disabled without the user ever
        agreeing to anything."""
        mgr = _manager(_Transport())
        transfer = ft.IncomingTransfer(peer="bob", offer=None)
        mgr.incoming["k"] = transfer
        assert mgr.transfer_in_flight("bob") is False
        transfer.accepted = True
        assert mgr.transfer_in_flight("bob") is True

    def test_a_cancelled_outgoing_transfer_does_not_count(self):
        mgr = _manager(_Transport())
        transfer = _Transfer()
        transfer.accepted = True
        mgr.outgoing["k"] = transfer
        assert mgr.transfer_in_flight(transfer.peer) is True
        transfer.cancelled = True
        assert mgr.transfer_in_flight(transfer.peer) is False

    def test_another_peers_transfer_does_not_raise_our_budget(self):
        mgr = _manager(_Transport())
        transfer = ft.IncomingTransfer(peer="bob", offer=None)
        transfer.accepted = True
        mgr.incoming["k"] = transfer
        assert mgr.transfer_in_flight("eve") is False


class TestThePacingIsReal:
    """The pump must actually wait between chunks, not just claim to."""

    def test_it_sleeps_between_chunks(self):
        client = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)
        t = _Transport()
        client._file_manager = _manager(t)
        client._file_fragments_sent = 0
        transfer = _Transfer(chunks=4)

        real_step = client._file_manager.pump_step
        slept = []

        def step(tr):
            client._file_fragments_sent = 5     # as if it fragmented into 5
            return real_step(tr)

        client._file_manager.pump_step = step

        async def _fake_sleep(seconds):
            slept.append(seconds)

        async def _drive():
            orig = asyncio.sleep
            asyncio.sleep = _fake_sleep
            try:
                client._start_file_pump(transfer)
                await orig(0)
                for _ in range(20):
                    await orig(0)
            finally:
                asyncio.sleep = orig

        asyncio.run(_drive())
        assert t.chunks == [0, 1, 2, 3], "the pump did not finish"
        assert len(slept) == 4, "one pause per chunk sent"
        expected = 5 / xmpp._FILE_FRAGMENTS_PER_SEC
        assert all(abs(s - expected) < 1e-9 for s in slept), (
            "the pause does not follow the stanzas actually sent: %s" % slept)

    def test_the_pause_follows_what_was_actually_sent(self):
        """A chunk that fitted in one frame costs one stanza of budget, not
        five.  Pacing on a fixed guess is wrong at both ends of a file."""
        client = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)
        t = _Transport()
        client._file_manager = _manager(t)
        client._file_fragments_sent = 0
        transfer = _Transfer(chunks=2)

        real_step = client._file_manager.pump_step
        counts = iter([1, 7])

        def step(tr):
            client._file_fragments_sent = next(counts, 1)
            return real_step(tr)

        client._file_manager.pump_step = step
        slept = []

        async def _fake_sleep(seconds):
            slept.append(seconds)

        async def _drive():
            orig = asyncio.sleep
            asyncio.sleep = _fake_sleep
            try:
                client._start_file_pump(transfer)
                for _ in range(20):
                    await orig(0)
            finally:
                asyncio.sleep = orig

        asyncio.run(_drive())
        assert slept == [1 / xmpp._FILE_FRAGMENTS_PER_SEC,
                         7 / xmpp._FILE_FRAGMENTS_PER_SEC]
