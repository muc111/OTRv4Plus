# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Termux fragments, Android reassembles. And the other way round.

This is the test that answers the question the extraction was for: can a
person running the app on a phone complete a DAKE with a person running the
terminal client on a laptop?

Before the extraction the answer was no, in both directions:

  * Termux -> Android. `send_otr_fragmented` splits anything over 6000 bytes
    into `?OTRv4F|` stanzas. The Android transport passed each one straight to
    `OtrApp.receive_message`, so the engine saw fragments where it expected a
    frame.
  * Android -> Termux. The Android transport sent the payload whole. A DAKE2
    is about 11.7 KB after base64 -- 1568 bytes of ML-KEM-1024 ciphertext, a
    2592-byte ML-DSA-87 public key and a 4627-byte signature -- and that is
    aimed straight at the ~8 KB I2P cliff.

So the tests here drive the REAL objects on both sides. The terminal side is
`OTRv4PlusXMPP.send_otr_fragmented` / `_reassemble_fragment`, unbound against a
stub, exactly as `tests/test_smp_end_to_end.py` has always driven them. The
Android side is a real `XmppTransport` with a fake slixmpp client, so what is
exercised is the transport's own `_send` and `_on_message`.

Nothing here fakes a successful DAKE. What is asserted is that the bytes one
side puts on the wire are the bytes the other side reassembles -- which is the
transport-layer precondition for a DAKE, and the precondition that was missing.
"""

import asyncio

import pytest

import otrv4plus_fragment as frag
from android_bridge.settings import ConnectionProfile
from android_bridge.transport import XmppTransport

JID = "alice@xmpp-elite.i2p"
SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"
PEER = "bob@xmpp-elite.i2p"

#: Sizes that matter, and why.
DAKE2 = 11716      # forces fragmentation; the frame that blocked interop
DAKE1 = 4455       # under the threshold: must stay a single stanza
DAKE3 = 4857       # likewise
SMP1 = 8100        # observed SMP1 size; fragments


def payload_of(size, fill="A"):
    head = "?OTRv4 "
    return head + fill * (size - len(head))


# ── the terminal client, driven the way its own tests drive it ───────────────

@pytest.fixture(scope="module")
def terminal_cls():
    xmpp = pytest.importorskip("otrv4plus_xmpp", reason="slixmpp not installed")
    return xmpp.OTRv4PlusXMPP


class TerminalStub:
    """A bare object for the terminal client's unbound methods.

    Deliberately minimal, and deliberately the same shape
    `tests/test_smp_end_to_end.py` uses: if the terminal's methods ever start
    needing more than this, that is a coupling worth finding here.
    """

    def __init__(self):
        self.sent = []
        self._frag_seq = 0
        self._probe = True          # suppress the progress print

    def send_message(self, mto=None, mbody=None, mtype=None):
        self.sent.append(mbody)

    def _dbg(self, *_a, **_kw):
        pass


# ── the Android transport, real, with a fake slixmpp client ──────────────────

class FakeClient:
    def __init__(self, jid, password):
        self.handlers = {}
        self.sent = []

    def add_event_handler(self, name, fn):
        self.handlers.setdefault(name, []).append(fn)

    def fire(self, name, arg=None):
        for fn in list(self.handlers.get(name, [])):
            fn(arg)

    def connect(self, host=None, port=None):
        self.fire("session_start", None)

    def send_message(self, mto=None, mbody=None, mtype=None):
        self.sent.append(mbody)

    def disconnect(self, *_a, **_kw):
        pass

    def abort(self, *_a, **_kw):
        pass


class Stanza(dict):
    """Enough of a slixmpp stanza for the transport to read one."""

    def __init__(self, frm, body):
        super().__init__({"from": frm, "body": body, "type": "chat"})

    def get(self, key, default=None):
        return super().get(key, default)


class AndroidSide:
    """A connected `XmppTransport` and the payloads its engine was handed."""

    def __init__(self):
        self.delivered = []
        self.client = None

        def factory(jid, password):
            self.client = FakeClient(jid, password)
            return self.client

        async def forwarder(*_a, **_kw):
            return ("127.0.0.1", 41234)

        self.transport = XmppTransport(
            ConnectionProfile(jid=JID, server=SERVER), "pw",
            on_payload=lambda peer, body: self.delivered.append((peer, body)),
            client_factory=factory,
            forwarder=forwarder,
        )
        self.transport.connect()
        # The peer's resource has advertised OTRv4Plus (XEP-0030): OTR frames
        # go only to a confirmed resource, never to the bare JID.
        import otrv4plus_caps
        self.transport._caps.presence_available(PEER + "/res")
        self.transport._caps.disco_result(PEER + "/res", [otrv4plus_caps.FEATURE])

    @property
    def sent(self):
        return self.client.sent

    def receive(self, body, frm=PEER):
        """Push one inbound stanza through the transport's own handler."""
        self.transport._on_message(Stanza(frm + "/res", body))

    def close(self):
        self.transport.close()


@pytest.fixture
def android():
    side = AndroidSide()
    yield side
    side.close()


# ── Termux -> Android ────────────────────────────────────────────────────────

class TestTermuxToAndroid:
    """The terminal client fragments; the Android transport reassembles."""

    @pytest.mark.parametrize("size", [DAKE2, SMP1, 13000, 24000])
    def test_a_fragmented_frame_reaches_the_engine_whole(
            self, terminal_cls, android, size):
        original = payload_of(size, "D")
        tx = TerminalStub()
        terminal_cls.send_otr_fragmented(tx, PEER, original)
        assert len(tx.sent) > 1, "%d bytes did not fragment" % size

        for body in tx.sent:
            android.receive(body)

        assert android.delivered == [(PEER, original)], (
            "the engine was handed %d payload(s); a Termux peer's DAKE2 must "
            "arrive as exactly one whole frame"
            % len(android.delivered))

    def test_nothing_reaches_the_engine_until_the_set_is_complete(
            self, terminal_cls, android):
        tx = TerminalStub()
        terminal_cls.send_otr_fragmented(tx, PEER, payload_of(DAKE2))
        for body in tx.sent[:-1]:
            android.receive(body)
        assert android.delivered == [], (
            "a partial frame reached the engine")
        android.receive(tx.sent[-1])
        assert len(android.delivered) == 1

    def test_out_of_order_fragments_still_arrive_whole(
            self, terminal_cls, android):
        original = payload_of(13000, "E")
        tx = TerminalStub()
        terminal_cls.send_otr_fragmented(tx, PEER, original)
        for body in reversed(tx.sent):
            android.receive(body)
        assert android.delivered == [(PEER, original)]

    @pytest.mark.parametrize("size", [DAKE1, DAKE3, 500])
    def test_an_unfragmented_frame_is_unchanged(
            self, terminal_cls, android, size):
        """Ordinary messages and the small DAKE frames must behave exactly as
        they did before any of this existed."""
        original = payload_of(size, "F")
        tx = TerminalStub()
        terminal_cls.send_otr_fragmented(tx, PEER, original)
        assert len(tx.sent) == 1
        android.receive(tx.sent[0])
        assert android.delivered == [(PEER, original)]

    def test_a_plain_chat_message_is_untouched(self, android):
        """Not an OTR frame at all. It must reach the engine as typed."""
        android.receive("hello there")
        assert android.delivered == [(PEER, "hello there")]


# ── Android -> Termux ────────────────────────────────────────────────────────

class TestAndroidToTermux:
    """The Android transport fragments; the terminal client reassembles."""

    @pytest.mark.parametrize("size", [DAKE2, SMP1, 13000, 24000])
    def test_a_large_frame_is_fragmented_before_it_goes_out(
            self, terminal_cls, android, size):
        original = payload_of(size, "G")
        android.transport.send(PEER, original)

        assert len(android.sent) > 1, (
            "%d bytes went out as one stanza; that is the ~8 KB I2P cliff "
            "and a Termux peer would never see a complete frame" % size)
        assert all(frag.is_fragment(b) for b in android.sent)

        rx = TerminalStub()
        out = None
        for body in android.sent:
            got = terminal_cls._reassemble_fragment(rx, JID, body)
            if got is not None:
                out = got
        assert out == original, "the terminal client could not reassemble it"

    def test_the_stanzas_are_byte_identical_to_what_termux_would_send(
            self, terminal_cls, android):
        """The strongest statement of interoperability available without a
        network: for the same payload and the same counter state, both sides
        put exactly the same bytes on the wire."""
        original = payload_of(DAKE2, "H")

        android.transport.send(PEER, original)

        tx = TerminalStub()
        terminal_cls.send_otr_fragmented(tx, PEER, original)

        assert android.sent == tx.sent, (
            "the two clients disagree on the wire format")

    @pytest.mark.parametrize("size", [DAKE1, DAKE3, 500])
    def test_a_small_frame_goes_out_whole_and_unwrapped(self, android, size):
        original = payload_of(size, "I")
        android.transport.send(PEER, original)
        assert android.sent == [original], (
            "a payload under the threshold must go out as itself, "
            "indistinguishable from a client that never heard of fragments")

    def test_an_ordinary_message_is_not_wrapped(self, android):
        android.transport.send(PEER, "hello there")
        assert android.sent == ["hello there"]


# ── both directions, and the same implementation ─────────────────────────────

class TestBothSidesUseOneImplementation:

    def test_the_terminal_client_calls_the_shared_module(self):
        import inspect

        import otrv4plus_xmpp

        source = inspect.getsource(otrv4plus_xmpp.OTRv4PlusXMPP.send_otr_fragmented)
        assert "_frag.fragment(" in source, (
            "the terminal client has its own fragmentation again")
        assert "?OTRv4F|%s" not in source and '"?OTRv4F|{' not in source

        source = inspect.getsource(
            otrv4plus_xmpp.OTRv4PlusXMPP._reassemble_fragment)
        assert "_frag.Reassembler(" in source

    def test_the_android_transport_calls_the_shared_module(self):
        import inspect

        import android_bridge.transport as mod

        source = inspect.getsource(mod)
        assert "_fragment.fragment(" in source
        assert "_fragment.Reassembler()" in source

    def test_neither_side_builds_a_fragment_header_itself(self):
        """One implementation means exactly one place that writes the format.

        A second `?OTRv4F|` format string anywhere is the thing that made the
        two clients diverge in the first place, so it is easier to ban it than
        to keep two copies honest.
        """
        import inspect

        import android_bridge.transport as android_mod
        import otrv4plus_fragment
        import otrv4plus_xmpp

        allowed = inspect.getsourcefile(otrv4plus_fragment)
        for module in (otrv4plus_xmpp, android_mod):
            path = inspect.getsourcefile(module)
            assert path != allowed
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            # The prefix may be MENTIONED -- in a docstring, or as the
            # constant's value in the shared module -- but no other file may
            # BUILD one with a format placeholder after it.
            for bad in ("?OTRv4F|%s|", "?OTRv4F|{"):
                assert bad not in text, (
                    "%s builds a fragment header itself: %r" % (path, bad))

    def test_the_constants_come_from_one_place(self):
        import inspect

        import otrv4plus_xmpp

        source = inspect.getsource(otrv4plus_xmpp)
        assert "MAX_FRAGMENT = 6000" not in source, (
            "the threshold is defined twice, so the two can drift apart")

    def test_a_round_trip_through_both_sides(self, terminal_cls, android):
        """Termux -> Android -> Termux, with the payload unchanged."""
        original = payload_of(18000, "J")

        tx = TerminalStub()
        terminal_cls.send_otr_fragmented(tx, PEER, original)
        for body in tx.sent:
            android.receive(body)
        assert android.delivered == [(PEER, original)]

        android.transport.send(PEER, android.delivered[0][1])
        rx = TerminalStub()
        out = None
        for body in android.sent:
            got = terminal_cls._reassemble_fragment(rx, JID, body)
            if got is not None:
                out = got
        assert out == original


class TestTheCounterSemanticsSurvived:
    """`_file_fragments_sent` is what the file-transfer pump paces on: what
    costs a receiver's rate-limit budget is stanzas, not chunks."""

    def test_a_whole_message_counts_one(self, terminal_cls):
        tx = TerminalStub()
        sent = terminal_cls.send_otr_fragmented(tx, PEER, payload_of(500))
        assert sent == 1
        assert tx._file_fragments_sent == 1

    def test_a_fragmented_message_counts_every_stanza(self, terminal_cls):
        tx = TerminalStub()
        sent = terminal_cls.send_otr_fragmented(tx, PEER, payload_of(13000))
        assert sent == 3
        assert tx._file_fragments_sent == 3

    def test_the_counter_accumulates_across_sends(self, terminal_cls):
        tx = TerminalStub()
        terminal_cls.send_otr_fragmented(tx, PEER, payload_of(13000))   # 3
        terminal_cls.send_otr_fragmented(tx, PEER, payload_of(500))     # 1
        assert tx._file_fragments_sent == 4

    def test_the_return_value_is_the_stanza_count(self, terminal_cls):
        tx = TerminalStub()
        assert terminal_cls.send_otr_fragmented(
            tx, PEER, payload_of(DAKE2)) == 2

    def test_it_works_without_an_init(self, terminal_cls):
        """The pump reads it off a client that the fragmentation tests build
        as a bare stub; `getattr` with a default is why that works."""
        class Bare:
            _frag_seq = 0
            _probe = True

            def __init__(self):
                self.sent = []

            def send_message(self, **kw):
                self.sent.append(kw.get("mbody"))

            def _dbg(self, *a, **k):
                pass

        bare = Bare()
        terminal_cls.send_otr_fragmented(bare, PEER, payload_of(13000))
        assert bare._file_fragments_sent == 3


class TestTheAndroidSessionDoesNotHoardFragments:

    def test_closing_drops_partial_sets(self, terminal_cls):
        """Partial sets are fragments of a message that will never complete
        once the session is gone. They are plaintext-to-be and there is no
        reason to keep them."""
        side = AndroidSide()
        tx = TerminalStub()
        terminal_cls.send_otr_fragmented(tx, PEER, payload_of(DAKE2))
        side.receive(tx.sent[0])
        assert side.transport._reassembler.pending() == 1
        side.close()
        assert side.transport._reassembler.pending() == 0
