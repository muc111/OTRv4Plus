# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Protocol traffic is not chat, and chat is not protocol traffic.

THE BUG THIS FILE EXISTS FOR, OBSERVED ON A HANDSET

A payload beginning `?OTRv4 NvM3G22wZ5AUSVebh8ZenAA...` reached the Android
client and was rendered in the conversation as a wall of base64, apparently
sent by the user's contact.

It was not a display bug. `EnhancedSessionManager.handle_incoming_message`
returns EITHER decrypted user text OR a protocol frame the CALLER is expected
to put back on the wire, and telling those apart is the caller's job.
`otrv4plus_xmpp` has always done it::

    if out_b.startswith(OTR_PREFIX_B):
        self.send_otr_fragmented(peer, ...)      # a reply, not a message
    else:
        ...                                       # something to show

`OtrApp` did neither. So the reply was displayed instead of sent, which is
simultaneously the gibberish on screen AND a handshake that could never
complete in either direction. One missing branch, both symptoms.

WHY THE FIX IS NOT `if body.startswith("?OTRv4"): hide()`

Because hiding it leaves the handshake just as broken, and because the UI must
not need to know what an OTR frame looks like. The classification belongs at
the engine boundary, where the payload either becomes a reply to send or a
message to show, and the layer above receives only the second kind.
"""

import pytest

import otrv4plus_fragment as _fragment
from android_bridge.app import OtrApp, Transport
from android_bridge.events import SecurityState

PEER = "alice@xmpp-elite.i2p"

#: The shape the handset actually saw.
DAKE = "?OTRv4 NvM3G22wZ5AUSVebh8ZenAA" + "Q" * 400


class Engine:
    """Enough EnhancedSessionManager to exercise the boundary."""

    def __init__(self):
        self.level = 0
        self.outgoing = ("?OTRv4 ciphertext", True)
        #: What `handle_incoming_message` hands back. The real engine returns a
        #: `?OTRv4 ...` string when it has a protocol reply to send, and bytes
        #: of plaintext when it has a message to show.
        self.reply = None
        self.seen = []

    def handle_incoming_message(self, peer, payload):
        self.seen.append((peer, payload))
        return self.reply

    def handle_outgoing_message(self, peer, body):
        return self.outgoing

    def get_security_level(self, peer):
        return self.level

    def get_or_create_session(self, peer, is_initiator=False):
        return object()

    def get_smp_status(self, peer):
        return {"state": "IDLE", "verified": False, "failed": False}


class FakeTransport(Transport):
    def __init__(self):
        self.sent = []
        self.raises = False

    def send(self, peer, payload):
        if self.raises:
            raise OSError("socket gone")
        self.sent.append((peer, payload))

    def connect(self):
        pass

    def disconnect(self):
        pass

    def roster(self):
        return []


class Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)

    def kinds(self):
        return [type(e).__name__ for e in self.events]

    def bodies(self):
        return [getattr(e, "body", None) for e in self.events]


@pytest.fixture
def app():
    engine, transport, sink = Engine(), FakeTransport(), Sink()
    return OtrApp(engine, transport, sink), engine, transport, sink


# ── the shared classifier ────────────────────────────────────────────────────

class TestTheClassifier:
    """One definition, because two would drift and the drift is a downgrade."""

    def test_a_protocol_frame_is_recognised(self):
        assert _fragment.is_otr_protocol(DAKE)

    def test_bytes_and_str_agree(self):
        assert _fragment.is_otr_protocol(DAKE.encode("utf-8"))

    def test_ordinary_text_is_not_protocol(self):
        for body in ("hello", "", "hello ?OTRv4 there", "OTRv4"):
            assert not _fragment.is_otr_protocol(body), body

    def test_a_fragment_is_not_a_whole_protocol_frame(self):
        """`?OTRv4F|` must not match `?OTRv4 `. The trailing space is what
        separates them, and reassembly happens before classification."""
        assert not _fragment.is_otr_protocol("?OTRv4F|abcd1234|1|2|xx")

    def test_the_space_is_required(self):
        assert not _fragment.is_otr_protocol("?OTRv4Xsomething")

    def test_neither_client_keeps_its_own_copy(self):
        """The terminal client re-exports the shared constant rather than
        redefining it, which is how the Android side came to have none."""
        import otrv4plus_xmpp
        assert otrv4plus_xmpp.OTR_PREFIX == _fragment.OTR_PREFIX
        assert otrv4plus_xmpp.OTR_PREFIX_B == _fragment.OTR_PREFIX.encode()

    def test_a_non_string_is_not_protocol(self):
        for value in (None, 42, object()):
            assert not _fragment.is_otr_protocol(value)


# ── inbound: the engine's output is classified ───────────────────────────────

class TestProtocolNeverReachesTheChat:

    def test_a_protocol_reply_is_not_shown_as_a_message(self, app):
        facade, engine, _transport, sink = app
        engine.reply = "?OTRv4 DAKE2payload"
        facade.receive_message(PEER, DAKE)
        assert "MessageReceived" not in sink.kinds(), (
            "the engine's reply was rendered as a chat message")

    def test_a_protocol_reply_is_sent(self, app):
        """The other half, and the one that made OTR impossible: the reply
        has to go back on the wire or the handshake stops here."""
        facade, engine, transport, _sink = app
        engine.reply = "?OTRv4 DAKE2payload"
        facade.receive_message(PEER, DAKE)
        assert transport.sent == [(PEER, "?OTRv4 DAKE2payload")]

    def test_receive_returns_nothing_for_a_protocol_frame(self, app):
        facade, engine, _transport, _sink = app
        engine.reply = "?OTRv4 DAKE2payload"
        assert facade.receive_message(PEER, DAKE) is None

    def test_bytes_replies_are_classified_too(self, app):
        facade, engine, transport, sink = app
        engine.reply = b"?OTRv4 DAKE2payload"
        facade.receive_message(PEER, DAKE)
        assert transport.sent == [(PEER, "?OTRv4 DAKE2payload")]
        assert "MessageReceived" not in sink.kinds()

    def test_a_frame_the_engine_consumes_silently_shows_nothing(self, app):
        """`None` is the ordinary case for a DAKE frame that needs no reply."""
        facade, engine, transport, sink = app
        engine.reply = None
        assert facade.receive_message(PEER, DAKE) is None
        assert transport.sent == []
        assert "MessageReceived" not in sink.kinds()

    def test_a_state_change_is_still_reported(self, app):
        facade, engine, _transport, sink = app

        def answer(peer, payload):
            engine.level = 1
            return "?OTRv4 DAKE2payload"

        engine.handle_incoming_message = answer
        facade.receive_message(PEER, DAKE)
        assert "SessionStateChanged" in sink.kinds()

    def test_a_reply_that_cannot_be_sent_is_reported_not_displayed(self, app):
        facade, engine, transport, sink = app
        engine.reply = "?OTRv4 DAKE2payload"
        transport.raises = True
        facade.receive_message(PEER, DAKE)
        assert "MessageReceived" not in sink.kinds()
        assert "ErrorOccurred" in sink.kinds()

    def test_a_reply_never_reaches_the_chat_even_without_a_transport(self):
        engine, sink = Engine(), Sink()
        engine.reply = "?OTRv4 DAKE2payload"
        facade = OtrApp(engine, None, sink)
        facade.receive_message(PEER, DAKE)
        assert "MessageReceived" not in sink.kinds()


class TestPlaintextStillReachesTheChat:

    def test_an_ordinary_message_is_delivered(self, app):
        facade, engine, _transport, sink = app
        engine.reply = b"hello"
        assert facade.receive_message(PEER, "hello") == "hello"
        assert sink.kinds() == ["MessageReceived"]
        assert sink.bodies() == ["hello"]

    def test_several_messages_all_arrive(self, app):
        facade, engine, _transport, sink = app
        for word in (b"one", b"two", b"three"):
            engine.reply = word
            facade.receive_message(PEER, word.decode())
        assert sink.bodies() == ["one", "two", "three"]

    def test_a_message_that_merely_mentions_otr_is_delivered(self, app):
        """Classification is on the ENGINE's output, and the engine returns a
        plaintext body as bytes. A user quoting the protocol is not protocol."""
        facade, engine, _transport, sink = app
        engine.reply = b"what is ?OTRv4 anyway"
        facade.receive_message(PEER, "what is ?OTRv4 anyway")
        assert sink.bodies() == ["what is ?OTRv4 anyway"]

    def test_a_decrypted_message_reaches_the_chat(self, app):
        """Once a session exists the engine returns plaintext, and that IS a
        chat message -- the point of the whole exercise."""
        facade, engine, _transport, sink = app
        engine.level = 3
        engine.reply = b"the decrypted words"
        facade.receive_message(PEER, "?OTRv4 ciphertext")
        assert sink.bodies() == ["the decrypted words"]

    def test_an_engine_failure_is_an_error_not_a_message(self, app):
        facade, engine, _transport, sink = app

        def boom(peer, payload):
            raise RuntimeError("bad mac")

        engine.handle_incoming_message = boom
        assert facade.receive_message(PEER, DAKE) is None
        assert sink.kinds() == ["ErrorOccurred"]
        assert "MessageReceived" not in sink.kinds()


class TestFragmentedProtocolTraffic:
    """A DAKE2 is ~11.7 KB and arrives as several stanzas. Reassembly happens
    in the transport, BEFORE classification -- so what the facade classifies is
    always a whole payload."""

    def test_reassembly_precedes_classification(self):
        parts, _seq = _fragment.fragment(DAKE, 0)
        assert len(parts) == 1, "this payload should not need fragmenting"

    def test_a_large_protocol_payload_survives_the_round_trip(self):
        big = "?OTRv4 " + "A" * 20000
        parts, _seq = _fragment.fragment(big, 0)
        assert len(parts) > 1
        assert all(_fragment.is_fragment(p) for p in parts)
        # A fragment is not itself protocol traffic to classify.
        assert all(not _fragment.is_otr_protocol(p) for p in parts)

        reassembler = _fragment.Reassembler()
        out = None
        for part in parts:
            out = reassembler.feed(PEER, part)
        assert out == big
        assert _fragment.is_otr_protocol(out), (
            "the reassembled payload must classify as protocol, or it lands "
            "in the chat window exactly as it did on the handset")

    def test_a_partial_set_yields_nothing(self):
        big = "?OTRv4 " + "A" * 20000
        parts, _seq = _fragment.fragment(big, 0)
        reassembler = _fragment.Reassembler()
        assert reassembler.feed(PEER, parts[0]) is None
