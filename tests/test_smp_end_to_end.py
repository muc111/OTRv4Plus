#!/usr/bin/env python3
"""SMP through two real sessions, over the real fragmentation path.

Why this file exists
--------------------
46 SMP tests passed while SMP was completely broken on a real device.

Every one of them was a unit test -- the SMP maths, the ZKP, the vault, the
state-name mapping, the bridge facade. Not one drove an SMP message through
the path a message actually takes:

    session A  ->  encrypt  ->  fragment  ->  reassemble  ->  decrypt  ->  session B

So when C1 moved OTRv4DataMessage.PROTOCOL_VERSION from 0x0004 to 0x0005, and
five separate call sites went on sniffing the literal bytes 00 04 to decide
whether a frame was a data message, the whole suite stayed green. The frames
fell through to the message-type branch, matched nothing, and were dropped
with "unknown message type: 0" and no error shown to the user. DAKE kept
working, because DAKE frames are classified by their own type byte -- so a
session would establish, pin fingerprints, and then silently discard the
first data message it was asked to carry. That first message is SMP1.

These tests exist so a version bump can never again pass CI while making the
product unable to send a single encrypted message.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")

SECRET = "correct horse battery staple"


def _manager():
    """A session manager with all persistent state in a throwaway directory."""
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


def _relay(first, sender, receiver, sender_id, receiver_id, limit=10):
    """Pass OTR frames back and forth until one side stops replying.

    Returns the number of frames delivered, which is how these tests tell a
    protocol that ran from one that stalled on its first message.
    """
    current = first
    delivered = 0
    for _ in range(limit):
        if not current:
            break
        out = receiver.handle_incoming_message(sender_id, current)
        delivered += 1
        text = out.decode() if isinstance(out, (bytes, bytearray)) else out
        if not text or not text.startswith("?OTRv4"):
            break
        current = text
        sender, receiver = receiver, sender
        sender_id, receiver_id = receiver_id, sender_id
    return delivered


@pytest.fixture
def pair():
    """Two managers with a completed DAKE between them."""
    alice_mgr, bob_mgr = _manager(), _manager()
    alice, bob = "alice@example.test", "bob@example.test"

    dake1, _send = alice_mgr.handle_outgoing_message(bob, "")
    assert dake1, "no DAKE1 produced"
    _relay(dake1, alice_mgr, bob_mgr, alice, bob)

    assert alice_mgr.has_encrypted_session(bob), "initiator never reached ENCRYPTED"
    assert bob_mgr.has_encrypted_session(alice), "responder never reached ENCRYPTED"
    return alice_mgr, bob_mgr, alice, bob


# ── The classifier that broke ────────────────────────────────────────────────

class TestDataFrameClassification:
    """The five call sites now share one classifier derived from the constant."""

    def _frame(self):
        msg = otr.OTRv4DataMessage()
        msg.sender_tag, msg.receiver_tag = 0x0101, 0x0202
        msg.flags = msg.prev_chain_len = msg.ratchet_id = msg.message_id = 0
        msg.ecdh_pub, msg.nonce = bytes(56), bytes(12)
        msg.ciphertext, msg.revealed_mac_keys = b"payload", []
        msg.mac = bytes(64)
        return msg.encode()

    def test_the_encoder_and_the_classifier_agree(self):
        """THE regression. These drifted apart and nothing noticed."""
        assert otr.OTRv4DataMessage.looks_like_data_frame(self._frame()), (
            "the classifier does not recognise this build's own data frame -- "
            "every encrypted message will be dropped as an unknown type")

    def test_the_classifier_tracks_the_constant(self):
        """Derived, not hardcoded: a future bump must carry it along."""
        frame = self._frame()
        version = otr.OTRv4DataMessage.PROTOCOL_VERSION
        assert frame[0] == (version >> 8)
        assert frame[1] == (version & 0xFF)
        assert frame[2] == otr.OTRv4DataMessage.TYPE

    def test_a_previous_revision_is_not_classified_as_current(self):
        frame = bytearray(self._frame())
        frame[1] = 0x04
        assert not otr.OTRv4DataMessage.looks_like_data_frame(bytes(frame))

    def test_a_dake_frame_is_not_a_data_frame(self):
        for dake_type in (0x35, 0x36, 0x37):
            assert not otr.OTRv4DataMessage.looks_like_data_frame(
                bytes([dake_type, 0x00, 0x00]))

    @pytest.mark.parametrize("short", [b"", b"\x00", b"\x00\x05"])
    def test_a_truncated_frame_is_refused_without_raising(self, short):
        assert otr.OTRv4DataMessage.looks_like_data_frame(short) is False

    def test_no_call_site_hardcodes_the_version_bytes(self):
        """The literals are what made a one-constant change silently fatal."""
        import re
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "otrv4+.py")
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        offenders = re.findall(r"(?:decoded|peek)\[1\]\s*==\s*0x0[45]", source)
        assert not offenders, (
            "%d call site(s) still sniff the data-message version as a "
            "literal; they will not follow PROTOCOL_VERSION" % len(offenders))


# ── SMP end to end ───────────────────────────────────────────────────────────

class TestSmpEndToEnd:

    def test_smp_runs_to_completion(self, pair):
        """The whole point: SMP must actually exchange messages.

        Stalling after one delivery is the exact failure this file was written
        for -- SMP1 accepted by the transport, dropped by the classifier, and
        no reply ever produced.
        """
        alice_mgr, bob_mgr, alice, bob = pair
        alice_mgr.set_smp_secret(bob, SECRET)
        bob_mgr.set_smp_secret(alice, SECRET)

        smp1 = alice_mgr.start_smp(bob, SECRET)
        assert smp1, "start_smp produced nothing"

        delivered = _relay(smp1, alice_mgr, bob_mgr, alice, bob)
        assert delivered > 1, (
            "SMP stalled after the first message: the peer accepted SMP1 and "
            "produced no reply, which is what a dropped data frame looks like")

    def test_the_first_data_message_is_not_silently_dropped(self, pair):
        """Narrower than SMP, and the property that actually broke.

        An established session must be able to carry one encrypted message.
        A None here means the frame was discarded with no error -- exactly
        how this presented to a user: DAKE succeeded, fingerprints were
        pinned, and then nothing worked.
        """
        alice_mgr, bob_mgr, alice, bob = pair
        wire, should_send = alice_mgr.handle_outgoing_message(bob, "hello there")
        assert should_send and wire and wire.startswith("?OTRv4")

        out = bob_mgr.handle_incoming_message(alice, wire)
        assert out is not None, (
            "the receiver dropped an encrypted data message without an error")
        text = out.decode() if isinstance(out, (bytes, bytearray)) else out
        assert "hello there" in text

    def test_smp1_is_large_enough_to_fragment(self, pair):
        """Documents why the fragmentation path is on SMP's critical route."""
        alice_mgr, bob_mgr, alice, bob = pair
        alice_mgr.set_smp_secret(bob, SECRET)
        bob_mgr.set_smp_secret(alice, SECRET)
        smp1 = alice_mgr.start_smp(bob, SECRET)
        assert len(smp1) > 6000, (
            "SMP1 no longer exceeds the 6000-byte fragment threshold; the "
            "fragmentation coverage below is testing nothing")


# ── The fragmentation path SMP depends on ────────────────────────────────────

class TestFragmentationRoundTrip:
    """send_otr_fragmented -> _reassemble_fragment, with the real methods.

    Bound to stub objects rather than a live client so this needs no XMPP
    connection; the methods under test are the ones the client calls.
    """

    @pytest.fixture
    def client_cls(self):
        xmpp = pytest.importorskip(
            "otrv4plus_xmpp", reason="slixmpp not installed")
        return xmpp.OTRv4PlusXMPP

    class _Stub:
        def __init__(self):
            self.sent = []
            self._frag_seq = 0
            self._probe = True          # suppress the progress print
        def send_message(self, mto=None, mbody=None, mtype=None):
            self.sent.append(mbody)
        def _dbg(self, *args, **kwargs):
            pass

    def _round_trip(self, client_cls, payload):
        peer = "alice@example.test"
        tx = self._Stub()
        client_cls.send_otr_fragmented(tx, peer, payload)
        rx = self._Stub()
        reassembled = None
        for fragment in tx.sent:
            if not fragment.startswith("?OTRv4F|"):
                reassembled = fragment          # sent whole, never fragmented
                continue
            result = client_cls._reassemble_fragment(rx, peer, fragment)
            if result is not None:
                reassembled = result
        return reassembled, len(tx.sent)

    @pytest.mark.parametrize("size", [6001, 8100, 12000, 18000, 24000])
    def test_a_fragmented_payload_survives_the_round_trip(self, client_cls, size):
        payload = "?OTRv4 " + "A" * (size - 7)
        reassembled, fragments = self._round_trip(client_cls, payload)
        assert fragments > 1, "%d bytes did not fragment" % size
        assert reassembled == payload, "reassembly corrupted the payload"

    def test_a_small_payload_is_sent_whole(self, client_cls):
        payload = "?OTRv4 " + "A" * 500
        reassembled, fragments = self._round_trip(client_cls, payload)
        assert fragments == 1
        assert reassembled == payload

    def test_an_smp_sized_payload_reassembles(self, client_cls):
        """8100 bytes is the observed SMP1 size on this build."""
        payload = "?OTRv4 " + "B" * 8093
        reassembled, fragments = self._round_trip(client_cls, payload)
        assert fragments == 2
        assert reassembled == payload

    def test_fragments_arriving_out_of_order_still_reassemble(self, client_cls):
        peer = "alice@example.test"
        payload = "?OTRv4 " + "C" * 12000
        tx = self._Stub()
        client_cls.send_otr_fragmented(tx, peer, payload)
        assert len(tx.sent) > 1

        rx = self._Stub()
        reassembled = None
        for fragment in reversed(tx.sent):
            result = client_cls._reassemble_fragment(rx, peer, fragment)
            if result is not None:
                reassembled = result
        assert reassembled == payload, "out-of-order fragments did not reassemble"

    def test_a_missing_fragment_yields_nothing_rather_than_garbage(self, client_cls):
        """The failure mode seen on the device: one fragment lost, silence.

        Incomplete must stay incomplete -- never a partial payload handed to
        the decoder.
        """
        peer = "alice@example.test"
        payload = "?OTRv4 " + "D" * 12000
        tx = self._Stub()
        client_cls.send_otr_fragmented(tx, peer, payload)
        assert len(tx.sent) >= 2

        rx = self._Stub()
        for fragment in tx.sent[:-1]:           # drop the last one
            assert client_cls._reassemble_fragment(rx, peer, fragment) is None
