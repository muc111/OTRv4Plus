#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Capability first, then OTRv4+ -- and only to the resource that has it.

The rule: never send OTRv4+ protocol traffic to an XMPP resource that has not
first been identified as OTRv4Plus-capable (XEP-0030 feature / XEP-0115 caps,
or an OTRv4+ frame that resource itself sent). No DAKE to find out, no
fallback to legacy OTRv4, no bare-JID routing, and no silent plaintext for a
peer whose client does speak it.

The cases the specification requires (§47): an OTRv4Plus peer, an ordinary
XMPP peer, a legacy OTRv4 peer, a capability change, multiple resources, and
offline -> online. Driven through the real CapabilityBook, the real
XmppTransport send/presence/message paths (with a fake slixmpp client), and
real OtrApp engines doing a real DAKE.
"""

import asyncio
import os
import sys
import tempfile
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import otrv4plus_caps as caps                                          # noqa: E402

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

from android_bridge.app import BridgeError, OtrApp, SecurityState     # noqa: E402
from android_bridge.events import OtrCapabilityChanged                 # noqa: E402
from android_bridge.transport import TransportError, XmppTransport     # noqa: E402

ALICE, BOB = "alice@example.test", "bob@example.test"
LEGACY_OTR_FEATURES = ["urn:xmpp:otr:0", "urn:xmpp:otr", "http://jabber.org/protocol/otr",
                       "urn:xmpp:otrv4", "eu.siacs.conversations.axolotl.devicelist+notify",
                       "urn:xmpp:omemo:2"]


# -- the book ------------------------------------------------------------------

class TestTheBook:

    def test_an_otrv4plus_resource_is_available_and_targeted(self):
        b = caps.CapabilityBook()
        assert b.presence_available(BOB + "/phone", "v1") is True
        assert b.state(BOB) == caps.CHECKING and b.target(BOB) is None
        b.disco_result(BOB + "/phone", [caps.FEATURE, "jabber:iq:version"])
        assert b.state(BOB) == caps.AVAILABLE
        assert b.target(BOB) == BOB + "/phone"

    def test_an_ordinary_client_is_unavailable_and_never_targeted(self):
        b = caps.CapabilityBook()
        b.presence_available(BOB + "/conversations", "v2")
        b.disco_result(BOB + "/conversations", ["http://jabber.org/protocol/disco#info"])
        assert b.state(BOB) == caps.UNAVAILABLE and b.target(BOB) is None

    @pytest.mark.parametrize("feature", LEGACY_OTR_FEATURES)
    def test_legacy_otr_and_other_e2ee_are_not_otrv4plus(self, feature):
        b = caps.CapabilityBook()
        b.presence_available(BOB + "/x")
        b.disco_result(BOB + "/x", [feature])
        assert b.state(BOB) == caps.UNAVAILABLE and b.target(BOB) is None

    def test_near_miss_identifiers_are_not_accepted(self):
        b = caps.CapabilityBook()
        b.presence_available(BOB + "/x")
        b.disco_result(BOB + "/x", [caps.FEATURE + "x", caps.CAPS_NODE,
                                    caps.FEATURE.upper(), "OTRv4Plus"])
        assert b.state(BOB) == caps.UNAVAILABLE

    def test_multiple_resources_one_contact_distinct_capabilities(self):
        b = caps.CapabilityBook()
        b.presence_available(BOB + "/otr", "a", priority=0)
        b.presence_available(BOB + "/other", "b", priority=10)
        b.disco_result(BOB + "/otr", [caps.FEATURE])
        b.disco_result(BOB + "/other", ["urn:xmpp:omemo:2"])
        assert b.resources(BOB) == {"otr": True, "other": False}
        # Higher priority does not win: the incapable resource is never a target.
        assert b.target(BOB) == BOB + "/otr"
        assert b.state(BOB) == caps.AVAILABLE

    def test_a_changed_client_on_the_same_resource_is_re_asked(self):
        b = caps.CapabilityBook()
        b.presence_available(BOB + "/r", "v1")
        b.disco_result(BOB + "/r", [caps.FEATURE])
        b.pin(BOB, "r")
        assert b.presence_available(BOB + "/r", "v2") is True, "a new caps hash was trusted"
        assert b.pinned(BOB) is None
        b.disco_result(BOB + "/r", ["jabber:iq:version"])
        assert b.target(BOB) is None and b.state(BOB) == caps.UNAVAILABLE

    def test_a_reconnect_with_another_client_does_not_inherit_capability(self):
        b = caps.CapabilityBook()
        b.presence_available(BOB + "/android", "v1")
        b.disco_result(BOB + "/android", [caps.FEATURE])
        b.presence_unavailable(BOB + "/android")
        assert b.state(BOB) == caps.OFFLINE and b.target(BOB) is None
        b.presence_available(BOB + "/desktop", "v9")
        assert b.state(BOB) == caps.CHECKING and b.target(BOB) is None
        b.disco_result(BOB + "/desktop", [])
        assert b.state(BOB) == caps.UNAVAILABLE

    def test_our_own_reconnect_forgets_everything(self):
        b = caps.CapabilityBook()
        b.presence_available(BOB + "/r")
        b.disco_result(BOB + "/r", [caps.FEATURE])
        b.clear()
        assert b.target(BOB) is None and b.state(BOB) == caps.UNKNOWN

    def test_a_disco_that_does_not_answer_fails_closed(self):
        b = caps.CapabilityBook()
        b.presence_available(BOB + "/r")
        b.disco_failed(BOB + "/r")
        assert b.state(BOB) == caps.UNAVAILABLE and b.target(BOB) is None

    def test_a_known_caps_hash_needs_no_second_question(self):
        b = caps.CapabilityBook()
        b.presence_available(BOB + "/a", "hashX")
        b.disco_result(BOB + "/a", [caps.FEATURE])
        assert b.presence_available(ALICE + "/b", "hashX") is False
        assert b.state(ALICE) == caps.AVAILABLE

    def test_in_band_otrv4plus_from_a_resource_pins_it(self):
        b = caps.CapabilityBook()
        b.inband_otr(BOB + "/old-build")
        assert b.target(BOB) == BOB + "/old-build" and b.pinned(BOB) == "old-build"

    def test_the_pinned_resource_leaving_is_reported_and_nothing_else_is_targeted(self):
        b = caps.CapabilityBook()
        for r in ("one", "two"):
            b.presence_available(BOB + "/" + r)
            b.disco_result(BOB + "/" + r, [caps.FEATURE])
        b.pin(BOB, "one")
        assert b.presence_unavailable(BOB + "/one") is True
        # Unpinned: the other capable device may be targeted for a NEW DAKE.
        assert b.target(BOB) == BOB + "/two"

    def test_offline_to_online(self):
        b = caps.CapabilityBook()
        b.presence_available(BOB + "/r")
        b.disco_result(BOB + "/r", [caps.FEATURE])
        b.presence_unavailable(BOB + "/r")
        assert b.state(BOB) == caps.OFFLINE and b.target(BOB) is None
        assert b.presence_available(BOB + "/r") is True, "stale capability reused"
        b.disco_result(BOB + "/r", [caps.FEATURE])
        assert b.target(BOB) == BOB + "/r"

    def test_only_otr_protocol_is_classified_as_such(self):
        assert caps.is_otr_protocol("?OTRv4 AAAA")
        assert caps.is_otr_protocol("?OTRv4F|1|1|2|x")
        assert not caps.is_otr_protocol("hello ?OTRv4")
        assert not caps.is_otr_protocol("?OTR:AAMC")      # OTRv3 is not ours either


# -- the transport ---------------------------------------------------------------

class _Disco:
    def __init__(self, answers):
        self.answers, self.asked, self.features = answers, [], []

    async def get_info(self, jid=None, timeout=None):
        self.asked.append(str(jid))
        if jid not in self.answers:
            raise TimeoutError("no answer")
        return {"disco_info": {"features": self.answers[jid]}}

    def add_feature(self, feature):
        self.features.append(feature)


class _Client(dict):
    def __init__(self, answers):
        self.disco = _Disco(answers)
        super().__init__({"xep_0030": self.disco})
        self.sent = []
        self.boundjid = types.SimpleNamespace(resource="me", bare=ALICE)

    def send_message(self, mto=None, mbody=None, mtype=None):
        self.sent.append((str(mto), mbody))


def _transport(answers):
    t = XmppTransport.__new__(XmppTransport)
    t._caps = caps.CapabilityBook()
    t._on_capability = None
    t._on_presence = None
    t._client = _Client(answers)
    t._profile = types.SimpleNamespace(jid=ALICE + "/me", effective_server="x")
    t._frag_seq = 0
    import threading
    t._connected = threading.Event()
    t._connected.set()
    t._closed = False

    def run(coro, _timeout):
        return asyncio.run(coro)
    t._run = run
    return t


def _presence(full, available=True, ver="", priority=0):
    return {"from": full, "caps": {"ver": ver}, "priority": priority,
            "show": "", "type": "" if available else "unavailable"}


def _deliver_presence(t, *stanzas):
    async def go():
        for s, online in stanzas:
            t._presence(s, online)
        pending = [x for x in asyncio.all_tasks() if x is not asyncio.current_task()]
        if pending:
            await asyncio.gather(*pending)
    asyncio.run(go())


class TestTheWire:

    def test_otr_frames_go_only_to_the_confirmed_resource(self):
        t = _transport({BOB + "/otr": [caps.FEATURE], BOB + "/other": []})
        _deliver_presence(t, (_presence(BOB + "/otr"), True),
                          (_presence(BOB + "/other", priority=50), True))
        t.send(BOB, "?OTRv4 AAAA")
        assert t._client.sent == [(BOB + "/otr", "?OTRv4 AAAA")]
        assert t._client.disco.asked == [BOB + "/otr", BOB + "/other"]

    def test_an_ordinary_client_receives_no_otr_traffic_at_all(self):
        t = _transport({BOB + "/other": ["jabber:iq:version"]})
        _deliver_presence(t, (_presence(BOB + "/other"), True))
        with pytest.raises(TransportError) as err:
            t.send(BOB, "?OTRv4 AAAA")
        assert err.value.code == "otrv4plus_unavailable"
        with pytest.raises(TransportError):
            t.send(BOB, "?OTRv4F|1|1|3|chunk")
        assert t._client.sent == [], "OTR traffic reached an incapable client"

    def test_plaintext_is_not_routed_by_capability(self):
        t = _transport({})
        t.send(BOB, "hello")
        assert t._client.sent == [(BOB, "hello")]

    def test_nothing_is_sent_while_offline_or_unknown(self):
        t = _transport({})
        with pytest.raises(TransportError):
            t.send(BOB, "?OTRv4 AAAA")
        assert t._client.sent == []

    def test_a_resource_that_leaves_takes_its_capability_with_it(self):
        t = _transport({BOB + "/otr": [caps.FEATURE]})
        seen = []
        t._on_capability = lambda bare, left: seen.append((bare, left))
        _deliver_presence(t, (_presence(BOB + "/otr"), True))
        t.send(BOB, "?OTRv4 A")
        _deliver_presence(t, (_presence(BOB + "/otr", available=False), False))
        with pytest.raises(TransportError):
            t.send(BOB, "?OTRv4 B")
        assert (BOB, True) in seen, "the pinned resource leaving was not reported"

    def test_an_inbound_otr_frame_is_evidence_for_that_resource_only(self):
        t = _transport({})
        t._on_payload = lambda *a: None
        t._reassembler = __import__("otrv4plus_fragment").Reassembler()
        t._on_message({"type": "chat", "body": "?OTRv4 DAKE1", "from": BOB + "/termux"})
        t.send(BOB, "?OTRv4 DAKE2")
        assert t._client.sent == [(BOB + "/termux", "?OTRv4 DAKE2")]

    def test_we_advertise_the_feature(self):
        t = _transport({})
        t._client["xep_0115"] = types.SimpleNamespace(
            caps_node="", update_caps=lambda **kw: None)
        t._advertise(t._client)
        assert caps.FEATURE in t._client.disco.features
        assert t._client["xep_0115"].caps_node == caps.CAPS_NODE


# -- the app, with two real engines -----------------------------------------------

def _manager():
    d = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(d, name))
    return otr.EnhancedSessionManager(config=config)


class _CapsWire:
    """A transport with the real CapabilityBook and the real wire rule."""

    def __init__(self, me):
        self.me, self.peer_app, self.book = me, None, caps.CapabilityBook()
        self.otr_sent, self.plain_sent = [], []

    def otr_capability(self, peer):
        return self.book.state(peer)

    def send(self, peer, payload):
        if caps.is_otr_protocol(payload):
            target = self.book.target(peer)
            if target is None:
                raise TransportError("otrv4plus_unavailable", "")
            self.otr_sent.append(target)
        else:
            self.plain_sent.append(peer)
        if self.peer_app is not None:
            self.peer_app.receive_message(self.me, payload)

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


class _Sink:
    def __init__(self):
        self.events = []

    def on_event(self, e):
        self.events.append(e)


@pytest.fixture
def pair():
    otr._dake1_rate_limiter._attempts.clear()
    a_wire, b_wire = _CapsWire(ALICE), _CapsWire(BOB)
    a, b = OtrApp(_manager(), a_wire, _Sink()), OtrApp(_manager(), b_wire, _Sink())
    a_wire.peer_app, b_wire.peer_app = b, a
    yield a, b, a_wire, b_wire
    for app in (a, b):
        app.shutdown()


class TestAutomaticOtr:

    def test_an_otrv4plus_peer_gets_automatic_otr_and_a_real_session(self, pair):
        a, b, aw, bw = pair
        aw.book.presence_available(BOB + "/phone")
        aw.book.disco_result(BOB + "/phone", [caps.FEATURE])
        bw.book.presence_available(ALICE + "/me")
        bw.book.disco_result(ALICE + "/me", [caps.FEATURE])
        assert a.ensure_otr(BOB) in ("started", "established")
        assert a.security_state(BOB) is not SecurityState.PLAINTEXT
        assert aw.otr_sent and set(aw.otr_sent) == {BOB + "/phone"}
        assert a.ensure_otr(BOB) == "established"

    def test_an_ordinary_peer_gets_no_otr_traffic_and_no_encryption(self, pair):
        a, b, aw, bw = pair
        aw.book.presence_available(BOB + "/pidgin")
        aw.book.disco_result(BOB + "/pidgin", ["jabber:iq:version"])
        assert a.ensure_otr(BOB) == caps.UNAVAILABLE
        with pytest.raises(BridgeError) as err:
            a.start_session(BOB)
        assert err.value.code == "otrv4plus_unavailable"
        assert aw.otr_sent == [], "OTR traffic went to an ordinary client"
        assert a.security_state(BOB) is SecurityState.PLAINTEXT
        assert a.call_gate(BOB)["gate"] in ("otrv4plus_unavailable", "not_connected")

    def test_a_legacy_otrv4_peer_is_not_negotiated_down_to(self, pair):
        a, b, aw, bw = pair
        aw.book.presence_available(BOB + "/legacy")
        aw.book.disco_result(BOB + "/legacy", ["urn:xmpp:otr:0", "urn:xmpp:otrv4"])
        assert a.ensure_otr(BOB) == caps.UNAVAILABLE
        assert aw.otr_sent == []

    def test_offline_then_online(self, pair):
        a, b, aw, bw = pair
        assert a.ensure_otr(BOB) == caps.UNKNOWN
        aw.book.presence_available(BOB + "/r")
        assert a.ensure_otr(BOB) == caps.CHECKING
        assert aw.otr_sent == [], "a handshake before capability was confirmed"
        aw.book.disco_result(BOB + "/r", [caps.FEATURE])
        bw.book.inband_otr(ALICE + "/me")
        assert a.ensure_otr(BOB) in ("started", "established")

    def test_a_capable_peer_is_never_sent_plaintext(self, pair):
        a, b, aw, bw = pair
        aw.book.presence_available(BOB + "/r")
        aw.book.disco_result(BOB + "/r", [caps.FEATURE])
        bw.book.inband_otr(ALICE + "/me")
        outcome = a.send_user_text(BOB, "hello")
        assert outcome != a.SEND_PLAINTEXT
        assert aw.plain_sent == [], "plaintext went to an OTRv4Plus-capable peer"

    def test_an_incapable_peer_is_sent_plaintext_only_as_plaintext(self, pair):
        """Not silent: reported as SEND_PLAINTEXT, which the screen labels,
        and the conversation says OTRv4Plus is unavailable."""
        a, b, aw, bw = pair
        aw.book.presence_available(BOB + "/pidgin")
        aw.book.disco_result(BOB + "/pidgin", [])
        assert a.send_user_text(BOB, "hi") == a.SEND_PLAINTEXT
        assert aw.otr_sent == []

    def test_the_departed_resource_ends_the_session_without_downgrade(self, pair):
        a, b, aw, bw = pair
        aw.book.presence_available(BOB + "/r")
        aw.book.disco_result(BOB + "/r", [caps.FEATURE])
        bw.book.inband_otr(ALICE + "/me")
        a.ensure_otr(BOB)
        assert a.security_state(BOB) is not SecurityState.PLAINTEXT
        aw.book.pin(BOB, "r")
        left = aw.book.presence_unavailable(BOB + "/r")
        a.note_capability(BOB, left)
        assert a.security_state(BOB) is SecurityState.PLAINTEXT
        # Still OTR-requested: the next line is NOT sent in the clear.
        assert a.send_user_text(BOB, "still secret?") != a.SEND_PLAINTEXT
        assert aw.plain_sent == []
        assert any(isinstance(e, OtrCapabilityChanged) for e in a._sink.events)

    def test_capability_is_not_trust_or_verification(self, pair):
        a, b, aw, bw = pair
        aw.book.presence_available(BOB + "/r")
        aw.book.disco_result(BOB + "/r", [caps.FEATURE])
        bw.book.inband_otr(ALICE + "/me")
        a.ensure_otr(BOB)
        assert a.security_state(BOB) is not SecurityState.SMP_VERIFIED
        assert a.call_gate(BOB)["gate"] != "available"


class TestBothClientsAgree:

    def test_the_termux_client_advertises_the_same_feature(self):
        src = open(os.path.join(ROOT, "otrv4plus_xmpp.py"), encoding="utf-8").read()
        assert "_caps.FEATURE" in src and "add_feature" in src

    def test_the_android_transport_registers_entity_capabilities(self):
        src = open(os.path.join(ROOT, "android_bridge", "transport.py"), encoding="utf-8").read()
        assert '"xep_0115"' in src and "_caps.FEATURE" in src
