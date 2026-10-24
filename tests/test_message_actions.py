# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Correct, delete for everyone, react, reply -- through two real bridges.

Owner (2026-10-14): "anything else conversations app uses".

In an ENCRYPTED conversation the action travels inside the OTR payload
(MESSAGE_META, TLV 0x0021): these tests drive two real OtrApps over a real
OTRv4 session and check (1) what the other side is told, (2) that nothing
about the action is outside the ciphertext, and (3) the rules: an action
with no session is refused, never sent in the clear.
"""
from __future__ import annotations

import os
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

import otrv4plus_actions as A                                      # noqa: E402
from android_bridge.app import OtrApp, Transport                   # noqa: E402
from android_bridge import events as E                             # noqa: E402
from android_bridge.events import SecurityState                    # noqa: E402


class Wire(Transport):
    def __init__(self):
        self.sent, self.typed = [], []
        self.peer_app = self.peer_id = None

    def _deliver(self, text):
        if self.peer_app is not None:
            self.peer_app.receive_message(self.peer_id, text)

    def send(self, peer, payload):
        text = payload.decode() if isinstance(payload, (bytes, bytearray)) else str(payload)
        self.sent.append((peer, text))
        self._deliver(text)

    def send_typed(self, peer, payload, message_id):
        self.typed.append((peer, payload, message_id))
        self.send(peer, payload)

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


class Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)

    def of(self, kind):
        return [e for e in self.events if isinstance(e, kind)]


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


@pytest.fixture
def pair():
    a_jid = "alice-%s@example.test" % uuid.uuid4().hex[:8]
    b_jid = "bob-%s@example.test" % uuid.uuid4().hex[:8]
    otr._dake1_rate_limiter._attempts.clear()
    aw, bw = Wire(), Wire()
    alice, bob = OtrApp(_manager(), aw), OtrApp(_manager(), bw)
    aw.peer_app, aw.peer_id = bob, a_jid
    bw.peer_app, bw.peer_id = alice, b_jid
    sinks = Sink(), Sink()
    alice.set_event_sink(sinks[0])
    bob.set_event_sink(sinks[1])
    alice.start_session(b_jid)
    assert alice.security_state(b_jid) is not SecurityState.PLAINTEXT
    yield alice, bob, a_jid, b_jid, aw, sinks[1]
    for app in (alice, bob):
        try:
            app.shutdown()
        except Exception:
            pass


def test_an_encrypted_message_carries_its_authenticated_id_and_reply(pair):
    alice, bob, a_jid, b_jid, aw, bob_sees = pair
    assert alice.send_user_text(b_jid, "first", "ID1") == alice.SEND_ENCRYPTED
    assert alice.send_user_text(b_jid, "re: first", "ID2", reply_to="ID1") == alice.SEND_ENCRYPTED
    got = bob_sees.of(E.MessageReceived)
    assert [(m.body, m.message_id, m.reply_to) for m in got] == [
        ("first", "ID1", ""), ("re: first", "ID2", "ID1")]
    # The id also went on the stanza (receipts); nothing about the reply did.
    assert aw.typed[-1][2] == "ID2"
    assert all(p.startswith("?OTRv4") for _, p, _ in aw.typed)


def test_correct_delete_and_react_arrive_as_changes(pair):
    alice, bob, a_jid, b_jid, aw, bob_sees = pair
    alice.send_user_text(b_jid, "teh typo", "ID1")
    assert alice.send_action(b_jid, "edit", "ID1", body="the typo") == alice.SEND_ENCRYPTED
    assert alice.send_action(b_jid, "react", "ID1", emojis=["\U0001F44D", "\U0001F44D", "x" * 40]) \
        == alice.SEND_ENCRYPTED
    assert alice.send_action(b_jid, "retract", "ID1") == alice.SEND_ENCRYPTED
    changes = bob_sees.of(E.MessageChanged)
    assert [(c.action, c.target_id, c.body, c.emojis) for c in changes] == [
        ("edit", "ID1", "the typo", ()),
        ("react", "ID1", "", ("\U0001F44D",)),
        ("retract", "ID1", "", ())]
    # None of them was also shown as a new message.
    assert [m.body for m in bob_sees.of(E.MessageReceived)] == ["teh typo"]
    # Every one is a sealed OTR frame: nothing about the action outside it.
    assert all(text.startswith("?OTRv4") for _, text in aw.sent)


def test_bad_actions_are_refused():
    app = OtrApp.__new__(OtrApp)
    assert OtrApp.send_action(app, "bob@x", "delete-everything", "ID1") == OtrApp.SEND_FAILED
    assert OtrApp.send_action(app, "bob@x", "edit", "bad id with spaces") == OtrApp.SEND_FAILED


def test_an_edit_with_no_text_is_refused(pair):
    alice, bob, a_jid, b_jid, aw, bob_sees = pair
    assert alice.send_action(b_jid, "edit", "ID1", body="  ") == alice.SEND_FAILED


def test_no_session_means_no_action_in_the_clear():
    """A conversation that asked for OTR but has no session: refused, not
    queued, and above all not sent as plaintext XEP elements."""
    sent = []

    class T(Transport):
        def send(self, peer, payload): sent.append(payload)
        def send_plain_action(self, *a): sent.append(a)
        def connect(self): pass
        def disconnect(self): pass
        def roster(self): return []

    app = OtrApp(_manager(), T())
    app._mode.request("bob@example.test")
    assert app.send_action("bob@example.test", "react", "ID1", emojis=["x"]) == app.SEND_FAILED
    assert sent == []


def test_a_one_to_one_action_never_goes_in_the_clear():
    """Owner, 2026-10-24: never plaintext between 1:1 users. A correction,
    deletion or reaction without an encrypted session is refused and nothing
    is sent (it used to go as standard XMPP elements)."""
    sent = []

    class T(Transport):
        def send(self, peer, payload): sent.append(("send", payload))
        def send_plain_action(self, peer, body, mid, elements):
            sent.append((body, [e.tag for e in elements]))
        def connect(self): pass
        def disconnect(self): pass
        def roster(self): return []

    app = OtrApp(_manager(), T())
    assert app.send_action("carol@example.test", "edit", "ID1", body="fixed") == app.SEND_FAILED
    assert app.send_action("carol@example.test", "retract", "ID1") == app.SEND_FAILED
    assert app.send_action("carol@example.test", "react", "ID1", emojis=["ok"]) == app.SEND_FAILED
    assert sent == []


def test_meta_codec_rules():
    raw = A.encode_meta("ID1", react="ID0", emojis=["a", "a", "b"])
    assert A.decode_meta(raw) == {"id": "ID1", "action": "react", "target": "ID0",
                                  "emojis": ["a", "b"], "reply": ""}
    with pytest.raises(ValueError):
        A.encode_meta("ID1", edit="A", retract="B")
    for bad in (b"not json", b'{"v":2,"id":"x"}', b'{"v":1,"id":"x","edit":"a","retract":"b"}',
                b'{"v":1,"id":"has space"}', b"x" * (A.MAX_META + 1)):
        assert A.decode_meta(bad) is None


def test_plaintext_elements_parse_back():
    for action, extra in (("edit", {}), ("retract", {}), ("react", {"emojis": ["a"]})):
        msg = ET.Element("{jabber:client}message")
        for el in A.action_elements(action, "ID9", **extra):
            msg.append(el)
        got = A.parse_action(msg)
        assert (got["action"], got["target"]) == (action, "ID9")
    msg = ET.Element("{jabber:client}message")
    for el in A.action_elements("reply", "ID3", reply_to_jid="bob@x/p"):
        msg.append(el)
    assert A.parse_action(msg)["reply"] == "ID3"
    # Two actions at once are ambiguous: neither is applied.
    msg = ET.Element("{jabber:client}message")
    for el in A.action_elements("edit", "A") + A.action_elements("retract", "B"):
        msg.append(el)
    assert A.parse_action(msg)["action"] == ""
