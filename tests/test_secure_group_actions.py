# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Reply, correct, delete for everyone and react in a SECURE GROUP: inside
MLS, and bound to the MLS-authenticated JID of the author -- never a
nickname. Real Rust MLS; the simulated room of test_secure_groups."""
from __future__ import annotations

import base64
import json

import pytest

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustMlsClient"):
    pytest.skip("this core was built without the mls feature", allow_module_level=True)

import otrv4plus_actions as A                                          # noqa: E402
from android_bridge.events import MessageChanged, RoomMessageReceived, SecurityState  # noqa: E402
from android_bridge.groups import ROOM_PREFIX, SIGNAL_PREFIX           # noqa: E402
from test_secure_groups import ROOM, World, _group                    # noqa: E402,F401


def env(mid, text="", **action):
    return A.encode_group_message(A.encode_meta(mid, **action), text)


def received(m):
    return [e for e in m.events if isinstance(e, RoomMessageReceived)]


def changed(m):
    return [e for e in m.events if isinstance(e, MessageChanged)]


def test_a_message_carries_its_id_and_reply_and_the_room_sees_only_ciphertext():
    w, (a, b, c) = _group(3)
    b.groups.send(ROOM, env("id-B1", "lunch at noon?"))
    c.groups.send(ROOM, env("C1", "yes", reply="id-B1"))
    got = [(e.sender_identity, e.body, e.message_id, e.reply_to) for e in received(a)]
    assert got == [("bob@x.i2p", "lunch at noon?", "id-B1", ""),
                   ("carol@x.i2p", "yes", "C1", "id-B1")]
    for _who, body in w.room.log:
        assert body.startswith((ROOM_PREFIX, "?OTRv4F|"))
        # Spaces and '-' never occur in base64: these would be plaintext.
        assert "lunch at noon?" not in body and "id-B1" not in body


def test_the_author_corrects_deletes_and_anyone_reacts():
    w, (a, b, c) = _group(3)
    b.groups.send(ROOM, env("B1", "teh plan"))
    b.groups.send(ROOM, env("B2", "the plan", edit="B1"))
    c.groups.send(ROOM, env("C9", react="B1", emojis=["\U0001F44D"]))
    b.groups.send(ROOM, env("B3", retract="B1"))
    got = [(e.action, e.target_id, e.body, e.emojis, e.sender_identity) for e in changed(a)]
    assert got == [("edit", "B1", "the plan", (), "bob@x.i2p"),
                   ("react", "B1", "", ("\U0001F44D",), "carol@x.i2p"),
                   ("retract", "B1", "", (), "bob@x.i2p")]
    # An action is never also shown as a message.
    assert [e.body for e in received(a)] == ["teh plan"]


def test_only_the_authors_jid_may_correct_or_delete():
    w, (a, b, c) = _group(3)
    b.groups.send(ROOM, env("B1", "I owe Carol 10"))
    # Carol -- a different MLS identity -- tries to rewrite and delete Bob's line.
    c.groups.send(ROOM, env("C2", "I owe Carol 1000", edit="B1"))
    c.groups.send(ROOM, env("C3", retract="B1"))
    assert changed(a) == []
    assert a.groups.stats.wrong_author == 2


def test_a_nickname_proves_nothing():
    """The room says the line came from "bob" -- but MLS says Carol sent it:
    the identity is MLS's, whatever nickname the room attaches."""
    w, (a, b, c) = _group(3)
    b.groups.send(ROOM, env("B1", "hello"))
    ct = c.groups._need().encrypt(ROOM.encode(), env("C2", "forged", edit="B1").encode())
    body = ROOM_PREFIX + base64.b64encode(bytes(ct)).decode()
    # Delivered under Bob's nickname (a room that let Carol take it).
    a.groups.on_room_body(ROOM, "bob", body, 0.0)
    assert changed(a) == []


def test_malformed_envelopes_are_dropped_never_shown():
    w, (a, b) = _group(2)
    for bad in (A.GROUP_PREFIX + "not json", A.GROUP_PREFIX + json.dumps({"m": {"v": 2}, "t": "x"}),
                A.GROUP_PREFIX + json.dumps({"m": {"v": 1, "id": "has space"}, "t": "x"})):
        b.groups.send(ROOM, bad)
    assert received(a) == [] and changed(a) == []
    assert a.groups.stats.malformed == 3


def test_a_key_package_naming_someone_else_never_joins():
    """Mallory, invited over her own OTR session, hands over a KeyPackage
    whose MLS credential says "bob@x.i2p". It must not be added -- and Bob's
    real leaf must not be removed as "stale"."""
    w, (a, b) = _group(2)
    mallory = w.add("mallory@x.i2p")
    w.pair("alice@x.i2p", "mallory@x.i2p", SecurityState.ENCRYPTED)
    mallory.join_room()
    a.groups.invite(ROOM, "mallory@x.i2p")
    forged = core.RustMlsClient(b"bob@x.i2p")
    kp = base64.b64encode(bytes(forged.key_package())).decode()
    a.groups.on_signal("mallory@x.i2p", SIGNAL_PREFIX + "KP:%s|%s" % (ROOM, kp))
    jids = sorted(m["jid"] for m in a.groups.members(ROOM))
    assert jids == ["alice@x.i2p", "bob@x.i2p"]
    # Bob still talks, as Bob.
    b.groups.send(ROOM, env("B1", "still me"))
    assert ("bob@x.i2p", "still me") in [(e.sender_identity, e.body) for e in received(a)]


def test_same_localpart_on_another_server_is_someone_else():
    w, (a, b) = _group(2)
    other = w.add("bob@y.i2p")
    w.pair("alice@x.i2p", "bob@y.i2p", SecurityState.ENCRYPTED)
    other.join_room()
    a.groups.invite(ROOM, "bob@y.i2p")
    forged = core.RustMlsClient(b"bob@x.i2p")
    kp = base64.b64encode(bytes(forged.key_package())).decode()
    a.groups.on_signal("bob@y.i2p", SIGNAL_PREFIX + "KP:%s|%s" % (ROOM, kp))
    assert sorted(m["jid"] for m in a.groups.members(ROOM)) == ["alice@x.i2p", "bob@x.i2p"]


def test_rust_refuses_an_unbound_add_even_if_python_did_not_check():
    w, (a, b) = _group(2)
    forged = core.RustMlsClient(b"bob@x.i2p")
    with pytest.raises(ValueError):
        a.groups._need().add_members(ROOM.encode(), [bytes(forged.key_package())],
                                     identities=[b"mallory@x.i2p"])


# -- the app: what goes into MLS -------------------------------------------------

class CaptureGroups:
    def __init__(self):
        self.sent = []

    def is_secure(self, room):
        return True

    def send(self, room, text):
        self.sent.append((room, text))
        return "sent"

    def on_room_body(self, *a, **k):
        return True

    def close(self):
        pass


@pytest.fixture
def app():
    import os
    import tempfile
    otr = pytest.importorskip("otrv4_")
    from android_bridge.app import OtrApp, Transport

    class Wire(Transport):
        def send(self, peer, payload): raise AssertionError("plaintext to a secure group")
        def send_room_message(self, *a, **k): raise AssertionError("plaintext to a secure group")
        def connect(self): pass
        def disconnect(self): pass
        def roster(self): return []

    d = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"), ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        setattr(config, attribute, os.path.join(d, name))
    a = OtrApp(otr.EnhancedSessionManager(config=config), Wire())
    a.note_room_joined(ROOM)
    a._groups = CaptureGroups()
    yield a
    a._groups = None
    a.shutdown()


def test_the_app_sends_typed_lines_and_actions_only_inside_mls(app):
    assert app.send_user_text(ROOM, "hello", "W1") == app.SEND_ENCRYPTED
    assert app.send_user_text(ROOM, "re", "W2", reply_to="B1") == app.SEND_ENCRYPTED
    assert app.send_action(ROOM, "edit", "W1", body="hello!", message_id="W3") == app.SEND_ENCRYPTED
    assert app.send_action(ROOM, "retract", "W1", message_id="W4") == app.SEND_ENCRYPTED
    assert app.send_action(ROOM, "react", "B1", emojis=["ok"], message_id="W5") == app.SEND_ENCRYPTED
    assert app.send_action(ROOM, "edit", "W1", body="  ") == app.SEND_FAILED
    decoded = [A.decode_group_message(t) for _r, t in app._groups.sent]
    assert [(m["id"], m["action"], m["target"], m["reply"], t) for m, t in decoded] == [
        ("W1", "", "", "", "hello"), ("W2", "", "", "B1", "re"),
        ("W3", "edit", "W1", "", "hello!"), ("W4", "retract", "W1", "", ""),
        ("W5", "react", "B1", "", "")]


def test_a_plaintext_action_in_a_secure_group_is_still_ignored(app):
    import otrv4plus_roomsync as RS
    import xml.etree.ElementTree as ET
    sink = []
    app._emit = sink.append
    el = ET.fromstring(
        "<message xmlns='jabber:client' type='groupchat' from='%s/bob' id='x'>"
        "<body>forged</body><replace xmlns='urn:xmpp:message-correct:0' id='B1'/></message>" % ROOM)
    item = RS.parse_room_message(el)
    app.receive_room_message(ROOM, "bob", "forged", 0.0, item=item)
    assert not [e for e in sink if isinstance(e, MessageChanged)]
