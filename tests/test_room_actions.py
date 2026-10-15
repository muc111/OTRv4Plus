# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Plain rooms: ids, replies, corrections, deletions, reactions, and the
room's own archive (otrv4plus_roomsync, android_bridge.room_sync)."""
from __future__ import annotations

import asyncio
import os
import tempfile
import xml.etree.ElementTree as ET

import pytest

otr = pytest.importorskip("otrv4_")
pytest.importorskip("slixmpp")

import otrv4plus_actions as A                                     # noqa: E402
import otrv4plus_roomsync as RS                                   # noqa: E402
import otrv4plus_sync as S                                        # noqa: E402
from android_bridge import events as E                           # noqa: E402
from android_bridge.app import OtrApp, Transport                  # noqa: E402
from test_android_sync import FakeStanza, transport, ME           # noqa: E402

ROOM = "lobby@rooms.example.test"


def room_msg(nick, body=None, mid="o1", sid="", extra="", by=ROOM, stamp=""):
    parts = ["<message xmlns='jabber:client' type='groupchat' from='%s/%s' id='%s'>"
             % (ROOM, nick, mid)]
    if body is not None:
        parts.append("<body>%s</body>" % body)
    parts.append("<origin-id xmlns='urn:xmpp:sid:0' id='%s'/>" % mid)
    if sid:
        parts.append("<stanza-id xmlns='urn:xmpp:sid:0' by='%s' id='%s'/>" % (by, sid))
    if stamp:
        parts.append("<delay xmlns='urn:xmpp:delay' stamp='%s'/>" % stamp)
    parts.append(extra + "</message>")
    return ET.fromstring("".join(parts))


# -- parsing ---------------------------------------------------------------------

def test_the_rooms_id_is_only_taken_from_the_room():
    item = RS.parse_room_message(room_msg("bob", "hi", sid="R1"))
    assert (item.room, item.nick, item.own_id, item.stanza_id, item.ref) == (
        ROOM, "bob", "o1", "R1", "R1")
    forged = RS.parse_room_message(room_msg("bob", "hi", sid="R1", by="evil@x"))
    assert forged.stanza_id == "" and forged.ref == "o1"


def test_subjects_and_the_room_itself_are_not_messages():
    assert RS.parse_room_message(ET.fromstring(
        "<message xmlns='jabber:client' type='groupchat' from='%s'><body>x</body></message>" % ROOM)) is None
    assert RS.parse_room_message(ET.fromstring(
        "<message xmlns='jabber:client' type='chat' from='%s/bob'><body>x</body></message>" % ROOM)) is None


def test_actions_are_read_and_protocol_bodies_carry_none():
    el = room_msg("bob", "fixed", mid="o2", extra="<replace xmlns='urn:xmpp:message-correct:0' id='o1'/>")
    item = RS.parse_room_message(el)
    assert (item.action, item.target) == ("edit", "o1")
    el = room_msg("bob", "?OTRv4MLS1:abc", extra="<replace xmlns='urn:xmpp:message-correct:0' id='o1'/>")
    assert RS.parse_room_message(el).action == ""


def test_refs_map_both_ways_and_see_each_message_once():
    refs = RS.RoomRefs()
    refs.remember(ROOM, "o1", "R1")
    assert refs.resolve(ROOM, "o1") == "R1" and refs.resolve(ROOM, "R1") == "R1"
    assert refs.own_id_of(ROOM, "R1") == "o1" and refs.own_id_of(ROOM, "zz") == "zz"
    item = RS.parse_room_message(room_msg("bob", "hi", sid="R1"))
    assert refs.first_time(item) and not refs.first_time(item)


def test_archive_results_only_from_the_room_and_our_query():
    wrap = ("<message xmlns='jabber:client' from='%s'><result xmlns='urn:xmpp:mam:2' queryid='q1' id='R7'>"
            "<forwarded xmlns='urn:xmpp:forward:0'><delay xmlns='urn:xmpp:delay' stamp='2026-10-14T08:00:00Z'/>"
            "<message xmlns='jabber:client' type='groupchat' from='%s/bob' id='o7'><body>old</body></message>"
            "</forwarded></result></message>")
    got = RS.parse_room_archive(ET.fromstring(wrap % (ROOM, ROOM)), ROOM, "q1")
    assert got[0] == "R7" and got[1].stanza_id == "R7" and got[1].source == "archive"
    assert RS.parse_room_archive(ET.fromstring(wrap % ("evil@x", ROOM)), ROOM, "q1") is None
    assert RS.parse_room_archive(ET.fromstring(wrap % (ROOM, ROOM)), ROOM, "q2") is None


# -- the app ---------------------------------------------------------------------

class Wire(Transport):
    def __init__(self):
        self.room = []

    def send(self, peer, payload):
        raise AssertionError("room traffic went out as chat")

    def send_room_message(self, room, body, volatile=False, message_id="", elements=None):
        self.room.append((room, body, message_id, [e.tag for e in (elements or [])],
                          [e.get("id") for e in (elements or [])]))

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


class Sink:
    def __init__(self):
        self.events = []

    def on_event(self, e):
        self.events.append(e)

    def of(self, kind):
        return [e for e in self.events if isinstance(e, kind)]


def _manager():
    d = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        setattr(config, attribute, os.path.join(d, name))
    return otr.EnhancedSessionManager(config=config)


@pytest.fixture
def app():
    wire, sink = Wire(), Sink()
    a = OtrApp(_manager(), wire, sink)
    a.note_room_joined(ROOM)
    a.wire, a.sink = wire, sink
    yield a
    a.shutdown()


def deliver(app, el, own=False, body=None):
    item = RS.parse_room_message(el)
    app.receive_room_message(ROOM, item.nick, item.body if body is None else body,
                             item.when, own=own, item=item)


def test_a_message_carries_the_rooms_id_and_its_reply(app):
    deliver(app, room_msg("bob", "first", mid="o1", sid="R1"))
    deliver(app, room_msg("carol", "re", mid="o2", sid="R2",
                          extra="<reply xmlns='urn:xmpp:reply:0' id='R1'/>"))
    got = app.sink.of(E.RoomMessageReceived)
    assert [(m.sender, m.message_id, m.reply_to) for m in got] == [
        ("bob", "R1", ""), ("carol", "R2", "R1")]


def test_the_same_message_live_and_archived_is_one(app):
    deliver(app, room_msg("bob", "hi", sid="R1"))
    deliver(app, room_msg("bob", "hi", sid="R1", stamp="2026-10-14T08:00:00Z"))
    assert len(app.sink.of(E.RoomMessageReceived)) == 1


def test_our_echo_only_tells_the_ui_the_rooms_id(app):
    deliver(app, room_msg("me", None, mid="W1", sid="R9"), own=True, body="")
    assert [(a.message_id, a.stanza_id) for a in app.sink.of(E.RoomMessageAcked)] == [("W1", "R9")]
    assert app.sink.of(E.RoomMessageReceived) == []


def test_a_correction_names_the_sender_id_and_is_resolved_to_the_rooms(app):
    deliver(app, room_msg("bob", "teh", mid="o1", sid="R1"))
    deliver(app, room_msg("bob", "the", mid="o2", sid="R2",
                          extra="<replace xmlns='urn:xmpp:message-correct:0' id='o1'/>"))
    change = app.sink.of(E.MessageChanged)[-1]
    assert (change.action, change.target_id, change.body, change.sender) == ("edit", "R1", "the", "bob")
    assert len(app.sink.of(E.RoomMessageReceived)) == 1, "a correction is not a new message"


def test_reactions_and_deletions_in_a_room(app):
    deliver(app, room_msg("bob", "lunch?", mid="o1", sid="R1"))
    deliver(app, room_msg("carol", None, mid="o3", sid="R3",
                          extra="<reactions xmlns='urn:xmpp:reactions:0' id='R1'><reaction>ok</reaction></reactions>"),
            body="")
    deliver(app, room_msg("bob", A.RETRACT_FALLBACK, mid="o4", sid="R4",
                          extra="<retract xmlns='urn:xmpp:message-retract:1' id='R1'/>"))
    changes = [(c.action, c.target_id, c.emojis, c.sender) for c in app.sink.of(E.MessageChanged)]
    assert changes == [("react", "R1", ("ok",), "carol"), ("retract", "R1", (), "bob")]


def test_sending_in_a_room_uses_ids_and_the_standard_elements(app):
    assert app.send_user_text(ROOM, "hello", "W1") == app.SEND_PLAINTEXT
    assert app.send_user_text(ROOM, "re", "W2", reply_to="R1") == app.SEND_PLAINTEXT
    # The room gave W1 the id R9.
    deliver(app, room_msg("me", None, mid="W1", sid="R9"), own=True, body="")
    assert app.send_action(ROOM, "edit", "R9", body="hello!", message_id="W3") == app.SEND_PLAINTEXT
    assert app.send_action(ROOM, "react", "R5", emojis=["ok"], message_id="W4") == app.SEND_PLAINTEXT
    assert app.send_action(ROOM, "retract", "R9", message_id="W5") == app.SEND_PLAINTEXT
    sent = app.wire.room
    assert sent[0][:3] == (ROOM, "hello", "W1")
    assert sent[1][3] == ["{urn:xmpp:reply:0}reply"] and sent[1][4] == ["R1"]
    # A correction names OUR id for the message; reaction and deletion the room's.
    assert sent[2][1] == "hello!" and sent[2][4] == ["W1"]
    assert sent[3][1] is None and sent[3][4][0] == "R5"
    assert sent[4][1] == A.RETRACT_FALLBACK and sent[4][4][0] == "R9"


def test_a_secure_group_never_takes_a_plaintext_action(app):
    class Groups:
        def is_secure(self, room): return True
        def on_room_body(self, *a, **k): return True
        def close(self): pass
    app._groups = Groups()
    deliver(app, room_msg("bob", "x", mid="o2",
                          extra="<replace xmlns='urn:xmpp:message-correct:0' id='o1'/>"))
    assert app.sink.of(E.MessageChanged) == []
    assert app.send_action(ROOM, "react", "R1", emojis=["ok"]) == app.SEND_FAILED
    app._groups = None


# -- the transport: bodiless reactions, the room's archive -----------------------

def test_a_bodiless_room_reaction_reaches_the_handler():
    t, c, _ = transport()
    t._our_nick = lambda room: "me"
    got = []
    t.set_room_handler(lambda *a, **k: got.append((a, k)))
    el = room_msg("carol", None, mid="o3", sid="R3",
                  extra="<reactions xmlns='urn:xmpp:reactions:0' id='R1'><reaction>ok</reaction></reactions>")
    t._on_any_message(FakeStanza(c, el))
    assert len(got) == 1 and got[0][1]["item"].action == "react" and got[0][0][1] == "carol"


def test_the_rooms_archive_is_read_after_the_cursor():
    t, c, _ = transport()
    t._our_nick = lambda room: "me"
    got = []
    t.set_room_handler(lambda *a, **k: got.append((a, k)))
    archive = [("R%d" % i, "<message xmlns='jabber:client' type='groupchat' from='%s/%s' id='o%d'>"
                "<body>line %d</body></message>" % (ROOM, "me" if i == 2 else "bob", i, i))
               for i in range(1, 4)]

    async def features(jid):
        return [RS.MUC_MAM] if jid == ROOM else []
    t._features = features

    def answer(iq):
        query = iq.find("{urn:xmpp:mam:2}query")
        assert iq.get("to") == ROOM

        async def reply():
            for aid, inner in archive:
                wrapper = ET.fromstring(
                    "<message xmlns='jabber:client' from='%s'><result xmlns='urn:xmpp:mam:2' "
                    "queryid='%s' id='%s'><forwarded xmlns='urn:xmpp:forward:0'>"
                    "<delay xmlns='urn:xmpp:delay' stamp='2026-10-14T08:00:00Z'/></forwarded></result></message>"
                    % (ROOM, query.get("queryid"), aid))
                wrapper.find(".//{urn:xmpp:forward:0}forwarded").append(ET.fromstring(inner))
                t._on_any_message(FakeStanza(c, wrapper))
            result = ET.Element("{jabber:client}iq", {"type": "result"})
            fin = ET.SubElement(result, "{urn:xmpp:mam:2}fin", {"complete": "true"})
            st = ET.SubElement(fin, "{http://jabber.org/protocol/rsm}set")
            ET.SubElement(st, "{http://jabber.org/protocol/rsm}last").text = archive[-1][0]
            return FakeStanza(c, result)
        return reply()
    c.answer = answer
    assert asyncio.run(t._room_catch_up(ROOM)) == 3
    assert [(a[1], a[2], k.get("own", False), k["item"].source) for a, k in got] == [
        ("bob", "line 1", False, "archive"), ("me", "line 2", True, "archive"),
        ("bob", "line 3", False, "archive")]
    key = RS.room_cursor_key(ME, ROOM)
    assert t._sync()["cursor"].get(key) == "R3"


def test_a_room_without_an_archive_is_not_asked():
    t, c, _ = transport()

    async def features(jid):
        return []
    t._features = features
    assert asyncio.run(t._room_catch_up(ROOM)) == 0
    assert c.sent == []
