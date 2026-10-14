# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The app's carbons, archive, receipts, read markers and typing.

Drives the real XmppTransport sync code (android_bridge.sync) against a fake
slixmpp client, and the real OtrApp.on_sync. Owner (2026-10-14): "we must add
message carbons and server side message history xep-0313 and anything else
conversations app uses".
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import xml.etree.ElementTree as ET

import pytest

import otrv4plus_sync as S
from android_bridge import events as E
from android_bridge.transport import XmppTransport

ME = "alice@example.i2p"
BOB = "bob@example.i2p"


# -- a fake slixmpp, just enough -------------------------------------------------

class FakeStanza:
    def __init__(self, client, xml):
        self.client, self.xml = client, xml

    def __setitem__(self, key, value):
        self.xml.set(key, value)

    def __getitem__(self, key):
        return self.xml.get(key)

    def send(self, timeout=None):
        self.client.sent.append(self.xml)
        if self.xml.tag.endswith("iq"):
            return self.client.answer(self.xml)
        return None


class FakeJid:
    bare, domain = ME, "example.i2p"


class FakeRoster(dict):
    pass


class FakeClient:
    def __init__(self):
        self.sent, self.plain = [], []
        self.boundjid = FakeJid()
        self.client_roster = FakeRoster()
        self.archive = []              # list of (archive id, inner message xml)
        self.answer = self._answer
        self._n = 0
        self.transport = None

    def make_message(self, mto, mbody=None, mtype="chat"):
        el = ET.Element("{jabber:client}message", {"to": mto, "type": mtype})
        if mbody is not None:
            ET.SubElement(el, "{jabber:client}body").text = mbody
        return FakeStanza(self, el)

    def make_iq_set(self, ito=None):
        self._n += 1
        el = ET.Element("{jabber:client}iq", {"type": "set", "id": "q%d" % self._n})
        return FakeStanza(self, el)

    def send_message(self, mto, mbody, mtype):
        self.plain.append((mto, mbody))

    def _answer(self, iq):
        """The server: an archive query is answered with its results (as
        messages, through the transport's handler) and then a <fin/>."""
        query = iq.find("{urn:xmpp:mam:2}query")

        async def reply():
            result = ET.Element("{jabber:client}iq", {"type": "result"})
            if query is None:
                return FakeStanza(self, result)
            rsm = query.find("{http://jabber.org/protocol/rsm}set")
            after = rsm.findtext("{http://jabber.org/protocol/rsm}after")
            before = rsm.find("{http://jabber.org/protocol/rsm}before")
            size = int(rsm.findtext("{http://jabber.org/protocol/rsm}max"))
            ids = [a for a, _ in self.archive]
            if after:
                start = ids.index(after) + 1 if after in ids else len(ids)
                chunk = self.archive[start:start + size]
                complete = start + size >= len(ids)
            elif before is not None:
                chunk = self.archive[-size:]
                complete = len(ids) <= size
            else:
                chunk, complete = self.archive[:size], len(ids) <= size
            for archive_id, inner in chunk:
                wrapper = ET.fromstring(
                    "<message xmlns='jabber:client' to='%s/phone'>"
                    "<result xmlns='urn:xmpp:mam:2' queryid='%s' id='%s'>"
                    "<forwarded xmlns='urn:xmpp:forward:0'>"
                    "<delay xmlns='urn:xmpp:delay' stamp='2026-10-14T08:00:00Z'/>"
                    "</forwarded></result></message>" % (ME, query.get("queryid"), archive_id))
                wrapper.find(".//{urn:xmpp:forward:0}forwarded").append(ET.fromstring(inner))
                self.transport._on_any_message(FakeStanza(self, wrapper))
            fin = ET.SubElement(result, "{urn:xmpp:mam:2}fin",
                                {"complete": "true" if complete else "false"})
            if chunk:
                st = ET.SubElement(fin, "{http://jabber.org/protocol/rsm}set")
                ET.SubElement(st, "{http://jabber.org/protocol/rsm}last").text = chunk[-1][0]
            return FakeStanza(self, result)
        return reply()


def transport():
    t = XmppTransport.__new__(XmppTransport)
    c = FakeClient()
    c.transport = t
    t._client = c
    t._loop = None
    t._thread = None
    t._on_loop_thread = lambda: False
    t._send_now = lambda coro, timeout: asyncio.run(coro)
    t._sync()["cursor"] = S.ArchiveCursor(os.path.join(tempfile.mkdtemp(), "c.json"))
    got = []
    t.set_sync_handler(lambda kind, **f: got.append((kind, f)))

    class Caps:
        def target(self, bare):
            return None
    t._caps = Caps()
    import threading
    t._connected = threading.Event()
    t._connected.set()
    t._closed = False
    return t, c, got


def inner(frm, to, body, extra="", mid="m1"):
    return ("<message xmlns='jabber:client' from='%s' to='%s' type='chat' id='%s'>"
            "<body>%s</body>%s</message>" % (frm, to, mid, body, extra))


# -- what we send ----------------------------------------------------------------

def test_an_otr_frame_is_kept_off_other_devices_and_out_of_the_archive():
    t, c, _ = transport()
    t._send_stanzas(BOB + "/phone", ["?OTRv4 AAAA"], otr=True)
    tags = {child.tag for child in c.sent[0]}
    assert "{urn:xmpp:carbons:2}private" in tags
    assert "{urn:xmpp:hints}no-permanent-store" in tags
    assert "{urn:xmpp:hints}no-copy" in tags


def test_a_typed_message_carries_its_id_and_asks_for_receipts_on_its_last_fragment():
    t, c, _ = transport()
    t._send_stanzas(BOB + "/phone", ["?OTRv4F|1|1|2|aa", "?OTRv4F|1|2|2|bb"],
                    message_id="ID7", otr=True)
    first, last = c.sent
    assert first.get("id") is None
    assert first.find("{urn:xmpp:receipts}request") is None
    assert last.get("id") == "ID7"
    assert last.find("{urn:xmpp:sid:0}origin-id").get("id") == "ID7"
    assert last.find("{urn:xmpp:receipts}request") is not None
    assert last.find("{urn:xmpp:chat-markers:0}markable") is not None


def test_plaintext_without_an_id_goes_as_it_always_did():
    t, c, _ = transport()
    t._send_stanzas(BOB, ["hello"])
    assert c.plain == [(BOB, "hello")] and c.sent == []


# -- carbons -------------------------------------------------------------------------

def carbon(kind, msg, frm=ME):
    xml = ET.fromstring(
        "<message xmlns='jabber:client' from='%s' to='%s/phone'>"
        "<%s xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'/>"
        "</%s></message>" % (frm, ME, kind, kind))
    xml.find(".//{urn:xmpp:forward:0}forwarded").append(ET.fromstring(msg))
    return xml


def test_plaintext_carbons_are_handed_up_once():
    t, c, got = transport()
    sent = carbon("sent", inner(ME + "/laptop", BOB, "from my laptop",
                                "<origin-id xmlns='urn:xmpp:sid:0' id='O1'/>"))
    t._on_any_message(FakeStanza(c, sent))
    t._on_any_message(FakeStanza(c, sent))          # the same copy again
    msgs = [f["item"] for k, f in got if k == "message"]
    assert len(msgs) == 1 and msgs[0].direction == "out" and msgs[0].ref == "O1"


def test_a_forged_carbon_and_an_otr_carbon_are_not():
    t, c, got = transport()
    t._on_any_message(FakeStanza(c, carbon("sent", inner(ME + "/x", BOB, "forged"), frm=BOB)))
    t._on_any_message(FakeStanza(c, carbon("received", inner(BOB + "/p", ME + "/l", "?OTRv4 AAAA"))))
    assert [k for k, _ in got if k == "message"] == []


# -- receipts, markers, typing --------------------------------------------------------

def test_receipts_markers_and_typing_are_reported():
    t, c, got = transport()
    for extra in ("<received xmlns='urn:xmpp:receipts' id='ID1'/>",
                  "<displayed xmlns='urn:xmpp:chat-markers:0' id='ID1'/>",
                  "<composing xmlns='http://jabber.org/protocol/chatstates'/>"):
        t._on_any_message(FakeStanza(c, ET.fromstring(
            "<message xmlns='jabber:client' from='%s/phone' type='chat'>%s</message>" % (BOB, extra))))
    kinds = [(k, f.get("message_id") or f.get("state")) for k, f in got]
    assert kinds == [("receipt", "ID1"), ("marker", "ID1"), ("chat_state", "composing")]


def test_a_receipt_is_answered_only_to_a_contact_who_sees_our_presence():
    t, c, _ = transport()
    asked = S.parse_message(ET.fromstring(inner(BOB + "/phone", ME, "hi",
        "<request xmlns='urn:xmpp:receipts'/>", mid="X1")), ME)
    t.after_live(asked, True)
    assert c.sent == []                                     # a stranger
    c.client_roster[BOB] = {"subscription": "both"}
    t.after_live(asked, False)
    assert c.sent == []                                     # not taken
    t.after_live(asked, True)
    receipt = c.sent[-1]
    assert receipt.get("to") == BOB + "/phone"
    assert receipt.find("{urn:xmpp:receipts}received").get("id") == "X1"
    assert receipt.find("{urn:xmpp:hints}no-store") is not None


def test_typing_goes_only_to_contacts_when_switched_on_and_not_too_often():
    t, c, _ = transport()
    assert not t.send_chat_state(BOB, "composing")         # not a contact
    c.client_roster[BOB] = {"subscription": "from"}
    assert t.send_chat_state(BOB, "composing")
    assert not t.send_chat_state(BOB, "composing")         # repeat, too soon
    assert t.send_chat_state(BOB, "paused")                # a change goes
    t.set_privacy(chat_states=False, read_markers=True)
    assert not t.send_chat_state(BOB, "composing")


# -- the archive -------------------------------------------------------------------

def test_first_sync_takes_the_newest_page_then_only_what_is_new():
    t, c, got = transport()
    c.archive = [("A%d" % i, inner(BOB + "/p", ME, "old %d" % i, mid="m%d" % i))
                 for i in range(S.FIRST_PAGE + 20)]
    shown = asyncio.run(t._catch_up(ME))
    assert shown == S.FIRST_PAGE
    bodies = [f["item"].body for k, f in got if k == "message"]
    assert bodies[0] == "old 20" and bodies[-1] == "old %d" % (S.FIRST_PAGE + 19)
    assert t._sync()["cursor"].get(ME) == "A%d" % (S.FIRST_PAGE + 19)
    # Away for a while: 150 new ones, read in pages after the cursor.
    got.clear()
    c.archive += [("B%d" % i, inner(BOB + "/p", ME, "new %d" % i, mid="n%d" % i))
                  for i in range(150)]
    assert asyncio.run(t._catch_up(ME)) == 150
    assert t._sync()["cursor"].get(ME) == "B149"


def test_the_archive_shows_plaintext_only_and_never_twice():
    t, c, got = transport()
    c.archive = [("A1", inner(BOB + "/p", ME, "?OTRv4 AAAA", mid="x1")),
                 ("A2", inner(BOB + "/p", ME, "hello", mid="x2")),
                 ("A3", inner(ME + "/laptop", BOB, "hi bob", mid="x3"))]
    live = S.parse_message(ET.fromstring(inner(BOB + "/p", ME, "hello", mid="x2")), ME)
    t._sync()["seen"].first_time(live)                     # it came in live
    asyncio.run(t._catch_up(ME))
    items = [f["item"] for k, f in got if k == "message"]
    assert [(i.direction, i.body) for i in items] == [("out", "hi bob")]


def test_results_for_someone_elses_query_or_archive_are_ignored():
    t, c, _ = transport()
    bucket = t._sync()["queries"].setdefault("q9", [])
    foreign = ET.fromstring(
        "<message xmlns='jabber:client' from='%s'><result xmlns='urn:xmpp:mam:2' "
        "queryid='q9' id='Z'/></message>" % BOB)
    t._on_any_message(FakeStanza(c, foreign))
    assert bucket == []


# -- the app -----------------------------------------------------------------------

class Sink:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)

    __call__ = emit


@pytest.fixture
def app():
    from android_bridge.app import OtrApp

    class Engine:
        def __getattr__(self, name):
            raise AttributeError(name)

    class T:
        def __init__(self):
            self.sent, self.typed, self.markers, self.states = [], [], [], []

        def send(self, peer, payload):
            self.sent.append((peer, payload))

        def send_typed(self, peer, payload, message_id):
            self.typed.append((peer, payload, message_id))

        def send_marker(self, to, mid, marker):
            self.markers.append((to, mid, marker))

        def send_chat_state(self, peer, state):
            self.states.append((peer, state))
            return True

    a = OtrApp.__new__(OtrApp)
    a._wiped = False
    a._rooms = set()
    a._groups = None
    a._markable = {}
    a._chat_states_on = True
    a._read_markers_on = True
    a._transport = T()
    sink = Sink()
    a._emit = sink.emit
    a.events = sink.events
    return a


def test_copies_become_events_plaintext_with_their_ids(app):
    out = S.Item(direction="out", peer=BOB, body="from laptop", when=10.0,
                 source="carbon", origin_id="O1")
    inn = S.Item(direction="in", peer=BOB, body="hi \t  \t\t\t\t \t \t \t  ", when=11.0,
                 source="archive", stanza_id="A9")
    app.on_sync("message", item=out)
    app.on_sync("message", item=inn)
    sent, received = app.events
    assert isinstance(sent, E.MessageSentElsewhere) and sent.message_id == "O1"
    assert isinstance(received, E.MessageReceived)
    assert received.body == "hi" and received.source == "archive" and received.message_id == "A9"


def test_room_copies_and_wiped_apps_show_nothing(app):
    app._rooms.add("room@muc.example.i2p")
    app.on_sync("message", item=S.Item(direction="in", peer="room@muc.example.i2p",
                                       body="x", when=1.0, source="carbon"))
    app._wiped = True
    app.on_sync("receipt", peer=BOB, message_id="m")
    assert app.events == []


def test_receipts_markers_typing_and_sync_events(app):
    app.on_sync("receipt", peer=BOB, message_id="ID1")
    app.on_sync("marker", peer=BOB, message_id="ID1", marker="displayed")
    app.on_sync("chat_state", peer=BOB, state="composing")
    app.on_sync("synced", count=3)
    kinds = [type(e).__name__ for e in app.events]
    assert kinds == ["MessageDelivered", "MessageDisplayed", "ChatStateChanged", "HistorySynced"]


def test_read_marker_is_sent_once_and_only_when_switched_on(app):
    app._markable[BOB] = (BOB + "/phone", "X5")
    assert app.mark_displayed(BOB)
    assert app._transport.markers == [(BOB + "/phone", "X5", "displayed")]
    assert not app.mark_displayed(BOB)                      # nothing new
    app.set_privacy(chat_states=True, read_markers=False)
    app._markable[BOB] = (BOB + "/phone", "X6")
    assert not app.mark_displayed(BOB)


def test_typing_is_never_sent_to_a_room(app):
    app._rooms.add("room@muc.example.i2p")
    assert not app.set_chat_state("room@muc.example.i2p", "composing")
    assert app.set_chat_state(BOB, "composing")
    app.set_privacy(chat_states=False, read_markers=True)
    assert not app.set_chat_state(BOB, "composing")


def test_a_queued_line_keeps_its_id_until_it_is_sent(app):
    from android_bridge.app import _Line
    line = _Line("hello", "ID9")
    assert line == "hello" and line.message_id == "ID9"
    app._send_user(BOB, line, line.message_id)
    assert app._transport.typed == [(BOB, "hello", "ID9")]
    app._send_user(BOB, "no id")
    assert app._transport.sent == [(BOB, "no id")]


# -- blocking and bookmarks (android_bridge.account_sync) ---------------------------

def account_transport():
    t, c, got = transport()

    def make_iq_get(ito=None):
        c._n += 1
        el = ET.Element("{jabber:client}iq", {"type": "get", "id": "g%d" % c._n})
        if ito:
            el.set("to", ito)
        return FakeStanza(c, el)
    c.make_iq_get = make_iq_get

    def answer(iq):
        async def reply():
            result = ET.Element("{jabber:client}iq", {"type": "result"})
            if iq.find("{urn:xmpp:blocking}blocklist") is not None:
                bl = ET.SubElement(result, "{urn:xmpp:blocking}blocklist")
                ET.SubElement(bl, "{urn:xmpp:blocking}item", {"jid": "old@x.i2p"})
            return FakeStanza(c, result)
        return reply()
    c.answer = answer
    t._room_call = lambda coro: ("ok", "", asyncio.run(coro))
    return t, c, got


def test_blocking_needs_server_support_then_blocks_and_reports():
    t, c, _ = account_transport()
    assert t.block_contact("spam@x.i2p", "spam")[0] == "unsupported"
    asyncio.run(t._account_after_session(["urn:xmpp:blocking"], []))
    assert t.blocked_contacts() == ["old@x.i2p"]
    code, _, value = t.block_contact("Spam@x.i2p", "spam")
    assert code == "ok" and "spam@x.i2p" in value
    sent = c.sent[-1]
    item = sent.find(".//{urn:xmpp:blocking}item")
    assert item.get("jid") == "spam@x.i2p"
    assert item.find("{urn:xmpp:reporting:1}report") is not None
    t.unblock_contact("spam@x.i2p")
    assert t.blocked_contacts() == ["old@x.i2p"]
    t._stop_self_ping()


def test_a_blocking_push_only_from_our_own_server():
    t, c, _ = account_transport()

    class Push(FakeStanza):
        def reply(self):
            return FakeStanza(c, ET.Element("{jabber:client}iq", {"type": "result"}))

    forged = Push(c, ET.fromstring(
        "<iq xmlns='jabber:client' type='set' from='mallory@x.i2p'>"
        "<block xmlns='urn:xmpp:blocking'><item jid='friend@x.i2p'/></block></iq>"))
    t._on_blocking_push(forged)
    assert t.blocked_contacts() == []
    real = Push(c, ET.fromstring(
        "<iq xmlns='jabber:client' type='set'>"
        "<block xmlns='urn:xmpp:blocking'><item jid='troll@x.i2p'/></block></iq>"))
    t._on_blocking_push(real)
    assert t.blocked_contacts() == ["troll@x.i2p"]


def test_bookmarks_are_kept_only_where_the_server_keeps_them_private():
    t, c, _ = account_transport()
    asyncio.run(t._account_after_session([], []))
    assert t.bookmark_room("r@muc.x.i2p", "me")[0] == "unsupported"
    assert not any(e.find(".//{http://jabber.org/protocol/pubsub}publish") is not None
                   for e in c.sent)
    asyncio.run(t._account_after_session(
        [], ["http://jabber.org/protocol/pubsub#publish-options"]))
    assert t.bookmark_room("r@muc.x.i2p", "me", "pw")[0] == "ok"
    assert t.bookmark_for("R@muc.x.i2p")["password"] == "pw"
    assert t.bookmarks()[0]["password"] is True        # never handed out
    assert t.room_password("r@muc.x.i2p") == "pw"
    t.unbookmark_room("r@muc.x.i2p")
    assert t.bookmarks() == []
    t._stop_self_ping()
