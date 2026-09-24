# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The OTRv4Plus Welcome room: found by discovery, never guessed; occupants
feed the People list only by the address the MUC service revealed.

The room JID is NOT known to this project (the live Prosody could not be
inspected from the development environment), so every test here discovers it
the way the transport does: server disco#items -> MUC service -> its public
rooms -> exact name. Fixture JIDs are fixtures, not claims about the server.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge import welcome as W
from android_bridge.settings import ConnectionProfile
from android_bridge.transport import XmppTransport
from tests.test_android_rooms import (FakeClient, FakeDisco, FakeMuc, IqError,
                                      SERVER)

slixmpp = pytest.importorskip("slixmpp")
from slixmpp.xmlstream import ET  # noqa: E402

ME = "me@xmpp-elite.i2p"
DOMAIN = "xmpp-elite.i2p"
MUC = "muc.fixture.i2p"            # a fixture; discovered, never assumed
ROOM = "lobby@" + MUC
OTHER_SERVICE = "upload.fixture.i2p"


class RosterMuc(FakeMuc):
    """FakeMuc with a room roster, as slixmpp keeps one."""

    def __init__(self, occupants=None, conflict_first=False, **kw):
        super().__init__(**kw)
        self.occupants = dict(occupants or {})   # nick -> real jid or ""
        self.conflict_first = conflict_first
        self.nicks_tried = []

    async def join_muc_wait(self, room, nick, password=None, timeout=None,
                            **_kw):
        self.nicks_tried.append(nick)
        if self.join_fails is not None:
            raise self.join_fails
        if self.conflict_first and len(self.nicks_tried) == 1:
            from tests.test_android_rooms import PresenceError
            raise PresenceError("conflict")
        self.joined.append((str(room), str(nick), password))
        self.occupants.setdefault(nick, ME)

    def get_roster(self, room):
        return list(self.occupants)

    def get_jid_property(self, room, nick, name, pfrom=None):
        if name == "jid":
            return self.occupants.get(nick) or None
        return super().get_jid_property(room, nick, name, pfrom)


def disco(rooms=None, room_features=("http://jabber.org/protocol/muc",
                                     "muc_public", "muc_persistent",
                                     "muc_nonanonymous"),
          upload_rooms=None):
    rooms = [(ROOM, None, W.ROOM_NAME)] if rooms is None else rooms
    return FakeDisco(
        items={DOMAIN: [(MUC, None, "Chatrooms"), (OTHER_SERVICE, None, "")],
               MUC: rooms,
               OTHER_SERVICE: upload_rooms or []},
        info={MUC: ([("conference", "text", None, "Chatrooms")],
                    ["http://jabber.org/protocol/muc"]),
              OTHER_SERVICE: ([("store", "file", None, "")], []),
              ROOM: ([("conference", "text", None, W.ROOM_NAME)],
                     list(room_features))})


class InfoLog(FakeDisco):
    pass


def build(d=None, muc=None, presence=None):
    made = {}
    d = d or disco()
    info_asked = []
    real_get_info = d.get_info

    async def get_info(jid=None, timeout=None, **kw):
        info_asked.append(str(jid))
        return await real_get_info(jid=jid, timeout=timeout, **kw)
    d.get_info = get_info

    def factory(jid, password):
        made["client"] = FakeClient(jid, password, disco=d,
                                    muc_plugin=muc or RosterMuc())
        return made["client"]

    async def forwarder(*_a, **_kw):
        return ("127.0.0.1", 41234)

    seen = []
    t = XmppTransport(ConnectionProfile(jid=ME, server=SERVER), "pw",
                      on_payload=lambda *a: None,
                      on_presence=lambda *a: seen.append(a),
                      client_factory=factory, forwarder=forwarder)
    t.connect()
    made.update(transport=t, disco=d, info_asked=info_asked, presence=seen)
    return t, made


def run_flow(t, nick="me"):
    t._room_call(t._welcome_flow(nick))
    return t.welcome_view()


def room_presence(nick, real_jid="", available=True, self_presence=False):
    client = slixmpp.ClientXMPP(ME, "pw")
    client.register_plugin("xep_0045")
    item = '<item affiliation="none" role="participant"%s/>' % (
        ' jid="%s"' % real_jid if real_jid else "")
    status = '<status code="110"/>' if self_presence else ""
    xml = ('<presence xmlns="jabber:client" from="%s/%s" to="%s/r"%s>'
           '<x xmlns="http://jabber.org/protocol/muc#user">%s%s</x>'
           '</presence>') % (ROOM, nick, ME,
                             "" if available else ' type="unavailable"',
                             item, status)
    return client.Presence(xml=ET.fromstring(xml))


# ── finding the room ────────────────────────────────────────────────────────

class TestTheRoomIsDiscoveredNeverGuessed:

    def test_found_by_exact_name_on_a_muc_service_and_joined(self):
        t, made = build()
        try:
            view = run_flow(t)
        finally:
            t.close()
        assert view["state"] == W.JOINED
        assert view["room"] == ROOM
        assert view["anonymity"] == W.NON_ANONYMOUS
        assert view["public"] and view["persistent"]
        assert made["client"]["xep_0045"].joined[0][0] == ROOM

    def test_absent_room_is_reported_and_nothing_is_joined(self):
        t, made = build(disco(rooms=[("general@" + MUC, None, "General")]))
        try:
            view = run_flow(t)
        finally:
            t.close()
        assert view["state"] == W.NOT_FOUND
        assert view["room"] == "" and view["people"] == []
        assert made["client"]["xep_0045"].joined == []

    def test_a_similar_name_is_not_the_welcome_room(self):
        t, made = build(disco(rooms=[
            ("x@" + MUC, None, "OTRv4Plus Welcome (unofficial)"),
            ("y@" + MUC, None, "otrv4plus welcome")]))
        try:
            assert run_flow(t)["state"] == W.NOT_FOUND
        finally:
            t.close()
        assert made["client"]["xep_0045"].joined == []

    def test_two_rooms_with_the_name_are_refused_not_picked(self):
        t, made = build(disco(rooms=[(ROOM, None, W.ROOM_NAME),
                                     ("other@" + MUC, None, W.ROOM_NAME)]))
        try:
            assert run_flow(t)["state"] == W.AMBIGUOUS
        finally:
            t.close()
        assert made["client"]["xep_0045"].joined == []

    def test_rooms_of_a_non_muc_service_are_ignored(self):
        t, _ = build(disco(rooms=[],
                           upload_rooms=[("z@" + OTHER_SERVICE, None,
                                          W.ROOM_NAME)]))
        try:
            assert run_flow(t)["state"] == W.NOT_FOUND
        finally:
            t.close()

    def test_nothing_but_the_server_its_muc_service_and_the_room_is_asked(self):
        """No occupant, no candidate JID, no enumeration: only our own
        server's services, the MUC service's room list, and the one room."""
        t, made = build(muc=RosterMuc(occupants={"bob": "bob@x.i2p/phone"}))
        try:
            run_flow(t)
        finally:
            t.close()
        assert set(made["disco"].asked) == {DOMAIN, MUC}
        assert set(made["info_asked"]) <= {MUC, OTHER_SERVICE, ROOM}

    def test_a_taken_nickname_retries_once_with_our_own_suffix(self):
        muc = RosterMuc(conflict_first=True)
        t, _ = build(muc=muc)
        try:
            view = run_flow(t)
        finally:
            t.close()
        assert view["state"] == W.JOINED
        assert muc.nicks_tried[0] == "me"
        assert muc.nicks_tried[1].startswith("me-") and len(muc.nicks_tried) == 2

    def test_a_refused_join_is_a_state_not_a_raise(self):
        muc = RosterMuc(join_fails=IqError("forbidden"))
        t, _ = build(muc=muc)
        try:
            view = run_flow(t)
        finally:
            t.close()
        assert view["state"] == W.FAILED and view["people"] == []


# ── occupants -> people ─────────────────────────────────────────────────────

class TestOccupantsBecomePeopleOnlyByTheirRevealedAddress:

    def test_joined_occupants_with_revealed_jids_are_people(self):
        muc = RosterMuc(occupants={"bob": "Bob@x.i2p/phone",
                                   "bob2": "bob@x.i2p/laptop",
                                   "carol": "carol@x.i2p/a"})
        t, _ = build(muc=muc)
        try:
            view = run_flow(t)
        finally:
            t.close()
        # One per bare JID however many resources; never our own account.
        assert view["people"] == ["bob@x.i2p", "carol@x.i2p"]

    def test_semi_anonymous_room_reveals_no_addresses_and_none_are_invented(self):
        muc = RosterMuc(occupants={"bob": "", "carol": ""})
        t, _ = build(disco(room_features=("http://jabber.org/protocol/muc",
                                          "muc_public", "muc_semianonymous")),
                     muc=muc)
        try:
            view = run_flow(t)
        finally:
            t.close()
        assert view["anonymity"] == W.SEMI_ANONYMOUS
        assert view["people"] == []
        assert view["hidden"] == 2

    def test_join_and_leave_update_the_people(self):
        t, _ = build()
        try:
            run_flow(t)
            t._presence(room_presence("dave", "dave@x.i2p/r1"), True)
            assert "dave@x.i2p" in t.welcome_view()["people"]
            t._presence(room_presence("dave", available=False), False)
            assert "dave@x.i2p" not in t.welcome_view()["people"]
            t._presence(room_presence("dave", "dave@x.i2p/r2"), True)
            assert "dave@x.i2p" in t.welcome_view()["people"]
        finally:
            t.close()

    def test_a_nickname_without_an_item_jid_is_never_an_address(self):
        t, _ = build()
        try:
            run_flow(t)
            t._presence(room_presence("eve@x.i2p"), True)   # a nick that LOOKS like a JID
            view = t.welcome_view()
        finally:
            t.close()
        assert "eve@x.i2p" not in view["people"]
        assert view["hidden"] >= 1

    def test_being_removed_from_the_room_clears_it(self):
        t, _ = build()
        try:
            run_flow(t)
            t._presence(room_presence("dave", "dave@x.i2p/r1"), True)
            t._presence(room_presence("me", available=False,
                                      self_presence=True), False)
            view = t.welcome_view()
        finally:
            t.close()
        assert view["state"] == W.LEFT and view["people"] == []

    def test_our_stream_going_clears_everybody(self):
        t, _ = build()
        try:
            run_flow(t)
            t._presence(room_presence("dave", "dave@x.i2p/r1"), True)
            t._on_disconnected(None)
            view = t.welcome_view()
        finally:
            t.close()
        assert view["state"] == W.NOT_CONNECTED and view["people"] == []


# ── a room presence is not a contact, and not a capability ─────────────────

class TestRoomPresenceIsNotPeerPresence:
    """Before this change every MUC occupant presence reached the contact
    presence handler (the ROOM looked like an online contact) and the
    OTRv4Plus capability book (which then sent a disco#info through the room
    to the occupant)."""

    def test_it_never_reaches_the_contact_presence_handler(self):
        t, made = build()
        try:
            run_flow(t)
            t._presence(room_presence("dave", "dave@x.i2p/r1"), True)
        finally:
            t.close()
        assert made["presence"] == []

    def test_it_never_feeds_the_capability_book(self):
        t, made = build()
        try:
            run_flow(t)
            asked = len(made["info_asked"])
            t._presence(room_presence("dave", "dave@x.i2p/r1"), True)
            assert t.otr_capability(ROOM) == "unknown"
            assert t.otr_capability("dave@x.i2p") == "unknown", (
                "being in the Welcome room made somebody OTRv4Plus-capable")
            assert len(made["info_asked"]) == asked, (
                "a disco#info was sent because of a room presence")
        finally:
            t.close()

    def test_welcome_presence_gives_no_route_for_otr_traffic(self):
        from android_bridge.transport import TransportError
        t, _ = build()
        try:
            run_flow(t)
            t._presence(room_presence("dave", "dave@x.i2p/r1"), True)
            with pytest.raises(TransportError) as err:
                t.send("dave@x.i2p", "?OTRv4 query")
            assert err.value.code == "otrv4plus_unavailable"
        finally:
            t.close()


# ── the controller ──────────────────────────────────────────────────────────

class TestTheControllerStartsAndExposesIt:

    def _src(self, *parts):
        with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
            return fh.read()

    def test_every_successful_connect_starts_the_welcome_room(self):
        src = self._src("android_bridge", "connection.py")
        body = src[src.index("def _connect(self, password: str)"):]
        body = body[:body.index("\n    def ", 10)]
        connected = body.index('self._enter("connected")')
        assert body.index("start_welcome", connected) > connected

    def test_the_view_needs_no_connection_to_answer(self):
        from android_bridge.connection import ConnectionController
        view = ConnectionController.welcome_directory(
            type("C", (), {"_transport": None})())
        assert view["state"] == "not_connected" and view["people"] == []

    def test_no_room_jid_is_written_into_the_bridge(self):
        """The room is discovered. A literal room address in the code would
        be a guess about a server this project could not inspect."""
        import re
        for name in ("transport.py", "welcome.py", "connection.py", "app.py"):
            src = self._src("android_bridge", name)
            assert not re.search(r'"[a-z0-9._-]+@(conference|muc|rooms|chat)\.',
                                 src), name


# ── the pure module ─────────────────────────────────────────────────────────

class TestTheDirectory:

    def test_people_only_while_joined(self):
        """XEP-0045 sends the occupants' presences BEFORE our own; they are
        held while joining and shown once the join completes."""
        d = W.WelcomeDirectory()
        d.joining(ROOM, [], "me")
        d.occupant("bob", "bob@x.i2p/a", True)
        assert d.people() == [], "people shown before the join completed"
        d.joined("me")
        assert d.people() == ["bob@x.i2p"]
        d.failed("x")
        assert d.people() == []

    def test_anonymity_from_features(self):
        assert W.room_properties(["muc_nonanonymous"])["anonymity"] == W.NON_ANONYMOUS
        assert W.room_properties(["muc_semianonymous"])["anonymity"] == W.SEMI_ANONYMOUS
        assert W.room_properties([])["anonymity"] == W.UNKNOWN


# ── Add, and pending ─────────────────────────────────────────────────────────

class TestAddingAndPending:

    def _src(self, *parts):
        with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
            return fh.read()

    def test_add_on_a_discovered_row_is_the_normal_roster_subscription(self):
        """The row's Add calls addContact with the row's bare JID -- the one
        the MUC service revealed -- which is roster add + subscribe."""
        screen = self._src("android", "app", "src", "main", "java", "org",
                           "otrv4plus", "android", "ui", "ConversationsScreen.kt")
        assert "onAdd = { model.addContact(it) }" in screen
        assert "OnlineUsers.Relation.ONLINE_ADD ->" in screen
        assert "onAdd(entry.jid)" in screen
        transport = self._src("android_bridge", "transport.py")
        body = transport[transport.index("async def _add_contact"):]
        body = body[:body.index("\n    def ", 5)]
        assert "update_roster(jid" in body
        assert 'ptype="subscribe"' in body

    def test_no_pending_expiry_anywhere_in_the_bridge(self):
        """RFC 6121 has no client-side expiry for a pending subscription;
        neither does this client. Pending comes from the roster's `ask`."""
        import re
        for name in ("transport.py", "app.py", "connection.py", "welcome.py"):
            src = self._src("android_bridge", name)
            assert not re.search(r"(pending|subscri)\w*[^\n]{0,60}"
                                 r"(172800|48\s*\*\s*3600|2\s*\*\s*86400|"
                                 r"timedelta\(days=2\))", src, re.I), name
