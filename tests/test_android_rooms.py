# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Rooms and service discovery, through the transport, without a network.

WHAT WAS MISSING
----------------
Neither `xep_0030` nor `xep_0045` was registered on the client. `client["xep_0045"]`
on a client that has not registered it raises, so there was nothing behind a
rooms screen at all -- and discovery had no way to find the MUC service, which
is conventionally `conference.<domain>` and conventionally is not.

`tests/test_muc_rules.py` covers the rules. This covers the PATH: that the
plugins are registered before the stream rather than after, that a failure
arrives as a code the UI knows rather than as an exception, and the one about
creating a room that is easy to get wrong and impossible to notice.

THE LOCKED ROOM. XEP-0045 §10.1.2: joining a room that does not exist creates
it LOCKED. The creator is in it and nobody else can get in, which looks exactly
like a room that works right up until somebody is invited. An owner sending the
empty configuration form is what unlocks it, and `TestCreatingARoom` is what
keeps that second step from being dropped as redundant.
"""

import asyncio
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_muc as muc
from android_bridge.settings import ConnectionProfile
from android_bridge.transport import XmppTransport

JID = "alice@xmpp-elite.i2p"
SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"
MUC_SERVICE = "rooms.xmpp-elite.i2p"
ROOM = "general@" + MUC_SERVICE
NICK = "alice"


# ── fakes shaped like slixmpp ────────────────────────────────────────────────

class PresenceError(Exception):
    """How a failed join arrives. Not an IqError."""

    def __init__(self, condition):
        super().__init__("presence error <%s/> from %s/%s"
                         % (condition, ROOM, NICK))
        self.presence = {"error": {"condition": condition}}


class IqError(Exception):
    def __init__(self, condition):
        super().__init__("iq error <%s/> for %s" % (condition, ROOM))
        self.condition = condition
        self.iq = {"error": {"condition": condition}}


class Items(dict):
    def __init__(self, entries):
        super().__init__({"disco_items": _Payload(entries)})


class _Payload:
    def __init__(self, entries):
        self._entries = entries

    def get_items(self):
        return self._entries


class Info(dict):
    def __init__(self, identities, features=()):
        super().__init__({"disco_info": {"identities": identities,
                                         "features": list(features)}})


class FakeDisco:
    def __init__(self, items=None, info=None, fail=None):
        self._items = items or {}
        self._info = info or {}
        self._fail = fail
        self.asked = []

    async def get_items(self, jid=None, timeout=None, **_kw):
        self.asked.append(str(jid))
        if self._fail is not None:
            raise self._fail
        return Items(self._items.get(str(jid), []))

    async def get_info(self, jid=None, timeout=None, **_kw):
        entry = self._info.get(str(jid))
        if entry is None:
            raise IqError("service-unavailable")
        return Info(*entry)


class FakeMuc:
    def __init__(self, *, join_fails=None, destroy_fails=None,
                 standing=("none", "participant")):
        self.join_fails = join_fails
        self.destroy_fails = destroy_fails
        self.standing = standing
        self.joined = []
        self.left = []
        self.destroyed = []
        self.configured = []

    async def join_muc_wait(self, room, nick, password=None, timeout=None,
                            **_kw):
        if self.join_fails is not None:
            raise self.join_fails
        self.joined.append((str(room), str(nick), password))
        return (None, None, [], [])

    def leave_muc(self, room, nick, msg="", pfrom=None):
        self.left.append((str(room), str(nick)))

    async def destroy(self, room, reason="", altroom=None, timeout=None,
                      **_kw):
        if self.destroy_fails is not None:
            raise self.destroy_fails
        self.destroyed.append((str(room), reason))

    async def set_room_config(self, room, config, timeout=None, **_kw):
        self.configured.append((str(room), config))

    def get_jid_property(self, room, nick, name, pfrom=None):
        return {"affiliation": self.standing[0],
                "role": self.standing[1]}.get(name, "")

    def get_joined_rooms(self, pfrom=None):
        return [r for r, _n, _p in self.joined]


class FakeForms:
    def make_form(self, ftype="form", **_kw):
        return {"type": ftype}


class FakeBoundJid:
    domain = "xmpp-elite.i2p"


class FakeClient:
    def __init__(self, jid, password, *, disco=None, muc_plugin=None):
        self.jid = jid
        self.password = password
        self.boundjid = FakeBoundJid()
        self.handlers = {}
        self.plugins = {
            "xep_0030": disco if disco is not None else FakeDisco(),
            "xep_0045": muc_plugin if muc_plugin is not None else FakeMuc(),
            "xep_0004": FakeForms(),
        }
        self.registered = []

    def add_event_handler(self, name, fn):
        self.handlers.setdefault(name, []).append(fn)

    def register_plugin(self, name):
        self.registered.append(name)

    def __getitem__(self, name):
        return self.plugins[name]

    def connect(self, host=None, port=None):
        for fn in list(self.handlers.get("session_start", [])):
            fn(None)

    def send_presence(self, **_kw):
        pass

    def get_roster(self):
        pass

    def add_filter(self, *_a, **_kw):
        pass

    def abort(self):
        pass

    def disconnect(self, *_a, **_kw):
        pass


def build(**kw):
    made = {}

    def factory(jid, password):
        made["client"] = FakeClient(jid, password,
                                    disco=kw.pop("disco", None),
                                    muc_plugin=kw.pop("muc", None))
        return made["client"]

    async def forwarder(*_a, **_kw):
        return ("127.0.0.1", 41234)

    t = XmppTransport(
        ConnectionProfile(jid=JID, server=SERVER), "pw",
        on_payload=lambda *a: None,
        client_factory=factory, forwarder=forwarder)
    t.connect()
    made["transport"] = t
    return t, made


# ── the plugins ──────────────────────────────────────────────────────────────

class TestThePluginsAreRegistered:
    """On a client that has not connected. A plugin added after the session is
    up does not get its handlers wired, and xep_0045's handlers are how
    joining a room ever completes."""

    @pytest.fixture(scope="class")
    @classmethod
    def factory_source(cls):
        import inspect

        from android_bridge import transport

        return inspect.getsource(transport._default_client_factory)

    @pytest.mark.parametrize("plugin",
                             ["xep_0030", "xep_0004", "xep_0045", "xep_0199"])
    def test_it_is_registered(self, factory_source, plugin):
        assert plugin in factory_source, plugin

    def test_each_is_registered_separately(self, factory_source):
        """One missing from a slimmed-down slixmpp must not take the others
        with it."""
        body = factory_source[factory_source.index("xep_0030"):]
        assert "try:" in body and "except" in body

    def test_they_are_registered_before_connecting(self, factory_source):
        """`_default_client_factory` builds the client and hands it back; the
        connect happens later in `_connect_inner`."""
        assert "connect(" not in factory_source

    def test_the_real_plugins_exist_under_those_names(self):
        pytest.importorskip("slixmpp")
        from slixmpp.plugins.xep_0030 import XEP_0030
        from slixmpp.plugins.xep_0045 import XEP_0045

        assert XEP_0030.name == "xep_0030"
        assert XEP_0045.name == "xep_0045"


class TestTheFakeCannotAgreeWithAMistake:
    """Bound against real slixmpp: a fake written from the same wrong
    assumption as the code is not evidence. This is the discipline that caught
    `async_ping`."""

    def test_join_muc_wait_takes_what_we_pass_it(self):
        pytest.importorskip("slixmpp")
        import inspect

        from slixmpp.plugins.xep_0045 import XEP_0045

        params = inspect.signature(XEP_0045.join_muc_wait).parameters
        for name in ("room", "nick", "password", "timeout"):
            assert name in params, name

    def test_leave_muc_is_not_a_coroutine(self):
        """It sends unavailable presence and returns; awaiting it would be a
        TypeError at the one moment nobody is watching."""
        pytest.importorskip("slixmpp")
        import inspect

        from slixmpp.plugins.xep_0045 import XEP_0045

        assert not inspect.iscoroutinefunction(XEP_0045.leave_muc)

    def test_destroy_and_set_room_config_are_coroutines(self):
        pytest.importorskip("slixmpp")
        import inspect

        from slixmpp.plugins.xep_0045 import XEP_0045

        assert inspect.iscoroutinefunction(XEP_0045.destroy)
        assert inspect.iscoroutinefunction(XEP_0045.set_room_config)

    def test_get_jid_property_answers_both_questions(self):
        """Pinned against the KEY TYPE rather than the function body: the
        body is a dict lookup and names neither, so a test reading the source
        would pass whatever the accepted keys became."""
        pytest.importorskip("slixmpp")
        import typing

        from slixmpp.types import MucRoomItemKeys

        keys = typing.get_args(MucRoomItemKeys)
        assert "affiliation" in keys
        assert "role" in keys

    def test_make_form_exists_on_xep_0004(self):
        pytest.importorskip("slixmpp")
        from slixmpp.plugins.xep_0004 import XEP_0004

        assert hasattr(XEP_0004, "make_form")


# ── discovery ────────────────────────────────────────────────────────────────

class TestDiscoveringWhatTheServerHosts:

    def _disco(self):
        return FakeDisco(
            items={"xmpp-elite.i2p": [(MUC_SERVICE, None, "Chatrooms"),
                                      ("upload.xmpp-elite.i2p", None, "")]},
            info={MUC_SERVICE: ([("conference", "text", None, "Chatrooms")],
                                ["http://jabber.org/protocol/muc"]),
                  "upload.xmpp-elite.i2p":
                      ([("store", "file", None, "Uploads")], [])})

    def test_it_asks_the_servers_own_domain(self):
        t, made = build(disco=self._disco())
        try:
            t.discover_services()
            assert "xmpp-elite.i2p" in made["client"]["xep_0030"].asked
        finally:
            t.close()

    def test_the_items_come_back(self):
        t, _ = build(disco=self._disco())
        try:
            code, _detail, services = t.discover_services()
            assert code == "ok"
            assert {s["jid"] for s in services} == {
                MUC_SERVICE, "upload.xmpp-elite.i2p"}
        finally:
            t.close()

    def test_each_carries_what_it_is(self):
        """disco#items gives a name and nothing about what the thing IS, so
        the category is what lets a rooms screen find the MUC service instead
        of guessing `conference.<domain>`."""
        t, _ = build(disco=self._disco())
        try:
            _code, _detail, services = t.discover_services()
            rooms = [s for s in services if s["jid"] == MUC_SERVICE][0]
            assert rooms["category"] == "conference"
            assert rooms["type"] == "text"
        finally:
            t.close()

    def test_a_service_that_will_not_answer_does_not_empty_the_list(self):
        disco = FakeDisco(
            items={"xmpp-elite.i2p": [(MUC_SERVICE, None, "Chatrooms"),
                                      ("broken.xmpp-elite.i2p", None, "")]},
            info={MUC_SERVICE: ([("conference", "text", None, "")], [])})
        t, _ = build(disco=disco)
        try:
            _code, _detail, services = t.discover_services()
            assert len(services) == 2, (
                "one component that would not answer a disco#info removed "
                "every other service from the list")
        finally:
            t.close()

    def test_a_server_that_refuses_discovery_is_a_code_not_a_raise(self):
        t, _ = build(disco=FakeDisco(fail=IqError("feature-not-implemented")))
        try:
            code, detail, services = t.discover_services()
            assert code == "unsupported"
            assert detail == muc.CODES["unsupported"]
            assert services is None
        finally:
            t.close()


class TestListingRooms:

    def test_the_public_rooms_come_back(self):
        disco = FakeDisco(items={MUC_SERVICE: [
            (ROOM, None, "General"), ("dev@" + MUC_SERVICE, None, "Dev")]})
        t, _ = build(disco=disco)
        try:
            code, _d, rooms = t.discover_rooms(MUC_SERVICE)
            assert code == "ok"
            assert [r["jid"] for r in rooms] == [ROOM, "dev@" + MUC_SERVICE]
            assert rooms[0]["name"] == "General"
        finally:
            t.close()

    def test_an_empty_list_is_not_a_failure(self):
        """A hidden room is absent by design. Empty is a fact, not an error."""
        t, _ = build(disco=FakeDisco(items={MUC_SERVICE: []}))
        try:
            code, _d, rooms = t.discover_rooms(MUC_SERVICE)
            assert code == "ok" and rooms == []
        finally:
            t.close()


# ── joining ──────────────────────────────────────────────────────────────────

class TestJoining:

    def test_it_joins_under_the_nickname_given(self):
        room = FakeMuc()
        t, _ = build(muc=room)
        try:
            assert t.join_room(ROOM, NICK)[0] == "ok"
            assert room.joined == [(ROOM, NICK, None)]
        finally:
            t.close()

    def test_a_password_is_passed_through(self):
        room = FakeMuc()
        t, _ = build(muc=room)
        try:
            t.join_room(ROOM, NICK, "hunter2")
            assert room.joined[0][2] == "hunter2"
        finally:
            t.close()

    def test_the_standing_comes_back_with_the_join(self):
        """It is in the presence the service sends on arrival, so asking for
        it separately would be a second round trip for something we have."""
        t, _ = build(muc=FakeMuc(standing=("owner", "moderator")))
        try:
            _c, _d, standing = t.join_room(ROOM, NICK)
            assert standing["affiliation"] == "owner"
            assert standing["role"] == "moderator"
            assert standing["destroy"] is True
        finally:
            t.close()

    def test_both_questions_are_asked_not_one_inferred_from_the_other(self):
        """An owner who joined as a visitor cannot speak."""
        t, _ = build(muc=FakeMuc(standing=("owner", "visitor")))
        try:
            _c, _d, standing = t.join_room(ROOM, NICK)
            assert standing["speak"] is False
            assert standing["destroy"] is True
        finally:
            t.close()

    def test_a_taken_nickname_is_a_conflict(self):
        t, _ = build(muc=FakeMuc(join_fails=PresenceError("conflict")))
        try:
            code, detail, _v = t.join_room(ROOM, NICK)
            assert code == "conflict"
            assert "nickname" in detail
        finally:
            t.close()

    def test_a_ban_says_banned(self):
        t, _ = build(muc=FakeMuc(join_fails=PresenceError("forbidden")))
        try:
            assert t.join_room(ROOM, NICK)[0] == "forbidden"
        finally:
            t.close()

    def test_a_members_only_room_says_so(self):
        t, _ = build(muc=FakeMuc(
            join_fails=PresenceError("registration-required")))
        try:
            assert t.join_room(ROOM, NICK)[0] == "registration_required"
        finally:
            t.close()

    def test_a_refusal_never_shows_the_services_own_words(self):
        t, _ = build(muc=FakeMuc(join_fails=PresenceError("conflict")))
        try:
            _c, detail, _v = t.join_room(ROOM, NICK)
            assert "general" not in detail
            assert NICK not in detail
        finally:
            t.close()

    def test_a_join_that_never_answers_is_a_timeout(self):
        class Hangs(FakeMuc):
            async def join_muc_wait(self, *a, **kw):
                raise asyncio.TimeoutError()

        t, _ = build(muc=Hangs())
        try:
            assert t.join_room(ROOM, NICK)[0] == "timeout"
        finally:
            t.close()


class TestCreatingARoom:
    """§10.1.2, and the step that is easy to drop as redundant."""

    def test_it_joins_first(self):
        room = FakeMuc()
        t, _ = build(muc=room)
        try:
            assert t.create_room(ROOM, NICK)[0] == "ok"
            assert room.joined == [(ROOM, NICK, None)]
        finally:
            t.close()

    def test_it_then_unlocks_the_room(self):
        """WITHOUT THIS THE ROOM STAYS LOCKED. The creator is in it and
        nobody else can get in, which looks exactly like a room that works
        until somebody is invited."""
        room = FakeMuc()
        t, _ = build(muc=room)
        try:
            t.create_room(ROOM, NICK)
            assert room.configured, (
                "the room was created locked and left that way")
            assert room.configured[0][0] == ROOM
        finally:
            t.close()

    def test_the_configuration_submitted_is_the_empty_form(self):
        """Accepting the defaults, rather than putting a screen of checkboxes
        in front of somebody who asked for a room."""
        room = FakeMuc()
        t, _ = build(muc=room)
        try:
            t.create_room(ROOM, NICK)
            assert room.configured[0][1]["type"] == "submit"
        finally:
            t.close()

    def test_a_service_that_forbids_creation_says_so(self):
        t, _ = build(muc=FakeMuc(join_fails=IqError("not-allowed")))
        try:
            code, detail, _v = t.create_room(ROOM, NICK)
            assert code == "not_allowed"
            assert "create" in detail
        finally:
            t.close()


class TestLeaving:

    def test_it_leaves(self):
        room = FakeMuc()
        t, _ = build(muc=room)
        try:
            assert t.leave_room(ROOM, NICK)[0] == "ok"
            assert room.left == [(ROOM, NICK)]
        finally:
            t.close()

    def test_leaving_is_not_destroying(self):
        room = FakeMuc()
        t, _ = build(muc=room)
        try:
            t.leave_room(ROOM, NICK)
            assert room.destroyed == [], (
                "leaving a room deleted it for everybody in it")
        finally:
            t.close()


class TestDestroying:

    def test_it_destroys(self):
        room = FakeMuc()
        t, _ = build(muc=room)
        try:
            assert t.destroy_room(ROOM)[0] == "ok"
            assert room.destroyed == [(ROOM, "")]
        finally:
            t.close()

    def test_a_reason_is_passed_on(self):
        room = FakeMuc()
        t, _ = build(muc=room)
        try:
            t.destroy_room(ROOM, "moved elsewhere")
            assert room.destroyed[0][1] == "moved elsewhere"
        finally:
            t.close()

    def test_the_service_is_what_refuses_a_non_owner(self):
        """No client-side permission check here, deliberately. A client that
        disagreed with the service would be a second opinion in a place with
        no way to be right; `otrv4plus_muc.privileges` is what stops the
        button being offered, and this is what happens if it is pressed
        anyway."""
        t, _ = build(muc=FakeMuc(destroy_fails=IqError("forbidden")))
        try:
            assert t.destroy_room(ROOM)[0] == "forbidden"
        finally:
            t.close()


# ── everything answers, nothing raises ───────────────────────────────────────

class TestNoRoomCallEverRaises:

    @pytest.mark.parametrize("call", [
        lambda t: t.discover_services(),
        lambda t: t.discover_rooms(MUC_SERVICE),
        lambda t: t.join_room(ROOM, NICK),
        lambda t: t.create_room(ROOM, NICK),
        lambda t: t.leave_room(ROOM, NICK),
        lambda t: t.destroy_room(ROOM),
        lambda t: t.room_standing(ROOM, NICK),
        lambda t: t.joined_rooms(),
    ])
    def test_a_disconnected_transport_answers_rather_than_throwing(self, call):
        t, _ = build()
        t.close()
        code, detail, _value = call(t)
        assert code in muc.CODES
        assert detail == muc.CODES[code]

    @pytest.mark.parametrize("call", [
        lambda t: t.join_room(ROOM, NICK),
        lambda t: t.create_room(ROOM, NICK),
        lambda t: t.destroy_room(ROOM),
    ])
    def test_an_unexpected_exception_is_classified(self, call):
        class Broken(FakeMuc):
            async def join_muc_wait(self, *a, **kw):
                raise RuntimeError("boom")

            async def destroy(self, *a, **kw):
                raise RuntimeError("boom")

        t, _ = build(muc=Broken())
        try:
            code, detail, _v = call(t)
            assert code == "unknown"
            assert detail == muc.CODES["unknown"]
        finally:
            t.close()

    def test_every_answer_is_a_triple(self):
        t, _ = build()
        try:
            for result in (t.discover_services(), t.join_room(ROOM, NICK),
                           t.leave_room(ROOM, NICK), t.joined_rooms()):
                assert isinstance(result, tuple) and len(result) == 3
        finally:
            t.close()


class TestTheTraceDoesNotLearnWhoIsInWhatRoom:
    """§7. A room name and a nickname are as identifying as a JID."""

    def test_joining_records_nothing_nameable(self):
        from android_bridge.trace import TRACE

        t, _ = build()
        try:
            before = len(TRACE.events())
            t.join_room(ROOM, NICK)
            t.discover_rooms(MUC_SERVICE)
            text = repr(TRACE.events()[before:])
            assert "general" not in text
            assert "rooms.xmpp-elite" not in text
        finally:
            t.close()
