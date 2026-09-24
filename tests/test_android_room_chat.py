#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Rooms are plaintext group chat, and nothing else.

WHAT WAS WRONG
==============
The Rooms screen could join and create a room, and then opened it as though
it were a one-to-one conversation with the room's JID. Typing there went out
as `type="chat"` to the room's bare JID -- which a MUC service rejects -- while
the UI marked it sent. Inbound room traffic arrives as `type="groupchat"`, which
the transport ignores by design, so nothing anybody said in the room ever
appeared. And an OTR request in that conversation would have sent a DAKE into
a room.

WHAT THIS HOLDS
===============
* room text goes out as group chat and comes in as its own event type
  (`RoomMessageReceived`), never through the OTR engine in either direction;
* our own reflected messages are dropped, and nicknames and bodies -- chosen by
  strangers -- lose control and bidi-override characters;
* OTR, SMP, calls and files are refused for a room by the bridge itself, not
  just hidden by the screen;
* membership is only recorded when the server agreed, and forgotten when the
  stream drops.
"""

import os
import tempfile
import types

import pytest

otr = pytest.importorskip("otrv4_")

from android_bridge.app import BridgeError, OtrApp, Transport        # noqa: E402
from android_bridge.events import RoomMessageReceived                # noqa: E402
from android_bridge.files import FileOutcome                         # noqa: E402
from android_bridge.voice import CallOutcome                         # noqa: E402

ROOM = "lobby@rooms.example.test"


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


class Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


class RoomWire(Transport):
    def __init__(self):
        self.chat, self.room = [], []

    def send(self, peer, payload):
        self.chat.append((peer, payload))

    def send_room_message(self, room, body):
        self.room.append((room, body))

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


@pytest.fixture
def app():
    wire, sink = RoomWire(), Sink()
    a = OtrApp(_manager(), wire, sink)
    a.note_room_joined(ROOM)
    a.test_wire, a.test_sink = wire, sink
    yield a
    a.shutdown()


class TestRoomTextNeverTouchesOtr:

    def test_text_to_a_room_goes_out_as_group_chat(self, app):
        assert app.send_user_text(ROOM, "hello all") == app.SEND_PLAINTEXT
        assert app.test_wire.room == [(ROOM, "hello all")]
        assert app.test_wire.chat == [], "room text went out as type=chat"
        assert app._engine.sessions == {}, "a room grew an OTR session"

    def test_a_room_spelled_differently_is_still_the_room(self, app):
        app.send_user_text("Lobby@Rooms.Example.Test", "hi")
        assert app.test_wire.room == [(ROOM, "hi")]

    def test_text_to_a_room_we_left_is_not_group_chat(self, app):
        app.note_room_left(ROOM)
        app.send_user_text(ROOM, "hi")
        assert app.test_wire.room == []

    def test_an_inbound_line_is_its_own_event(self, app):
        app.receive_room_message(ROOM, "bob", "hi", 1.0)
        events = [e for e in app.test_sink.events if isinstance(e, RoomMessageReceived)]
        assert len(events) == 1
        assert (events[0].peer, events[0].sender, events[0].body) == (ROOM, "bob", "hi")

    def test_a_room_we_are_not_in_is_not_delivered(self, app):
        app.receive_room_message("other@rooms.example.test", "bob", "hi")
        assert not any(isinstance(e, RoomMessageReceived) for e in app.test_sink.events)


class TestTheBridgeRefusesWhatARoomCannotHave:

    def test_no_otr(self, app):
        with pytest.raises(BridgeError) as err:
            app.start_session(ROOM)
        assert err.value.code == "room_not_encryptable"
        assert app.test_wire.chat == [], "a DAKE was sent into a room"

    def test_no_encrypted_send(self, app):
        with pytest.raises(BridgeError):
            app.send_message(ROOM, "x")

    def test_no_smp(self, app):
        for call in (lambda: app.smp_start(ROOM, "a long shared secret"),
                     lambda: app.smp_respond(ROOM, "a long shared secret")):
            with pytest.raises(BridgeError) as err:
                call()
            assert err.value.code == "room_not_verifiable"

    def test_no_call_and_no_file(self, app):
        assert app.start_call(ROOM) == CallOutcome.UNAVAILABLE
        assert app.send_file(ROOM, "/nope") == FileOutcome.UNAVAILABLE
        assert app._calls_bridge is None and app._files_bridge is None


# -- the transport -------------------------------------------------------------

from android_bridge.transport import XmppTransport                    # noqa: E402


class _Jid:
    def __init__(self, bare, resource):
        self.bare, self.resource = bare, resource


class _Muc:
    def __init__(self, ours="me", roster=None, props=None):
        self.our_nicks = {ROOM: ours}
        self._roster = roster or []
        self._props = props or {}

    def get_roster(self, room):
        return list(self._roster)

    def get_jid_property(self, room, nick, name):
        return self._props.get((nick, name), "")


def _stanza(nick, body, stamp=None):
    delay = {"stamp": stamp}
    return {"from": _Jid(ROOM, nick), "body": body, "delay": delay}


def _transport(muc):
    t = XmppTransport.__new__(XmppTransport)
    t._client = {"xep_0045": muc}
    got = []
    t._on_room_message = lambda *a: got.append(a)
    return t, got


class TestTheTransportRoomPath:

    def test_a_line_reaches_the_handler(self):
        t, got = _transport(_Muc())
        t._on_groupchat(_stanza("bob", "hi"))
        assert got and got[0][:3] == (ROOM, "bob", "hi")

    def test_our_own_reflection_is_dropped(self):
        t, got = _transport(_Muc(ours="me"))
        t._on_groupchat(_stanza("me", "what I said"))
        assert got == []

    def test_a_subject_change_is_not_a_message(self):
        t, got = _transport(_Muc())
        t._on_groupchat(_stanza("bob", ""))
        assert got == []

    def test_strangers_cannot_smuggle_control_characters(self):
        t, got = _transport(_Muc())
        t._on_groupchat(_stanza("bo‮b\x1b[31m", "hi\x07 there⁦"))
        _, nick, body, _ = got[0]
        assert "‮" not in nick and "\x1b" not in nick
        assert "\x07" not in body and "⁦" not in body
        assert body == "hi there"

    def test_a_handler_that_raises_does_not_take_the_stream_down(self):
        t, _ = _transport(_Muc())

        def boom(*a):
            raise RuntimeError("ui bug")
        t._on_room_message = boom
        t._on_groupchat(_stanza("bob", "hi"))          # must not raise

    def test_occupants_come_moderators_first(self):
        import asyncio
        muc = _Muc(roster=["zed", "amy", "bob"],
                   props={("zed", "role"): "moderator",
                          ("amy", "role"): "visitor",
                          ("bob", "role"): "participant"})
        t, _ = _transport(muc)
        people = asyncio.run(t._room_occupants(ROOM))
        assert [p["nick"] for p in people] == ["zed", "bob", "amy"]
        assert people[0]["role"] == "moderator"


# -- the controller ------------------------------------------------------------

class TestMembershipFollowsTheServer:

    def _controller(self, outcome):
        from android_bridge.connection import ConnectionController
        from android_bridge.settings import ConnectionProfile
        app = OtrApp(_manager(), None, None)
        ctl = ConnectionController(app, ConnectionProfile(jid="me@example.test",
                                                          server="example.test"))
        ctl._transport = types.SimpleNamespace(
            join_room=lambda *a: outcome, leave_room=lambda *a: ("ok", "", {}))
        return ctl, app

    def test_a_join_the_server_accepted_makes_it_a_room(self):
        ctl, app = self._controller(("ok", "", {}))
        ctl.join_room(ROOM, "me")
        assert app.is_room(ROOM)
        ctl.leave_room(ROOM, "me")
        assert not app.is_room(ROOM)

    def test_a_refused_join_does_not(self):
        ctl, app = self._controller(("forbidden", "banned", None))
        ctl.join_room(ROOM, "me")
        assert not app.is_room(ROOM)

    def test_a_dropped_stream_forgets_every_room(self):
        ctl, app = self._controller(("ok", "", {}))
        ctl.join_room(ROOM, "me")
        ctl._on_transport_state("disconnected", "")
        assert not app.is_room(ROOM)


# -- the 1:1 path's bounds -------------------------------------------------------

class TestTheDirectPathIsBounded:

    def _t(self):
        from android_bridge import transport as tmod
        t = XmppTransport.__new__(XmppTransport)
        t._reassembler = tmod._fragment.Reassembler()
        got = []
        t._on_payload = lambda peer, body: got.append((peer, body))
        return t, got

    def _stanza(self, body, kind="chat"):
        return {"type": kind, "body": body, "from": "bob@example.test/phone"}

    def test_an_ordinary_body_is_delivered(self):
        t, got = self._t()
        t._on_message(self._stanza("hi"))
        assert got == [("bob@example.test", "hi")]

    def test_an_oversized_body_is_dropped_not_truncated(self):
        t, got = self._t()
        t._on_message(self._stanza("x" * (XmppTransport.MAX_DIRECT_BODY + 1)))
        assert got == []

    def test_the_limit_is_well_above_any_fragment(self):
        from otrv4plus_fragment import MAX_FRAGMENT
        assert XmppTransport.MAX_DIRECT_BODY > 4 * MAX_FRAGMENT

    def test_error_and_groupchat_stanzas_are_not_one_to_one(self):
        t, got = self._t()
        t._on_message(self._stanza("?OTRv4 AAAA.", kind="error"))
        t._on_message(self._stanza("?OTRv4 AAAA.", kind="groupchat"))
        assert got == []

    def test_a_malformed_stanza_does_not_raise(self):
        t, got = self._t()
        t._on_message({"type": "chat", "body": "hi"})    # no "from"
        t._on_message(None)
        assert got == [], "a stanza with no sender was delivered"
