# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A room's messages on arrival are delivered, not silently dropped.

What a MUC service sends when we join, in order: other occupants'
presences, OUR self-presence, then the room's history, then the subject.
slixmpp resolves `join_muc_wait` on the self-presence, but the coroutine
awaiting it only resumes on a later loop iteration. slixmpp dispatches every
stanza of one network read synchronously, and over I2P the self-presence and
the history usually arrive in one read. So the history reached
`OtrApp.receive_room_message` BEFORE anything had called `note_room_joined`.
The app refuses text from rooms it does not know (a groupchat stanza can be
forged by any JID), and the messages were dropped without a trace. For
ordinary rooms it was worse: the connection layer noted the join only after
the cross-thread call returned.

The transport now holds a joining room's messages, registers the room with
the app on the loop thread the moment the join succeeds, and then delivers
what it held, in order. A failed join delivers nothing.
"""
import asyncio
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
from android_bridge.app import OtrApp, Transport                     # noqa: E402
from android_bridge.events import RoomMessageReceived                # noqa: E402
from android_bridge.transport import XmppTransport                   # noqa: E402

ROOM = "lobby@rooms.example.test"
OTHER = "elsewhere@rooms.example.test"


class _Jid:
    def __init__(self, bare, resource):
        self.bare, self.resource = bare, resource


def _stanza(room, nick, body):
    return {"from": _Jid(room, nick), "body": body, "delay": {"stamp": None}}


class _BurstMuc:
    """join_muc_wait that delivers the room's history DURING the join --
    exactly what one network read carrying self-presence + history does."""

    def __init__(self, transport, history, refuse=False, extra=()):
        self.transport, self.history = transport, history
        self.refuse, self.extra = refuse, extra
        self.our_nicks = {None: {}}

    async def join_muc_wait(self, room, nick, password=None, timeout=None):
        for who, body in self.history:
            self.transport._on_groupchat(_stanza(room, who, body))
        for other_room, who, body in self.extra:
            self.transport._on_groupchat(_stanza(other_room, who, body))
        if self.refuse:
            raise TimeoutError()
        self.our_nicks[None][room] = nick
        return None


class _Client(dict):
    def add_event_handler(self, *_a): pass
    def del_event_handler(self, *_a): pass


class _Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


class _Wire(Transport):
    def send(self, peer, payload): pass
    def send_room_message(self, room, body): pass
    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


@pytest.fixture
def wired():
    """The real app behind a real transport, wired as connection.py does."""
    sink = _Sink()
    app = OtrApp(_manager(), _Wire(), sink)
    t = XmppTransport.__new__(XmppTransport)
    t.set_room_handler(app.receive_room_message)
    t.set_room_joined_handler(app.note_room_joined)
    yield app, t, sink
    app.shutdown()


def _join(t, muc, room=ROOM):
    t._client = _Client({"xep_0045": muc})
    return asyncio.run(t._join_muc(room, "me"))


def _texts(sink):
    return [(e.sender, e.body) for e in sink.events
            if isinstance(e, RoomMessageReceived)]


HISTORY = [("alice", "first"), ("bob", "second"), ("alice", "third")]


def test_history_that_arrives_with_the_join_is_delivered_in_order(wired):
    app, t, sink = wired
    _join(t, _BurstMuc(t, HISTORY))
    assert app.is_room(ROOM)
    assert _texts(sink) == HISTORY


def test_without_the_hold_the_same_burst_was_dropped(wired):
    """The defect, reproduced against the app gate: text for a room the app
    has not been told about is refused -- which is right for a stranger's
    forged groupchat, and was wrong for our own room's history."""
    app, t, sink = wired
    for who, body in HISTORY:
        app.receive_room_message(ROOM, who, body)
    assert _texts(sink) == []


def test_a_failed_join_delivers_nothing_and_registers_nothing(wired):
    app, t, sink = wired
    with pytest.raises(Exception):
        _join(t, _BurstMuc(t, HISTORY, refuse=True))
    assert not app.is_room(ROOM)
    assert _texts(sink) == []
    assert t._held() == {}, "a failed join left messages held"


def test_other_rooms_are_not_held_and_strangers_are_still_refused(wired):
    """Only the joining room is held. A groupchat from a room we are not in
    still meets the app's gate and is dropped."""
    app, t, sink = wired
    _join(t, _BurstMuc(t, [("alice", "hello")],
                       extra=[(OTHER, "mallory", "forged")]))
    assert _texts(sink) == [("alice", "hello")]
    assert not app.is_room(OTHER)


def test_a_hostile_room_cannot_make_the_hold_unbounded(wired):
    app, t, sink = wired
    flood = [("x", "m%d" % i) for i in range(XmppTransport.MAX_HELD_ROOM_MESSAGES + 50)]
    _join(t, _BurstMuc(t, flood))
    assert len(_texts(sink)) == XmppTransport.MAX_HELD_ROOM_MESSAGES


def test_after_the_join_messages_flow_directly(wired):
    app, t, sink = wired
    _join(t, _BurstMuc(t, []))
    t._on_groupchat(_stanza(ROOM, "carol", "live"))
    assert _texts(sink) == [("carol", "live")]


def test_the_connection_wires_the_joined_handler_for_every_room():
    src = open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "android_bridge", "connection.py"),
        encoding="utf-8").read()
    assert 'getattr(self._transport, "set_room_joined_handler", None)' in src


@pytest.mark.parametrize("method", ["_create_room", "_welcome_flow"])
def test_every_join_path_goes_through_the_hold(method):
    """create_room holds from its own join; the Welcome flow and
    join_room/create_welcome go through _join_muc. No bare join_muc_wait
    may appear on a path that does not hold."""
    import inspect
    src = inspect.getsource(getattr(XmppTransport, method))
    if method == "_create_room":
        assert "_begin_join(room)" in src and "_end_join(room, ok)" in src
    else:
        assert "join_muc_wait" not in src and "self._join_muc(" in src
