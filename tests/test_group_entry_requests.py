# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Ask to join an encrypted group (owner, 2026-10-17: "request entry
instead of the password ... password protection is for plaintext rooms").

An encrypted group is invite-only. Someone outside steps into its room for a
moment, posts ONE request carrying their address and leaves; members see
"X asks to join" with Invite and Dismiss. These tests drive the real app gate
and the controller with a fake transport.
"""
import json
import os
import sys
import tempfile
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")
from android_bridge.app import OtrApp, Transport                     # noqa: E402
from android_bridge.connection import ConnectionController           # noqa: E402
from android_bridge.events import GroupEntryRequested, RoomMessageReceived  # noqa: E402

ROOM = "team@rooms.example.test"
ASK = OtrApp.ENTRY_REQUEST_PREFIX


class _Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


class _Wire(Transport):
    _profile = types.SimpleNamespace(jid="me@example.test/phone")

    def send(self, peer, payload): pass
    def send_room_message(self, room, body): pass
    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


class _Groups:
    """Just enough of SecureGroups: ROOM is ours; nothing else is shown."""

    def __init__(self):
        self.bodies = []

    def is_secure(self, room):
        return room == ROOM

    def on_room_body(self, room, nick, body, timestamp, own=False):
        self.bodies.append(body)
        return True


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


@pytest.fixture
def app():
    sink = _Sink()
    clock = [1_000_000.0]
    a = OtrApp(_manager(), _Wire(), sink, clock=lambda: clock[0])
    a._groups = _Groups()
    a.note_room_joined(ROOM)
    a.sink, a.clock = sink, clock
    yield a
    a.shutdown()


def _asks(app):
    return [(e.peer, e.requester, e.live) for e in app.sink.events
            if isinstance(e, GroupEntryRequested)]


def _ask(jid):
    return ASK + json.dumps({"jid": jid})


def test_a_request_reaches_the_members_and_never_mls(app):
    app.receive_room_message(ROOM, "bob", _ask("Bob@Example.test"))
    assert _asks(app) == [(ROOM, "bob@example.test", True)]
    assert app._groups.bodies == []
    assert not [e for e in app.sink.events if isinstance(e, RoomMessageReceived)]


def test_one_request_per_person_per_hour(app):
    for _ in range(5):
        app.receive_room_message(ROOM, "bob", _ask("bob@example.test"))
    assert len(_asks(app)) == 1
    app.clock[0] += OtrApp.ENTRY_REQUEST_EVERY
    app.receive_room_message(ROOM, "bob", _ask("bob@example.test"))
    assert len(_asks(app)) == 2


@pytest.mark.parametrize("body", [
    ASK + "not json",
    ASK + json.dumps({"jid": "no-domain"}),
    ASK + json.dumps({"jid": "a@b/c"}),
    ASK + json.dumps({"jid": "a b@c"}),
    ASK + json.dumps({"jid": "me@example.test"}),      # our own address
])
def test_nonsense_and_our_own_address_are_ignored(app, body):
    app.receive_room_message(ROOM, "x", body)
    assert _asks(app) == []


def test_our_own_reflection_and_old_history_are_ignored(app):
    app.receive_room_message(ROOM, "me", _ask("bob@example.test"), own=True)
    old = types.SimpleNamespace(source="history", action="")
    app.receive_room_message(ROOM, "bob", _ask("bob@example.test"),
                             timestamp=app.clock[0] - 2 * OtrApp.ENTRY_REQUEST_MAX_AGE,
                             item=old)
    assert _asks(app) == []
    recent = types.SimpleNamespace(source="history", action="")
    app.receive_room_message(ROOM, "bob", _ask("bob@example.test"),
                             timestamp=app.clock[0] - 60, item=recent)
    assert _asks(app) == [(ROOM, "bob@example.test", False)]


def test_in_a_plain_room_it_is_just_text(app):
    plain = "lobby@rooms.example.test"
    app.note_room_joined(plain)
    app.receive_room_message(plain, "bob", _ask("bob@example.test"))
    assert _asks(app) == []


def test_while_knocking_nothing_from_the_room_reaches_the_app(app):
    other = "club@rooms.example.test"
    app.note_knocking(other, True)
    app.note_room_joined(other)          # the join completes: not recorded
    assert not app.is_room(other)
    app.receive_room_message(other, "carol", "secret-looking text")
    app.note_knocking(other, False)
    assert not app.is_room(other)
    assert not [e for e in app.sink.events if isinstance(e, RoomMessageReceived)]


class _Transport:
    def __init__(self, join=("ok", "", {})):
        self.calls, self.join = [], join

    def join_room(self, room, nick, password=""):
        self.calls.append(("join", room, nick, password))
        return self.join

    def send_room_message(self, room, body):
        self.calls.append(("send", room, body))

    def leave_room(self, room, nick):
        self.calls.append(("leave", room, nick))
        return ("ok", "", {})


class _App:
    ENTRY_REQUEST_PREFIX = ASK

    def __init__(self):
        self.knocking = []
        self.groups = types.SimpleNamespace(
            is_secure=lambda r: False, awaiting_welcome=lambda r: False,
            pending_invites=lambda: [])

    def note_knocking(self, room, on):
        self.knocking.append((room, on))

    def is_room(self, room):
        return False


def _controller(transport):
    c = ConnectionController.__new__(ConnectionController)
    c._transport, c._app = transport, _App()
    c._profile = types.SimpleNamespace(jid="Me@Example.test")
    return c


def test_asking_steps_in_posts_once_and_leaves():
    t = _Transport()
    c = _controller(t)
    result = c.request_group_entry(ROOM)
    assert result["ok"], result
    assert t.calls == [("join", ROOM, "me", ""),
                       ("send", ROOM, _ask("me@example.test")),
                       ("leave", ROOM, "me")]
    assert c._app.knocking == [(ROOM, True), (ROOM, False)]


def test_a_password_room_says_to_ask_a_member():
    t = _Transport(join=("not_authorized", "this room needs a password", None))
    c = _controller(t)
    result = c.request_group_entry(ROOM)
    assert not result["ok"]
    assert "Ask one of its members" in result["detail"]
    assert [x[0] for x in t.calls] == ["join"]
    assert c._app.knocking == [(ROOM, True), (ROOM, False)]


def test_the_desktop_host_offers_it():
    from desktop_bridge.host import CONTROLLER_OPS
    assert CONTROLLER_OPS["request_group_entry"] == ("room",)
