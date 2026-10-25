# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
""""No keys for this group" only when it is true.

Device report (2026-10-25, desktop): the banner said "test@conference... is an
encrypted group, but this device has no keys for it" over a group that worked
-- padlock shown, messages sent and received. The room replays its history on
join, and that ciphertext arrived before the Welcome was processed (or before
the groups opened at sign-in). It fell through to the "no keys" verdict, which
was then never taken back.
"""
import io
import os

from android_bridge.app import OtrApp
from android_bridge.events import ErrorOccurred

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOM = "test@conference.example.i2p"
FRAME = "?OTRv4MLS1:AAAA"


class _Groups:
    def __init__(self, is_open=True, awaiting=False, secure=False):
        self.is_open = is_open
        self._awaiting = awaiting
        self._secure = secure

    def is_secure(self, room):
        return self._secure

    def awaiting_welcome(self, room):
        return self._awaiting

    def on_room_body(self, room, nick, body, timestamp=0.0, own=False):
        return self._secure      # a secure group handles every body


def _app(groups):
    app = OtrApp.__new__(OtrApp)
    app._groups = groups
    app._rooms = {ROOM: {}}
    app._knocking = set()
    app._keyless_groups = set()
    app.canonical_peer = lambda p: str(p).lower()
    app.events = []
    app._emit = app.events.append
    return app


def _keys_missing(app):
    return [e for e in app.events if isinstance(e, ErrorOccurred) and e.code == "group_keys_missing"]


def test_history_before_the_welcome_is_not_called_keyless():
    app = _app(_Groups(awaiting=True))
    app.receive_room_message(ROOM, "bob", FRAME)
    assert _keys_missing(app) == [] and ROOM not in app._keyless_groups


def test_history_before_the_groups_open_is_not_called_keyless():
    app = _app(_Groups(is_open=False))
    app.receive_room_message(ROOM, "bob", FRAME)
    assert _keys_missing(app) == [] and ROOM not in app._keyless_groups


def test_a_group_that_became_secure_drops_the_old_verdict():
    groups = _Groups()
    app = _app(groups)
    app.receive_room_message(ROOM, "bob", FRAME)
    assert len(_keys_missing(app)) == 1 and ROOM in app._keyless_groups
    groups._secure = True
    app.receive_room_message(ROOM, "bob", FRAME)
    assert ROOM not in app._keyless_groups, "sending must not stay refused"


def test_a_room_we_really_hold_no_keys_for_still_says_so_once():
    app = _app(_Groups())
    app.receive_room_message(ROOM, "bob", FRAME)
    app.receive_room_message(ROOM, "carol", FRAME)
    assert len(_keys_missing(app)) == 1


def test_the_banner_comes_down_when_the_group_joins():
    with io.open(os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus",
                              "android", "chat", "ChatState.kt"), encoding="utf-8") as fh:
        state = fh.read()
    fn = state[state.index("private fun noteGroupChange("):]
    fn = fn[:fn.index("\n    }\n")]
    assert 'event.change in setOf("created", "joined", "synced")' in fn
    assert 'notice == GroupText.failure("group_keys_missing", room)' in fn
