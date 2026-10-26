# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Deleting a secure group removes every member first.

Owner (2026-10-26): "deleted groups - must remove everyone from group before
deletion!" Delete used to destroy the room only. That ejects whoever is in it,
but each member kept the group's MLS state. Now the creator removes every
other member in one MLS commit and waits for it to come back from the room
before destroying the room. Real MLS clients (test_secure_groups.World).
"""
from __future__ import annotations

import types

import pytest

pytest.importorskip("otrv4_core")

from android_bridge.connection import ConnectionController  # noqa: E402
from test_secure_groups import ROOM, _group                  # noqa: E402,F401
from test_secure_groups import _rooms_settle_at_once          # noqa: E402,F401


class _Rooms:
    """The service: destroying the room is recorded with what every member
    had seen by then."""

    def __init__(self, world, members):
        self.world, self.members, self.calls = world, members, []

    def destroy_room(self, room, reason):
        self.calls.append(("destroy_room", room, {
            m.jid: ("removed_us" in m.changes(), m.groups.is_secure(room))
            for m in self.members}, len(self.world.room.log)))
        return ("ok", "", None)


def _controller(member, rooms):
    c = ConnectionController.__new__(ConnectionController)
    c._app = types.SimpleNamespace(groups=member.groups)
    c._transport = rooms
    c._noting_room = lambda result, room, joined: result
    c._bookmark = lambda *a, **k: None
    c._on_room_destroyed = lambda room: member.groups.on_room_destroyed(room)
    return c


def test_every_member_is_removed_before_the_room_is_destroyed():
    w, (a, b, c, d) = _group(4)
    rooms = _Rooms(w, [b, c, d])
    out = _controller(a, rooms).delete_secure_group(ROOM)
    assert out["ok"], out
    [(_op, room, seen, _log)] = rooms.calls
    assert room == ROOM
    for jid, (removed, _secure) in seen.items():
        assert removed, "%s still a member when the room went" % jid


def test_a_removed_member_cannot_read_what_follows():
    """Membership ended by MLS, not only by the room: the epoch has moved on
    without them, so the group's later traffic is not theirs to open."""
    w, (a, b, c) = _group(3)
    rooms = _Rooms(w, [b, c])
    _controller(a, rooms).delete_secure_group(ROOM)
    assert "removed_us" in b.changes() and "removed_us" in c.changes()
    assert not a.groups.is_secure(ROOM), "the creator's copy goes too"


def test_the_removal_commit_is_in_the_room_before_the_destroy():
    w, (a, b, c) = _group(3)
    before = len(w.room.log)
    rooms = _Rooms(w, [b, c])
    _controller(a, rooms).delete_secure_group(ROOM)
    [(_op, _room, _seen, log_at_destroy)] = rooms.calls
    assert log_at_destroy > before, "a commit was posted before the destroy"


def test_unconfirmed_removal_deletes_nothing_and_a_retry_finishes(monkeypatch):
    monkeypatch.setattr(ConnectionController, "REMOVE_BEFORE_DELETE_SECONDS", 0.3)
    w, (a, b, c) = _group(3)
    rooms = _Rooms(w, [b, c])
    ctl = _controller(a, rooms)
    w.room.drop_next = 1                    # the room loses the removal commit
    out = ctl.delete_secure_group(ROOM)
    assert not out["ok"] and out["code"] == "group_removal_unconfirmed"
    assert rooms.calls == [], "nothing deleted while members may still be in it"
    assert a.groups.is_secure(ROOM)
    out = ctl.delete_secure_group(ROOM)     # again: the removal is re-sent
    assert out["ok"], out
    [(_op, _room, seen, _log)] = rooms.calls
    assert all(removed for removed, _s in seen.values())


def test_only_the_creator_removes_others_only_destroy():
    """A member who is not the creator (a server admin, say) cannot remove
    anyone; Delete goes straight to the service, which decides."""
    w, (a, b, c) = _group(3)
    rooms = _Rooms(w, [a, c])
    before = len(w.room.log)
    _controller(b, rooms).delete_secure_group(ROOM)
    assert len(rooms.calls) == 1
    assert len(w.room.log) == before, "no commit from someone who may not remove"
    assert "removed_us" not in a.changes()


def test_a_group_of_one_is_deleted_at_once():
    w, (a,) = _group(1)
    rooms = _Rooms(w, [])
    assert _controller(a, rooms).delete_secure_group(ROOM)["ok"]
    assert len(rooms.calls) == 1
