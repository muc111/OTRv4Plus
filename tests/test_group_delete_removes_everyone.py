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


# ── device report, 2026-10-27: Delete on the creator's phone did nothing ────

import test_secure_groups as T                                 # noqa: E402
from android_bridge.groups import GROUP_DELETED_SIGNAL         # noqa: E402


def _group_created_by(creator, others):
    """[creator] makes the group and invites [others]: names chosen so the
    creator does NOT sort first, as on the device ("dontlook", "charlie")."""
    w = T.World()
    for name in [creator] + others:
        w.add(name)
    a = w.members[creator]
    a.join_room()
    a.groups.create(ROOM)
    for other in others:
        w.pair(creator, other)
        T._invite(w, creator, other)
    return w, [w.members[n] for n in [creator] + others]


def test_the_creator_is_the_first_leaf_not_the_first_name():
    w, (d, c) = _group_created_by("dontlook@x.i2p", ["charlie@x.i2p"])
    assert d.groups.coordinator(ROOM) == "dontlook@x.i2p"
    assert c.groups.coordinator(ROOM) == "dontlook@x.i2p", "the member agrees"
    assert d.groups.is_creator(ROOM) and not c.groups.is_creator(ROOM)


def test_a_creator_who_sorts_last_removes_everyone_on_delete():
    w, (d, c) = _group_created_by("dontlook@x.i2p", ["charlie@x.i2p"])
    rooms = _Rooms(w, [c])
    out = _controller(d, rooms).delete_secure_group(ROOM)
    assert out["ok"], out
    [(_op, _room, seen, _log)] = rooms.calls
    assert seen["charlie@x.i2p"][0], "charlie was removed before the room went"
    assert not c.groups.is_secure(ROOM)


def test_delete_also_tells_each_member_over_otr():
    w, (d, c) = _group_created_by("dontlook@x.i2p", ["charlie@x.i2p"])
    told = []
    ctl = _controller(d, _Rooms(w, [c]))
    ctl._app.notify_group_deleted = lambda room, members: told.append((room, list(members)))
    assert ctl.delete_secure_group(ROOM)["ok"]
    assert told == [(ROOM, ["charlie@x.i2p"])]


def test_a_member_who_was_away_ends_its_copy_on_the_creators_notice():
    w, (d, c) = _group_created_by("dontlook@x.i2p", ["charlie@x.i2p"])
    del w.room.occupants[c.jid]                 # away: no removal, no destroy
    _controller(d, _Rooms(w, [])).delete_secure_group(ROOM)
    assert c.groups.is_secure(ROOM), "nothing reached charlie through the room"
    c.groups.on_signal(d.jid, GROUP_DELETED_SIGNAL + ROOM)
    assert not c.groups.is_secure(ROOM)
    assert "deleted" in c.changes()


def test_a_notice_after_the_removal_takes_the_room_off_the_list_too():
    w, (d, c) = _group_created_by("dontlook@x.i2p", ["charlie@x.i2p"])
    _controller(d, _Rooms(w, [c])).delete_secure_group(ROOM)
    assert "removed_us" in c.changes() and "deleted" not in c.changes()
    c.groups.on_signal(d.jid, GROUP_DELETED_SIGNAL + ROOM)
    assert "deleted" in c.changes()


def test_only_the_creator_can_delete_it_for_someone_else():
    w, (d, c, e) = _group_created_by("dontlook@x.i2p", ["charlie@x.i2p", "erin@x.i2p"])
    w.pair(c.jid, e.jid)
    e.groups.on_signal(c.jid, GROUP_DELETED_SIGNAL + ROOM)    # charlie is no creator
    assert e.groups.is_secure(ROOM)
    assert any(getattr(ev, "detail", "") == "not_the_creator" for ev in e.events)


def test_the_app_sends_the_notice_inside_the_session_or_keeps_it_for_one():
    import test_deniability_wire_audit as W
    wire, alice, bob = W._pair()
    seen = []
    bob.groups.on_signal = lambda peer, body: seen.append((peer, body))
    alice.notify_group_deleted(ROOM, [W.BOB])
    assert seen == [(W.ALICE, GROUP_DELETED_SIGNAL + ROOM)]
    assert not any(GROUP_DELETED_SIGNAL in body for _f, _t, body in wire.frames), \
        "never on the wire in the clear"
    # No session with them: kept, and a session asked for.
    started = []
    alice._engine.end_session(W.BOB)
    alice.ensure_otr = lambda peer: started.append(peer) or "checking"
    alice.notify_group_deleted(ROOM, [W.BOB])
    assert alice._deleted_after_otr == {W.BOB: [ROOM]} and started == [W.BOB]


def test_members_are_told_even_when_the_server_refuses_the_destroy():
    w, (d, c) = _group_created_by("dontlook@x.i2p", ["charlie@x.i2p"])
    told = []
    rooms = _Rooms(w, [c])
    rooms.destroy_room = lambda room, reason: ("forbidden", "not the owner", None)
    ctl = _controller(d, rooms)
    ctl._app.notify_group_deleted = lambda room, members: told.append((room, list(members)))
    out = ctl.delete_secure_group(ROOM)
    assert not out["ok"], "the destroy was refused, and Delete says so"
    assert told == [(ROOM, ["charlie@x.i2p"])], "removed, so told regardless"
    assert "removed_us" in c.changes()
