# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Gate: deleting a room or secure group, per role.

Who may (rc.83 5b3218c, rc.88 256c3c8): the room's OWNER (creator) and a
SERVER ADMIN; everyone else gets Leave only. rc.88's mechanism is approach
(b): a plain XEP-0045 10.9 owner destroy -- an IQ set to the room carrying
muc#owner <destroy/> -- relying on Prosody counting its server admins as
owners of every room. No affiliation grant, no ad-hoc command, before it.
A room ADMIN affiliation is not enough (10.9 is owner-only): not offered.

When the server refuses a SERVER ADMIN's owner destroy -- the owner's server
(2026-10-18) did not count its admin as owner of other people's rooms --
the app falls back to mod_otrv4plus_moderation's admin-only "Destroy a
room" command, after the owner destroy and only for an admin.

MLS+ groups are MUC rooms carrying ciphertext: the same destroy, no special
case. The real slixmpp stanzas are captured here, not hand-built ones.
"""
from source_of import transport_source  # noqa: E402
import asyncio
import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
slixmpp = pytest.importorskip("slixmpp")
pytest.importorskip("otrv4_")
from slixmpp.stanza import Iq, Presence                              # noqa: E402

import otrv4plus_muc as M                                            # noqa: E402
from android_bridge.connection import ConnectionController           # noqa: E402
from android_bridge.transport import XmppTransport                   # noqa: E402

ROOM = "team@conference.otrv4plus.i2p"
MUC_OWNER = "{http://jabber.org/protocol/muc#owner}"


@pytest.fixture
def wire(monkeypatch):
    """A real slixmpp client whose stanzas are recorded instead of sent."""
    sent = []

    async def iq_send(self, *a, **k):
        sent.append(self)

    monkeypatch.setattr(Iq, "send", iq_send)
    monkeypatch.setattr(Presence, "send", lambda self, *a, **k: sent.append(self))
    client = slixmpp.ClientXMPP("alice@otrv4plus.i2p/phone", "pw")
    client.register_plugin("xep_0045")
    t = XmppTransport.__new__(XmppTransport)
    t._client = client
    t._room_nicks = {ROOM: "alice"}
    return t, sent


def test_delete_is_one_owner_destroy_iq_to_the_room(wire):
    t, sent = wire
    asyncio.run(t._destroy_room(ROOM, "secure group deleted"))
    assert len(sent) == 1, "approach (b): nothing is sent before the destroy"
    iq = sent[0]
    assert isinstance(iq, Iq)
    assert iq["type"] == "set" and str(iq["to"]) == ROOM
    destroy = iq.xml.find(MUC_OWNER + "query/" + MUC_OWNER + "destroy")
    assert destroy is not None
    assert destroy.findtext(MUC_OWNER + "reason") == "secure group deleted"


def test_leave_is_unavailable_presence_without_destroy(wire):
    t, sent = wire
    try:
        asyncio.run(t._leave_room(ROOM, "alice"))
    except KeyError:
        pass        # slixmpp's own bookkeeping; the presence is already out
    assert len(sent) == 1
    p = sent[0]
    assert isinstance(p, Presence)
    assert p["type"] == "unavailable" and str(p["to"]) == ROOM + "/alice"
    assert "destroy" not in str(p)


@pytest.mark.parametrize("affiliation,may", [
    ("owner", True), ("admin", False), ("member", False), ("none", False),
    ("outcast", False), ("unheard-of", False)])
def test_only_an_owner_may_destroy(affiliation, may):
    for role in ("moderator", "participant", "visitor", "none"):
        assert M.privileges(affiliation, role).destroy is may


def test_owned_rooms_lists_rooms_whose_roster_says_owner():
    t = XmppTransport.__new__(XmppTransport)
    t._room_nicks = {ROOM: "alice", "other@conference.otrv4plus.i2p": "alice"}
    t._room_standing = lambda room, nick: {"destroy": room == ROOM}
    assert t.owned_rooms()[2] == [ROOM]


def test_a_refused_destroy_says_who_may_not_you_may_be_banned():
    c = ConnectionController.__new__(ConnectionController)
    c._app = types.SimpleNamespace(groups=None)
    c._transport = types.SimpleNamespace(
        destroy_room=lambda room, reason: ("forbidden", M.CODES["forbidden"], None))
    c._noting_room = lambda result, room, joined: result
    c._bookmark = lambda *a, **k: None
    result = c.destroy_room(ROOM)
    assert not result["ok"] and result["code"] == "forbidden"
    assert "owner" in result["detail"] and "server admin" in result["detail"]
    assert "banned" not in result["detail"]


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


A = ("android", "app", "src", "main", "java", "org", "otrv4plus", "android")


def test_the_server_admin_predicate_feeds_both_screens():
    """rc.88: the server lists XEP-0133 commands to its admins only."""
    tr = transport_source()
    assert 'ADMIN_COMMAND_PREFIX = "http://jabber.org/protocol/admin#"' in tr
    state = _read(*A, "chat", "ChatState.kt")
    assert "RoomDeletion.mayDelete(owner = bare(jid) in ownedRooms, serverAdmin = serverAdmin)" in state
    vm = _read(*A, "RoomsViewModel.kt")
    assert "RoomDeletion.mayDelete(owner = owner, serverAdmin = serverAdmin)" in vm
    rule = _read(*A, "chat", "RoomDeletion.kt")
    assert "fun mayDelete(owner: Boolean, serverAdmin: Boolean): Boolean = owner || serverAdmin" in rule


def test_delete_is_never_dropped_silently():
    """A Delete confirmed while discovery ran (minutes over I2P since rc.117)
    returned without a word: "Delete does not work"."""
    vm = _read(*A, "RoomsViewModel.kt")
    for fn in ("private fun groupOp(", "fun deleteRoom(", "fun destroy(room"):
        body = vm[vm.index(fn):]
        body = body[:body.index("viewModelScope.launch")]
        assert "if (busy != null) return" not in body, fn
        assert "refuseWhileBusy()" in body, fn


class _AdminTransport:
    """destroy_room refused (as on the owner's server, 2026-10-18: Prosody
    did not count the admin as owner); the moderation command available."""

    def __init__(self, admin=True, command=True, refused=False):
        self._server_admin = admin
        self.admin_answer = bool(admin)
        self.command, self.refused, self.calls = command, refused, []

    def server_admin(self):
        # As transport.server_admin: asked when this stream has not been.
        self.calls.append(("server_admin",))
        return ("ok", "", self.admin_answer)

    def destroy_room(self, room, reason):
        self.calls.append(("destroy_room", room))
        return ("forbidden", M.CODES["forbidden"], None)

    def moderation(self, op, account="", days=0, reason=""):
        self.calls.append(("moderation", op, account))
        return ("ok", "", {"available": self.command, "refused": self.refused,
                           "message": "Destroyed."})


def _ctl(t):
    c = ConnectionController.__new__(ConnectionController)
    c._app = types.SimpleNamespace(groups=None)
    c._transport = t
    c._noting_room = lambda result, room, joined: result
    c._bookmark = lambda *a, **k: None
    return c


def test_an_admin_refused_as_owner_destroys_through_the_admin_command():
    t = _AdminTransport()
    result = _ctl(t).destroy_room(ROOM, "clean up")
    assert result["ok"], result
    # (b) first, exactly as rc.88; the admin command only after its refusal.
    assert t.calls == [("destroy_room", ROOM), ("moderation", "destroy", ROOM)]


def test_an_admin_after_a_reconnect_still_gets_the_admin_route():
    """rc.120 on the owner's phone: the transport forgets _server_admin on
    every reconnect while the screen remembers it, so Delete was offered
    and then refused as if Alice were nobody. Asked again, not assumed."""
    t = _AdminTransport(admin=None)
    t.admin_answer = True
    result = _ctl(t).destroy_room(ROOM)
    assert result["ok"], result
    assert t.calls == [("destroy_room", ROOM), ("server_admin",),
                       ("moderation", "destroy", ROOM)]


def test_not_an_admin_the_refusal_stands():
    t = _AdminTransport(admin=False)
    result = _ctl(t).destroy_room(ROOM)
    assert not result["ok"] and result["code"] == "forbidden"
    assert result["detail"] == ConnectionController.DESTROY_REFUSED
    assert ("moderation", "destroy", ROOM) not in t.calls


def test_an_admin_on_an_old_module_is_told_to_update_it():
    result = _ctl(_AdminTransport(command=False)).destroy_room(ROOM)
    assert not result["ok"]
    assert result["detail"] == ConnectionController.DESTROY_NEEDS_MODULE
    assert "install-server-limits.sh" in result["detail"]


def test_an_admin_refused_by_the_command_sees_what_the_server_said():
    t = _AdminTransport(refused=True)
    t.moderation = lambda *a, **k: ("ok", "", {"available": True, "refused": True,
                                               "message": "There is no such room."})
    result = _ctl(t).destroy_room(ROOM)
    assert not result["ok"] and result["detail"] == "There is no such room."


def test_the_admin_command_is_in_the_module_and_admin_only():
    mod = _read("prosody", "mod_otrv4plus_moderation.lua")
    assert ('adhoc_new("Destroy a room", NS .. "destroy-room", destroy_handler, "admin")'
            in mod)
    tr = transport_source()
    assert '"destroy": "destroy-room"' in tr


@pytest.mark.parametrize("code", ["room_gone", "item_not_found"])
def test_deleting_a_room_already_deleted_is_done_not_red(code):
    """Owner, 2026-10-18: Delete on "lol" said "This room was deleted." in
    red and the room stayed listed -- Prosody's tombstone answered <gone/>."""
    t = _AdminTransport()
    t.destroy_room = lambda room, reason: (code, M.CODES.get(code, ""), None)
    result = _ctl(t).destroy_room(ROOM)
    assert result["ok"] and result["code"] == "ok"
    assert "already deleted" in result["detail"]


def test_the_admin_list_and_destroy_know_tombstones():
    mod = _read("prosody", "mod_otrv4plus_moderation.lua")
    assert "local function is_tombstone(room)" in mod
    assert "if not is_tombstone(room) then" in mod
    assert 'was already deleted; its record is removed too."' in mod


def test_a_secure_group_keeps_what_the_admin_route_said():
    t = _AdminTransport(command=False)
    c = _ctl(t)
    c._on_room_destroyed = lambda room: None
    out = c.delete_secure_group(ROOM)
    assert not out["ok"] and out["detail"] == ConnectionController.DESTROY_NEEDS_MODULE


def test_an_admin_deleting_a_tombstone_removes_its_record_too():
    """Owner, 2026-10-18: "lol" stayed on muc:list after Delete said it was
    deleted -- Prosody's tombstone. The admin route removes it."""
    t = _AdminTransport()
    t.destroy_room = lambda room, reason: ("room_gone", M.CODES["room_gone"], None)
    assert _ctl(t).destroy_room(ROOM)["ok"]
    assert ("moderation", "destroy", ROOM) in t.calls
