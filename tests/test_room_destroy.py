# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Gate: deleting a room or secure group, per role.

Who may (rc.83 5b3218c, rc.88 256c3c8): the room's OWNER (creator) and a
SERVER ADMIN; everyone else gets Leave only. rc.88's mechanism is approach
(b): a plain XEP-0045 10.9 owner destroy -- an IQ set to the room carrying
muc#owner <destroy/> -- relying on Prosody counting its server admins as
owners of every room. No affiliation grant, no ad-hoc command, before it.
A room ADMIN affiliation is not enough (10.9 is owner-only): not offered.

MLS+ groups are MUC rooms carrying ciphertext: the same destroy, no special
case. The real slixmpp stanzas are captured here, not hand-built ones.
"""
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
    tr = _read("android_bridge", "transport.py")
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
