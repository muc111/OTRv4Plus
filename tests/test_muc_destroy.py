# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A room its owner destroyed leaves every member's phone (device report,
2026-10-24: "other clients remain stuck in the room").

The service tells each occupant with an unavailable presence carrying
muc#user <destroy/> (XEP-0045 10.9). The transport already noticed it, but
only a secure group was ended, and only its keys: the room stayed in the
app's list with its history, a plain room was not handled at all, and the
bridge kept the room as one it is in. Now every destroyed room is forgotten
by the bridge and the transport and the app is told (secure group:
"deleted", plain room: "room_deleted"); ChatState then drops the room, its
history, draft and invitation (SecureGroupStateTest).
"""
import types

import pytest

slixmpp = pytest.importorskip("slixmpp")
pytest.importorskip("otrv4_")
from slixmpp.stanza import Presence  # noqa: E402

from android_bridge.connection import ConnectionController  # noqa: E402
from android_bridge.events import GroupChanged  # noqa: E402
from android_bridge.transport import XmppTransport  # noqa: E402

ROOM = "team@conference.otrv4plus.i2p"
MUC_USER = "http://jabber.org/protocol/muc#user"


def _transport():
    client = slixmpp.ClientXMPP("bob@otrv4plus.i2p/phone", "pw")
    client.register_plugin("xep_0045")
    t = XmppTransport.__new__(XmppTransport)
    t._client = client
    t._room_nicks = {ROOM: "bob"}
    t._on_presence = None
    return t


def _destroy_presence(client, reason="the owner deleted it"):
    p = Presence(stream=client)
    p["from"] = ROOM + "/bob"
    p["to"] = "bob@otrv4plus.i2p/phone"
    p["type"] = "unavailable"
    xml = ('<x xmlns="%s"><item affiliation="none" role="none"/>'
           '<destroy><reason>%s</reason></destroy></x>' % (MUC_USER, reason))
    from slixmpp.xmlstream import ET
    p.append(ET.fromstring(xml))
    return p


def test_the_transport_reports_a_destroy_presence():
    t = _transport()
    seen = []
    t.room_destroyed = seen.append
    t._presence(_destroy_presence(t._client), False)
    assert seen == [ROOM]


def test_an_ordinary_leave_is_not_a_destroy():
    t = _transport()
    seen = []
    t.room_destroyed = seen.append
    p = Presence(stream=t._client)
    p["from"] = ROOM + "/carol"
    p["type"] = "unavailable"
    t._presence(p, False)
    assert seen == []


def _controller(transport, secure):
    events, rooms = [], {ROOM, "other@conference.x"}
    groups = types.SimpleNamespace(on_room_destroyed=lambda room: secure)
    app = types.SimpleNamespace(groups=groups, _rooms=rooms, _emit=events.append)
    c = ConnectionController.__new__(ConnectionController)
    c._app, c._transport = app, transport
    return c, app, events


@pytest.mark.parametrize("secure", [False, True], ids=["plain room", "secure group"])
def test_a_destroyed_room_is_forgotten_and_the_app_is_told(secure):
    t = _transport()
    c, app, events = _controller(t, secure)
    c._on_room_destroyed(ROOM.upper() + "/bob")      # any spelling, a full JID
    assert ROOM not in app._rooms, "the bridge no longer treats it as a room it is in"
    assert "other@conference.x" in app._rooms
    assert ROOM not in t._room_nicks, "nothing sends to it or rejoins it"
    if secure:
        assert events == [], "the group layer already said 'deleted'"
    else:
        assert [(e.peer, e.change) for e in events] == [(ROOM, "room_deleted")]
        assert isinstance(events[0], GroupChanged)


def test_end_to_end_a_destroy_presence_clears_the_room():
    t = _transport()
    c, app, events = _controller(t, secure=False)
    t.room_destroyed = c._on_room_destroyed
    t._presence(_destroy_presence(t._client), False)
    assert ROOM not in app._rooms and ROOM not in t._room_nicks
    assert [e.change for e in events] == ["room_deleted"]
