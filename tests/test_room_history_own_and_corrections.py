# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What a room replays as we join is history: our own lines in it are shown,
our corrections in it applied, and none of it is announced (owner,
2026-10-17: "messages in the public room should be displayed for all users
who login ... the corrected must overwrite the original").

Before: every message from our own nickname was taken for the room echoing
what we had just sent, and dropped -- so after Sign out, or on another
phone, our own earlier lines and corrections in the Welcome room were gone.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from slixmpp import Message
from slixmpp.xmlstream import ET

from android_bridge.transport import XmppTransport

ROOM = "otrv4plus-welcome@conference.otrv4plus.i2p"
DELAY = "<delay xmlns='urn:xmpp:delay' stamp='2026-10-17T09:00:00Z'/>"


def _msg(nick, body, mid, delayed, extra=""):
    xml = ("<message xmlns='jabber:client' type='groupchat' from='%s/%s' id='%s'>"
           "<body>%s</body>%s%s"
           "<stanza-id xmlns='urn:xmpp:sid:0' by='%s' id='room-%s'/></message>"
           % (ROOM, nick, mid, body, DELAY if delayed else "", extra, ROOM, mid))
    return Message(xml=ET.fromstring(xml))


def _transport():
    t = XmppTransport.__new__(XmppTransport)
    t.delivered = []
    t._on_room_message = lambda *a, **k: t.delivered.append((a, k))
    t._our_nick = lambda room: "alice"
    t._held = lambda: {}
    t._room_key = lambda room: room
    return t


def test_our_own_line_in_the_history_is_shown_as_ours():
    t = _transport()
    t._on_groupchat(_msg("alice", "hello from yesterday", "m1", delayed=True))
    (args, kwargs), = t.delivered
    assert args[2] == "hello from yesterday"
    assert kwargs.get("own") is True
    assert kwargs["item"].source == "history"


def test_our_live_echo_is_still_only_an_acknowledgement():
    t = _transport()
    t._on_groupchat(_msg("alice", "just now", "m2", delayed=False))
    (args, kwargs), = t.delivered
    assert args[2] == ""                         # nothing shown twice
    assert kwargs["item"].source == "live"


def test_someone_elses_history_is_marked_history():
    t = _transport()
    t._on_groupchat(_msg("bob", "earlier", "m3", delayed=True))
    (args, kwargs), = t.delivered
    assert args[2] == "earlier" and not kwargs.get("own")
    assert kwargs["item"].source == "history"


def test_our_correction_in_the_history_reaches_the_app_as_ours():
    t = _transport()
    fix = "<replace xmlns='urn:xmpp:message-correct:0' id='m1'/>"
    t._on_groupchat(_msg("alice", "hello, corrected", "m4", delayed=True, extra=fix))
    (args, kwargs), = t.delivered
    assert kwargs["item"].action == "edit" and kwargs["item"].target == "m1"
    assert kwargs.get("own") is True


def test_the_app_shows_and_applies_our_history_but_not_our_live_echo():
    src = open(os.path.join(ROOT, "android_bridge", "app.py")).read()
    assert 'if own and item.source == "live":' in src


def test_history_is_stored_but_never_announced():
    kt = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                           "android/chat/ChatState.kt")).read()
    body = kt[kt.index("fun receiveRoom("):]
    body = body[:body.index("fun receive(")]
    assert 'return added && event.source == "live"' in body
