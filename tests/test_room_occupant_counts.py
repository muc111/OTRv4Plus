# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""How many people are in each listed room (XEP-0045 §6.4).

Handset report: the rooms list on yax.im showed many rooms and no idea which
had anyone in them. A room's disco#info carries a `muc#roominfo` form whose
`muc#roominfo_occupants` field is the count; Prosody and ejabberd send it for
public rooms. The count is the service's own. When a room does not give one,
the app shows nothing -- "unknown" is never rendered as "0 users".
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (HERE, ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("slixmpp")

from slixmpp.plugins.xep_0030.stanza import DiscoInfo  # noqa: E402
from slixmpp.xmlstream import ET  # noqa: E402

from android_bridge import transport as T  # noqa: E402
from tests.test_android_rooms import (FakeDisco, Items, MUC_SERVICE,  # noqa: E402
                                      build)

NS = "http://jabber.org/protocol/disco#info"


def info_with(count_text=None, form_type="http://jabber.org/protocol/muc#roominfo"):
    """A real slixmpp disco#info payload, as a room returns it."""
    xml = ET.fromstring(
        "<query xmlns='%s'><identity category='conference' type='text' "
        "name='Room'/><feature var='http://jabber.org/protocol/muc'/>%s</query>"
        % (NS, "" if count_text is None else
           "<x xmlns='jabber:x:data' type='result'>"
           "<field var='FORM_TYPE' type='hidden'><value>%s</value></field>"
           "<field var='muc#roominfo_occupants'><value>%s</value></field></x>"
           % (form_type, count_text)))
    return {"disco_info": DiscoInfo(xml=xml)}


class TestParsing:

    @pytest.mark.parametrize("text,want", [("0", 0), ("1", 1), ("42", 42),
                                           (" 7 ", 7)])
    def test_the_count_is_read(self, text, want):
        assert T._room_occupant_count(info_with(text)) == want

    @pytest.mark.parametrize("text", ["", "-1", "many", "1.5", "99999999"])
    def test_anything_but_a_plain_count_is_not_given(self, text):
        assert T._room_occupant_count(info_with(text)) is None

    def test_no_form_means_not_given_not_zero(self):
        assert T._room_occupant_count(info_with(None)) is None

    def test_garbage_does_not_raise(self):
        assert T._room_occupant_count(object()) is None


class CountingDisco(FakeDisco):
    def __init__(self, rooms, counts, *, fail=(), delay=0.0):
        super().__init__(items={MUC_SERVICE: rooms})
        self.counts, self.fail, self.delay = counts, set(fail), delay
        self.info_asked, self.in_flight, self.peak = [], 0, 0

    async def get_info(self, jid=None, timeout=None, **_kw):
        jid = str(jid)
        self.info_asked.append(jid)
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if jid in self.fail:
                raise RuntimeError("service-unavailable")
            return info_with(self.counts.get(jid))
        finally:
            self.in_flight -= 1


def room(n):
    return ("r%d@%s" % (n, MUC_SERVICE), None, "Room %d" % n)


class TestListing:

    def test_counts_are_attached_and_occupied_rooms_come_first(self):
        disco = CountingDisco([room(1), room(2), room(3)],
                              {room(1)[0]: "0", room(2)[0]: "5", room(3)[0]: "2"})
        t, _ = build(disco=disco)
        try:
            code, _d, rooms = t.discover_rooms(MUC_SERVICE)
        finally:
            t.close()
        assert code == "ok"
        assert [(r["name"], r["occupants"]) for r in rooms] == [
            ("Room 2", 5), ("Room 3", 2), ("Room 1", 0)]

    def test_a_room_that_gives_no_count_is_listed_without_one(self):
        disco = CountingDisco([room(1), room(2)], {room(1)[0]: None},
                              fail={room(2)[0]})
        t, _ = build(disco=disco)
        try:
            code, _d, rooms = t.discover_rooms(MUC_SERVICE)
        finally:
            t.close()
        assert code == "ok"
        assert [r["occupants"] for r in rooms] == [None, None]
        assert len(rooms) == 2, "a failed count must not drop the room"

    def test_asking_is_bounded(self):
        many = [room(n) for n in range(T.XmppTransport.ROOM_INFO_LIMIT + 30)]
        disco = CountingDisco(many, {r[0]: "1" for r in many}, delay=0.005)
        t, _ = build(disco=disco)
        try:
            code, _d, rooms = t.discover_rooms(MUC_SERVICE)
        finally:
            t.close()
        assert code == "ok" and len(rooms) == len(many)
        assert len(disco.info_asked) == T.XmppTransport.ROOM_INFO_LIMIT
        assert disco.peak <= T.XmppTransport.ROOM_INFO_PARALLEL

    def test_the_counts_cross_to_kotlin_as_plain_values(self):
        disco = CountingDisco([room(1)], {room(1)[0]: "3"})
        t, _ = build(disco=disco)
        try:
            _c, _d, rooms = t.discover_rooms(MUC_SERVICE)
        finally:
            t.close()
        assert all(isinstance(v, (str, int, type(None)))
                   for r in rooms for v in r.values())


def test_kotlin_renders_unknown_as_nothing():
    src = open(os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                            "otrv4plus", "android", "ui", "RoomsScreen.kt")).read()
    assert "room.occupants?.let" in src
    core = open(os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                             "otrv4plus", "android", "bridge",
                             "ChaquopyOtrCore.kt")).read()
    assert 'entry(item, "occupants").toIntOrNull()' in core


assert Items  # the shared fake is the same one the rooms tests use
