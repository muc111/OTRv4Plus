# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The room list shows what each room is (owner request, 2026-10-10).

Secure groups' rooms were on the server (Prosody `muc:list` showed all nine)
but missing from the app's room search: the service lists only rooms
configured public, and nothing ever asked for that. Now:

  * a room the app or Termux creates asks to be public; a secure group's
    room also carries a fixed description (`SECURE_GROUP_DESC`);
  * discovery reads each room's disco#info for that marker and for
    `muc_passwordprotected`, so the list can show 🔐 group / # channel / 🔒;
  * groups this account holds are listed (and marked secure) even when the
    service hides their room -- the rooms made before this change.
"""
from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_muc as M  # noqa: E402
from tests.test_android_rooms import FakeMuc, build  # noqa: E402

DISCO = "http://jabber.org/protocol/disco#info"
SERVICE = "conference.x.i2p"


def info_xml(*, password=False, desc=""):
    q = ET.Element("{%s}query" % DISCO)
    ET.SubElement(q, "{%s}identity" % DISCO, category="conference", type="text")
    for var in ["http://jabber.org/protocol/muc"] + (
            ["muc_passwordprotected"] if password else []):
        ET.SubElement(q, "{%s}feature" % DISCO, var=var)
    x = ET.SubElement(q, "{jabber:x:data}x", type="result")
    for var, value in (("FORM_TYPE", "http://jabber.org/protocol/muc#roominfo"),
                       ("muc#roominfo_occupants", "2"),
                       ("muc#roominfo_description", desc)):
        f = ET.SubElement(x, "{jabber:x:data}field", var=var)
        ET.SubElement(f, "{jabber:x:data}value").text = value
    return q


class _Info(dict):
    def __init__(self, xml):
        class _P:
            pass
        p = _P()
        p.xml = xml
        super().__init__({"disco_info": p})


class _Disco:
    def __init__(self, items, infos):
        self.items, self.infos = items, infos

    async def get_items(self, jid=None, timeout=None, **_kw):
        class _Pl:
            def __init__(s, e):
                s.e = e

            def get_items(s):
                return s.e
        return {"disco_items": _Pl(self.items)}

    async def get_info(self, jid=None, timeout=None, **_kw):
        return _Info(self.infos[str(jid)])


class TestTheKindOfARoom:

    def test_marker_and_password_are_read(self):
        assert M.room_kind(info_xml(desc=M.SECURE_GROUP_DESC)) == (True, False)
        assert M.room_kind(info_xml(password=True)) == (False, True)
        assert M.room_kind(info_xml(desc="a chat about cats")) == (False, False)

    def test_unreadable_is_an_ordinary_open_room(self):
        assert M.room_kind(None) == (False, False)


class TestDiscovery:

    def test_the_list_says_group_channel_and_password(self):
        g, c, p = ("lmao@" + SERVICE, "chat@" + SERVICE, "club@" + SERVICE)
        disco = _Disco([(g, None, ""), (c, None, "Chat"), (p, None, "")],
                       {g: info_xml(desc=M.SECURE_GROUP_DESC), c: info_xml(),
                        p: info_xml(password=True)})
        t, _made = build(disco=disco, muc=FakeMuc())
        try:
            code, _d, rooms = t.discover_rooms(SERVICE)
        finally:
            t.close()
        assert code == "ok"
        kind = {r["jid"]: (r["secure"], r["password"], r["occupants"]) for r in rooms}
        assert kind == {g: (True, False, 2), c: (False, False, 2), p: (False, True, 2)}


class TestHeldGroupsAreListed:

    def _controller(self, held):
        from android_bridge.connection import ConnectionController

        class _Groups:
            def rooms(self):
                return list(held)

        class _App:
            groups = _Groups()

        ctl = ConnectionController.__new__(ConnectionController)
        ctl._app = _App()
        return ctl

    def test_a_hidden_room_of_ours_is_added_and_ours_are_marked(self):
        ctl = self._controller(["mls2@" + SERVICE, "lmao@" + SERVICE,
                                "other@conference.elsewhere.i2p"])
        listed = {"ok": True, "code": "ok", "detail": "",
                  "value": [{"jid": "lmao@" + SERVICE, "name": "", "occupants": 1,
                             "secure": False, "password": False},
                            {"jid": "chat@" + SERVICE, "name": "", "occupants": 0,
                             "secure": False, "password": False}]}
        out = ctl._with_held_groups(listed, SERVICE)["value"]
        by = {r["jid"]: r for r in out}
        assert by["lmao@" + SERVICE]["secure"] is True
        assert by["chat@" + SERVICE]["secure"] is False
        assert by["mls2@" + SERVICE]["secure"] is True        # hidden, but ours
        assert "other@conference.elsewhere.i2p" not in by     # another service

    def test_a_failed_listing_is_passed_through(self):
        ctl = self._controller(["mls2@" + SERVICE])
        failed = {"ok": False, "code": "network", "detail": "", "value": None}
        assert ctl._with_held_groups(failed, SERVICE) is failed


class TestCreatedRoomsAskToBeListed:

    def test_the_app_and_termux_ask_for_a_public_marked_room(self):
        here = os.path.join(ROOT, "android_bridge", "transport.py")
        termux = os.path.join(ROOT, "otrv4plus_groups.py")
        for path in (here, termux):
            src = open(path, encoding="utf-8").read()
            assert "muc#roomconfig_publicroom" in src, path
            assert "SECURE_GROUP_DESC" in src, path
