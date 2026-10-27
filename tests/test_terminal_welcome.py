# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal joins the Welcome room, so the apps show it as online.

Device report, 2026-10-27: "Termux users aren't showing as online on
desktop or app". The apps list who is online from the server's OTRv4Plus
Welcome room (android_bridge.welcome); the terminal never joined it. It
now finds it the same way -- by its exact public name, never guessed, never
created -- and joins it unless `--no-welcome`.
"""
from __future__ import annotations

import asyncio
import types

import pytest

xmpp = pytest.importorskip("otrv4plus_xmpp")
from android_bridge import welcome as W  # noqa: E402

DOMAIN = "otrv4plus.i2p"
MUC = "conference.otrv4plus.i2p"
ROOM = "otrv4plus-welcome@conference.otrv4plus.i2p"


class _Items(dict):
    def __init__(self, items):
        super().__init__(disco_items=types.SimpleNamespace(get_items=lambda: items))


class _Disco:
    def __init__(self, rooms):
        self.rooms = rooms

    async def get_items(self, jid, timeout=None):
        if str(jid) == DOMAIN:
            return _Items([(MUC, None, "Chatrooms"), ("upload.otrv4plus.i2p", None, "")])
        return _Items([(r, None, n) for r, n in self.rooms])

    async def get_info(self, jid, timeout=None):
        category = "conference" if str(jid) == MUC else "store"
        return {"disco_info": {"identities": [(category, "text", None, "")]}}


class _Muc:
    def __init__(self, taken=()):
        self.joined, self.taken = [], set(taken)

    async def join_muc_wait(self, room, nick, timeout=None, **kw):
        if nick in self.taken:
            raise RuntimeError("conflict")
        self.joined.append((room, nick))


def _client(rooms, taken=()):
    c = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)
    c.plugin = {"xep_0030": _Disco(rooms), "xep_0045": _Muc(taken)}
    c.boundjid = types.SimpleNamespace(domain=DOMAIN, user="b")
    return c


def _run(c):
    asyncio.new_event_loop().run_until_complete(c._welcome_join())


def test_the_welcome_room_is_found_by_its_name_and_joined(capsys):
    c = _client([(ROOM, W.ROOM_NAME), ("other@" + MUC, "Something else")])
    _run(c)
    assert c.plugin["xep_0045"].joined == [(ROOM, "b")]
    assert "the apps show you as online" in capsys.readouterr().out


def test_a_taken_nickname_gets_a_suffix(capsys):
    c = _client([(ROOM, W.ROOM_NAME)], taken={"b"})
    _run(c)
    [(room, nick)] = c.plugin["xep_0045"].joined
    assert room == ROOM and nick.startswith("b-")


@pytest.mark.parametrize("rooms", [[], [("x@" + MUC, "OTRv4Plus Welcome (unofficial)")],
                                   [(ROOM, W.ROOM_NAME), ("y@" + MUC, W.ROOM_NAME)]])
def test_no_room_or_an_unclear_one_is_not_joined_or_guessed(rooms, capsys):
    c = _client(rooms)
    _run(c)
    assert c.plugin["xep_0045"].joined == []
    assert "only to your contacts" in capsys.readouterr().out


def test_no_welcome_keeps_the_terminal_out():
    args = xmpp._parser().parse_args(["--jid", "b@otrv4plus.i2p", "--no-welcome"])
    assert args.no_welcome is True
    assert xmpp._parser().parse_args(["--jid", "b@otrv4plus.i2p"]).no_welcome is False
    src = open(xmpp.__file__, encoding="utf-8").read()
    assert 'client._join_welcome = not getattr(args, "no_welcome", False)' in src
    start = src[src.index("        self.send_presence()\n        # The apps list who is online"):][:600]
    assert 'if getattr(self, "_join_welcome", False):' in start
    assert "asyncio.ensure_future(self._welcome_join())" in start
