# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""One lost disco#info reply no longer hides the rooms service (owner,
2026-10-17: "it now says this server does not advertise a rooms service")."""
import asyncio
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
pytest.importorskip("otrv4_")
from android_bridge.transport import XmppTransport                   # noqa: E402


class _Items:
    def get_items(self):
        return [("conference.x.i2p", None, "")]


class _Disco:
    def __init__(self, lose):
        self.lose = lose

    async def get_items(self, jid, timeout=None):
        return {"disco_items": _Items()}

    async def get_info(self, jid, timeout=None):
        if self.lose:
            self.lose -= 1
            raise TimeoutError("lost over I2P")
        return {"disco_info": {"identities": [("conference", "text", None, "Rooms")],
                               "features": []}}


class _Client(dict):
    boundjid = type("J", (), {"domain": "x.i2p"})()


def _discover(lose):
    t = XmppTransport.__new__(XmppTransport)
    t._client = _Client({"xep_0030": _Disco(lose)})
    return asyncio.run(t._discover_services())


def test_a_lost_reply_is_asked_again():
    [entry] = _discover(lose=2)
    assert (entry["category"], entry["type"]) == ("conference", "text")


def test_it_gives_up_on_one_item_without_emptying_the_list():
    [entry] = _discover(lose=XmppTransport.DISCO_INFO_TRIES)
    assert entry["jid"] == "conference.x.i2p" and entry["category"] == ""


def test_the_screen_never_calls_a_failed_ask_a_finding():
    vm = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/android/"
                           "RoomsViewModel.kt"), encoding="utf-8").read()
    body = vm[vm.index("fun discover()"):vm.index("fun refreshRooms(")]
    assert "if (outcome.ok && (service != null || found.isNotEmpty()))" in body
    assert "roomService = service ?: roomService" in body
