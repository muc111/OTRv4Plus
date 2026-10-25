# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The app's half of server moderation (owner, 2026-10-17): a server admin
bans, unbans and sees every room; a banned account is told so and not
retried. The server half is tests/test_prosody_moderation_module.py."""
import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
pytest.importorskip("otrv4_")
import android_bridge.transport as T                                 # noqa: E402
from android_bridge.connection import ConnectionController           # noqa: E402

SERVICE = "conference.x.i2p"


class _Transport:
    def __init__(self, admin=True, rooms=None, refused=False):
        self.admin, self.rooms, self.refused = admin, rooms or [], refused
        self._server_admin = admin
        self.calls = []

    def server_admin(self):
        return ("ok", "", self.admin)

    def moderation(self, op, account="", days=0, reason=""):
        self.calls.append((op, account, days, reason))
        return ("ok", "", {"available": True, "refused": self.refused,
                           "message": "An admin cannot be banned." if self.refused else "Banned.",
                           "banned": op == "ban", "until": 0 if op == "ban" else -1,
                           "rooms": self.rooms})

    def discover_rooms(self, service):
        return ("ok", "", [{"jid": "lobby@" + SERVICE, "name": "Lobby", "occupants": 3,
                            "secure": False, "claims_secure": False, "password": False}])


def _controller(t):
    c = ConnectionController.__new__(ConnectionController)
    c._transport = t
    c._app = types.SimpleNamespace(groups=None)
    return c


def test_bad_requests_never_reach_the_server():
    t = _Transport()
    c = _controller(t)
    assert c.moderate("explode", "bob@x.i2p")["code"] == "bad_request"
    assert c.moderate("ban", "not-an-address")["code"] == "bad_request"
    assert c.moderate("ban", "bob@x.i2p/phone")["code"] == "bad_request"
    assert c.moderate("ban", "bob@x.i2p", days=3651)["code"] == "bad_request"
    assert c.moderate("ban", "bob@x.i2p", days=-1)["code"] == "bad_request"
    assert t.calls == []


def test_a_ban_goes_to_the_server_and_its_refusal_comes_back():
    t = _Transport()
    # Permanent only (owner, 2026-10-25): days other than 0 never reach the server.
    timed = _controller(t).moderate("ban", "Bob@X.i2p", days=7, reason="spam")
    assert timed["code"] == "bad_request" and t.calls == []
    assert _controller(t).moderate("ban", "Bob@X.i2p", days=0, reason="spam")["ok"]
    assert t.calls == [("ban", "bob@x.i2p", 0, "spam")]
    refused = _controller(_Transport(refused=True)).moderate("ban", "alice@x.i2p", days=0)
    assert not refused["ok"] and refused["code"] == "moderation_refused"
    assert refused["detail"] == "An admin cannot be banned."


def test_an_admin_sees_hidden_rooms_and_others_do_not():
    rooms = [{"jid": "secret@" + SERVICE, "name": "Secret", "description": "",
              "password": True, "hidden": True, "occupants": 1},
             {"jid": "lobby@" + SERVICE, "hidden": False},
             {"jid": "elsewhere@other.i2p", "hidden": True}]
    admin = _controller(_Transport(admin=True, rooms=rooms)).discover_rooms(SERVICE)
    by = {r["jid"]: r for r in admin["value"]}
    assert set(by) == {"lobby@" + SERVICE, "secret@" + SERVICE}
    assert by["secret@" + SERVICE]["hidden"] and by["secret@" + SERVICE]["password"]
    assert by["lobby@" + SERVICE]["hidden"] is False
    other = _controller(_Transport(admin=False, rooms=rooms)).discover_rooms(SERVICE)
    assert [r["jid"] for r in other["value"]] == ["lobby@" + SERVICE]


def test_the_ban_text_says_until_when():
    assert "permanently" in T._ban_text("banned permanently (until=0).")
    assert "until 2026-10-24 20:43 UTC" in T._ban_text("x (until=1792874580)")
    assert T._is_ban("policy-violation", "This account is banned from this server")
    assert not T._is_ban("policy-violation", "Too many active connections")
    assert not T._is_ban("conflict", "banned")


def test_a_banned_account_is_not_reconnected():
    kt = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/android/"
                           "connection/ConnectProblem.kt"), encoding="utf-8").read()
    assert 'ACCOUNT_BANNED = "%s"' % T.BANNED_CODE in kt
    needs = kt[kt.index("val NEEDS_YOU"):kt.index("val TRANSIENT")]
    assert "ACCOUNT_BANNED" in needs


def test_only_an_admin_sees_the_controls():
    screen = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/android/"
                               "ui/ProfileScreen.kt"), encoding="utf-8").read()
    assert "if (!own && model.isServerAdmin) ModerationSection(model, jid)" in screen
    vm = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/android/"
                           "chat/ChatViewModel.kt"), encoding="utf-8").read()
    body = vm[vm.index("fun moderate(jid"):vm.index("private fun moderationOp(")]
    assert "if (!isServerAdmin || moderationBusy) return" in body


def test_the_desktop_host_offers_it():
    from desktop_bridge.host import CONTROLLER_OPS
    assert CONTROLLER_OPS["moderate"] == ("op", "account", "days", "reason")
