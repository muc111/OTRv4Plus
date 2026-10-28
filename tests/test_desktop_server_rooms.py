# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The desktop's Rooms tab lists the server's rooms (owner, 2026-10-28).

"Server Admin should be able to scan for groups and join if they wish and
delete groups etc. Desktop app should allow for this feature." The phone's
Rooms screen already did; the desktop listed only rooms it was in.

An admin sees hidden rooms too and may delete any room. An encrypted group
is never joined from the listing, by an admin or anyone: its keys come only
with an invitation over OTRv4+, so the listing offers Ask to join, and a
member decides (the creator-decides rule of rc.181 stands).
"""
import inspect
import os
import re
import sys
import types

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "client"))


def _src(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


DESK = ("desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop")
MODEL = _src(*DESK, "AppModel.kt")
CORE = _src(*DESK, "engine", "DesktopCore.kt")
PANES = _src(*DESK, "ui", "Panes.kt")


def _fn(src, signature):
    start = src.index(signature)
    depth, i = 0, src.index("{", start)
    for j in range(i, len(src)):
        depth += {"{": 1, "}": -1}.get(src[j], 0)
        if depth == 0:
            return src[start:j + 1]
    raise AssertionError(signature)


class TestTheEngineOffersIt:

    def test_the_host_names_every_call_the_listing_needs(self):
        from android_bridge.connection import ConnectionController
        from desktop_bridge.host import CONTROLLER_OPS
        for op, args in (("discover_services", ()), ("discover_rooms", ("service",)),
                         ("destroy_room", ("room", "reason")),
                         ("request_group_entry", ("room",))):
            assert CONTROLLER_OPS[op] == args
            params = list(inspect.signature(getattr(ConnectionController, op)).parameters)[1:]
            assert params == list(args), (op, params)

    def test_an_admin_scan_lists_hidden_rooms_and_says_so(self):
        from android_bridge.connection import ConnectionController
        ctl = ConnectionController.__new__(ConnectionController)
        ctl._app = types.SimpleNamespace(groups=None)
        ctl._muc_call = lambda op, *a: {"ok": True, "code": "ok", "detail": "",
                                        "value": [{"jid": "open@conf.x", "name": "open"}]}
        ctl._transport = types.SimpleNamespace(
            _server_admin=True,
            moderation=lambda op, *a: ("ok", "", {"available": True, "rooms": [
                {"jid": "secret@conf.x", "name": "secret", "hidden": True,
                 "description": __import__("otrv4plus_muc").SECURE_GROUP_DESC}]}))
        rooms = {r["jid"]: r for r in ctl.discover_rooms("conf.x")["value"]}
        assert set(rooms) == {"open@conf.x", "secret@conf.x"}
        assert rooms["secret@conf.x"]["hidden"] is True
        # Listed as a CLAIM: the admin holds no keys for it.
        assert rooms["secret@conf.x"]["claims_secure"] is True
        assert rooms["secret@conf.x"]["secure"] is False

    def test_anyone_else_gets_the_public_listing_only(self):
        from android_bridge.connection import ConnectionController
        ctl = ConnectionController.__new__(ConnectionController)
        ctl._app = types.SimpleNamespace(groups=None)
        ctl._muc_call = lambda op, *a: {"ok": True, "code": "ok", "detail": "",
                                        "value": [{"jid": "open@conf.x", "name": "open"}]}
        asked = []
        ctl._transport = types.SimpleNamespace(
            _server_admin=False, server_admin=lambda: ("ok", "", False),
            moderation=lambda *a: asked.append(a))
        assert [r["jid"] for r in ctl.discover_rooms("conf.x")["value"]] == ["open@conf.x"]
        assert asked == []


class TestTheDesktopUsesIt:

    def test_the_core_reads_every_flag_the_phone_reads(self):
        fn = _fn(CORE, "fun discoverRooms(service: String)")
        assert 'controller("discover_rooms", "service" to service)' in fn
        for flag in ('"secure"', '"claims_secure"', '"password"', '"hidden"', '"occupants"'):
            assert flag in fn
        assert 'controller("destroy_room", "room" to room, "reason" to reason)' in CORE

    def test_a_group_with_no_keys_here_is_asked_about_not_joined(self):
        fn = _fn(MODEL, "fun joinListed(room: org.otrv4plus.android.bridge.RoomSummary)")
        guard = fn.index("if (room.claimsSecure && !room.secure) { askToJoinFor = room.jid; return }")
        assert guard < fn.index("joinRoom(")
        ask = _fn(MODEL, "fun askToJoin(room: String)")
        assert "core.requestGroupEntry(room)" in ask
        assert "RoomSections.mayAsk(before, now)" in ask
        assert "joinRoom" not in ask and "acceptGroupInvite" not in ask

    def test_delete_is_offered_to_the_owner_or_an_admin_only(self):
        assert re.search(r"fun canDeleteRoom\(jid: String\): Boolean = chat\.canDeleteRoom\(jid\)",
                         MODEL)
        row = _fn(PANES, "private fun ServerRoomRow(")
        assert "if (model.canDeleteRoom(room.jid))" in row

    def test_a_held_group_is_deleted_for_everyone_first(self):
        fn = _fn(MODEL, "fun deleteServerRoom(jid: String)")
        assert fn.index("deleteSecureGroup(jid)") < fn.index("core.destroyRoom(jid")

    def test_the_tab_has_the_listing_and_the_scan(self):
        pane = _fn(PANES, "fun RoomsPane(model: AppModel)")
        assert "if (showServer) ServerRoomsCard(model" in pane
        assert "model.scanServerRooms()" in pane
        card = _fn(PANES, "private fun ServerRoomsCard(")
        assert "ServerRooms.title(model.isServerAdmin)" in card
        assert "ServerRooms.note(model.isServerAdmin)" in card
        assert 'ServerRoomRow(model, room, "Ask to join", onDelete)' in card

    def test_a_new_account_does_not_see_the_last_ones_scan(self):
        signed_in = MODEL[MODEL.index("                roomService = null"):]
        signed_in = signed_in[:signed_in.index("findRoomService()")]
        assert "serverRooms = emptyList()" in signed_in
        assert "serverRoomsScanned = false" in signed_in

    def test_the_desktop_shares_the_phones_room_sections(self):
        assert '"org/otrv4plus/android/chat/RoomSections.kt"' in _src("desktop", "build.gradle.kts")


def test_the_desktop_build_with_the_listing_is_told_apart():
    assert 'version = "0.14.11"' in _src("desktop", "build.gradle.kts")
