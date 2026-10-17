# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Password-protected rooms: asked for, re-asked when wrong, and an
encrypted group's password never mistaken for membership (owner,
2026-10-17: "ensure proper prompts for entering password and joining").
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
A = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")
D = os.path.join(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop")


def _read(*p):
    return open(os.path.join(*p), encoding="utf-8").read()


def test_the_room_list_asks_before_joining():
    screen = _read(A, "ui", "RoomsScreen.kt")
    assert "model.joinListed(room, nick.trim())" in screen
    vm = _read(A, "RoomsViewModel.kt")
    listed = vm[vm.index("fun joinListed("):]
    listed = listed[:listed.index("var inviteNeeded")]
    assert "RoomPassword.beforeJoin(room.jid, nick, room.password)" in listed
    # An encrypted group this phone holds no keys for: explained, not joined.
    assert "room.claimsSecure && !room.secure" in listed
    assert "inviteNeeded = room.jid" in listed


def test_the_explanation_is_shown():
    screen = _read(A, "ui", "RoomsScreen.kt")
    assert "RoomPassword.NEEDS_INVITE" in screen


def test_the_desktop_asks_and_re_asks():
    model = _read(D, "AppModel.kt")
    join = model[model.index("fun joinRoom("):]
    join = join[:join.index("fun createSecureGroup(")]
    assert "RoomPassword.afterJoin(" in join
    assert "triedPassword = password.isNotEmpty()" in join
    panes = _read(D, "ui", "Panes.kt")
    assert "RoomPasswordDialog(model, prompt)" in panes
    assert "RoomPassword.NOT_ENCRYPTION" in panes
    from desktop_bridge.host import CONTROLLER_OPS
    assert CONTROLLER_OPS["join_room"] == ("room", "nick", "password")
